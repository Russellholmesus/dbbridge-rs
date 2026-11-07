use super::Ingress;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub(super) fn raise_nofile() {
    #[cfg(target_os = "linux")]
    {
        extern "C" {
            fn getrlimit(resource: i32, rlim: *mut [u64; 2]) -> i32;
            fn setrlimit(resource: i32, rlim: *const [u64; 2]) -> i32;
        }
        const RLIMIT_NOFILE: i32 = 7;
        let mut lim = [0u64; 2];
        // SAFETY: plain libc calls on a properly sized rlimit struct.
        unsafe {
            if getrlimit(RLIMIT_NOFILE, &mut lim) == 0 && lim[0] < lim[1] {
                lim[0] = lim[1].min(65536);
                setrlimit(RLIMIT_NOFILE, &lim);
            }
        }
    }
}

pub(super) const TOKEN: &str = "test-token-0123456789abcdef012345";

/// What the proxy does with one request.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(super) enum Action {
    Pass,
    /// Holds the request (not forwarded) for the duration, then forwards it.
    Hang(Duration),
    /// Closes both sides of the connection without forwarding.
    #[allow(dead_code)]
    Drop,
    /// Answers with these raw bytes (a whole HTTP response) without
    /// forwarding; the connection stays usable for the next request.
    Respond(String),
    /// Like Respond with an owned response, then closes the client side.
    RespondClose(String),
    /// Writes these raw bytes (e.g. a 101 answer and WebSocket frames)
    /// without forwarding, then closes both sides.
    RespondRawClose(Vec<u8>),
    /// Writes these bytes (a response head and a stream prefix) and then
    /// holds the connection open, sending nothing more, until the client
    /// closes it (a blackholed stream).
    RespondHold(String),
    ForwardThenDrop,
    ForwardThenRespond(String),
    /// Forwards a WebSocket upgrade, then relays the client's frames but
    /// drops every binary message (a blackholed upstream data path; text
    /// control messages and the downstream direction keep flowing).
    PassDropUpBinary,
    /// Writes the response head (and stream prefix), then keeps writing the
    /// drip bytes at the interval until the client goes away (a gateway that
    /// turns a stream into keep-alive comments).
    RespondDrip(String, Vec<u8>, Duration),
}

pub(super) type Hook = Arc<dyn Fn(&Req) -> Action + Send + Sync>;

/// One request seen by the proxy.
pub(super) struct Req<'a> {
    pub(super) method: &'a str,
    pub(super) path: &'a str,
    pub(super) body: &'a [u8],
    /// The request head, lowercased (for header checks).
    pub(super) head: &'a str,
    /// The request head as sent (header values keep their case).
    pub(super) raw: &'a str,
}

/// A whole HTTP/1.1 response with a JSON body.
pub(super) fn json_response(status: u16, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

#[derive(Default)]
pub(super) struct Counts {
    pub(super) requests: Mutex<Vec<(String, String)>>,
    /// Binary WebSocket messages dropped by `Action::PassDropUpBinary`.
    pub(super) dropped_up_binary: AtomicUsize,
}

impl Counts {
    pub(super) fn count(&self, method: &str, path_pred: impl Fn(&str) -> bool) -> usize {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(m, p)| (method.is_empty() || m == method) && path_pred(p))
            .count()
    }
}

pub(super) struct Target {
    pub(super) addr: SocketAddr,
    pub(super) received: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
    pub(super) dials: Arc<AtomicI64>,
    stop: Arc<AtomicBool>,
}

impl Target {
    pub(super) fn echo(special: &'static str) -> Self {
        Self::with(move |mut c: TcpStream, tx: mpsc::SyncSender<Vec<u8>>| {
            if special == "down_fin_first" {
                let _ = c.shutdown(Shutdown::Write);
            }
            let mut buf = vec![0u8; 32768];
            loop {
                match c.read(&mut buf) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        let _ = tx.try_send(buf[..n].to_vec());
                        if special != "down_fin_first" && c.write_all(&buf[..n]).is_err() {
                            return;
                        }
                    }
                }
            }
        })
    }

    pub(super) fn with(
        serve: impl Fn(TcpStream, mpsc::SyncSender<Vec<u8>>) + Send + Sync + 'static,
    ) -> Self {
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = ln.local_addr().unwrap();
        let (tx, rx) = mpsc::sync_channel(64);
        let dials = Arc::new(AtomicI64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let serve = Arc::new(serve);
        let (d, s) = (dials.clone(), stop.clone());
        std::thread::spawn(move || {
            for c in ln.incoming() {
                if s.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(c) = c else { continue };
                d.fetch_add(1, Ordering::SeqCst);
                let (serve, tx) = (serve.clone(), tx.clone());
                std::thread::spawn(move || serve(c, tx));
            }
        });
        Target {
            addr,
            received: Arc::new(Mutex::new(rx)),
            dials,
            stop,
        }
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
    }
}

/// HTTP/1.1 sniffing proxy: records each request line and applies the hook.
/// Request bodies are skipped by Content-Length; a WebSocket upgrade, chunked
/// body or anything unparsable switches the connection to raw relaying.
pub(super) struct Proxy {
    pub(super) addr: SocketAddr,
    pub(super) counts: Arc<Counts>,
    conns: Conns,
    stop: Arc<AtomicBool>,
}

/// Live proxied connections: first request path, client and server sockets.
type Conns = Arc<Mutex<Vec<(Arc<Mutex<String>>, TcpStream, TcpStream)>>>;

impl Proxy {
    pub(super) fn start(upstream: SocketAddr, hook: Option<Hook>) -> Self {
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = ln.local_addr().unwrap();
        let counts = Arc::new(Counts::default());
        let stop = Arc::new(AtomicBool::new(false));
        let conns: Conns = Default::default();
        let (c2, s2, k2) = (counts.clone(), stop.clone(), conns.clone());
        std::thread::spawn(move || {
            for client in ln.incoming() {
                if s2.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(client) = client else { continue };
                let Ok(server) = TcpStream::connect(upstream) else {
                    continue;
                };
                let (counts, hook) = (c2.clone(), hook.clone());
                let (sr, cw) = (server.try_clone().unwrap(), client.try_clone().unwrap());
                let first = Arc::new(Mutex::new(String::new()));
                {
                    let mut live = k2.lock().unwrap();
                    live.retain(|(_, c, _)| c.peer_addr().is_ok());
                    live.push((
                        first.clone(),
                        client.try_clone().unwrap(),
                        server.try_clone().unwrap(),
                    ));
                }
                let mute = Arc::new(AtomicBool::new(false));
                let m2 = mute.clone();
                std::thread::spawn(move || relay_muted(sr, cw, m2));
                std::thread::spawn(move || sniff(client, server, counts, hook, first, mute));
            }
        });
        Proxy {
            addr,
            counts,
            conns,
            stop,
        }
    }

    /// Cuts every live proxied connection whose first request path matches
    /// (a carrier loss on the network path). Returns how many were cut.
    pub(super) fn kill(&self, pred: impl Fn(&str) -> bool) -> usize {
        let mut n = 0;
        for (first, c, s) in self.conns.lock().unwrap().iter() {
            if pred(&first.lock().unwrap()) && c.peer_addr().is_ok() {
                let _ = c.shutdown(Shutdown::Both);
                let _ = s.shutdown(Shutdown::Both);
                n += 1;
            }
        }
        n
    }
}

fn relay_muted(mut from: TcpStream, mut to: TcpStream, mute: Arc<AtomicBool>) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if mute.load(Ordering::SeqCst) {
                    continue;
                }
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    // A muted connection belongs to the hook's answer, which closes the
    // client side itself.
    if !mute.load(Ordering::SeqCst) {
        let _ = to.shutdown(Shutdown::Write);
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.addr);
    }
}

/// Relays client WebSocket frames to the server, dropping binary messages
/// (and their continuation frames).
fn relay_drop_binary(mut from: TcpStream, mut to: TcpStream, counts: &Counts) {
    let mut dropping = false;
    loop {
        let mut h = [0u8; 2];
        if from.read_exact(&mut h).is_err() {
            break;
        }
        let mut head = h.to_vec();
        let mut len = u64::from(h[1] & 0x7f);
        if len == 126 {
            let mut b = [0u8; 2];
            if from.read_exact(&mut b).is_err() {
                break;
            }
            head.extend_from_slice(&b);
            len = u64::from(u16::from_be_bytes(b));
        } else if len == 127 {
            let mut b = [0u8; 8];
            if from.read_exact(&mut b).is_err() {
                break;
            }
            head.extend_from_slice(&b);
            len = u64::from_be_bytes(b);
        }
        if h[1] & 0x80 != 0 {
            let mut m = [0u8; 4];
            if from.read_exact(&mut m).is_err() {
                break;
            }
            head.extend_from_slice(&m);
        }
        let mut payload = vec![0u8; len as usize];
        if from.read_exact(&mut payload).is_err() {
            break;
        }
        let fin = h[0] & 0x80 != 0;
        let drop = match h[0] & 0x0f {
            0x2 => {
                dropping = !fin;
                counts.dropped_up_binary.fetch_add(1, Ordering::SeqCst);
                true
            }
            0x0 => {
                let d = dropping;
                if fin {
                    dropping = false;
                }
                d
            }
            _ => false,
        };
        if drop {
            continue;
        }
        if to.write_all(&head).is_err() || to.write_all(&payload).is_err() {
            break;
        }
    }
    let _ = from.shutdown(Shutdown::Both);
    let _ = to.shutdown(Shutdown::Both);
}

fn relay(mut from: TcpStream, mut to: TcpStream) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match from.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if to.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    let _ = to.shutdown(Shutdown::Write);
}

fn sniff(
    mut client: TcpStream,
    mut server: TcpStream,
    counts: Arc<Counts>,
    hook: Option<Hook>,
    first: Arc<Mutex<String>>,
    mute: Arc<AtomicBool>,
) {
    let mut pending: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let Some(end) = pending.windows(4).position(|w| w == b"\r\n\r\n") else {
            match client.read(&mut buf) {
                Ok(0) | Err(_) => {
                    let _ = server.write_all(&pending);
                    let _ = server.shutdown(Shutdown::Write);
                    return;
                }
                Ok(n) => {
                    pending.extend_from_slice(&buf[..n]);
                    continue;
                }
            }
        };
        let head = String::from_utf8_lossy(&pending[..end]).to_string();
        let mut words = head.lines().next().unwrap_or("").split_whitespace();
        let method = words.next().unwrap_or("").to_string();
        let target = words.next().unwrap_or("").to_string();
        let path = target.split('?').next().unwrap_or("").to_string();
        counts
            .requests
            .lock()
            .unwrap()
            .push((method.clone(), path.clone()));
        {
            let mut f = first.lock().unwrap();
            if f.is_empty() {
                *f = path.clone();
            }
        }
        let lower = head.to_ascii_lowercase();
        let header = |name: &str| {
            lower
                .lines()
                .find_map(|l| l.strip_prefix(name).map(|v| v.trim().to_string()))
        };
        let raw = header("upgrade:").is_some()
            || header("transfer-encoding:").is_some_and(|v| v.contains("chunked"));
        let body_len: usize = header("content-length:")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let mut total = end + 4 + body_len;
        if raw {
            total = pending.len();
        }
        while pending.len() < total {
            match client.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => pending.extend_from_slice(&buf[..n]),
            }
        }
        let body_end = total.min(pending.len());
        let action = hook.as_ref().map_or(Action::Pass, |h| {
            h(&Req {
                method: &method,
                path: &path,
                body: &pending[(end + 4).min(body_end)..body_end],
                head: &lower,
                raw: &head,
            })
        });
        let drop_up_binary = action == Action::PassDropUpBinary;
        match action {
            Action::Pass | Action::PassDropUpBinary => {}
            Action::Hang(d) => std::thread::sleep(d),
            Action::Drop => {
                let _ = client.shutdown(Shutdown::Both);
                let _ = server.shutdown(Shutdown::Both);
                return;
            }
            Action::Respond(resp) => {
                let _ = client.write_all(resp.as_bytes());
                pending.drain(..body_end);
                continue;
            }
            Action::RespondRawClose(resp) => {
                let _ = client.write_all(&resp);
                std::thread::sleep(Duration::from_millis(20));
                let _ = client.shutdown(Shutdown::Both);
                let _ = server.shutdown(Shutdown::Both);
                return;
            }
            Action::RespondClose(resp) => {
                let _ = client.write_all(resp.as_bytes());
                let _ = client.shutdown(Shutdown::Both);
                let _ = server.shutdown(Shutdown::Both);
                return;
            }
            Action::ForwardThenDrop => {
                mute.store(true, Ordering::SeqCst);
                let _ = server.write_all(&pending[..body_end]);
                std::thread::sleep(Duration::from_millis(300));
                let _ = client.shutdown(Shutdown::Both);
                let _ = server.shutdown(Shutdown::Both);
                return;
            }
            Action::ForwardThenRespond(resp) => {
                mute.store(true, Ordering::SeqCst);
                let _ = server.write_all(&pending[..body_end]);
                std::thread::sleep(Duration::from_millis(150));
                let _ = client.write_all(resp.as_bytes());
                let _ = client.shutdown(Shutdown::Both);
                let _ = server.shutdown(Shutdown::Both);
                return;
            }
            Action::RespondDrip(resp, drip, every) => {
                mute.store(true, Ordering::SeqCst);
                let _ = server.shutdown(Shutdown::Both);
                if client.write_all(resp.as_bytes()).is_ok() {
                    loop {
                        std::thread::sleep(every);
                        if client.write_all(&drip).is_err() {
                            break;
                        }
                    }
                }
                let _ = client.shutdown(Shutdown::Both);
                return;
            }
            Action::RespondHold(resp) => {
                mute.store(true, Ordering::SeqCst);
                let _ = server.shutdown(Shutdown::Both);
                let _ = client.write_all(resp.as_bytes());
                let _ = client.set_read_timeout(None);
                while matches!(client.read(&mut buf), Ok(n) if n > 0) {}
                let _ = client.shutdown(Shutdown::Both);
                return;
            }
        }
        let take = total.min(pending.len());
        if server.write_all(&pending[..take]).is_err() {
            return;
        }
        pending.drain(..take);
        if raw {
            if server.write_all(&pending).is_err() {
                return;
            }
            if drop_up_binary {
                relay_drop_binary(client, server, &counts);
            } else {
                relay(client, server);
            }
            return;
        }
    }
}

pub(super) struct Opts {
    pub(super) mode: &'static str,
    /// Egress `transport:` keys (later inserts override).
    pub(super) egress_transport: std::collections::BTreeMap<&'static str, String>,
    /// Ingress `transport:` keys (later inserts override).
    pub(super) ingress_transport: std::collections::BTreeMap<&'static str, String>,
    /// Egress / ingress `transport.recovery` (enabled, grace, barrier_timeout).
    pub(super) egress_recovery: Option<String>,
    pub(super) ingress_recovery: Option<String>,
    /// Extra YAML under the ingress peer (each line indented 4 spaces).
    pub(super) peer_extra: String,
    /// Ingress peer endpoints YAML (each line indented 6 spaces); `{proxy}`
    /// is the proxy address in front of the egress. Default: e1 -> proxy.
    pub(super) endpoints: Option<String>,
    pub(super) max_sessions: u32,
    pub(super) hook: Option<Hook>,
    /// Filled with the egress server once it runs (for hooks).
    pub(super) egress_cell: EgressCell,
    /// A second proxy to the same egress (`{proxy2}` in `endpoints`).
    pub(super) second_proxy: bool,
    /// The second proxy's hook.
    pub(super) hook2: Option<Hook>,
    pub(super) second_egress: bool,
}

impl Opts {
    pub(super) fn new(mode: &'static str) -> Self {
        Opts {
            mode,
            egress_transport: Default::default(),
            ingress_transport: Default::default(),
            egress_recovery: None,
            ingress_recovery: None,
            peer_extra: String::new(),
            endpoints: None,
            max_sessions: 10,
            hook: None,
            egress_cell: Default::default(),
            second_proxy: false,
            hook2: None,
            second_egress: false,
        }
    }

    pub(super) fn e2e(mode: &'static str) -> Self {
        let mut o = Self::new(mode);
        for t in [&mut o.egress_transport, &mut o.ingress_transport] {
            t.insert("heartbeat", "50ms".into());
            t.insert("failure_detect_timeout", "150ms".into());
        }
        o.ingress_transport.insert("ack_max_delay", "30ms".into());
        o.ingress_transport
            .insert("control_request_timeout", "150ms".into());
        o.egress_recovery = Some("enabled: false".into());
        o.ingress_recovery = Some("enabled: false".into());
        o
    }
}

fn transport_yaml(
    keys: &std::collections::BTreeMap<&'static str, String>,
    recovery: &Option<String>,
) -> String {
    let mut out = String::new();
    for (k, v) in keys {
        out.push_str(&format!("  {k}: {v}\n"));
    }
    if let Some(r) = recovery {
        out.push_str("  recovery:\n");
        for kv in r.split(',') {
            out.push_str(&format!("    {}\n", kv.trim()));
        }
    }
    out
}

static SERIAL: Mutex<()> = Mutex::new(());

pub(super) struct Env {
    _serial: std::sync::MutexGuard<'static, ()>,
    pub(super) egress: Arc<crate::egress::Server>,
    pub(super) ingress: Ingress,
    pub(super) proxy: Proxy,
    /// The second proxy (`{proxy2}`), when the options asked for one.
    pub(super) proxy2: Option<Proxy>,
    /// The second egress instance, when the options asked for one.
    pub(super) egress2: Option<Arc<crate::egress::Server>>,
    pub(super) local: SocketAddr,
    egress_stop: Arc<AtomicBool>,
    ingress_stop: Arc<AtomicBool>,
    ingress_threads: Vec<std::thread::JoinHandle<()>>,
    dir: std::path::PathBuf,
}

impl Env {
    /// Builds egress + proxy + ingress for `target` and starts the ingress.
    pub(super) fn start(target: &Target, o: Opts) -> Env {
        let serial = SERIAL
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = std::env::temp_dir().join(format!(
            "dbb-ingress-e2e-{}",
            crate::util::random_hex(6).unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("token"), TOKEN).unwrap();
        let b_path = dir.join("b.yaml");
        std::fs::write(
            &b_path,
            format!(
                "node:\n  id: B\nhttp:\n  enabled: true\n  listen: \"127.0.0.1:0\"\ntargets:\n  db:\n    address: \"{}\"\nauth:\n  inbound_peers:\n    - id: A\n      token_files: [token]\n      allowed_targets: [db]\n      max_sessions: {}\nlimits:\n  max_sessions: {}\ntransport:\n{}",
                target.addr,
                o.max_sessions,
                o.max_sessions.max(10),
                transport_yaml(
                    &{
                        let mut t = o.egress_transport.clone();
                        t.entry("unattached_timeout").or_insert_with(|| "5s".into());
                        t
                    },
                    &o.egress_recovery
                )
            ),
        )
        .unwrap();
        let egress_stop = Arc::new(AtomicBool::new(false));
        let start_egress = || {
            let b_cfg = Arc::new(crate::config::load(&b_path).expect("egress config"));
            let egress = Arc::new(crate::egress::Server::new(
                b_cfg,
                Arc::new(crate::metrics::Metrics::new()),
            ));
            {
                let (srv, stop) = (egress.clone(), egress_stop.clone());
                std::thread::spawn(move || {
                    let _ = srv.listen(stop);
                });
            }
            let until = Instant::now() + Duration::from_secs(5);
            let addr = loop {
                if let Some(a) = *egress.accept_addr.lock().unwrap() {
                    break a;
                }
                assert!(Instant::now() < until, "egress did not start");
                std::thread::sleep(Duration::from_millis(2));
            };
            (egress, addr)
        };
        let (egress, egress_addr) = start_egress();
        let egress2 = o.second_egress.then(start_egress);
        let _ = o.egress_cell.set(egress.clone());
        let proxy = Proxy::start(egress_addr, o.hook);
        let proxy2 = o.second_proxy.then(|| {
            let upstream = egress2.as_ref().map_or(egress_addr, |(_, a)| *a);
            Proxy::start(upstream, o.hook2)
        });
        let egress2 = egress2.map(|(e, _)| e);
        let a_path = dir.join("a.yaml");
        let endpoints = o
            .endpoints
            .as_deref()
            .unwrap_or("      - id: e1\n        url: \"http://{proxy}\"\n")
            .replace("{proxy}", &proxy.addr.to_string())
            .replace(
                "{proxy2}",
                &proxy2
                    .as_ref()
                    .map_or(String::new(), |p| p.addr.to_string()),
            );
        std::fs::write(
            &a_path,
            format!(
                "node:\n  id: A\nlisteners:\n  - id: local\n    listen: \"127.0.0.1:0\"\n    peer: B\n    target: db\npeers:\n  - id: B\n    expected_node_id: B\n    credential_ref: B\n    token_file: token\n    transport:\n      protocol: {}\n{}    endpoints:\n{}transport:\n  protocol: {}\n{}",
                o.mode,
                o.peer_extra,
                endpoints,
                o.mode,
                transport_yaml(&o.ingress_transport, &o.ingress_recovery)
            ),
        )
        .unwrap();
        let a_cfg = Arc::new(crate::config::load(&a_path).expect("ingress config"));
        let auth = Arc::new(crate::auth::Authenticator::new(a_cfg.clone()));
        let ingress = Ingress::new(a_cfg).with_auth(auth);
        let ingress_stop = Arc::new(AtomicBool::new(false));
        let ingress_threads = ingress.start(ingress_stop.clone()).expect("ingress start");
        let local = ingress.accept_addrs.lock().unwrap()[0];
        Env {
            _serial: serial,
            egress,
            ingress,
            proxy,
            proxy2,
            egress2,
            local,
            egress_stop,
            ingress_stop,
            ingress_threads,
            dir,
        }
    }

    pub(super) fn dial(&self) -> TcpStream {
        let c = TcpStream::connect(self.local).unwrap();
        c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        c.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
        c
    }

    pub(super) fn egress_sessions(&self) -> usize {
        self.egress.registry.all_sessions().len()
    }

    pub(super) fn wait_egress_sessions(&self, want: usize, within: Duration) -> usize {
        let until = Instant::now() + within;
        loop {
            let n = self.egress_sessions();
            if n == want || Instant::now() >= until {
                return n;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    pub(super) fn close_ingress(&mut self) {
        self.ingress_stop.store(true, Ordering::SeqCst);
        self.ingress.request_shutdown();
        for t in self.ingress_threads.drain(..) {
            let _ = t.join();
        }
        self.ingress.wait_idle(Duration::from_secs(10));
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        self.close_ingress();
        self.egress_stop.store(true, Ordering::SeqCst);
        self.egress.request_shutdown();
        self.egress.registry.close_all();
        if let Some(e) = &self.egress2 {
            e.request_shutdown();
            e.registry.close_all();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub(super) fn echo(c: &mut TcpStream, msg: &[u8]) -> std::io::Result<()> {
    c.write_all(msg)?;
    let mut got = vec![0u8; msg.len()];
    c.read_exact(&mut got)?;
    if got != msg {
        return Err(std::io::Error::other(format!("echo mismatch: {got:?}")));
    }
    Ok(())
}

/// The egress server of the environment, for hooks that need session state
/// (set right after the egress starts).
pub(super) type EgressCell = Arc<std::sync::OnceLock<Arc<crate::egress::Server>>>;

pub(super) fn injected_events(
    cell: &EgressCell,
    path: &str,
    more: impl FnOnce(&Arc<crate::session::Session>, &str) -> String,
) -> Option<String> {
    let srv = cell.get()?;
    let id = path.split('/').nth(3)?;
    let session = srv.registry.get(id)?;
    let stream = crate::util::random_id(16).ok()?;
    session.attach(&stream).ok()?;
    let mut ready = crate::wire::Control::base(
        crate::wire::ControlKind::Ready,
        &session.id,
        &session.instance_id,
        session.epoch(),
        &stream,
    );
    ready.protocol_version = Some(crate::wire::PROTOCOL_VERSION.to_string());
    ready.transport = Some("http-sse".to_string());
    let mut out = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n{}: {}\r\nConnection: close\r\n\r\nevent: ready\ndata: {}\n\n",
        crate::wire::H_INSTANCE_ID,
        srv.cfg.node.instance_id,
        ready.to_json()
    );
    out.push_str(&more(&session, &stream));
    Some(out)
}

pub(super) fn probe_response(
    cell: &EgressCell,
    body: &[u8],
    transports: &[&str],
) -> Option<String> {
    let srv = cell.get()?;
    let req = crate::util::json::parse_bytes(body).ok()?;
    let nonce = req.get("nonce")?.as_str()?.to_string();
    let list = transports
        .iter()
        .map(|t| format!("\"{t}\""))
        .collect::<Vec<_>>()
        .join(",");
    Some(json_response(
        200,
        &format!(
            r#"{{"protocol_version":"1.5","node_id":"B","instance_id":"{}","nonce":"{nonce}","recovery_available":true,"accepting_new_sessions":true,"transports":[{list}]}}"#,
            srv.cfg.node.instance_id
        ),
    ))
}
