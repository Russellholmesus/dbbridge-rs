//! The database side of reverse mode.
//!
//! It keeps `reverse.tunnels_per_endpoint` tunnels to each public-side
//! endpoint and hands every stream the public side opens to a listener, which
//! the egress HTTP server accepts from as if it were a TCP socket. Nothing
//! above that point knows the connection came in over a tunnel.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::config::{Config, Protocol};
use crate::error::{Error, Result};
use crate::mux::{Opener, Session};
use crate::net::ws;
use crate::net::{header, BufferedConn, Conn};
use crate::wire;

use super::{
    mux_config, split_tunnel, H_EXPECTED_NODE_ID, H_NODE_ID, H_TUNNEL_ID, H_TUNNEL_PRIORITY,
    PATH_REVERSE, REVERSE_SUBPROTOCOL,
};

/// Streams the public side opened, waiting for the egress HTTP server to
/// accept them. There is no queue limit: the public side opens one stream per
/// connection it needs, and a stream it cannot get served would fail anyway.
pub struct TunnelListener {
    conns: Mutex<VecDeque<Box<dyn Conn>>>,
    cv: Condvar,
    closed: AtomicBool,
}

impl TunnelListener {
    pub fn new() -> TunnelListener {
        TunnelListener {
            conns: Mutex::new(VecDeque::new()),
            cv: Condvar::new(),
            closed: AtomicBool::new(false),
        }
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        // Streams already queued have no egress server to serve them any
        // more: shut them down so the public side sees the end of each
        // session instead of a stream that stays open until the tunnel dies.
        let queued: Vec<Box<dyn Conn>> = {
            let mut g = self
                .conns
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            g.drain(..).collect()
        };
        for c in queued {
            let _ = c.shutdown_both();
        }
        self.cv.notify_all();
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    /// Queues a stream. Returns false once the listener is closed, and the
    /// caller must drop the connection.
    pub fn deliver(&self, conn: Box<dyn Conn>) -> bool {
        let mut g = self
            .conns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.closed.load(Ordering::SeqCst) {
            return false;
        }
        g.push_back(conn);
        self.cv.notify_all();
        true
    }

    /// Waits for the next stream. `None` means the listener was closed.
    pub fn accept_next(&self) -> Option<Box<dyn Conn>> {
        let mut g = self
            .conns
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if let Some(c) = g.pop_front() {
                return Some(c);
            }
            if self.closed.load(Ordering::SeqCst) {
                return None;
            }
            g = self
                .cv
                .wait(g)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

impl Default for TunnelListener {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) struct LiveTunnel {
    pub(crate) id: String,
    pub(crate) endpoint: String,
    pub(crate) priority: i32,
    pub(crate) transport: String,
    pub(crate) session: Arc<Session>,
}

#[derive(Clone, Copy)]
struct EndpointMode {
    mode: Protocol,
    since: Instant,
}

pub struct Client {
    pub(crate) cfg: Arc<Config>,
    listener: Arc<TunnelListener>,
    live: Mutex<HashMap<String, Arc<LiveTunnel>>>,
    /// Signalled whenever a tunnel goes down, so slots waiting behind a
    /// better endpoint re-check.
    wake: Mutex<()>,
    wake_cv: Condvar,
    shutdown: AtomicBool,
    pub(crate) auth: Option<Arc<crate::auth::Authenticator>>,
    pub(crate) metrics: Option<Arc<crate::metrics::Metrics>>,
    modes: Mutex<HashMap<String, EndpointMode>>,
}

impl Client {
    pub fn new(cfg: Arc<Config>, listener: Arc<TunnelListener>) -> Arc<Client> {
        Arc::new(Client {
            cfg,
            listener,
            live: Mutex::new(HashMap::new()),
            wake: Mutex::new(()),
            wake_cv: Condvar::new(),
            shutdown: AtomicBool::new(false),
            auth: None,
            metrics: None,
            modes: Mutex::new(HashMap::new()),
        })
    }

    pub fn with_auth(mut self: Arc<Self>, auth: Arc<crate::auth::Authenticator>) -> Arc<Self> {
        Arc::get_mut(&mut self)
            .expect("tunnel client not shared")
            .auth = Some(auth);
        self
    }

    /// Injects the process metrics owned by the runtime. HTTP auto fallback
    /// calls this at the transition point; no global registry is used.
    pub fn with_metrics(mut self: Arc<Self>, metrics: Arc<crate::metrics::Metrics>) -> Arc<Self> {
        Arc::get_mut(&mut self)
            .expect("tunnel client not shared")
            .metrics = Some(metrics);
        self
    }

    pub(crate) fn record_fallback(&self, from: &str, to: &str) {
        if let Some(metrics) = &self.metrics {
            metrics.reverse_tunnel_fallback(from, to);
        }
    }
    /// Starts one dial loop per slot. Returns the join handles so a caller can
    /// wait for a clean stop.
    pub fn start(self: &Arc<Self>) -> Vec<std::thread::JoinHandle<()>> {
        let mut handles = Vec::new();
        let per = self.cfg.reverse.tunnels_per_endpoint.max(1);
        for ep in self.cfg.reverse.endpoints.clone() {
            for index in 0..per {
                let me = self.clone();
                let ep = ep.clone();
                handles.push(std::thread::spawn(move || me.slot(ep, index as usize)));
            }
        }
        handles
    }

    pub fn live_count(&self) -> usize {
        self.live
            .lock()
            .unwrap()
            .values()
            .filter(|t| !t.session.is_closed())
            .count()
    }

    pub fn stop(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        self.listener.close();
        for t in self.live.lock().unwrap().values() {
            t.session.close();
        }
        self.wake_cv.notify_all();
    }

    #[cfg(test)]
    pub fn close_tunnels(&self) {
        for t in self.live.lock().unwrap().values() {
            t.session.close();
        }
        self.wake_cv.notify_all();
    }

    fn stopping(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    /// True when an endpoint with a better (lower) priority has a live
    /// tunnel. Lower-priority slots then wait instead of dialing, so the
    /// preferred endpoint is used whenever it is reachable. Tunnels already
    /// up stay up when a better endpoint returns.
    fn better_live(&self, priority: i32) -> bool {
        self.live
            .lock()
            .unwrap()
            .values()
            .any(|t| t.priority < priority && !t.session.is_closed())
    }

    fn slot(self: Arc<Self>, ep: crate::config::Endpoint, index: usize) {
        let mut failures = 0usize;
        let mut last_err = String::new();
        while !self.stopping() && !self.listener.is_closed() {
            if self.better_live(ep.priority) {
                // Wait for a tunnel to go down before re-checking.
                let g = self.wake.lock().unwrap();
                let _ = self
                    .wake_cv
                    .wait_timeout(g, Duration::from_millis(500))
                    .unwrap();
                continue;
            }
            match self.dial(&ep) {
                Ok(tunnel) => {
                    crate::slog::info(
                        "reverse tunnel established",
                        &[
                            ("endpoint", ep.id.as_str().into()),
                            ("tunnel", tunnel.id.as_str().into()),
                            ("transport", tunnel.transport.as_str().into()),
                        ],
                    );
                    if let Some(metrics) = &self.metrics {
                        metrics.reverse_tunnel_opened(&tunnel.endpoint, &tunnel.transport);
                    }
                    if failures > 0 {
                        crate::slog::info(
                            "reverse tunnel reconnected",
                            &[
                                ("endpoint", ep.id.as_str().into()),
                                ("slot", index.into()),
                                ("after_failures", failures.into()),
                            ],
                        );
                    }
                    failures = 0;
                    last_err.clear();
                    self.serve(tunnel);
                }
                Err(e) => {
                    if self.stopping() {
                        return;
                    }
                    if let Some(metrics) = &self.metrics {
                        metrics.reverse_tunnel_dial_failed();
                    }
                    failures += 1;
                    if e.message != last_err || failures == 1 {
                        crate::slog::warn(
                            "reverse tunnel dial failed",
                            &[
                                ("endpoint", ep.id.as_str().into()),
                                ("slot", index.into()),
                                ("err", crate::slog::err(&e)),
                            ],
                        );
                        last_err = e.message.clone();
                    }
                    let wait = match backoff(
                        self.cfg.reverse.min_backoff,
                        self.cfg.reverse.max_backoff,
                        failures,
                    ) {
                        Ok(wait) => wait,
                        Err(error) => {
                            crate::slog::error(
                                "reverse tunnel retry jitter unavailable",
                                &[("err", crate::slog::err(&error))],
                            );
                            return;
                        }
                    };
                    if !self.sleep(wait) {
                        return;
                    }
                }
            }
        }
    }

    fn sleep(&self, d: Duration) -> bool {
        let end = Instant::now() + d;
        while Instant::now() < end {
            if self.stopping() {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20).min(end - Instant::now()));
        }
        !self.stopping()
    }

    fn mode_for(&self, ep: &crate::config::Endpoint) -> Protocol {
        match self.cfg.reverse.transport {
            Protocol::Ws | Protocol::HttpSse | Protocol::LongPoll => self.cfg.reverse.transport,
            Protocol::Auto => self
                .modes
                .lock()
                .unwrap()
                .get(&ep.id)
                .filter(|m| m.since.elapsed() < Duration::from_secs(600))
                .map(|m| m.mode)
                .unwrap_or(Protocol::Ws),
        }
    }

    fn dial(&self, ep: &crate::config::Endpoint) -> Result<Arc<LiveTunnel>> {
        let mode = self.mode_for(ep);
        if mode != Protocol::Ws {
            let id = super::new_tunnel_id()?;
            return match super::client_http::dial(self, ep, &id, mode) {
                Ok(t) => Ok(t),
                Err(e)
                    if mode == Protocol::HttpSse
                        && self.cfg.reverse.transport == Protocol::Auto
                        && (super::client_http::sse_ready_timeout(&e)
                            || super::client_http::http_fallback_allowed(&e)) =>
                {
                    self.modes.lock().unwrap().insert(
                        ep.id.clone(),
                        EndpointMode {
                            mode: Protocol::LongPoll,
                            since: Instant::now(),
                        },
                    );
                    self.record_fallback("http-sse", "long-poll");
                    super::client_http::dial(self, ep, &super::new_tunnel_id()?, Protocol::LongPoll)
                }
                Err(e) => Err(e),
            };
        }
        match self.dial_ws(ep) {
            Ok(t) => Ok(t),
            Err(e) if self.cfg.reverse.transport == Protocol::Auto => {
                let next = if super::client_http::http_fallback_allowed(&e) {
                    Some(Protocol::HttpSse)
                } else {
                    None
                };
                if let Some(next) = next {
                    self.modes.lock().unwrap().insert(
                        ep.id.clone(),
                        EndpointMode {
                            mode: next,
                            since: Instant::now(),
                        },
                    );
                    self.record_fallback("ws", "http-sse");
                    super::client_http::dial(self, ep, &super::new_tunnel_id()?, next)
                } else {
                    Err(e)
                }
            }
            Err(e) => Err(e),
        }
    }

    fn dial_ws(&self, ep: &crate::config::Endpoint) -> Result<Arc<LiveTunnel>> {
        let id = super::new_tunnel_id()?;
        let url = ep.url.clone();
        // Capture one live snapshot for this handshake; rotation affects only
        // the next handshake, never an active tunnel.
        let token = match &self.auth {
            Some(auth) => auth
                .reverse_token(&self.cfg.reverse.peer_node_id)
                .ok_or_else(|| {
                    Error::new(
                        crate::config::CODE_CREDENTIAL,
                        format!(
                            "missing reverse credential for peer {}",
                            self.cfg.reverse.peer_node_id
                        ),
                    )
                })?,
            None if !self.cfg.reverse.token.is_empty() => self.cfg.reverse.token.clone(),
            None => {
                return Err(Error::new(
                    crate::config::CODE_CREDENTIAL,
                    "missing reverse credential",
                ))
            }
        };
        let headers = vec![
            (wire::H_PEER_AUTH.to_string(), format!("Bearer {token}")),
            (H_NODE_ID.to_string(), self.cfg.node.id.clone()),
            (
                wire::H_INSTANCE_ID.to_string(),
                self.cfg.node.instance_id.clone(),
            ),
            (
                H_EXPECTED_NODE_ID.to_string(),
                self.cfg.reverse.peer_node_id.clone(),
            ),
            (H_TUNNEL_ID.to_string(), id.clone()),
            (H_TUNNEL_PRIORITY.to_string(), ep.priority.to_string()),
        ];
        let timeout = self
            .cfg
            .transport
            .ws_handshake_timeout
            .max(Duration::from_secs(5));
        let stream = crate::net::dial(&url.host, url.port, timeout).map_err(|e| {
            Error::new(
                wire::ERR_TUNNEL_NOT_FOUND,
                format!("dial {}: {e}", url.authority()),
            )
            .retryable(true)
        })?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        #[cfg(feature = "tls")]
        let mut conn = if url.is_tls() {
            let tls = connect_wss_tls(
                stream,
                &url.host,
                self.cfg.reverse.tls.ca_file.as_deref(),
                self.cfg.reverse.tls.verify,
                timeout.min(Duration::from_secs(5)),
            )?;
            BufferedConn::new(tls)
        } else {
            BufferedConn::new(stream)
        };
        #[cfg(not(feature = "tls"))]
        let mut conn = BufferedConn::new(stream);
        let (head, key) =
            ws::client_handshake_head_proto(&url, PATH_REVERSE, REVERSE_SUBPROTOCOL, &headers)?;
        conn.write_all(head.as_bytes())?;
        conn.flush()?;

        let (status, resp_headers) = crate::net::http1::read_response_head(&mut conn)?;
        if status != 101 {
            let body = header(&resp_headers, "content-length")
                .and_then(|v| v.parse::<usize>().ok())
                .filter(|n| *n <= 32 * 1024)
                .and_then(|n| conn.read_exact_vec(n).ok())
                .unwrap_or_default();
            return Err(super::client_http::ws_refusal(status, &resp_headers, &body));
        }
        ws::verify_server_handshake_proto(status, &resp_headers, &key, REVERSE_SUBPROTOCOL)?;
        if header(&resp_headers, "sec-websocket-protocol") != Some(REVERSE_SUBPROTOCOL) {
            return Err(Error::new(
                wire::ERR_PROTOCOL_MISMATCH,
                "tunnel handshake: subprotocol mismatch",
            ));
        }
        // The public side proves its identity after the transport: the token
        // authenticated us to it, these headers authenticate it to us.
        if header(&resp_headers, H_NODE_ID) != Some(self.cfg.reverse.peer_node_id.as_str()) {
            return Err(Error::new(
                wire::ERR_NODE_MISMATCH,
                "tunnel peer node mismatch",
            ));
        }
        if header(&resp_headers, wire::H_INSTANCE_ID)
            .unwrap_or("")
            .is_empty()
        {
            return Err(Error::new(
                wire::ERR_PROTOCOL_MISMATCH,
                "tunnel handshake: no instance id",
            ));
        }
        // The handshake timeouts end here: `split_tunnel` puts the socket on
        // the multiplexer's keepalive window instead.
        let _ = conn.set_read_timeout(None);

        // The side that dialed the tunnel takes even stream ids.
        let session = split_tunnel(conn, true, mux_config(&self.cfg.transport), Opener::Even)?;
        let tunnel = Arc::new(LiveTunnel {
            id: id.clone(),
            endpoint: ep.id.clone(),
            priority: ep.priority,
            transport: "ws".to_string(),
            session: session.clone(),
        });
        self.live.lock().unwrap().insert(id.clone(), tunnel.clone());
        Ok(tunnel)
    }

    fn refuse_stream(&self, tunnel: &LiveTunnel, stream: crate::mux::Stream) {
        crate::slog::debug(
            "reverse tunnel stream refused: codec budget or stream bound",
            &[
                ("tunnel", tunnel.id.as_str().into()),
                ("streams", tunnel.session.num_streams().into()),
            ],
        );
        let _ = crate::net::Conn::shutdown_both(&stream);
    }

    /// Delivers the streams of a tunnel to the listener until it ends.
    fn serve(&self, tunnel: Arc<LiveTunnel>) {
        loop {
            if self.stopping() {
                break;
            }
            match tunnel.session.accept(Duration::from_millis(500)) {
                Ok(Some(stream)) => {
                    crate::egress::log_debug(&format!(
                        "reverse tunnel {}: stream {} opened by the public side",
                        tunnel.id,
                        stream.id()
                    ));
                    let resources = self.metrics.as_ref().and_then(|m| m.resource_manager());
                    let lease = match &resources {
                        Some(r) => {
                            r.mark_instrumented("codec");
                            let window = i64::try_from(self.cfg.transport.tunnel_stream_window())
                                .unwrap_or(i64::MAX);
                            match r.try_codec_keep(window) {
                                Some(lease) => Some(lease),
                                None => {
                                    self.refuse_stream(&tunnel, stream);
                                    continue;
                                }
                            }
                        }
                        None => None,
                    };
                    if tunnel.session.num_streams() > crate::tunnel::MAX_STREAMS_PER_TUNNEL {
                        drop(lease);
                        self.refuse_stream(&tunnel, stream);
                        continue;
                    }
                    let conn: Box<dyn Conn> = match lease {
                        Some(lease) => {
                            Box::new(crate::net::LeasedConn::new(Box::new(stream), lease))
                        }
                        None => Box::new(stream),
                    };
                    if !self.listener.deliver(conn) {
                        break;
                    }
                }
                Ok(None) => {
                    if tunnel.session.is_closed() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        tunnel.session.close();
        self.live.lock().unwrap().remove(&tunnel.id);
        if let Some(metrics) = &self.metrics {
            metrics.reverse_tunnel_closed(&tunnel.endpoint, &tunnel.transport, !self.stopping());
        }
        self.wake_cv.notify_all();
        crate::slog::info(
            "reverse tunnel lost",
            &[
                ("endpoint", tunnel.endpoint.as_str().into()),
                ("tunnel", tunnel.id.as_str().into()),
            ],
        );
    }
}

#[cfg(feature = "tls")]
fn connect_wss_tls(
    stream: std::net::TcpStream,
    host: &str,
    ca_file: Option<&std::path::Path>,
    verify: bool,
    timeout: Duration,
) -> std::io::Result<crate::net::tls::TlsConn> {
    let mut config = crate::net::tls::client_config(ca_file, verify)?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    crate::net::tls::TlsConn::connect_with_config(stream, host, Arc::new(config), timeout)
}

#[cfg(all(test, feature = "tls", feature = "h2"))]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;

    #[test]
    fn reverse_wss_tls_uses_http1_alpn_and_completes_upgrade() {
        let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/net/testdata");
        let cert = fixtures.join("localhost-cert.pem");
        let key = fixtures.join("localhost-key.pem");
        let ca = fixtures.join("localhost-ca.pem");
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_config = Arc::new(crate::net::tls::server_config(&cert, &key).unwrap());
        let url = crate::net::Url::parse(&format!("https://localhost:{port}/base")).unwrap();
        let expected_path = url.path(PATH_REVERSE);
        let (alpn_tx, alpn_rx) = mpsc::channel();

        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let tls = crate::net::tls::TlsConn::accept_with_config(
                socket,
                server_config,
                Duration::from_secs(5),
            )
            .unwrap();
            let alpn = tls.alpn_protocol();
            tls.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            tls.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut conn = BufferedConn::new(tls);
            let request = crate::net::http1::read_request_head(&mut conn)
                .unwrap()
                .unwrap();
            assert_eq!(request.method, "GET");
            assert_eq!(request.path, expected_path);
            assert_eq!(request.version, "HTTP/1.1");
            assert!(request.is_websocket_upgrade());
            assert_eq!(
                request.header("sec-websocket-protocol"),
                Some(REVERSE_SUBPROTOCOL)
            );
            let key = request.header("sec-websocket-key").unwrap().to_string();
            let accept = ws::accept_key(&key);
            let response = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\nSec-WebSocket-Protocol: {REVERSE_SUBPROTOCOL}\r\n\r\n"
            );
            conn.write_all(response.as_bytes()).unwrap();
            conn.flush().unwrap();
            alpn_tx.send(alpn).unwrap();
        });

        let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let tls =
            connect_wss_tls(stream, &url.host, Some(&ca), true, Duration::from_secs(5)).unwrap();
        assert_eq!(tls.alpn_protocol(), Some(b"http/1.1".to_vec()));
        tls.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        tls.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut conn = BufferedConn::new(tls);
        let (head, request_key) =
            ws::client_handshake_head_proto(&url, PATH_REVERSE, REVERSE_SUBPROTOCOL, &[]).unwrap();
        conn.write_all(head.as_bytes()).unwrap();
        conn.flush().unwrap();
        let (status, headers) = crate::net::http1::read_response_head(&mut conn).unwrap();
        assert_eq!(status, 101);
        ws::verify_server_handshake_proto(status, &headers, &request_key, REVERSE_SUBPROTOCOL)
            .unwrap();
        assert_eq!(
            crate::net::header(&headers, "sec-websocket-protocol"),
            Some(REVERSE_SUBPROTOCOL)
        );
        assert_eq!(
            alpn_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            Some(b"http/1.1".to_vec())
        );
        server.join().unwrap();
    }
}

fn backoff(min: Duration, max: Duration, n: usize) -> std::io::Result<Duration> {
    let lo = if min.is_zero() {
        Duration::from_millis(500)
    } else {
        min
    };
    let hi = max.max(lo);
    let mut d = lo;
    let mut i = 1;
    while i < n && d < hi {
        d = d.saturating_mul(2);
        i += 1;
    }
    let d = d.min(hi);
    let half = u64::try_from(d.as_nanos() / 2).unwrap_or(u64::MAX);
    if half == 0 {
        return Ok(d);
    }
    let jitter = crate::util::random_u64()? % half.saturating_add(1);
    Ok(Duration::from_nanos(half.saturating_add(jitter)))
}

#[cfg(test)]
mod spec_backoff_tests {
    use super::backoff;
    use std::time::Duration;

    #[test]
    fn spec_backoff() {
        let ms = Duration::from_millis;
        for (n, want) in [
            (1, ms(100)),
            (2, ms(200)),
            (3, ms(400)),
            (5, ms(1000)),
            (20, ms(1000)),
        ] {
            for _ in 0..20 {
                let d = backoff(ms(100), ms(1000), n).unwrap();
                assert!(
                    d >= want / 2 && d <= want,
                    "backoff({n}) = {d:?}, want in [{:?}, {want:?}]",
                    want / 2
                );
            }
        }
    }
}

#[cfg(test)]
#[path = "spec_client2_tests.rs"]
mod spec_client2_tests;
