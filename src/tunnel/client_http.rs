use std::io;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::config::{Endpoint, Protocol};
use crate::error::{Error, Result};
use crate::mux::Opener;
use crate::net::http1::{BodyReader, Client as HttpClient};
use crate::net::Url;
use crate::util::base64;
use crate::wire;

use super::client::{Client, LiveTunnel};
use super::http;
#[cfg(test)]
use super::http::Fallback;
use super::pipe::{Pipe, ReceiveError};
use super::{
    mux_config, split_pipe, H_EXPECTED_NODE_ID, H_NODE_ID, H_TUNNEL_ID, H_TUNNEL_PRIORITY,
    PATH_REVERSE, REVERSE_SUBPROTOCOL,
};

const OPEN: &str = "/open";
const EVENTS: &str = "/events";
const POLL: &str = "/poll";
const UP: &str = "/up";
const MAX_SSE_LINE: usize = http::SSE_CHUNK * 4 / 3 + 64;
const RETRY: Duration = Duration::from_millis(100);
type ReadySignal = mpsc::Sender<std::result::Result<(), String>>;
type ReadyState = Arc<Mutex<Option<ReadySignal>>>;

#[derive(Debug)]
struct Refusal {
    status: u16,
    code: Option<String>,
    identity: bool,
}
impl Refusal {
    fn error(self) -> Error {
        Error::new(
            self.code.as_deref().unwrap_or(""),
            format!("HTTP reverse handshake refused ({})", self.status),
        )
        .remote_status(self.status)
        .trusted(self.identity)
        .retryable(false)
    }
}

fn headers(c: &Client, ep: &Endpoint, id: &str, mode: &str) -> Vec<(String, String)> {
    let token = match &c.auth {
        Some(a) => a
            .reverse_token(&c.cfg.reverse.peer_node_id)
            .unwrap_or_default(),
        None => c.cfg.reverse.token.clone(),
    };
    vec![
        (wire::H_PEER_AUTH.into(), format!("Bearer {token}")),
        (wire::H_INSTANCE_ID.into(), c.cfg.node.instance_id.clone()),
        (H_NODE_ID.into(), c.cfg.node.id.clone()),
        (
            H_EXPECTED_NODE_ID.into(),
            c.cfg.reverse.peer_node_id.clone(),
        ),
        (H_TUNNEL_ID.into(), id.into()),
        (H_TUNNEL_PRIORITY.into(), ep.priority.to_string()),
        ("X-DBB-Reverse-Protocol".into(), REVERSE_SUBPROTOCOL.into()),
        ("X-DBB-Tunnel-Transport".into(), mode.into()),
        ("Cache-Control".into(), "no-store".into()),
    ]
}
fn path(id: &str, suffix: &str) -> String {
    format!("{PATH_REVERSE}/{id}{suffix}")
}
fn refusal(resp: &crate::net::http1::Response) -> Refusal {
    let code = if resp.body.windows(7).any(|w| w == b"DBB_") {
        let s = String::from_utf8_lossy(&resp.body);
        s.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .find(|x| x.starts_with("DBB_"))
            .map(str::to_string)
    } else {
        None
    };
    Refusal {
        status: resp.status,
        code,
        identity: resp.header(wire::H_INSTANCE_ID).is_some(),
    }
}

pub(crate) fn http_fallback_allowed(e: &Error) -> bool {
    e.remote_status != Some(401)
        && e.remote_status.is_some()
        && ((!e.trusted && e.code.is_empty())
            || (e.trusted && e.code == wire::ERR_TRANSPORT_UNSUPPORTED))
}

pub(crate) fn sse_ready_timeout(e: &Error) -> bool {
    e.code.is_empty() && e.message == "SSE stream buffered: the ready event did not arrive in time"
}

pub(crate) fn ws_refusal(status: u16, headers: &[(String, String)], body: &[u8]) -> Error {
    let identity = crate::net::header(headers, wire::H_INSTANCE_ID).is_some();
    let code = extract_code(body);
    Error::new(
        code.as_deref().unwrap_or(""),
        format!("HTTP reverse handshake refused ({status})"),
    )
    .remote_status(status)
    .trusted(identity)
    .retryable(false)
}

fn extract_code(body: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(body);
    text.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .find(|x| x.starts_with("DBB_"))
        .map(str::to_string)
}

pub(crate) fn dial(c: &Client, ep: &Endpoint, id: &str, mode: Protocol) -> Result<Arc<LiveTunnel>> {
    let mode_name = mode_name(mode);
    let codec_lease = match c.metrics.as_ref().and_then(|m| m.resource_manager()) {
        Some(resources) => {
            resources.mark_instrumented("codec");
            Some(
                resources
                    .try_codec_keep(super::http_tunnel_budget())
                    .ok_or_else(|| {
                        Error::local("codec budget exhausted for a tunnel carrier buffer")
                    })?,
            )
        }
        None => None,
    };
    let timeout = c
        .cfg
        .transport
        .ws_handshake_timeout
        .max(Duration::from_secs(5));
    let request_timeout = if mode == Protocol::LongPoll {
        timeout.max(Duration::from_secs(30))
    } else {
        timeout
    };
    let httpc = HttpClient::new_with_tls(
        c.cfg.transport.dial_timeout.max(Duration::from_secs(5)),
        request_timeout,
        c.cfg.reverse.tls.clone(),
    );
    let u = ep.url.clone();
    let hs = headers(c, ep, id, mode_name);
    let r = httpc.request(&u, "POST", &path(id, OPEN), &hs, None)?;
    if r.status != 200 {
        return Err(refusal(&r).error());
    }
    if r.header(H_NODE_ID) != Some(c.cfg.reverse.peer_node_id.as_str()) {
        return Err(Error::new(
            wire::ERR_NODE_MISMATCH,
            "reverse HTTP peer node mismatch",
        ));
    }
    if r.header("X-DBB-Reverse-Protocol") != Some(REVERSE_SUBPROTOCOL)
        || r.header(wire::H_INSTANCE_ID).unwrap_or("").is_empty()
    {
        return Err(Error::new(
            wire::ERR_PROTOCOL_MISMATCH,
            "reverse HTTP protocol mismatch",
        ));
    }
    let pipe = Pipe::new("tunnel", format!("tunnel/{id}"));
    let session = split_pipe(pipe.clone(), mux_config(&c.cfg.transport), Opener::Even);
    if let Some(lease) = codec_lease {
        session.hold_until_closed(Box::new(lease));
    }
    let carrier = Arc::new(Carrier {
        client: httpc,
        url: u,
        headers: hs,
        id: id.to_string(),
        mode: mode_name.to_string(),
        pipe: pipe.clone(),
        cancel: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        timeout,
        ready: Arc::new(Mutex::new(None)),
    });
    let up = carrier.clone();
    thread::spawn(move || up.upload_loop());
    let down = carrier.clone();
    if mode == Protocol::HttpSse {
        let (tx, rx) = mpsc::channel();
        *carrier.ready.lock().unwrap() = Some(tx);
        thread::spawn(move || down.download_loop());
        match rx.recv_timeout(timeout) {
            Ok(Ok(())) => {}
            Ok(Err(message)) => {
                carrier.pipe.close_with(Some(io::ErrorKind::InvalidData));
                return Err(Error::local(message));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                carrier.pipe.close_with(Some(io::ErrorKind::TimedOut));
                return Err(Error::local(
                    "SSE stream buffered: the ready event did not arrive in time",
                ));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                carrier
                    .pipe
                    .close_with(Some(io::ErrorKind::ConnectionAborted));
                return Err(Error::local("SSE stream ended before ready"));
            }
        }
    } else {
        thread::spawn(move || down.download_loop());
    }
    Ok(Arc::new(LiveTunnel {
        id: id.to_string(),
        endpoint: ep.id.clone(),
        priority: ep.priority,
        transport: mode_name.to_string(),
        session,
    }))
}
fn mode_name(m: Protocol) -> &'static str {
    match m {
        Protocol::HttpSse => "http-sse",
        Protocol::LongPoll => "long-poll",
        _ => "http-sse",
    }
}

fn is_sse_data_event(event: &str, data: &str) -> bool {
    !data.is_empty() && (event.is_empty() || event == "data")
}

struct Carrier {
    client: HttpClient,
    url: Url,
    headers: Vec<(String, String)>,
    id: String,
    mode: String,
    pipe: Pipe,
    cancel: Arc<std::sync::atomic::AtomicBool>,
    timeout: Duration,
    ready: ReadyState,
}

impl Drop for Carrier {
    fn drop(&mut self) {
        self.cancel
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let headers = self.common();
        let _ = self
            .client
            .request(&self.url, "DELETE", &path(&self.id, ""), &headers, None);
    }
}

impl Carrier {
    fn signal_ready(&self, result: std::result::Result<(), String>) {
        if let Some(tx) = self.ready.lock().unwrap().take() {
            let _ = tx.send(result);
        }
    }
    fn common(&self) -> Vec<(String, String)> {
        self.headers.clone()
    }
    fn upload_loop(self: Arc<Self>) {
        let mut acked = 0i64;
        while !self.cancel.load(std::sync::atomic::Ordering::Relaxed) && !self.pipe.is_closed() {
            let Some((off, mut data)) = self.pipe.wait_for_data(acked, self.timeout) else {
                thread::sleep(RETRY);
                continue;
            };
            data.truncate(http::MAX_UPLOAD);
            let recv = self.pipe.received();
            let digest = crate::util::sha256::digest(&data);
            let mut h = self.common();
            h.extend([
                (wire::H_OFFSET.into(), off.to_string()),
                (
                    wire::H_SHA256.into(),
                    digest.iter().map(|b| format!("{b:02x}")).collect(),
                ),
                (wire::H_ACK_DOWN_OFFSET.into(), recv.to_string()),
                ("Content-Type".into(), "application/octet-stream".into()),
            ]);
            match self
                .client
                .request(&self.url, "POST", &path(&self.id, UP), &h, Some(&data))
            {
                Ok(r) if r.status == 200 => {
                    if let Some(v) = r
                        .header(wire::H_CONFIRM_UP_OFFSET)
                        .and_then(|v| v.parse().ok())
                    {
                        if self.pipe.ack(v).is_ok() {
                            acked = acked.max(v);
                        } else {
                            self.pipe.close_with(Some(io::ErrorKind::InvalidData));
                            break;
                        }
                    }
                }
                Ok(r) => {
                    let f = refusal(&r);
                    if f.code.as_deref() == Some(wire::ERR_TUNNEL_NOT_FOUND)
                        || f.code.is_some() && f.code.as_deref() != Some(wire::ERR_BUFFER_EXHAUSTED)
                    {
                        self.pipe.close_with(Some(io::ErrorKind::ConnectionAborted));
                        break;
                    }
                    thread::sleep(RETRY);
                }
                Err(_) => thread::sleep(RETRY),
            }
        }
    }
    fn download_loop(self: Arc<Self>) {
        if self.mode == "http-sse" {
            self.sse_loop();
        } else {
            self.poll_loop();
        }
    }
    fn poll_loop(&self) {
        while !self.pipe.is_closed() {
            let mut h = self.common();
            h.push((
                wire::H_ACK_DOWN_OFFSET.into(),
                self.pipe.received().to_string(),
            ));
            match self
                .client
                .request(&self.url, "GET", &path(&self.id, POLL), &h, None)
            {
                Ok(r) if r.status == 204 => {}
                Ok(r) if r.status == 200 => {
                    if let Some((off, body)) =
                        http::parse_poll_response(r.status, r.header(wire::H_OFFSET), &r.body)
                    {
                        if self.pipe.receive(off, body, self.timeout).is_err() {
                            self.pipe.close_with(Some(io::ErrorKind::InvalidData));
                            break;
                        }
                    } else {
                        self.pipe.close_with(Some(io::ErrorKind::InvalidData));
                        break;
                    }
                }
                Ok(r) => {
                    let f = refusal(&r);
                    if f.code.as_deref() == Some(wire::ERR_TUNNEL_NOT_FOUND)
                        || f.code.is_some() && f.code.as_deref() != Some(wire::ERR_BUFFER_EXHAUSTED)
                    {
                        self.pipe.close_with(Some(io::ErrorKind::ConnectionAborted));
                        break;
                    }
                    thread::sleep(RETRY);
                }
                Err(_) => thread::sleep(RETRY),
            }
        }
    }
    fn sse_loop(&self) {
        let mut first = true;
        while !self.pipe.is_closed() {
            let mut h = self.common();
            h.extend([
                ("Accept".into(), "text/event-stream".into()),
                (
                    wire::H_ACK_DOWN_OFFSET.into(),
                    self.pipe.received().to_string(),
                ),
            ]);
            match self
                .client
                .stream(&self.url, "GET", &path(&self.id, EVENTS), &h, self.timeout)
            {
                Ok((mut body, r)) if r.status == 200 => {
                    if let Err(e) = self.read_sse(&mut body, &mut first) {
                        if first {
                            self.signal_ready(Err(e.to_string()));
                        }
                        thread::sleep(RETRY);
                    }
                }
                Ok((_, r)) => {
                    if first {
                        let f = refusal(&r);
                        self.signal_ready(Err(f.error().message));
                    }
                    if r.status == 503 {
                        thread::sleep(RETRY);
                    } else {
                        self.pipe.close_with(Some(io::ErrorKind::ConnectionAborted));
                        break;
                    }
                }
                Err(e) => {
                    if first {
                        self.signal_ready(Err(e.message));
                    }
                    thread::sleep(RETRY);
                }
            }
        }
    }
    fn read_sse(&self, body: &mut BodyReader, first: &mut bool) -> io::Result<()> {
        let mut event = String::new();
        let mut id = String::new();
        let mut data = String::new();
        loop {
            let line = body.read_line(MAX_SSE_LINE)?;
            if !line.is_empty() {
                if let Some(v) = line.strip_prefix("event:") {
                    event = v.trim().into();
                } else if let Some(v) = line.strip_prefix("id:") {
                    id = v.trim().into();
                } else if let Some(v) = line.strip_prefix("data:") {
                    data.push_str(v.trim());
                }
                continue;
            }
            if event == "ready" {
                let off: i64 = data.parse().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "bad SSE ready offset")
                })?;
                if off < 0 || off != self.pipe.received() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "bad SSE ready offset",
                    ));
                }
                *first = false;
                self.signal_ready(Ok(()));
            } else if is_sse_data_event(&event, &data) {
                if *first {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SSE data arrived before ready",
                    ));
                }
                let off: i64 = id
                    .parse()
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad SSE offset"))?;
                if off < 0 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "bad SSE offset"));
                }
                let bytes = base64::decode(&data)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad SSE base64"))?;
                if bytes.len() > http::SSE_CHUNK {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SSE chunk too large",
                    ));
                }
                match self.pipe.receive(off, &bytes, self.timeout) {
                    Ok(_) => {}
                    Err(ReceiveError::Gap(_)) => {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "SSE offset gap"))
                    }
                    Err(_) => return Ok(()),
                }
            }
            event.clear();
            id.clear();
            data.clear();
        }
    }
}

// Kept as a unit-test compatibility seam; production fallback uses the client path.
#[cfg(test)]
#[allow(dead_code)]
fn fallback(
    mode: &str,
    status: u16,
    code: Option<&str>,
    identity: bool,
    ready_buffered: bool,
) -> Fallback {
    http::classify_fallback_identity(mode, status, code, identity, ready_buffered)
}

#[cfg(test)]
mod tests {
    use super::is_sse_data_event;

    #[test]
    fn accepts_standard_default_message_data_event() {
        assert!(is_sse_data_event("", "AQID"));
        assert!(is_sse_data_event("data", "AQID"));
        assert!(!is_sse_data_event("", ""));
        assert!(!is_sse_data_event("ready", "0"));
        assert!(!is_sse_data_event("unknown", "AQID"));
    }
}
