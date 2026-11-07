use super::Server;
use crate::net::http1::Request;
use crate::net::ws::Message;
use crate::net::BufferedConn;
use crate::wire;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(super) struct Node {
    pub(super) server: Arc<Server>,
    pub(super) dir: std::path::PathBuf,
}

impl Drop for Node {
    fn drop(&mut self) {
        self.server.request_shutdown();
        self.server.registry.close_all();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

pub(super) fn echo_backend() -> String {
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = ln.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for c in ln.incoming() {
            let Ok(mut c) = c else { return };
            std::thread::spawn(move || {
                let mut buf = [0u8; 1024];
                loop {
                    match c.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if c.write_all(&buf[..n]).is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

pub(super) fn node(extra_transport: &str) -> Node {
    let dir = std::env::temp_dir().join(format!(
        "dbb-egress-gows3-{}",
        crate::util::random_hex(6).unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("tok-A"), "tokA").unwrap();
    let text = format!(
        "node:\n  id: B\nhttp:\n  enabled: true\n  listen: \"127.0.0.1:0\"\n  allowed_transports: [ws, http-sse]\ntargets:\n  db:\n    network: tcp\n    address: \"{}\"\nauth:\n  inbound_peers:\n    - id: A\n      token_files: [tok-A]\n      allowed_targets: [db]\n      max_sessions: 5\nlimits:\n  max_sessions: 8\ntransport:\n  max_frame_size: 1024\n  buffer_per_direction: 4096\n  up_window_bytes: 2048\n  up_max_inflight_frames: 8\n  dial_timeout: 1s\n  unattached_timeout: 30s\n{extra_transport}",
        echo_backend()
    );
    let path = dir.join("config.yaml");
    std::fs::write(&path, text).unwrap();
    let cfg = Arc::new(crate::config::load(&path).unwrap_or_else(|e| panic!("{}", e.message)));
    let metrics = Arc::new(crate::metrics::Metrics::new());
    metrics.configure_resources(&cfg);
    let server = Arc::new(Server::new(cfg, metrics));
    Node { server, dir }
}

pub(super) fn listen(n: &Node) -> SocketAddr {
    let server = n.server.clone();
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
    std::thread::spawn(move || {
        let _ = server.listen(shutdown);
    });
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(addr) = *n.server.accept_addr.lock().unwrap() {
            return addr;
        }
        assert!(Instant::now() < deadline, "egress listener did not start");
        std::thread::sleep(Duration::from_millis(5));
    }
}

pub(super) fn request(
    method: &str,
    path: &str,
    headers: Vec<(String, String)>,
    body: &str,
) -> Request {
    Request {
        method: method.to_string(),
        path: path.to_string(),
        query: Vec::new(),
        version: "HTTP/1.1".to_string(),
        headers,
        body: body.as_bytes().to_vec(),
    }
}

pub(super) fn headers(n: &Node, token: &str, instance: Option<&str>) -> Vec<(String, String)> {
    let mut h = vec![(wire::H_PEER_AUTH.to_string(), format!("Bearer {token}"))];
    h.push((
        wire::H_INSTANCE_ID.to_string(),
        instance
            .map(str::to_string)
            .unwrap_or_else(|| n.server.cfg.node.instance_id.clone()),
    ));
    h
}

pub(super) fn create_body(
    id: &str,
    target: &str,
    mode: &str,
    version: &str,
    limits: &str,
) -> String {
    format!(
        "{{\"protocol_version\":\"{version}\",\"transport\":{{\"mode\":\"{mode}\"}},\"recovery\":{{\"enabled\":false,\"grace_ms\":0}},\"create_request_id\":\"{id}\",\"ingress_instance_id\":\"ai\",\"target_id\":\"{target}\",\"limits\":{limits}}}"
    )
}

pub(super) const LIMITS: &str = r#"{"max_frame_size":1024,"up_max_inflight_frames":8,"up_window_bytes":2048,"down_buffer_bytes":4096}"#;

pub(super) fn route_create(n: &Node, instance: Option<&str>, body: &str) -> (u16, String) {
    let (status, body, _) = n.server.route(&request(
        "POST",
        wire::PATH_SESSIONS,
        headers(n, "tokA", instance),
        body,
    ));
    (status, String::from_utf8_lossy(&body).to_string())
}

pub(super) fn code(body: &str) -> String {
    wire::ErrorBody::parse(body)
        .map(|e| e.code)
        .unwrap_or_default()
}

pub(super) fn ws_create(n: &Node, id: &str) -> wire::CreateResponse {
    let (status, body) = route_create(
        n,
        None,
        &create_body(id, "db", "ws", wire::PROTOCOL_VERSION, LIMITS),
    );
    assert_eq!(status, 201, "create {id}: {body}");
    wire::CreateResponse::from_json(&crate::util::json::parse(&body).unwrap()).unwrap()
}

/// One raw GET /v1/transport/ws request; `upgrade` adds the WebSocket
/// upgrade headers with the given version and key (None omits the key).
pub(super) fn ws_request(
    addr: SocketAddr,
    headers: &[(String, String)],
    upgrade: Option<(&str, Option<&str>)>,
) -> (u16, Vec<(String, String)>, BufferedConn) {
    let mut c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut head = format!("GET {} HTTP/1.1\r\nHost: x\r\n", wire::PATH_WS);
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    if let Some((version, key)) = upgrade {
        head.push_str(&format!(
            "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: {version}\r\n"
        ));
        if let Some(key) = key {
            head.push_str(&format!("Sec-WebSocket-Key: {key}\r\n"));
        }
    }
    head.push_str("\r\n");
    c.write_all(head.as_bytes()).unwrap();
    let mut conn = BufferedConn::new(c);
    let (status, resp_headers) = crate::net::http1::read_response_head(&mut conn).unwrap();
    (status, resp_headers, conn)
}

pub(super) fn ws_header(n: &Node, cr: &wire::CreateResponse) -> Vec<(String, String)> {
    let mut h = headers(n, "tokA", None);
    h.extend([
        (wire::H_WS_PURPOSE.to_string(), "session".to_string()),
        (wire::H_WS_SESSION_ID.to_string(), cr.session_id.clone()),
        (wire::H_SESSION_TOKEN.to_string(), cr.session_token.clone()),
        (wire::H_WS_EPOCH.to_string(), "1".to_string()),
        (
            "Sec-WebSocket-Protocol".to_string(),
            wire::WS_SUBPROTOCOL.to_string(),
        ),
    ]);
    h
}

pub(super) const KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";

/// The JSON error body of a refused (non-101) answer.
pub(super) fn error_of(headers: &[(String, String)], mut conn: BufferedConn) -> wire::ErrorBody {
    let len: usize = crate::net::header(headers, "content-length")
        .and_then(|v| v.parse().ok())
        .expect("content-length");
    let rest = conn.read_exact_vec(len).unwrap();
    let text = String::from_utf8_lossy(&rest).to_string();
    let start = text.find('{').unwrap_or(0);
    wire::ErrorBody::parse(&text[start..]).unwrap_or_else(|| panic!("error body: {text:?}"))
}

pub(super) type WsPair = (
    crate::net::ws::WsReader,
    Arc<std::sync::Mutex<crate::net::ws::WsWriter>>,
);

pub(super) fn ws_dial(
    addr: SocketAddr,
    h: &[(String, String)],
) -> Result<WsPair, (u16, wire::ErrorBody)> {
    let (status, headers, conn) = ws_request(addr, h, Some(("13", Some(KEY))));
    if status != 101 {
        return Err((status, error_of(&headers, conn)));
    }
    Ok(crate::net::ws::split(conn, true).unwrap())
}

#[test]
pub(super) fn spec_ws_requires_subprotocol_and_instance() {
    let n = node("");
    let addr = listen(&n);
    let h = vec![
        (wire::H_PEER_AUTH.to_string(), "Bearer tokA".to_string()),
        (wire::H_WS_PURPOSE.to_string(), "check".to_string()),
        (wire::H_WS_NONCE.to_string(), "nonce".to_string()),
    ];
    let (status, resp_headers, _) = ws_request(addr, &h, Some(("13", Some(KEY))));
    assert_ne!(
        status, 101,
        "101 allowed without instance or required subprotocol; headers={resp_headers:?}"
    );
}

#[test]
fn spec_malformed_ws_handshake_leaves_session_attachable() {
    let n = node("");
    let addr = listen(&n);
    let cr = ws_create(&n, "w1");
    for (name, version, key) in [
        ("version 8", "8", Some(KEY)),
        ("no key", "13", None),
        ("short key", "13", Some("c2hvcnQ=")),
        ("invalid key", "13", Some("not base64!")),
    ] {
        let (status, headers, conn) = ws_request(addr, &ws_header(&n, &cr), Some((version, key)));
        let er = error_of(&headers, conn);
        assert!(
            status == 400 && er.code == wire::ERR_BAD_FRAME,
            "{name}: {status} {}",
            er.code
        );
    }
    let sess = n.server.registry.get(&cr.session_id).unwrap();
    assert!(
        !sess.is_closed(),
        "malformed handshake closed the session: {:?}",
        sess.terminal_error()
    );
    assert!(
        ws_dial(addr, &ws_header(&n, &cr)).is_ok(),
        "session not attachable after malformed handshakes"
    );
}

fn read_ws_terminal_error(reader: &mut crate::net::ws::WsReader) -> wire::ErrorBody {
    reader.set_read_deadline(Some(Instant::now() + Duration::from_secs(5)));
    loop {
        match reader.read_message() {
            Ok(Some(Message::Text(text))) => {
                let v = crate::util::json::parse(&text).unwrap();
                if v.get("type").and_then(|t| t.as_str()) != Some("error") {
                    continue;
                }
                assert!(
                    text.contains(r#""retryable":false"#)
                        && text.contains(r#""session_closed":true"#),
                    "terminal error must carry retryable and session_closed: {text}"
                );
                assert!(
                    !matches!(
                        reader.read_message(),
                        Ok(Some(Message::Text(_)) | Some(Message::Binary(_)))
                    ),
                    "carrier stayed open after the terminal error message"
                );
                return wire::ErrorBody::parse(&text).unwrap();
            }
            Ok(Some(_)) => continue,
            other => panic!("carrier ended without a terminal error message: {other:?}"),
        }
    }
}

#[test]
fn spec_ws_session_errors() {
    let n = node("");
    let addr = listen(&n);
    let cr = ws_create(&n, "w1");
    let (status, _, _) = ws_request(addr, &ws_header(&n, &cr), None);
    assert_eq!(status, 400, "non-upgrade WS session request");
    let sess = n.server.registry.get(&cr.session_id).expect("session");
    assert!(!sess.is_closed(), "failed upgrade closed the session");
    let (mut reader, _writer) = ws_dial(addr, &ws_header(&n, &cr))
        .unwrap_or_else(|(s, _)| panic!("session still attachable: {s}"));
    // Wait for the ready message so the carrier is attached.
    reader.set_read_deadline(Some(Instant::now() + Duration::from_secs(5)));
    assert!(matches!(reader.read_message(), Ok(Some(Message::Text(_)))));
    sess.close(crate::error::Error::new(wire::ERR_BACKEND_LOST, "backend lost").closed(true));
    let notice = read_ws_terminal_error(&mut reader);
    assert!(
        notice.code == wire::ERR_BACKEND_LOST && notice.session_closed && !notice.retryable,
        "terminal notice: {notice:?}"
    );
    drop(reader);
    let (status, er) = match ws_dial(addr, &ws_header(&n, &cr)) {
        Ok(_) => panic!("closed session attached"),
        Err(e) => e,
    };
    assert!(
        status == 410 && er.code == wire::ERR_BACKEND_LOST && er.session_closed,
        "closed session: {status} {er:?}"
    );
}

#[test]
fn spec_ws_session_bidirectional_and_mismatch() {
    let n = node("");
    let addr = listen(&n);
    let (status, body) = route_create(
        &n,
        None,
        &create_body("cr_ws_test_01", "db", "ws", wire::PROTOCOL_VERSION, LIMITS),
    );
    assert_eq!(status, 201, "create session failed: {body}");
    let created =
        wire::CreateResponse::from_json(&crate::util::json::parse(&body).unwrap()).unwrap();
    assert!(
        body.contains(r#""mode":"ws""#),
        "create response transport: {body}"
    );

    let payload = b"test";
    let mut up_headers = headers(&n, "tokA", None);
    up_headers.extend([
        (
            wire::H_SESSION_TOKEN.to_string(),
            created.session_token.clone(),
        ),
        (wire::H_OFFSET.to_string(), "0".to_string()),
        (wire::H_LENGTH.to_string(), "4".to_string()),
        (
            wire::H_SHA256.to_string(),
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08".to_string(),
        ),
    ]);
    let mut up = request(
        "POST",
        &format!("{}/{}/up", wire::PATH_SESSIONS, created.session_id),
        up_headers,
        std::str::from_utf8(payload).unwrap(),
    );
    up.query = vec![("epoch".to_string(), "1".to_string())];
    let (status, _, _) = n.server.route(&up);
    assert_eq!(status, 409, "/up in ws mode");

    let (mut reader, writer) = ws_dial(addr, &ws_header(&n, &created))
        .unwrap_or_else(|(s, _)| panic!("ws session dial failed: {s}"));
    reader.set_read_deadline(Some(Instant::now() + Duration::from_secs(3)));
    let ready = match reader.read_message() {
        Ok(Some(Message::Text(text))) => text,
        other => panic!("expected ready TextMessage, got {other:?}"),
    };
    let rv = crate::util::json::parse(&ready).unwrap();
    let stream_id = rv
        .get("stream_id")
        .and_then(|s| s.as_str())
        .unwrap_or_default()
        .to_string();
    assert!(
        rv.get("type").and_then(|t| t.as_str()) == Some("ready")
            && !stream_id.is_empty()
            && rv.get("transport").and_then(|t| t.as_str()) == Some("ws"),
        "unexpected ready message: {ready}"
    );

    let mut ack_headers = headers(&n, "tokA", None);
    ack_headers.extend([
        (
            wire::H_SESSION_TOKEN.to_string(),
            created.session_token.clone(),
        ),
        (wire::H_STREAM_ID.to_string(), stream_id.clone()),
    ]);
    let mut ack = request(
        "POST",
        &format!("{}/{}/ack", wire::PATH_SESSIONS, created.session_id),
        ack_headers,
        &format!(
            // json.Marshal(protocol.AckRequest{...}): omitempty fields only when set.
            r#"{{"stream_id":"{stream_id}","ready_received":true,"down_delivered_offset":"0","down_fin_applied":false,"up_confirmed_offset":"0","data_tx_blocked":false,"data_rx_blocked":false,"backpressure_reason":""}}"#
        ),
    );
    ack.query = vec![("epoch".to_string(), "1".to_string())];
    let (status, body, _) = n.server.route(&ack);
    assert_eq!(
        status,
        200,
        "ack activation failed: {}",
        String::from_utf8_lossy(&body)
    );

    let test_payload = b"PING DATABASE VIA WS";
    writer
        .lock()
        .unwrap()
        .write_binary(&wire::encode_ws_frame(1, 0, test_payload).unwrap())
        .unwrap();
    let (mut got_ack_up, mut got_echo) = (false, false);
    reader.set_read_deadline(Some(Instant::now() + Duration::from_secs(3)));
    for i in 0..5 {
        if got_ack_up && got_echo {
            break;
        }
        match reader.read_message() {
            Ok(Some(Message::Text(text))) => {
                let v = crate::util::json::parse(&text).unwrap();
                if v.get("type").and_then(|t| t.as_str()) == Some("ack_up") {
                    got_ack_up = true;
                }
            }
            Ok(Some(Message::Binary(b))) => {
                if let Ok(f) = wire::decode_ws_frame(&b) {
                    if f.epoch == 1 && f.offset == 0 && f.payload == test_payload {
                        got_echo = true;
                    }
                }
            }
            other => panic!(
                "iter {i} error reading from ws (gotAckUp={got_ack_up}, gotEcho={got_echo}): {other:?}"
            ),
        }
    }
    assert!(got_ack_up, "expected ack_up control message on WS");
    assert!(
        got_echo,
        "expected binary echo frame from dummy backend on WS"
    );
}

#[test]
fn spec_create_session_validation_full() {
    let n = node("");
    let (status, body) = route_create(
        &n,
        None,
        &create_body("cr_bad_ver", "db", "ws", "1.2", LIMITS),
    );
    assert_eq!(status, 409, "bad protocol version: {body}");
    assert_eq!(code(&body), wire::ERR_PROTOCOL_MISMATCH);

    let ok = create_body(
        "cr_inst_mismatch",
        "db",
        "ws",
        wire::PROTOCOL_VERSION,
        LIMITS,
    );
    let (status, body) = route_create(&n, Some("wrong_instance_id"), &ok);
    assert_eq!(status, 409, "instance mismatch: {body}");
    assert_eq!(code(&body), wire::ERR_INSTANCE_MISMATCH);

    let (status, body) = route_create(&n, None, &ok);
    assert_eq!(status, 201, "valid create: {body}");

    let conflict = create_body(
        "cr_inst_mismatch",
        "different-target",
        "ws",
        wire::PROTOCOL_VERSION,
        LIMITS,
    );
    let (status, body) = route_create(&n, None, &conflict);
    assert_eq!(status, 409, "idempotency param conflict: {body}");
    assert_eq!(code(&body), wire::ERR_IDEMPOTENCY_CONFLICT);
}

#[test]
fn spec_boundary_negotiated_up_window_reported() {
    let n = node("");
    let limits = r#"{"max_frame_size":8,"up_max_inflight_frames":2,"up_window_bytes":16,"down_buffer_bytes":32}"#;
    let body = create_body(
        "negotiated-window",
        "db",
        "http-sse",
        wire::PROTOCOL_VERSION,
        limits,
    );
    let (status, text) = route_create(&n, None, &body);
    assert_eq!(status, 201, "{text}");
    let cr = wire::CreateResponse::from_json(&crate::util::json::parse(&text).unwrap()).unwrap();
    let sess = n.server.registry.get(&cr.session_id).unwrap();
    sess.attach("sse-stream").unwrap();
    let data = b"x";
    let mut h = headers(&n, "tokA", None);
    h.extend([
        (wire::H_SESSION_TOKEN.to_string(), cr.session_token.clone()),
        (wire::H_STREAM_ID.to_string(), "sse-stream".to_string()),
        (wire::H_OFFSET.to_string(), "0".to_string()),
        (wire::H_LENGTH.to_string(), "1".to_string()),
        (
            wire::H_SHA256.to_string(),
            crate::util::hex(&crate::util::sha256::digest(data)),
        ),
        (
            "Content-Type".to_string(),
            "application/octet-stream".to_string(),
        ),
        ("Content-Length".to_string(), "1".to_string()),
    ]);
    let mut up = request(
        "POST",
        &format!("{}/{}/up", wire::PATH_SESSIONS, cr.session_id),
        h,
        "x",
    );
    up.query = vec![("epoch".to_string(), "1".to_string())];
    let (status, resp, _) = n.server.route(&up);
    let resp = String::from_utf8_lossy(&resp).to_string();
    assert_eq!(status, 200, "{resp}");
    let v = crate::util::json::parse(&resp).unwrap();
    let off = |k: &str| -> u64 {
        v.get(k)
            .and_then(|x| x.as_str())
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("{k} in {resp}"))
    };
    let (ack, limit) = (off("ack_up_offset"), off("up_receive_limit"));
    assert_eq!(
        limit - ack,
        cr.limits.up_window_bytes,
        "up_receive_limit uses local maximum instead of negotiated window (ack={ack} limit={limit})"
    );
}

#[test]
fn spec_fin_ack_race() {
    let n = node("");
    for i in 0..100 {
        let (status, body) = route_create(
            &n,
            None,
            &create_body(
                &format!("race-{i}"),
                "db",
                "http-sse",
                wire::PROTOCOL_VERSION,
                LIMITS,
            ),
        );
        assert_eq!(status, 201, "{body}");
        let cr =
            wire::CreateResponse::from_json(&crate::util::json::parse(&body).unwrap()).unwrap();
        let s = n.server.registry.get(&cr.session_id).unwrap();
        let fin = {
            let s = s.clone();
            std::thread::spawn(move || {
                let _ = s.ingest_up_fin(1, 0);
            })
        };
        for _ in 0..3 {
            let mut h = headers(&n, "tokA", None);
            h.push((wire::H_SESSION_TOKEN.to_string(), cr.session_token.clone()));
            let mut ack = request(
                "POST",
                &format!("{}/{}/ack", wire::PATH_SESSIONS, cr.session_id),
                h,
                "{}",
            );
            ack.query = vec![("epoch".to_string(), "1".to_string())];
            let _ = n.server.route(&ack);
        }
        fin.join().unwrap();
        s.close(crate::error::Error::new(wire::ERR_SESSION_CLOSED, "done"));
    }
}
