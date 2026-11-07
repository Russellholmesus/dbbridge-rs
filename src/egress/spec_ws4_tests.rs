use super::spec_ws3_tests::*;
use crate::wire;
use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// One masked client WebSocket frame (zero mask key).
fn client_frame(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![(if fin { 0x80 } else { 0 }) | opcode];
    if payload.len() < 126 {
        f.push(0x80 | payload.len() as u8);
    } else {
        f.push(0x80 | 126);
        f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    }
    f.extend_from_slice(&[0, 0, 0, 0]);
    f.extend_from_slice(payload);
    f
}

#[test]
fn spec_trickled_ws_frame_body_drops_carrier() {
    let n = node("  up_request_timeout: 500ms\n");
    let addr = listen(&n);
    let cr = ws_create(&n, "w1");
    let (status, _, conn) = ws_request(addr, &ws_header(&n, &cr), Some(("13", Some(KEY))));
    assert_eq!(status, 101);
    let mut sock = conn.try_clone().unwrap();
    let frame = wire::encode_ws_frame(1, 0, &[b'x'; 1024]).unwrap();
    let start = Instant::now();
    let sess = n.server.registry.get(&cr.session_id).unwrap();
    let mut off = 0;
    while off + 64 <= frame.len() && !sess.is_closed() {
        let opcode = if off == 0 { 0x2 } else { 0x0 };
        if sock
            .write_all(&client_frame(false, opcode, &frame[off..off + 64]))
            .is_err()
        {
            break;
        }
        off += 64;
        std::thread::sleep(Duration::from_millis(100));
    }
    for _ in 0..20 {
        if sess.is_closed() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(sess.is_closed(), "trickled frame body kept the carrier");
    let el = start.elapsed();
    assert!(
        el <= Duration::from_secs(3),
        "carrier dropped only after {el:?}"
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    let codec = n.server.codec_for("A").expect("codec share");
    while codec.used() != 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(codec.used(), 0, "codec still held: {}", codec.used());
}

fn node_with(sections: &str) -> Node {
    node_with_target(sections, "127.0.0.1:3306")
}

fn sink_backend() -> String {
    let ln = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = ln.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for c in ln.incoming() {
            let Ok(mut c) = c else { return };
            std::thread::spawn(move || {
                let mut buf = [0u8; 8];
                while matches!(std::io::Read::read(&mut c, &mut buf), Ok(k) if k > 0) {}
            });
        }
    });
    addr
}

fn node_with_target(sections: &str, target: &str) -> Node {
    let dir = std::env::temp_dir().join(format!(
        "dbb-egress-gows4-{}",
        crate::util::random_hex(6).unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    for t in ["tokA", "tokB", "tokC"] {
        std::fs::write(dir.join(t), t).unwrap();
    }
    std::fs::write(dir.join("tokP"), "abcdefghijklmnop").unwrap();
    let text = format!(
        "node:\n  id: B\nhttp:\n  enabled: true\n  listen: \"127.0.0.1:0\"\n  allowed_transports: [ws, http-sse]\ntargets:\n  db:\n    network: tcp\n    address: \"{target}\"\nlimits:\n  max_sessions: 8\ntransport:\n  max_frame_size: 1024\n  buffer_per_direction: 4096\n  up_window_bytes: 2048\n  up_max_inflight_frames: 8\n  dial_timeout: 1s\n  unattached_timeout: 30s\n{sections}"
    );
    let path = dir.join("config.yaml");
    std::fs::write(&path, text).unwrap();
    let cfg = Arc::new(crate::config::load(&path).unwrap_or_else(|e| panic!("{}", e.message)));
    let metrics = Arc::new(crate::metrics::Metrics::new());
    metrics.configure_resources(&cfg);
    let server = Arc::new(super::Server::new(cfg, metrics));
    Node { server, dir }
}

fn inbound(ids: &[&str]) -> String {
    let mut s = "auth:\n  inbound_peers:\n".to_string();
    for id in ids {
        s.push_str(&format!(
            "    - id: {id}\n      token_files: [tok{id}]\n      allowed_targets: [db]\n      max_sessions: 2\n"
        ));
    }
    s
}

const LISTENER: &str = "listeners:\n  - id: l1\n    listen: \"127.0.0.1:0\"\n    peer: P\n    target: db\npeers:\n  - id: P\n    expected_node_id: P\n    credential_ref: P\n    token_file: tokP\n    endpoints:\n      - {id: p, url: \"http://127.0.0.1:18081\", priority: 1}\n";

#[test]
fn spec_egress_codec_leaves_ingress_reserve() {
    let n = node_with(&format!("{}{LISTENER}", inbound(&["A"])));
    let res = n.server.metrics.resource_manager().expect("resources");
    let floor = res.ingress_codec_reserve();
    assert_eq!(
        floor,
        res.codec.limit() / 8,
        "codec reserve {floor} of {}",
        res.codec.limit()
    );
    let a = n.server.codec_for("A").expect("codec share");
    assert!(
        a.try_acquire(res.codec.limit() - floor + 1).is_none(),
        "egress share took the local ingress reserve"
    );
    let held = a
        .try_acquire(res.codec.limit() - floor)
        .expect("egress share refused the egress part");
    let local = res
        .codec
        .try_acquire(floor)
        .expect("local ingress cannot use its reserve");
    drop(local);
    drop(held);
}

#[test]
fn spec_peer_codec_share_follows_enabled_peers() {
    let n = node_with(&inbound(&["A", "B", "C"]));
    let res = n.server.metrics.resource_manager().expect("resources");
    let want = crate::auth::peer_share(res.egress_codec_limit(), 3);
    assert_eq!(n.server.codec_for("A").unwrap().limit(), want, "peer share");
}

#[test]
fn spec_stream_releases_request_budget() {
    let n = node("");
    let addr = listen(&n);
    let (status, body) = route_create(
        &n,
        None,
        &create_body("e1", "db", "http-sse", wire::PROTOCOL_VERSION, LIMITS),
    );
    assert_eq!(status, 201, "create {status}: {body}");
    let cr = wire::CreateResponse::from_json(&crate::util::json::parse(&body).unwrap()).unwrap();
    let mut c = std::net::TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut head = format!(
        "GET {}/{}/events?epoch=1 HTTP/1.1\r\nHost: x\r\n",
        wire::PATH_SESSIONS,
        cr.session_id
    );
    for (k, v) in headers(&n, "tokA", None) {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str(&format!(
        "{}: {}\r\n\r\n",
        wire::H_SESSION_TOKEN,
        cr.session_token
    ));
    c.write_all(head.as_bytes()).unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    let ready = loop {
        let k = std::io::Read::read(&mut c, &mut buf).expect("events read");
        assert!(k > 0, "events closed: {}", String::from_utf8_lossy(&got));
        got.extend_from_slice(&buf[..k]);
        let text = String::from_utf8_lossy(&got).to_string();
        assert!(text.starts_with("HTTP/1.1 200"), "events: {text}");
        if let Some(line) = text
            .lines()
            .filter_map(|l| l.strip_prefix("data: "))
            .find(|d| d.contains("\"stream_id\""))
        {
            break line.to_string();
        }
    };
    assert!(ready.contains("stream_id"), "{ready}");
    let res = n.server.metrics.resource_manager().expect("resources");
    assert_eq!(
        res.data_requests.used(),
        0,
        "live SSE stream holds data request slots"
    );
    let used = res.metadata.used();
    assert!(
        used < res.session_metadata_cost() + (16 << 10),
        "metadata {used} still includes the request's 16 KiB (session {})",
        res.session_metadata_cost()
    );
    drop(c);
}

/// Precheck upgrade headers (`X-DBB-WS-Purpose: check`) for `token`.
fn precheck_headers(n: &Node, token: &str) -> Vec<(String, String)> {
    let mut h = headers(n, token, None);
    h.extend([
        (wire::H_WS_PURPOSE.to_string(), "check".to_string()),
        (
            wire::H_WS_NONCE.to_string(),
            "nonce-for-precheck".to_string(),
        ),
        (
            "Sec-WebSocket-Protocol".to_string(),
            wire::WS_SUBPROTOCOL.to_string(),
        ),
    ]);
    h
}

#[test]
fn spec_single_peer_ws_prechecks_must_be_bounded() {
    let n = node("");
    let addr = listen(&n);
    let res = n.server.metrics.resource_manager().expect("resources");
    let mut sockets = Vec::new();
    for i in 0..3 {
        let (status, h, conn) =
            ws_request(addr, &precheck_headers(&n, "tokA"), Some(("13", Some(KEY))));
        if status != 101 {
            assert!(
                i == 2 && status == 429,
                "unexpected rejection for precheck {}: {status}",
                i + 1
            );
            let retry_after = crate::net::header(&h, "retry-after").map(str::to_string);
            let refusal = error_of(&h, conn);
            assert!(
                refusal.code == wire::ERR_QUOTA_EXCEEDED && refusal.retryable,
                "unsafe quota refusal: {refusal:?}"
            );
            assert!(
                retry_after.as_deref() == Some("1") && res.probes.used() <= 2,
                "quota rejection leaked admission or omitted retry budget (retry-after {retry_after:?}, probes {})",
                res.probes.used()
            );
            return;
        }
        sockets.push(conn);
    }
    panic!(
        "same inbound identity owns {} concurrent WS prechecks; default per-peer max_concurrent_probes is 2; global used={}",
        sockets.len(),
        res.probes.used()
    );
}

#[test]
fn spec_ws_precheck_peer_share() {
    let n = node_with(&inbound(&["A", "C"]));
    let addr = listen(&n);
    let res = n.server.metrics.resource_manager().expect("resources");
    let global = res.probes.limit();
    let mut held = Vec::new();
    for _ in 0..crate::auth::peer_share(global, 2) {
        held.push(
            n.server
                .probe_budget
                .try_acquire_probe_with_reason("A", 2)
                .expect("setup"),
        );
    }
    let mut h = precheck_headers(&n, "tokA");
    for (k, v) in h.iter_mut() {
        if k == wire::H_WS_NONCE {
            *v = "n1".to_string();
        }
    }
    let (status, _, _) = ws_request(addr, &h, Some(("13", Some(KEY))));
    assert_eq!(status, 429, "precheck beyond the peer's probe share");
    drop(held);
}

fn post_ack(
    n: &Node,
    cr: &wire::CreateResponse,
    stream: &str,
    extra: &str,
) -> (u16, crate::util::json::Json) {
    let mut h = headers(n, "tokA", None);
    h.extend([
        (wire::H_SESSION_TOKEN.to_string(), cr.session_token.clone()),
        (wire::H_STREAM_ID.to_string(), stream.to_string()),
    ]);
    let mut req = request(
        "POST",
        &format!("{}/{}/ack", wire::PATH_SESSIONS, cr.session_id),
        h,
        &format!(
            r#"{{"stream_id":"{stream}",{extra}"down_delivered_offset":"0","down_fin_applied":false,"up_confirmed_offset":"0","data_tx_blocked":false,"data_rx_blocked":false,"backpressure_reason":"none"}}"#
        ),
    );
    req.query = vec![("epoch".to_string(), "1".to_string())];
    let (status, body, _) = n.server.route(&req);
    let text = String::from_utf8_lossy(&body).to_string();
    let v = crate::util::json::parse(&text).unwrap_or_else(|_| panic!("ack body: {text}"));
    (status, v)
}

#[test]
fn spec_ws_waits_for_payload_budget() {
    let n = node_with_target(&inbound(&["A"]), &sink_backend());
    let addr = listen(&n);
    let cr = ws_create(&n, "payload-pressure");
    let sess = n.server.registry.get(&cr.session_id).unwrap();
    let res = n.server.metrics.resource_manager().expect("resources");
    let (mut reader, writer) =
        ws_dial(addr, &ws_header(&n, &cr)).unwrap_or_else(|e| panic!("{e:?}"));
    let ready = loop {
        match reader.read_message().unwrap() {
            Some(crate::net::ws::Message::Text(t)) => break t,
            Some(_) => {}
            None => {}
        }
    };
    let rv = crate::util::json::parse(&ready).unwrap();
    let stream = rv
        .get("stream_id")
        .and_then(|s| s.as_str())
        .unwrap()
        .to_string();
    let (st, v) = post_ack(
        &n,
        &cr,
        &stream,
        r#""ready_received":true,"probe_id":"test-credential","#,
    );
    assert_eq!(st, 200, "{v:?}");
    // The backend reader holds its pre-read reservation; take every byte of
    // the process payload budget that is left.
    let deadline = Instant::now() + Duration::from_secs(1);
    while res.payload.used() == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    let held = res.payload.limit() - res.payload.used();
    let lease = res
        .payload
        .try_acquire(held)
        .expect("fixture budget reservation");
    writer
        .lock()
        .unwrap()
        .write_binary(&wire::encode_ws_frame(1, 0, b"four").unwrap())
        .unwrap();
    let deadline = Instant::now() + Duration::from_millis(150);
    while !sess.is_closed() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(
        !sess.is_closed(),
        "temporary payload pressure closed a valid WS session instead of applying backpressure: {:?}",
        sess.terminal_error()
    );
    // Independent HTTP control stays responsive and reports the blocked reader.
    let (st, ack) = post_ack(&n, &cr, &stream, r#""probe_id":"pressure-control","#);
    assert!(
        st == 200
            && ack.get("data_rx_blocked").and_then(|b| b.as_bool()) == Some(true)
            && ack.get("backpressure_reason").and_then(|r| r.as_str()) == Some("global_buffer")
            && ack.get("probe_id").and_then(|p| p.as_str()) == Some("pressure-control"),
        "control under pressure: status={st} ack={ack:?}"
    );
    drop(lease);
    let deadline = Instant::now() + Duration::from_secs(1);
    while sess.snapshot().ack_up_offset != 4 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(
        sess.snapshot().ack_up_offset,
        4,
        "frame did not resume after release (closed={})",
        sess.is_closed()
    );
    // A following frame proves the duplicate has passed through the same reader.
    let baseline = res.payload.used();
    {
        let mut w = writer.lock().unwrap();
        w.write_binary(&wire::encode_ws_frame(1, 0, b"four").unwrap())
            .unwrap();
        w.write_binary(&wire::encode_ws_frame(1, 4, b"more").unwrap())
            .unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(1);
    while (sess.snapshot().ack_up_offset != 8 || res.payload.used() > baseline)
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(
        sess.snapshot().ack_up_offset == 8 && !sess.is_closed() && res.payload.used() <= baseline,
        "duplicate changed stable progress or leaked a payload lease (ack {}, used {} > {baseline})",
        sess.snapshot().ack_up_offset,
        res.payload.used()
    );
}

/// Reads the status line of a raw HTTP response, then everything until the
/// server closes; `Err` when the connection is held past the read timeout.
fn status_line_then_close(c: &mut std::net::TcpStream) -> (String, Result<(), String>) {
    let mut got = Vec::new();
    let mut buf = [0u8; 4096];
    let line = loop {
        match std::io::Read::read(c, &mut buf) {
            Ok(0) => {
                break String::from_utf8_lossy(&got)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_string()
            }
            Ok(k) => {
                got.extend_from_slice(&buf[..k]);
                if let Some(i) = got.windows(2).position(|w| w == b"\r\n") {
                    break String::from_utf8_lossy(&got[..i]).to_string();
                }
            }
            Err(e) => return (String::new(), Err(format!("no response: {e}"))),
        }
    };
    loop {
        match std::io::Read::read(c, &mut buf) {
            Ok(0) => return (line, Ok(())),
            Ok(_) => {}
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                return (line, Err("connection held open after response".into()))
            }
            Err(_) => return (line, Ok(())),
        }
    }
}

#[test]
fn spec_slow_body_connections_are_released() {
    let n = node("  control_request_timeout: 400ms\n");
    let addr = listen(&n);
    let inst = n.server.cfg.node.instance_id.clone();
    let reqs = vec![
        ("unauth up", "POST /v1/sessions/x/up HTTP/1.1\r\nHost: a\r\nContent-Length: 200000\r\nContent-Type: application/octet-stream\r\n\r\n".to_string()),
        ("GET ws with body", "GET /v1/transport/ws HTTP/1.1\r\nHost: a\r\nContent-Length: 200000\r\n\r\n".to_string()),
        ("GET chunked body", "GET /v1/sessions/x/events HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n".to_string()),
        ("authed up no body", format!("POST /v1/sessions/x/up HTTP/1.1\r\nHost: a\r\nAuthorization: Bearer tokA\r\nX-DBB-Instance-ID: {inst}\r\nContent-Length: 200000\r\n\r\n")),
        ("create slow body", format!("POST /v1/sessions HTTP/1.1\r\nHost: a\r\nAuthorization: Bearer tokA\r\nX-DBB-Instance-ID: {inst}\r\nContent-Length: 2000\r\n\r\n{{")),
    ];
    let workers: Vec<_> = reqs
        .into_iter()
        .map(|(name, raw)| {
            std::thread::spawn(move || {
                let mut c = std::net::TcpStream::connect(addr).unwrap();
                let start = Instant::now();
                let _ = c.write_all(raw.as_bytes());
                c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let (line, r) = status_line_then_close(&mut c);
                (name, line, r, start.elapsed())
            })
        })
        .collect();
    for w in workers {
        let (name, line, r, took) = w.join().unwrap();
        assert!(
            r.is_ok(),
            "{name}: {:?} (line {line:?} after {took:?})",
            r.err()
        );
        assert!(
            took <= Duration::from_secs(3),
            "{name}: released only after {took:?}"
        );
        if name.starts_with("GET") {
            assert!(
                line.contains(" 400 "),
                "{name}: GET with body must be rejected with 400, got {line:?}"
            );
        }
    }
    // The listener still serves a legitimate caller.
    let mut c = std::net::TcpStream::connect(addr).unwrap();
    let body = r#"{"protocol_version":"1.5","expected_node_id":"B","nonce":"n1"}"#;
    write!(
        c,
        "POST /v1/peer/probe HTTP/1.1\r\nHost: a\r\nAuthorization: Bearer tokA\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut buf = [0u8; 512];
    let k = std::io::Read::read(&mut c, &mut buf).unwrap_or(0);
    let line = String::from_utf8_lossy(&buf[..k])
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    assert!(line.contains(" 200 "), "legitimate probe: {line:?}");
}

#[test]
fn spec_streams_outlive_request_deadline() {
    let n = node("  control_request_timeout: 200ms\n  heartbeat: 700ms\n");
    let addr = listen(&n);
    // sse
    let (status, body) = route_create(
        &n,
        None,
        &create_body("sse1", "db", "http-sse", wire::PROTOCOL_VERSION, LIMITS),
    );
    assert_eq!(status, 201, "create {status}: {body}");
    let cr = wire::CreateResponse::from_json(&crate::util::json::parse(&body).unwrap()).unwrap();
    let mut c = std::net::TcpStream::connect(addr).unwrap();
    let mut head = format!(
        "GET {}/{}/events?epoch=1 HTTP/1.1\r\nHost: x\r\n",
        wire::PATH_SESSIONS,
        cr.session_id
    );
    for (k, v) in headers(&n, "tokA", None) {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str(&format!(
        "{}: {}\r\n\r\n",
        wire::H_SESSION_TOKEN,
        cr.session_token
    ));
    c.write_all(head.as_bytes()).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut text = String::new();
    let mut buf = [0u8; 4096];
    while text.matches("event: ping").count() < 3 && Instant::now() < deadline {
        match std::io::Read::read(&mut c, &mut buf) {
            Ok(0) | Err(_) => panic!(
                "SSE stream ended after {} pings: {text}",
                text.matches("event: ping").count()
            ),
            Ok(k) => text.push_str(&String::from_utf8_lossy(&buf[..k])),
        }
    }
    assert!(text.starts_with("HTTP/1.1 200"), "events: {text}");
    assert!(
        text.matches("event: ping").count() >= 3,
        "only {} pings",
        text.matches("event: ping").count()
    );
    // ws
    let cr = ws_create(&n, "ws1");
    let (mut reader, _writer) =
        ws_dial(addr, &ws_header(&n, &cr)).unwrap_or_else(|e| panic!("{e:?}"));
    reader.set_read_deadline(Some(Instant::now() + Duration::from_secs(3)));
    let mut pings = 0;
    while pings < 3 {
        match reader.read_message() {
            Ok(Some(crate::net::ws::Message::Text(t))) if t.contains("\"ping\"") => pings += 1,
            Ok(Some(_)) => {}
            Ok(None) => panic!("WS stream ended after {pings} pings: deadline"),
            Err(e) => panic!("WS stream ended after {pings} pings: {e}"),
        }
    }
}
