use super::{ConnectionBudget, ProbeBudget, Registry, Server};
use crate::net::http1::Request;
use crate::wire;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

struct Boundary {
    server: Arc<Server>,
    dials: Arc<AtomicI64>,
    dir: std::path::PathBuf,
}

impl Drop for Boundary {
    fn drop(&mut self) {
        self.server.registry.close_all();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn boundary(target: Option<&str>, extra_transport: &str, extra: &str) -> Boundary {
    let dials = Arc::new(AtomicI64::new(0));
    let addr = match target {
        Some(a) => a.to_string(),
        None => {
            let ln = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = ln.local_addr().unwrap().to_string();
            let d = dials.clone();
            std::thread::spawn(move || {
                for c in ln.incoming() {
                    let Ok(mut c) = c else { return };
                    d.fetch_add(1, Ordering::SeqCst);
                    std::thread::spawn(move || {
                        let mut buf = [0u8; 8];
                        while matches!(c.read(&mut buf), Ok(n) if n > 0) {}
                    });
                }
            });
            addr
        }
    };
    let dir = std::env::temp_dir().join(format!(
        "dbb-egress-goapi-{}",
        crate::util::random_hex(6).unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("peer-token"), "token").unwrap();
    let path = dir.join("config.yaml");
    let text = format!(
        "node:\n  id: B\nhttp:\n  enabled: true\n  listen: \"127.0.0.1:0\"\n  allowed_transports: [ws, http-sse]\ntargets:\n  db:\n    network: tcp\n    address: \"{addr}\"\nauth:\n  inbound_peers:\n    - id: A\n      token_files: [peer-token]\n      allowed_targets: [db]\n      max_sessions: 1\ntransport:\n  max_frame_size: 1024\n  buffer_per_direction: 4096\n  up_window_bytes: 1024\n  up_max_inflight_frames: 8\n  dial_timeout: 1s\n  unattached_timeout: 30ms\n{extra_transport}{extra}"
    );
    std::fs::write(&path, text).unwrap();
    let cfg = Arc::new(crate::config::load(&path).unwrap_or_else(|e| panic!("{}", e.message)));
    let metrics = Arc::new(crate::metrics::Metrics::new());
    let registry = Arc::new(Registry::new(metrics.clone()));
    let client = Arc::new(crate::net::http1::Client::new(
        cfg.transport.dial_timeout,
        cfg.transport.control_request_timeout,
    ));
    let server = Arc::new(Server {
        cfg: cfg.clone(),
        auth: Arc::new(crate::auth::Authenticator::new(cfg.clone())),
        registry,
        client,
        started: Instant::now(),
        hub: None,
        tunnels: None,
        metrics,
        connection_budget: Arc::new(ConnectionBudget::new(1)),
        authz_lock: Arc::new(std::sync::Mutex::new(())),
        probe_budget: Arc::new(ProbeBudget::new()),
        accept_addr: Arc::new(std::sync::Mutex::new(None)),
    });
    Boundary { server, dials, dir }
}

fn request(path: &str, headers: Vec<(String, String)>, body: &str) -> Request {
    Request {
        method: "POST".to_string(),
        path: path.to_string(),
        query: Vec::new(),
        version: "HTTP/1.1".to_string(),
        headers,
        body: body.as_bytes().to_vec(),
    }
}

fn auth_headers(token: &str, instance: Option<&str>) -> Vec<(String, String)> {
    let mut h = vec![(wire::H_PEER_AUTH.to_string(), format!("Bearer {token}"))];
    if let Some(i) = instance {
        h.push((wire::H_INSTANCE_ID.to_string(), i.to_string()));
    }
    h
}

fn create_body(
    id: &str,
    target: &str,
    version: &str,
    recovery: Option<&str>,
    limits: &str,
) -> String {
    let recovery = match recovery {
        Some(r) => format!(",\"recovery\":{r}"),
        None => String::new(),
    };
    format!(
        "{{\"protocol_version\":\"{version}\",\"transport\":{{\"mode\":\"ws\"}}{recovery},\"create_request_id\":\"{id}\",\"ingress_instance_id\":\"ai\",\"target_id\":\"{target}\",\"limits\":{limits}}}"
    )
}

const LIMITS: &str = r#"{"max_frame_size":1024,"up_max_inflight_frames":8,"up_window_bytes":1024,"down_buffer_bytes":1024}"#;
const NO_RECOVERY: &str = r#"{"enabled":false,"grace_ms":0}"#;

fn create(b: &Boundary, id: &str, instance: Option<&str>) -> (u16, Vec<u8>) {
    let (status, body, _) = b.server.route(&request(
        wire::PATH_SESSIONS,
        auth_headers("token", instance),
        &create_body(id, "db", wire::PROTOCOL_VERSION, Some(NO_RECOVERY), LIMITS),
    ));
    (status, body)
}

fn code(body: &[u8]) -> String {
    wire::ErrorBody::parse(std::str::from_utf8(body).unwrap())
        .map(|e| e.code)
        .unwrap_or_default()
}

fn instance(b: &Boundary) -> String {
    b.server.cfg.node.instance_id.clone()
}

#[test]
fn spec_create_session_validation() {
    let b = boundary(None, "", "");
    let inst = instance(&b);
    let (status, body, _) = b.server.route(&request(
        wire::PATH_SESSIONS,
        auth_headers("token", Some(&inst)),
        &create_body("cr_bad_ver", "db", "1.2", Some(NO_RECOVERY), LIMITS),
    ));
    assert_eq!(
        status,
        409,
        "bad protocol version: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(code(&body), wire::ERR_PROTOCOL_MISMATCH);

    let ok = create_body(
        "cr_inst_mismatch",
        "db",
        wire::PROTOCOL_VERSION,
        Some(NO_RECOVERY),
        LIMITS,
    );
    let (status, body, _) = b.server.route(&request(
        wire::PATH_SESSIONS,
        auth_headers("token", Some("wrong_instance_id")),
        &ok,
    ));
    assert_eq!(
        status,
        409,
        "instance mismatch: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(code(&body), wire::ERR_INSTANCE_MISMATCH);

    let (status, body, _) = b.server.route(&request(
        wire::PATH_SESSIONS,
        auth_headers("token", Some(&inst)),
        &ok,
    ));
    assert_eq!(
        status,
        201,
        "valid create: {}",
        String::from_utf8_lossy(&body)
    );

    let (status, body, _) = b.server.route(&request(
        wire::PATH_SESSIONS,
        auth_headers("token", Some(&inst)),
        &create_body(
            "cr_inst_mismatch",
            "db",
            wire::PROTOCOL_VERSION,
            Some(NO_RECOVERY),
            LIMITS,
        )
        .replace(r#""mode":"ws""#, r#""mode":"http-sse""#),
    ));
    assert_eq!(
        status,
        409,
        "idempotency conflict: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(code(&body), wire::ERR_IDEMPOTENCY_CONFLICT);
}

/// Serves one connection with `raw` written by the client; returns what the
/// server wrote before closing (or until the read timeout).
fn raw_exchange(server: Arc<Server>, raw: &[u8]) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server_stream, _) = listener.accept().unwrap();
    std::thread::spawn(move || {
        let _ = server.handle_conn(
            Box::new(server_stream),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            None,
        );
    });
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let _ = client.write_all(raw);
    let mut response = Vec::new();
    let _ = client.read_to_end(&mut response);
    String::from_utf8_lossy(&response).to_string()
}

#[test]
fn spec_control_body_limit() {
    let b = boundary(None, "", "");
    let body = "a".repeat(20000);
    let raw = format!(
        "POST {} HTTP/1.1\r\nHost: x\r\n{}: Bearer token\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        wire::PATH_PROBE,
        wire::H_PEER_AUTH,
        body.len()
    );
    let response = raw_exchange(b.server.clone(), raw.as_bytes());
    assert!(
        response.starts_with("HTTP/1.1 400 "),
        "expected 400 on >16KiB control body: {}",
        response.lines().next().unwrap_or("")
    );
}

#[test]
fn spec_invalid_cidr_must_fail_closed() {
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let dir = std::env::temp_dir().join(format!(
        "dbb-egress-gocidr-{}",
        crate::util::random_hex(6).unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("peer-token"), "test-token").unwrap();
    let path = dir.join("config.yaml");
    std::fs::write(
        &path,
        format!(
            "node:\n  id: hq-b\nhttp:\n  enabled: true\n  listen: \"127.0.0.1:0\"\ntargets:\n  cidr-target:\n    network: tcp\n    address: \"{}\"\n    allowed_cidrs: [not-a-cidr]\nauth:\n  inbound_peers:\n    - id: plant-a\n      token_files: [peer-token]\n      allowed_targets: [cidr-target]\n      max_sessions: 10\n",
            ln.local_addr().unwrap()
        ),
    )
    .unwrap();
    let result = crate::config::load(&path);
    std::fs::remove_dir_all(&dir).ok();
    let e = result.expect_err("invalid CIDR whitelist accepted: a create could dial");
    assert!(e.message.contains("invalid CIDR"), "{}", e.message);
}

#[test]
fn spec_duplicate_json() {
    let b = boundary(None, "", "");
    let (status, _, _) = b.server.route(&request(
        wire::PATH_PROBE,
        auth_headers("token", None),
        r#"{"protocol_version":"wrong","protocol_version":"1.5","expected_node_id":"B","nonce":"x"}"#,
    ));
    assert_ne!(status, 200, "duplicate critical protocol_version accepted");
}

#[test]
fn spec_create_requires_instance() {
    let b = boundary(None, "", "");
    let (status, _) = create(&b, "c1", None);
    assert_ne!(
        status, 201,
        "creation without bound X-DBB-Instance-ID returned 201"
    );
}

#[test]
fn spec_quota_released_after_orphan() {
    let b = boundary(None, "", "");
    let inst = instance(&b);
    let (status, body) = create(&b, "c1", Some(&inst));
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    let deadline = Instant::now() + Duration::from_secs(1);
    while !b.server.registry.all_sessions().is_empty() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    let (status, body) = create(&b, "c2", Some(&inst));
    assert_eq!(
        status,
        201,
        "orphan removed from registry, but next create rejected: {}",
        String::from_utf8_lossy(&body)
    );
}

#[test]
fn spec_session_token_url() {
    let b = boundary(None, "", "");
    let inst = instance(&b);
    let (status, body) = create(&b, "c1", Some(&inst));
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    let created = wire::CreateResponse::from_json(
        &crate::util::json::parse(std::str::from_utf8(&body).unwrap()).unwrap(),
    )
    .unwrap();
    let raw = format!(
        "GET {}?purpose=session&session_id={}&epoch=1&session_token={} HTTP/1.1\r\nHost: x\r\n{}: Bearer token\r\n{}: {inst}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: {}\r\n\r\n",
        wire::PATH_WS,
        created.session_id,
        created.session_token,
        wire::H_PEER_AUTH,
        wire::H_INSTANCE_ID,
        wire::WS_SUBPROTOCOL
    );
    let response = raw_exchange(b.server.clone(), raw.as_bytes());
    assert!(
        !response.starts_with("HTTP/1.1 101"),
        "WS session secret in URL was accepted: {}",
        response.lines().next().unwrap_or("")
    );
}

#[test]
fn spec_create_requires_recovery_object() {
    let b = boundary(None, "", "");
    let inst = instance(&b);
    let (status, _, _) = b.server.route(&request(
        wire::PATH_SESSIONS,
        auth_headers("token", Some(&inst)),
        &create_body(
            "missing-recovery",
            "db",
            wire::PROTOCOL_VERSION,
            None,
            LIMITS,
        ),
    ));
    std::thread::sleep(Duration::from_millis(10));
    assert_eq!(
        (status, b.dials.load(Ordering::SeqCst)),
        (400, 0),
        "incomplete schema: status / backend dials"
    );
}

#[test]
fn spec_grace_milliseconds_overflow() {
    let b = boundary(None, "", "  recovery:\n    enabled: true\n    grace: 1s\n");
    let inst = instance(&b);
    let (status, body, _) = b.server.route(&request(
        wire::PATH_SESSIONS,
        auth_headers("token", Some(&inst)),
        &create_body(
            "overflow-grace",
            "db",
            wire::PROTOCOL_VERSION,
            Some(r#"{"enabled":true,"grace_ms":9223372036854775807}"#),
            LIMITS,
        ),
    ));
    if status == 201 {
        let v = crate::util::json::parse(std::str::from_utf8(&body).unwrap()).unwrap();
        let grace = v
            .get("recovery")
            .and_then(|r| r.get("grace_ms"))
            .and_then(|g| g.as_u64())
            .unwrap_or(0);
        assert!(
            grace > 0,
            "overflow produced successful invalid recovery contract grace_ms={grace}"
        );
    }
}

#[test]
fn spec_invalid_negotiation_rejected_before_dial() {
    let b = boundary(None, "", "");
    let inst = instance(&b);
    let (status, _, _) = b.server.route(&request(
        wire::PATH_SESSIONS,
        auth_headers("token", Some(&inst)),
        &create_body(
            "invalid-limits",
            "db",
            wire::PROTOCOL_VERSION,
            Some(NO_RECOVERY),
            r#"{"max_frame_size":1024,"up_max_inflight_frames":8,"up_window_bytes":1,"down_buffer_bytes":1024}"#,
        ),
    ));
    std::thread::sleep(Duration::from_millis(10));
    let n = b.dials.load(Ordering::SeqCst);
    assert_eq!(
        n, 0,
        "invalid negotiation returned HTTP {status} after already dialing backend {n} time(s)"
    );
}

#[test]
fn spec_unresolvable_target_is_dial_failure() {
    let b = boundary(
        Some("no-such-host.invalid:3306"),
        "  control_request_timeout: 10s\n",
        "",
    );
    let inst = instance(&b);
    for what in ["first", "replay"] {
        let (status, body) = create(&b, "d1", Some(&inst));
        assert_eq!(
            (status, code(&body)),
            (502, wire::ERR_DIAL_FAILED.to_string()),
            "{what}: {}",
            String::from_utf8_lossy(&body)
        );
    }
}

#[test]
fn spec_instance_id_not_leaked_pre_auth() {
    let b = boundary(None, "", "");
    let inst = instance(&b);
    let head = |raw: String| {
        let head = raw.split("\r\n\r\n").next().unwrap_or("").to_string();
        let status = head.split_whitespace().nth(1).unwrap_or("").to_string();
        let value = head
            .lines()
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.trim()
                    .eq_ignore_ascii_case(wire::H_INSTANCE_ID)
                    .then(|| v.trim().to_string())
            })
            .unwrap_or_default();
        (status, value)
    };
    let anonymous = raw_exchange(
        b.server.clone(),
        format!(
            "POST {} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}",
            wire::PATH_PROBE
        )
        .as_bytes(),
    );
    assert_eq!(
        head(anonymous),
        ("401".to_string(), String::new()),
        "anonymous"
    );
    let bound = raw_exchange(
        b.server.clone(),
        format!(
            "POST {} HTTP/1.1\r\nHost: x\r\n{}: {inst}\r\nContent-Length: 2\r\n\r\n{{}}",
            wire::PATH_SESSIONS,
            wire::H_INSTANCE_ID
        )
        .as_bytes(),
    );
    assert_eq!(head(bound), ("401".to_string(), inst), "bound client");
}

#[test]
fn spec_flow_limits_advertised() {
    let b = boundary(None, "  receipt_limit_per_session: 40\n", "");
    let inst = instance(&b);
    let (status, raw) = create(&b, "flow", Some(&inst));
    assert_eq!(status, 201, "create: {}", String::from_utf8_lossy(&raw));
    let created = wire::CreateResponse::from_json(
        &crate::util::json::parse(std::str::from_utf8(&raw).unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        (
            created.limits.up_receipt_limit,
            created.limits.down_max_frames
        ),
        (40, 512),
        "advertised limits {:?}",
        created.limits
    );
    let (status, raw2) = create(&b, "flow", Some(&inst));
    assert_eq!(status, 200, "replay: {}", String::from_utf8_lossy(&raw2));
    assert_eq!(
        String::from_utf8_lossy(&raw).trim(),
        String::from_utf8_lossy(&raw2).trim(),
        "replay body differs"
    );
}

#[test]
fn spec_early_reject_closes_without_drain() {
    let b = boundary(None, "  control_request_timeout: 10s\n", "");
    let start = Instant::now();
    let response = raw_exchange(
        b.server.clone(),
        b"POST /v1/sessions/x/up HTTP/1.1\r\nHost: a\r\nContent-Length: 200000\r\n\r\n",
    );
    let elapsed = start.elapsed();
    let head = response
        .split("\r\n\r\n")
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    assert!(
        head.starts_with("http/1.1 401 ")
            && head.contains("\r\nconnection: close")
            && elapsed <= Duration::from_secs(1),
        "status/close after {elapsed:?}: {head}"
    );
    assert!(
        head.contains("\r\nwww-authenticate:"),
        "401 without WWW-Authenticate: {head}"
    );
}

/// A Boundary from a complete YAML text; `files` are written next to it.
fn custom(text: &str, files: &[(&str, &str)], max_conn: u32) -> Boundary {
    let dir = std::env::temp_dir().join(format!(
        "dbb-egress-goapi-{}",
        crate::util::random_hex(6).unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    for (name, content) in files {
        std::fs::write(dir.join(name), content).unwrap();
    }
    let path = dir.join("config.yaml");
    std::fs::write(&path, text).unwrap();
    let cfg = Arc::new(crate::config::load(&path).unwrap_or_else(|e| panic!("{}", e.message)));
    let metrics = Arc::new(crate::metrics::Metrics::new());
    let registry = Arc::new(Registry::new(metrics.clone()));
    let client = Arc::new(crate::net::http1::Client::new(
        cfg.transport.dial_timeout,
        cfg.transport.control_request_timeout,
    ));
    let server = Arc::new(Server {
        cfg: cfg.clone(),
        auth: Arc::new(crate::auth::Authenticator::new(cfg.clone())),
        registry,
        client,
        started: Instant::now(),
        hub: None,
        tunnels: None,
        metrics,
        connection_budget: Arc::new(ConnectionBudget::new(max_conn)),
        authz_lock: Arc::new(std::sync::Mutex::new(())),
        probe_budget: Arc::new(ProbeBudget::new()),
        accept_addr: Arc::new(std::sync::Mutex::new(None)),
    });
    Boundary {
        server,
        dials: Arc::new(AtomicI64::new(0)),
        dir,
    }
}

fn dead_addr() -> String {
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = ln.local_addr().unwrap().to_string();
    drop(ln);
    addr
}

/// Two inbound peers: A (tokA, target db, max 4) and X (tokX, target dead,
/// max 1); `db` is a discarding backend, `dead` refuses connections.
fn two_peers() -> Boundary {
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let db = ln.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for c in ln.incoming() {
            let Ok(mut c) = c else { return };
            std::thread::spawn(move || {
                let mut buf = [0u8; 64];
                while matches!(c.read(&mut buf), Ok(n) if n > 0) {}
            });
        }
    });
    let text = format!(
        "node:\n  id: B\nhttp:\n  enabled: true\n  listen: \"127.0.0.1:0\"\n  allowed_transports: [ws, http-sse]\ntargets:\n  db:\n    network: tcp\n    address: \"{db}\"\n  dead:\n    network: tcp\n    address: \"{}\"\nauth:\n  inbound_peers:\n    - id: A\n      token_files: [tok-a]\n      allowed_targets: [db]\n      max_sessions: 4\n    - id: X\n      token_files: [tok-x]\n      allowed_targets: [dead]\n      max_sessions: 1\ntransport:\n  max_frame_size: 1024\n  buffer_per_direction: 4096\n  up_window_bytes: 1024\n  dial_timeout: 1s\n",
        dead_addr()
    );
    custom(
        &text,
        &[
            ("tok-a", "tokA-0123456789abcdef"),
            ("tok-x", "tokX-0123456789abcdef"),
        ],
        16,
    )
}

fn create_as(b: &Boundary, token: &str, id: &str, target: &str) -> (u16, Vec<u8>) {
    let inst = instance(b);
    let (status, body, _) = b.server.route(&request(
        wire::PATH_SESSIONS,
        auth_headers(token, Some(&inst)),
        &create_body(
            id,
            target,
            wire::PROTOCOL_VERSION,
            Some(NO_RECOVERY),
            LIMITS,
        ),
    ));
    (status, body)
}

fn peer_records(b: &Boundary, peer: &str) -> usize {
    b.server
        .registry
        .creates
        .lock()
        .unwrap()
        .values()
        .filter(|r| r.peer == peer)
        .count()
}

#[test]
fn spec_peer_idempotency_quota() {
    let b = two_peers();
    let limit = super::RecordLimits::peer_pending(1);
    for i in 0..limit {
        let (status, body) = create_as(&b, "tokX-0123456789abcdef", &format!("d-{i}"), "dead");
        assert_eq!(
            status,
            502,
            "dial failure {i}: {}",
            String::from_utf8_lossy(&body)
        );
    }
    assert_eq!(peer_records(&b, "X"), limit, "tracked records");
    let (status, body) = create_as(&b, "tokX-0123456789abcdef", "d-over", "dead");
    let e = wire::ErrorBody::parse(std::str::from_utf8(&body).unwrap()).unwrap();
    assert_eq!(
        status,
        429,
        "over quota: {}",
        String::from_utf8_lossy(&body)
    );
    assert!(e.retryable, "over quota must be retryable");
    assert_eq!(e.message, "peer idempotency quota");
    assert_eq!(peer_records(&b, "X"), limit, "refused create kept a record");
    let (status, _) = create_as(&b, "tokX-0123456789abcdef", "d-0", "dead");
    assert_eq!(status, 502, "replay of a cached failure");
    let (status, body) = create_as(&b, "tokA-0123456789abcdef", "a1", "db");
    assert_eq!(
        status,
        201,
        "other peer: {}",
        String::from_utf8_lossy(&body)
    );
}

#[test]
fn spec_concurrent_same_key_creates_keep_failed_record_counted() {
    let b = Arc::new(two_peers());
    let mut threads = Vec::new();
    for _ in 0..2 {
        let b = b.clone();
        threads.push(std::thread::spawn(move || {
            create_as(&b, "tokX-0123456789abcdef", "dup", "dead").0
        }));
    }
    for t in threads {
        let status = t.join().unwrap();
        assert!(
            status == 502 || status == 202 || status == 409,
            "concurrent create status {status}"
        );
    }
    assert_eq!(peer_records(&b, "X"), 1, "one key tracked more than once");
    let (status, body) = create_as(&b, "tokX-0123456789abcdef", "dup", "dead");
    assert_eq!(status, 502, "replay: {}", String::from_utf8_lossy(&body));
    assert_eq!(code(&body), wire::ERR_DIAL_FAILED);
    assert_eq!(
        peer_records(&b, "X"),
        1,
        "replay changed the tracked records"
    );
}
