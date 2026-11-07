use super::{ConnectionBudget, ProbeBudget, Registry, Server};
use crate::error::Error;
use crate::net::http1::Request;
use crate::wire::{self, CreateRequest, Mode};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::time::{Duration, Instant};

struct Fixture {
    server: Arc<Server>,
    dir: std::path::PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.registry.close_all();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn fixture(target_addr: &str, max_sessions: u32) -> Fixture {
    fixture_with_cidr(target_addr, max_sessions, None)
}

fn fixture_with_cidr(target_addr: &str, max_sessions: u32, allowed_cidr: Option<&str>) -> Fixture {
    let dir = std::env::temp_dir().join(format!(
        "dbb-egress-migration-{}",
        crate::util::random_hex(6).unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("peer-token"), "abc").unwrap();
    let path = dir.join("config.yaml");
    let allowed_cidrs = allowed_cidr
        .map(|cidr| format!("\n    allowed_cidrs: [\"{cidr}\"]"))
        .unwrap_or_default();
    let text = format!(
        "node:\n  id: peer-b\nhttp:\n  enabled: true\n  listen: \"127.0.0.1:0\"\ntargets:\n  db:\n    network: tcp\n    address: \"{target_addr}\"{allowed_cidrs}\nauth:\n  inbound_peers:\n    - id: peer-a\n      token_files: [peer-token]\n      allowed_targets: [db]\n      max_sessions: {max_sessions}\nlimits:\n  max_sessions: {max_sessions}\ntransport:\n  unattached_timeout: 5s\n"
    );
    std::fs::write(&path, text).unwrap();
    let cfg = Arc::new(crate::config::load(&path).unwrap());
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
        connection_budget: Arc::new(ConnectionBudget::new(max_sessions)),
        authz_lock: Arc::new(std::sync::Mutex::new(())),
        probe_budget: Arc::new(ProbeBudget::new()),
        accept_addr: Arc::new(std::sync::Mutex::new(None)),
    });
    Fixture { server, dir }
}

fn create_request(server: &Server, id: &str, mode: Mode) -> Request {
    let create = CreateRequest {
        target_id: "db".to_string(),
        create_request_id: id.to_string(),
        ingress_instance_id: "ingress-test".to_string(),
        mode,
        recovery_enabled: false,
        recovery_grace_ms: 0,
        limits: crate::transport::requested_limits(&server.cfg.transport),
    };
    Request {
        method: "POST".to_string(),
        path: wire::PATH_SESSIONS.to_string(),
        query: Vec::new(),
        version: "HTTP/1.1".to_string(),
        headers: vec![
            (wire::H_PEER_AUTH.to_string(), "Bearer abc".to_string()),
            (
                wire::H_INSTANCE_ID.to_string(),
                server.cfg.node.instance_id.clone(),
            ),
        ],
        body: create.to_json().to_string().into_bytes(),
    }
}

fn parse_create_response(body: &str) -> wire::CreateResponse {
    let json = crate::util::json::parse(body).unwrap();
    wire::CreateResponse::from_json(&json).unwrap()
}

fn error_body(status: u16, body: &[u8], expected_status: u16) -> wire::ErrorBody {
    assert_eq!(
        status,
        expected_status,
        "unexpected HTTP status with body: {}",
        String::from_utf8_lossy(body)
    );
    wire::ErrorBody::parse(std::str::from_utf8(body).unwrap()).expect("JSON error response")
}

fn raw_http_exchange(server: Arc<Server>, request: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server_stream, _) = listener.accept().unwrap();
    let handler = std::thread::spawn(move || {
        let _ = server.handle_conn(
            Box::new(server_stream),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            None,
        );
    });
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    client.write_all(request.as_bytes()).unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).unwrap();
    handler.join().expect("egress request handler thread");
    String::from_utf8(response).unwrap()
}

#[test]
fn p4_01_egress_probe_endpoint_reports_spec_contract() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let fixture = fixture(&target.local_addr().unwrap().to_string(), 4);
    let request = Request {
        method: "POST".to_string(),
        path: wire::PATH_PROBE.to_string(),
        query: Vec::new(),
        version: "HTTP/1.1".to_string(),
        headers: vec![(wire::H_PEER_AUTH.to_string(), "Bearer abc".to_string())],
        body: wire::ProbeRequest {
            expected_node_id: "peer-b".to_string(),
            nonce: "test_nonce_123".to_string(),
        }
        .to_json()
        .to_string()
        .into_bytes(),
    };

    let (status, body, _) = fixture.server.route(&request);
    assert_eq!(status, 200);
    let json = crate::util::json::parse(std::str::from_utf8(&body).unwrap()).unwrap();
    let response = wire::ProbeResponse::from_json(&json).unwrap();
    assert_eq!(response.protocol_version, wire::PROTOCOL_VERSION);
    assert_eq!(response.node_id, fixture.server.cfg.node.id);
    assert_eq!(response.instance_id, fixture.server.cfg.node.instance_id);
    assert_eq!(response.nonce, "test_nonce_123");
    assert_eq!(
        response.recovery_available,
        fixture.server.cfg.transport.recovery_enabled
    );
    assert!(response.accepting_new_sessions);
    assert_eq!(
        response.transports,
        vec!["ws".to_string(), "http-sse".to_string()]
    );
}

#[test]
fn p4_01_egress_create_without_instance_binding_is_rejected_before_dial() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    target.set_nonblocking(true).unwrap();
    let fixture = fixture(&target.local_addr().unwrap().to_string(), 4);
    let mut request = create_request(&fixture.server, "missing-instance", Mode::Ws);
    request
        .headers
        .retain(|(name, _)| !name.eq_ignore_ascii_case(wire::H_INSTANCE_ID));

    let (status, body, _) = fixture.server.route(&request);
    let error = error_body(status, &body, 409);
    assert_eq!(error.code, wire::ERR_INSTANCE_MISMATCH);
    assert!(!error.retryable);
    assert!(!error.session_closed);
    assert!(matches!(target.accept(), Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock));
    assert!(fixture.server.registry.all_sessions().is_empty());
}

#[test]
fn p4_01_egress_create_protocol_mismatch_returns_protocol_error() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    target.set_nonblocking(true).unwrap();
    let fixture = fixture(&target.local_addr().unwrap().to_string(), 4);
    let mut request = create_request(&fixture.server, "wrong-version", Mode::Ws);
    let body = String::from_utf8(request.body).unwrap();
    request.body = body
        .replace(
            "\"protocol_version\":\"1.5\"",
            "\"protocol_version\":\"1.2\"",
        )
        .into_bytes();

    let (status, body, _) = fixture.server.route(&request);
    let error = error_body(status, &body, 409);
    assert_eq!(error.code, wire::ERR_PROTOCOL_MISMATCH);
    assert!(!error.retryable);
    assert!(!error.session_closed);
    assert!(matches!(target.accept(), Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock));
    assert!(fixture.server.registry.all_sessions().is_empty());
}

#[test]
fn p4_01_egress_create_response_reports_negotiated_flow_limits() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let fixture = fixture(&target.local_addr().unwrap().to_string(), 4);
    let request = create_request(&fixture.server, "flow-limits", Mode::HttpSse);
    let requested = crate::transport::requested_limits(&fixture.server.cfg.transport);

    let (status, body, _) = fixture.server.route(&request);
    assert_eq!(status, 201);
    let response = parse_create_response(std::str::from_utf8(&body).unwrap());
    assert_eq!(response.node_id, fixture.server.cfg.node.id);
    assert_eq!(response.instance_id, fixture.server.cfg.node.instance_id);
    assert_eq!(response.mode, Mode::HttpSse);
    assert_eq!(response.limits.max_frame_size, requested.max_frame_size);
    assert_eq!(
        response.limits.up_max_inflight_frames,
        requested.up_max_inflight_frames
    );
    assert_eq!(response.limits.up_window_bytes, requested.up_window_bytes);
    assert_eq!(
        response.limits.down_buffer_bytes,
        requested.down_buffer_bytes
    );
    assert!(response.limits.up_receipt_limit > 0);
    assert!(response.limits.down_max_frames > 0);
}

#[test]
fn p4_01_egress_duplicate_authorization_is_rejected_and_closed() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let fixture = fixture(&target.local_addr().unwrap().to_string(), 4);
    let response = raw_http_exchange(
        fixture.server.clone(),
        "POST /v1/peer/probe HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer abc\r\nAuthorization: Bearer other\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
    );
    let (head, body) = response.split_once("\r\n\r\n").expect("HTTP response");
    assert!(head.starts_with("HTTP/1.1 400 "), "{head}");
    assert!(head.to_ascii_lowercase().contains("\r\nconnection: close"));
    let error = wire::ErrorBody::parse(body).unwrap();
    assert_eq!(error.code, wire::ERR_BAD_FRAME);
}

#[test]
fn p4_01_egress_unauthorized_request_closes_keep_alive_and_does_not_pipeline() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let fixture = fixture(&target.local_addr().unwrap().to_string(), 4);
    let response = raw_http_exchange(
        fixture.server.clone(),
        "POST /v1/peer/probe HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer wrong\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\nPOST /v1/peer/probe HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer abc\r\nContent-Length: 0\r\n\r\n",
    );
    let (head, body) = response.split_once("\r\n\r\n").expect("HTTP response");
    assert!(head.starts_with("HTTP/1.1 401 "), "{head}");
    assert!(head.to_ascii_lowercase().contains("\r\nconnection: close"));
    assert_eq!(response.matches("HTTP/1.1 ").count(), 1);
    let error = wire::ErrorBody::parse(body).unwrap();
    assert_eq!(error.code, wire::ERR_UNAUTHORIZED);
}

#[test]
fn p4_01_egress_target_outside_allowed_cidrs_is_forbidden() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    target.set_nonblocking(true).unwrap();
    let fixture = fixture_with_cidr(
        &target.local_addr().unwrap().to_string(),
        4,
        Some("10.0.0.0/8"),
    );
    let request = create_request(&fixture.server, "outside-cidr", Mode::Ws);

    let (status, body, _) = fixture.server.route(&request);
    let error = error_body(status, &body, 403);
    assert_eq!(error.code, wire::ERR_TARGET_FORBIDDEN);
    assert!(!error.retryable);
    assert!(!error.session_closed);
    assert!(matches!(target.accept(), Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock));
}

fn session_action_request(
    server: &Server,
    session_id: &str,
    session_token: &str,
    action: &str,
    stream_id: &str,
    body: Vec<u8>,
) -> Request {
    Request {
        method: "POST".to_string(),
        path: format!("{}/{session_id}/{action}", wire::PATH_SESSIONS),
        query: vec![("epoch".to_string(), "1".to_string())],
        version: "HTTP/1.1".to_string(),
        headers: vec![
            (wire::H_PEER_AUTH.to_string(), "Bearer abc".to_string()),
            (
                wire::H_INSTANCE_ID.to_string(),
                server.cfg.node.instance_id.clone(),
            ),
            (wire::H_SESSION_TOKEN.to_string(), session_token.to_string()),
            (wire::H_STREAM_ID.to_string(), stream_id.to_string()),
        ],
        body,
    }
}

fn up_request(
    server: &Server,
    session_id: &str,
    session_token: &str,
    stream_id: &str,
    offset: u64,
    payload: &[u8],
) -> Request {
    let digest = crate::util::hex(&crate::util::sha256::digest(payload));
    let mut request = session_action_request(
        server,
        session_id,
        session_token,
        "up",
        stream_id,
        payload.to_vec(),
    );
    request.headers.extend([
        (wire::H_OFFSET.to_string(), offset.to_string()),
        (wire::H_LENGTH.to_string(), payload.len().to_string()),
        (wire::H_SHA256.to_string(), digest),
        ("Content-Length".to_string(), payload.len().to_string()),
        (
            "Content-Type".to_string(),
            "application/octet-stream".to_string(),
        ),
    ]);
    request
}

#[test]
fn p4_01_egress_authenticate_before_probe_admission() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let fixture = fixture(&target.local_addr().unwrap().to_string(), 4);
    let server = &fixture.server;

    let occupied: Vec<_> = (0..16)
        .map(|index| {
            server
                .probe_budget
                .try_acquire_probe_with_reason(&format!("load-{index}"), 1)
                .expect("fill global probe admission")
        })
        .collect();
    let request = Request {
        method: "POST".to_string(),
        path: wire::PATH_PROBE.to_string(),
        query: Vec::new(),
        version: "HTTP/1.1".to_string(),
        headers: vec![(wire::H_PEER_AUTH.to_string(), "Bearer invalid".to_string())],
        body: br#"{"protocol_version":"1.5","nonce":"n"}"#.to_vec(),
    };

    let (status, body, _) = server.route(&request);
    let error = error_body(status, &body, 401);
    assert_eq!(error.code, wire::ERR_UNAUTHORIZED);
    assert!(!error.retryable);
    assert!(!error.session_closed);
    assert_eq!(server.probe_budget.resource_budget.used(), 16);
    drop(occupied);
}

#[test]
fn p4_01_egress_create_validation_returns_protocol_error_body() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let fixture = fixture(&target.local_addr().unwrap().to_string(), 4);
    let mut request = create_request(&fixture.server, "wrong-instance", Mode::Ws);
    request
        .headers
        .iter_mut()
        .find(|(name, _)| name == wire::H_INSTANCE_ID)
        .unwrap()
        .1 = "stale-instance".to_string();

    let (status, body, headers) = fixture.server.route(&request);
    let error = error_body(status, &body, 409);
    assert_eq!(error.code, wire::ERR_INSTANCE_MISMATCH);
    assert!(!error.retryable);
    assert!(!error.session_closed);
    assert!(headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("content-type") && value == "application/json"
    }));
    assert!(headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("cache-control") && value == "no-store"
    }));
}

#[test]
fn p4_01_egress_retryable_quota_refusal_does_not_reserve_idempotency_key() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let fixture = fixture(&target.local_addr().unwrap().to_string(), 1);
    let server = &fixture.server;

    let first = create_request(server, "occupy-slot", Mode::Ws);
    let (status, body, _) = server.route(&first);
    assert_eq!(status, 201);
    let first_response = parse_create_response(std::str::from_utf8(&body).unwrap());

    let retry = create_request(server, "retry-after-quota", Mode::Ws);
    let (status, body, _) = server.route(&retry);
    let error = error_body(status, &body, 429);
    assert_eq!(error.code, wire::ERR_QUOTA_EXCEEDED);
    assert!(error.retryable);
    assert!(!error.session_closed);

    let delete = Request {
        method: "DELETE".to_string(),
        path: format!(
            "{}/{session_id}",
            wire::PATH_SESSIONS,
            session_id = first_response.session_id
        ),
        query: vec![("epoch".to_string(), "1".to_string())],
        version: "HTTP/1.1".to_string(),
        headers: vec![
            (wire::H_PEER_AUTH.to_string(), "Bearer abc".to_string()),
            (
                wire::H_INSTANCE_ID.to_string(),
                server.cfg.node.instance_id.clone(),
            ),
            (
                wire::H_SESSION_TOKEN.to_string(),
                first_response.session_token,
            ),
        ],
        body: Vec::new(),
    };
    let (status, _, _) = server.route(&delete);
    assert_eq!(status, 200);

    let (status, body, _) = server.route(&retry);
    assert_eq!(
        status, 201,
        "quota-refused key should be available after the slot frees"
    );
    let created_body = String::from_utf8(body).unwrap();
    let created = parse_create_response(&created_body);
    let (status, replay, _) = server.route(&retry);
    assert_eq!(status, 200);
    assert_eq!(replay, created_body.as_bytes());
    server.registry.remove(&created.session_id);
}

#[test]
fn p4_01_egress_request_time_target_revocation_closes_with_http_error_body() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let fixture = fixture(&target.local_addr().unwrap().to_string(), 4);
    let server = &fixture.server;
    let create = create_request(server, "acl-revoked", Mode::Ws);
    let (status, body, _) = server.route(&create);
    assert_eq!(status, 201);
    let created = parse_create_response(std::str::from_utf8(&body).unwrap());
    let session = server.registry.get(&created.session_id).unwrap();

    // Publish a changed ACL without wiring the egress sweep callback: the next
    // request must discover and close the now-unauthorized live session.
    let config_path = fixture.dir.join("config.yaml");
    let config_text = std::fs::read_to_string(&config_path).unwrap();
    let other_target = format!(
        "  other:\n    network: tcp\n    address: \"{}\"\n",
        target.local_addr().unwrap()
    );
    let config_text = config_text.replace("auth:\n", &format!("{other_target}auth:\n"));
    std::fs::write(
        &config_path,
        config_text.replace("allowed_targets: [db]", "allowed_targets: [other]"),
    )
    .unwrap();
    assert!(server.auth.reload("test").unwrap());
    let request = Request {
        method: "POST".to_string(),
        path: format!("{}/{}/ack", wire::PATH_SESSIONS, created.session_id),
        query: vec![("epoch".to_string(), "1".to_string())],
        version: "HTTP/1.1".to_string(),
        headers: vec![
            (wire::H_PEER_AUTH.to_string(), "Bearer abc".to_string()),
            (
                wire::H_INSTANCE_ID.to_string(),
                server.cfg.node.instance_id.clone(),
            ),
            (wire::H_SESSION_TOKEN.to_string(), created.session_token),
        ],
        body: b"{}".to_vec(),
    };

    let (status, body, _) = server.route(&request);
    let error = error_body(status, &body, 403);
    assert_eq!(error.code, wire::ERR_TARGET_FORBIDDEN);
    assert!(error.session_closed);
    assert!(session.is_closed());
    assert_eq!(
        session.terminal_error().unwrap().code,
        wire::ERR_TARGET_FORBIDDEN
    );
    server.registry.remove(&created.session_id);
}

#[test]
fn p4_01_egress_tombstone_terminal_error_is_preserved_in_http_body() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let fixture = fixture(&target.local_addr().unwrap().to_string(), 4);
    let server = &fixture.server;
    let create = create_request(server, "terminal-tombstone", Mode::Ws);
    let (status, body, _) = server.route(&create);
    assert_eq!(status, 201);
    let created = parse_create_response(std::str::from_utf8(&body).unwrap());
    let session = server.registry.get(&created.session_id).unwrap();

    session.close(Error::new(wire::ERR_BACKEND_LOST, "backend lost").closed(true));
    server.registry.remove(&created.session_id);

    let request = Request {
        method: "POST".to_string(),
        path: format!("{}/{}/ack", wire::PATH_SESSIONS, created.session_id),
        query: vec![("epoch".to_string(), "1".to_string())],
        version: "HTTP/1.1".to_string(),
        headers: vec![
            (wire::H_PEER_AUTH.to_string(), "Bearer abc".to_string()),
            (
                wire::H_INSTANCE_ID.to_string(),
                server.cfg.node.instance_id.clone(),
            ),
            (wire::H_SESSION_TOKEN.to_string(), created.session_token),
        ],
        body: b"{}".to_vec(),
    };

    let (status, body, _) = server.route(&request);
    let error = error_body(status, &body, 410);
    assert_eq!(error.code, wire::ERR_BACKEND_LOST);
    assert!(!error.retryable);
    assert!(error.session_closed);
}

#[test]
fn p4_01_egress_fin_below_queued_up_frame_is_terminal_conflict() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let fixture = fixture(&target.local_addr().unwrap().to_string(), 4);
    let server = &fixture.server;
    let create = create_request(server, "fin-pending-conflict", Mode::HttpSse);
    let (status, body, _) = server.route(&create);
    assert_eq!(status, 201);
    let created = parse_create_response(std::str::from_utf8(&body).unwrap());
    let session = server.registry.get(&created.session_id).unwrap();
    session.attach("sse-stream").unwrap();
    session.ingest_up(1, 100, &[b'x'; 100]).unwrap();

    let fin = session_action_request(
        server,
        &created.session_id,
        &created.session_token,
        "fin",
        "sse-stream",
        br#"{"direction":"up","final_offset":"50"}"#.to_vec(),
    );
    let (status, body, _) = server.route(&fin);
    let error = error_body(status, &body, 409);
    assert_eq!(error.code, wire::ERR_FRAME_CONFLICT);
    assert!(!error.retryable);
    assert!(error.session_closed);
    assert!(session.is_closed());
    assert_eq!(
        session.terminal_error().unwrap().code,
        wire::ERR_FRAME_CONFLICT
    );

    let followup = session_action_request(
        server,
        &created.session_id,
        &created.session_token,
        "ack",
        "sse-stream",
        b"{}".to_vec(),
    );
    let (status, body, _) = server.route(&followup);
    let terminal = error_body(status, &body, 410);
    assert_eq!(terminal.code, wire::ERR_FRAME_CONFLICT);
    assert!(terminal.session_closed);
}

#[test]
fn p4_01_egress_conflicting_up_frame_fences_the_session() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let fixture = fixture(&target.local_addr().unwrap().to_string(), 4);
    let server = &fixture.server;
    let create = create_request(server, "up-conflict", Mode::HttpSse);
    let (status, body, _) = server.route(&create);
    assert_eq!(status, 201);
    let created = parse_create_response(std::str::from_utf8(&body).unwrap());
    let session = server.registry.get(&created.session_id).unwrap();
    session.attach("sse-stream").unwrap();
    session.ingest_up(1, 100, b"first").unwrap();

    let conflict = up_request(
        server,
        &created.session_id,
        &created.session_token,
        "sse-stream",
        100,
        b"other",
    );
    let (status, body, _) = server.route(&conflict);
    let error = error_body(status, &body, 409);
    assert_eq!(error.code, wire::ERR_FRAME_CONFLICT);
    assert!(!error.retryable);
    assert!(error.session_closed);
    assert!(session.is_closed());
    assert_eq!(
        session.terminal_error().unwrap().code,
        wire::ERR_FRAME_CONFLICT
    );

    let (status, body, _) = server.route(&conflict);
    let terminal = error_body(status, &body, 410);
    assert_eq!(terminal.code, wire::ERR_FRAME_CONFLICT);
    assert!(terminal.session_closed);
}

fn normal_close_tombstone(server: &Server, session_id: &str) -> crate::session::Tombstone {
    let session = server.registry.get(session_id).unwrap();
    let mut tombstone = session.compact_tombstone();
    server.registry.remove(session_id);
    tombstone.stream_id = "s-final".to_string();
    tombstone.up_fin = true;
    tombstone.down_fin = true;
    tombstone.down_fin_acked = true;
    tombstone.down_ack = 7;
    tombstone.down_produced = 7;
    tombstone.ack_up = 3;
    tombstone
}

#[test]
fn egress_tombstone_answers_final_ack_and_delete_like_spec_view() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let fixture = fixture(&target.local_addr().unwrap().to_string(), 4);
    let server = &fixture.server;
    let (status, body, _) = server.route(&create_request(server, "tomb-normal", Mode::HttpSse));
    assert_eq!(status, 201);
    let created = parse_create_response(std::str::from_utf8(&body).unwrap());
    let tombstone = normal_close_tombstone(server, &created.session_id);
    server.registry.insert_tombstone(tombstone);
    let ack_body = br#"{"stream_id":"s-final","down_delivered_offset":"7","up_confirmed_offset":"3","down_fin_applied":true,"ready_received":false,"probe_id":"p1","data_tx_blocked":false,"data_rx_blocked":false,"backpressure_reason":"none"}"#;

    // Final ACK of the final generation: 200 with both FIN bits.
    let ack = session_action_request(
        server,
        &created.session_id,
        &created.session_token,
        "ack",
        "s-final",
        ack_body.to_vec(),
    );
    let (status, body, _) = server.route(&ack);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let json = crate::util::json::parse(std::str::from_utf8(&body).unwrap()).unwrap();
    let resp = wire::AckResponse::from_json(&json).unwrap();
    assert!(resp.up_fin_applied && resp.down_fin_acked);
    assert_eq!(resp.stream_id, "s-final");
    assert_eq!(resp.down_ack_offset, 7);
    assert_eq!(resp.ack_up_offset, 3);
    assert_eq!(resp.probe_id, "p1");
    assert_eq!(resp.mode, Mode::HttpSse);

    // Another stream of the same session: the terminal refusal.
    let other = session_action_request(
        server,
        &created.session_id,
        &created.session_token,
        "ack",
        "s-other",
        b"{}".to_vec(),
    );
    let (status, body, _) = server.route(&other);
    let error = error_body(status, &body, 410);
    assert!(error.session_closed);

    let mut stale = ack.clone();
    stale.query = vec![("epoch".to_string(), "2".to_string())];
    let (status, body, _) = server.route(&stale);
    assert_eq!(error_body(status, &body, 409).code, wire::ERR_STALE_EPOCH);

    // up/fin on the tombstone stay refused.
    let fin = session_action_request(
        server,
        &created.session_id,
        &created.session_token,
        "fin",
        "s-final",
        br#"{"direction":"up","final_offset":"3"}"#.to_vec(),
    );
    let (status, body, _) = server.route(&fin);
    assert_eq!(status, 410, "{}", String::from_utf8_lossy(&body));

    let mut delete = session_action_request(
        server,
        &created.session_id,
        &created.session_token,
        "",
        "",
        Vec::new(),
    );
    delete.method = "DELETE".to_string();
    delete.path = format!("{}/{}", wire::PATH_SESSIONS, created.session_id);
    let (status, body, _) = server.route(&delete);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let json = crate::util::json::parse(std::str::from_utf8(&body).unwrap()).unwrap();
    assert_eq!(
        json.get("closed")
            .and_then(crate::util::json::Json::as_bool),
        Some(true)
    );
    assert_eq!(
        json.get("epoch").and_then(crate::util::json::Json::as_str),
        Some("1")
    );
}

#[test]
fn egress_delete_of_closed_live_session_succeeds_like_spec() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let fixture = fixture(&target.local_addr().unwrap().to_string(), 4);
    let server = &fixture.server;
    let (status, body, _) = server.route(&create_request(server, "closed-delete", Mode::HttpSse));
    assert_eq!(status, 201);
    let created = parse_create_response(std::str::from_utf8(&body).unwrap());
    let session = server.registry.get(&created.session_id).unwrap();
    session.close(Error::new(wire::ERR_BACKEND_LOST, "backend lost").closed(true));
    let mut delete = session_action_request(
        server,
        &created.session_id,
        &created.session_token,
        "",
        "",
        Vec::new(),
    );
    delete.method = "DELETE".to_string();
    delete.path = format!("{}/{}", wire::PATH_SESSIONS, created.session_id);
    let (status, body, _) = server.route(&delete);
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert!(server.registry.get(&created.session_id).is_none());
}

fn created_sse(server: &Server, id: &str) -> (wire::CreateResponse, Arc<crate::session::Session>) {
    let (status, body, _) = server.route(&create_request(server, id, Mode::HttpSse));
    assert_eq!(status, 201, "{}", String::from_utf8_lossy(&body));
    let created = parse_create_response(std::str::from_utf8(&body).unwrap());
    let session = server.registry.get(&created.session_id).unwrap();
    (created, session)
}

fn ack_body(down: u64, fin: bool, confirm: u64) -> Vec<u8> {
    format!(
        "{{\"stream_id\":\"sse-stream\",\"down_delivered_offset\":\"{down}\",\"down_fin_applied\":{fin},\"up_confirmed_offset\":\"{confirm}\",\"data_tx_blocked\":false,\"data_rx_blocked\":false,\"backpressure_reason\":\"none\"}}"
    )
    .into_bytes()
}

#[test]
fn spec_oversized_up_frame_is_frame_too_large() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let fixture = fixture(&target.local_addr().unwrap().to_string(), 4);
    let server = &fixture.server;
    let (created, session) = created_sse(server, "u1");
    session.attach("sse-stream").unwrap();
    let body = vec![b'z'; session.limits.max_frame_size + 1];
    let up = up_request(
        server,
        &created.session_id,
        &created.session_token,
        "sse-stream",
        0,
        &body,
    );
    let (status, raw, _) = server.route(&up);
    assert_eq!(
        error_body(status, &raw, 413).code,
        wire::ERR_FRAME_TOO_LARGE
    );
    let mut short = up_request(
        server,
        &created.session_id,
        &created.session_token,
        "sse-stream",
        0,
        &body[..100],
    );
    for (name, value) in short.headers.iter_mut() {
        if name == wire::H_LENGTH {
            *value = "99".to_string();
        }
    }
    let (status, raw, _) = server.route(&short);
    assert_eq!(error_body(status, &raw, 400).code, wire::ERR_BAD_FRAME);
}

#[test]
fn spec_ingest_up_frame_still_verifies_digest() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let fixture = fixture(&target.local_addr().unwrap().to_string(), 4);
    let server = &fixture.server;
    let (created, session) = created_sse(server, "digest");
    session.attach("sse-stream").unwrap();
    let mut up = up_request(
        server,
        &created.session_id,
        &created.session_token,
        "sse-stream",
        0,
        b"x",
    );
    for (name, value) in up.headers.iter_mut() {
        if name == wire::H_SHA256 {
            *value = "0".repeat(64);
        }
    }
    let (status, raw, _) = server.route(&up);
    assert_eq!(error_body(status, &raw, 400).code, wire::ERR_BAD_DIGEST);
    assert_eq!(session.snapshot().ack_up_offset, 0);
}

#[test]
fn spec_write_before_ready() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let fixture = fixture(&target.local_addr().unwrap().to_string(), 4);
    let server = &fixture.server;
    let (created, _session) = created_sse(server, "early");
    let (mut backend, _) = target.accept().unwrap();
    let up = up_request(
        server,
        &created.session_id,
        &created.session_token,
        "",
        0,
        b"x",
    );
    let (status, _raw, _) = server.route(&up);
    assert_ne!(status, 200, "frame accepted before the stream was ready");
    backend
        .set_read_timeout(Some(Duration::from_millis(80)))
        .unwrap();
    let mut buf = [0u8; 1];
    assert!(
        !matches!(backend.read(&mut buf), Ok(n) if n > 0),
        "backend received data before any stream reservation/ready ACK"
    );
}

#[test]
fn spec_final_ack_completes_normal_close() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let fixture = fixture(&target.local_addr().unwrap().to_string(), 4);
    let server = &fixture.server;
    let (created, session) = created_sse(server, "final-ack");
    let (mut backend, _) = target.accept().unwrap();
    session.attach("sse-stream").unwrap();
    session.ingest_up(1, 0, b"hello").unwrap();
    let mut got = [0u8; 5];
    backend.read_exact(&mut got).unwrap();
    assert!(session.ingest_up_fin(1, 5).unwrap(), "up FIN not applied");
    session.mark_down_produced(b"world").unwrap();
    session.mark_down_fin();
    let ack = session_action_request(
        server,
        &created.session_id,
        &created.session_token,
        "ack",
        "sse-stream",
        ack_body(5, true, 5),
    );
    let (status, body, _) = server.route(&ack);
    assert_eq!(status, 200, "final ACK: {}", String::from_utf8_lossy(&body));
    let text = String::from_utf8(body).unwrap();
    assert!(text.contains("\"down_fin_acked\":true"), "{text}");
    assert!(text.contains("\"up_fin_applied\":true"), "{text}");
    assert!(session.finished());
    session.close(Error::local("session finished"));
    let (status, body, _) = server.route(&ack);
    assert_eq!(
        status,
        200,
        "repeated final ACK: {}",
        String::from_utf8_lossy(&body)
    );
}
