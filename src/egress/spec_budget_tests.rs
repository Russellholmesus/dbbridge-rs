use super::{RecordLimits, Server};
use crate::net::http1::Request;
use crate::wire;
use std::io::Read;
use std::net::TcpListener;
use std::sync::Arc;
use std::time::{Duration, Instant};

struct Node {
    server: Arc<Server>,
    dir: std::path::PathBuf,
}

impl Drop for Node {
    fn drop(&mut self) {
        self.server.registry.close_all();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn discard_backend() -> String {
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = ln.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for c in ln.incoming() {
            let Ok(mut c) = c else { return };
            std::thread::spawn(move || {
                let mut buf = [0u8; 64];
                while matches!(c.read(&mut buf), Ok(n) if n > 0) {}
            });
        }
    });
    addr
}

fn node(peers: &[(&str, &str, &str, u32)], targets: &str, extra: &str) -> Node {
    let dir = std::env::temp_dir().join(format!(
        "dbb-egress-gobudget-{}",
        crate::util::random_hex(6).unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let mut inbound = String::new();
    for (id, token, target, max) in peers {
        std::fs::write(dir.join(format!("tok-{id}")), token).unwrap();
        inbound.push_str(&format!(
            "    - id: {id}\n      token_files: [tok-{id}]\n      allowed_targets: [{target}]\n      max_sessions: {max}\n"
        ));
    }
    let text = format!(
        "node:\n  id: B\nhttp:\n  enabled: true\n  listen: \"127.0.0.1:0\"\n  allowed_transports: [ws, http-sse]\ntargets:\n{targets}auth:\n  inbound_peers:\n{inbound}{extra}"
    );
    let path = dir.join("config.yaml");
    std::fs::write(&path, text).unwrap();
    let cfg = Arc::new(crate::config::load(&path).unwrap_or_else(|e| panic!("{}", e.message)));
    let metrics = Arc::new(crate::metrics::Metrics::new());
    metrics.configure_resources(&cfg);
    let server = Arc::new(Server::new(cfg, metrics));
    Node { server, dir }
}

fn db_target(addr: &str) -> String {
    format!("  db:\n    network: tcp\n    address: \"{addr}\"\n")
}

fn request(method: &str, path: &str, headers: Vec<(String, String)>, body: &str) -> Request {
    Request {
        method: method.to_string(),
        path: path.to_string(),
        query: Vec::new(),
        version: "HTTP/1.1".to_string(),
        headers,
        body: body.as_bytes().to_vec(),
    }
}

fn headers(n: &Node, token: &str) -> Vec<(String, String)> {
    vec![
        (wire::H_PEER_AUTH.to_string(), format!("Bearer {token}")),
        (
            wire::H_INSTANCE_ID.to_string(),
            n.server.cfg.node.instance_id.clone(),
        ),
    ]
}

fn create_body(id: &str, target: &str) -> String {
    format!(
        "{{\"protocol_version\":\"{}\",\"transport\":{{\"mode\":\"ws\"}},\"recovery\":{{\"enabled\":false,\"grace_ms\":0}},\"create_request_id\":\"{id}\",\"ingress_instance_id\":\"ai\",\"target_id\":\"{target}\",\"limits\":{{\"max_frame_size\":1024,\"up_max_inflight_frames\":8,\"up_window_bytes\":1024,\"down_buffer_bytes\":1024}}}}",
        wire::PROTOCOL_VERSION
    )
}

fn create(
    n: &Node,
    token: &str,
    id: &str,
    target: &str,
) -> (u16, Option<wire::ErrorBody>, Option<wire::CreateResponse>) {
    let (status, body, _) = n.server.route(&request(
        "POST",
        wire::PATH_SESSIONS,
        headers(n, token),
        &create_body(id, target),
    ));
    let text = String::from_utf8_lossy(&body).to_string();
    if status == 201 || status == 200 {
        let v = crate::util::json::parse(&text).unwrap();
        (status, None, wire::CreateResponse::from_json(&v).ok())
    } else {
        (status, wire::ErrorBody::parse(&text), None)
    }
}

fn delete(n: &Node, token: &str, cr: &wire::CreateResponse) -> u16 {
    let mut h = headers(n, token);
    h.push((wire::H_SESSION_TOKEN.to_string(), cr.session_token.clone()));
    let mut req = request(
        "DELETE",
        &format!("{}/{}", wire::PATH_SESSIONS, cr.session_id),
        h,
        "",
    );
    req.query = vec![("epoch".to_string(), cr.epoch.to_string())];
    n.server.route(&req).0
}

#[test]
fn spec_create_close_churn_does_not_starve_other_peers() {
    let db = discard_backend();
    let n = node(
        &[("A", "tokA", "db", 2), ("B", "tokB", "db", 2)],
        &db_target(&db),
        "limits:\n  max_sessions: 4\ntransport:\n  metadata_limit: 1MiB\n",
    );
    let mut cycles = 0;
    while cycles < 2000 {
        let (st, er, cr) = create(&n, "tokA", &format!("c-{cycles}"), "db");
        if st != 201 {
            let er = er.expect("error body");
            assert!(
                st == 429 && er.message == "peer idempotency quota" && er.retryable,
                "churn refused with {st} {} {}",
                er.code,
                er.message
            );
            break;
        }
        assert_eq!(delete(&n, "tokA", &cr.unwrap()), 200);
        cycles += 1;
    }
    assert!(cycles < 2000, "create/DELETE churn was never bounded");
    let resources = n.server.metrics.resource_manager().unwrap();
    let limit = RecordLimits::from_budget(
        resources.egress_metadata_limit(),
        resources.egress_session_slots(),
        resources.session_metadata_cost(),
        2,
        2,
    )
    .total;
    let got = n
        .server
        .registry
        .creates
        .lock()
        .unwrap()
        .values()
        .filter(|r| r.peer == "A")
        .count();
    assert_eq!(got, limit, "peer A charged {got} records, limit {limit}");
    let (st, er, _) = create(&n, "tokB", "victim", "db");
    assert_eq!(st, 201, "peer B create after A's churn: {er:?}");
    assert!(resources.metadata.used() <= resources.metadata.limit());
}

#[test]
fn spec_rejected_create_metadata_budget() {
    let db = discard_backend();
    let n = node(&[("A", "token", "db", 1)], &db_target(&db), "");
    let metadata = n
        .server
        .metrics
        .resource_manager()
        .unwrap()
        .metadata
        .clone();
    let target = "x".repeat(12 << 10);
    for i in 0..32 {
        let id = format!("rejected-{i}");
        let (st, _, _) = create(&n, "token", &id, &target);
        assert_eq!(st, 403, "unexpected response");
        let used = metadata.used();
        let (st, _, _) = create(&n, "token", &id, &target);
        assert!(
            st == 403 && metadata.used() == used,
            "cached rejection changed status or charged metadata twice"
        );
    }
    assert_eq!(metadata.used(), 0, "refused creates retained metadata");
    assert_eq!(n.server.registry.create_record_count(), 0);
}

#[test]
fn spec_create_cancelled_by_close_is_draining() {
    let n = node(
        &[("X", "tokX", "slow", 1)],
        "  slow:\n    network: tcp\n    address: \"10.255.255.1:3306\"\n",
        "transport:\n  dial_timeout: 2s\n  control_request_timeout: 10s\n",
    );
    let server = n.server.clone();
    let instance = n.server.cfg.node.instance_id.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let h = vec![
            (wire::H_PEER_AUTH.to_string(), "Bearer tokX".to_string()),
            (wire::H_INSTANCE_ID.to_string(), instance),
        ];
        let (st, body, _) = server.route(&request(
            "POST",
            wire::PATH_SESSIONS,
            h,
            &create_body("P", "slow"),
        ));
        let _ = tx.send((st, String::from_utf8_lossy(&body).to_string()));
    });
    if let Ok((st, _)) = rx.recv_timeout(Duration::from_millis(300)) {
        eprintln!("blackhole address answered before Close ({st}); no route in this sandbox");
        return;
    }
    n.server.request_shutdown();
    let started = Instant::now();
    let (st, body) = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("create not cancelled by Close");
    let er = wire::ErrorBody::parse(&body).unwrap();
    assert!(
        st == 503 && er.code == wire::ERR_DRAINING && er.retryable,
        "create cancelled by Close: {st} {body}"
    );
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(n.server.registry.all_sessions().is_empty());
}

/// Starts `n.server` listening on its configured 127.0.0.1:0 and returns
/// the bound address.
fn listen(n: &Node) -> std::net::SocketAddr {
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

#[test]
fn spec_sockets_use_conn_metadata() {
    let db = discard_backend();
    let n = node(&[("A", "tokA", "db", 5)], &db_target(&db), "");
    let resources = n.server.metrics.resource_manager().unwrap();
    let addr = listen(&n);
    let meta = resources.metadata.used();
    let c = std::net::TcpStream::connect(addr).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while resources.conn_metadata.used() == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        resources.conn_metadata.used(),
        16 << 10,
        "ConnMetadata used"
    );
    assert_eq!(
        resources.metadata.used(),
        meta,
        "socket admission charged session Metadata"
    );
    drop(c);
    let deadline = Instant::now() + Duration::from_secs(5);
    while resources.conn_metadata.used() != 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(
        resources.conn_metadata.used(),
        0,
        "ConnMetadata not released"
    );
    n.server.request_shutdown();
}

#[test]
fn spec_maximum_valid_token_can_use_probe() {
    use std::io::Write;
    let token = "x".repeat(8 << 10);
    let db = discard_backend();
    let n = node(&[("A", &token, "db", 1)], &db_target(&db), "");
    let addr = listen(&n);
    let body = format!(
        "{{\"protocol_version\":\"{}\",\"expected_node_id\":\"B\",\"nonce\":\"nonce\"}}",
        wire::PROTOCOL_VERSION
    );
    let mut c = std::net::TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    write!(
        c,
        "POST {} HTTP/1.1\r\nHost: x\r\n{}: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        wire::PATH_PROBE,
        wire::H_PEER_AUTH,
        body.len()
    )
    .unwrap();
    let mut response = Vec::new();
    let _ = c.read_to_end(&mut response);
    let response = String::from_utf8_lossy(&response);
    assert!(
        response.starts_with("HTTP/1.1 200 "),
        "configured valid maximum credential cannot pass the HTTP header budget: {}",
        response.lines().next().unwrap_or("")
    );
    n.server.request_shutdown();
    for size in [(8 << 10) + 1, 16 << 10] {
        let dir =
            std::env::temp_dir().join(format!("dbb-gotok-{}", crate::util::random_hex(6).unwrap()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("tok"), "x".repeat(size)).unwrap();
        let path = dir.join("config.yaml");
        std::fs::write(
            &path,
            "node:\n  id: B\ntargets:\n  db:\n    network: tcp\n    address: 127.0.0.1:3306\nauth:\n  inbound_peers:\n    - id: A\n      token_files: [tok]\n      allowed_targets: [db]\n",
        )
        .unwrap();
        let result = crate::config::load(&path);
        std::fs::remove_dir_all(&dir).ok();
        assert!(result.is_err(), "accepted oversized token_bytes={size}");
    }
}

#[test]
fn spec_resolve_follows_context() {
    let start = Instant::now();
    let r = super::api::resolve_target("db.example.invalid", 3306, Duration::ZERO);
    assert!(
        r.is_err() && start.elapsed() < Duration::from_secs(1),
        "resolution with an expired deadline: {:?} after {:?}",
        r.map(|a| a.len()),
        start.elapsed()
    );
    assert_eq!(
        super::api::resolve_target("127.0.0.1", 9, Duration::ZERO).unwrap(),
        vec!["127.0.0.1:9".parse().unwrap()]
    );
}

/// Sends one raw HTTP/1.1 request (Connection: close) and returns the whole
/// response text.
fn raw(addr: std::net::SocketAddr, head: &str, body: &str) -> String {
    use std::io::Write;
    let mut c = std::net::TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let request = format!(
        "{head}\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    c.write_all(request.as_bytes()).unwrap();
    let mut response = Vec::new();
    let _ = c.read_to_end(&mut response);
    String::from_utf8_lossy(&response).to_string()
}

#[test]
fn spec_unauthenticated_create_does_not_take_creates() {
    let db = discard_backend();
    let n = node(&[("A", "tokA", "db", 5)], &db_target(&db), "");
    let resources = n.server.metrics.resource_manager().unwrap();
    let addr = listen(&n);
    let limit = resources.creates.limit();
    let _held = resources.creates.try_acquire(limit).expect("setup");
    let response = raw(
        addr,
        &format!(
            "POST {} HTTP/1.1\r\n{}: Bearer wrong\r\n{}: {}\r\nContent-Type: application/json",
            wire::PATH_SESSIONS,
            wire::H_PEER_AUTH,
            wire::H_INSTANCE_ID,
            n.server.cfg.node.instance_id
        ),
        &create_body("u1", "db"),
    );
    assert!(
        response.starts_with("HTTP/1.1 401 "),
        "unauthenticated create with Creates exhausted: {}",
        response.lines().next().unwrap_or("")
    );
    let response = raw(addr, &format!("GET {} HTTP/1.1", wire::PATH_SESSIONS), "");
    assert!(
        response.starts_with("HTTP/1.1 405 ")
            && response
                .lines()
                .any(|l| l.eq_ignore_ascii_case("Allow: POST")),
        "GET /v1/sessions: {response}"
    );
    assert_eq!(
        resources.creates.used(),
        limit,
        "creation budget changed by rejected requests"
    );
    n.server.request_shutdown();
}

#[test]
fn spec_authenticate_before_budgets() {
    let db = discard_backend();
    let n = node(&[("A", "tokA", "db", 5)], &db_target(&db), "");
    let resources = n.server.metrics.resource_manager().unwrap();
    let addr = listen(&n);
    let limit = resources.control_requests.limit();
    let _held = resources
        .control_requests
        .try_acquire(limit)
        .expect("setup");
    let response = raw(
        addr,
        &format!(
            "POST {} HTTP/1.1\r\n{}: Bearer wrong\r\nContent-Type: application/json",
            wire::PATH_PROBE,
            wire::H_PEER_AUTH
        ),
        "{}",
    );
    assert!(
        response.starts_with("HTTP/1.1 401 "),
        "unauthenticated request with budgets exhausted: {}",
        response.lines().next().unwrap_or("")
    );
    assert_eq!(
        (
            resources.control_metadata.used(),
            resources.probe_metadata.used()
        ),
        (0, 0),
        "unauthenticated request charged metadata"
    );
    n.server.request_shutdown();
}

#[test]
fn spec_peer_cannot_take_whole_create_budget() {
    let db = discard_backend();
    let n = node(
        &[("A", "tokA", "db", 5), ("C", "tokC", "db", 5)],
        &db_target(&db),
        "",
    );
    let resources = n.server.metrics.resource_manager().unwrap();
    let global = resources.creates.limit();
    let share = crate::auth::peer_share(global, 2);
    assert!(share < global, "share {share} must leave room in {global}");
    let mut held = Vec::new();
    for i in 0..share {
        let fair = n
            .server
            .auth
            .reserve_fair_n("A", "create", global, 1)
            .unwrap_or_else(|| panic!("reservation {i} refused"));
        let lease = resources.creates.try_acquire(1).expect("global budget");
        held.push((fair, lease));
    }
    let (st, er, _) = create(&n, "tokA", "a-over", "db");
    assert_eq!(st, 429, "peer A beyond its share: {er:?}");
    let (st, er, _) = create(&n, "tokC", "c1", "db");
    assert_eq!(st, 201, "peer C starved: {er:?}");
}

/// Opens a connection that sends `head` (with Content-Length 1000) and one
/// body byte, then trickles nothing more: the request holds its admission
/// slot while its body never completes.
fn trickle(addr: std::net::SocketAddr, head: &str) -> std::net::TcpStream {
    use std::io::Write;
    let mut c = std::net::TcpStream::connect(addr).unwrap();
    write!(
        c,
        "{head}\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{{"
    )
    .unwrap();
    c
}

#[test]
fn spec_control_budget_per_peer() {
    let db = discard_backend();
    let n = node(
        &[("V", "tokV", "db", 2), ("G", "tokG", "db", 2)],
        &db_target(&db),
        "transport:\n  control_request_timeout: 10s\n  unattached_timeout: 30s\n",
    );
    let resources = n.server.metrics.resource_manager().unwrap();
    let addr = listen(&n);
    let (_, _, victim) = create(&n, "tokV", "v1", "db");
    let (_, _, greedy) = create(&n, "tokG", "g1", "db");
    let (victim, greedy) = (victim.expect("victim"), greedy.expect("greedy"));
    let slots = resources.control_requests.limit();
    let inst = n.server.cfg.node.instance_id.clone();
    let mut hogs = Vec::new();
    for _ in 0..slots {
        hogs.push(trickle(
            addr,
            &format!(
                "POST {}/{}/ack?epoch=1 HTTP/1.1\r\n{}: Bearer tokG\r\n{}: {}\r\n{}: {inst}",
                wire::PATH_SESSIONS,
                greedy.session_id,
                wire::H_PEER_AUTH,
                wire::H_SESSION_TOKEN,
                greedy.session_token,
                wire::H_INSTANCE_ID
            ),
        ));
    }
    std::thread::sleep(Duration::from_millis(300));
    let held = resources.control_requests.used();
    assert!(
        held <= crate::auth::peer_share(slots, 2),
        "greedy peer holds {held} of {slots} control slots"
    );
    let response = raw(
        addr,
        &format!(
            "DELETE {}/{}?epoch=1 HTTP/1.1\r\n{}: Bearer tokV\r\n{}: {}\r\n{}: {inst}",
            wire::PATH_SESSIONS,
            victim.session_id,
            wire::H_PEER_AUTH,
            wire::H_SESSION_TOKEN,
            victim.session_token,
            wire::H_INSTANCE_ID
        ),
        "",
    );
    assert!(
        response.starts_with("HTTP/1.1 200 "),
        "victim DELETE while greedy peer trickles: {}",
        response.lines().next().unwrap_or("")
    );
    drop(hogs);
    n.server.request_shutdown();
}

#[test]
fn spec_boundary_probe_cannot_starve_delete() {
    let db = discard_backend();
    let n = node(
        &[("A", "token", "db", 1)],
        &db_target(&db),
        "transport:\n  unattached_timeout: 10s\n",
    );
    let addr = listen(&n);
    let (st, er, created) = create(&n, "token", "probe-control", "db");
    assert_eq!(st, 201, "{er:?}");
    let created = created.unwrap();
    let mut probes = Vec::new();
    for _ in 0..16 {
        probes.push(trickle(
            addr,
            &format!(
                "POST {} HTTP/1.1\r\n{}: Bearer token",
                wire::PATH_PROBE,
                wire::H_PEER_AUTH
            ),
        ));
    }
    std::thread::sleep(Duration::from_millis(200));
    let response = raw(
        addr,
        &format!(
            "DELETE {}/{}?epoch=1 HTTP/1.1\r\n{}: Bearer token\r\n{}: {}\r\n{}: {}",
            wire::PATH_SESSIONS,
            created.session_id,
            wire::H_PEER_AUTH,
            wire::H_INSTANCE_ID,
            n.server.cfg.node.instance_id,
            wire::H_SESSION_TOKEN,
            created.session_token
        ),
        "",
    );
    assert!(
        response.starts_with("HTTP/1.1 200 "),
        "16 probes exhausted the control reserve and rejected DELETE: {}",
        response.lines().next().unwrap_or("")
    );
    drop(probes);
    n.server.request_shutdown();
}

/// A client (masked, zero key) WebSocket binary frame.
fn masked_binary(payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0x82];
    match payload.len() {
        n if n < 126 => f.push(0x80 | n as u8),
        n => {
            f.push(0x80 | 126);
            f.extend_from_slice(&(n as u16).to_be_bytes());
        }
    }
    f.extend_from_slice(&[0, 0, 0, 0]);
    f.extend_from_slice(payload);
    f
}

fn malformed_ws_must_terminate(scenario: &str) {
    use std::io::Write;
    let db = discard_backend();
    let n = node(
        &[("A", "token", "db", 1)],
        &db_target(&db),
        "transport:\n  max_frame_size: 1024\n  up_window_bytes: 1024\n  unattached_timeout: 3s\n  recovery:\n    enabled: true\n    grace: 1s\n",
    );
    let addr = listen(&n);
    let inst = n.server.cfg.node.instance_id.clone();
    let body = create_body("malformed-ws", "db").replace(
        r#""enabled":false,"grace_ms":0"#,
        r#""enabled":true,"grace_ms":1000"#,
    );
    let (st, created, _) = n.server.route(&request(
        "POST",
        wire::PATH_SESSIONS,
        headers(&n, "token"),
        &body,
    ));
    assert_eq!(st, 201, "{}", String::from_utf8_lossy(&created));
    let cr = wire::CreateResponse::from_json(
        &crate::util::json::parse(std::str::from_utf8(&created).unwrap()).unwrap(),
    )
    .unwrap();
    let sess = n.server.registry.get(&cr.session_id).unwrap();
    let mut c = std::net::TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    write!(
        c,
        "GET {} HTTP/1.1\r\nHost: x\r\n{}: Bearer token\r\n{}: {inst}\r\n{}: {}\r\n{}: session\r\n{}: {}\r\n{}: 1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: {}\r\n\r\n",
        wire::PATH_WS,
        wire::H_PEER_AUTH,
        wire::H_INSTANCE_ID,
        wire::H_SESSION_TOKEN,
        cr.session_token,
        wire::H_WS_PURPOSE,
        wire::H_WS_SESSION_ID,
        cr.session_id,
        wire::H_WS_EPOCH,
        wire::WS_SUBPROTOCOL
    )
    .unwrap();
    let mut conn = crate::net::BufferedConn::new(c.try_clone().unwrap());
    let (status, _) = crate::net::http1::read_response_head(&mut conn).unwrap();
    assert_eq!(status, 101, "{scenario}: WS attach");
    // Wait for the ready message so the carrier is attached.
    conn.read_exact_vec(2).unwrap();
    let mut msg = wire::encode_ws_frame(1, 0, b"x").unwrap();
    let raw_bytes = match scenario {
        "flags" => {
            msg[1] = 1;
            masked_binary(&msg)
        }
        "short_header" => masked_binary(&msg[..4]),
        "short_payload" => masked_binary(&msg[..msg.len() - 1]),
        "wire_rsv" => vec![0xc2, 0x81, 0, 0, 0, 0, 7],
        _ => unreachable!(),
    };
    c.write_all(&raw_bytes).unwrap();
    let until = Instant::now() + Duration::from_millis(500);
    while !sess.is_closed() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(
        sess.is_closed(),
        "{scenario}: explicit WS protocol violation treated as recoverable transport loss (recovery state {:?})",
        sess.recovery_state()
    );
    n.server.request_shutdown();
}

#[test]
fn spec_boundary_malformed_ws_must_terminate_not_suspend() {
    for scenario in ["flags", "short_header", "short_payload", "wire_rsv"] {
        malformed_ws_must_terminate(scenario);
    }
}

fn local_listener(limits: &str) -> String {
    format!(
        "listeners:\n  - id: l1\n    listen: \"127.0.0.1:0\"\n    peer: P\n    target: db\npeers:\n  - id: P\n    expected_node_id: P\n    credential_ref: P\n    token_file: tok-A\n    endpoints:\n      - {{id: p, url: \"http://127.0.0.1:18081\", priority: 1}}\n{limits}"
    )
}

#[test]
fn spec_local_ingress_reserve() {
    let db = discard_backend();
    let n = node(
        &[("A", "tokA", "db", 8)],
        &db_target(&db),
        &local_listener("limits:\n  max_sessions: 8\n"),
    );
    let resources = n.server.metrics.resource_manager().unwrap();
    let limit = resources.sessions.limit();
    let allowed = limit - (limit / 4).max(1);
    for i in 0..allowed {
        let (st, er, _) = create(&n, "tokA", &format!("s{i}"), "db");
        assert_eq!(st, 201, "create {i}: {er:?}");
    }
    let (st, _, _) = create(&n, "tokA", "over", "db");
    assert_eq!(st, 429, "egress took the local ingress reserve");
    let free = limit - resources.sessions.used();
    let slot = resources.sessions.try_acquire(1);
    assert!(
        free >= 1 && slot.is_some(),
        "no session slot left for local ingress (free {free})"
    );
}

#[test]
fn spec_create_record_budget_leaves_sessions_and_ingress_reserve() {
    let db = discard_backend();
    let n = node(
        &[("A", "tokA", "db", 2)],
        &db_target(&db),
        &local_listener(""),
    );
    let res = n.server.metrics.resource_manager().unwrap();
    let (sess_floor, meta_floor) = res.ingress_reserve();
    assert!(meta_floor > 0, "setup: no ingress reserve");
    let slots = res.sessions.limit() - sess_floor;
    let cost = res.session_metadata_cost();
    let egress = res.metadata.limit() - meta_floor;
    let want = (egress - slots * cost).max(egress / 8).min(egress);
    assert!(egress - slots * cost >= egress / 8, "setup: budget clamped");
    let records = n.server.create_record_limits(2);
    assert_eq!(records.total as i64, want / (2 << 10), "record budget");
    let record_bytes = records.total as i64 * (2 << 10);
    let held = res
        .metadata
        .try_acquire(record_bytes)
        .expect("record budget not available");
    let mut leases = Vec::new();
    for i in 0..slots {
        leases.push(
            res.try_egress_metadata(cost)
                .unwrap_or_else(|| panic!("session {i} metadata refused with full records")),
        );
    }
    assert!(
        res.metadata.try_acquire(meta_floor).is_some(),
        "local ingress reserve taken"
    );
    drop(leases);
    drop(held);
}
