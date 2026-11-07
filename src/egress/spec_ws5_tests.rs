use super::spec_ws3_tests::*;
use crate::wire;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

fn node5(transport: &str, sections: &str) -> Node {
    let dir = std::env::temp_dir().join(format!(
        "dbb-egress-gows5-{}",
        crate::util::random_hex(6).unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    for t in ["tokA", "tokC"] {
        std::fs::write(dir.join(t), t).unwrap();
    }
    std::fs::write(dir.join("tokP"), "abcdefghijklmnop").unwrap();
    let text = format!(
        "node:\n  id: B\nhttp:\n  enabled: true\n  listen: \"127.0.0.1:0\"\n  allowed_transports: [ws, http-sse]\ntargets:\n  db:\n    network: tcp\n    address: \"{}\"\ntransport:\n  max_frame_size: 1024\n  buffer_per_direction: 4096\n  up_window_bytes: 2048\n  up_max_inflight_frames: 8\n  dial_timeout: 1s\n  unattached_timeout: 30s\n  control_request_timeout: 10s\n{transport}{sections}",
        echo_backend()
    );
    let path = dir.join("config.yaml");
    std::fs::write(&path, text).unwrap();
    let cfg = Arc::new(crate::config::load(&path).unwrap_or_else(|e| panic!("{}", e.message)));
    let metrics = Arc::new(crate::metrics::Metrics::new());
    metrics.configure_resources(&cfg);
    let server = Arc::new(super::Server::new(cfg, metrics));
    Node { server, dir }
}

fn peer(id: &str, max_sessions: u32) -> String {
    format!(
        "    - id: {id}\n      token_files: [tok{id}]\n      allowed_targets: [db]\n      max_sessions: {max_sessions}\n"
    )
}

const LISTENER: &str = "listeners:\n  - id: l1\n    listen: \"127.0.0.1:0\"\n    peer: P\n    target: db\npeers:\n  - id: P\n    expected_node_id: P\n    credential_ref: P\n    token_file: tokP\n    endpoints:\n      - {id: p, url: \"http://127.0.0.1:18081\", priority: 1}\n";

#[test]
fn spec_bind_cred_revalidates() {
    let n = node5("", &format!("auth:\n  inbound_peers:\n{}", peer("A", 5)));
    let (status, body) = route_create(
        &n,
        None,
        &create_body("b1", "db", "http-sse", wire::PROTOCOL_VERSION, LIMITS),
    );
    assert_eq!(status, 201, "create {status}: {body}");
    assert!(
        !n.server.bind_cred("A", "revoked"),
        "revoked credential accepted"
    );
    assert!(n.server.bind_cred("A", "tokA"), "valid credential refused");
}

#[test]
fn spec_request_metadata_leaves_ingress_reserve() {
    let n = node5(
        "  metadata_limit: 2097152\n",
        &format!(
            "auth:\n  inbound_peers:\n{}limits:\n  max_sessions: 8\n{LISTENER}",
            peer("A", 5)
        ),
    );
    let addr = listen(&n);
    let res = n.server.metrics.resource_manager().expect("resources");
    assert_eq!(res.metadata.limit(), 1 << 20, "Metadata 1 MiB");
    let (_, reserve) = res.ingress_reserve();
    assert_eq!(reserve, 128 << 10, "reserve 128 KiB");
    let held = res
        .try_egress_metadata(res.egress_metadata_limit() - (32 << 10))
        .expect("setup");
    let (tx, rx) = std::sync::mpsc::channel();
    let mut conns = Vec::new();
    for _ in 0..2 {
        let mut c = TcpStream::connect(addr).unwrap();
        write!(
            c,
            "POST {} HTTP/1.1\r\nHost: x\r\n{}: Bearer tokA\r\n{}: {}\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{{",
            wire::PATH_SESSIONS,
            wire::H_PEER_AUTH,
            wire::H_INSTANCE_ID,
            n.server.cfg.node.instance_id
        )
        .unwrap();
        let mut r = c.try_clone().unwrap();
        conns.push(c);
        let tx = tx.clone();
        std::thread::spawn(move || {
            r.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let mut line = Vec::new();
            let mut buf = [0u8; 12];
            while line.len() < 12 {
                match r.read(&mut buf[..12 - line.len()]) {
                    Ok(0) | Err(_) => break,
                    Ok(k) => line.extend_from_slice(&buf[..k]),
                }
            }
            let _ = tx.send(String::from_utf8_lossy(&line).to_string());
        });
    }
    let got = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(
        got.contains("429"),
        "request beyond the egress metadata was not refused: {got:?}"
    );
    let local = res.metadata.try_acquire(reserve);
    assert!(
        local.is_some(),
        "local ingress reserve taken by remote requests: used {} of {}",
        res.metadata.used(),
        res.metadata.limit()
    );
    drop(local);
    drop(held);
    drop(conns);
}

/// Open `GET /v1/sessions/{id}/events` for `token` and return the stream id
/// of its ready event (the connection stays open).
fn open_sse(
    n: &Node,
    addr: SocketAddr,
    token: &str,
    cr: &wire::CreateResponse,
) -> (String, TcpStream) {
    let mut c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut head = format!(
        "GET {}/{}/events?epoch=1 HTTP/1.1\r\nHost: x\r\n",
        wire::PATH_SESSIONS,
        cr.session_id
    );
    for (k, v) in headers(n, token, None) {
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
    loop {
        let k = c.read(&mut buf).expect("events read");
        assert!(k > 0, "events closed: {}", String::from_utf8_lossy(&got));
        got.extend_from_slice(&buf[..k]);
        let text = String::from_utf8_lossy(&got).to_string();
        assert!(text.starts_with("HTTP/1.1 200"), "events: {text}");
        if let Some(line) = text
            .lines()
            .filter_map(|l| l.strip_prefix("data: "))
            .find(|d| d.contains("\"stream_id\""))
        {
            let v = crate::util::json::parse(line).expect("ready json");
            let id = v
                .get("stream_id")
                .and_then(|s| s.as_str())
                .expect("stream_id")
                .to_string();
            return (id, c);
        }
    }
}

fn up_frame(
    n: &Node,
    addr: SocketAddr,
    token: &str,
    stream: &str,
    cr: &wire::CreateResponse,
    off: u64,
    body: &[u8],
) -> (u16, String) {
    let digest = crate::util::hex(&crate::util::sha256::digest(body));
    let mut c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut head = format!(
        "POST {}/{}/up?epoch=1 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n",
        wire::PATH_SESSIONS,
        cr.session_id
    );
    for (k, v) in headers(n, token, None) {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    for (k, v) in [
        (wire::H_SESSION_TOKEN, cr.session_token.clone()),
        (wire::H_STREAM_ID, stream.to_string()),
        (wire::H_OFFSET, off.to_string()),
        (wire::H_LENGTH, body.len().to_string()),
        (wire::H_SHA256, digest),
        ("Content-Type", "application/octet-stream".to_string()),
        ("Content-Length", body.len().to_string()),
    ] {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    c.write_all(head.as_bytes()).unwrap();
    c.write_all(body).unwrap();
    let mut raw = Vec::new();
    let _ = c.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw).to_string();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (status, text)
}

#[test]
fn spec_ws_readers_stay_within_peer_codec_share() {
    let n = node5(
        "  codec_buffer_limit: 32768\n",
        &format!(
            "auth:\n  inbound_peers:\n{}{}limits:\n  max_sessions: 64\n",
            peer("A", 40),
            peer("C", 4)
        ),
    );
    let addr = listen(&n);
    let res = n.server.metrics.resource_manager().expect("resources");
    let share = crate::auth::peer_share(res.codec.limit(), 2);
    let frame = wire::encode_ws_frame(1, 0, &[b'x'; 1024]).unwrap();
    let mut carriers = Vec::new();
    for i in 0..32 {
        let cr = ws_create(&n, &format!("a{i}"));
        let (status, _, conn) = ws_request(addr, &ws_header(&n, &cr), Some(("13", Some(KEY))));
        assert_eq!(status, 101, "ws attach a{i}");
        let mut sock = conn.try_clone().unwrap();
        // One binary message announcing the whole frame, of which only the
        // first 200 bytes ever arrive.
        let mut head = vec![0x82u8, 0x80 | 126];
        head.extend_from_slice(&(frame.len() as u16).to_be_bytes());
        head.extend_from_slice(&[0, 0, 0, 0]);
        head.extend_from_slice(&frame[..200]);
        sock.write_all(&head).unwrap();
        carriers.push(conn);
    }
    std::thread::sleep(Duration::from_millis(300));
    let used = n.server.codec_for("A").expect("codec share").used();
    assert!(
        used <= share,
        "peer A holds {used} codec bytes, share {share}"
    );

    let mut h = headers(&n, "tokC", None);
    h.push(("Content-Type".to_string(), "application/json".to_string()));
    let (status, body, _) = n.server.route(&request(
        "POST",
        wire::PATH_SESSIONS,
        h,
        &create_body("c1", "db", "http-sse", wire::PROTOCOL_VERSION, LIMITS),
    ));
    let body = String::from_utf8_lossy(&body).to_string();
    assert_eq!(status, 201, "create C {status}: {body}");
    let cr = wire::CreateResponse::from_json(&crate::util::json::parse(&body).unwrap()).unwrap();
    let (stream, _events) = open_sse(&n, addr, "tokC", &cr);
    let (st, raw) = up_frame(&n, addr, "tokC", &stream, &cr, 0, &[b'y'; 1000]);
    assert!(
        st == 200 || st == 202,
        "peer C /up while A's WS readers wait: {st} {raw}"
    );
    drop(carriers);
}

/// One raw HTTP request to `addr`; returns (status, whole response text).
fn raw_http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
) -> (u16, String) {
    let mut c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n");
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("Content-Length: 0\r\n\r\n");
    c.write_all(head.as_bytes()).unwrap();
    let mut raw = Vec::new();
    let _ = c.read_to_end(&mut raw);
    let text = String::from_utf8_lossy(&raw).to_string();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (status, text)
}

#[test]
fn spec_audit_reverse_requests_respect_admission() {
    const TOK: &str = "audit-reverse-token-0123456789abcdef";
    let dir = std::env::temp_dir().join(format!(
        "dbb-egress-gows5-rev-{}",
        crate::util::random_hex(6).unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("tok"), TOK).unwrap();
    std::fs::write(dir.join("tokA"), "tokA").unwrap();
    let text = format!(
        "node:\n  id: hq\nhttp:\n  enabled: true\n  listen: \"127.0.0.1:0\"\npeers:\n  - id: plant\n    mode: reverse\n    expected_node_id: plant\n    credential_ref: plant\n    token_file: tok\nlisteners:\n  - id: l\n    listen: \"127.0.0.1:0\"\n    peer: plant\n    target: db\ntargets:\n  db:\n    network: tcp\n    address: \"{}\"\nauth:\n  inbound_peers:\n{}",
        echo_backend(),
        peer("A", 5)
    );
    let path = dir.join("config.yaml");
    std::fs::write(&path, text).unwrap();
    let cfg = Arc::new(crate::config::load(&path).unwrap_or_else(|e| panic!("{}", e.message)));
    let metrics = Arc::new(crate::metrics::Metrics::new());
    metrics.configure_resources(&cfg);
    let mut server = super::Server::new(cfg.clone(), metrics.clone());
    let hub = Arc::new(crate::tunnel::Hub::new(&cfg));
    hub.set_auth(server.auth.clone());
    let res = metrics.resource_manager().expect("resources");
    hub.set_resources(res.clone());
    server.hub = Some(hub.clone());
    let n = Node {
        server: Arc::new(server),
        dir,
    };
    let addr = listen(&n);

    let id = "tn_00000000000000000000000000000001";
    let (st, raw) = raw_http(
        addr,
        "POST",
        &format!("/v1/reverse/{id}/open"),
        &[
            ("Authorization", format!("Bearer {TOK}")),
            (crate::tunnel::H_NODE_ID, "plant".to_string()),
            (crate::tunnel::H_EXPECTED_NODE_ID, "hq".to_string()),
            (wire::H_INSTANCE_ID, "pi_audit".to_string()),
            (crate::tunnel::H_TUNNEL_ID, id.to_string()),
            (crate::tunnel::H_TUNNEL_PRIORITY, "1".to_string()),
            (
                "X-DBB-Reverse-Protocol",
                crate::tunnel::REVERSE_SUBPROTOCOL.to_string(),
            ),
            ("X-DBB-Tunnel-Transport", "long-poll".to_string()),
        ],
    );
    assert_eq!(st, 200, "open: {raw}");

    // Hold every configured data request slot before another upload arrives.
    let b = res.data_requests.clone();
    let held = b
        .try_acquire(b.limit())
        .expect("cannot occupy request budget");
    let empty = crate::util::hex(&crate::util::sha256::digest(b""));
    let upload = || {
        raw_http(
            addr,
            "POST",
            &format!("/v1/reverse/{id}/up"),
            &[
                ("Authorization", format!("Bearer {TOK}")),
                (wire::H_INSTANCE_ID, "pi_audit".to_string()),
                (wire::H_OFFSET, "0".to_string()),
                (wire::H_SHA256, empty.clone()),
            ],
        )
    };
    let (st, raw) = upload();
    assert_ne!(
        st,
        200,
        "reverse upload admitted while all data request slots are held: used={} limit={} {raw}",
        b.used(),
        b.limit()
    );
    // Once the slots are free again the upload is admitted, and every budget
    // it took is back afterwards.
    drop(held);
    let (meta, codec) = (res.metadata.used(), res.codec.used());
    let (st, raw) = upload();
    assert_eq!(st, 200, "upload after release: {raw}");
    assert!(
        b.used() == 0 && res.metadata.used() == meta && res.codec.used() == codec,
        "budgets not restored: requests={} metadata {meta}->{} codec {codec}->{}",
        b.used(),
        res.metadata.used(),
        res.codec.used()
    );
    hub.close();
}

#[test]
fn spec_quota_reload_rejects_zero_and_retains_counts() {
    let dir = std::env::temp_dir().join(format!(
        "dbb-egress-gows5-quota-{}",
        crate::util::random_hex(6).unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("tokA"), "tokA").unwrap();
    let creds = |quota: &str| {
        std::fs::write(
            dir.join("auth.yaml"),
            format!("version: 1\ninbound_peers:\n- id: A\n  token_files: [tokA]\n  allowed_targets: [db]\n  max_sessions: {quota}\n"),
        )
        .unwrap()
    };
    creds("2");
    let path = dir.join("config.yaml");
    std::fs::write(
        &path,
        format!(
            "node:\n  id: B\nhttp:\n  enabled: true\n  listen: \"127.0.0.1:0\"\n  allowed_transports: [ws, http-sse]\ntargets:\n  db:\n    network: tcp\n    address: \"{}\"\nauth:\n  credentials_file: auth.yaml\n  reload_interval: 1h\ntransport:\n  max_frame_size: 1024\n  buffer_per_direction: 4096\n  up_window_bytes: 2048\n  up_max_inflight_frames: 8\n  unattached_timeout: 30s\n",
            echo_backend()
        ),
    )
    .unwrap();
    let mut cfg = crate::config::load(&path).unwrap_or_else(|e| panic!("{}", e.message));
    cfg.path = path;
    let cfg = Arc::new(cfg);
    let metrics = Arc::new(crate::metrics::Metrics::new());
    metrics.configure_resources(&cfg);
    let n = Node {
        server: Arc::new(super::Server::new(cfg, metrics)),
        dir: dir.clone(),
    };
    let mut seq = 0;
    let mut create = || {
        seq += 1;
        route_create(
            &n,
            None,
            &create_body(
                &format!("q{seq}"),
                "db",
                "http-sse",
                wire::PROTOCOL_VERSION,
                LIMITS,
            ),
        )
    };
    let quota_refused = |(status, body): (u16, String)| {
        status == 429
            && code(&body) == wire::ERR_QUOTA_EXCEEDED
            && body.contains("peer session quota")
    };
    let mut live = Vec::new();
    for _ in 0..2 {
        let (status, body) = create();
        assert_eq!(status, 201, "create: {body}");
        live.push(
            wire::CreateResponse::from_json(&crate::util::json::parse(&body).unwrap())
                .unwrap()
                .session_id,
        );
    }
    let auth = n.server.auth.clone();
    let revision = || auth.revision();
    let rev = revision();
    creds("0");
    assert!(auth.reload("interval").is_err());
    assert_eq!(revision(), rev, "invalid quota replaced snapshot");
    assert!(quota_refused(create()), "invalid quota erased counts");

    creds("1");
    assert!(auth.reload("interval").unwrap());
    assert_ne!(revision(), rev, "lower quota not installed");
    assert!(
        quota_refused(create()),
        "lower quota did not retain active counts"
    );
    let decr = |id: &str| {
        let s = n.server.registry.get(id).expect("live session");
        s.close(crate::error::Error::new(
            wire::ERR_SESSION_CLOSED,
            "test close",
        ));
        n.server.registry.remove(id);
    };
    decr(&live[0]);
    assert!(
        quota_refused(create()),
        "one active session must exhaust quota one"
    );
    decr(&live[1]);
    let (status, body) = create();
    assert_eq!(status, 201, "create after both sessions ended: {body}");
}

fn reverse_hub_node(tok: &str) -> (Node, Arc<crate::tunnel::Hub>, SocketAddr) {
    let dir = std::env::temp_dir().join(format!(
        "dbb-egress-gows5-hub-{}",
        crate::util::random_hex(6).unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("tok"), tok).unwrap();
    std::fs::write(
        dir.join("hq.yaml"),
        "node:\n  id: hq-b\nhttp:\n  enabled: true\n  listen: \"127.0.0.1:0\"\npeers:\n  - id: plant\n    mode: reverse\n    expected_node_id: plant-a\n    credential_ref: plant\n    token_file: tok\nlisteners:\n  - id: l\n    listen: \"127.0.0.1:0\"\n    peer: plant\n    target: db\ntargets:\n  db:\n    network: tcp\n    address: \"127.0.0.1:9\"\n",
    )
    .unwrap();
    let cfg = Arc::new(
        crate::config::load(&dir.join("hq.yaml")).unwrap_or_else(|e| panic!("{}", e.message)),
    );
    let metrics = Arc::new(crate::metrics::Metrics::new());
    metrics.configure_resources(&cfg);
    let mut server = super::Server::new(cfg.clone(), metrics.clone());
    let hub = Arc::new(crate::tunnel::Hub::new(&cfg));
    hub.set_auth(server.auth.clone());
    hub.set_resources(metrics.resource_manager().expect("resources"));
    server.hub = Some(hub.clone());
    metrics.set_reverse_hub(&hub);
    let n = Node {
        server: Arc::new(server),
        dir,
    };
    let addr = listen(&n);
    (n, hub, addr)
}

fn plant_config(n: &Node, reverse_extra: &str) -> Arc<crate::config::Config> {
    let path = n.dir.join(format!(
        "plant-{}.yaml",
        crate::util::random_hex(4).unwrap()
    ));
    std::fs::write(
        &path,
        format!("node:\n  id: plant-a\nhttp:\n  enabled: false\nreverse:\n  enabled: true\n  peer_node_id: hq-b\n  token_file: tok\n  transport: ws\n{reverse_extra}targets:\n  db:\n    network: tcp\n    address: '127.0.0.1:3306'\nauth:\n  inbound_peers:\n    - id: hq-b\n      token_files: [tok]\n      allowed_targets: [db]\n"),
    )
    .unwrap();
    Arc::new(crate::config::load(&path).unwrap_or_else(|e| panic!("{}", e.message)))
}

fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !f() {
        assert!(std::time::Instant::now() < deadline, "timed out: {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn spec_hub_client_streams() {
    let (n, hub, addr) = reverse_hub_node("reverse-token-0123456789abcdef");
    let err = hub
        .open_stream("plant")
        .err()
        .expect("stream without tunnel");
    assert_eq!(err.code, wire::ERR_TUNNEL_NOT_FOUND, "err = {err:?}");
    assert!(err.retryable, "tunnel unavailable must be retryable");

    let ccfg = plant_config(
        &n,
        &format!("  endpoints:\n    - id: e1\n      url: http://{addr}\n"),
    );
    let ln = Arc::new(crate::tunnel::client::TunnelListener::new());
    let cl = crate::tunnel::client::Client::new(ccfg, ln.clone());
    let _threads = cl.start();
    wait_until("two tunnels on both sides", || {
        hub.live_tunnels("plant") == 2 && cl.live_count() == 2
    });
    let echo_ln = ln.clone();
    std::thread::spawn(move || {
        while let Some(mut c) = echo_ln.accept_next() {
            std::thread::spawn(move || {
                let mut buf = [0u8; 1024];
                loop {
                    match c.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(k) => {
                            if c.write_all(&buf[..k]).is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    let mut s = hub.open_stream("plant").expect("open stream");
    let desc = crate::net::Conn::describe(&s);
    assert!(
        desc.starts_with("tunnel stream"),
        "stream remote address {desc}"
    );
    s.write_all(b"ping").unwrap();
    crate::net::Conn::set_read_timeout(&s, Some(Duration::from_secs(5))).unwrap();
    let mut buf = [0u8; 4];
    s.read_exact(&mut buf).expect("echo");
    assert_eq!(&buf, b"ping", "echo");
    drop(s);
    cl.stop();
    ln.close();
    hub.close();
}

#[test]
fn spec_client_priority() {
    let (n, hub, addr) = reverse_hub_node("reverse-token-0123456789abcdef");
    let backup = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let backup_addr = backup.local_addr().unwrap();
    let backup_dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let dials = backup_dials.clone();
    std::thread::spawn(move || {
        for c in backup.incoming() {
            let Ok(c) = c else { return };
            dials.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            drop(c); // "backup unreachable"
        }
    });
    let ccfg = plant_config(
        &n,
        &format!("  tunnels_per_endpoint: 1\n  endpoints:\n    - id: e1\n      url: http://{addr}\n      priority: 1\n    - id: backup\n      url: http://{backup_addr}\n      priority: 2\n"),
    );
    let ln = Arc::new(crate::tunnel::client::TunnelListener::new());
    let cl = crate::tunnel::client::Client::new(ccfg, ln.clone());
    let _threads = cl.start();
    wait_until("primary tunnel", || hub.live_tunnels("plant") == 1);
    std::thread::sleep(Duration::from_millis(200));
    let k = backup_dials.load(std::sync::atomic::Ordering::SeqCst);
    // The backup slot may have raced the first dial once, but not more.
    assert!(
        k <= 1,
        "backup endpoint dialed {k} times while primary was up"
    );
    cl.stop();
    ln.close();
    hub.close();
}

#[test]
fn spec_reverse_tunnel_metrics() {
    let (n, hub, addr) = reverse_hub_node("reverse-token-0123456789abcdef");
    let ccfg = plant_config(
        &n,
        &format!("  reconnect: {{min_backoff: 20ms, max_backoff: 100ms}}\n  endpoints:\n    - id: primary\n      url: http://{addr}\n"),
    );
    let db_metrics = Arc::new(crate::metrics::Metrics::new());
    let ln = Arc::new(crate::tunnel::client::TunnelListener::new());
    let cl = crate::tunnel::client::Client::new(ccfg.clone(), ln.clone())
        .with_metrics(db_metrics.clone());
    let _threads = cl.start();
    wait_until("two tunnels", || {
        hub.live_tunnels("plant") == 2 && cl.live_count() == 2
    });
    let public = || {
        n.server
            .metrics
            .render(&n.server.cfg, std::time::Instant::now(), true)
    };
    let db = || db_metrics.render(&ccfg, std::time::Instant::now(), true);
    let m = public();
    for want in [
        "dbb_reverse_hub_tunnels{peer=\"plant\",transport=\"ws\"} 2\n",
        "dbb_reverse_hub_tunnels{peer=\"plant\",transport=\"http-sse\"} 0\n",
        "dbb_reverse_hub_accepted_total 2\n",
        "# TYPE dbb_reverse_hub_rejected_total counter\n",
    ] {
        assert!(m.contains(want), "public metrics lack {want:?}:\n{m}");
    }
    let m = db();
    for want in [
        "dbb_reverse_tunnels{endpoint=\"primary\",transport=\"ws\"} 2\n",
        "dbb_reverse_tunnel_established_total 2\n",
        "dbb_reverse_tunnel_lost_total 0\n",
        "# TYPE dbb_reverse_tunnel_fallback_total counter\n",
    ] {
        assert!(
            m.contains(want),
            "database-side metrics lack {want:?}:\n{m}"
        );
    }
    assert!(
        !db().contains("dbb_reverse_hub_") && !public().contains("dbb_reverse_tunnels{"),
        "a side renders the other side's tunnel metrics"
    );
    cl.close_tunnels();
    wait_until("tunnels back", || {
        db().contains("dbb_reverse_tunnel_established_total 4\n")
            && hub.live_tunnels("plant") == 2
            && cl.live_count() == 2
    });
    let m = db();
    assert!(
        m.contains("dbb_reverse_tunnel_lost_total 2\n")
            && m.contains("dbb_reverse_tunnel_established_total 4\n"),
        "reconnect not counted:\n{m}"
    );
    cl.stop();
    ln.close();
    hub.close();
}
