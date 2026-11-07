use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::net::http1::Request;
use crate::net::BufferedConn;
use crate::wire;

use super::{Hub, H_EXPECTED_NODE_ID, H_NODE_ID, H_TUNNEL_ID, H_TUNNEL_PRIORITY};

pub(super) fn config() -> Config {
    let dir = std::env::temp_dir().join(format!(
        "dbb-hub-{}",
        crate::util::random_hex(6).expect("OS random for test fixture")
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("peer-token"), "abc").unwrap();
    let path: PathBuf = dir.join("config.yaml");
    std::fs::write(
        &path,
        "node:\n  id: peer-a\nhttp:\n  enabled: true\n  listen: \"127.0.0.1:18080\"\nlisteners:\n  - id: local\n    listen: \"127.0.0.1:13306\"\n    peer: peer-b\n    target: db\npeers:\n  - id: peer-b\n    mode: reverse\n    expected_node_id: peer-b\n    credential_ref: peer-b\n    token_file: peer-token\ntargets:\n  db:\n    network: tcp\n    address: \"127.0.0.1:3306\"\nauth:\n  inbound_peers:\n    - id: peer-b\n      token_files: [peer-token]\n      allowed_targets: [db]\n",
    )
    .unwrap();
    let cfg = crate::config::load(&path).unwrap();
    std::fs::remove_dir_all(dir).unwrap();
    cfg
}

pub(super) fn tunnel_id(n: usize) -> String {
    format!("tn_{n:032x}")
}

pub(super) fn valid_request() -> Request {
    Request {
        method: "GET".to_string(),
        path: "/v1/reverse".to_string(),
        query: Vec::new(),
        version: "HTTP/1.1".to_string(),
        headers: vec![
            (wire::H_PEER_AUTH.to_string(), "Bearer abc".to_string()),
            (H_NODE_ID.to_string(), "peer-b".to_string()),
            (H_EXPECTED_NODE_ID.to_string(), "peer-a".to_string()),
            (H_TUNNEL_ID.to_string(), tunnel_id(1)),
            (H_TUNNEL_PRIORITY.to_string(), "0".to_string()),
            (wire::H_INSTANCE_ID.to_string(), "instance-b".to_string()),
            (
                "Sec-WebSocket-Protocol".to_string(),
                super::REVERSE_SUBPROTOCOL.to_string(),
            ),
            ("Upgrade".to_string(), "websocket".to_string()),
            ("Connection".to_string(), "Upgrade".to_string()),
            ("Sec-WebSocket-Version".to_string(), "13".to_string()),
            (
                "Sec-WebSocket-Key".to_string(),
                "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
            ),
        ],
        body: Vec::new(),
    }
}

fn request_for(id: &str, instance: &str) -> Request {
    let mut req = valid_request();
    set_header(&mut req, H_TUNNEL_ID, Some(id));
    set_header(&mut req, wire::H_INSTANCE_ID, Some(instance));
    req
}

fn http_open_request(id: &str, instance: &str) -> Request {
    let mut req = request_for(id, instance);
    req.method = "POST".to_string();
    req.path = format!("/v1/reverse/{id}/open");
    set_header(
        &mut req,
        "X-DBB-Reverse-Protocol",
        Some(super::REVERSE_SUBPROTOCOL),
    );
    req
}

pub(super) fn set_header(req: &mut Request, name: &str, value: Option<&str>) {
    req.headers
        .retain(|(key, _)| !key.eq_ignore_ascii_case(name));
    if let Some(value) = value {
        req.headers.push((name.to_string(), value.to_string()));
    }
}

fn assert_error(err: &crate::error::Error, code: &str, status: u16) {
    assert_eq!(err.code, code, "{err}");
    assert_eq!(err.status(), status, "{err}");
}

fn assert_rejected(hub: &Hub, cfg: &Config, req: &Request, code: &str, status: u16) {
    let err = hub.reserve(req, cfg).err().unwrap();
    assert_error(&err, code, status);
}

fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    (server, client)
}

fn register_ws_tunnel(hub: &Hub, cfg: &Config, req: &Request) -> TcpStream {
    let reserved = hub.reserve(req, cfg).unwrap();
    let (hub_conn, peer_conn) = tcp_pair();
    hub.register(reserved, BufferedConn::new(hub_conn), cfg, None)
        .unwrap();
    peer_conn
}

fn wait_for_tunnels(hub: &Hub, peer: &str, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while hub.live_tunnels(peer) != count {
        assert!(
            Instant::now() < deadline,
            "tunnel count did not reach {count}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn handshake_status_table() {
    let cfg = config();
    let hub = Hub::new(&cfg);

    let mut req = valid_request();
    set_header(&mut req, wire::H_PEER_AUTH, None);
    assert_rejected(&hub, &cfg, &req, wire::ERR_UNAUTHORIZED, 401);

    let mut req = valid_request();
    set_header(&mut req, wire::H_PEER_AUTH, Some("Bearer wrong-token"));
    assert_rejected(&hub, &cfg, &req, wire::ERR_UNAUTHORIZED, 401);

    let mut req = valid_request();
    set_header(&mut req, H_NODE_ID, Some("unexpected-node"));
    assert_rejected(&hub, &cfg, &req, wire::ERR_NODE_MISMATCH, 403);

    let mut req = valid_request();
    set_header(&mut req, H_EXPECTED_NODE_ID, Some("unexpected-public-node"));
    assert_rejected(&hub, &cfg, &req, wire::ERR_NODE_MISMATCH, 403);

    let mut req = valid_request();
    set_header(
        &mut req,
        "Sec-WebSocket-Protocol",
        Some("dbbridge.reverse.v1.4"),
    );
    assert_rejected(&hub, &cfg, &req, wire::ERR_PROTOCOL_MISMATCH, 409);

    let mut req = valid_request();
    set_header(&mut req, "Sec-WebSocket-Protocol", None);
    assert_rejected(&hub, &cfg, &req, wire::ERR_TRANSPORT_UNSUPPORTED, 409);

    let mut req = valid_request();
    set_header(&mut req, "Upgrade", None);
    set_header(&mut req, "Connection", None);
    assert_rejected(&hub, &cfg, &req, wire::ERR_TRANSPORT_UNSUPPORTED, 426);

    let mut req = valid_request();
    set_header(&mut req, H_TUNNEL_ID, Some("bad-id"));
    assert_rejected(&hub, &cfg, &req, wire::ERR_BAD_FRAME, 400);

    let mut req = valid_request();
    set_header(&mut req, H_TUNNEL_PRIORITY, Some("-1"));
    assert_rejected(&hub, &cfg, &req, wire::ERR_BAD_FRAME, 400);

    let mut req = valid_request();
    set_header(&mut req, "Sec-WebSocket-Version", Some("12"));
    assert_rejected(&hub, &cfg, &req, wire::ERR_BAD_FRAME, 400);

    let mut req = valid_request();
    set_header(&mut req, "Sec-WebSocket-Key", Some("not-base64"));
    assert_rejected(&hub, &cfg, &req, wire::ERR_BAD_FRAME, 400);

    let reserved = hub.reserve(&valid_request(), &cfg).unwrap();
    assert!(reserved
        .headers
        .iter()
        .any(|(name, value)| name.eq_ignore_ascii_case("Cache-Control") && value == "no-store"));
    assert!(reserved
        .headers
        .iter()
        .any(|(name, value)| { name.eq_ignore_ascii_case(H_NODE_ID) && value == "peer-a" }));
    assert!(reserved.headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case(wire::H_INSTANCE_ID) && value == &cfg.node.instance_id
    }));
}

#[test]
fn shared_token_selects_peer_by_expected_node_id() {
    let mut cfg = config();
    let mut second_peer = cfg.peers[0].clone();
    second_peer.id = "peer-c".to_string();
    second_peer.expected_node_id = "peer-c".to_string();
    cfg.peers.push(second_peer);

    let hub = Hub::new(&cfg);
    let mut req = valid_request();
    set_header(&mut req, H_NODE_ID, Some("peer-c"));
    assert!(hub.reserve(&req, &cfg).is_ok());
}

#[test]
fn pending_registration_rechecks_rotated_credential() {
    let mut cfg = config();
    let hub = Hub::new(&cfg);
    let reserved = hub.reserve(&valid_request(), &cfg).unwrap();

    cfg.peers[0].token = "rotated-token-0123456789abcdef".to_string();
    let conn = BufferedConn::new(crate::tunnel::pipe::Pipe::new("test", "hub"));
    let err = hub.register(reserved, conn, &cfg, None).unwrap_err();
    assert_error(&err, wire::ERR_UNAUTHORIZED, 401);
    assert_eq!(hub.live_tunnels("peer-b"), 0);
}

#[test]
fn hub_refuses_duplicate_and_foreign_instances_but_allows_restart() {
    let cfg = config();
    let hub = Hub::new(&cfg);
    let first_id = tunnel_id(11);
    let first_req = request_for(&first_id, "instance-b");
    let first_peer = register_ws_tunnel(&hub, &cfg, &first_req);
    assert_eq!(hub.live_tunnels("peer-b"), 1);

    let duplicate = request_for(&first_id, "instance-b");
    assert_rejected(&hub, &cfg, &duplicate, wire::ERR_TUNNEL_CONFLICT, 409);

    let foreign = request_for(&tunnel_id(12), "instance-impostor");
    assert_rejected(&hub, &cfg, &foreign, wire::ERR_TUNNEL_CONFLICT, 409);

    let second_req = request_for(&tunnel_id(13), "instance-b");
    let second_peer = register_ws_tunnel(&hub, &cfg, &second_req);
    assert_eq!(hub.live_tunnels("peer-b"), 2);

    first_peer.shutdown(Shutdown::Both).unwrap();
    second_peer.shutdown(Shutdown::Both).unwrap();
    wait_for_tunnels(&hub, "peer-b", 0);

    let restarted_req = request_for(&tunnel_id(14), "instance-impostor");
    let restarted_peer = register_ws_tunnel(&hub, &cfg, &restarted_req);
    assert_eq!(hub.live_tunnels("peer-b"), 1);
    restarted_peer.shutdown(Shutdown::Both).unwrap();
    wait_for_tunnels(&hub, "peer-b", 0);
    hub.close();
}

#[test]
fn hub_tunnel_capacity_rejects_overflow_and_reclaims_closed_sessions() {
    let cfg = config();
    let hub = Hub::new(&cfg);
    let mut peers = Vec::with_capacity(super::MAX_TUNNELS_PER_PEER);

    for n in 0..super::MAX_TUNNELS_PER_PEER {
        let req = request_for(&tunnel_id(100 + n), "instance-b");
        peers.push(register_ws_tunnel(&hub, &cfg, &req));
    }
    assert_eq!(hub.live_tunnels("peer-b"), super::MAX_TUNNELS_PER_PEER);

    let overflow = request_for(&tunnel_id(100 + super::MAX_TUNNELS_PER_PEER), "instance-b");
    assert_rejected(&hub, &cfg, &overflow, wire::ERR_QUOTA_EXCEEDED, 429);

    for peer in &mut peers {
        peer.shutdown(Shutdown::Both).unwrap();
    }
    wait_for_tunnels(&hub, "peer-b", 0);

    let after_close = request_for(&tunnel_id(1000), "instance-after-close");
    assert!(hub.reserve(&after_close, &cfg).is_ok());
    hub.close();
}

#[test]
fn hub_stream_allocation_respects_capacity_and_close_errors() {
    let cfg = config();
    let hub = Hub::new(&cfg);

    let unavailable = match hub.open_stream("peer-b") {
        Ok(stream) => {
            drop(stream);
            panic!("opened a stream without a registered tunnel");
        }
        Err(err) => err,
    };
    assert_error(&unavailable, wire::ERR_TUNNEL_NOT_FOUND, 404);
    assert!(unavailable.retryable);

    let req = request_for(&tunnel_id(2001), "instance-b");
    let peer = register_ws_tunnel(&hub, &cfg, &req);
    let mut streams = Vec::with_capacity(super::MAX_STREAMS_PER_TUNNEL);
    for _ in 0..super::MAX_STREAMS_PER_TUNNEL {
        streams.push(hub.open_stream("peer-b").unwrap());
    }
    let full = match hub.open_stream("peer-b") {
        Ok(stream) => {
            drop(stream);
            panic!("opened a stream beyond the per-tunnel capacity");
        }
        Err(err) => err,
    };
    assert_error(&full, wire::ERR_TUNNEL_NOT_FOUND, 404);

    hub.close();
    assert_eq!(hub.live_tunnels("peer-b"), 0);
    let write_err = std::io::Write::write(&mut streams[0], b"after close").unwrap_err();
    assert_eq!(write_err.kind(), std::io::ErrorKind::BrokenPipe);

    let draining = hub.reserve(&valid_request(), &cfg).err().unwrap();
    assert_error(&draining, wire::ERR_DRAINING, 503);
    assert!(draining.retryable);

    drop(streams);
    peer.shutdown(Shutdown::Both).unwrap();
}

#[test]
fn http_tunnel_requests_bind_token_instance_and_rotation() {
    let cfg = config();
    let hub = Hub::new(&cfg);
    let id = tunnel_id(3001);
    hub.open_http(
        &http_open_request(&id, "instance-b"),
        &cfg,
        &id,
        "long-poll",
    )
    .unwrap();

    let mut wrong_token = http_open_request(&id, "instance-b");
    set_header(
        &mut wrong_token,
        wire::H_PEER_AUTH,
        Some("Bearer wrong-token"),
    );
    let err = hub.http_reader_start(&wrong_token, &id, &cfg).unwrap_err();
    assert_error(&err, wire::ERR_UNAUTHORIZED, 401);

    let wrong_instance = http_open_request(&id, "instance-other");
    let err = hub
        .http_reader_start(&wrong_instance, &id, &cfg)
        .unwrap_err();
    assert_error(&err, wire::ERR_TUNNEL_NOT_FOUND, 404);

    let mut rotated_cfg = cfg.clone();
    rotated_cfg.peers[0].token = "rotated-token-0123456789abcdef".to_string();
    let old_token = http_open_request(&id, "instance-b");
    let err = hub
        .http_reader_start(&old_token, &id, &rotated_cfg)
        .unwrap_err();
    assert_error(&err, wire::ERR_UNAUTHORIZED, 401);

    let mut new_token = http_open_request(&id, "instance-b");
    set_header(
        &mut new_token,
        wire::H_PEER_AUTH,
        Some("Bearer rotated-token-0123456789abcdef"),
    );
    let err = hub
        .http_reader_start(&new_token, &id, &rotated_cfg)
        .unwrap_err();
    assert_error(&err, wire::ERR_TUNNEL_NOT_FOUND, 404);
    hub.close();
}

#[test]
fn invalid_http_ack_closes_and_drops_its_tunnel() {
    let cfg = config();
    let hub = Hub::new(&cfg);
    let id = tunnel_id(4001);
    hub.open_http(
        &http_open_request(&id, "instance-b"),
        &cfg,
        &id,
        "long-poll",
    )
    .unwrap();

    let mut bad_ack = http_open_request(&id, "instance-b");
    set_header(&mut bad_ack, wire::H_ACK_DOWN_OFFSET, Some("1"));
    let err = hub.http_reader_start(&bad_ack, &id, &cfg).unwrap_err();
    assert_error(&err, wire::ERR_BAD_ACK, 400);
    assert_eq!(hub.live_tunnels("peer-b"), 0);

    let lookup = http_open_request(&id, "instance-b");
    let err = hub.http_reader_start(&lookup, &id, &cfg).unwrap_err();
    assert_error(&err, wire::ERR_TUNNEL_NOT_FOUND, 404);
    hub.close();
}

#[test]
fn tunnel_holds_its_connection_slot_and_streams_charge_codec() {
    let cfg = config();
    let hub = std::sync::Arc::new(Hub::new(&cfg));
    let resources = crate::resource::manager::ResourceManager::new(&cfg);
    hub.set_resources(resources.clone());
    let reserved = hub.reserve(&valid_request(), &cfg).unwrap();
    let (hub_conn, peer_conn) = tcp_pair();
    let guard = std::sync::Arc::new(());
    hub.register(
        reserved,
        BufferedConn::new(hub_conn),
        &cfg,
        Some(Box::new(guard.clone())),
    )
    .unwrap();
    assert_eq!(std::sync::Arc::strong_count(&guard), 2);

    let dialer = super::TunnelDialer::new(hub.clone(), "peer-b");
    let url = crate::net::Url::parse(crate::tunnel::REVERSE_ENDPOINT_URL).unwrap();
    let conn = crate::net::http1::Dialer::dial(&dialer, &url, Duration::from_secs(1)).unwrap();
    let window = cfg.transport.tunnel_stream_window() as i64;
    assert_eq!(resources.codec.used(), window);
    let clone = conn.try_clone().unwrap();
    drop(conn);
    assert_eq!(resources.codec.used(), window);
    drop(clone);
    assert_eq!(resources.codec.used(), 0);

    drop(peer_conn);
    let deadline = Instant::now() + Duration::from_secs(5);
    while std::sync::Arc::strong_count(&guard) != 1 {
        assert!(Instant::now() < deadline, "tunnel kept its connection slot");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn http_tunnel_charges_two_pipe_capacities_to_codec_for_its_lifetime() {
    let cfg = config();
    let hub = Hub::new(&cfg);
    let resources = crate::resource::manager::ResourceManager::new(&cfg);
    hub.set_resources(resources.clone());
    let id = tunnel_id(5001);
    hub.open_http(
        &http_open_request(&id, "instance-b"),
        &cfg,
        &id,
        "long-poll",
    )
    .unwrap();
    assert_eq!(resources.codec.used(), super::http_tunnel_budget());
    assert_eq!(super::http_tunnel_budget(), 1 << 20);
    hub.close();
    assert_eq!(resources.codec.used(), 0);

    let hub = Hub::new(&cfg);
    hub.set_resources(resources.clone());
    let room = resources.codec.limit() - resources.ingress_codec_reserve();
    let _full = resources
        .codec
        .try_acquire(room - super::http_tunnel_budget() + 1)
        .unwrap();
    let id = tunnel_id(5002);
    let err = hub
        .open_http(
            &http_open_request(&id, "instance-b"),
            &cfg,
            &id,
            "long-poll",
        )
        .unwrap_err();
    assert_error(&err, wire::ERR_BUFFER_EXHAUSTED, 503);
    assert!(err.retryable);
    assert_eq!(hub.live_tunnels("peer-b"), 0);
    hub.close();
}

#[test]
fn spec_audit_reverse_tunnel_leaves_codec_for_sessions() {
    let dir = std::env::temp_dir().join(format!(
        "dbb-hub-codec-{}",
        crate::util::random_hex(6).expect("OS random for test fixture")
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("peer-token"), "abc").unwrap();
    let path: PathBuf = dir.join("config.yaml");
    std::fs::write(
        &path,
        "node:\n  id: peer-a\nhttp:\n  enabled: true\n  listen: \"127.0.0.1:18080\"\nlisteners:\n  - id: local\n    listen: \"127.0.0.1:0\"\n    peer: peer-b\n    target: db\npeers:\n  - id: peer-b\n    mode: reverse\n    expected_node_id: peer-b\n    credential_ref: peer-b\n    token_file: peer-token\ntargets:\n  db:\n    network: tcp\n    address: \"127.0.0.1:3306\"\nauth:\n  inbound_peers:\n    - id: peer-b\n      token_files: [peer-token]\n      allowed_targets: [db]\ntransport:\n  codec_buffer_limit: 2MiB\n",
    )
    .unwrap();
    let cfg = crate::config::load(&path).unwrap();
    std::fs::remove_dir_all(dir).unwrap();
    let resources = crate::resource::manager::ResourceManager::new(&cfg);
    assert_eq!(resources.codec.limit(), 2 << 20, "fixture codec limit");
    resources.set_ingress_codec_reserve(512 << 10);
    let hub = Hub::new(&cfg);
    hub.set_resources(resources.clone());
    let id = tunnel_id(6001);
    hub.open_http(
        &http_open_request(&id, "instance-b"),
        &cfg,
        &id,
        "long-poll",
    )
    .expect("open");
    assert!(
        resources.codec.available() >= resources.ingress_codec_reserve(),
        "one idle HTTP tunnel consumed the local data-plane reserve: need={} used={} available={} ingress_reserve={}",
        super::http_tunnel_budget(),
        resources.codec.used(),
        resources.codec.available(),
        resources.ingress_codec_reserve()
    );
    hub.close();
}
