use std::net::{Shutdown, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use crate::net::http1::Request;
use crate::net::BufferedConn;
use crate::wire;

use super::{Hub, H_EXPECTED_NODE_ID, H_NODE_ID, H_TUNNEL_ID, H_TUNNEL_PRIORITY};

fn config() -> crate::config::Config {
    let dir =
        std::env::temp_dir().join(format!("dbb-hub2-{}", crate::util::random_hex(6).unwrap()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("peer-token"), "abc").unwrap();
    let path = dir.join("config.yaml");
    std::fs::write(
        &path,
        "node:\n  id: peer-a\nhttp:\n  enabled: true\n  listen: \"127.0.0.1:18080\"\nlisteners:\n  - id: local\n    listen: \"127.0.0.1:13306\"\n    peer: peer-b\n    target: db\npeers:\n  - id: peer-b\n    mode: reverse\n    expected_node_id: peer-b\n    credential_ref: peer-b\n    token_file: peer-token\ntargets:\n  db:\n    network: tcp\n    address: \"127.0.0.1:3306\"\nauth:\n  inbound_peers:\n    - id: peer-b\n      token_files: [peer-token]\n      allowed_targets: [db]\n",
    )
    .unwrap();
    let cfg = crate::config::load(&path).unwrap();
    std::fs::remove_dir_all(dir).unwrap();
    cfg
}

fn ws_request() -> Request {
    Request {
        method: "GET".to_string(),
        path: "/v1/reverse".to_string(),
        query: Vec::new(),
        version: "HTTP/1.1".to_string(),
        headers: vec![
            (wire::H_PEER_AUTH.to_string(), "Bearer abc".to_string()),
            (H_NODE_ID.to_string(), "peer-b".to_string()),
            (H_EXPECTED_NODE_ID.to_string(), "peer-a".to_string()),
            (H_TUNNEL_ID.to_string(), format!("tn_{:032x}", 1)),
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

#[test]
fn spec_reverse_public_side_ready_without_tunnel() {
    let cfg = config();
    let hub = Hub::new(&cfg);
    assert_eq!(hub.missing_peers(), vec!["peer-b".to_string()]);
    let reserved = hub.reserve(&ws_request(), &cfg).unwrap();
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let peer = TcpStream::connect(ln.local_addr().unwrap()).unwrap();
    let (hub_conn, _) = ln.accept().unwrap();
    hub.register(reserved, BufferedConn::new(hub_conn), &cfg, None)
        .unwrap();
    assert!(
        hub.missing_peers().is_empty(),
        "registered tunnel counted missing"
    );
    assert_eq!(
        crate::admin::reverse_readiness(true, "", None, &hub.missing_peers()),
        (true, String::new())
    );
    peer.shutdown(Shutdown::Both).unwrap();
    drop(peer);
    let deadline = Instant::now() + Duration::from_secs(5);
    while hub.live_tunnels("peer-b") != 0 {
        assert!(Instant::now() < deadline, "tunnels gone");
        std::thread::sleep(Duration::from_millis(5));
    }
    let (ok, detail) = crate::admin::reverse_readiness(true, "", None, &hub.missing_peers());
    assert!(
        ok && detail.contains("reverse peers without a tunnel: peer-b"),
        "public side without tunnels: ready={ok} detail={detail:?}"
    );
}

#[test]
fn spec_hub_revalidate_closes_stale_tunnels() {
    use std::io::Read;
    let cfg = config();
    let hub = Hub::new(&cfg);
    let reserved = hub.reserve(&ws_request(), &cfg).unwrap();
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut peer = TcpStream::connect(ln.local_addr().unwrap()).unwrap();
    let (hub_conn, _) = ln.accept().unwrap();
    hub.register(reserved, BufferedConn::new(hub_conn), &cfg, None)
        .unwrap();
    assert_eq!(hub.live_tunnels("peer-b"), 1);
    let mut tokens = std::collections::HashMap::new();
    tokens.insert("peer-b".to_string(), "abc".to_string());
    hub.revalidate(&tokens);
    assert_eq!(
        hub.live_tunnels("peer-b"),
        1,
        "unchanged token closed the tunnel"
    );
    tokens.insert(
        "peer-b".to_string(),
        "rotated-token-0123456789abcdef".to_string(),
    );
    hub.revalidate(&tokens);
    assert_eq!(hub.live_tunnels("peer-b"), 0);
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut buf = [0u8; 256];
    loop {
        match peer.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => continue,
            Err(e) => {
                assert_ne!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock,
                    "stale tunnel connection not closed"
                );
                break;
            }
        }
    }
}

#[test]
fn spec_reverse_ws_close_interrupts_stalled_carrier() {
    let cfg = config();
    let hub = Hub::new(&cfg);
    let reserved = hub.reserve(&ws_request(), &cfg).unwrap();
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let peer = TcpStream::connect(ln.local_addr().unwrap()).unwrap();
    let (hub_conn, _) = ln.accept().unwrap();
    hub.register(reserved, BufferedConn::new(hub_conn), &cfg, None)
        .unwrap();
    // Fill the carrier: the peer never reads, so writes stall.
    let stream = hub.open_stream("peer-b");
    let writer = std::thread::spawn(move || {
        if let Ok(mut s) = stream {
            let chunk = vec![0u8; 64 << 10];
            for _ in 0..10_000 {
                if std::io::Write::write_all(&mut s, &chunk).is_err() {
                    break;
                }
            }
        }
    });
    std::thread::sleep(Duration::from_millis(300));
    let start = Instant::now();
    hub.close();
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "reverse WS close blocked behind a stalled carrier write: {:?}",
        start.elapsed()
    );
    // The stalled writer is released and the peer's socket ends.
    let deadline = Instant::now() + Duration::from_secs(3);
    while !writer.is_finished() {
        assert!(
            Instant::now() < deadline,
            "stalled tunnel writer not released"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(peer);
}
