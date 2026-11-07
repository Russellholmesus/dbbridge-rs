use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::admin::{readiness, readyz_response, reverse_readiness, ReadyCheck, ReadyCheckSlot};

#[test]
fn spec_ready_check_holds_readyz() {
    let slot = ReadyCheckSlot::default();
    let state = Arc::new(Mutex::new((true, String::new())));
    let s = state.clone();
    let check: ReadyCheck = Arc::new(move || s.lock().unwrap().clone());
    *slot.lock().unwrap() = Some(check);
    let (ok, detail) = readiness(true, &slot);
    assert_eq!(readyz_response(ok, &detail), (200, "ready\n".to_string()));
    *state.lock().unwrap() = (false, "reverse: no tunnel to hq".into());
    let (ok, detail) = readiness(true, &slot);
    assert_eq!(
        readyz_response(ok, &detail),
        (503, "not ready\nreverse: no tunnel to hq\n".to_string())
    );
    assert!(!ok, "held check still reported ready");
    state.lock().unwrap().0 = true;
    assert!(
        !readiness(false, &slot).0,
        "check overrides SetReady(false)"
    );
}

#[test]
fn spec_ready_check_served_on_admin_readyz() {
    use std::io::{Read, Write};
    let dir = std::env::temp_dir().join(format!(
        "dbb-gonode-{}",
        crate::util::random_hex(6).unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.yaml");
    std::fs::write(
        &path,
        "node:\n  id: n\nadmin:\n  enabled: true\n  listen: '127.0.0.1:0'\ntargets:\n  db:\n    network: tcp\n    address: '127.0.0.1:3306'\n",
    )
    .unwrap();
    let cfg = Arc::new(crate::config::load(&path).unwrap());
    std::fs::remove_dir_all(&dir).ok();
    let shutdown = Arc::new(AtomicBool::new(false));
    let ready = Arc::new(AtomicBool::new(true));
    let slot = ReadyCheckSlot::default();
    let check: ReadyCheck = Arc::new(|| (false, "reverse: no tunnel to hq".to_string()));
    *slot.lock().unwrap() = Some(check);
    let (worker, addr) = crate::admin::Admin::start_with_check(
        cfg,
        Arc::new(crate::metrics::Metrics::new()),
        std::time::Instant::now(),
        shutdown.clone(),
        ready,
        slot,
    )
    .unwrap();
    let mut c = std::net::TcpStream::connect(addr).unwrap();
    c.write_all(b"GET /readyz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    c.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 503 "), "{response}");
    assert!(
        response.ends_with("not ready\nreverse: no tunnel to hq\n"),
        "{response}"
    );
    shutdown.store(true, Ordering::Relaxed);
    let _ = crate::net::wake_tcp_listener(addr);
    worker.join().unwrap();
}

#[test]
fn spec_reverse_readiness() {
    assert_eq!(
        reverse_readiness(false, "hq-b", Some(2), &[]),
        (true, String::new())
    );
    assert_eq!(
        reverse_readiness(true, "", None, &[]),
        (true, String::new())
    );
    let (ok, detail) = reverse_readiness(false, "hq-b", Some(0), &[]);
    assert!(
        !ok && detail.contains("no tunnel to hq-b"),
        "database side without tunnels: ready={ok} detail={detail:?}"
    );
    // A database side that also serves HTTP stays ready but reports it.
    let (ok, detail) = reverse_readiness(true, "hq-b", Some(0), &[]);
    assert!(ok && detail == "reverse: no tunnel to hq-b");
}

#[test]
fn spec_reverse_readiness_client_without_tunnel() {
    let ln = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead = ln.local_addr().unwrap();
    drop(ln);
    let dir = std::env::temp_dir().join(format!(
        "dbb-gonode-rev-{}",
        crate::util::random_hex(6).unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("tok"), "reverse-token-0123456789abcdef").unwrap();
    let path = dir.join("config.yaml");
    std::fs::write(
        &path,
        format!("node:\n  id: plant\nhttp:\n  enabled: false\nreverse:\n  enabled: true\n  peer_node_id: hq-b\n  token_file: tok\n  endpoints:\n    - id: e1\n      url: http://{dead}\ntargets:\n  db:\n    network: tcp\n    address: '127.0.0.1:3306'\nauth:\n  inbound_peers:\n    - id: hq-b\n      token_files: [tok]\n      allowed_targets: [db]\n"),
    )
    .unwrap();
    let cfg = match crate::config::load(&path) {
        Ok(cfg) => Arc::new(cfg),
        Err(e) => panic!("{}", e.message),
    };
    std::fs::remove_dir_all(&dir).ok();
    let ln = Arc::new(crate::tunnel::client::TunnelListener::new());
    let client = crate::tunnel::client::Client::new(cfg.clone(), ln);
    assert_eq!(client.live_count(), 0);
    let (ok, detail) = reverse_readiness(
        cfg.http.enabled,
        &cfg.reverse.peer_node_id,
        Some(client.live_count()),
        &[],
    );
    assert!(!ok && detail.contains("no tunnel to hq-b"), "{detail}");
}
