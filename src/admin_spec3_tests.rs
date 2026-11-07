use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::Admin;

fn scrape(addr: std::net::SocketAddr) -> String {
    let mut c = TcpStream::connect(addr).unwrap();
    c.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut out = String::new();
    c.read_to_string(&mut out).unwrap();
    out
}

#[test]
fn spec_admin_cache_and_connection_cap() {
    let dir = std::env::temp_dir().join(format!(
        "dbb-spec-admin3-{}",
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
    let metrics = Arc::new(crate::metrics::Metrics::new());
    let shutdown = Arc::new(AtomicBool::new(false));
    let (worker, addr) = Admin::start_with_check(
        cfg,
        metrics.clone(),
        Instant::now(),
        shutdown.clone(),
        Arc::new(AtomicBool::new(true)),
        Default::default(),
    )
    .unwrap();
    let started = Instant::now();
    let mut bodies = Vec::new();
    for _ in 0..5 {
        bodies.push(scrape(addr));
        metrics.post_received();
    }
    assert!(
        started.elapsed() < Duration::from_millis(900),
        "scrapes did not fit in the cache window"
    );
    assert!(
        bodies[0].contains("dbb_post_count_total 0\n"),
        "{}",
        bodies[0]
    );
    for body in &bodies[1..] {
        assert!(
            body.contains("dbb_post_count_total 0\n"),
            "metrics rendered again for a scrape within the cache window"
        );
    }
    std::thread::sleep(Duration::from_millis(1100));
    assert!(
        scrape(addr).contains("dbb_post_count_total 5\n"),
        "cache never expires"
    );

    // Let the scrape connections' permits go back before filling the cap.
    std::thread::sleep(Duration::from_millis(100));
    let conns: Vec<TcpStream> = (0..16).map(|_| TcpStream::connect(addr).unwrap()).collect();
    let mut extra = TcpStream::connect(addr).unwrap();
    extra
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    match extra.read(&mut [0u8; 1]) {
        Ok(0) => {}
        Ok(_) => panic!("connection beyond the cap was served"),
        Err(e) => assert!(
            !matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "connection beyond the cap was left open"
        ),
    }
    drop(conns);
    shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = crate::net::wake_tcp_listener(addr);
    worker.join().unwrap();
}
