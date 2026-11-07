use super::serve::cleanup::CleanupTracker;
use super::spec_e2e_harness::*;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[test]
fn spec_cleanup_tracker_late_add() {
    let c = CleanupTracker::default();
    assert!(c.idle().is_ready(), "empty tracker must be idle");
    c.add();
    let w = c.idle();
    c.add();
    c.done();
    assert!(!w.is_ready(), "idle while a cleanup still runs");
    c.done();
    assert!(
        w.wait_timeout(Duration::from_secs(1)),
        "not idle after the last cleanup"
    );
}

#[test]
fn spec_codec_wait_misclassified_as_network_loss() {
    for mode in ["ws", "http-sse"] {
        codec_wait(mode);
    }
}

fn codec_wait(mode: &'static str) {
    let send = Arc::new(AtomicBool::new(false));
    let trigger = send.clone();
    let target = Target::with(move |mut c, _| {
        let until = Instant::now() + Duration::from_secs(10);
        while !trigger.load(Ordering::SeqCst) && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(1));
        }
        let _ = c.write_all(b"hello");
        let mut buf = [0u8; 256];
        while matches!(c.read(&mut buf), Ok(n) if n > 0) {}
    });
    let env = Env::start(&target, Opts::e2e(mode));
    env.ingress.metrics.configure_resources(&env.ingress.cfg);
    let mut c = env.dial();
    let until = Instant::now() + Duration::from_secs(1);
    while !env
        .ingress
        .metrics
        .ingress_gauges()
        .iter()
        .any(|g| g.bound.is_some())
    {
        assert!(Instant::now() < until, "{mode}: fixture session missing");
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(
        env.wait_egress_sessions(1, Duration::from_secs(1)),
        1,
        "{mode}: fixture backend missing"
    );
    let res = env
        .ingress
        .metrics
        .resource_manager()
        .expect("ingress resource manager");
    let limit = res.codec.limit();
    let held = loop {
        if let Some(lease) = res.codec.try_acquire(limit) {
            break Arc::new(Mutex::new(Some(lease)));
        }
        assert!(Instant::now() < until, "{mode}: codec fixture");
        std::thread::sleep(Duration::from_millis(1));
    };
    let control = || env.proxy.counts.count("POST", |p| p.contains("/ack"));
    let control_before = control();
    send.store(true, Ordering::SeqCst);
    let started = Instant::now();
    let free = {
        let held = held.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(350));
            held.lock().unwrap().take();
        })
    };
    c.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let mut b = [0u8; 5];
    let result = c.read_exact(&mut b);
    let control_after = control();
    free.join().unwrap();
    eprintln!(
        "{mode}: codec wait: result={result:?} elapsed={:?} detect={:?} backpressure={:?} control_request_timeout={:?} control_progress={}",
        started.elapsed(),
        env.ingress.cfg.transport.failure_detect_timeout,
        env.ingress.cfg.transport.backpressure_timeout,
        env.ingress.cfg.transport.control_request_timeout,
        control_after > control_before
    );
    assert!(
        control_after > control_before,
        "{mode}: fixture did not observe independent control progress"
    );
    assert!(
        result.is_ok() && &b == b"hello",
        "{mode}: local codec contention terminated the socket before its backpressure deadline despite a healthy independent control path: {result:?} {b:?}"
    );
}
