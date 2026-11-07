use super::spec_e2e_harness::*;
use std::io::{Read, Write};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn spec_broken_ws_attach_with_recovery_uses_sse() {
    let (n, served) = super::spec_e2e_tests::broken_ws_attach(true);
    assert!(
        served == 3 && n == 1,
        "recovery on: served={served}/3 ws session attempts={n}"
    );
}

fn is_carrier(path: &str) -> bool {
    path == crate::wire::PATH_WS || path.ends_with("/events")
}

fn ws_session_purpose(r: &Req) -> bool {
    r.path == crate::wire::PATH_WS
        && r.head.contains(&format!(
            "{}: session",
            crate::wire::H_WS_PURPOSE.to_ascii_lowercase()
        ))
}

fn resumes(env: &Env) -> usize {
    env.proxy.counts.count("POST", |p| p.ends_with("/resume"))
}

#[test]
fn spec_cooldown_recovery_records_drop_before_selection() {
    let target = Target::echo("");
    let mut o = Opts::new("auto");
    o.egress_recovery = Some("enabled: true".into());
    o.ingress_recovery = Some("enabled: true".into());
    let env = Env::start(&target, o);
    let mut c = env.dial();
    echo(&mut c, b"before").unwrap();
    let sess = env.egress.registry.all_sessions()[0].clone();
    assert_eq!(
        sess.current_mode().as_str(),
        "ws",
        "fixture: auto starts on ws"
    );
    let start = Instant::now();
    assert!(env.proxy.kill(is_carrier) > 0, "no carrier to cut");
    echo(&mut c, b"after").unwrap_or_else(|e| panic!("session did not recover: {e}"));
    assert!(
        start.elapsed() <= Duration::from_secs(3),
        "recovery onto the same address's SSE took {:?}",
        start.elapsed()
    );
    assert_eq!(
        sess.current_mode().as_str(),
        "http-sse",
        "recovery reused the WS carrier that just dropped"
    );
    let now = Instant::now();
    assert!(
        !env.ingress
            .endpoints
            .transport_available("B", "e1", crate::wire::Mode::Ws, now),
        "the dropped WS carrier is not cooling down"
    );
    assert!(
        !env.ingress.endpoints.in_cooldown("B", "e1"),
        "a single-carrier drop must not cool the whole address"
    );
}

#[test]
fn spec_cooldown_create_ends_at_create_retry_timeout() {
    let target = Target::echo("");
    let mut o = Opts::new("ws");
    o.ingress_transport
        .insert("create_retry_timeout", "700ms".into());
    o.peer_extra = "    failover:\n      enabled: false\n".into();
    let env = Env::start(&target, o);
    env.ingress.endpoints.record_transport_failure(
        "B",
        "e1",
        crate::wire::Mode::Ws,
        Duration::from_secs(5),
    );
    let mut c = env.dial();
    let start = Instant::now();
    let _ = c.write_all(b"x");
    let got = c.read(&mut [0u8; 1]);
    let d = start.elapsed();
    assert!(
        !matches!(got, Ok(n) if n > 0),
        "a session was created over the cooled-down WS carrier"
    );
    assert!(
        d >= Duration::from_millis(500) && d <= Duration::from_millis(2500),
        "create ended after {d:?}, want about create_retry_timeout (700ms)"
    );
    assert_eq!(env.egress_sessions(), 0, "no session may be created");
}

#[test]
fn spec_cooldown_recovery_ends_at_grace() {
    let target = Target::echo("");
    let mut o = Opts::new("ws");
    o.egress_recovery = Some("enabled: true, grace: 1s, barrier_timeout: 500ms".into());
    o.ingress_recovery = Some("enabled: true, grace: 1s, barrier_timeout: 500ms".into());
    o.peer_extra = "    failover:\n      enabled: false\n      cooldown: 5s\n".into();
    let env = Env::start(&target, o);
    let mut c = env.dial();
    echo(&mut c, b"x").unwrap();
    let start = Instant::now();
    assert!(env.proxy.kill(is_carrier) > 0, "no carrier to cut");
    let got = c.read(&mut [0u8; 1]);
    let d = start.elapsed();
    assert!(
        !matches!(got, Ok(n) if n > 0),
        "expected the local connection to close at the recovery deadline"
    );
    assert!(
        d >= Duration::from_millis(800) && d <= Duration::from_secs(3),
        "recovery ended after {d:?}, want about recovery.grace (1s)"
    );
    assert_eq!(
        resumes(&env),
        0,
        "a resume was sent over the cooled-down carrier"
    );
}

#[test]
fn spec_first_attach_bounded_by_unattached_timeout() {
    let target = Target::echo("");
    let mut o = Opts::new("ws");
    o.egress_recovery = Some("enabled: true".into());
    o.ingress_recovery = Some("enabled: true".into());
    o.egress_transport
        .insert("unattached_timeout", "400ms".into());
    o.hook = Some(Arc::new(|r: &Req| {
        if ws_session_purpose(r) {
            return Action::Hang(Duration::from_millis(800));
        }
        Action::Pass
    }));
    let env = Env::start(&target, o);
    let mut c = env.dial();
    let start = Instant::now();
    let got = c.read(&mut [0u8; 1]);
    let elapsed = start.elapsed();
    let ws =
        env.ingress
            .endpoints
            .transport_available("B", "e1", crate::wire::Mode::Ws, Instant::now());
    assert!(
        !matches!(got, Ok(n) if n > 0)
            && elapsed <= Duration::from_secs(2)
            && resumes(&env) == 0
            && ws,
        "read {got:?} after {elapsed:?}, resumes={}, ws available={ws}",
        resumes(&env)
    );
}

#[test]
fn spec_local_create_deadline_does_not_cool_carrier() {
    let target = Target::echo("");
    let mut o = Opts::new("ws");
    o.ingress_transport
        .insert("create_retry_timeout", "1500ms".into());
    o.egress_recovery = Some("enabled: true".into());
    o.ingress_recovery = Some("enabled: true".into());
    o.hook = Some(Arc::new(|r: &Req| {
        if r.method == "POST" && r.path == crate::wire::PATH_SESSIONS {
            return Action::Hang(Duration::from_millis(1300));
        }
        if ws_session_purpose(r) {
            return Action::Hang(Duration::from_millis(300));
        }
        Action::Pass
    }));
    let env = Env::start(&target, o);
    let mut c = env.dial();
    c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let _ = c.read(&mut [0u8; 1]);
    drop(c);
    assert!(
        env.ingress
            .endpoints
            .transport_available("B", "e1", crate::wire::Mode::Ws, Instant::now()),
        "local create-deadline expiry during attach cooled the healthy WS carrier"
    );
}

#[test]
fn spec_carrier_failure_excludes_local_causes() {
    use crate::error::Error;
    let cases = [
        (
            "carrier reset",
            Error::local("read: connection reset by peer"),
            true,
        ),
        (
            "detection timeout",
            Error::new(crate::wire::ERR_BACKEND_LOST, "carrier closed"),
            true,
        ),
        (
            "upgrade refused",
            Error::new(
                crate::wire::ERR_WS_HANDSHAKE_FAILED,
                "expected 101, got 502",
            ),
            true,
        ),
        (
            "local deadline",
            Error::local("first attach deadline: use of closed network connection"),
            false,
        ),
        (
            "local budget",
            Error::local("dial: data connection budget exhausted"),
            false,
        ),
        (
            "client socket",
            Error::local("local client socket error: write: broken pipe"),
            false,
        ),
        ("io timeout", Error::local("read: timed out"), false),
    ];
    for (name, e, want) in cases {
        assert_eq!(
            super::link::first_attach_carrier_failure(&e),
            want,
            "{name}: {e:?}"
        );
    }
}

#[test]
fn spec_transport_cooldown_waits_without_alternative() {
    let target = Target::echo("");
    let mut o = Opts::new("http-sse");
    o.ingress_transport
        .insert("create_retry_timeout", "300ms".into());
    let env = Env::start(&target, o);
    env.ingress.endpoints.record_transport_failure(
        "B",
        "e1",
        crate::wire::Mode::HttpSse,
        Duration::from_secs(5),
    );
    let mut c = env.dial();
    let start = Instant::now();
    let got = c.read(&mut [0u8; 1]);
    let d = start.elapsed();
    assert!(
        !matches!(got, Ok(n) if n > 0) && env.egress_sessions() == 0,
        "cooled SSE carrier was reselected during its cooldown"
    );
    assert!(
        d >= Duration::from_millis(250) && d <= Duration::from_secs(2),
        "selection should wait until the deadline, returned after {d:?}"
    );
    drop(env);

    let mut o = Opts::new("http-sse");
    o.ingress_transport
        .insert("create_retry_timeout", "3s".into());
    let env = Env::start(&target, o);
    env.ingress.endpoints.record_transport_failure(
        "B",
        "e1",
        crate::wire::Mode::HttpSse,
        Duration::from_millis(400),
    );
    let mut c = env.dial();
    let start = Instant::now();
    echo(&mut c, b"hi").unwrap_or_else(|e| panic!("selection after the cooldown ended: {e}"));
    let d = start.elapsed();
    assert!(
        d >= Duration::from_millis(350) && d <= Duration::from_secs(2),
        "selection did not wait for the cooldown to end: {d:?}"
    );
}

#[test]
fn spec_trusted_resume_refusal_stops_at_once() {
    let target = Target::echo("");
    let mut o = Opts::new("ws");
    o.egress_recovery = Some("enabled: true, grace: 30s".into());
    o.ingress_recovery = Some("enabled: true, grace: 30s".into());
    o.peer_extra = "    failover:\n      cooldown: 5s\n".into();
    let resumed_at: Arc<std::sync::Mutex<Option<Instant>>> = Default::default();
    let (at, cell) = (resumed_at.clone(), o.egress_cell.clone());
    o.hook = Some(Arc::new(move |r: &Req| {
        if !r.path.ends_with("/resume") {
            return Action::Pass;
        }
        at.lock().unwrap().get_or_insert_with(Instant::now);
        let instance = cell
            .get()
            .map(|s| s.cfg.node.instance_id.clone())
            .unwrap_or_default();
        let body = format!(r#"{{"code":"{}"}}"#, crate::wire::ERR_TRANSPORT_UNSUPPORTED);
        Action::ForwardThenRespond(format!(
            "HTTP/1.1 409 Conflict\r\n{}: {instance}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            crate::wire::H_INSTANCE_ID,
            body.len()
        ))
    }));
    let env = Env::start(&target, o);
    let mut c = env.dial();
    c.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    echo(&mut c, b"x").unwrap();
    let start = Instant::now();
    assert!(env.proxy.kill(is_carrier) > 0, "no carrier to cut");
    let got = c.read(&mut [0u8; 1]);
    let closed = Instant::now();
    assert!(
        !matches!(got, Ok(n) if n > 0),
        "expected the local connection to close"
    );
    let at = resumed_at.lock().unwrap().expect("no resume was sent");
    assert!(
        start.elapsed() >= Duration::from_secs(4),
        "the dropped WS carrier was reused after {:?}, inside its 5s cooldown",
        start.elapsed()
    );
    assert!(
        closed.duration_since(at) <= Duration::from_secs(2),
        "trusted resume refusal closed the client after {:?}",
        closed.duration_since(at)
    );
}

#[test]
fn spec_recovery_outlasts_backpressure_timeout() {
    for mode in ["ws", "http-sse"] {
        let target = Target::echo("");
        let mut o = Opts::new(mode);
        o.egress_recovery = Some("enabled: true, grace: 6s, barrier_timeout: 1s".into());
        o.ingress_recovery = Some("enabled: true, grace: 6s, barrier_timeout: 1s".into());
        o.ingress_transport
            .insert("backpressure_timeout", "1s".into());
        let fail_until: Arc<std::sync::Mutex<Option<Instant>>> = Default::default();
        let f = fail_until.clone();
        o.hook = Some(Arc::new(move |r: &Req| {
            let failing = f.lock().unwrap().is_some_and(|u| Instant::now() < u);
            if failing && (r.path.ends_with("/ack") || r.path.ends_with("/resume")) {
                return Action::Respond(json_response(
                    503,
                    r#"{"code":"DBB_X","message":"x","retryable":false,"session_closed":false}"#,
                ));
            }
            Action::Pass
        }));
        let env = Env::start(&target, o);
        let mut c = env.dial();
        c.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
        echo(&mut c, b"a").unwrap();
        *fail_until.lock().unwrap() = Some(Instant::now() + Duration::from_secs(2));
        std::thread::sleep(Duration::from_secs(3));
        echo(&mut c, b"b").unwrap_or_else(|e| {
            panic!("{mode}: session did not survive a 2s outage (grace 6s, backpressure_timeout 1s): {e}")
        });
    }
}

#[test]
fn spec_server_close_first_does_not_cool_carrier() {
    for mode in ["ws", "http-sse"] {
        let target = Target::with(|mut c, _| {
            let mut buf = [0u8; 64];
            let n = c.read(&mut buf).unwrap_or(0);
            let mut out = b"re:".to_vec();
            out.extend_from_slice(&buf[..n]);
            let _ = c.write_all(&out);
        });
        let mut o = Opts::new(mode);
        o.egress_recovery = Some("enabled: true".into());
        o.ingress_recovery = Some("enabled: true".into());
        let env = Env::start(&target, o);
        let mut worst = Duration::ZERO;
        for i in 0..30 {
            let start = Instant::now();
            let mut c = env.dial();
            c.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
            c.write_all(b"ping").unwrap();
            let mut got = Vec::new();
            let r = c.read_to_end(&mut got);
            assert!(
                r.is_ok() && got == b"re:ping",
                "{mode}: connection {i}: {:?} {r:?}",
                String::from_utf8_lossy(&got)
            );
            worst = worst.max(start.elapsed());
        }
        assert!(
            worst <= Duration::from_secs(2),
            "{mode}: a connection waited {worst:?} after earlier server-first closes"
        );
        assert_eq!(
            resumes(&env),
            0,
            "{mode}: a server-first normal close entered recovery"
        );
        let m = if mode == "ws" {
            crate::wire::Mode::Ws
        } else {
            crate::wire::Mode::HttpSse
        };
        assert!(
            env.ingress
                .endpoints
                .transport_available("B", "e1", m, Instant::now()),
            "{mode}: server-first normal closes cooled the carrier down"
        );
    }
}

#[test]
fn spec_blackholed_primary_does_not_stall_create() {
    let bh = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let bh_addr = bh.local_addr().unwrap();
    let held = Arc::new(std::sync::Mutex::new(Vec::new()));
    let h = held.clone();
    std::thread::spawn(move || {
        for c in bh.incoming() {
            match c {
                Ok(c) => h.lock().unwrap().push(c),
                Err(_) => return,
            }
        }
    });
    let target = Target::echo("");
    let mut o = Opts::new("ws");
    o.peer_extra = "    failover:\n      healthcheck_timeout: 300ms\n".into();
    o.endpoints = Some(format!(
        "      - id: primary\n        url: \"http://{bh_addr}\"\n        priority: 1\n      - id: backup\n        url: \"http://{{proxy}}\"\n        priority: 2\n"
    ));
    let env = Env::start(&target, o);
    let echo_once = |env: &Env| -> (Duration, std::io::Result<()>) {
        let mut c = env.dial();
        c.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
        let start = Instant::now();
        let r = echo(&mut c, b"hi");
        (start.elapsed(), r)
    };
    let results: Vec<(Duration, String)> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..4)
            .map(|_| {
                s.spawn(|| {
                    let (d, r) = echo_once(&env);
                    (d, format!("{r:?}"))
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for (d, r) in results {
        assert!(r == "Ok(())", "session failed: {r}");
        assert!(
            d <= Duration::from_secs(2),
            "session behind a black-holed primary waited {d:?} (want about healthcheck_timeout)"
        );
    }
    let (d, r) = echo_once(&env);
    assert!(
        r.is_ok() && d <= Duration::from_millis(250),
        "next session after a failed primary probe: {d:?} {r:?} (should go straight to the backup)"
    );
    drop(held);
}

#[test]
fn spec_cleanup_without_probe() {
    let target = Target::echo("");
    let mut env = Env::start(&target, Opts::new("ws"));
    let deletes = |env: &Env| env.proxy.counts.count("DELETE", |_| true);
    let probes = |env: &Env| {
        env.proxy
            .counts
            .count("POST", |p| p == crate::wire::PATH_PROBE)
    };
    let mut c = env.dial();
    echo(&mut c, b"x").unwrap();
    c.shutdown(std::net::Shutdown::Write).unwrap();
    let _ = c.read(&mut [0u8; 1]);
    let until = Instant::now() + Duration::from_secs(2);
    while env.ingress.metrics.ingress_connection_count() > 0 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(deletes(&env), 0, "a normal close sent DELETE(s)");
    let mut c2 = env.dial();
    echo(&mut c2, b"y").unwrap();
    let before = probes(&env);
    env.close_ingress();
    assert_eq!(deletes(&env), 1, "terminated session DELETEs, want 1");
    assert_eq!(
        probes(&env) - before,
        0,
        "cleanup probed the bound endpoint"
    );
    assert_eq!(
        env.wait_egress_sessions(0, Duration::from_secs(2)),
        0,
        "remote sessions left after cleanup"
    );
}

#[test]
fn spec_close_bounded_when_peer_hangs() {
    let target = Target::echo("");
    let mut o = Opts::new("http-sse");
    let hang = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let h = hang.clone();
    o.hook = Some(Arc::new(move |r: &Req| {
        if r.method == "DELETE" && h.load(Ordering::SeqCst) {
            return Action::Hang(Duration::from_secs(5));
        }
        Action::Pass
    }));
    let env = Env::start(&target, o);
    let mut c = env.dial();
    echo(&mut c, b"x").unwrap();
    hang.store(true, Ordering::SeqCst);
    let start = Instant::now();
    env.ingress.close_until(start + Duration::from_millis(300));
    let d = start.elapsed();
    assert!(
        d <= Duration::from_millis(300) + Duration::from_secs(1),
        "CloseContext took {d:?} with a hanging peer (deadline 300ms)"
    );
    hang.store(false, Ordering::SeqCst);
}

#[test]
fn spec_idle_session_retains_nothing() {
    let target = Target::echo("");
    let env = Env::start(&target, Opts::new("ws"));
    let mut c = env.dial();
    echo(&mut c, b"idle").unwrap();
    let retained = || -> (u64, u64) {
        env.ingress
            .metrics
            .ingress_gauges()
            .iter()
            .fold((0, 0), |(f, b), g| {
                (f + g.retained_frames, b + g.up_pending_bytes)
            })
    };
    let until = Instant::now() + Duration::from_secs(3);
    while retained() != (0, 0) && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        retained(),
        (0, 0),
        "idle session retains (frames, bytes) for recovery"
    );
    assert_eq!(
        env.ingress.metrics.ingress_gauges().len(),
        1,
        "fixture: one live session"
    );
}
