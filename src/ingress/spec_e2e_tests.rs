use super::spec_e2e_harness::*;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::time::{Duration, Instant};

#[test]
fn spec_real_byte_round_trip() {
    for mode in ["ws", "http-sse"] {
        let target = Target::echo("");
        let env = Env::start(&target, Opts::e2e(mode));
        let mut c = env.dial();
        c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let p: Vec<u8> = [0u8, 255, 7, 22].repeat(32768);
        c.write_all(&p).unwrap();
        let mut got = vec![0u8; p.len()];
        c.read_exact(&mut got)
            .unwrap_or_else(|e| panic!("{mode}: 128KiB round trip failed: {e}"));
        assert!(got == p, "{mode}: bytes differ");
    }
}

fn half_close(mode: &'static str, kind: &'static str) -> Result<(), String> {
    let target = Target::echo(kind);
    let env = Env::start(&target, Opts::e2e(mode));
    let mut c = env.dial();
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    if kind == "down_fin_first" {
        let mut one = [0u8; 1];
        match c.read(&mut one) {
            Ok(0) => {}
            other => return Err(format!("expected server half close: {other:?}")),
        }
    }
    let data = b"half-close".repeat(1000);
    c.write_all(&data).map_err(|e| format!("write: {e}"))?;
    c.shutdown(Shutdown::Write)
        .map_err(|e| format!("CloseWrite: {e}"))?;
    if kind.is_empty() {
        let mut got = Vec::new();
        let r = c.read_to_end(&mut got);
        if r.is_err() || got != data {
            return Err(format!(
                "half-close truncated payload: bytes={} err={r:?}",
                got.len()
            ));
        }
    } else {
        let rx = target.received.lock().unwrap();
        let mut received = 0;
        while received < data.len() {
            match rx.recv_timeout(Duration::from_secs(1)) {
                Ok(b) => received += b.len(),
                Err(_) => {
                    return Err(format!(
                        "upstream lost after downstream FIN ({received} bytes)"
                    ))
                }
            }
        }
    }
    let left = env.wait_egress_sessions(0, Duration::from_secs(1));
    if left != 0 {
        return Err(format!("normal completion leaked {left} session(s)"));
    }
    Ok(())
}

#[test]
fn spec_half_close_both_orders() {
    let mut failures = Vec::new();
    for mode in ["ws", "http-sse"] {
        for kind in ["", "down_fin_first"] {
            if let Err(e) = half_close(mode, kind) {
                failures.push(format!("{mode}/{kind}: {e}"));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn spec_large_bidirectional_byte_stream() {
    for mode in ["ws", "http-sse"] {
        let target = Target::echo("");
        let mut o = Opts::e2e(mode);
        for t in [&mut o.egress_transport, &mut o.ingress_transport] {
            t.insert("heartbeat", "200ms".into());
            t.insert("failure_detect_timeout", "3s".into());
        }
        o.ingress_transport
            .insert("control_request_timeout", "1s".into());
        let env = Env::start(&target, o);
        let mut c = env.dial();
        let stall = Duration::from_secs(15);
        c.set_read_timeout(Some(stall)).unwrap();
        c.set_write_timeout(Some(stall)).unwrap();
        let block: Vec<u8> = [0u8, 1, 255, 127, 0, 9, 31, 4].repeat(8192);
        const BLOCKS: usize = 800;
        let mut w = c.try_clone().unwrap();
        let wb = block.clone();
        let writer = std::thread::spawn(move || -> std::io::Result<()> {
            for _ in 0..BLOCKS {
                w.write_all(&wb)?;
            }
            Ok(())
        });
        let start = Instant::now();
        let mut buf = vec![0u8; block.len()];
        for i in 0..BLOCKS {
            c.read_exact(&mut buf).unwrap_or_else(|e| {
                panic!(
                    "{mode}: block {i} (no progress for {stall:?}, {:?} elapsed): {e}",
                    start.elapsed()
                )
            });
            assert!(buf == block, "{mode}: byte mismatch block {i}");
        }
        writer.join().unwrap().unwrap();
    }
}

#[test]
fn spec_two_hundred_sessions_close() {
    raise_nofile();
    let target = Target::echo("");
    let mut o = Opts::e2e("ws");
    o.max_sessions = 256;
    for t in [&mut o.egress_transport, &mut o.ingress_transport] {
        t.insert("heartbeat", "1s".into());
        t.insert("failure_detect_timeout", "10s".into());
        t.insert("control_request_timeout", "5s".into());
    }
    o.ingress_transport
        .insert("create_retry_timeout", "20s".into());
    let mut env = Env::start(&target, o);
    let clients: Vec<_> = (0..200).map(|_| env.dial()).collect();
    assert_eq!(
        env.wait_egress_sessions(200, Duration::from_secs(20)),
        200,
        "created sessions"
    );
    let start = Instant::now();
    let readers: Vec<_> = clients
        .into_iter()
        .enumerate()
        .map(|(i, mut c)| {
            std::thread::spawn(move || {
                c.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
                match c.read(&mut [0u8; 1]) {
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        Err(format!("client {i} exceeded 1s"))
                    }
                    _ => Ok(()),
                }
            })
        })
        .collect();
    env.close_ingress();
    let errs: Vec<String> = readers
        .into_iter()
        .filter_map(|r| r.join().unwrap().err())
        .collect();
    assert!(
        errs.is_empty(),
        "{} clients not closed in {:?}: {:?}",
        errs.len(),
        start.elapsed(),
        &errs[..errs.len().min(5)]
    );
}

#[test]
fn spec_small_frames_do_not_wait_for_ack_timer() {
    for mode in ["ws", "http-sse"] {
        let target = Target::echo("");
        let mut o = Opts::new(mode);
        o.ingress_transport.insert("ack_max_delay", "2s".into());
        let env = Env::start(&target, o);
        let mut c = env.dial();
        let mut worst = Duration::ZERO;
        for i in 0..300u32 {
            let t0 = Instant::now();
            echo(&mut c, &[i as u8]).unwrap_or_else(|e| panic!("{mode} {i}: {e}"));
            worst = worst.max(t0.elapsed());
        }
        assert!(
            worst <= Duration::from_secs(1),
            "{mode} round trip stalled {worst:?} waiting for the ACK timer"
        );
    }
}

#[test]
fn spec_downstream_small_frames_acked() {
    let target = Target::with(|mut c, _| {
        for i in 0..400u32 {
            let _ = c.write_all(&[i as u8]);
            std::thread::sleep(Duration::from_micros(100));
        }
        let _ = std::io::copy(&mut c, &mut std::io::sink());
    });
    let mut o = Opts::new("ws");
    o.ingress_transport.insert("ack_max_delay", "2s".into());
    let env = Env::start(&target, o);
    let mut c = env.dial();
    let mut buf = [0u8; 64];
    let (mut got, mut last, mut worst) = (0, Instant::now(), Duration::ZERO);
    while got < 400 {
        let n = c.read(&mut buf).unwrap_or_else(|e| panic!("{got}: {e}"));
        assert!(n > 0, "EOF after {got} bytes");
        if got > 0 {
            worst = worst.max(last.elapsed());
        }
        last = Instant::now();
        got += n;
    }
    assert!(
        worst <= Duration::from_secs(1),
        "downstream small frames stalled {worst:?} waiting for the ACK timer"
    );
}

#[test]
fn spec_shutdown_cleans_up_every_session() {
    const N: usize = 24;
    let target = Target::echo("");
    let mut o = Opts::new("http-sse");
    o.max_sessions = 64;
    let mut env = Env::start(&target, o);
    let mut clients = Vec::new();
    for _ in 0..N {
        let mut c = env.dial();
        echo(&mut c, b"z").unwrap();
        clients.push(c);
    }
    assert_eq!(env.egress_sessions(), N, "fixture: remote sessions");
    env.close_ingress();
    let left = env.egress_sessions();
    let deletes = env.proxy.counts.count("DELETE", |_| true);
    assert!(
        left == 0 && deletes == N,
        "after shutdown: {left} remote sessions left, {deletes} DELETEs"
    );
}

#[test]
fn spec_normal_close_does_not_delay_next_session() {
    for mode in ["ws", "http-sse"] {
        let target = Target::echo("");
        let env = Env::start(&target, Opts::new(mode));
        for i in 0..6 {
            let mut c = env.dial();
            let start = Instant::now();
            echo(&mut c, b"hello").unwrap();
            let d = start.elapsed();
            assert!(
                d <= Duration::from_secs(2),
                "{mode}: connection {i} waited {d:?} for its first echo after a normal close"
            );
            c.shutdown(Shutdown::Write).unwrap();
            std::io::copy(&mut c, &mut std::io::sink()).unwrap();
        }
        assert_eq!(env.wait_egress_sessions(0, Duration::from_secs(5)), 0);
        assert_eq!(
            env.proxy.counts.count("POST", |p| p.ends_with("/resume")),
            0,
            "{mode}: a normal close entered recovery"
        );
        assert!(
            !env.ingress.endpoints.in_cooldown("B", "e1"),
            "{mode}: normal closes cooled the carrier down"
        );
    }
}

#[test]
fn spec_start_twice_keeps_listeners() {
    let target = Target::echo("");
    let env = Env::start(&target, Opts::new("http-sse"));
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    assert!(env.ingress.start(stop).is_err(), "second Start succeeded");
    std::net::TcpStream::connect_timeout(&env.local, Duration::from_secs(1))
        .expect("second Start closed the running listener");
}

#[test]
fn spec_secondary_endpoint_used_after_primary_fails() {
    let target = Target::echo("");
    let mut o = Opts::e2e("ws");
    o.endpoints = Some(
        "      - id: dead\n        url: \"http://127.0.0.1:1\"\n        priority: 0\n      - id: e1\n        url: \"http://{proxy}\"\n        priority: 10\n".into(),
    );
    let env = Env::start(&target, o);
    let mut c = env.dial();
    c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    echo(&mut c, b"backup").unwrap();
    assert_eq!(
        env.proxy.counts.count("POST", |p| p == "/v1/sessions"),
        1,
        "more than one database session"
    );
}

#[test]
fn spec_terminal_ack_closes_client() {
    let target = Target::echo("");
    let mut o = Opts::e2e("ws");
    o.hook = Some(std::sync::Arc::new(|r: &Req| {
        if r.path.ends_with("/ack")
            && !String::from_utf8_lossy(r.body).contains("\"ready_received\":true")
        {
            return Action::Respond(json_response(
                410,
                r#"{"code":"DBB_SESSION_CLOSED","message":"x","retryable":false,"session_closed":true}"#,
            ));
        }
        Action::Pass
    }));
    let env = Env::start(&target, o);
    let mut c = env.dial();
    c.set_read_timeout(Some(Duration::from_millis(600)))
        .unwrap();
    if let Err(e) = c.read(&mut [0u8; 1]) {
        assert!(
            !matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "authenticated DBB_SESSION_CLOSED ACK stopped worker but left original client TCP open"
        );
    }
}

#[test]
fn spec_ready_ack_failure_closes_implicit() {
    let target = Target::echo("");
    let mut o = Opts::e2e("ws");
    o.hook = Some(std::sync::Arc::new(|r: &Req| {
        if r.path.ends_with("/ack")
            && String::from_utf8_lossy(r.body).contains("\"ready_received\":true")
        {
            return Action::Respond(json_response(
                403,
                r#"{"code":"DBB_UNAUTHORIZED","message":"xy","retryable":false,"session_closed":true}"#,
            ));
        }
        Action::Pass
    }));
    let env = Env::start(&target, o);
    let mut c = env.dial();
    let _ = c.write_all(b"early-write");
    c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    if let Err(e) = std::io::copy(&mut c, &mut std::io::sink()) {
        assert!(
            !matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "client stayed open after the egress rejected the ready ACK"
        );
    }
}

#[test]
fn spec_peer_recovery_override_is_sent() {
    let target = Target::echo("");
    let mut o = Opts::e2e("ws");
    o.egress_recovery = Some("enabled: true".into());
    o.ingress_recovery = Some("enabled: true".into());
    o.peer_extra = "    recovery:\n      enabled: false\n".into();
    let env = Env::start(&target, o);
    let mut c = env.dial();
    c.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    echo(&mut c, b"ok").unwrap();
    for s in env.egress.registry.all_sessions() {
        assert_eq!(
            s.recovery_state(),
            crate::session::recovery::RecoveryState::Disabled,
            "peer recovery override ignored"
        );
    }
}

fn sse_injection_env(special: &'static str) -> (Target, Env) {
    let target = Target::echo("");
    let mut o = Opts::e2e("http-sse");
    let cell = o.egress_cell.clone();
    o.hook = Some(std::sync::Arc::new(move |r: &Req| {
        if r.method != "GET" || !r.path.ends_with("/events") {
            return Action::Pass;
        }
        let resp = injected_events(&cell, r.path, |session, _stream| {
            if special != "offset_gap" {
                return String::new();
            }
            let ping = session.ping_control().unwrap();
            std::thread::sleep(Duration::from_millis(50));
            format!(
                "event: ping\ndata: {}\n\nid: 1:14\nevent: data\ndata: {}\n\n",
                ping.to_json(),
                crate::wire::format_sse_data(10, b"oops").unwrap()
            )
        });
        match (special, resp) {
            (_, None) => Action::Pass,
            ("eof_stream", Some(resp)) => Action::RespondClose(resp),
            (_, Some(resp)) => Action::RespondHold(resp),
        }
    }));
    let env = Env::start(&target, o);
    (target, env)
}

fn closed_within(c: &mut std::net::TcpStream, d: Duration) -> Result<usize, std::io::Error> {
    c.set_read_timeout(Some(d)).unwrap();
    c.read(&mut [0u8; 1])
}

fn is_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

#[test]
fn spec_unexpected_sse_eof_closes_client() {
    let (_t, env) = sse_injection_env("eof_stream");
    let mut c = env.dial();
    match closed_within(&mut c, Duration::from_secs(1)) {
        Err(e) if is_timeout(&e) => panic!("client remained open after unexpected stream EOF"),
        Ok(n) if n > 0 => panic!("expected closed client"),
        _ => {}
    }
}

#[test]
fn spec_sse_blackhole_detected() {
    let (_t, env) = sse_injection_env("sse_blackhole");
    let mut c = env.dial();
    if let Err(e) = closed_within(&mut c, Duration::from_millis(600)) {
        assert!(
            !is_timeout(&e),
            "SSE stayed open 600ms despite failure_detect_timeout=150ms and no stream activity"
        );
    }
}

#[test]
fn spec_downstream_offset_gap_is_fatal() {
    let (_t, env) = sse_injection_env("offset_gap");
    let mut c = env.dial();
    match closed_within(&mut c, Duration::from_secs(1)) {
        Err(e) if is_timeout(&e) => panic!("offset gap did not close client"),
        Ok(n) if n > 0 => panic!("invalid bytes delivered"),
        _ => {}
    }
}

fn recovery_opts(mode: &'static str) -> Opts {
    let mut o = Opts::e2e(mode);
    o.egress_recovery = Some("enabled: true, grace: 1s, barrier_timeout: 100ms".into());
    o.ingress_recovery = Some("enabled: true, grace: 1s, barrier_timeout: 100ms".into());
    o.peer_extra = "    failover:\n      cooldown: 10ms\n".into();
    o
}

fn is_carrier(path: &str) -> bool {
    path == "/v1/transport/ws" || path.ends_with("/events")
}

fn wait_epoch(env: &Env, s: &std::sync::Arc<crate::session::Session>, want: u64, within: Duration) {
    let until = Instant::now() + within;
    while s.epoch() < want && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(1));
    }
    let _ = env;
}

#[test]
fn spec_real_ws_recovery() {
    let target = Target::echo("");
    let env = Env::start(&target, recovery_opts("ws"));
    let mut c = env.dial();
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    echo(&mut c, b"first").unwrap();
    let sessions = env.egress.registry.all_sessions();
    assert_eq!(sessions.len(), 1, "session count");
    let s = sessions[0].clone();
    assert!(
        env.proxy.kill(|p| p == "/v1/transport/ws") > 0,
        "no WS carrier to cut"
    );
    wait_epoch(&env, &s, 2, Duration::from_secs(2));
    std::thread::sleep(Duration::from_millis(100));
    echo(&mut c, b"after").expect("post-recovery read");
    assert!(
        s.epoch() >= 2,
        "session {} not resumed: epoch {}",
        s.id,
        s.epoch()
    );
}

#[test]
fn spec_carrier_and_path_recovery() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    for kind in ["ws_to_sse", "sse_to_ws", "drop_resume", "path_failover"] {
        let target = Target::echo("");
        let mut o = recovery_opts("auto");
        let switched = Arc::new(AtomicBool::new(false));
        let primary_down = Arc::new(AtomicBool::new(false));
        let (sw, pd, cell) = (
            switched.clone(),
            primary_down.clone(),
            o.egress_cell.clone(),
        );
        o.hook = Some(Arc::new(move |r: &Req| {
            if kind == "path_failover" && pd.load(Ordering::SeqCst) {
                return Action::Respond(json_response(503, ""));
            }
            if r.path == "/v1/peer/probe" && (kind == "ws_to_sse" || kind == "sse_to_ws") {
                let only_sse = (kind == "ws_to_sse" && sw.load(Ordering::SeqCst))
                    || (kind == "sse_to_ws" && !sw.load(Ordering::SeqCst));
                let modes: &[&str] = if only_sse {
                    &["http-sse"]
                } else {
                    &["ws", "http-sse"]
                };
                if let Some(resp) = probe_response(&cell, r.body, modes) {
                    return Action::Respond(resp);
                }
            }
            if kind == "drop_resume"
                && r.path.ends_with("/resume")
                && !sw.swap(true, Ordering::SeqCst)
            {
                return Action::ForwardThenDrop;
            }
            Action::Pass
        }));
        if kind == "path_failover" {
            o.second_proxy = true;
            o.endpoints = Some(
                "      - id: e1\n        url: \"http://{proxy}\"\n      - id: backup\n        url: \"http://{proxy2}\"\n        priority: 10\n".into(),
            );
        }
        let env = Env::start(&target, o);
        let mut c = env.dial();
        c.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
        echo(&mut c, b"before").unwrap_or_else(|e| panic!("{kind}: {e}"));
        let all = env.egress.registry.all_sessions();
        assert_eq!(all.len(), 1, "{kind}: session count");
        let sess = all[0].clone();
        switched.store(kind != "drop_resume", Ordering::SeqCst);
        primary_down.store(true, Ordering::SeqCst);
        if kind != "path_failover" {
            primary_down.store(false, Ordering::SeqCst);
        }
        assert!(env.proxy.kill(is_carrier) > 0, "{kind}: no carrier to cut");
        wait_epoch(&env, &sess, 2, Duration::from_secs(3));
        std::thread::sleep(Duration::from_millis(70));
        echo(&mut c, b"after!").unwrap_or_else(|e| panic!("{kind}: post-recovery: {e}"));
        assert_eq!(
            (target.dials.load(Ordering::SeqCst), sess.epoch()),
            (1, 2),
            "{kind}: recovery changed socket (dials) or epoch"
        );
        let mode = sess.current_mode().as_str();
        match kind {
            "ws_to_sse" => assert_eq!(mode, "http-sse", "{kind}: carrier did not change"),
            "sse_to_ws" => assert_eq!(mode, "ws", "{kind}: carrier did not change"),
            _ => {}
        }
    }
}

pub(super) fn broken_ws_attach(recovery: bool) -> (usize, usize) {
    let ws_sessions = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let purpose = format!(
        "{}: session",
        crate::wire::H_WS_PURPOSE.to_ascii_lowercase()
    );
    let seen = ws_sessions.clone();
    let hook: Hook = std::sync::Arc::new(move |r: &Req| {
        if r.path == crate::wire::PATH_WS && r.head.contains(&purpose) {
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            return Action::Respond(json_response(502, ""));
        }
        Action::Pass
    });
    let target = Target::echo("");
    let mut o = Opts::new("auto");
    let r = if recovery {
        "enabled: true"
    } else {
        "enabled: false"
    };
    o.egress_recovery = Some(r.into());
    o.ingress_recovery = Some(r.into());
    o.hook = Some(hook);
    let env = Env::start(&target, o);
    let mut served = 0;
    for _ in 0..3 {
        let mut c = env.dial();
        c.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
        if echo(&mut c, b"q").is_ok() {
            served += 1;
        }
    }
    (
        ws_sessions.load(std::sync::atomic::Ordering::SeqCst),
        served,
    )
}

#[test]
fn spec_broken_ws_attach_without_recovery_cools_carrier() {
    let (n, served) = broken_ws_attach(false);
    assert!(
        n == 1 && served >= 2,
        "recovery off: ws session attempts={n} served={served}/3; want one failed WS attempt, later clients on SSE"
    );
}
