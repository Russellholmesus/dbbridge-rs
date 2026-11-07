use super::spec_e2e_harness::*;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn is_carrier(path: &str) -> bool {
    path == crate::wire::PATH_WS || path.ends_with("/events")
}

fn is_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

const TWO_ENDPOINTS: &str = "      - id: primary\n        url: \"http://{proxy}\"\n        priority: 0\n      - id: backup\n        url: \"http://{proxy2}\"\n        priority: 10\n";

fn route_opts(mode: &'static str) -> Opts {
    let mut o = Opts::new(mode);
    for t in [&mut o.egress_transport, &mut o.ingress_transport] {
        t.insert("heartbeat", "50ms".into());
        t.insert("failure_detect_timeout", "500ms".into());
    }
    o.ingress_transport.insert("ack_max_delay", "30ms".into());
    o.ingress_transport
        .insert("control_request_timeout", "200ms".into());
    o.ingress_transport
        .insert("create_retry_timeout", "1400ms".into());
    o.egress_recovery = Some("enabled: true, grace: 1400ms, barrier_timeout: 100ms".into());
    o.ingress_recovery = Some("enabled: true, grace: 1400ms, barrier_timeout: 100ms".into());
    o.peer_extra = "    failover:\n      cooldown: 0s\n".into();
    o.second_proxy = true;
    o.endpoints = Some(TWO_ENDPOINTS.into());
    o
}

fn hello_target() -> Target {
    Target::with(|mut c, tx| {
        let _ = c.write_all(b"hello");
        let mut buf = vec![0u8; 4096];
        loop {
            match c.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    let _ = tx.try_send(buf[..n].to_vec());
                    if c.write_all(&buf[..n]).is_err() {
                        return;
                    }
                }
            }
        }
    })
}

fn count(p: &Proxy, method: &str, pred: impl Fn(&str) -> bool) -> usize {
    p.counts.count(method, pred)
}

#[test]
fn spec_create_reply_loss_does_not_try_backup() {
    for mode in ["auto", "ws", "http-sse"] {
        let target = hello_target();
        let mut o = route_opts(mode);
        o.hook = Some(Arc::new(|r: &Req| {
            if r.method == "POST" && r.path == crate::wire::PATH_SESSIONS {
                let body = "lost create reply at primary gateway";
                return Action::ForwardThenRespond(format!(
                    "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                ));
            }
            Action::Pass
        }));
        let env = Env::start(&target, o);
        let mut c = env.dial();
        c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut b = [0u8; 5];
        let got = c.read_exact(&mut b);
        let primary = count(&env.proxy, "POST", |p| p == crate::wire::PATH_SESSIONS);
        let backup = count(env.proxy2.as_ref().unwrap(), "POST", |p| {
            p == crate::wire::PATH_SESSIONS
        });
        let dials = target.dials.load(Ordering::SeqCst);
        assert!(
            got.is_ok() && &b == b"hello" && primary > 0 && backup > 0 && dials == 1,
            "{mode}: backup did not retrieve the original create result without another backend connection: {got:?} primary={primary} backup={backup} dials={dials}"
        );
    }
}

#[test]
fn spec_resume_failure_does_not_try_backup() {
    for mode in ["auto", "ws", "http-sse"] {
        let target = hello_target();
        let mut o = route_opts(mode);
        let bad = Arc::new(AtomicBool::new(false));
        let b = bad.clone();
        o.hook = Some(Arc::new(move |r: &Req| {
            if b.load(Ordering::SeqCst) && r.path.ends_with("/resume") {
                let body = "primary resume path unavailable";
                return Action::Respond(format!(
                    "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                ));
            }
            Action::Pass
        }));
        let env = Env::start(&target, o);
        let mut c = env.dial();
        c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        c.read_exact(&mut [0u8; 5]).unwrap();
        let all = env.egress.registry.all_sessions();
        assert_eq!(all.len(), 1, "{mode}: fixture session count");
        let s = all[0].clone();
        bad.store(true, Ordering::SeqCst);
        assert!(env.proxy.kill(is_carrier) > 0, "{mode}: no carrier to cut");
        let until = Instant::now() + Duration::from_secs(3);
        while s.epoch() < 2 && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(1));
        }
        let primary = count(&env.proxy, "POST", |p| p.ends_with("/resume"));
        let backup = count(env.proxy2.as_ref().unwrap(), "POST", |p| {
            p.ends_with("/resume")
        });
        assert!(
            s.epoch() == 2 && primary > 0 && backup > 0,
            "{mode}: healthy probe kept selecting the broken primary resume path: epoch={} primary={primary} backup={backup}",
            s.epoch()
        );
        std::thread::sleep(Duration::from_millis(50));
        echo(&mut c, b"after-resume")
            .unwrap_or_else(|e| panic!("{mode}: resumed byte stream did not progress: {e}"));
        assert_eq!(
            target.dials.load(Ordering::SeqCst),
            1,
            "{mode}: backend redialed"
        );
    }
}

#[test]
fn spec_recovery_skips_failed_reattach() {
    let target = Target::echo("");
    let mut o = Opts::new("auto");
    for t in [&mut o.egress_transport, &mut o.ingress_transport] {
        t.insert("heartbeat", "50ms".into());
        t.insert("failure_detect_timeout", "500ms".into());
    }
    o.ingress_transport.insert("ack_max_delay", "30ms".into());
    o.ingress_transport
        .insert("control_request_timeout", "250ms".into());
    o.egress_recovery = Some("enabled: true, grace: 1200ms, barrier_timeout: 100ms".into());
    o.ingress_recovery = Some("enabled: true, grace: 1200ms, barrier_timeout: 100ms".into());
    o.peer_extra = "    failover:\n      cooldown: 5s\n".into();
    o.second_proxy = true;
    o.endpoints = Some(TWO_ENDPOINTS.into());
    let failed = Arc::new(AtomicBool::new(false));
    let attach_failures = Arc::new(AtomicUsize::new(0));
    let (f, a) = (failed.clone(), attach_failures.clone());
    o.hook = Some(Arc::new(move |r: &Req| {
        if f.load(Ordering::SeqCst) && r.path.ends_with("/events") {
            a.fetch_add(1, Ordering::SeqCst);
            return Action::Respond(json_response(503, ""));
        }
        Action::Pass
    }));
    let env = Env::start(&target, o);
    let mut c = env.dial();
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    echo(&mut c, b"before").expect("initial echo");
    let s = env.egress.registry.all_sessions()[0].clone();
    assert_eq!(
        s.current_mode().as_str(),
        "ws",
        "initial carrier must be ws"
    );
    failed.store(true, Ordering::SeqCst);
    assert!(
        env.proxy.kill(|p| p == crate::wire::PATH_WS) > 0,
        "no WS carrier"
    );
    let got = echo(&mut c, b"after!");
    let backup = env.proxy2.as_ref().unwrap().counts.count("", |_| true);
    assert!(
        got.is_ok(),
        "a healthy backup exists, but recovery exhausted without trying it: {got:?} primary_failed_reattaches={} backup_requests={backup}",
        attach_failures.load(Ordering::SeqCst)
    );
    assert_eq!(
        target.dials.load(Ordering::SeqCst),
        1,
        "stream/socket changed"
    );
    assert!(backup > 0, "the backup endpoint carried nothing");
}

#[test]
fn spec_recovery_stops_after_trusted_selection_refusal() {
    let target = Target::echo("");
    let mut o = Opts::e2e("ws");
    o.egress_recovery = Some("enabled: true, grace: 1400ms, barrier_timeout: 100ms".into());
    o.ingress_recovery = Some("enabled: true, grace: 1400ms, barrier_timeout: 100ms".into());
    o.peer_extra = "    failover:
      cooldown: 10ms
"
    .into();
    let cell = o.egress_cell.clone();
    let refuse = Arc::new(AtomicBool::new(false));
    let refused = Arc::new(AtomicUsize::new(0));
    let (rf, rd) = (refuse.clone(), refused.clone());
    o.hook = Some(Arc::new(move |r: &Req| {
        if rf.load(Ordering::SeqCst) && r.path != crate::wire::PATH_PROBE {
            rd.fetch_add(1, Ordering::SeqCst);
            let instance = cell
                .get()
                .map(|s| s.cfg.node.instance_id.clone())
                .unwrap_or_default();
            let body = r#"{"code":"DBB_UNAUTHORIZED","message":"no","retryable":false}"#;
            return Action::Respond(format!(
                "HTTP/1.1 401 Unauthorized\r\n{}: {instance}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                crate::wire::H_INSTANCE_ID,
                body.len()
            ));
        }
        Action::Pass
    }));
    let env = Env::start(&target, o);
    let mut c = env.dial();
    echo(&mut c, b"x").unwrap();
    refuse.store(true, Ordering::SeqCst);
    let started = Instant::now();
    assert!(env.proxy.kill(is_carrier) > 0, "no carrier to cut");
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let got = c.read(&mut [0u8; 1]);
    let elapsed = started.elapsed();
    match &got {
        Ok(0) => {}
        Ok(_) => panic!("client socket still delivers data"),
        Err(e) => assert!(!is_timeout(e), "client socket was not closed: {e}"),
    }
    assert!(
        refused.load(Ordering::SeqCst) > 0,
        "fixture never returned a trusted refusal"
    );
    assert!(
        elapsed <= Duration::from_secs(1),
        "a deterministic authorization refusal was retried until grace expiry instead of immediately terminating ({elapsed:?})"
    );
}

/// The resume answer the egress would give for `body`, with the peer's
/// remaining recovery budget replaced by `remaining_ms`.
fn crafted_resume(cell: &EgressCell, path: &str, body: &[u8], remaining_ms: u64) -> Option<String> {
    let srv = cell.get()?;
    let sid = path.split('/').nth(3)?;
    let v = crate::util::json::parse_bytes(body).ok()?;
    let field = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("0").to_string();
    let epoch: u64 = field("expected_epoch").parse().ok()?;
    let mode = v
        .get("transport")
        .and_then(|t| t.get("mode"))
        .and_then(|m| m.as_str())?
        .to_string();
    let ack = field("known_up_ack_offset");
    let down = field("down_delivered_offset");
    let json = format!(
        r#"{{"session_id":"{sid}","instance_id":"{}","resume_request_id":"{}","epoch":"{}","transport":{{"mode":"{mode}"}},"up_written_offset":"{ack}","ack_up_offset":"{ack}","down_replay_from":"{down}","down_produced_offset":"{down}","down_retained_from":"{down}","up_fin":{{"received":false,"final_offset":null,"applied":false}},"down_fin":{{"seen":false,"final_offset":null,"applied":false,"acked":false}},"resume_remaining_ms":{remaining_ms}}}"#,
        srv.cfg.node.instance_id,
        field("resume_request_id"),
        epoch + 1
    );
    Some(format!(
        "HTTP/1.1 200 OK\r\n{}: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{json}",
        crate::wire::H_INSTANCE_ID,
        srv.cfg.node.instance_id,
        json.len()
    ))
}

#[test]
fn spec_resume_remaining_must_tighten_deadline() {
    let target = Target::echo("");
    let mut o = Opts::new("auto");
    for t in [&mut o.egress_transport, &mut o.ingress_transport] {
        t.insert("heartbeat", "30ms".into());
        t.insert("failure_detect_timeout", "150ms".into());
    }
    o.ingress_transport.insert("ack_max_delay", "20ms".into());
    o.ingress_transport
        .insert("control_request_timeout", "250ms".into());
    o.ingress_transport
        .insert("backpressure_timeout", "3s".into());
    o.egress_recovery = Some("enabled: true, grace: 1200ms, barrier_timeout: 100ms".into());
    o.ingress_recovery = Some("enabled: true, grace: 1200ms, barrier_timeout: 100ms".into());
    let cell = o.egress_cell.clone();
    let answered: Arc<Mutex<Option<Instant>>> = Arc::default();
    let a = answered.clone();
    let epoch_header = format!("{}: ", crate::wire::H_WS_EPOCH.to_ascii_lowercase());
    o.hook = Some(Arc::new(move |r: &Req| {
        if r.path.ends_with("/resume") {
            if let Some(resp) = crafted_resume(&cell, r.path, r.body, 10) {
                // ForwardThenRespond answers 150ms after forwarding.
                a.lock()
                    .unwrap()
                    .get_or_insert_with(|| Instant::now() + Duration::from_millis(150));
                return Action::ForwardThenRespond(resp);
            }
        }
        let ws_epoch = r
            .head
            .lines()
            .find_map(|l| l.strip_prefix(epoch_header.as_str()))
            .map(str::trim);
        if r.path == crate::wire::PATH_WS && ws_epoch.is_some_and(|e| e != "1") {
            return Action::RespondHold(String::new());
        }
        if r.path.ends_with("/events")
            && r.head
                .lines()
                .next()
                .is_some_and(|l| !l.contains("epoch=1 "))
        {
            return Action::RespondHold(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n".into(),
            );
        }
        Action::Pass
    }));
    let env = Env::start(&target, o);
    let mut c = env.dial();
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    echo(&mut c, b"before").unwrap();
    let s = env.egress.registry.all_sessions()[0].clone();
    assert!(env.proxy.kill(is_carrier) > 0, "no carrier to cut");
    let wait = Instant::now() + Duration::from_secs(1);
    while answered.lock().unwrap().is_none() && Instant::now() < wait {
        std::thread::sleep(Duration::from_millis(1));
    }
    let received = answered.lock().unwrap().expect("no resume response");
    let got = c.read(&mut [0u8; 1]);
    let closed_at = Instant::now();
    if let Err(e) = &got {
        assert!(
            !is_timeout(e),
            "client still open 3s after the resume answer"
        );
    }
    assert!(
        closed_at <= received + Duration::from_millis(1010),
        "shortened budget did not close a blocked ready handshake within the terminal allowance: closed {:?} after the resume answer",
        closed_at.saturating_duration_since(received)
    );
    assert!(
        s.epoch() >= 2,
        "fixture: the resume was not processed by the owner (epoch {})",
        s.epoch()
    );
}
