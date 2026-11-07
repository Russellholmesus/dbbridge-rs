use super::spec_e2e_harness::*;
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn spec_resume410_normal_message_ends_normally() {
    let target = Target::echo("");
    let mut o = Opts::new("ws");
    let cell = o.egress_cell.clone();
    o.hook = Some(Arc::new(move |r: &Req| {
        if !r.path.ends_with("/resume") {
            return Action::Pass;
        }
        let instance = cell
            .get()
            .map(|s| s.cfg.node.instance_id.clone())
            .unwrap_or_default();
        let body = format!(
            r#"{{"code":"{}","message":"{}","retryable":false,"session_closed":true}}"#,
            crate::wire::ERR_SESSION_CLOSED,
            crate::wire::SESSION_CLOSED_NORMAL_MESSAGE
        );
        Action::ForwardThenRespond(format!(
            "HTTP/1.1 410 Gone\r\n{}: {instance}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            crate::wire::H_INSTANCE_ID,
            body.len()
        ))
    }));
    let mut env = Env::start(&target, o);
    let mut c = env.dial();
    echo(&mut c, b"x").unwrap();
    assert!(
        env.proxy.kill(|p| p == crate::wire::PATH_WS) > 0,
        "no WS carrier to cut"
    );
    let got = c.read(&mut [0u8; 1]);
    assert!(
        matches!(got, Ok(0)) || got.is_err(),
        "expected the local connection to close: {got:?}"
    );
    let until = Instant::now() + Duration::from_secs(2);
    while env.ingress.metrics.ingress_connection_count() > 0 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        env.proxy.counts.count("POST", |p| p.ends_with("/resume")) > 0,
        "fixture: no resume was attempted"
    );
    env.close_ingress();
    let deletes = env.proxy.counts.count("DELETE", |_| true);
    assert_eq!(
        deletes, 0,
        "410 normal message not treated as a normal close: owner-closed session sent {deletes} cleanup DELETE(s)"
    );
}

#[test]
fn spec_sse_upstream_unconfirmed_frame_is_detected() {
    let target = Target::echo("");
    let mut o = Opts::new("http-sse");
    for t in [&mut o.egress_transport, &mut o.ingress_transport] {
        t.insert("heartbeat", "30ms".into());
        t.insert("failure_detect_timeout", "150ms".into());
    }
    o.ingress_transport.insert("ack_max_delay", "20ms".into());
    o.ingress_transport
        .insert("control_request_timeout", "250ms".into());
    o.egress_recovery = Some("enabled: false".into());
    o.ingress_recovery = Some("enabled: false".into());
    let cell = o.egress_cell.clone();
    o.hook = Some(Arc::new(move |r: &Req| {
        if !r.path.ends_with("/up") {
            return Action::Pass;
        }
        let Some(srv) = cell.get() else {
            return Action::Respond(json_response(404, ""));
        };
        let Some(s) = srv.registry.all_sessions().into_iter().last() else {
            return Action::Respond(json_response(404, ""));
        };
        let snap = s.snapshot();
        Action::Respond(json_response(
            202,
            &format!(
                r#"{{"session_id":"{}","instance_id":"{}","epoch":"{}","frame_accepted":true,"ack_up_offset":"0","down_ack_offset":"0","up_receive_limit":"2097152","up_fin_applied":false,"stream_id":"{}","transport":{{"mode":"http-sse"}}}}"#,
                snap.session_id,
                snap.instance_id,
                s.epoch(),
                snap.stream_id
            ),
        ))
    }));
    let env = Env::start(&target, o);
    let mut c = env.dial();
    c.write_all(b"short-query").unwrap();
    let until = Instant::now() + Duration::from_secs(1);
    while env.proxy.counts.count("POST", |p| p.ends_with("/up")) == 0 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(
        env.proxy.counts.count("POST", |p| p.ends_with("/up")) > 0,
        "fixture: the frame was never posted"
    );
    c.set_read_timeout(Some(Duration::from_millis(900)))
        .unwrap();
    let got = c.read(&mut [0u8; 64]);
    match &got {
        Ok(0) => {}
        Err(e)
            if !matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ) => {}
        _ => panic!(
            "http-sse session with unconfirmed /up frame stayed alive past failure_detect_timeout: {got:?}"
        ),
    }
}

#[test]
fn spec_boundary_fin_throttle_does_not_fault_session() {
    let target = Target::echo("");
    let mut o = Opts::e2e("ws");
    o.ingress_transport
        .insert("control_request_timeout", "1s".into());
    let cell = o.egress_cell.clone();
    let fins = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let f = fins.clone();
    o.hook = Some(Arc::new(move |r: &Req| {
        if r.method == "POST"
            && r.path.ends_with("/fin")
            && f.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0
        {
            let instance = cell
                .get()
                .map(|s| s.cfg.node.instance_id.clone())
                .unwrap_or_default();
            let body = format!(
                r#"{{"code":"{}","message":"slow down","retryable":true}}"#,
                crate::wire::ERR_QUOTA_EXCEEDED
            );
            return Action::Respond(format!(
                    "HTTP/1.1 429 Too Many Requests\r\n{}: {instance}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                    crate::wire::H_INSTANCE_ID,
                    body.len()
                ));
        }
        Action::Pass
    }));
    let env = Env::start(&target, o);
    let mut c = env.dial();
    echo(&mut c, b"x").unwrap();
    c.shutdown(std::net::Shutdown::Write).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut rest = Vec::new();
    let got = c.read_to_end(&mut rest);
    let n = fins.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        got.is_ok(),
        "side-effect-free FIN 429 triggered session failure after {n} request(s): {got:?}"
    );
    assert!(n >= 2, "FIN not retried ({n} request(s))");
    assert_eq!(env.wait_egress_sessions(0, Duration::from_secs(2)), 0);
    assert_eq!(
        env.proxy.counts.count("DELETE", |_| true),
        0,
        "the throttled FIN faulted the session (cleanup DELETE sent)"
    );
}
