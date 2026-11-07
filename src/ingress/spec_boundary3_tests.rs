use super::spec_e2e_harness::*;
use std::io::Read;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn spec_boundary_sse_remote_backpressure_read_does_not_expire_detect_timer() {
    let target = Target::echo("");
    let mut o = Opts::new("http-sse");
    o.ingress_transport
        .insert("failure_detect_timeout", "60ms".into());
    o.ingress_transport.insert("heartbeat", "20ms".into());
    o.ingress_transport.insert("ack_max_delay", "10ms".into());
    o.ingress_transport
        .insert("control_request_timeout", "1s".into());
    o.ingress_transport
        .insert("backpressure_timeout", "1s".into());
    o.egress_recovery = Some("enabled: false".into());
    o.ingress_recovery = Some("enabled: false".into());
    let cell = o.egress_cell.clone();
    let controls = Arc::new(AtomicUsize::new(0));
    let ctl = controls.clone();
    o.hook = Some(Arc::new(move |r: &Req| {
        if r.path.ends_with("/events") {
            return match injected_events(&cell, r.path, |_, _| String::new()) {
                Some(head) => Action::RespondHold(head),
                None => Action::Respond(json_response(404, "")),
            };
        }
        if !r.path.ends_with("/ack") {
            return Action::Pass;
        }
        let Some(srv) = cell.get() else {
            return Action::Respond(json_response(404, ""));
        };
        let Some(s) = srv.registry.all_sessions().into_iter().last() else {
            return Action::Respond(json_response(404, ""));
        };
        let probe = crate::util::json::parse_bytes(r.body)
            .ok()
            .and_then(|v| {
                v.get("probe_id")
                    .and_then(|p| p.as_str().map(str::to_string))
            })
            .unwrap_or_default();
        let snap = s.snapshot();
        let body = format!(
            r#"{{"session_id":"{}","instance_id":"{}","epoch":"{}","stream_id":"{}","transport":{{"mode":"http-sse"}},"ack_up_offset":"0","up_fin_applied":false,"down_ack_offset":"0","down_fin_acked":false,"probe_id":"{probe}","data_tx_blocked":true,"data_rx_blocked":false,"backpressure_reason":"data_channel_write"}}"#,
            snap.session_id,
            snap.instance_id,
            s.epoch(),
            snap.stream_id
        );
        ctl.fetch_add(1, Ordering::SeqCst);
        Action::Respond(format!(
            "HTTP/1.1 200 OK\r\n{}: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            crate::wire::H_INSTANCE_ID,
            snap.instance_id,
            body.len()
        ))
    }));
    let env = Env::start(&target, o);
    let mut c = env.dial();
    let until = Instant::now() + Duration::from_secs(1);
    while controls.load(Ordering::SeqCst) == 0 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(controls.load(Ordering::SeqCst) > 0, "fixture: no control");
    c.set_read_timeout(Some(Duration::from_millis(160)))
        .unwrap();
    let got = c.read(&mut [0u8; 1]);
    assert!(
        matches!(&got, Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)),
        "read deadline ignored declared remote backpressure after {} successful controls: {got:?}",
        controls.load(Ordering::SeqCst)
    );
    assert!(
        controls.load(Ordering::SeqCst) >= 2,
        "control fixture made no progress"
    );
    assert_eq!(env.proxy.counts.count("DELETE", |_| true), 0);
}

#[test]
fn spec_bound_sessions_count_only_active_carriers() {
    let target = Target::echo("");
    // auto: a cut WS carrier recovers onto the same address's SSE.
    let mut o = Opts::new("auto");
    o.egress_recovery = Some("enabled: true, grace: 3s, barrier_timeout: 100ms".into());
    o.ingress_recovery = Some("enabled: true, grace: 3s, barrier_timeout: 100ms".into());
    let resumes = Arc::new(AtomicUsize::new(0));
    let rs = resumes.clone();
    o.hook = Some(Arc::new(move |r: &Req| {
        if r.path.ends_with("/resume") && rs.fetch_add(1, Ordering::SeqCst) == 1 {
            // The second session's resume hangs: it stays recovering.
            return Action::Hang(Duration::from_secs(2));
        }
        Action::Pass
    }));
    let env = Env::start(&target, o);
    let mut c1 = env.dial();
    echo(&mut c1, b"one").unwrap();
    let mut c2 = env.dial();
    echo(&mut c2, b"two").unwrap();
    let metrics = || {
        env.ingress
            .metrics
            .render(&env.ingress.cfg, Instant::now(), true)
    };
    let bound_lines = |out: &str| -> Vec<String> {
        out.lines()
            .filter(|l| l.starts_with("dbb_ingress_bound_sessions{"))
            .map(str::to_string)
            .collect()
    };
    let want = vec![
        r#"dbb_ingress_bound_sessions{peer="B",endpoint="e1",transport="ws",recovery="true"} 2"#
            .to_string(),
    ];
    let until = Instant::now() + Duration::from_secs(2);
    let mut before = metrics();
    while bound_lines(&before) != want && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(5));
        before = metrics();
    }
    assert_eq!(
        bound_lines(&before),
        want,
        "fixture: two bound sessions:\n{before}"
    );
    assert!(
        env.proxy.kill(|p| p == crate::wire::PATH_WS) >= 2,
        "no carriers to cut"
    );
    // One session recovers, the other waits on its hanging resume.
    let until = Instant::now() + Duration::from_secs(2);
    let mut out = metrics();
    while Instant::now() < until {
        out = metrics();
        let bound = bound_lines(&out);
        if resumes.load(Ordering::SeqCst) >= 2
            && bound.len() == 1
            && bound[0].ends_with(" 1")
            && out.contains("\ndbb_ingress_recovering_sessions 1\n")
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let bound = bound_lines(&out);
    assert!(
        bound.len() == 1
            && bound[0].starts_with(r#"dbb_ingress_bound_sessions{peer="B",endpoint="e1","#)
            && bound[0].ends_with(r#",recovery="true"} 1"#),
        "bound sessions:\n{out}"
    );
    assert!(
        out.contains("\ndbb_ingress_recovering_sessions 1\n"),
        "recovering sessions:\n{out}"
    );
}
