use super::spec_e2e_harness::*;
use std::io::{Read, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

const COMMENT: &[u8] = b": gateway keepalive\n\n";

/// Reads from the local connection until it is closed by the ingress or
/// `within` passes; returns how long the session stayed open, or None.
fn closed_within(c: &mut std::net::TcpStream, within: Duration) -> Option<Duration> {
    let start = Instant::now();
    let mut buf = [0u8; 256];
    loop {
        let left = within.saturating_sub(start.elapsed());
        if left.is_zero() {
            return None;
        }
        c.set_read_timeout(Some(left)).unwrap();
        match c.read(&mut buf) {
            Ok(0) => return Some(start.elapsed()),
            Ok(_) => continue,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return None
            }
            Err(_) => return Some(start.elapsed()),
        }
    }
}

/// An SSE events answer for a session the egress really attached: the ready
/// event (and, when `ping`, one bound ping), then only comments every 20ms.
fn comment_hook(cell: EgressCell, ping: bool) -> Hook {
    Arc::new(move |r: &Req| {
        if !r.path.ends_with("/events") {
            return Action::Pass;
        }
        match injected_events(&cell, r.path, |s, stream| {
            if !ping {
                return String::new();
            }
            let _ = stream;
            match s.ping_control() {
                Ok(p) => format!("event: ping\ndata: {}\n\n", p.to_json()),
                Err(_) => String::new(),
            }
        }) {
            Some(head) => Action::RespondDrip(head, COMMENT.to_vec(), Duration::from_millis(20)),
            None => Action::Respond(json_response(404, "")),
        }
    })
}

#[test]
fn spec_sse_comments_do_not_renew_liveness() {
    let target = Target::echo("");
    let mut o = Opts::new("http-sse");
    o.ingress_transport
        .insert("failure_detect_timeout", "100ms".into());
    o.ingress_transport.insert("heartbeat", "30ms".into());
    o.ingress_transport
        .insert("control_request_timeout", "1s".into());
    o.ingress_transport
        .insert("backpressure_timeout", "1s".into());
    o.egress_recovery = Some("enabled: false".into());
    o.ingress_recovery = Some("enabled: false".into());
    o.hook = Some(comment_hook(o.egress_cell.clone(), false));
    let env = Env::start(&target, o);
    let mut c = env.dial();
    c.write_all(b"x").unwrap();
    let start = Instant::now();
    let until = start + Duration::from_secs(2);
    while env.proxy.counts.count("GET", |p| p.ends_with("/events")) == 0 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(
        env.proxy.counts.count("GET", |p| p.ends_with("/events")) > 0,
        "fixture: no events stream"
    );
    let closed = closed_within(&mut c, Duration::from_millis(450));
    assert!(
        closed.is_some(),
        "no bound ping/data/control event for 4.5 detection intervals, but comment bytes kept the session alive"
    );
    // The fault is the liveness timeout, not an immediate carrier error.
    assert!(
        start.elapsed() >= Duration::from_millis(60),
        "session ended before a detection interval: {:?}",
        start.elapsed()
    );
}

#[test]
fn spec_sse_comment_only_stream_is_detected() {
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
    o.hook = Some(comment_hook(o.egress_cell.clone(), true));
    let env = Env::start(&target, o);
    let mut c = env.dial();
    let until = Instant::now() + Duration::from_secs(1);
    while env.proxy.counts.count("GET", |p| p.ends_with("/events")) == 0 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(
        env.proxy.counts.count("GET", |p| p.ends_with("/events")) > 0,
        "fixture session not created"
    );
    let closed = closed_within(&mut c, Duration::from_millis(900));
    assert!(
        closed.is_some(),
        "session still active after 6 detection intervals of comment-only SSE (control requests: {}), recovery disabled",
        env.proxy.counts.count("POST", |p| p.ends_with("/ack"))
    );
    assert!(
        closed.unwrap() >= Duration::from_millis(90),
        "session ended before a detection interval: {closed:?}"
    );
}
