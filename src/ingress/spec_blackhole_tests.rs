use super::spec_e2e_harness::*;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(super) fn is_ws_session(r: &Req) -> bool {
    r.path == crate::wire::PATH_WS
        && r.head.lines().any(|l| {
            l.split_once(':').is_some_and(|(n, v)| {
                n.trim().eq_ignore_ascii_case(crate::wire::H_WS_PURPOSE) && v.trim() == "session"
            })
        })
}

pub(super) fn review_opts(recovery: bool) -> Opts {
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
    let r = format!("enabled: {recovery}, grace: 1200ms, barrier_timeout: 100ms");
    o.egress_recovery = Some(r.clone());
    o.ingress_recovery = Some(r);
    o
}

pub(super) fn count_resumes(hook_count: &Arc<AtomicUsize>, r: &Req) {
    if r.path.ends_with("/resume") {
        hook_count.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn spec_malformed_initial_ready_must_terminate() {
    let target = Target::echo("");
    let mut o = review_opts(true);
    let resumes = Arc::new(AtomicUsize::new(0));
    let malformed = Arc::new(AtomicBool::new(false));
    let (rs, mf) = (resumes.clone(), malformed.clone());
    o.hook = Some(Arc::new(move |r: &Req| {
        count_resumes(&rs, r);
        if is_ws_session(r) && !mf.swap(true, Ordering::SeqCst) {
            let header = |name: &str| {
                r.raw
                    .lines()
                    .find_map(|l| {
                        let (n, v) = l.split_once(':')?;
                        n.trim()
                            .eq_ignore_ascii_case(name)
                            .then(|| v.trim().to_string())
                    })
                    .unwrap_or_default()
            };
            let mut out = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: {}\r\n\r\n",
                crate::net::ws::accept_key(&header("sec-websocket-key")),
                crate::wire::WS_SUBPROTOCOL
            )
            .into_bytes();
            out.extend_from_slice(&crate::transport::spec_precheck_tests::frame(
                crate::net::ws::OP_TEXT,
                br#"{"type":"ready","type":"ready"}"#,
            ));
            return Action::RespondRawClose(out);
        }
        Action::Pass
    }));
    let env = Env::start(&target, o);
    let mut c = env.dial();
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let p = b"must not survive an invalid protocol message";
    let _ = c.write_all(p);
    let mut got = vec![0u8; p.len()];
    let err = c.read_exact(&mut got);
    assert!(
        err.is_err(),
        "malformed duplicate-key ready was tolerated through recovery and carrier fallback"
    );
    assert!(
        malformed.load(Ordering::SeqCst),
        "fixture never answered the WS carrier"
    );
    let until = Instant::now() + Duration::from_secs(1);
    while target.dials.load(Ordering::SeqCst) == 0 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(1));
    }
    let (r, d) = (
        resumes.load(Ordering::SeqCst),
        target.dials.load(Ordering::SeqCst),
    );
    assert!(
        r == 0 && d == 1,
        "protocol rejection must not recover or replace the database connection: resumes={r} dials={d}"
    );
}

#[test]
fn spec_upstream_blackhole_without_recovery_must_close() {
    let target = Target::echo("");
    let mut o = review_opts(false);
    o.hook = Some(Arc::new(|r: &Req| {
        if is_ws_session(r) {
            return Action::PassDropUpBinary;
        }
        Action::Pass
    }));
    let env = Env::start(&target, o);
    let mut c = env.dial();
    c.write_all(b"unconfirmed bytes").unwrap();
    let dropped = || env.proxy.counts.dropped_up_binary.load(Ordering::SeqCst);
    let until = Instant::now() + Duration::from_secs(1);
    while dropped() == 0 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(dropped() > 0, "fixture did not drop an upstream frame");
    // Include the detection interval and the full one-second terminal allowance.
    std::thread::sleep(Duration::from_millis(1250));
    c.set_read_timeout(Some(Duration::from_millis(25))).unwrap();
    let r = c.read(&mut [0u8; 1]);
    if let Err(e) = &r {
        assert!(
            !matches!(
                e.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
            ),
            "client remained open beyond detection plus one-second closure allowance"
        );
    }
}
