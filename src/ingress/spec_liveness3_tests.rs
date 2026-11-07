use super::spec_blackhole_tests::{count_resumes, is_ws_session, review_opts};
use super::spec_e2e_harness::*;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn spec_upstream_ws_blackhole_must_trigger_recovery() {
    let target = Target::echo("");
    let mut o = review_opts(true);
    let resumes = Arc::new(AtomicUsize::new(0));
    let rs = resumes.clone();
    o.hook = Some(Arc::new(move |r: &Req| {
        count_resumes(&rs, r);
        if is_ws_session(r) {
            return Action::PassDropUpBinary;
        }
        Action::Pass
    }));
    let env = Env::start(&target, o);
    let mut c = env.dial();
    let msg = b"pending upstream frame";
    c.write_all(msg).unwrap();
    let dropped = || env.proxy.counts.dropped_up_binary.load(Ordering::SeqCst);
    let until = Instant::now() + Duration::from_secs(1);
    while dropped() == 0 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(dropped() > 0, "fixture did not drop any upstream frame");
    // More than four detection intervals; control and downstream remain active.
    std::thread::sleep(Duration::from_millis(650));
    assert!(
        resumes.load(Ordering::SeqCst) > 0,
        "upstream data blackhole was not detected while independent controls and downstream pings stayed healthy (dropped={}) requests={:?}",
        dropped(),
        env.proxy.counts.requests.lock().unwrap()
    );
    c.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let mut got = vec![0u8; msg.len()];
    let r = c.read_exact(&mut got);
    let dials = target.dials.load(Ordering::SeqCst);
    assert!(
        r.is_ok() && &got[..] == msg && dials == 1,
        "recovery did not preserve original bytes/socket: {:?} dials={dials} error={r:?}",
        String::from_utf8_lossy(&got)
    );
}

#[test]
fn spec_local_backpressure_not_link_failure() {
    const TOTAL: usize = 8 << 20;
    let target = Target::with(|mut c, _tx| {
        // Consume the client's hello first: closing with unread input would
        // reset the backend connection.
        let mut hello = [0u8; 2];
        if c.read_exact(&mut hello).is_err() {
            return;
        }
        let chunk: Vec<u8> = (0..65536u32).map(|i| (i % 251) as u8).collect();
        let mut sent = 0;
        while sent < TOTAL {
            if c.write_all(&chunk).is_err() {
                return;
            }
            sent += chunk.len();
        }
        let mut sink = [0u8; 64];
        while matches!(c.read(&mut sink), Ok(n) if n > 0) {}
    });
    let env = Env::start(&target, Opts::e2e("ws"));
    let mut c = env.dial();
    c.write_all(b"go").unwrap();
    // Several detection intervals with the local socket write blocked.
    std::thread::sleep(Duration::from_millis(600));
    c.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut buf = vec![0u8; 65536];
    let mut got = 0usize;
    while got < TOTAL {
        match c.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                for (i, b) in buf[..n].iter().enumerate() {
                    assert_eq!(
                        *b,
                        ((got + i) % 65536 % 251) as u8,
                        "corrupt byte at {}",
                        got + i
                    );
                }
                got += n;
            }
            Err(e) => panic!("read failed after {got} bytes: {e}"),
        }
    }
    assert_eq!(
        got, TOTAL,
        "healthy local write backpressure classified as a transport failure"
    );
    assert_eq!(
        env.proxy.counts.count("POST", |p| p.ends_with("/resume")),
        0
    );
    assert_eq!(env.proxy.counts.count("DELETE", |_| true), 0);
}

#[test]
fn spec_boundary_heartbeat_independent_of_ack_delay() {
    let target = Target::echo("");
    let mut o = Opts::new("ws");
    for t in [&mut o.egress_transport, &mut o.ingress_transport] {
        t.insert("heartbeat", "20ms".into());
        t.insert("failure_detect_timeout", "90ms".into());
    }
    o.ingress_transport.insert("ack_max_delay", "500ms".into());
    let env = Env::start(&target, o);
    let mut c = env.dial();
    echo(&mut c, b"x").unwrap();
    // Let the echo's own acknowledgements settle, then measure an idle window.
    std::thread::sleep(Duration::from_millis(30));
    let acks = || env.proxy.counts.count("POST", |p| p.ends_with("/ack"));
    let before = acks();
    std::thread::sleep(Duration::from_millis(120));
    let n = acks() - before;
    assert!(
        n >= 2,
        "heartbeat=20ms, detect=90ms, ACK delay=500ms: only {n} controls in 120ms"
    );
}
