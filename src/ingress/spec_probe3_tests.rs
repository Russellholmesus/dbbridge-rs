use super::spec_e2e_harness::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn spec_cooldown_respects_unhealthy_threshold() {
    let t = super::EndpointTable::default();
    let cooldown = Duration::from_secs(60);
    t.record_probe_failure("B", "e1", cooldown, 2, false);
    let state = t.get("B", "e1").map(|h| h.state).unwrap_or("UNKNOWN");
    assert!(
        !t.in_cooldown("B", "e1") && !super::select::excluded_state(state),
        "one failure below unhealthy_threshold=2 put the endpoint in cooldown (state={state})"
    );
    let state = t.record_probe_failure("B", "e1", cooldown, 2, false);
    assert!(
        t.in_cooldown("B", "e1") && state == "UNHEALTHY",
        "reaching unhealthy_threshold must start cooldown: state={state}"
    );
    let t2 = super::EndpointTable::default();
    t2.record_probe_failure("B", "e1", cooldown, 2, true);
    assert!(
        t2.in_cooldown("B", "e1"),
        "identity mismatch must cool down immediately"
    );
}

fn counting_opts(
    mode: &'static str,
) -> (Opts, Arc<AtomicUsize>, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let mut o = Opts::new(mode);
    let acks = Arc::new(AtomicUsize::new(0));
    let probes = Arc::new(AtomicUsize::new(0));
    let checks = Arc::new(AtomicUsize::new(0));
    let (a, p, c) = (acks.clone(), probes.clone(), checks.clone());
    o.hook = Some(Arc::new(move |r: &Req| {
        if r.path.ends_with("/ack") {
            a.fetch_add(1, Ordering::SeqCst);
        }
        if r.path == crate::wire::PATH_PROBE {
            p.fetch_add(1, Ordering::SeqCst);
        }
        if r.path == crate::wire::PATH_WS
            && r.head.lines().any(|l| {
                l.split_once(':')
                    .is_some_and(|(k, v)| k.contains("purpose") && v.trim() == "check")
            })
        {
            c.fetch_add(1, Ordering::SeqCst);
        }
        Action::Pass
    }));
    (o, acks, probes, checks)
}

#[test]
fn spec_idle_session_no_ack_storm() {
    for mode in ["ws", "http-sse"] {
        let target = Target::echo("");
        let (o, acks, _, _) = counting_opts(mode);
        let env = Env::start(&target, o);
        let mut c = env.dial();
        echo(&mut c, b"hi").unwrap();
        std::thread::sleep(Duration::from_millis(400));
        let before = acks.load(Ordering::SeqCst);
        std::thread::sleep(Duration::from_secs(2));
        let n = acks.load(Ordering::SeqCst) - before;
        assert!(
            n <= 2,
            "idle {mode} session sent {n} ACK POSTs in 2s with nothing to acknowledge"
        );
        let before = acks.load(Ordering::SeqCst);
        echo(&mut c, b"again").unwrap();
        let until = Instant::now() + Duration::from_secs(2);
        while acks.load(Ordering::SeqCst) == before && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            acks.load(Ordering::SeqCst) > before,
            "{mode}: downstream data after idle period was never acknowledged"
        );
        assert_eq!(env.egress_sessions(), 1, "{mode}: sessions on egress");
    }
}

#[test]
fn spec_single_probe_per_create() {
    let target = Target::echo("");
    let (o, _, probes, checks) = counting_opts("ws");
    let env = Env::start(&target, o);
    let mut c = env.dial();
    echo(&mut c, b"hi").unwrap();
    let n = probes.load(Ordering::SeqCst);
    assert!(
        (1..=2).contains(&n),
        "one session create issued {n} probes, want 1"
    );
    let n = checks.load(Ordering::SeqCst);
    assert_eq!(n, 1, "one session create issued {n} WS prechecks, want 1");
}

#[test]
fn spec_recovery_mismatch_fatal_without_owner() {
    let target = Target::echo("");
    let mut o = Opts::new("http-sse");
    o.second_proxy = true;
    o.second_egress = true;
    o.endpoints = Some("      - id: primary\n        url: \"http://{proxy}\"\n        priority: 0\n      - id: backup\n        url: \"http://{proxy2}\"\n        priority: 10\n".into());
    o.peer_extra = "    failover:\n      cooldown: 0s\n".into();
    o.egress_recovery = Some("enabled: true, grace: 5s, barrier_timeout: 100ms".into());
    o.ingress_recovery = Some("enabled: true, grace: 5s, barrier_timeout: 100ms".into());
    let down = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let d = down.clone();
    o.hook = Some(Arc::new(move |r: &Req| {
        if !d.load(Ordering::SeqCst) {
            return Action::Pass;
        }
        if r.path == crate::wire::PATH_PROBE {
            let nonce = crate::util::json::parse_bytes(r.body)
                .ok()
                .and_then(|q| q.get("nonce").and_then(|n| n.as_str()).map(str::to_string))
                .unwrap_or_default();
            return Action::Respond(json_response(
                200,
                &format!(
                    r#"{{"protocol_version":"1.5","node_id":"B","instance_id":"some-other-instance","nonce":"{nonce}","recovery_available":true,"accepting_new_sessions":true,"transports":["ws","http-sse"]}}"#
                ),
            ));
        }
        Action::Respond(json_response(503, ""))
    }));
    let env = Env::start(&target, o);
    let mut c = env.dial();
    echo(&mut c, b"x").unwrap();
    down.store(true, Ordering::SeqCst);
    let started = Instant::now();
    assert!(
        env.proxy.kill(|p| p.ends_with("/events")) > 0,
        "no carrier to cut"
    );
    c.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
    let mut b = [0u8; 1];
    let got = std::io::Read::read(&mut c, &mut b);
    let elapsed = started.elapsed();
    assert!(
        matches!(got, Ok(0))
            || matches!(&got, Err(e) if !matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut)),
        "client socket still open: {got:?}"
    );
    assert!(
        elapsed < Duration::from_secs(2),
        "owner absent from every reachable endpoint should be a protocol fault, but recovery ran {elapsed:?} (grace 5s)"
    );
    let other = env.egress2.as_ref().unwrap().registry.all_sessions().len();
    assert_eq!(other, 0, "the other instance got {other} sessions");
}
