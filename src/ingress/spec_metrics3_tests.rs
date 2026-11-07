use super::spec_e2e_harness::*;
use std::sync::Arc;
use std::time::Instant;

const FALLBACK_SAMPLE: &str = r#"dbb_session_events_total{role="ingress",event="fallback",reason="transport",from="ws",to="http-sse"} "#;

fn fallback_events(env: &Env) -> u64 {
    env.ingress
        .metrics
        .render(&env.ingress.cfg, Instant::now(), true)
        .lines()
        .find_map(|l| l.strip_prefix(FALLBACK_SAMPLE))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

#[test]
fn spec_fallback_counted_once_per_created_session() {
    let target = Target::echo("");
    let mut o = Opts::new("auto");
    o.hook = Some(Arc::new(|r: &Req| {
        let check = r.path == crate::wire::PATH_WS
            && r.head.lines().any(|l| {
                l.split_once(':').is_some_and(|(n, v)| {
                    n.trim().eq_ignore_ascii_case(crate::wire::H_WS_PURPOSE) && v.trim() == "check"
                })
            });
        if check {
            return Action::Respond(
                "HTTP/1.1 426 Upgrade Required\r\nContent-Length: 0\r\n\r\n".to_string(),
            );
        }
        Action::Pass
    }));
    let env = Env::start(&target, o);
    let before = fallback_events(&env);
    let peer = env.ingress.cfg.peer("B").unwrap().clone();
    let (ep, h) = env.ingress.select_endpoint(&peer).expect("selection");
    let client = env.ingress.client_for(&peer.id);
    let mode = env
        .ingress
        .select_mode(&peer, &ep, &h, &client)
        .expect("selection mode");
    assert_eq!(mode, crate::wire::Mode::HttpSse, "selection mode");
    assert_eq!(
        fallback_events(&env),
        before,
        "a bare selection counted a fallback"
    );
    let mut c = env.dial();
    echo(&mut c, b"q").unwrap();
    assert_eq!(
        fallback_events(&env),
        before + 1,
        "fallback events, want +1"
    );
}

#[test]
fn spec_termination_counters_by_recovery_mode() {
    use super::errors::reason_category;
    use super::termination::count_termination;
    use crate::error::Error;
    let m = crate::metrics::Metrics::new();
    let path = std::env::temp_dir().join(format!(
        "dbb-termcount-{}.yaml",
        crate::util::random_hex(4).unwrap()
    ));
    std::fs::write(
        &path,
        "node:\n  id: test\ntargets:\n  db:\n    network: tcp\n    address: 127.0.0.1:3306\n",
    )
    .unwrap();
    let cfg = crate::config::load(&path).unwrap();
    std::fs::remove_file(path).ok();
    let read = || {
        let out = m.render(&cfg, Instant::now(), true);
        let get = |name: &str| -> u64 {
            out.lines()
                .find_map(|l| l.strip_prefix(&format!("{name} ")))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0)
        };
        (
            get("dbb_terminated_direct_total"),
            get("dbb_terminated_after_resume_fail_total"),
            get("dbb_resume_failed_total"),
        )
    };
    let (d0, f0, r0) = read();
    count_termination(&m, "shutdown", true, true);
    count_termination(&m, "shutdown", false, false);
    count_termination(&m, "normal", true, false);
    let (d, f, r) = read();
    assert!(
        d == d0 && f == f0 && r == r0,
        "shutdown/normal counted as failures: direct {d0}->{d} final {f0}->{f} resume {r0}->{r}"
    );
    // Recovery enabled, fatal error while active: final failure, no failed resume.
    let fatal = Error::new(crate::wire::ERR_BACKEND_LOST, "peer HTTP 410");
    count_termination(&m, reason_category(&fatal), true, false);
    let (d, f, r) = read();
    assert!(
        d == d0 && f == f0 + 1 && r == r0,
        "recovery-enabled fatal: direct {d0}->{d} final {f0}->{f} resume {r0}->{r}"
    );
    let deadline = Error::local("recovery deadline exceeded");
    count_termination(&m, reason_category(&deadline), true, true);
    let (_, f, r) = read();
    assert!(
        f == f0 + 2 && r == r0 + 1,
        "recovery deadline: final {f0}->{f} resume {r0}->{r}"
    );
    let reset = Error::local("reset");
    count_termination(&m, reason_category(&reset), false, false);
    let (d, _, _) = read();
    assert_eq!(d, d0 + 1, "recovery disabled: direct {d0}->{d}");
}

#[test]
fn spec_first_fault_source_is_kept() {
    let target = Target::echo("");
    let mut o = Opts::e2e("ws");
    let acks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let a = acks.clone();
    o.hook = Some(Arc::new(move |r: &Req| {
        // The first ACK (the ready ACK) attaches; every later one is cut.
        if r.path.ends_with("/ack") && a.fetch_add(1, std::sync::atomic::Ordering::SeqCst) > 0 {
            return Action::Drop;
        }
        Action::Pass
    }));
    let env = Env::start(&target, o);
    let mut c = env.dial();
    echo(&mut c, b"x").unwrap();
    let sid = env.egress.registry.all_sessions()[0].id.clone();
    let short: String = sid.chars().take(12).collect();
    c.set_read_timeout(Some(std::time::Duration::from_secs(3)))
        .unwrap();
    let _ = std::io::Read::read(&mut c, &mut [0u8; 1]);
    let until = Instant::now() + std::time::Duration::from_secs(3);
    let record = loop {
        let found = crate::slog::test_captured().into_iter().find(|l| {
            l.contains("msg=\"session terminated\"")
                && l.contains(&format!("session={short} "))
                && l.contains("role=ingress")
        });
        if let Some(l) = found {
            break l;
        }
        assert!(Instant::now() < until, "no termination record");
        std::thread::sleep(std::time::Duration::from_millis(5));
    };
    assert!(
        record.contains("fault_source=control") && record.contains("fault_reason=network"),
        "first fault not kept (want control/network): {record}"
    );
}
