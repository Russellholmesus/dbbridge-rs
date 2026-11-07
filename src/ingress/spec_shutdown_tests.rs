use super::spec_e2e_harness::*;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const TWO_ENDPOINTS: &str = "      - id: primary\n        url: \"http://{proxy}\"\n        priority: 0\n      - id: backup\n        url: \"http://{proxy2}\"\n        priority: 10\n";

fn is_carrier(path: &str) -> bool {
    path == crate::wire::PATH_WS || path.ends_with("/events")
}

fn cleanup_failover_opts(o: &mut Opts, broken: &Arc<AtomicBool>) {
    o.peer_extra = "    failover:\n      enabled: true\n      cooldown: 0s\n".into();
    o.second_proxy = true;
    o.endpoints = Some(TWO_ENDPOINTS.into());
    let b = broken.clone();
    o.hook = Some(Arc::new(move |_r: &Req| {
        if b.load(Ordering::SeqCst) {
            return Action::Respond(json_response(503, ""));
        }
        Action::Pass
    }));
}

fn deletes(p: &Proxy) -> usize {
    p.counts.count("DELETE", |_| true)
}

fn wait_for(within: Duration, f: impl Fn() -> bool) -> bool {
    let until = Instant::now() + within;
    while !f() {
        if Instant::now() >= until {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    true
}

#[test]
fn spec_cleanup_failover_outside_shutdown_reaches_backup() {
    let target = Target::echo("");
    let broken = Arc::new(AtomicBool::new(false));
    let mut o = Opts::e2e("ws");
    cleanup_failover_opts(&mut o, &broken);
    let env = Env::start(&target, o);
    let mut c = env.dial();
    echo(&mut c, b"x").unwrap();
    assert_eq!(env.egress_sessions(), 1, "fixture session");
    broken.store(true, Ordering::SeqCst);
    assert!(env.proxy.kill(is_carrier) > 0, "no carrier to cut");
    let backup = env.proxy2.as_ref().unwrap();
    wait_for(Duration::from_secs(3), || deletes(backup) > 0);
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(deletes(backup), 1, "want 1 backup DELETE");
    assert_eq!(
        env.wait_egress_sessions(0, Duration::from_secs(2)),
        0,
        "the backup DELETE did not close the remote session"
    );
}

#[test]
fn spec_shutdown_cleanup_reaches_backup_endpoint() {
    let target = Target::echo("");
    let broken = Arc::new(AtomicBool::new(false));
    let mut o = Opts::e2e("ws");
    cleanup_failover_opts(&mut o, &broken);
    let mut env = Env::start(&target, o);
    let mut c = env.dial();
    echo(&mut c, b"x").unwrap();
    assert_eq!(env.egress_sessions(), 1, "fixture session");
    broken.store(true, Ordering::SeqCst);
    let started = Instant::now();
    env.close_ingress();
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "shutdown took {:?}",
        started.elapsed()
    );
    let backup = env.proxy2.as_ref().unwrap();
    let probes = backup
        .counts
        .count("POST", |p| p == crate::wire::PATH_PROBE);
    assert_eq!(
        deletes(backup),
        1,
        "shutdown cleanup did not reach the backup endpoint: probes={probes}"
    );
    assert_eq!(env.wait_egress_sessions(0, Duration::from_secs(2)), 0);
}

#[test]
fn spec_shutdown_cleanup_of_recovering_session_tries_backup_first() {
    let target = Target::echo("");
    let broken = Arc::new(AtomicBool::new(false));
    let mut o = Opts::new("ws");
    for t in [&mut o.egress_transport, &mut o.ingress_transport] {
        t.insert("heartbeat", "50ms".into());
        t.insert("failure_detect_timeout", "500ms".into());
    }
    o.ingress_transport
        .insert("control_request_timeout", "200ms".into());
    o.egress_recovery = Some("enabled: true, grace: 20s, barrier_timeout: 100ms".into());
    o.ingress_recovery = Some("enabled: true, grace: 20s, barrier_timeout: 100ms".into());
    cleanup_failover_opts(&mut o, &broken);
    // The backup refuses the resume (retryable), so the session stays in
    // recovery until shutdown.
    o.hook2 = Some(Arc::new(|r: &Req| {
        if r.path.ends_with("/resume") {
            return Action::Respond(json_response(503, ""));
        }
        Action::Pass
    }));
    let mut env = Env::start(&target, o);
    let mut c = env.dial();
    echo(&mut c, b"x").unwrap();
    broken.store(true, Ordering::SeqCst);
    assert!(env.proxy.kill(is_carrier) > 0, "no carrier to cut");
    let resumes = || {
        env.proxy2
            .as_ref()
            .unwrap()
            .counts
            .count("POST", |p| p.ends_with("/resume"))
    };
    assert!(
        wait_for(Duration::from_secs(3), || resumes() > 0),
        "fixture: the session never tried to resume at the backup"
    );
    let primary_before = deletes(&env.proxy);
    env.close_ingress();
    let backup = deletes(env.proxy2.as_ref().unwrap());
    let primary = deletes(&env.proxy) - primary_before;
    assert!(
        backup == 1 && primary == 0,
        "recovering session: backup deletes={backup} primary deletes={primary}, want 1 and 0"
    );
}

#[test]
fn spec_reused_probe_instance_mismatch_recovers() {
    let target = Target::echo("");
    let mut o = Opts::new("ws");
    let stale = Arc::new(AtomicBool::new(false));
    let creates = Arc::new(AtomicUsize::new(0));
    let probes = Arc::new(AtomicUsize::new(0));
    let cell = o.egress_cell.clone();
    let (st, cr, pr) = (stale.clone(), creates.clone(), probes.clone());
    o.hook = Some(Arc::new(move |r: &Req| {
        if r.path == crate::wire::PATH_PROBE {
            pr.fetch_add(1, Ordering::SeqCst);
        }
        if r.method == "POST" && r.path == crate::wire::PATH_SESSIONS {
            cr.fetch_add(1, Ordering::SeqCst);
            if st
                .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                let instance = cell
                    .get()
                    .map(|s| s.cfg.node.instance_id.clone())
                    .unwrap_or_default();
                let body = format!(
                    r#"{{"code":"{}","message":"instance mismatch","retryable":false}}"#,
                    crate::wire::ERR_INSTANCE_MISMATCH
                );
                return Action::Respond(format!(
                    "HTTP/1.1 409 Conflict\r\n{}: {instance}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                    crate::wire::H_INSTANCE_ID,
                    body.len()
                ));
            }
        }
        Action::Pass
    }));
    let env = Env::start(&target, o);
    {
        let mut warm = env.dial();
        echo(&mut warm, b"warm").unwrap();
    }
    assert!(
        probes.load(Ordering::SeqCst) > 0,
        "the warm-up probe never landed"
    );
    std::thread::sleep(Duration::from_millis(50));
    let before = probes.load(Ordering::SeqCst);
    let creates_before = creates.load(Ordering::SeqCst);
    stale.store(true, Ordering::SeqCst);
    let mut c = env.dial();
    c.write_all(b"hello").unwrap();
    let mut buf = [0u8; 5];
    let got = c.read_exact(&mut buf);
    assert!(got.is_ok() && &buf == b"hello", "echo: {buf:?} {got:?}");
    assert_eq!(
        creates.load(Ordering::SeqCst) - creates_before,
        2,
        "want the refused create and one more"
    );
    assert!(
        probes.load(Ordering::SeqCst) > before,
        "no fresh probe after the refused create"
    );
}

#[test]
fn spec_recovery_with_backup_instance() {
    let target = Target::echo("");
    let mut o = Opts::new("ws");
    o.peer_extra = "    failover:\n      cooldown: 200ms\n".into();
    o.second_proxy = true;
    o.second_egress = true;
    o.endpoints = Some(TWO_ENDPOINTS.into());
    o.egress_recovery = Some("enabled: true, grace: 3s, barrier_timeout: 1s".into());
    o.ingress_recovery = Some("enabled: true, grace: 3s, barrier_timeout: 1s".into());
    let env = Env::start(&target, o);
    let mut c = env.dial();
    c.set_read_timeout(Some(Duration::from_secs(6))).unwrap();
    echo(&mut c, b"first").unwrap();
    let s = env.egress.registry.all_sessions()[0].clone();
    assert!(
        env.proxy.kill(|p| p == crate::wire::PATH_WS) > 0,
        "no WS carrier on the primary"
    );
    std::thread::sleep(Duration::from_millis(1500));
    echo(&mut c, b"after").unwrap_or_else(|e| {
        panic!("recovery aborted although the owner endpoint was reachable: {e}")
    });
    assert!(
        s.epoch() >= 2,
        "session did not resume on the owner: epoch={}",
        s.epoch()
    );
    let backup = env.egress2.as_ref().unwrap().registry.all_sessions().len();
    assert_eq!(backup, 0, "backup instance got {backup} sessions");
}
