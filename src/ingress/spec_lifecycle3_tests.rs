use super::spec_blackhole_tests::is_ws_session;
use super::spec_e2e_harness::*;
use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn spec_cleanup_without_generation() {
    let target = Target::echo("");
    let mut o = Opts::new("ws");
    o.hook = Some(Arc::new(|r: &Req| {
        if is_ws_session(r) {
            // The first carrier never comes up while the node stops.
            return Action::Hang(Duration::from_secs(3));
        }
        Action::Pass
    }));
    let mut env = Env::start(&target, o);
    let mut c = env.dial();
    let _ = c.write_all(b"x");
    let until = Instant::now() + Duration::from_secs(2);
    while env.proxy.counts.count("GET", |p| p == crate::wire::PATH_WS) == 0
        && Instant::now() < until
    {
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(
        env.proxy.counts.count("POST", |p| p == "/v1/sessions"),
        1,
        "fixture: session not created"
    );
    assert!(
        env.proxy.counts.count("GET", |p| p == crate::wire::PATH_WS) > 0,
        "fixture: no attach in flight"
    );
    env.close_ingress();
    let until = Instant::now() + Duration::from_secs(3);
    while env.proxy.counts.count("DELETE", |_| true) == 0 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(5));
    }
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        env.proxy.counts.count("DELETE", |_| true),
        1,
        "DELETE attempts, want 1"
    );
}
