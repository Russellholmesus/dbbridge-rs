use super::*;

fn probe_ok() -> Health {
    Health {
        instance_id: "i".into(),
        transports: vec![Mode::Ws, Mode::HttpSse],
        accepting_new_sessions: true,
        probed_at: Instant::now(),
        cooldown_until: None,
        failures: 0,
        probe_failures: 0,
        successes: 0,
        state: "UNKNOWN",
    }
}

fn expire_cooldown(t: &EndpointTable) {
    let past = Instant::now()
        .checked_sub(Duration::from_millis(1))
        .unwrap();
    for h in t.inner.lock().unwrap().values_mut() {
        h.cooldown_until = Some(past);
    }
}

#[test]
fn spec_threshold_consistent_when_unset() {
    let t = EndpointTable::default();
    let state = t.record_probe_failure("B", "e1", Duration::from_secs(60), 0, false);
    assert_eq!(state, "UNHEALTHY");
    assert!(
        t.in_cooldown("B", "e1"),
        "one failure with threshold<=0 must cool down"
    );
    assert_eq!(t.get("B", "e1").unwrap().failures, 1);
}

#[test]
fn spec_success_does_not_clear_cooldown() {
    let t = EndpointTable::default();
    t.record_probe_failure("B", "e1", Duration::from_secs(3600), 1, false);
    assert!(
        t.in_cooldown("B", "e1"),
        "fixture: endpoint should be cooling down"
    );
    t.put("B", "e1", probe_ok(), 2);
    assert_eq!(t.put("B", "e1", probe_ok(), 2), "HEALTHY");
    assert!(
        t.in_cooldown("B", "e1"),
        "successes cleared an unexpired failure cooldown"
    );
    let ep = crate::config::Endpoint {
        id: "e1".into(),
        url: crate::net::Url::parse("http://127.0.0.1:1").unwrap(),
        priority: 1,
    };
    assert!(
        t.cooldown_end("B", std::slice::from_ref(&ep)).is_some(),
        "the running cooldown must be reported"
    );
    expire_cooldown(&t);
    assert!(
        !t.in_cooldown("B", "e1"),
        "endpoint not available after its cooldown expired"
    );
    assert!(t.cooldown_end("B", &[ep]).is_none());
}

#[test]
fn spec_path_failure_cools_address() {
    let t = EndpointTable::default();
    let started = Instant::now();
    t.penalize("B", "e1", Duration::from_secs(5));
    assert!(
        t.in_cooldown("B", "e1"),
        "a whole-path failure must cool the address down"
    );
    assert_ne!(t.get("B", "e1").unwrap().state, "UNHEALTHY");
    t.put("B", "e1", probe_ok(), 1);
    assert!(
        t.in_cooldown("B", "e1"),
        "a success cleared the path cooldown"
    );
    let until = t.get("B", "e1").unwrap().cooldown_until.unwrap();
    assert!(
        until.duration_since(started) >= Duration::from_secs(4),
        "address cooldown too short"
    );
}

#[test]
fn spec_failure_cooldown_must_not_be_bypassed() {
    // first_transport_drop
    let t = EndpointTable::default();
    t.record_transport_failure("B", "e", Mode::Ws, Duration::from_secs(5));
    assert!(
        !t.transport_available("B", "e", Mode::Ws, Instant::now()),
        "failed WS carrier remains immediately eligible after its first drop"
    );
    // success_cannot_clear_cooldown
    let t = EndpointTable::default();
    t.record_probe_failure("B", "e", Duration::from_secs(5), 1, false);
    let mut p = probe_ok();
    p.instance_id = "bi".into();
    t.put("B", "e", p.clone(), 2);
    t.put("B", "e", p, 2);
    assert!(
        t.in_cooldown("B", "e"),
        "two immediate probes cleared the 5s endpoint cooldown"
    );
}

#[test]
fn spec_transport_drop_cooldown() {
    let t = EndpointTable::default();
    let minute = Duration::from_secs(60);
    t.record_transport_failure("B", "e1", Mode::HttpSse, minute);
    let now = Instant::now();
    assert!(
        !t.transport_available("B", "e1", Mode::HttpSse, now),
        "the first SSE carrier drop must start the SSE cooldown"
    );
    assert!(
        t.transport_available("B", "e1", Mode::Ws, now) && !t.in_cooldown("B", "e1"),
        "a single-carrier drop must cool only that (endpoint, transport) pair"
    );
    assert!(
        t.next_eligible("B", "e1", &[Mode::Ws, Mode::HttpSse], now)
            .is_none(),
        "WS is still eligible, so the endpoint has an eligible carrier"
    );
    assert!(
        t.next_eligible("B", "e1", &[Mode::HttpSse], now).is_some(),
        "SSE-only selection must see the SSE cooldown"
    );
    t.record_transport_failure("B", "e1", Mode::Ws, minute);
    assert!(
        !t.transport_available("B", "e1", Mode::Ws, Instant::now()),
        "a transport failure must cool the carrier down immediately"
    );
    assert!(
        t.transport_available(
            "B",
            "e1",
            Mode::HttpSse,
            now + minute + Duration::from_secs(1)
        ),
        "the carrier cooldown must expire"
    );
}
