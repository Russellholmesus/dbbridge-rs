use super::*;
use crate::config::Config;
use std::collections::BTreeMap;
use std::time::Instant;

#[test]
fn a_closed_session_never_wraps_the_gauge() {
    let m = Metrics::new();
    m.session_closed();
    assert_eq!(m.sessions_active.load(Ordering::Relaxed), 0);
    m.session_opened();
    m.session_opened();
    m.session_closed();
    assert_eq!(m.sessions_active.load(Ordering::Relaxed), 1);
    assert_eq!(m.sessions_created.load(Ordering::Relaxed), 2);
}

#[test]
fn frames_and_bytes_are_counted_separately() {
    let m = Metrics::new();
    m.upstream(100);
    m.upstream(24);
    m.downstream(7);
    assert_eq!(m.upstream_frames.load(Ordering::Relaxed), 2);
    assert_eq!(m.upstream_bytes.load(Ordering::Relaxed), 124);
    assert_eq!(m.downstream_frames.load(Ordering::Relaxed), 1);
    assert_eq!(m.downstream_bytes.load(Ordering::Relaxed), 7);
}

#[test]
fn reverse_client_metrics_track_live_tunnel_lifecycle() {
    let m = Metrics::new();
    let mut cfg = test_config();
    cfg.reverse.enabled = true;
    cfg.reverse.endpoints.push(crate::config::Endpoint {
        id: "public".into(),
        url: crate::net::Url::parse("http://127.0.0.1:18081").unwrap(),
        priority: 1,
    });
    m.reverse_tunnel_opened("public", "ws");
    m.reverse_tunnel_dial_failed();
    let live = m.render(&cfg, Instant::now(), true);
    assert!(live.contains("dbb_reverse_tunnels{endpoint=\"public\",transport=\"ws\"} 1\n"));
    assert!(live.contains("dbb_reverse_tunnel_established_total 1\n"));
    assert!(live.contains("dbb_reverse_tunnel_dial_failures_total 1\n"));

    m.reverse_tunnel_closed("public", "ws", true);
    let closed = m.render(&cfg, Instant::now(), true);
    assert!(closed.contains("dbb_reverse_tunnels{endpoint=\"public\",transport=\"ws\"} 0\n"));
    assert!(closed.contains("dbb_reverse_tunnel_lost_total 1\n"));
}

#[test]
fn protocol_event_counters_render_the_recorded_values() {
    let m = Metrics::new();
    m.post_received();
    m.post_received();
    m.piggyback_acknowledged();
    m.explicit_ack_received();
    m.upstream_fin_applied();
    m.downstream_fin_acked();

    let rendered = m.render(&test_config(), Instant::now(), true);
    for metric in [
        "dbb_post_count_total 2\n",
        "dbb_piggyback_ack_total 1\n",
        "dbb_explicit_ack_total 1\n",
        "dbb_up_fin_applied_total 1\n",
        "dbb_down_fin_acked_total 1\n",
    ] {
        assert!(rendered.contains(metric), "missing metric {metric}");
    }
}

#[test]
fn auth_reload_metrics_track_rejection_recovery_and_changed_installs() {
    let m = Metrics::new();
    m.auth_reload_failed();
    assert_eq!(m.auth_credentials_stale.load(Ordering::Relaxed), 1);
    assert_eq!(m.auth_reload_failed.load(Ordering::Relaxed), 1);
    m.auth_reload_succeeded(false);
    assert_eq!(m.auth_credentials_stale.load(Ordering::Relaxed), 0);
    assert!(m.auth_reload_last_success_unix.load(Ordering::Relaxed) > 0);
    assert_eq!(m.auth_reload_success.load(Ordering::Relaxed), 0);
    m.auth_reload_succeeded(true);
    assert_eq!(m.auth_reload_success.load(Ordering::Relaxed), 1);
    let rendered = m.render(&test_config(), Instant::now(), true);
    for metric in [
        "dbb_auth_credentials_stale 0",
        "dbb_auth_reload_success_total 1",
        "dbb_auth_reload_failed_total 1",
        "dbb_auth_reload_last_success_timestamp_seconds ",
    ] {
        assert!(rendered.contains(metric), "missing metric {metric}");
    }
}

#[test]
fn documentation_metric_contract_has_help_type_and_stable_order() {
    let mut cfg = ingress_config("peer\\\"\nA", "endpoint\\\"\n1");
    cfg.peers.push(crate::config::Peer {
        id: "reverse-peer".into(),
        expected_node_id: "reverse-db".into(),
        token: String::new(),
        endpoints: Vec::new(),
        failover: crate::config::Failover::default(),
        protocol: crate::config::Protocol::Auto,
        recovery_enabled: None,
        reverse: true,
        tls: crate::config::ClientTls::default(),
    });
    cfg.reverse.enabled = true;
    cfg.reverse.endpoints.push(crate::config::Endpoint {
        id: "reverse-endpoint".into(),
        url: crate::net::Url::parse("http://127.0.0.1:18081").unwrap(),
        priority: 1,
    });

    let m = Metrics::new();
    // A running node always has cfg.Resources (node.NewNode), so the
    // resource families are always rendered.
    m.configure_resources(&cfg);
    m.ingress_connection_opened();
    m.carrier_sessions.lock().unwrap().insert("ws".into(), 1);
    m.set_endpoint_state("peer\\\"\nA", "endpoint\\\"\n1", "HEALTHY");
    m.record_session_event("ingress", "attach", "success", "none", "ws");
    m.record_ingress_fault("data", "network");
    m.observe_operation("ingress", "attach", Duration::from_millis(20));
    m.observe_phase(
        "peer\\\"\nA",
        "endpoint\\\"\n1",
        "attach",
        true,
        Duration::from_millis(20),
    );
    m.reverse_hub_rejected
        .lock()
        .unwrap()
        .insert("DBB_UNAUTHORIZED".into(), 1);
    m.reverse_tunnel_fallback("ws", "http-sse");

    let started = Instant::now();
    let first = m.render(&cfg, started, true);
    let second = m.render(&cfg, started, true);
    assert_eq!(first, second, "metric output order must be stable");

    let expected: &[(&str, &str, &str)] = &[
        ("dbb_session_events_total", "counter", "Session lifecycle events by role, event, reason and carrier transition"),
        ("dbb_ingress_faults_total", "counter", "Carrier faults detected by the ingress, by source and reason"),
        ("dbb_operation_duration_seconds", "histogram", "Duration of session operations by role and phase"),
        ("dbb_recovery_retained_bytes", "gauge", "Bytes retained for session recovery"),
        ("dbb_recovery_retained_limit", "gauge", "Limit on bytes retained for session recovery"),
        ("dbb_resource_in_use", "gauge", "Resource budget units in use"),
        ("dbb_resource_limit", "gauge", "Resource budget limit"),
        ("dbb_resource_wait_seconds", "summary", "Time spent waiting for resource budgets"),
        ("dbb_egress_carrier_sessions", "gauge", "Egress sessions by carrier transport"),
        ("dbb_reverse_hub_tunnels", "gauge", "Live reverse tunnels accepted from each reverse peer, by transport"),
        ("dbb_reverse_hub_accepted_total", "counter", "Reverse tunnels accepted and registered"),
        ("dbb_reverse_hub_rejected_total", "counter", "Reverse tunnel handshakes refused, by DBBridge error code"),
        ("dbb_reverse_tunnels", "gauge", "Live reverse tunnels dialed by this node, by endpoint and transport"),
        ("dbb_reverse_tunnel_established_total", "counter", "Reverse tunnels established"),
        ("dbb_reverse_tunnel_lost_total", "counter", "Established reverse tunnels that ended while the node was running"),
        ("dbb_reverse_tunnel_dial_failures_total", "counter", "Failed reverse tunnel dials (after any transport fallback)"),
        ("dbb_reverse_tunnel_fallback_total", "counter", "Transport fallbacks of reverse.transport auto"),
        ("dbb_endpoint_state", "gauge", "Endpoint health state (1 for the current state)"),
        ("dbb_phase_duration_seconds", "summary", "Duration of ingress phases per endpoint"),
        ("dbb_ingress_bound_sessions", "gauge", "Ingress sessions by bound endpoint and carrier"),
        ("dbb_ingress_recovering_sessions", "gauge", "Ingress sessions inside a recovery window without an active carrier"),
        ("dbb_ingress_up_pending_bytes", "gauge", "Upstream bytes sent but not yet acknowledged"),
        ("dbb_ingress_retained_frames", "gauge", "Upstream frames retained for replay"),
        ("dbb_ingress_accept_rejected_total", "counter", "Ingress accept_rejected_total"),
        ("dbb_ingress_codec_bytes", "gauge", "Ingress codec_bytes"),
        ("dbb_ingress_connections", "gauge", "Ingress connections"),
        ("dbb_ingress_payload_bytes", "gauge", "Ingress payload_bytes"),
        ("dbb_active_sessions", "gauge", "Number of currently active sessions"),
        ("dbb_suspended_sessions", "gauge", "Number of currently suspended sessions"),
        ("dbb_unbalanced_release_total", "counter", "Budget releases that exceeded the held amount (accounting bug indicator)"),
        ("dbb_up_bytes_total", "counter", "Total bytes sent upstream"),
        ("dbb_down_bytes_total", "counter", "Total bytes received downstream"),
        ("dbb_post_count_total", "counter", "Total HTTP POST requests"),
        ("dbb_piggyback_ack_total", "counter", "Total piggyback ACK counts"),
        ("dbb_explicit_ack_total", "counter", "Total explicit /ack counts"),
        ("dbb_resume_success_total", "counter", "Total successful resumes"),
        ("dbb_resume_failed_total", "counter", "Total failed resumes"),
        ("dbb_buffer_memory_bytes", "gauge", "Total buffered memory bytes in use"),
        ("dbb_suspended_mem_bytes", "gauge", "Memory bytes occupied by suspended sessions"),
        ("dbb_terminated_direct_total", "counter", "Total sessions terminated directly on failure without resume"),
        ("dbb_terminated_after_resume_fail_total", "counter", "Total sessions terminated after recovery failed"),
        ("dbb_remote_cleanup_failed_total", "counter", "Total remote cleanup delete attempts failed"),
        ("dbb_remote_cleanup_unknown_total", "counter", "Total remote cleanup delete attempts with unknown/stale epoch"),
        ("dbb_client_close_duration_sum_ms", "counter", "Total client close duration in milliseconds"),
        ("dbb_client_close_count_total", "counter", "Total client connections actively closed"),
        ("dbb_dial_total", "counter", "Backend dial attempts made by the egress role"),
        ("dbb_dial_failed_total", "counter", "Backend dial attempts that failed"),
        ("dbb_auth_reload_success_total", "counter", "Credential reloads that installed a changed snapshot"),
        ("dbb_auth_reload_failed_total", "counter", "Credential load or reload attempts that were rejected"),
        ("dbb_up_fin_applied_total", "counter", "Upstream FIN frames applied to the backend connection"),
        ("dbb_down_fin_acked_total", "counter", "Downstream FIN frames acknowledged by the peer"),
        ("dbb_backpressure_total", "counter", "Times a session waited for buffer space"),
        ("dbb_admission_rejected_total", "counter", "Connections and requests rejected by admission control"),
        ("dbb_auth_credentials_stale", "gauge", "1 while the last credential reload was rejected and the previous credentials are still in effect"),
        ("dbb_auth_reload_last_success_timestamp_seconds", "gauge", "Unix time of the last accepted credential load"),
    ];
    let families: Vec<&str> = first
        .lines()
        .filter_map(|line| line.strip_prefix("# TYPE "))
        .map(|rest| rest.split(' ').next().unwrap())
        .collect();
    let expected_families: Vec<&str> = expected.iter().map(|(name, _, _)| *name).collect();
    assert_eq!(
        families, expected_families,
        "family set or order differs from the reference"
    );
    for (name, kind, help) in expected {
        let header = format!("# HELP {name} {help}\n# TYPE {name} {kind}\n");
        assert_eq!(
            first.matches(&header).count(),
            1,
            "missing, duplicate or non-reference HELP/TYPE for {name}"
        );
    }
    // Every sample line belongs to the family declared right above it.
    let mut current = "";
    for line in first.lines() {
        if let Some(rest) = line.strip_prefix("# TYPE ") {
            current = rest.split(' ').next().unwrap();
        } else if !line.starts_with('#') {
            assert!(
                line.starts_with(current),
                "sample outside its family: {line}"
            );
        }
    }

    let label_contract = BTreeMap::from([
        ("dbb_egress_carrier_sessions", vec!["transport"]),
        (
            "dbb_session_events_total",
            vec!["role", "event", "reason", "from", "to"],
        ),
        ("dbb_ingress_faults_total", vec!["source", "reason"]),
        (
            "dbb_operation_duration_seconds_bucket",
            vec!["role", "phase", "le"],
        ),
        (
            "dbb_operation_duration_seconds_count",
            vec!["role", "phase"],
        ),
        ("dbb_operation_duration_seconds_sum", vec!["role", "phase"]),
        ("dbb_endpoint_state", vec!["peer", "endpoint", "state"]),
        (
            "dbb_phase_duration_seconds_sum",
            vec!["peer", "endpoint", "phase", "success"],
        ),
        (
            "dbb_phase_duration_seconds_count",
            vec!["peer", "endpoint", "phase", "success"],
        ),
        ("dbb_resource_in_use", vec!["resource"]),
        ("dbb_resource_limit", vec!["resource"]),
        ("dbb_resource_wait_seconds_count", vec!["resource"]),
        ("dbb_resource_wait_seconds_sum", vec!["resource"]),
        ("dbb_reverse_hub_tunnels", vec!["peer", "transport"]),
        ("dbb_reverse_hub_rejected_total", vec!["code"]),
        ("dbb_reverse_tunnels", vec!["endpoint", "transport"]),
        ("dbb_reverse_tunnel_fallback_total", vec!["from", "to"]),
    ]);
    for (name, expected_keys) in label_contract {
        let mut found = false;
        for line in first
            .lines()
            .filter(|line| line.starts_with(&format!("{name}{{")))
        {
            found = true;
            let labels = line.split_once('{').unwrap().1.split_once('}').unwrap().0;
            let keys = labels
                .split(',')
                .map(|pair| pair.split_once('=').unwrap().0)
                .collect::<Vec<_>>();
            assert_eq!(keys, expected_keys, "wrong label keys for {name}: {line}");
        }
        assert!(found, "no sample emitted to check labels for {name}");
    }
    assert!(first.contains(
        "dbb_operation_duration_seconds_bucket{role=\"ingress\",phase=\"attach\",le=\"0.001\"}"
    ));
    assert!(first.contains(
        "dbb_operation_duration_seconds_bucket{role=\"ingress\",phase=\"attach\",le=\"+Inf\"}"
    ));
    let mut budgets: Vec<&str> = super::RESOURCES.to_vec();
    budgets.sort_unstable();
    assert_eq!(budgets.len(), 16);
    for family in ["dbb_resource_in_use", "dbb_resource_limit"] {
        let rendered: Vec<&str> = first
            .lines()
            .filter_map(|line| line.strip_prefix(&format!("{family}{{resource=\"")))
            .map(|rest| rest.split('"').next().unwrap())
            .collect();
        assert_eq!(rendered, budgets, "{family} series");
    }
    for family in [
        "dbb_buffer_memory_bytes 0\n",
        "dbb_suspended_mem_bytes 0\n",
        "dbb_recovery_retained_bytes 0\n",
        "dbb_ingress_connections 1\n",
        "dbb_egress_carrier_sessions{transport=\"ws\"} 1\n",
        "dbb_egress_carrier_sessions{transport=\"http-sse\"} 0\n",
    ] {
        assert!(first.contains(family), "missing sample {family}");
    }
    assert!(!first.contains("dbb_egress_state_"));
    assert!(!first.contains("dbb_node_info"));
    assert!(!first.contains("dbb_uptime_seconds"));
    assert!(!first.contains("dbb_ready"));
    assert!(first.contains("state=\"HEALTHY\"} 1\n"));
    assert!(first.contains(
        "dbb_endpoint_state{peer=\"reverse-peer\",endpoint=\"tunnel\",state=\"UNKNOWN\"} 1\n"
    ));
    assert!(!first.contains("dbb_sessions_active"));
    assert!(!first.contains("dbb_upstream_bytes_total"));
}

#[test]
fn connections_metric_is_written_only_while_a_connection_is_open() {
    let cfg = ingress_config("peer", "endpoint");
    let m = Metrics::new();
    m.configure_resources(&cfg);
    let idle = m.render(&cfg, Instant::now(), true);
    assert!(!idle.contains("dbb_ingress_connections"));
    for always in [
        "dbb_ingress_accept_rejected_total 0\n",
        "dbb_ingress_codec_bytes 0\n",
        "dbb_ingress_payload_bytes 0\n",
    ] {
        assert!(idle.contains(always), "missing {always}");
    }
    assert!(!idle.contains("dbb_egress_state_"));

    m.ingress_connection_opened();
    let open = m.render(&cfg, Instant::now(), true);
    assert!(open.contains(
        "# HELP dbb_ingress_connections Ingress connections\n# TYPE dbb_ingress_connections gauge\ndbb_ingress_connections 1\n"
    ));
    // Sorted snapshot keys: codec_bytes < connections < payload_bytes.
    let codec = open.find("dbb_ingress_codec_bytes 0").unwrap();
    let connections = open.find("dbb_ingress_connections 1").unwrap();
    let payload = open.find("dbb_ingress_payload_bytes 0").unwrap();
    assert!(codec < connections && connections < payload);

    m.ingress_connection_closed();
    m.ingress_connection_closed();
    assert_eq!(m.ingress_connections.load(Ordering::Relaxed), 0);
    assert!(!m
        .render(&cfg, Instant::now(), true)
        .contains("dbb_ingress_connections"));

    // An egress-only node has no ingress manager and no ingress families.
    let egress_only = test_config();
    assert!(!egress_only.ingress_role());
    m.ingress_connection_opened();
    let egress_render = m.render(&egress_only, Instant::now(), true);
    for absent in [
        "dbb_ingress_connections",
        "dbb_ingress_payload_bytes",
        "dbb_ingress_bound_sessions",
        "dbb_endpoint_state",
    ] {
        assert!(
            !egress_render.contains(absent),
            "{absent} on an egress-only node"
        );
    }
}

#[test]
fn resource_budget_metrics_follow_real_create_and_metadata_lease_lifetimes() {
    let cfg = test_config();
    let metrics = std::sync::Arc::new(Metrics::new());
    metrics.configure_resources(&cfg);
    let registry = std::sync::Arc::new(crate::egress::Registry::new_with_resource_limits(
        metrics.clone(),
        cfg.transport.idempotency_tombstone_ttl,
        cfg.transport.suspended_buffer_limit,
        cfg.transport.global_buffer_limit,
        cfg.transport.backpressure_timeout,
    ));
    metrics.set_egress_registry(std::sync::Arc::downgrade(&registry));
    let resources = metrics.resource_manager().unwrap();

    assert!(matches!(
        registry.reserve_create("key", "peer", "params".into(), 0, cfg.limits.max_sessions),
        crate::egress::CreateLookup::Reserved
    ));
    assert_eq!(resources.creates.used(), 1);
    assert_eq!(resources.sessions.used(), 1);
    assert_eq!(
        resources.metadata.used(),
        resources.session_metadata_cost() + (2 << 10)
    );
    let pending = metrics.render(&cfg, Instant::now(), true);
    assert!(pending.contains("dbb_resource_in_use{resource=\"payload\"} 0\n"));
    assert!(pending.contains("dbb_resource_in_use{resource=\"creates\"} 1\n"));
    assert!(pending.contains("dbb_resource_in_use{resource=\"sessions\"} 1\n"));
    assert!(pending.contains("dbb_resource_in_use{resource=\"codec\"} 0\n"));
    for name in super::RESOURCES {
        let limit = resources.budget(name).unwrap().limit();
        assert!(
            pending.contains(&format!(
                "dbb_resource_limit{{resource=\"{name}\"}} {limit}\n"
            )),
            "missing dbb_resource_limit for {name}"
        );
    }

    registry.fail_create("key", 503, "{}".into());
    assert_eq!(resources.creates.used(), 0);
    assert_eq!(resources.sessions.used(), 0);
    assert_eq!(resources.metadata.used(), 2 << 10);
    let failed = metrics.render(&cfg, Instant::now(), true);
    assert!(failed.contains("dbb_resource_in_use{resource=\"creates\"} 0\n"));
    assert!(failed.contains("dbb_resource_in_use{resource=\"metadata\"} 2048\n"));
}

/// A node with the ingress role: one listener and one forward peer.
fn ingress_config(peer: &str, endpoint: &str) -> Config {
    let mut cfg = test_config();
    cfg.listeners.push(crate::config::Listener {
        id: "local".into(),
        listen: "127.0.0.1:0".into(),
        peer: peer.into(),
        target: "db".into(),
    });
    cfg.peers.push(crate::config::Peer {
        id: peer.into(),
        expected_node_id: "remote".into(),
        token: String::new(),
        endpoints: vec![crate::config::Endpoint {
            id: endpoint.into(),
            url: crate::net::Url::parse("http://127.0.0.1:18080").unwrap(),
            priority: 1,
        }],
        failover: crate::config::Failover::default(),
        protocol: crate::config::Protocol::Auto,
        recovery_enabled: None,
        reverse: false,
        tls: crate::config::ClientTls::default(),
    });
    assert!(cfg.ingress_role());
    cfg
}

fn test_config() -> Config {
    let path = std::env::temp_dir().join(format!(
        "dbb-metrics-{}.yaml",
        crate::util::random_hex(4).unwrap()
    ));
    std::fs::write(
        &path,
        "node:\n  id: test\ntargets:\n  db:\n    network: tcp\n    address: 127.0.0.1:3306\n",
    )
    .unwrap();
    let cfg = crate::config::load(&path).unwrap();
    std::fs::remove_file(path).ok();
    cfg
}
