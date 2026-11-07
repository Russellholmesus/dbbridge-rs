use super::*;

fn public_side(peer_extra: &str, extra: &str) -> String {
    format!(
        "node: {{id: hq-b}}\nhttp: {{enabled: true, listen: \"127.0.0.1:0\"}}\nauth:\n  inbound_peers: [{{id: plant, token_envs: [DBB_TEST_TOKEN], allowed_targets: [db]}}]\ntargets: {{db: {{address: \"127.0.0.1:3306\"}}}}\npeers:\n  - id: plant\n    mode: reverse\n    expected_node_id: plant-a\n    credential_ref: plant\n    token_env: DBB_TEST_TOKEN\n{peer_extra}\nlisteners: [{{id: l, listen: \"127.0.0.1:0\", peer: plant, target: db}}]\n{extra}"
    )
}

fn db_side(reverse: &str, extra: &str) -> String {
    format!(
        "node: {{id: plant-a}}\nauth:\n  inbound_peers: [{{id: hq, token_envs: [DBB_TEST_TOKEN], allowed_targets: [db]}}]\ntargets: {{db: {{address: \"127.0.0.1:3306\"}}}}\nreverse:\n  enabled: true\n{reverse}\n{extra}"
    )
}

const DB_SIDE_BASE: &str = "  peer_node_id: hq-b\n  token_env: DBB_TEST_TOKEN\n  endpoints: [{id: primary, url: \"https://hq.example.com:8443\", priority: 1}]";

#[track_caller]
fn want_code(got: Result<Config>, code: &str, substr: &str) {
    match got {
        Ok(_) => panic!("expected {code} error containing {substr:?}, got nil"),
        Err(e) => {
            assert_eq!(e.code, code, "code mismatch (err: {})", e.message);
            assert!(
                e.message.contains(substr),
                "error {:?} does not contain {substr:?}",
                e.message
            );
        }
    }
}

#[test]
fn spec_peer_mode_defaults_to_forward() {
    let c = test_load(&test_peer_config("http://127.0.0.1:18080", "", "")).unwrap();
    assert!(!c.peers[0].reverse && !c.has_reverse_peers());
}

#[test]
fn spec_peer_mode_validation() {
    let fwd = test_peer_config("http://127.0.0.1:18080", "", "");
    test_load(&fwd.replacen(
        "expected_node_id: B",
        "expected_node_id: B\n    mode: forward",
        1,
    ))
    .unwrap();
    want_code(
        test_load(&fwd.replacen(
            "expected_node_id: B",
            "expected_node_id: B\n    mode: sideways",
            1,
        )),
        CODE_PEER_MODE,
        "invalid peers[B].mode: \"sideways\"",
    );
    want_code(
        test_load(&public_side(
            "    endpoints: [{id: e, url: \"http://127.0.0.1:18081\"}]",
            "",
        )),
        CODE_PEER_MODE,
        "cannot have endpoints",
    );
    want_code(
        test_load(&public_side("", "").replacen(
            "http: {enabled: true, listen: \"127.0.0.1:0\"}",
            "",
            1,
        )),
        CODE_PEER_MODE,
        "needs http.enabled: true",
    );
    want_code(
        test_load(&public_side("", "").replacen("mode: reverse", "mode: forward", 1)),
        CODE_CONFIG_INVALID,
        "peers[plant].endpoints cannot be empty",
    );
}

#[test]
fn spec_reverse_peer_accepted() {
    let c = test_load(&public_side("", "")).unwrap();
    let p = &c.peers[0];
    assert!(p.reverse && c.has_reverse_peers());
    assert_eq!(p.token, TEST_TOKEN);
    assert!(p.endpoints.is_empty(), "{:?}", p.endpoints);
    assert_eq!(
        crate::tunnel::REVERSE_ENDPOINT_URL,
        "http://reverse.tunnel.invalid"
    );
    assert!(
        !has_warning(&c, "ignored for a reverse peer"),
        "{:?}",
        c.warnings
    );
}

#[test]
fn spec_reverse_peer_tls_ignored_warning() {
    let c = test_load(&public_side("    tls: {verify: true}", "")).unwrap();
    assert!(
        has_warning(&c, "ignored for a reverse peer"),
        "{:?}",
        c.warnings
    );
}

#[test]
fn spec_mixed_forward_and_reverse_peers() {
    let body = format!("{}\n", public_side("", "")).replacen(
        "listeners:",
        "  - id: branch\n    expected_node_id: branch-c\n    credential_ref: branch\n    token_env: DBB_TEST_TOKEN\n    endpoints: [{id: e, url: \"http://127.0.0.1:18085\"}]\nlisteners:",
        1,
    );
    let c = test_load(&body).unwrap();
    assert!(c.peers[0].reverse && !c.peers[1].reverse);
    assert_eq!(c.peers[1].id, "branch");
}

#[cfg(feature = "tls")]
#[test]
fn spec_reverse_defaults() {
    let c = test_load(&db_side(DB_SIDE_BASE, "")).unwrap();
    let r = &c.reverse;
    assert_eq!(r.transport, Protocol::Auto);
    assert_eq!(r.tunnels_per_endpoint, 2);
    assert_eq!(r.min_backoff, Duration::from_millis(500));
    assert_eq!(r.max_backoff, Duration::from_secs(30));
    assert_eq!(r.token, TEST_TOKEN, "reverse token not resolved");
    assert_eq!(r.endpoints[0].url.scheme, "https");
    assert_eq!(r.endpoints[0].url.host, "hq.example.com");
    assert_eq!(r.endpoints[0].url.port, 8443);
    assert!(
        c.egress_role() && !c.http.enabled,
        "reverse node must have the egress role without http.enabled"
    );
    assert!(
        !has_warning(&c, "http.enabled is false"),
        "{:?}",
        c.warnings
    );
}

#[cfg(feature = "tls")]
#[test]
fn spec_reverse_explicit_values() {
    let c = test_load(&db_side(
        &format!("{DB_SIDE_BASE}\n  transport: long-poll\n  tunnels_per_endpoint: 4\n  reconnect: {{min_backoff: 2s, max_backoff: 1m}}"),
        "",
    ))
    .unwrap();
    let r = &c.reverse;
    assert_eq!(r.transport, Protocol::LongPoll);
    assert_eq!(r.tunnels_per_endpoint, 4);
    assert_eq!(r.min_backoff, Duration::from_secs(2));
    assert_eq!(r.max_backoff, Duration::from_secs(60));
}

#[cfg(feature = "tls")]
#[test]
fn spec_reverse_max_backoff_follows_min() {
    let c = test_load(&db_side(
        &format!("{DB_SIDE_BASE}\n  reconnect: {{min_backoff: 45s}}"),
        "",
    ))
    .unwrap();
    assert_eq!(c.reverse.max_backoff, Duration::from_secs(45));
}

#[test]
fn spec_reverse_validation() {
    let ep = "  endpoints: [{id: primary, url: \"https://hq.example.com:8443\", priority: 1}]";
    let base = DB_SIDE_BASE;
    let cases: Vec<(&str, String, &str, &str)> = vec![
        ("no peer node", format!("  token_env: DBB_TEST_TOKEN\n{ep}"), CODE_REVERSE, "reverse.peer_node_id is required"),
        ("peer node is self", format!("  peer_node_id: plant-a\n  token_env: DBB_TEST_TOKEN\n{ep}"), CODE_REVERSE, "must differ"),
        ("no endpoints", "  peer_node_id: hq-b\n  token_env: DBB_TEST_TOKEN".into(), CODE_REVERSE, "reverse.endpoints cannot be empty"),
        ("no token", format!("  peer_node_id: hq-b\n{ep}"), CODE_REVERSE, "reverse needs a token"),
        ("two token sources", format!("{base}\n  token_file: plant.token"), CODE_REVERSE, "ambiguous credential source"),
        ("bad transport", format!("{base}\n  transport: carrier-pigeon"), CODE_REVERSE, "invalid reverse.transport: \"carrier-pigeon\""),
        ("too many tunnels", format!("{base}\n  tunnels_per_endpoint: 17"), CODE_REVERSE, "tunnels_per_endpoint must be 1-16"),
        ("plaintext remote", "  peer_node_id: hq-b\n  token_env: DBB_TEST_TOKEN\n  endpoints: [{id: p, url: \"http://hq.example.com:8080\"}]".into(), CODE_REVERSE, "set reverse.allow_insecure_http: true"),
        ("endpoint path", "  peer_node_id: hq-b\n  token_env: DBB_TEST_TOKEN\n  endpoints: [{id: p, url: \"https://hq.example.com/x\"}]".into(), CODE_REVERSE, "reverse.endpoints[p].url must be an origin"),
        ("duplicate endpoint", "  peer_node_id: hq-b\n  token_env: DBB_TEST_TOKEN\n  endpoints: [{id: p, url: \"https://a.example.com\"}, {id: p, url: \"https://b.example.com\"}]".into(), CODE_REVERSE, "duplicate endpoint id \"p\" in reverse"),
        ("skip verify remote", format!("{base}\n  tls: {{verify: false}}"), CODE_REVERSE, "reverse.tls.verify: false for non-loopback endpoint primary"),
        ("zero min backoff", format!("{base}\n  reconnect: {{min_backoff: 0s}}"), CODE_REVERSE, "min_backoff must be > 0"),
        ("max below min", format!("{base}\n  reconnect: {{min_backoff: 5s, max_backoff: 1s}}"), CODE_REVERSE, "max_backoff (1s) must be >= min_backoff (5s)"),
        ("max too large", format!("{base}\n  reconnect: {{max_backoff: 11m}}"), CODE_REVERSE, "must be <= 10m0s"),
        ("bad duration", format!("{base}\n  reconnect: {{min_backoff: soon}}"), CODE_REVERSE, "invalid reverse.reconnect.min_backoff"),
        ("missing ca file", format!("{base}\n  tls: {{ca_file: missing-ca.pem}}"), CODE_TLS, "reverse.tls.ca_file"),
        ("missing token file", format!("  peer_node_id: hq-b\n  token_file: missing.token\n{ep}"), CODE_CREDENTIAL, "reverse credential"),
    ];
    let mut failures = Vec::new();
    for (name, reverse, code, substr) in cases {
        if cfg!(not(feature = "tls")) && reverse.contains("https://") {
            continue; // https endpoints need the tls feature
        }
        match test_load(&db_side(&reverse, "")) {
            Ok(_) => failures.push(format!("{name}: accepted")),
            Err(e) if e.code != code || !e.message.contains(substr) => failures.push(format!(
                "{name}: [{}] {:?}, want [{code}] {substr:?}",
                e.code, e.message
            )),
            Err(_) => {}
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[cfg(feature = "tls")]
#[test]
fn spec_reverse_insecure_opt_ins() {
    for reverse in [
        "  peer_node_id: hq-b\n  token_env: DBB_TEST_TOKEN\n  allow_insecure_http: true\n  endpoints: [{id: p, url: \"http://hq.example.com:8080\"}]".to_string(),
        "  peer_node_id: hq-b\n  token_env: DBB_TEST_TOKEN\n  endpoints: [{id: p, url: \"http://127.0.0.1:18080\"}]".to_string(),
        format!("{DB_SIDE_BASE}\n  tls: {{verify: false, allow_insecure_skip_verify: true}}"),
    ] {
        if let Err(e) = test_load(&db_side(&reverse, "")) {
            panic!("{reverse}: {}", e.message);
        }
    }
}

#[cfg(feature = "tls")]
#[test]
fn spec_reverse_schema() {
    want_code(
        test_load(&db_side(
            &format!("{DB_SIDE_BASE}\n  tunnels_per_endpoint: 0"),
            "",
        )),
        CODE_CONFIG_READ,
        "a positive integer",
    );
    want_code(
        test_load(&db_side(&format!("{DB_SIDE_BASE}\n  tunnels: 2"), "")),
        CODE_CONFIG_READ,
        "field \"tunnels\" not found in config.reverse",
    );
    want_code(
        test_load(&db_side(DB_SIDE_BASE, "").replacen("enabled: true", "enabled: \"yes\"", 1)),
        CODE_CONFIG_READ,
        "must be a boolean",
    );
    want_code(
        test_load(&public_side("", "").replacen("mode: reverse", "mode: 1", 1)),
        CODE_CONFIG_READ,
        "must be a string",
    );
}

#[test]
fn spec_reverse_disabled_settings_warn() {
    let body = db_side(DB_SIDE_BASE, "").replacen("enabled: true", "enabled: false", 1);
    let c = test_load(&body).unwrap();
    assert!(
        has_warning(&c, "reverse.enabled is false") && !c.egress_role(),
        "{:?}",
        c.warnings
    );
    assert!(
        c.reverse.token.is_empty(),
        "disabled reverse section resolved its token"
    );
}

#[cfg(feature = "tls")]
#[test]
fn spec_reverse_without_targets_warns() {
    let body = db_side(DB_SIDE_BASE, "")
        .replacen("targets: {db: {address: \"127.0.0.1:3306\"}}", "", 1)
        .replacen(
            "  inbound_peers: [{id: hq, token_envs: [DBB_TEST_TOKEN], allowed_targets: [db]}]",
            "  reload_interval: 5s",
            1,
        );
    let c = test_load(&body).unwrap();
    assert!(
        has_warning(&c, "no targets are configured"),
        "{:?}",
        c.warnings
    );
}

#[cfg(feature = "tls")]
#[test]
fn spec_reverse_grace_warning() {
    let short = db_side(
        &format!("{DB_SIDE_BASE}\n  reconnect: {{min_backoff: 10s}}"),
        "transport:\n  recovery: {enabled: true, grace: 12s, barrier_timeout: 3s}\n",
    );
    let c = test_load(&short).unwrap();
    assert!(
        has_warning(
            &c,
            "a tunnel that fails its first reconnect cannot come back"
        ),
        "{:?}",
        c.warnings
    );
    let c = test_load(&db_side(
        DB_SIDE_BASE,
        "transport:\n  recovery: {enabled: true, grace: 60s}\n",
    ))
    .unwrap();
    assert!(
        !has_warning(&c, "a tunnel that fails its first reconnect"),
        "{:?}",
        c.warnings
    );
}

#[cfg(feature = "tls")]
#[test]
fn spec_reverse_offline() {
    let body = db_side(
        "  peer_node_id: hq-b\n  token_file: /nonexistent/plant.token\n  endpoints: [{id: p, url: \"https://hq.example.com\"}]",
        "",
    );
    let c = load_env(&body, &[], true).unwrap();
    assert!(
        c.reverse.token.is_empty() || c.reverse.token == "offline-credential-placeholder",
        "offline validation read the reverse token"
    );
    want_code(
        load_env(
            &db_side(
                "  peer_node_id: hq-b\n  endpoints: [{id: p, url: \"https://hq.example.com\"}]",
                "",
            ),
            &[],
            true,
        ),
        CODE_REVERSE,
        "reverse needs a token",
    );
}

#[test]
fn spec_protocol_version_15_only() {
    assert_eq!(crate::wire::PROTOCOL_VERSION, "1.5");
    test_load(&test_peer_config("http://127.0.0.1:18080", "", "")).unwrap();
    want_code(
        test_load(&test_peer_config(
            "http://127.0.0.1:18080",
            "",
            "transport: {protocol_version: \"1.4\"}",
        )),
        CODE_CONFIG_INVALID,
        "protocol_version must be \"1.5\", got \"1.4\"",
    );
}

#[test]
fn spec_reverse_error_codes_distinct() {
    let codes = [
        (CODE_CONFIG_READ, "DBB-CFG-001"),
        (CODE_CONFIG_INVALID, "DBB-CFG-002"),
        (CODE_CREDENTIAL, "DBB-CFG-003"),
        (CODE_TLS, "DBB-CFG-004"),
        (CODE_LISTEN, "DBB-CFG-005"),
        (CODE_ENVIRONMENT, "DBB-CFG-006"),
        (CODE_PEER_MODE, "DBB-CFG-007"),
        (CODE_REVERSE, "DBB-CFG-008"),
        (CODE_START_FAILED, "DBB-CFG-010"),
        ("DBB-CFG-011", "DBB-CFG-011"),
        ("DBB-CFG-020", "DBB-CFG-020"),
        (CODE_SERVICE_INSTALL, "DBB-CFG-030"),
    ];
    let mut seen = std::collections::HashSet::new();
    for (code, want) in codes {
        assert_eq!(code, want);
        assert!(seen.insert(code), "duplicate code {code}");
    }
}
