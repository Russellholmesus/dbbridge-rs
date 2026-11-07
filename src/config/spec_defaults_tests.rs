use super::*;

#[test]
fn spec_dependent_defaults_follow_their_configured_neighbour() {
    let url = "http://127.0.0.1:18080";
    let cfg = test_load(&test_peer_config(
        url,
        "    failover: {healthcheck_interval: 2s}\n",
        "",
    ))
    .unwrap();
    assert_eq!(
        cfg.peers[0].failover.healthcheck_timeout,
        Duration::from_secs(1)
    );
    let cfg = test_load(&test_peer_config(
        url,
        "",
        "transport: {recovery: {grace: 4s}}\n",
    ))
    .unwrap();
    assert_eq!(
        cfg.transport.recovery_barrier_timeout,
        Duration::from_secs(2)
    );
    let cfg = test_load(&test_peer_config(
        url,
        "",
        "transport: {buffer_per_direction: 128KiB}\n",
    ))
    .unwrap();
    let tr = &cfg.transport;
    assert_eq!(
        (
            tr.up_window_bytes,
            tr.max_frame_size,
            tr.frame_size,
            tr.ack_batch_bytes
        ),
        (128 << 10, 128 << 10, 32 << 10, 32 << 10),
        "derived sizes"
    );
    let cfg = test_load(&test_peer_config(
        url,
        "",
        "transport: {global_buffer_limit: 64MiB}\n",
    ))
    .unwrap();
    assert_eq!(cfg.transport.suspended_buffer_limit, 16 << 20);
}

#[test]
fn spec_default_ack_batch_is_at_most_a_quarter_of_the_buffer() {
    for bpd in ["2MiB", "4MiB", "16MiB"] {
        let cfg = test_load(&test_peer_config(
            "http://127.0.0.1:18080",
            "",
            &format!("transport: {{buffer_per_direction: {bpd}}}\n"),
        ))
        .unwrap();
        assert!(
            cfg.transport.ack_batch_bytes * 4 <= cfg.transport.buffer_per_direction,
            "{bpd}: ack_batch_bytes {} exceeds a quarter",
            cfg.transport.ack_batch_bytes
        );
    }
}

#[test]
fn spec_constraint_errors_name_default_neighbours() {
    let e = test_load(&test_peer_config(
        "http://127.0.0.1:18080",
        "",
        "transport: {buffer_per_direction: 256KiB, max_frame_size: 512KiB}\n",
    ))
    .unwrap_err();
    assert!(
        e.message
            .contains("max_frame_size (524288) must be <= up_window_bytes (262144, default)"),
        "error does not mark the default: {}",
        e.message
    );
    let e = test_load(&test_peer_config(
        "http://127.0.0.1:18080",
        "    failover: {healthcheck_interval: 2s, healthcheck_timeout: 3s}\n",
        "",
    ))
    .unwrap_err();
    assert!(
        e.message
            .contains("healthcheck_timeout (3s) must be < healthcheck_interval (2s)"),
        "explicit healthcheck values: {}",
        e.message
    );
}

#[test]
fn spec_inbound_quota_sum_does_not_overflow() {
    let base = "node: {id: B}\ntargets: {db: {address: '127.0.0.1:3306', allowed_cidrs: ['127.0.0.1/32']}}\n";
    let two = |a: u64, b: u64| {
        format!("{base}auth:\n  inbound_peers:\n    - {{id: peer-a, token_envs: [DBB_TEST_TOKEN], allowed_targets: [db], max_sessions: {a}}}\n    - {{id: peer-b, token_envs: [DBB_TEST_TOKEN_B], allowed_targets: [db], max_sessions: {b}}}\n")
    };
    let env = [("DBB_TEST_TOKEN_B", "test-test-token-b-0123456789abcdef")];
    let max = u32::MAX as u64;
    assert!(
        load_env(&two(max, max), &env, false).is_err(),
        "quota partition with overflowing sum accepted"
    );
    load_env(&two(100, 100), &env, false).unwrap();
}

#[test]
fn spec_max_shutdown_duration() {
    let cfg = test_load(&test_peer_config(
        "http://127.0.0.1:18080",
        "",
        "transport: {shutdown_timeout: 20s}\n",
    ))
    .unwrap();
    assert_eq!(
        cfg.max_shutdown_duration(),
        Duration::from_secs(20) + SHUTDOWN_TEARDOWN_BUDGET
    );
    assert_eq!(SHUTDOWN_TEARDOWN_BUDGET, Duration::from_secs(15));
}

#[test]
fn spec_alias_expansion_is_linear() {
    let k = 6000;
    let mut b = String::from("version: 1\ninbound_peers:\n  - &p {id: x, allowed_targets: &t [");
    for i in 0..k {
        if i > 0 {
            b.push(',');
        }
        b.push_str(&format!("t{i}"));
    }
    b.push_str("]}\n");
    for _ in 0..k {
        b.push_str("  - *p\n");
    }
    let dir = scratch();
    std::fs::write(dir.join("creds.yaml"), &b).unwrap();
    std::fs::write(
        dir.join("peer.yaml"),
        "node: {id: B}\nhttp: {enabled: true, listen: '127.0.0.1:18080'}\nauth: {credentials_file: creds.yaml}\n",
    )
    .unwrap();
    let start = std::time::Instant::now();
    let _ = load_with_options(&dir.join("peer.yaml"), true);
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "alias validation took {:?}",
        start.elapsed()
    );
    std::fs::write(dir.join("a.yaml"), "node: &n {id: A}\nhttp: *n\n").unwrap();
    assert!(
        load_with_options(&dir.join("a.yaml"), true).is_err(),
        "aliased node with wrong fields accepted"
    );
    let got = yaml::parse("node: {id: &i A}\nadmin: {listen: *i}\n").unwrap();
    assert_eq!(
        got.get("admin").and_then(|a| a.str_of("listen")).as_deref(),
        Some("A"),
        "valid alias rejected"
    );
}

#[test]
fn spec_sample_configs_are_safe() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/configs");
    for name in [
        "DBB_TOKEN_TO_HQ",
        "DBB_TOKEN_FROM_PLANT_CURRENT",
        "DBB_TOKEN_FROM_PLANT_PREV",
    ] {
        std::env::set_var(name, format!("configuration-check-{name}"));
    }
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "yaml"))
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "no sample configs in {}", dir.display());
    for path in &paths {
        if cfg!(not(feature = "tls")) && std::fs::read_to_string(path).unwrap().contains("https://")
        {
            continue;
        }
        let text = std::fs::read_to_string(path).unwrap();
        let cfg = load(path).unwrap_or_else(|e| panic!("{}: {}", path.display(), e.message));
        assert!(
            !text.contains("allow_insecure_http: true"),
            "{} enables allow_insecure_http",
            path.display()
        );
        if cfg.http.enabled && !cfg.http.tls.enabled {
            assert!(
                cfg.http.listen.starts_with("127."),
                "{} listens in plaintext on {}",
                path.display(),
                cfg.http.listen
            );
        }
        for p in &cfg.peers {
            assert!(
                p.tls.verify,
                "{} disables TLS verification for {}",
                path.display(),
                p.id
            );
        }
    }
    assert!(
        !dir.join("token.secret").exists(),
        "configs/token.secret is still present"
    );
}

#[test]
fn spec_main_config_limit_before_allocation() {
    let path = scratch().join("oversized-config.yaml");
    let f = std::fs::File::create(&path).unwrap();
    f.set_len(16 << 20).unwrap();
    drop(f);
    let e = load(&path).unwrap_err();
    assert!(
        e.message.contains("too large") || e.message.contains("exceeds maximum size"),
        "{}",
        e.message
    );
}

#[test]
fn spec_reject_null_and_wrong_scalar_types() {
    let mut accepted = Vec::new();
    for body in [
        "node: {id: A}\ntransport: {recovery: {enabled: null}}\n",
        "node: {id: A}\nhttp: {allowed_transports: null}\n",
        "node: {id: 123}\n",
        "node: {id: A}\nauth: {reload_interval: -1s}\n",
        "node: {id: true}\n",
        "node: {id: A}\nhttp: {enabled: 'true'}\n",
        "node: {id: A}\nhttp: []\n",
        "node: {id: A}\npeers: {}\n",
        "node: {id: A}\ntargets: {db: null}\n",
        "node: {id: A}\ntransport: {frame_size: true}\n",
        "node: {id: A}\ntransport: {heartbeat: false}\n",
        "node: {id: A}\ntransport: {ws: null}\n",
    ] {
        let path = scratch().join("config.yaml");
        std::fs::write(&path, body).unwrap();
        if load(&path).is_ok() {
            accepted.push(body);
        }
    }
    assert!(
        accepted.is_empty(),
        "invalid schema accepted: {accepted:#?}"
    );
}
