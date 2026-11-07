use super::scalars::*;
use super::*;

#[test]
fn parses_durations() {
    assert_eq!(parse_duration("15s").unwrap(), Duration::from_secs(15));
    assert_eq!(parse_duration("200ms").unwrap(), Duration::from_millis(200));
    assert_eq!(parse_duration("1m").unwrap(), Duration::from_secs(60));
    assert!(parse_duration("15x").is_err());
}

#[test]
fn parses_sizes() {
    assert_eq!(parse_size("32KiB").unwrap(), 32 * 1024);
    assert_eq!(parse_size("1MiB").unwrap(), 1024 * 1024);
    assert_eq!(parse_size("1024").unwrap(), 1024);
    assert_eq!(parse_size("1MB").unwrap(), 1024 * 1024);
}

#[test]
fn cidr_matching() {
    assert!(cidr_contains("127.0.0.1/32", "127.0.0.1".parse().unwrap()));
    assert!(!cidr_contains("127.0.0.1/32", "127.0.0.2".parse().unwrap()));
    assert!(cidr_contains("10.0.0.0/8", "10.9.8.7".parse().unwrap()));
    assert!(!cidr_contains("10.0.0.0/8", "11.0.0.1".parse().unwrap()));
}

#[test]
fn parses_hostports() {
    assert_eq!(
        parse_hostport("127.0.0.1:3306").unwrap(),
        ("127.0.0.1".to_string(), 3306)
    );
    assert_eq!(parse_hostport(":8080").unwrap(), ("".to_string(), 8080));
    assert_eq!(parse_hostport("[::1]:80").unwrap(), ("::1".to_string(), 80));
    assert!(parse_hostport("nope").is_err());
}

/// Writes `text` to a scratch file and loads it as a configuration.
fn load_text(text: &str) -> Result<Config> {
    let dir = std::env::temp_dir().join(format!("dbbcfg-{}", crate::util::random_hex(6).unwrap()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("inbound-token"), "abc").unwrap();
    let path = dir.join("cfg.yaml");
    std::fs::write(&path, text).unwrap();
    load(&path)
}

fn load_text_with_files(text: &str, files: &[(&str, &str)]) -> Result<Config> {
    let dir = std::env::temp_dir().join(format!("dbbcfg-{}", crate::util::random_hex(6).unwrap()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("inbound-token"), "abc").unwrap();
    for (name, contents) in files {
        std::fs::write(dir.join(name), contents).unwrap();
    }
    let path = dir.join("cfg.yaml");
    std::fs::write(&path, text).unwrap();
    load(&path)
}

#[cfg(feature = "tls")]
fn tls_fixture() -> [(&'static str, &'static str); 2] {
    [
        (
            "cert.pem",
            include_str!("../net/testdata/localhost-cert.pem"),
        ),
        ("key.pem", include_str!("../net/testdata/localhost-key.pem")),
    ]
}

const MINIMAL: &str = "\
node:
  id: peer-b

http:
  enabled: true
  listen: \"127.0.0.1:18080\"

targets:
  db:
    network: tcp
    address: \"127.0.0.1:3306\"

auth:
  inbound_peers:
    - id: peer-a
      token_files: [inbound-token]
      allowed_targets: [db]
";

#[test]
fn boundary_config_strict_scalar_types_are_rejected() {
    let fractional = format!("{}transport:\n  frame_size: 1024.9\n", MINIMAL);
    let error = load_text(&fractional).unwrap_err();
    assert!(error.message.contains("frame_size"), "{error}");

    let string_boolean = MINIMAL.replace(
        "auth:\n",
        "transport:\n  recovery:\n    enabled: \"false\"\nauth:\n",
    );
    let error = load_text(&string_boolean).unwrap_err();
    assert_eq!(error.code, CODE_CONFIG_READ);
    assert!(
        error
            .message
            .contains("config.transport.recovery.enabled must be a boolean"),
        "{error}"
    );
}

#[test]
fn non_boolean_bool_keys_are_rejected_like_spec_schema() {
    let cases: &[(&str, &str, &str)] = &[
        (
            "      allowed_targets: [db]\n",
            "      allowed_targets: [db]\n      enabled: \"false\"\n",
            "config.auth.inbound_peers[0].enabled must be a boolean",
        ),
        (
            "      allowed_targets: [db]\n",
            "      allowed_targets: [db]\n      enabled: 0\n",
            "config.auth.inbound_peers[0].enabled must be a boolean",
        ),
        (
            "  enabled: true\n",
            "  enabled: \"true\"\n",
            "config.http.enabled must be a boolean",
        ),
        (
            "  listen: \"127.0.0.1:18080\"\n",
            "  listen: \"127.0.0.1:18080\"\n  allow_insecure_listen: \"no\"\n",
            "config.http.allow_insecure_listen must be a boolean",
        ),
        (
            "auth:\n",
            "admin:\n  enabled: yes\nauth:\n",
            "config.admin.enabled must be a boolean",
        ),
        (
            "auth:\n",
            "admin:\n  allow_remote: \"false\"\nauth:\n",
            "config.admin.allow_remote must be a boolean",
        ),
        (
            "auth:\n",
            "reverse:\n  enabled: \"false\"\nauth:\n",
            "config.reverse.enabled must be a boolean",
        ),
        (
            "auth:\n",
            "peers:\n  - id: up\n    allow_insecure_http: \"true\"\nauth:\n",
            "config.peers[0].allow_insecure_http must be a boolean",
        ),
        (
            "auth:\n",
            "peers:\n  - id: up\n    tls:\n      verify: \"false\"\nauth:\n",
            "config.peers[0].tls.verify must be a boolean",
        ),
        (
            "auth:\n",
            "peers:\n  - id: up\n    tls:\n      allow_insecure_skip_verify: 1\nauth:\n",
            "config.peers[0].tls.allow_insecure_skip_verify must be a boolean",
        ),
        (
            "auth:\n",
            "peers:\n  - id: up\n    failover:\n      enabled: \"true\"\nauth:\n",
            "config.peers[0].failover.enabled must be a boolean",
        ),
        (
            "auth:\n",
            "peers:\n  - id: up\n    recovery:\n      enabled: \"true\"\nauth:\n",
            "config.peers[0].recovery.enabled must be a boolean",
        ),
    ];
    for (from, to, want) in cases {
        let text = MINIMAL.replacen(from, to, 1);
        assert_ne!(text, MINIMAL, "case did not apply: {want}");
        let error = load_text(&text).unwrap_err();
        assert_eq!(error.code, CODE_CONFIG_READ, "{want}: {error}");
        assert!(error.message.contains(want), "{want}: {error}");
    }
    // A target may legitimately be called `enabled`: map keys are names.
    let named = MINIMAL
        .replace("targets:\n  db:", "targets:\n  enabled:")
        .replace("allowed_targets: [db]", "allowed_targets: [enabled]");
    load_text(&named).unwrap();
    // Real booleans keep working, and `enabled: false` disables the peer.
    let disabled = MINIMAL.replace(
        "      allowed_targets: [db]\n",
        "      allowed_targets: [db]\n      enabled: false\n",
    );
    let cfg = load_text(&disabled).unwrap();
    assert!(!cfg.inbound.iter().any(|peer| peer.enabled));
}

#[test]
fn credentials_file_non_boolean_enabled_is_rejected() {
    let text = "node:\n  id: peer-b\nhttp:\n  enabled: true\n  listen: \"127.0.0.1:18080\"\ntargets:\n  db:\n    network: tcp\n    address: \"127.0.0.1:3306\"\nauth:\n  credentials_file: creds.yaml\n";
    let creds = "version: 1\ninbound_peers:\n  - id: peer-a\n    enabled: \"false\"\n    token_files: [inbound-token]\n    allowed_targets: [db]\n";
    let error = load_text_with_files(text, &[("creds.yaml", creds)]).unwrap_err();
    assert!(
        error
            .message
            .contains("config.inbound_peers[0].enabled must be a boolean"),
        "{error}"
    );
}

#[test]
fn boundary_unknown_config_fields_are_rejected() {
    let cases = [
        ("transport:\n  resume_enabled: true\n", "resume_enabled"),
        ("transport:\n  resume_grace: 30s\n", "resume_grace"),
        (
            "transport:\n  resume_barrier_timeout: 5s\n",
            "resume_barrier_timeout",
        ),
        ("peers:\n  - id: B\n    url: https://b.invalid\n", "url"),
        (
            "peers:\n  - id: B\n    failover:\n      mode: priority\n",
            "mode",
        ),
        (
            "listeners:\n  - id: db\n    resume_enabled: true\n",
            "resume_enabled",
        ),
        (
            "auth:\n  inbound_peers:\n    - id: B\n      tokens: [test-token]\n",
            "tokens",
        ),
    ];
    for (fields, key) in cases {
        let text = format!("node:\n  id: A\n{fields}");
        let error = load_text(&text).unwrap_err();
        assert_eq!(error.code, CODE_CONFIG_READ, "field={key}: {error}");
        assert!(error.message.contains(key), "field={key}: {error}");
    }
}

#[test]
fn config_contracts_reject_invalid_configurations() {
    let missing_outbound = format!(
        "{}peers:\n  - id: upstream\n    expected_node_id: remote\n    credential_ref: upstream\n    endpoints:\n      - id: e1\n        url: \"http://127.0.0.1:19080\"\n",
        MINIMAL
    );
    let error = load_text(&missing_outbound).unwrap_err();
    assert_eq!(error.code, CODE_CREDENTIAL);
    assert!(error.message.contains("no outbound credential"), "{error}");

    let duplicate_identity = format!(
        "{}    - id: peer-a\n      token_files: [inbound-token]\n      allowed_targets: [db]\n",
        MINIMAL
    );
    let error = load_text(&duplicate_identity).unwrap_err();
    assert!(
        error.message.contains("duplicate inbound identity"),
        "{error}"
    );

    let negative_limit = format!("{}limits:\n  max_sessions: -1\n", MINIMAL);
    let error = load_text(&negative_limit).unwrap_err();
    assert!(error.message.contains("max_sessions"), "{error}");

    let recovery_conflict = format!(
        "{}transport:\n  recovery:\n    enabled: false\npeers:\n  - id: upstream\n    expected_node_id: remote\n    credential_ref: upstream\n    token_file: peer-token\n    recovery:\n      enabled: true\n    endpoints:\n      - id: e1\n        url: \"http://127.0.0.1:19080\"\n",
        MINIMAL
    );
    let error =
        load_text_with_files(&recovery_conflict, &[("peer-token", "peer-secret")]).unwrap_err();
    assert!(error.message.contains("cannot be true"), "{error}");

    let small_codec_budget = format!("{}transport:\n  codec_buffer_limit: 16KiB\n", MINIMAL);
    let error = load_text(&small_codec_budget).unwrap_err();
    assert_eq!(error.message, "codec/metadata budget too small", "{error}");

    let missing_credentials =
        "node:\n  id: node-a\nauth:\n  credentials_file: missing-credentials.yaml\n";
    let error = load_text(missing_credentials).unwrap_err();
    assert_eq!(error.code, CODE_CREDENTIAL);
}

#[test]
fn duration_integer_overflow_is_rejected() {
    assert!(parse_duration("9223372036854775807s").is_err());
}

#[test]
fn config_validation_rules_reject_invalid_cidr_and_zero_heartbeat() {
    let invalid_cidr = MINIMAL.replace(
        "    address: \"127.0.0.1:3306\"",
        "    address: \"127.0.0.1:3306\"\n    allowed_cidrs: [not-a-valid-cidr]",
    );
    let error = load_text(&invalid_cidr).unwrap_err();
    assert!(error.message.contains("allowed_cidrs"), "{error}");

    let zero_heartbeat = format!("{}transport:\n  heartbeat: 0s\n", MINIMAL);
    let error = load_text(&zero_heartbeat).unwrap_err();
    assert_eq!(error.code, CODE_CONFIG_INVALID);
    assert!(error.message.contains("heartbeat"), "{error}");
}

#[test]
fn ipv6_endpoint_keeps_host_and_default_port() {
    let text = format!(
        "{}peers:\n  - id: upstream\n    expected_node_id: remote\n    credential_ref: upstream\n    token_file: peer-token\n    endpoints:\n      - id: e1\n        url: \"http://[::1]:80\"\n",
        MINIMAL
    );
    let config = load_text_with_files(&text, &[("peer-token", "peer-secret")]).unwrap();
    let url = &config.peers[0].endpoints[0].url;
    assert_eq!(url.host, "::1");
    assert_eq!(url.port, 80);
    assert_eq!(url.authority(), "[::1]:80");
}

#[test]
fn duplicate_token_slots_for_one_identity_are_allowed() {
    let env_a = format!(
        "DBB_TEST_DUPLICATE_TOKEN_{}_A",
        crate::util::random_hex(6).unwrap()
    );
    let env_b = format!(
        "DBB_TEST_DUPLICATE_TOKEN_{}_B",
        crate::util::random_hex(6).unwrap()
    );
    std::env::set_var(&env_a, "repeated-token-0123456789");
    std::env::set_var(&env_b, "repeated-token-0123456789");
    let text = MINIMAL.replace(
        "token_files: [inbound-token]",
        &format!("token_envs: [{env_a}, {env_b}]"),
    );
    let config = load_text(&text).unwrap();
    assert_eq!(config.inbound[0].tokens, vec!["repeated-token-0123456789"]);
}

#[test]
fn configuration_failures_keep_stable_codes() {
    let schema = load_text("node: {id: A}\nunknown_key: 1\n").unwrap_err();
    assert_eq!(schema.code, CODE_CONFIG_READ);

    let value = load_text("node: {id: A}\ntransport: {protocol: carrier-pigeon}\n").unwrap_err();
    assert_eq!(value.code, CODE_CONFIG_INVALID);

    let listen =
        load_text("node: {id: A}\nadmin: {enabled: true, listen: 'nonsense'}\n").unwrap_err();
    assert_eq!(listen.code, CODE_LISTEN);

    let missing_env = format!(
        "DBB_TEST_UNSET_CONFIG_TOKEN_{}",
        crate::util::random_hex(6).unwrap()
    );
    let missing_token = MINIMAL.replace(
        "token_files: [inbound-token]",
        &format!("token_envs: [{missing_env}]"),
    );
    let error = load_text(&missing_token).unwrap_err();
    assert_eq!(error.code, CODE_CREDENTIAL);

    let missing_config = std::env::temp_dir().join(format!(
        "dbbcfg-missing-{}.yaml",
        crate::util::random_hex(6).unwrap()
    ));
    let error = load(&missing_config).unwrap_err();
    assert_eq!(error.code, CODE_CONFIG_READ);
}

#[test]
fn loads_a_minimal_egress() {
    let cfg = load_text(MINIMAL).unwrap();
    assert!(cfg.egress_role());
    assert_eq!(cfg.limits.max_sessions, 200, "the default quota");
    assert_eq!(cfg.limits.max_endpoints_per_peer, 16);
    assert_eq!(cfg.inbound[0].max_sessions, 200, "inbound quota default");
    assert_eq!(cfg.transport.h2_pool_size, 4);
}

#[test]
fn security_warnings_are_collected_on_config() {
    let text = MINIMAL.replace(
        "listen: \"127.0.0.1:18080\"",
        "listen: \"0.0.0.0:18080\"\n  allow_insecure_listen: true",
    ) + "admin:\n  enabled: true\n  listen: \"0.0.0.0:18090\"\n  allow_remote: true\n";
    let cfg = load_text(&text).unwrap();
    assert!(cfg.warnings.len() >= 3, "{:?}", cfg.warnings);
    assert!(cfg
        .warnings
        .iter()
        .any(|warning| warning.contains("http.listen 0.0.0.0:18080")));
    assert!(cfg
        .warnings
        .iter()
        .any(|warning| warning.contains("admin.listen 0.0.0.0:18090")));
    assert!(cfg
        .warnings
        .iter()
        .any(|warning| warning
            .contains("inbound peer peer-a uses a bearer token shorter than 16 bytes")));
}

#[test]
fn noncanonical_node_id_is_collected_as_spec_warning() {
    let text = MINIMAL.replace("id: peer-b", "id: \"bad id\"");
    let cfg = load_text(&text).unwrap();
    assert!(cfg.warnings.iter().any(|warning| {
        warning == "node id \"bad id\" should match ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ (letters, digits, '.', '_', '-', at most 64 characters)"
    }));
}

#[test]
fn noncanonical_endpoint_and_inbound_ids_use_spec_warning_kinds() {
    let text = MINIMAL
        .replace("id: peer-a", "id: \"bad inbound id\"")
        .replace(
            "auth:\n  inbound_peers:",
            "peers:\n  - id: upstream\n    expected_node_id: remote\n    credential_ref: upstream\n    token_file: peer-token\n    endpoints:\n      - id: \"bad endpoint id\"\n        url: \"http://127.0.0.1:19080\"\nauth:\n  inbound_peers:",
        );
    let cfg = load_text_with_files(&text, &[("peer-token", "peer-secret")]).unwrap();
    assert!(cfg.warnings.iter().any(|warning| warning == "endpoint id \"bad endpoint id\" should match ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ (letters, digits, '.', '_', '-', at most 64 characters)"));
    assert!(cfg.warnings.iter().any(|warning| warning == "inbound peer id \"bad inbound id\" should match ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ (letters, digits, '.', '_', '-', at most 64 characters)"));
}

#[test]
fn disabled_http_reports_spec_unused_section_warnings_and_idle_node_warning() {
    let text = "\
node:
  id: node-a
http:
  enabled: false
  tls:
    cert_file: cert.pem
targets:
  db:
    network: tcp
    address: \"127.0.0.1:3306\"
auth:
  inbound_peers:
    - id: peer-a
      token_files: [inbound-token]
      allowed_targets: [db]
";
    let cfg = load_text(text).unwrap();
    for expected in [
        "auth inbound peers are configured but http.enabled is false; this node never accepts inbound sessions",
        "targets are configured but http.enabled is false; they are only used by the inbound HTTP server",
        "http.tls is configured but http.enabled is false; the TLS settings are ignored",
    ] {
        assert!(cfg.warnings.iter().any(|warning| warning == expected), "missing {expected:?}: {:?}", cfg.warnings);
    }
    let idle = load_text("node:\n  id: node-a\n").unwrap();
    assert!(idle.warnings.iter().any(|warning| warning == "neither http.enabled nor any peers or listeners are configured; the node has nothing to do"));
}

#[test]
fn reverse_peer_ignored_tls_warning_is_spec_exact_and_not_duplicated() {
    let text = "\
node:
  id: public
http:
  enabled: true
  listen: \"127.0.0.1:18080\"
targets:
  db:
    network: tcp
    address: \"127.0.0.1:3306\"
peers:
  - id: reverse-peer
    mode: reverse
    expected_node_id: database
    credential_ref: reverse-peer
    token_file: peer-token
    allow_insecure_http: true
    tls:
      verify: true
auth:
  inbound_peers:
    - id: reverse-peer
      token_files: [inbound-token]
      allowed_targets: [db]
";
    let cfg = load_text_with_files(text, &[("peer-token", "peer-secret")]).unwrap();
    let expected = "peers[reverse-peer]: tls and allow_insecure_http are ignored for a reverse peer; the tunnel's TLS is http.tls on this node and reverse.tls on the database side";
    assert_eq!(
        cfg.warnings
            .iter()
            .filter(|warning| warning.as_str() == expected)
            .count(),
        1,
        "{:?}",
        cfg.warnings
    );
}

#[test]
fn collects_hostname_listener_reverse_and_bidirectional_quota_warnings() {
    let text = MINIMAL
        .replace(
            "auth:\n  inbound_peers:\n    - id: peer-a\n      token_files: [inbound-token]\n      allowed_targets: [db]\n",
            "auth:\n  credentials_file: credentials.yaml\n",
        )
        .replace(
            "listen: \"127.0.0.1:18080\"",
            "listen: \"0.0.0.0:18080\"\n  allow_insecure_listen: true",
        )
        .replace("127.0.0.1:3306", "db.internal:3306")
        + "listeners:\n  - id: exposed\n    listen: \"0.0.0.0:13306\"\n    peer: peer-a\n    target: db\npeers:\n  - id: peer-a\n    expected_node_id: peer-a-remote\n    credential_ref: peer-a\n    endpoints:\n      - id: endpoint-a\n        url: \"http://127.0.0.1:18081\"\n";
    let credentials = "version: 1\ninbound_peers:\n  - id: peer-a\n    token_files: [inbound-token]\n    allowed_targets: [db]\noutbound_peers:\n  - id: peer-a\n    token_file: out-token\n";
    let cfg = load_text_with_files(
        &text,
        &[
            ("credentials.yaml", credentials),
            ("out-token", "different-secret"),
        ],
    )
    .unwrap();
    for fragment in [
        "target db uses hostname \"db.internal\" without allowed_cidrs",
        "listeners[exposed].listen 0.0.0.0:13306 is not a loopback address",
        "inbound peers may hold all 200 sessions (quota sum 200)",
    ] {
        assert!(
            cfg.warnings
                .iter()
                .any(|warning| warning.contains(fragment)),
            "missing {fragment:?} in {:?}",
            cfg.warnings
        );
    }

    let disabled_reverse = format!(
        "{}reverse:\n  enabled: false\n  token_file: ignored-token\n",
        MINIMAL
    );
    let cfg = load_text(&disabled_reverse).unwrap();
    assert!(cfg.warnings.iter().any(|warning| {
        warning == "reverse is configured but reverse.enabled is false; the settings are ignored"
    }));
}

#[test]
fn h2_pool_size_accepts_only_inclusive_range() {
    for size in [1, 4, 64] {
        let text = format!("{}transport:\n  h2_pool_size: {size}\n", MINIMAL);
        assert_eq!(load_text(&text).unwrap().transport.h2_pool_size, size);
    }
    for (value, code) in [
        ("0", CODE_CONFIG_INVALID),
        ("65", CODE_CONFIG_INVALID),
        ("-1", CODE_CONFIG_INVALID),
        ("1.5", CODE_CONFIG_READ),
        ("four", CODE_CONFIG_READ),
    ] {
        let text = format!("{}transport:\n  h2_pool_size: {value}\n", MINIMAL);
        let error = load_text(&text).expect_err(value);
        assert_eq!(error.code, code);
        assert!(error.message.contains("h2_pool_size"), "{}", error.message);
    }
}

#[test]
fn h2_pool_size_rejects_unknown_transport_field() {
    let text = format!("{}transport:\n  h2_pool_szie: 4\n", MINIMAL);
    let error = load_text(&text).unwrap_err();
    assert_eq!(error.code, CODE_CONFIG_READ);
    assert!(error.message.contains("h2_pool_szie"), "{}", error.message);
}

#[test]
fn auth_reload_interval_matches_spec_default_and_bounds() {
    assert_eq!(
        load_text(MINIMAL).unwrap().auth_reload_interval,
        std::time::Duration::from_secs(5)
    );
    for (raw, expected) in [("7", 7), ("7s", 7), ("0", 5), ("0s", 5)] {
        let text = MINIMAL.replace("auth:\n", &format!("auth:\n  reload_interval: {raw}\n"));
        assert_eq!(
            load_text(&text).unwrap().auth_reload_interval,
            std::time::Duration::from_secs(expected)
        );
    }
    for raw in ["500ms", "-1", "-1s"] {
        let text = MINIMAL.replace("auth:\n", &format!("auth:\n  reload_interval: {raw}\n"));
        let error = load_text(&text).unwrap_err();
        assert!(error.message.contains("auth.reload_interval"), "{error}");
    }
}

#[test]
fn reads_the_node_wide_session_quota() {
    let inbound_limited = MINIMAL.replace(
        "      allowed_targets: [db]",
        "      allowed_targets: [db]\n      max_sessions: 7",
    );
    let text = format!("{inbound_limited}limits:\n  max_sessions: 7\n");
    assert_eq!(load_text(&text).unwrap().limits.max_sessions, 7);
    for (key, value) in [
        ("max_sessions", "0"),
        ("max_sessions", "-1"),
        ("max_endpoints_per_peer", "0"),
        ("max_endpoints_per_peer", "-1"),
    ] {
        let text = format!("{}limits:\n  {key}: {value}\n", MINIMAL);
        let error = load_text(&text).expect_err(&format!("{key}={value}"));
        assert!(error.message.contains("positive integer"), "{error}");
    }
}

#[test]
fn max_endpoints_per_peer_is_enforced() {
    let mut text = format!(
        "{}peers:\n  - id: upstream\n    expected_node_id: remote-node\n    credential_ref: upstream\n    token_file: peer-token\n    endpoints:\n",
        MINIMAL
    );
    for index in 0..17 {
        text.push_str(&format!(
            "      - id: ep-{index}\n        url: \"http://127.0.0.1:{}\"\n",
            19000 + index
        ));
    }
    let error = load_text_with_files(&text, &[("peer-token", "peer-secret")]).unwrap_err();
    assert!(error.message.contains("max_endpoints_per_peer"), "{error}");
}

#[test]
fn a_misspelled_key_is_an_error() {
    // A silently ignored key is the worst outcome: the node starts, looks
    // healthy and behaves as if the setting was never written.
    let text = format!("{}transport:\n  frame_sise: 32KiB\n", MINIMAL);
    let e = load_text(&text).unwrap_err();
    assert_eq!(e.code, CODE_CONFIG_READ);
    assert!(e.message.contains("frame_sise"), "{}", e.message);
}

#[test]
fn p0_08_security_keys_are_accepted() {
    let text = MINIMAL
        .replace(
            "  listen: \"127.0.0.1:18080\"",
            "  listen: \"127.0.0.1:18080\"\n  tls:\n    enabled: true\n    cert_file: cert.pem\n    key_file: key.pem",
        )
        .replace("admin:\n", "admin:\n  allow_remote: true\n");
    #[cfg(feature = "tls")]
    load_text_with_files(&text, &tls_fixture()).unwrap();
    #[cfg(not(feature = "tls"))]
    assert_eq!(load_text(&text).unwrap_err().code, "DBB-CFG-004");
}

#[test]
fn non_loopback_plaintext_listen_requires_opt_in() {
    let text = MINIMAL.replace("127.0.0.1:18080", "0.0.0.0:18080");
    let e = load_text(&text).unwrap_err();
    assert_eq!(e.code, "DBB-CFG-005");
    assert_eq!(
        e.message,
        "non-loopback HTTP needs TLS or explicit insecure opt-in (http.allow_insecure_listen: true)"
    );

    let opted_in = text.replace(
        "  listen: \"0.0.0.0:18080\"",
        "  listen: \"0.0.0.0:18080\"\n  allow_insecure_listen: true",
    );
    load_text(&opted_in).unwrap();

    let tls = text.replace(
        "  listen: \"0.0.0.0:18080\"",
        "  listen: \"0.0.0.0:18080\"\n  tls:\n    enabled: true\n    cert_file: cert.pem\n    key_file: key.pem",
    );
    #[cfg(feature = "tls")]
    load_text_with_files(&tls, &tls_fixture()).unwrap();
    #[cfg(not(feature = "tls"))]
    assert_eq!(load_text(&tls).unwrap_err().code, "DBB-CFG-004");
}

#[test]
fn remote_admin_requires_allow_remote() {
    let text = format!(
        "{}admin:\n  enabled: true\n  listen: \"0.0.0.0:18090\"\n",
        MINIMAL
    );
    let e = load_text(&text).unwrap_err();
    assert_eq!(e.code, "DBB-CFG-005");
    assert_eq!(
        e.message,
        "admin.listen must be a loopback address (the admin endpoint has no TLS or authentication); set admin.allow_remote: true to override"
    );

    let opted_in = text.replace(
        "  listen: \"0.0.0.0:18090\"",
        "  listen: \"0.0.0.0:18090\"\n  allow_remote: true",
    );
    load_text(&opted_in).unwrap();
}

#[test]
fn a_reverse_peer_may_not_declare_endpoints() {
    // A reverse peer dials this node, so the endpoints of a forward peer
    // would be dead config: refuse it rather than ignore it.
    let text = "\
node:
  id: peer-a
http:
  enabled: true
  listen: \"127.0.0.1:18080\"
listeners:
  - id: local
    listen: \"127.0.0.1:13306\"
    peer: peer-b
    target: db
peers:
  - id: peer-b
    mode: reverse
    expected_node_id: remote-node
    credential_ref: peer-b
    token_file: peer-token
    endpoints:
      - id: primary
        url: \"http://127.0.0.1:18080\"
";
    let e = load_text_with_files(text, &[("peer-token", "peer-secret")]).unwrap_err();
    assert!(e.message.contains("endpoints"), "{}", e.message);
}

#[test]
fn a_reverse_peer_needs_an_inbound_http_listener() {
    // The tunnel arrives on http.listen, so there must be one.
    let text = "\
node:
  id: peer-a
listeners:
  - id: local
    listen: \"127.0.0.1:13306\"
    peer: peer-b
    target: db
peers:
  - id: peer-b
    mode: reverse
    expected_node_id: remote-node
    credential_ref: peer-b
    token_file: peer-token
";
    let e = load_text_with_files(text, &[("peer-token", "peer-secret")]).unwrap_err();
    assert!(e.message.contains("http.enabled"), "{}", e.message);
}

#[test]
fn a_reverse_peer_without_endpoints_is_accepted() {
    let text = "\
node:
  id: peer-a
http:
  enabled: true
  listen: \"127.0.0.1:18080\"
listeners:
  - id: local
    listen: \"127.0.0.1:13306\"
    peer: peer-b
    target: db
targets:
  db:
    network: tcp
    address: \"127.0.0.1:3306\"
peers:
  - id: peer-b
    mode: reverse
    expected_node_id: remote-node
    credential_ref: peer-b
    token_file: peer-token
auth:
  inbound_peers:
    - id: peer-b
      token_files: [inbound-token]
      allowed_targets: [db]
";
    let cfg = load_text_with_files(text, &[("peer-token", "peer-secret")]).unwrap();
    assert!(cfg.peer("peer-b").unwrap().reverse);
    assert!(cfg.has_reverse_peers());
}

#[test]
fn reads_the_reverse_section() {
    let text = "\
node:
  id: peer-b
targets:
  db:
    network: tcp
    address: \"127.0.0.1:3306\"
reverse:
  enabled: true
  peer_node_id: peer-a
  token_file: reverse-token
  transport: ws
  tunnels_per_endpoint: 3
  endpoints:
    - id: public
      url: \"http://127.0.0.1:18080\"
      priority: 2
  reconnect:
    min_backoff: 200ms
    max_backoff: 10s
";
    let cfg = load_text_with_files(text, &[("reverse-token", "reverse-secret")]).unwrap();
    assert!(cfg.reverse.enabled);
    assert_eq!(cfg.reverse.peer_node_id, "peer-a");
    assert_eq!(cfg.reverse.tunnels_per_endpoint, 3);
    assert_eq!(cfg.reverse.endpoints.len(), 1);
    assert_eq!(cfg.reverse.min_backoff, Duration::from_millis(200));
    assert_eq!(cfg.reverse.max_backoff, Duration::from_secs(10));
    // Enabling reverse makes this an egress even without http.enabled.
    assert!(cfg.egress_role());
    assert!(!cfg.http.enabled);
}

#[test]
fn reverse_tunnels_per_endpoint_rejects_out_of_range_values() {
    for value in ["0", "-1", "17"] {
        let text = format!(
            "node:\n  id: peer-b\nreverse:\n  enabled: true\n  peer_node_id: peer-a\n  token_file: reverse-token\n  tunnels_per_endpoint: {value}\n  endpoints:\n    - id: public\n      url: \"http://127.0.0.1:18080\"\n"
        );
        let error = load_text(&text).unwrap_err();
        let want = if value == "17" {
            CODE_REVERSE
        } else {
            CODE_CONFIG_READ
        };
        assert_eq!(error.code, want, "value={value}: {error}");
        assert!(error.message.contains("tunnels_per_endpoint"));
    }
}

#[test]
fn reverse_backoff_default_tracks_min_and_enforces_ten_minute_cap() {
    let text = "\
node:\n  id: peer-b\nreverse:\n  enabled: true\n  peer_node_id: peer-a\n  token_file: reverse-token\n  endpoints:\n    - id: public\n      url: \"http://127.0.0.1:18080\"\n  reconnect:\n    min_backoff: 45s\n";
    let cfg = load_text_with_files(text, &[("reverse-token", "reverse-secret")]).unwrap();
    assert_eq!(cfg.reverse.max_backoff, Duration::from_secs(45));

    let too_large = text.replace("min_backoff: 45s", "min_backoff: 11m");
    let error = load_text(&too_large).unwrap_err();
    assert_eq!(error.code, CODE_REVERSE);
    assert!(error.message.contains("<= 10m"));
}

#[test]
fn long_poll_reverse_carrier_is_supported() {
    let text = "\
node:
  id: peer-b
reverse:
  enabled: true
  peer_node_id: peer-a
  token_file: reverse-token
  transport: long-poll
  endpoints:
    - id: public
      url: \"http://127.0.0.1:18080\"
";
    let cfg = load_text_with_files(text, &[("reverse-token", "reverse-secret")]).unwrap();
    assert_eq!(cfg.reverse.transport, Protocol::LongPoll);
}

#[test]
fn allowed_transports_belongs_to_the_http_section() {
    // Under `transport` it is not a key, and must not be quietly dropped:
    // the egress would keep offering WebSocket while the operator believes
    // it is SSE-only.
    let text = format!("{}transport:\n  allowed_transports: [http-sse]\n", MINIMAL);
    let e = load_text(&text).unwrap_err();
    assert!(e.message.contains("allowed_transports"), "{}", e.message);

    let text = MINIMAL.replace(
        "  listen: \"127.0.0.1:18080\"",
        "  listen: \"127.0.0.1:18080\"\n  allowed_transports: [http-sse]",
    );
    let cfg = load_text(&text).unwrap();
    assert_eq!(cfg.transports(), &[Mode::HttpSse]);
}

#[test]
fn recovery_defaults_and_strict_validation() {
    let cfg = load_text(MINIMAL).unwrap();
    assert!(cfg.transport.recovery_enabled);
    assert_eq!(
        cfg.transport.recovery_grace,
        std::time::Duration::from_secs(30)
    );
    assert_eq!(
        cfg.transport.recovery_barrier_timeout,
        std::time::Duration::from_secs(5)
    );
    let text = format!("{}transport:\n  recovery:\n    enabled: true\n", MINIMAL);
    let cfg = load_text(&text).unwrap();
    assert!(cfg.transport.recovery_enabled);
    let disabled = format!("{}transport:\n  recovery:\n    enabled: false\n", MINIMAL);
    let cfg = load_text(&disabled).unwrap();
    assert!(!cfg.transport.recovery_enabled);
    let bad = format!(
        "{}transport:\n  recovery:\n    enabled: true\n    grace: 5s\n    barrier_timeout: 5s\n",
        MINIMAL
    );
    assert!(load_text(&bad).is_err());
}

#[test]
fn peer_recovery_override_matches_spec_validation() {
    let peer = "peers:\n  - id: peer-c\n    expected_node_id: peer-c\n    credential_ref: peer-c\n    token_file: inbound-token\n    endpoints:\n      - {id: primary, url: \"http://127.0.0.1:18081\"}\n    recovery:\n      enabled: true\n";
    let cfg = load_text(&format!("{MINIMAL}{peer}")).unwrap();
    assert_eq!(cfg.peers[0].recovery_enabled, Some(true));

    let disabled_peer = peer.replace("enabled: true", "enabled: false");
    let cfg = load_text(&format!("{MINIMAL}{disabled_peer}")).unwrap();
    assert_eq!(cfg.peers[0].recovery_enabled, Some(false));

    let conflict = format!("{MINIMAL}{peer}transport:\n  recovery:\n    enabled: false\n");
    let error = load_text(&conflict).unwrap_err();
    assert_eq!(
        error.message,
        "peer[peer-c].recovery.enabled cannot be true when transport.recovery.enabled is false"
    );
}

#[test]
fn disabled_inbound_identity_needs_no_tokens() {
    let text = MINIMAL.replace(
        "      allowed_targets: [db]",
        "      allowed_targets: [db]\n    - id: disabled-env\n      enabled: false\n      token_envs: [DBB_TEST_UNSET_DISABLED_TOKEN]\n      allowed_targets: [db]\n    - id: disabled-file\n      enabled: false\n      token_files: [missing-secret]\n      allowed_targets: [db]",
    );
    let cfg = load_text(&text).unwrap();
    let disabled_env = cfg
        .inbound
        .iter()
        .find(|peer| peer.id == "disabled-env")
        .unwrap();
    assert!(!disabled_env.enabled);
    assert!(disabled_env.tokens.is_empty());
    let disabled_file = cfg
        .inbound
        .iter()
        .find(|peer| peer.id == "disabled-file")
        .unwrap();
    assert!(!disabled_file.enabled);
    assert!(disabled_file.tokens.is_empty());
}

#[test]
fn inbound_credentials_accept_only_spec_canonical_field_names() {
    let cases = [
        (
            MINIMAL.replace("token_files: [inbound-token]", "token: abc"),
            "not found in",
        ),
        (
            MINIMAL.replace("token_files: [inbound-token]", "token_file: inbound-token"),
            "not found in",
        ),
        (
            MINIMAL.replace("allowed_targets: [db]", "targets: [db]"),
            "not found in",
        ),
        (
            MINIMAL.replace("token_files: [inbound-token]", "token_files: inbound-token"),
            "must be a list",
        ),
    ];
    for (text, expected) in cases {
        let error = load_text(&text).unwrap_err();
        assert!(
            error.message.contains(expected),
            "expected {expected:?}, got {error}"
        );
    }
}

#[test]
fn peer_identity_and_credential_fields_follow_spec_schema() {
    let valid = format!(
        "{}peers:\n  - id: upstream\n    expected_node_id: remote-node\n    credential_ref: upstream\n    token_file: peer-token\n    endpoints:\n      - id: e1\n        url: \"http://127.0.0.1:19080\"\n",
        MINIMAL
    );
    let cases = [
        (
            valid.replace("    expected_node_id: remote-node\n", ""),
            "expected_node_id is required",
        ),
        (
            valid.replace("expected_node_id: remote-node", "expected_node_id: peer-b"),
            "must differ from this node's node.id",
        ),
        (
            valid.replace("    credential_ref: upstream\n", ""),
            "credential_ref is required",
        ),
        (
            valid.replace("    token_file: peer-token", "    token: peer-secret"),
            "token",
        ),
        (
            valid.replace(
                "    token_file: peer-token",
                "    token_file: peer-token\n    token_env: DBB_TEST_TOKEN",
            ),
            "ambiguous credential source",
        ),
        (
            valid.replace("    token_file: peer-token\n", ""),
            "no outbound credential",
        ),
    ];
    for (text, expected) in cases {
        let error = load_text_with_files(&text, &[("peer-token", "peer-secret")]).unwrap_err();
        assert!(
            error.message.contains(expected),
            "expected {expected:?}, got {error}"
        );
    }
}

#[test]
fn reverse_peers_need_distinct_expected_node_ids() {
    let text = format!(
        "{}peers:\n  - id: reverse-a\n    mode: reverse\n    expected_node_id: remote-node\n    credential_ref: reverse-a\n    token_file: peer-token\n  - id: reverse-b\n    mode: reverse\n    expected_node_id: remote-node\n    credential_ref: reverse-b\n    token_file: peer-token\n",
        MINIMAL
    );
    let error = load_text_with_files(&text, &[("peer-token", "peer-secret")]).unwrap_err();
    assert!(
        error
            .message
            .contains("reverse peers must have distinct expected_node_id"),
        "{error}"
    );
}

#[test]
fn credentials_file_validates_version_and_root_keys() {
    let main = "node:\n  id: node-a\nauth:\n  credentials_file: credentials.yaml\n";
    for (credentials, expected) in [
        ("version: 2\ninbound_peers: []\n", "version must be 1"),
        ("version: 1\nunknown: true\n", "not found in"),
    ] {
        let error = load_text_with_files(main, &[("credentials.yaml", credentials)]).unwrap_err();
        assert!(error.message.contains(expected), "{}", error.message);
    }
}

#[test]
fn credentials_file_rejects_inline_and_direct_credentials_mixing() {
    let inline = MINIMAL.replace(
        "auth:\n  inbound_peers:",
        "auth:\n  credentials_file: credentials.yaml\n  inbound_peers:",
    );
    let error = load_text_with_files(
        &inline,
        &[("credentials.yaml", "version: 1\ninbound_peers: []\n")],
    )
    .unwrap_err();
    assert_eq!(error.code, CODE_AUTH_CONFLICT);
    assert!(error.message.contains("inline inbound credentials"));

    let direct_peer = format!(
        "{}peers:\n  - id: upstream\n    expected_node_id: remote\n    credential_ref: upstream\n    token_file: secret.txt\n    endpoints:\n      - id: e1\n        url: \"http://127.0.0.1:19080\"\n",
        MINIMAL.replace(
            "auth:\n  inbound_peers:\n    - id: peer-a\n      token_files: [inbound-token]\n      allowed_targets: [db]",
            "auth:\n  credentials_file: credentials.yaml",
        )
    );
    let error = load_text_with_files(
        &direct_peer,
        &[(
            "credentials.yaml",
            "version: 1\ninbound_peers: []\noutbound_peers: []\n",
        )],
    )
    .unwrap_err();
    assert_eq!(error.code, CODE_AUTH_CONFLICT);
    assert!(error.message.contains("direct outbound credentials"));

    let direct_env_peer =
        direct_peer.replace("token_file: secret.txt", "token_env: DBB_TEST_MIXED");
    let error = load_text_with_files(
        &direct_env_peer,
        &[(
            "credentials.yaml",
            "version: 1\ninbound_peers: []\noutbound_peers: []\n",
        )],
    )
    .unwrap_err();
    assert_eq!(error.code, CODE_AUTH_CONFLICT);
    assert!(error.message.contains("direct outbound credentials"));
}

#[test]
fn credential_token_files_resolve_relative_to_credentials_file() {
    let dir = std::env::temp_dir().join(format!(
        "dbbcfg-cred-dir-{}",
        crate::util::random_hex(6).unwrap()
    ));
    let credential_dir = dir.join("creds");
    std::fs::create_dir_all(&credential_dir).unwrap();
    let main = MINIMAL.replace(
        "auth:\n  inbound_peers:\n    - id: peer-a\n      token_files: [inbound-token]\n      allowed_targets: [db]",
        "auth:\n  credentials_file: creds/credentials.yaml",
    );
    let config_path = dir.join("config.yaml");
    std::fs::write(&config_path, main).unwrap();
    std::fs::write(
        credential_dir.join("credentials.yaml"),
        "version: 1\ninbound_peers:\n  - id: peer-a\n    token_files: [token.txt]\n    allowed_targets: [db]\n",
    )
    .unwrap();
    std::fs::write(credential_dir.join("token.txt"), "resolved-token\n").unwrap();
    let config = load(&config_path).unwrap();
    assert_eq!(config.inbound[0].tokens, vec!["resolved-token"]);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn token_files_are_alternatives() {
    let text = MINIMAL.replace(
        "      token_files: [inbound-token]",
        "      token_files: [first-token, second-token]",
    );
    let cfg = load_text_with_files(
        &text,
        &[("first-token", "alpha\n"), ("second-token", "beta\r\n")],
    )
    .unwrap();
    assert_eq!(cfg.inbound[0].tokens, vec!["alpha", "beta"]);
}

#[test]
fn same_token_two_identities_rejected() {
    let text = format!(
        "{}    - id: peer-c\n      token_files: [inbound-token]\n      allowed_targets: [db]\n",
        MINIMAL
    );
    let error = load_text(&text).unwrap_err();
    assert_eq!(error.code, CODE_AUTH_CONFLICT);
    assert_eq!(
        error.message,
        "inbound peers peer-a and peer-c use the same token; every inbound identity needs its own token"
    );
}

#[test]
fn inbound_identity_ids_and_quotas_are_bounded() {
    let duplicate_id = format!(
        "{}    - id: peer-a\n      token_files: [inbound-token]\n      allowed_targets: [db]\n",
        MINIMAL
    );
    let error = load_text(&duplicate_id).unwrap_err();
    assert_eq!(error.code, CODE_CREDENTIAL);
    assert!(error.message.contains("duplicate inbound identity"));

    let zero_quota = MINIMAL.replace(
        "      allowed_targets: [db]",
        "      allowed_targets: [db]\n      max_sessions: 0",
    );
    let error = load_text(&zero_quota).unwrap_err();
    assert!(error
        .message
        .contains("max_sessions must be a positive integer"));

    let over_quota = format!(
        "{}    - id: peer-c\n      token_files: [other-token]\n      allowed_targets: [db]\n      max_sessions: 100\n",
        MINIMAL.replace(
            "      allowed_targets: [db]",
            "      allowed_targets: [db]\n      max_sessions: 150",
        )
    );
    let error =
        load_text_with_files(&over_quota, &[("other-token", "different-secret")]).unwrap_err();
    assert_eq!(
        error.message,
        "sum of inbound peer max_sessions (250, an omitted quota counts as 200) exceeds limits.max_sessions (200); set explicit per-peer quotas or raise the global limit"
    );
    let cfg = load_text_with_files(
        &over_quota.replace("max_sessions: 150", "max_sessions: 100"),
        &[("other-token", "different-secret")],
    )
    .unwrap();
    assert_eq!(cfg.inbound.len(), 2);
    assert_eq!(cfg.limits.max_sessions, 200);

    let identity_over_global = MINIMAL.replace(
        "      allowed_targets: [db]",
        "      allowed_targets: [db]\n      max_sessions: 201",
    );
    let cfg = load_text(&identity_over_global).unwrap();
    assert!(cfg.warnings.iter().any(|warning| {
        warning == "inbound peer peer-a max_sessions (201) exceeds limits.max_sessions (200); the global limit applies"
    }));
}

#[test]
fn mixed_token_sources_rejected() {
    let text = MINIMAL.replace(
        "      token_files: [inbound-token]",
        "      token_files: [first-token]\n      token_envs: [DBB_MISSING_SECRET]",
    );
    let error = load_text(&text).unwrap_err();
    assert!(
        error.message.contains("mixed inbound token sources"),
        "{}",
        error.message
    );
}

#[test]
fn metadata_and_codec_budget_fields_are_validated() {
    let text = format!("{}transport:\n  metadata_limit: 512KiB\n", MINIMAL);
    let error = load_text(&text).unwrap_err();
    assert!(error.message.contains("max_sessions"), "{}", error.message);

    let text = format!("{}transport:\n  codec_buffer_limit: 16KiB\n", MINIMAL);
    let error = load_text(&text).unwrap_err();
    assert_eq!(error.message, "codec/metadata budget too small");
}

#[test]
fn yaml_is_single_document_and_rejects_explicit_null() {
    let leading_marker = format!("---\n{MINIMAL}");
    assert!(load_text(&leading_marker).is_ok());

    let two_documents = format!("---\n{MINIMAL}---\n{MINIMAL}");
    let error = load_text(&two_documents).unwrap_err();
    assert!(error.message.contains("exactly one YAML document"));

    let explicit_null = format!("{}transport:\n  heartbeat: null\n", MINIMAL);
    let error = load_text(&explicit_null).unwrap_err();
    assert!(error.message.contains("explicit null is not allowed"));
}

#[test]
fn config_and_credentials_files_are_size_limited() {
    let too_large_config = "x".repeat((4 << 20) + 1);
    let error = load_text(&too_large_config).unwrap_err();
    assert!(
        error.message.starts_with("failed to read config file "),
        "{}",
        error.message
    );
    assert!(
        error.message.ends_with(": config too large"),
        "{}",
        error.message
    );

    let main = "node:\n  id: only\nauth:\n  credentials_file: credentials.yaml\n";
    let too_large_credentials = "x".repeat((1 << 20) + 1);
    let error =
        load_text_with_files(main, &[("credentials.yaml", &too_large_credentials)]).unwrap_err();
    assert_eq!(error.code, CODE_CREDENTIAL);
    assert!(error.message.contains("maximum size of 1048576 bytes"));
}

#[test]
fn tunnel_stream_window_uses_codec_budget_and_buffer_cap() {
    let mut transport = Transport::default();
    assert_eq!(transport.tunnel_stream_window(), 256 << 10);

    transport.codec_buffer_limit = 64 << 20;
    assert_eq!(transport.tunnel_stream_window(), 512 << 10);

    transport.buffer_per_direction = 512 << 10;
    assert_eq!(transport.tunnel_stream_window(), 512 << 10);

    transport.buffer_per_direction = 128 << 10;
    assert_eq!(transport.tunnel_stream_window(), 256 << 10);
}

#[cfg(unix)]
#[test]
fn filesystem_permission_warning_matches_spec_text() {
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir().join(format!(
        "dbbcfg-perm-{}",
        crate::util::random_hex(6).unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("token");
    std::fs::write(&path, "secret").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let mut warnings = Vec::new();
    super::build::warn_insecure_permissions(&path, &mut warnings);
    assert_eq!(
        warnings,
        vec![format!(
            "secret file {} has mode 0644: other users can access it or its group can write it; use chmod 600 (or 640 with a service group)",
            path.display()
        )]
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn sandboxed_credential_warning_is_string_only_and_spec_exact() {
    let mut warnings = Vec::new();
    super::build::warn_filesystem_sources(
        std::path::Path::new("/etc/dbbridge"),
        &[std::path::PathBuf::from("/tmp/token")],
        &[],
        None,
        true,
        &mut warnings,
    );
    assert_eq!(
        warnings,
        vec![
            "credential file /tmp/token is under /tmp but the configuration is not; a service installed with 'dbbridge install' sees /tmp only when a file there is referenced at install time, so keep credential files next to the configuration"
        ]
    );
}

#[test]
fn spec_buffer_limits_are_parsed_with_derived_default_and_constraints() {
    let cfg = load_text("node:\n  id: node-a\ntransport:\n  global_buffer_limit: 32MiB\n").unwrap();
    assert_eq!(cfg.transport.global_buffer_limit, 32 * 1024 * 1024);
    assert_eq!(cfg.transport.suspended_buffer_limit, 8 * 1024 * 1024);

    let invalid = MINIMAL.to_string()
        + "transport:\n  global_buffer_limit: 64MiB\n  suspended_buffer_limit: 64MiB\n";
    let error = load_text(&invalid).unwrap_err();
    assert!(error.message.contains("suspended_buffer_limit"), "{error}");
}

#[test]
fn offline_does_not_read_token_files_or_environment() {
    let dir = std::env::temp_dir().join(format!(
        "dbbcfg-offline-{}",
        crate::util::random_hex(6).unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("cfg.yaml");
    let text = MINIMAL.replace("inbound-token", "missing-token-file");
    std::fs::write(&path, text).unwrap();
    let cfg = load_with_options(&path, true).unwrap();
    assert_eq!(cfg.inbound[0].tokens.len(), 0);
}

#[test]
fn ipv6_cidr_matches() {
    assert!(cidr_contains(
        "2001:db8:abcd::1/48",
        "2001:db8:abcd:ffff::1".parse().unwrap()
    ));
    assert!(!cidr_contains(
        "2001:db8:abcd::/48",
        "2001:db8:abce::1".parse().unwrap()
    ));
    assert!(!cidr_contains(
        "2001:db8::/32",
        "192.0.2.1".parse().unwrap()
    ));
}

#[test]
fn boundary_cidr_validation_matches_runtime() {
    let text = MINIMAL.replace(
        "    address: \"127.0.0.1:3306\"",
        "    address: \"127.0.0.1:3306\"\n    allowed_cidrs: [\" 127.0.0.0/8 \", \"2001:db8::/32\"]",
    );
    let cfg = load_text(&text).unwrap();
    let cidrs = &cfg.target("db").unwrap().allowed_cidrs;
    assert_eq!(cidrs[0], "127.0.0.0/8");
    assert_eq!(cidrs[1], "2001:db8::/32");
    assert!(cidr_contains(&cidrs[0], "127.10.20.30".parse().unwrap()));
    assert!(cidr_contains(&cidrs[1], "2001:db8:1::1".parse().unwrap()));
}

#[test]
fn disabled_identity_acl_still_rejects_unknown_target() {
    let text = MINIMAL
        .replace(
            "      token_files: [inbound-token]",
            "      enabled: false\n      token_files: [missing-token]",
        )
        .replace("allowed_targets: [db]", "allowed_targets: [missing-target]");
    let error = load_text(&text).unwrap_err();
    assert_eq!(error.code, CODE_CREDENTIAL);
    assert_eq!(error.message, "unknown ACL target \"missing-target\"");
}

#[test]
fn failover_healthcheck_timeout_is_derived_and_must_be_positive() {
    let peer = |failover: &str| {
        let failover_block = if failover.is_empty() {
            String::new()
        } else {
            format!("    failover:\n{failover}")
        };
        format!(
            "{MINIMAL}peers:\n  - id: upstream\n    expected_node_id: remote\n    credential_ref: upstream\n    token_file: peer-token\n    endpoints:\n      - id: e1\n        url: \"http://127.0.0.1:19080\"\n{failover_block}"
        )
    };

    let defaults = load_text_with_files(&peer(""), &[("peer-token", "peer-secret")]).unwrap();
    assert!(!defaults.peers[0].failover.enabled);
    assert_eq!(
        defaults.peers[0].failover.healthcheck_interval,
        Duration::from_secs(10)
    );
    assert_eq!(
        defaults.peers[0].failover.healthcheck_timeout,
        Duration::from_secs(3)
    );
    assert_eq!(defaults.peers[0].failover.healthy_threshold, 2);
    assert_eq!(defaults.peers[0].failover.unhealthy_threshold, 2);

    let two_endpoints = peer("").replace(
        "      - id: e1\n        url: \"http://127.0.0.1:19080\"\n",
        "      - id: e1\n        url: \"http://127.0.0.1:19080\"\n      - id: e2\n        url: \"http://127.0.0.1:19081\"\n",
    );
    let defaults = load_text_with_files(&two_endpoints, &[("peer-token", "peer-secret")]).unwrap();
    assert!(defaults.peers[0].failover.enabled);

    let shortened = load_text_with_files(
        &peer("      healthcheck_interval: 2s\n"),
        &[("peer-token", "peer-secret")],
    )
    .unwrap();
    assert_eq!(
        shortened.peers[0].failover.healthcheck_timeout,
        Duration::from_secs(1)
    );

    for failover in [
        "      healthcheck_timeout: 0s\n",
        "      healthcheck_interval: 2s\n      healthcheck_timeout: 3s\n",
    ] {
        let error =
            load_text_with_files(&peer(failover), &[("peer-token", "peer-secret")]).unwrap_err();
        assert_eq!(error.code, CODE_CONFIG_INVALID);
        assert!(error.message.contains("healthcheck_timeout"), "{error}");
    }
}

#[test]
fn default_ack_batch_is_at_most_a_quarter_of_the_buffer() {
    for buffer in ["128KiB", "2MiB", "4MiB", "16MiB"] {
        let text = format!("{MINIMAL}transport:\n  buffer_per_direction: {buffer}\n");
        let cfg = load_text(&text).unwrap();
        assert!(
            cfg.transport.ack_batch_bytes * 4 <= cfg.transport.buffer_per_direction,
            "buffer={buffer}, ack_batch_bytes={}, buffer_per_direction={}",
            cfg.transport.ack_batch_bytes,
            cfg.transport.buffer_per_direction
        );
    }
}

#[cfg(feature = "tls")]
#[test]
fn http_tls_certificate_is_loaded_relative_to_config_dir() {
    let tls = "  listen: \"127.0.0.1:18080\"\n  tls:\n    enabled: true\n    cert_file: server.pem\n    key_file: server.key\n";
    let text = MINIMAL.replace("  listen: \"127.0.0.1:18080\"\n", tls);
    let error = load_text(&text).unwrap_err();
    assert_eq!(error.code, CODE_TLS);
    assert!(
        error.message.starts_with("http.tls certificate/key: open ")
            && error
                .message
                .ends_with("server.pem: no such file or directory"),
        "{error}"
    );
    // Offline check-config does not read TLS files.
    let dir = std::env::temp_dir().join(format!("dbbcfg-{}", crate::util::random_hex(6).unwrap()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("inbound-token"), "abc").unwrap();
    std::fs::write(dir.join("cfg.yaml"), &text).unwrap();
    load_with_options(&dir.join("cfg.yaml"), true).unwrap();
    // Relative paths resolve against the configuration directory.
    let testdata = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/net/testdata");
    let cert = std::fs::read(testdata.join("localhost-cert.pem")).unwrap();
    let key = std::fs::read(testdata.join("localhost-key.pem")).unwrap();
    let cert = String::from_utf8(cert).unwrap();
    let key = String::from_utf8(key).unwrap();
    let cfg = load_text_with_files(&text, &[("server.pem", &cert), ("server.key", &key)]).unwrap();
    let cert_path = cfg.http.tls.cert_file.as_ref().unwrap();
    assert!(cert_path.is_absolute() && cert_path.ends_with("server.pem"));
    // A key that is not a key is also a DBB-CFG-004 load error.
    let error =
        load_text_with_files(&text, &[("server.pem", &cert), ("server.key", "junk")]).unwrap_err();
    assert_eq!(error.code, CODE_TLS, "{error}");
}

#[test]
fn acl_without_targets_section_is_not_checked_like_spec() {
    let dir = std::env::temp_dir().join(format!("dbbcfg-{}", crate::util::random_hex(6).unwrap()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("cfg.yaml");
    std::fs::write(
        &path,
        "node:\n  id: n\nauth:\n  inbound_peers:\n    - {id: A, token_envs: [DBB_ACL_NO_TARGETS], allowed_targets: [db]}\n",
    )
    .unwrap();
    let cfg = load_with_options(&path, true).unwrap();
    assert!(
        cfg.warnings
            .iter()
            .any(|w| w.contains("http.enabled is false")),
        "{:?}",
        cfg.warnings
    );
    std::fs::write(
        &path,
        "node:\n  id: n\ntargets: {}\nauth:\n  inbound_peers:\n    - {id: A, token_envs: [DBB_ACL_NO_TARGETS], allowed_targets: [db]}\n",
    )
    .unwrap();
    let error = load_with_options(&path, true).unwrap_err();
    assert_eq!(error.message, "unknown ACL target \"db\"");
    std::fs::remove_dir_all(dir).unwrap();
}
