use std::path::{Path, PathBuf};
use std::time::Duration;

use super::*;

const TEST_TOKEN: &str = "test-test-token-0123456789abcdef";

fn test_peer_config(url: &str, tls: &str, extra: &str) -> String {
    format!(
        "node: {{id: A}}\npeers:\n  - id: B\n    expected_node_id: B\n    credential_ref: B\n    token_env: DBB_TEST_TOKEN\n    endpoints: [{{id: e, url: {url:?}, priority: 1}}]\n{tls}\n{extra}"
    )
}

const EGRESS_CONFIG: &str = "node: {id: B}\nhttp: {enabled: true, listen: '127.0.0.1:18080'}\ntargets: {db: {address: '127.0.0.1:3306', allowed_cidrs: ['127.0.0.1/32']}}\n";

fn scratch() -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("dbb-gocfg-{}", crate::util::random_hex(8).unwrap()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn load_env(body: &str, env: &[(&str, &str)], offline: bool) -> Result<Config> {
    let tag = crate::util::random_hex(5).unwrap().to_ascii_uppercase();
    let rename = |s: &str| s.replace("DBB_TEST_", &format!("DBB_T{tag}_"));
    std::env::set_var(rename("DBB_TEST_TOKEN"), TEST_TOKEN);
    for (k, v) in env {
        std::env::set_var(rename(k), v);
    }
    let path = scratch().join("peer.yaml");
    std::fs::write(&path, rename(body)).unwrap();
    load_with_options(&path, offline).map_err(|mut e| {
        e.message = e.message.replace(&format!("DBB_T{tag}_"), "DBB_TEST_");
        e
    })
}

fn test_load(body: &str) -> Result<Config> {
    load_env(body, &[], false)
}

fn has_warning(cfg: &Config, fragment: &str) -> bool {
    cfg.warnings.iter().any(|w| w.contains(fragment))
}

#[cfg(feature = "tls")]
fn test_certificate_pair() -> (String, String) {
    let dir = scratch();
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    std::fs::write(&cert, include_str!("../net/testdata/localhost-cert.pem")).unwrap();
    std::fs::write(&key, include_str!("../net/testdata/localhost-key.pem")).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    (
        cert.to_string_lossy().into_owned(),
        key.to_string_lossy().into_owned(),
    )
}

#[cfg(feature = "tls")]
#[test]
fn spec_float_durations() {
    let cfg = test_load(&test_peer_config(
        "https://b.example.invalid",
        "",
        "transport: {heartbeat: 1.5, failure_detect_timeout: 4.5}\n",
    ))
    .unwrap();
    assert_eq!(cfg.transport.heartbeat, Duration::from_millis(1500));
    for bad in [
        ".nan",
        ".inf",
        "-.inf",
        "-0.5",
        "1e10",
        "1.7976931348623157e308",
    ] {
        let body = test_peer_config(
            "https://b.example.invalid",
            "",
            &format!("transport: {{heartbeat: {bad}}}\n"),
        );
        assert!(test_load(&body).is_err(), "heartbeat {bad} accepted");
    }
    for (value, want) in [("0.5", 500), ("10.9", 10_900)] {
        let body = test_peer_config(
            "https://b.example.invalid",
            "",
            &format!("transport: {{heartbeat: 30s, failure_detect_timeout: 90s, ack_max_delay: {value}}}\n"),
        );
        assert_eq!(
            test_load(&body).unwrap().transport.ack_max_delay,
            Duration::from_millis(want)
        );
    }
}

#[cfg(feature = "tls")]
#[test]
fn spec_reload_interval_bounds() {
    for (value, ok, want) in [
        ("", true, 5_000),
        ("1s", true, 1_000),
        ("999ms", false, 0),
        ("1ns", false, 0),
    ] {
        let extra = if value.is_empty() {
            String::new()
        } else {
            format!("auth: {{reload_interval: {value}}}\n")
        };
        let got = test_load(&test_peer_config("https://b.example.invalid", "", &extra));
        assert_eq!(
            got.is_ok(),
            ok,
            "reload_interval {value:?}: {:?}",
            got.as_ref().err().map(|e| &e.message)
        );
        if ok {
            assert_eq!(
                got.unwrap().auth_reload_interval,
                Duration::from_millis(want)
            );
        }
    }
}

#[cfg(feature = "tls")]
#[test]
fn spec_endpoint_url_rules() {
    for (url, ok) in [
        ("https://b.example.invalid", true),
        ("https://b.example.invalid:8443", true),
        ("https://b.example.invalid:65535", true),
        ("https://b.example.invalid/", false),
        ("https://b.example.invalid:99999", false),
        ("https://b.example.invalid:0", false),
        ("https://b.example.invalid:", false),
        ("https://b.example.invalid/?", false),
        ("http://127.0.0.2:18080", true),
        ("http://localhost:18080", true),
        ("http://[::1]:18080", true),
        ("http://10.0.0.1:18080", false),
    ] {
        let got = test_load(&test_peer_config(url, "", ""));
        assert_eq!(
            got.is_ok(),
            ok,
            "url {url}: {:?}",
            got.err().map(|e| e.message)
        );
    }
}

#[test]
fn spec_expected_node_id_must_differ_from_self() {
    let body = test_peer_config("http://127.0.0.1:18080", "", "").replacen(
        "expected_node_id: B",
        "expected_node_id: A",
        1,
    );
    let e = test_load(&body).unwrap_err();
    assert!(e.message.contains("expected_node_id"), "{}", e.message);
}

#[test]
fn spec_http_listen_loopback_consistency() {
    for (listen, ok) in [
        ("localhost:18080", true),
        ("127.0.0.2:18080", true),
        ("[::1]:18080", true),
        ("0.0.0.0:18080", false),
        ("10.1.2.3:18080", false),
    ] {
        let body = format!("node: {{id: A}}\nhttp: {{enabled: true, listen: {listen:?}}}\n");
        assert_eq!(test_load(&body).is_ok(), ok, "http.listen {listen}");
    }
}

#[test]
fn spec_admin_listen_requires_opt_in_for_remote() {
    for (admin, ok) in [
        ("{enabled: true}", true),
        ("{enabled: true, listen: '127.0.0.1:9080'}", true),
        ("{enabled: true, listen: 'localhost:9080'}", true),
        ("{enabled: true, listen: '0.0.0.0:9080'}", false),
        ("{enabled: true, listen: '10.0.0.5:9080'}", false),
        (
            "{enabled: true, listen: '10.0.0.5:9080', allow_remote: true}",
            true,
        ),
    ] {
        let got = test_load(&format!("node: {{id: A}}\nadmin: {admin}\n"));
        assert_eq!(
            got.is_ok(),
            ok,
            "admin {admin}: {:?}",
            got.err().map(|e| e.message)
        );
    }
    let cfg = test_load("node: {id: A}\nadmin: {enabled: true}\n").unwrap();
    assert_eq!(cfg.admin.listen, "127.0.0.1:18090");
}

#[test]
fn spec_admin_default_does_not_collide_with_generated_pair() {
    let mut o = crate::cli::genconfig::PairOptions::default();
    for listen in [&o.a.http_listen, &o.b.http_listen, &o.a.listen, &o.b.listen] {
        assert_ne!(listen, "127.0.0.1:18090");
    }
    o.output_dir = scratch().to_string_lossy().into_owned();
    let files = crate::cli::genconfig::generate_pair(&o).unwrap();
    let a = load(&files.config_a).unwrap();
    let b = load(&files.config_b).unwrap();
    assert!(a.admin.enabled && b.admin.enabled);
    assert_ne!(a.admin.listen, b.admin.listen);
    assert_eq!(a.admin.listen, "127.0.0.1:18090");
}

#[cfg(feature = "tls")]
#[test]
fn spec_tls_skip_verify_requires_opt_in() {
    for (url, tls, ok) in [
        (
            "https://b.example.invalid",
            "    tls: {verify: false}",
            false,
        ),
        (
            "https://b.example.invalid",
            "    tls: {verify: false, allow_insecure_skip_verify: true}",
            true,
        ),
        ("https://127.0.0.1:8443", "    tls: {verify: false}", true),
        ("https://localhost:8443", "    tls: {verify: false}", true),
        ("https://b.example.invalid", "    tls: {verify: true}", true),
    ] {
        let got = test_load(&test_peer_config(url, tls, ""));
        assert_eq!(
            got.is_ok(),
            ok,
            "{url} {tls}: {:?}",
            got.err().map(|e| e.message)
        );
    }
}

#[cfg(feature = "tls")]
#[test]
fn spec_tls_ca_file() {
    let (cert, key) = test_certificate_pair();
    let cfg = test_load(&test_peer_config(
        "https://b.example.invalid",
        &format!("    tls: {{ca_file: {cert}}}"),
        "",
    ))
    .unwrap();
    assert_eq!(cfg.peers[0].tls.ca_file.as_deref(), Some(Path::new(&cert)));
    for tls in [
        format!("    tls: {{ca_file: {key}}}"),
        "    tls: {ca_file: /definitely/missing/ca.pem}".to_string(),
        format!("    tls: {{ca_file: {cert}, verify: false, allow_insecure_skip_verify: true}}"),
    ] {
        assert!(
            test_load(&test_peer_config("https://b.example.invalid", &tls, "")).is_err(),
            "accepted {tls}"
        );
    }
}

#[test]
fn spec_inbound_quota_partitions_global_limit() {
    let base = "node: {id: B}\ntargets: {db: {address: '127.0.0.1:3306', allowed_cidrs: ['127.0.0.1/32']}}\n";
    let two = |limits: &str, a: &str, b: &str| {
        format!("{base}{limits}auth:\n  inbound_peers:\n    - {{id: A, token_envs: [DBB_TEST_TOKEN], allowed_targets: [db]{a}}}\n    - {{id: C, token_envs: [DBB_TEST_TOKEN_C], allowed_targets: [db]{b}}}\n")
    };
    let env = [("DBB_TEST_TOKEN_C", "test-test-token-c-0123456789abcdef")];
    for (body, ok) in [
        (two("", "", ""), false),
        (two("", ", max_sessions: 200", ", max_sessions: 1"), false),
        (two("", ", max_sessions: 100", ", max_sessions: 100"), true),
        (
            two(
                "limits: {max_sessions: 400}\ntransport: {metadata_limit: 64MiB}\n",
                "",
                "",
            ),
            true,
        ),
        (two("", "", ", enabled: false"), true),
    ] {
        let got = load_env(&body, &env, false);
        assert_eq!(
            got.is_ok(),
            ok,
            "{body}: {:?}",
            got.err().map(|e| e.message)
        );
    }
    let single = format!("{base}auth:\n  inbound_peers:\n    - {{id: A, token_envs: [DBB_TEST_TOKEN], allowed_targets: [db]}}\n");
    test_load(&single).unwrap();
}

#[test]
fn spec_short_token_warning() {
    let cfg = test_load(&test_peer_config("http://127.0.0.1:18080", "", "")).unwrap();
    assert!(cfg.warnings.is_empty(), "{:?}", cfg.warnings);
    let body = test_peer_config("http://127.0.0.1:18080", "", "").replacen(
        "DBB_TEST_TOKEN",
        "DBB_TEST_SHORT",
        1,
    );
    let cfg = load_env(&body, &[("DBB_TEST_SHORT", "short")], false).unwrap();
    assert_eq!(cfg.warnings.len(), 1, "{:?}", cfg.warnings);
    assert!(cfg.warnings[0].contains("shorter"));
}

#[test]
fn spec_listen_overlap() {
    for (a, b, want) in [
        ("0.0.0.0", "localhost", true),
        ("localhost", "0.0.0.0", true),
        ("localhost", "127.0.0.2", false),
        ("localhost", "127.0.0.1", true),
        ("localhost", "::1", true),
        ("0.0.0.0", "::1", false),
        ("::", "127.0.0.1", true),
        ("", "10.0.0.1", true),
        ("10.0.0.1", "10.0.0.2", false),
        ("[::1]", "::1", true),
        ("db.local", "db.local", true),
        ("db.local", "127.0.0.1", false),
        ("db.local", "0.0.0.0", true),
    ] {
        assert_eq!(
            super::build::listen_hosts_overlap(a, b),
            want,
            "overlap({a:?},{b:?})"
        );
    }
    let body = EGRESS_CONFIG.replacen(
        "listen: '127.0.0.1:18080'",
        "listen: '0.0.0.0:18080', allow_insecure_listen: true",
        1,
    ) + "admin: {enabled: true, listen: 'localhost:18080'}\n";
    let e = test_load(&body).unwrap_err();
    assert!(e.message.contains("conflicting"), "{}", e.message);
    assert_eq!(e.code, CODE_LISTEN);
    let body = (EGRESS_CONFIG.to_string() + "admin: {enabled: true, listen: 'localhost:18081'}\n")
        .replacen("127.0.0.1:18080", "127.0.0.2:18081", 1);
    test_load(&body).unwrap();
}

#[test]
fn spec_hostname_target_remote_listener_warn() {
    let cfg = test_load(&EGRESS_CONFIG.replacen(
        "address: '127.0.0.1:3306', allowed_cidrs: ['127.0.0.1/32']",
        "address: 'db.internal:3306'",
        1,
    ))
    .unwrap();
    assert!(has_warning(&cfg, "DNS rebinding"));
    let cfg = test_load(&test_peer_config(
        "http://127.0.0.1:18080",
        "",
        "listeners: [{id: l, listen: '0.0.0.0:13306', peer: B, target: db}]\n",
    ))
    .unwrap();
    assert!(has_warning(&cfg, "not a loopback address"));
    let cfg = test_load(&test_peer_config(
        "http://127.0.0.1:18080",
        "",
        "listeners: [{id: l, listen: '127.0.0.1:13306', peer: B, target: db}]\n",
    ))
    .unwrap();
    assert!(!has_warning(&cfg, "not a loopback address"));
}

#[test]
fn spec_credential_errors_have_context() {
    let body = test_peer_config("http://127.0.0.1:18080", "", "").replacen(
        "DBB_TEST_TOKEN",
        "DBB_TEST_UNSET_VAR",
        1,
    );
    let e = test_load(&body).unwrap_err();
    assert!(
        e.message.contains("DBB_TEST_UNSET_VAR") && e.message.contains("peer[B]"),
        "{}",
        e.message
    );
    let e = test_load(&format!("{EGRESS_CONFIG}auth:\n  inbound_peers:\n    - {{id: plant-a, token_envs: [DBB_TEST_UNSET_VAR], allowed_targets: [db]}}\n")).unwrap_err();
    assert!(
        e.message.contains("inbound_peers[plant-a]") && e.message.contains("DBB_TEST_UNSET_VAR"),
        "{}",
        e.message
    );
    let bad = format!("bad token {TEST_TOKEN}");
    let body = test_peer_config("http://127.0.0.1:18080", "", "").replacen(
        "DBB_TEST_TOKEN",
        "DBB_TEST_BAD",
        1,
    );
    let e = load_env(&body, &[("DBB_TEST_BAD", &bad)], false).unwrap_err();
    assert!(
        !e.message.contains(TEST_TOKEN),
        "token leaked: {}",
        e.message
    );
}

#[test]
fn spec_token_permission_warning() {
    use std::os::unix::fs::PermissionsExt;
    let tok = scratch().join("t.tok");
    std::fs::write(&tok, format!("{TEST_TOKEN}\n")).unwrap();
    std::fs::set_permissions(&tok, std::fs::Permissions::from_mode(0o600)).unwrap();
    let body = test_peer_config("http://127.0.0.1:18080", "", "").replacen(
        "token_env: DBB_TEST_TOKEN",
        &format!("token_file: {}", tok.display()),
        1,
    );
    let cfg = test_load(&body).unwrap();
    assert!(!has_warning(&cfg, "secret file"), "{:?}", cfg.warnings);
    std::fs::set_permissions(&tok, std::fs::Permissions::from_mode(0o644)).unwrap();
    let cfg = test_load(&body).unwrap();
    assert!(has_warning(&cfg, "secret file"), "{:?}", cfg.warnings);
}

#[test]
fn spec_derived_defaults() {
    let cfg = test_load(&test_peer_config(
        "http://127.0.0.1:18080",
        "",
        "transport: {heartbeat: 20s}\n",
    ))
    .unwrap();
    assert_eq!(
        cfg.transport.failure_detect_timeout,
        Duration::from_secs(60)
    );
    let cfg = test_load(&test_peer_config(
        "http://127.0.0.1:18080",
        "",
        "transport: {buffer_per_direction: 1MiB}\n",
    ))
    .unwrap();
    assert_eq!(cfg.transport.up_window_bytes, 1 << 20);
    assert_eq!(cfg.transport.ack_batch_bytes, 256 << 10);
    assert!(test_load(&test_peer_config(
        "http://127.0.0.1:18080",
        "",
        "transport: {heartbeat: 20s, failure_detect_timeout: 30s}\n"
    ))
    .is_err());
}

#[test]
fn spec_idle_and_unused_warnings() {
    let cfg = test_load("node: {id: A}\n").unwrap();
    assert!(has_warning(&cfg, "nothing to do"));
    let cfg = test_load(&EGRESS_CONFIG.replacen("enabled: true", "enabled: false", 1)).unwrap();
    assert!(
        has_warning(&cfg, "targets are configured"),
        "{:?}",
        cfg.warnings
    );
    let cfg =
        test_load(&EGRESS_CONFIG.replacen("node: {id: B}", "node: {id: 'bad idé x'}", 1)).unwrap();
    assert!(has_warning(&cfg, "node id"), "{:?}", cfg.warnings);
    test_load(&format!("{EGRESS_CONFIG}auth:\n  inbound_peers:\n    - {{id: A, token_envs: [DBB_TEST_TOKEN], allowed_targets: [db]}}\nlimits: {{max_sessions: 10}}\n")).unwrap();
    assert!(
        test_load(&EGRESS_CONFIG.replacen("targets: {db:", "targets: {'':", 1)).is_err(),
        "empty target name accepted"
    );
    let cfg = test_load(&format!(
        "{EGRESS_CONFIG}admin: {{enabled: true, listen: '0.0.0.0:18090', allow_remote: true}}\n"
    ))
    .unwrap();
    assert!(has_warning(&cfg, "without TLS or authentication"));
}

#[test]
fn spec_split_insecure_switches() {
    let remote = EGRESS_CONFIG.replacen("127.0.0.1:18080", "0.0.0.0:18080", 1);
    assert!(test_load(&remote).is_err());
    let cfg = test_load(&remote.replacen(
        "listen: '0.0.0.0:18080'",
        "listen: '0.0.0.0:18080', allow_insecure_listen: true",
        1,
    ))
    .unwrap();
    assert!(has_warning(&cfg, "plaintext HTTP"));
    assert!(test_load(&test_peer_config("http://10.0.0.5:18080", "", "")).is_err());
    let body = test_peer_config("http://10.0.0.5:18080", "", "").replacen(
        "    credential_ref: B\n",
        "    credential_ref: B\n    allow_insecure_http: true\n",
        1,
    );
    test_load(&body).unwrap();
}

#[test]
fn spec_generator_token_limit() {
    let dir = scratch();
    let token = dir.join("big.token");
    std::fs::write(&token, "a".repeat(9 << 10) + "\n").unwrap();
    let o = crate::cli::genconfig::GenerateOptions {
        output: dir.join("peer.yaml").to_string_lossy().into_owned(),
        role: "egress".into(),
        node_id: "A".into(),
        peer_id: "B".into(),
        listen: "127.0.0.1:13306".into(),
        http_listen: "127.0.0.1:18080".into(),
        target_id: "mysql".into(),
        target_address: "127.0.0.1:3306".into(),
        protocol: "auto".into(),
        recovery: true,
        max_sessions: 200,
        token_file: token.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let e = crate::cli::genconfig::generate(o).unwrap_err();
    assert!(e.message.contains("larger than"), "{}", e.message);
}

#[test]
fn spec_reload_interval_numeric_seconds() {
    let cfg = test_load(&test_peer_config(
        "http://127.0.0.1:18080",
        "",
        "auth: {reload_interval: 5}\n",
    ))
    .unwrap();
    assert_eq!(cfg.auth_reload_interval, Duration::from_secs(5));
    assert!(test_load(&test_peer_config(
        "http://127.0.0.1:18080",
        "",
        "auth: {reload_interval: -1}\n"
    ))
    .is_err());
}

#[test]
fn spec_sessions_fit_metadata_budget() {
    let e = test_load(&format!("{EGRESS_CONFIG}limits: {{max_sessions: 1000}}\n")).unwrap_err();
    assert!(e.message.contains("metadata_limit"), "{}", e.message);
    test_load(&format!(
        "{EGRESS_CONFIG}limits: {{max_sessions: 1000}}\ntransport: {{metadata_limit: 128MiB}}\n"
    ))
    .unwrap();
    let o = crate::cli::genconfig::PairOptions {
        output_dir: scratch().to_string_lossy().into_owned(),
        max_sessions: 1000,
        ..Default::default()
    };
    crate::cli::genconfig::generate_pair(&o).unwrap();
}

#[cfg(feature = "tls")]
#[test]
fn spec_offline_validation() {
    let body = "node: {id: B}
http: {enabled: true, listen: '0.0.0.0:8443', tls: {enabled: true, cert_file: /nonexistent/b.crt, key_file: /nonexistent/b.key}}
targets: {db: {address: '127.0.0.1:3306', allowed_cidrs: ['127.0.0.1/32']}}
auth:
  inbound_peers:
    - {id: A, token_envs: [DBB_TEST_OFFLINE_UNSET], allowed_targets: [db]}
peers:
  - {id: A, expected_node_id: A, credential_ref: A, token_file: /nonexistent/t, tls: {ca_file: /nonexistent/ca.pem}, endpoints: [{id: e, url: 'https://a.example.invalid:8443'}]}
";
    let body = body.replace("node: {id: B}", "node: {id: N}");
    assert!(
        load_env(&body, &[], false).is_err(),
        "online validation passed without secrets"
    );
    load_env(&body, &[], true).unwrap();
    let bad = body.replacen("allowed_targets: [db]", "allowed_targets: [missing]", 1);
    assert!(
        load_env(&bad, &[], true).is_err(),
        "offline validation skipped cross references"
    );
}

#[test]
fn spec_tombstone_ttl_boundary() {
    for (value, valid) in [
        ("1ms", false),
        ("9m59s", false),
        ("10m", true),
        ("11m", true),
    ] {
        let got = test_load(&format!(
            "node: {{id: A}}\ntransport: {{idempotency_tombstone_ttl: {value}}}\n"
        ));
        assert_eq!(got.is_ok(), valid, "ttl={value}");
        if valid {
            assert!(got.unwrap().transport.idempotency_tombstone_ttl >= Duration::from_secs(600));
        }
    }
}

#[test]
fn spec_ip_target_without_cidrs_accepted() {
    let cfg = test_load("node: {id: B}\ntargets: {db: {address: '127.0.0.1:3306'}}\n").unwrap();
    assert!(!has_warning(&cfg, "DNS rebinding"));
}

fn credentials_config(credentials: &str) -> Result<Config> {
    let dir = scratch();
    let tag = crate::util::random_hex(5).unwrap().to_ascii_uppercase();
    let name = format!("DBB_T{tag}_AUTH");
    std::env::set_var(&name, "test-credential-0123456789");
    std::fs::write(
        dir.join("auth.yaml"),
        credentials.replace("DBB_TEST_AUTH", &name),
    )
    .unwrap();
    let path = dir.join("cfg.yaml");
    std::fs::write(
        &path,
        "node: {id: B}\nhttp: {enabled: true, listen: '127.0.0.1:18080'}\ntargets: {db: {address: '127.0.0.1:3306'}}\nauth: {credentials_file: auth.yaml}\n",
    )
    .unwrap();
    load(&path)
}

#[test]
fn spec_credentials_require_positive_quota() {
    let e = credentials_config("version: 1\ninbound_peers:\n  - id: A\n    token_envs: [DBB_TEST_AUTH]\n    allowed_targets: [db]\n    max_sessions: 0\n").unwrap_err();
    assert!(e.message.contains("max_sessions"), "{}", e.message);
}

#[test]
fn spec_omitted_credential_quota_is_bounded() {
    let cfg = credentials_config("version: 1\ninbound_peers:\n- id: A\n  token_envs: [DBB_TEST_AUTH]\n  allowed_targets: [db]\n").unwrap();
    assert_eq!(cfg.inbound[0].max_sessions, 200);
}

#[test]
fn spec_check_config_validates_tls_files() {
    let e = test_load("node: {id: B}\nhttp:\n  enabled: true\n  tls: {enabled: true, cert_file: missing.crt, key_file: missing.key}\n").unwrap_err();
    assert_eq!(e.code, CODE_TLS, "{}", e.message);
}

#[test]
fn spec_user_agent_default_and_validation() {
    assert_eq!(
        DEFAULT_USER_AGENT,
        format!("DBBridge/{}", crate::wire::PROTOCOL_VERSION)
    );
    for ok in [
        "DBBridge/1.x",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "curl/8.0",
    ] {
        super::sections::valid_user_agent(ok).unwrap();
    }
    for bad in [
        "a\r\nX-Evil: 1".to_string(),
        "tab\there".into(),
        " lead".into(),
        "trail ".into(),
        "caf\u{e9}".into(),
        "a".repeat(257),
    ] {
        assert!(
            super::sections::valid_user_agent(&bad).is_err(),
            "{bad:?} accepted"
        );
    }
    let cfg = test_load("node: {id: A}\n").unwrap();
    assert_eq!(cfg.transport.user_agent, DEFAULT_USER_AGENT);
    let cfg = test_load("node: {id: A}\ntransport: {user_agent: 'curl/8.0'}\n").unwrap();
    assert_eq!(cfg.transport.user_agent, "curl/8.0");
    assert!(test_load("node: {id: A}\ntransport: {user_agent: ' x'}\n").is_err());
}

#[test]
fn spec_peer_dial_timeout() {
    let cfg = test_load(&test_peer_config(
        "http://127.0.0.1:18080",
        "",
        "transport: {dial_timeout: 3s}\n",
    ))
    .unwrap();
    assert_eq!(cfg.transport.peer_dial_timeout, Duration::from_secs(3));
    let cfg = test_load(&test_peer_config(
        "http://127.0.0.1:18080",
        "",
        "transport: {dial_timeout: 3s, peer_dial_timeout: 750ms}\n",
    ))
    .unwrap();
    assert_eq!(cfg.transport.peer_dial_timeout, Duration::from_millis(750));
    assert_eq!(cfg.transport.dial_timeout, Duration::from_secs(3));
    assert!(test_load(&test_peer_config(
        "http://127.0.0.1:18080",
        "",
        "transport: {peer_dial_timeout: -1s}\n"
    ))
    .is_err());
}

#[test]
fn spec_warns_when_grace_cannot_outlast_cooldown_of_only_carrier() {
    let warn = |protocol: &str, grace: &str| -> usize {
        let cfg = test_load(&format!(
            "node: {{id: A}}\ntransport: {{protocol: {protocol}, recovery: {{enabled: true, grace: {grace}}}}}\npeers:\n  - {{id: B, expected_node_id: B, credential_ref: B, token_env: DBB_TEST_TOKEN, endpoints: [{{id: e, url: 'http://127.0.0.1:8443'}}]}}\n"
        ))
        .unwrap();
        cfg.warnings
            .iter()
            .filter(|w| w.contains("failover.cooldown"))
            .count()
    };
    assert_eq!(warn("ws", "8s"), 1);
    assert_eq!(warn("auto", "8s"), 0);
    assert_eq!(warn("http-sse", "30s"), 0);
}

#[test]
fn spec_transport_timeouts_and_proxy_keys() {
    let cfg = test_load("node: {id: A}\ntransport: {up_request_timeout: 10s, socket_write_timeout: 20s, use_environment_proxy: true, ws: {write_idle_timeout: 5s}}\n").unwrap();
    assert_eq!(cfg.transport.up_request_timeout, Duration::from_secs(10));
    assert_eq!(cfg.transport.socket_write_timeout, Duration::from_secs(20));
    assert_eq!(cfg.transport.ws_write_idle_timeout, Duration::from_secs(5));
    assert!(cfg.transport.use_environment_proxy);
    for bad in [
        "up_request_timeout: 0",
        "socket_write_timeout: 0s",
        "ws: {write_idle_timeout: 0}",
    ] {
        let e = test_load(&format!("node: {{id: A}}\ntransport: {{{bad}}}\n")).unwrap_err();
        assert!(e.message.contains("must be > 0"), "{bad}: {}", e.message);
    }
}

#[path = "spec_reverse_tests.rs"]
mod reverse_tests;

#[path = "spec_token_tests.rs"]
mod token_tests;

#[path = "spec_defaults_tests.rs"]
mod defaults_tests;

#[path = "spec_matrix_tests.rs"]
mod matrix_tests;
