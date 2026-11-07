use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::*;

const TEST_TOKEN: &str = "test-test-token-0123456789abcdef";

fn scratch() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "dbb-gocfg3-{}",
        crate::util::random_hex(8).unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn tag() -> String {
    crate::util::random_hex(5).unwrap().to_ascii_uppercase()
}

fn test_load_env(body: &str, env: &[(&str, &str)]) -> Result<Config> {
    let tag = tag();
    let rename = |s: &str| s.replace("DBB_TEST_", &format!("DBB_C3{tag}_"));
    std::env::set_var(rename("DBB_TEST_TOKEN"), TEST_TOKEN);
    for (k, v) in env {
        std::env::set_var(rename(k), v);
    }
    let path = scratch().join("peer.yaml");
    std::fs::write(&path, rename(body)).unwrap();
    load(&path).map_err(|mut e| {
        e.message = e.message.replace(&format!("DBB_C3{tag}_"), "DBB_TEST_");
        e
    })
}

fn test_load(body: &str) -> Result<Config> {
    test_load_env(body, &[])
}

fn test_peer_config(url: &str, tls: &str, extra: &str) -> String {
    format!(
        "node: {{id: A}}\npeers:\n  - id: B\n    expected_node_id: B\n    credential_ref: B\n    token_env: DBB_TEST_TOKEN\n    endpoints: [{{id: e, url: {url:?}, priority: 1}}]\n{tls}\n{extra}"
    )
}

fn load_body(body: &str) -> Result<Config> {
    let path = scratch().join("config.yaml");
    std::fs::write(&path, body).unwrap();
    load(&path)
}

#[test]
fn spec_config_validation_rules() {
    let invalid_cidr = "\nnode:\n  id: node-1\ntargets:\n  t1:\n    address: \"127.0.0.1:3306\"\n    allowed_cidrs: [\"not-a-valid-cidr\"]\npeers:\n  - id: p1\n    endpoints:\n      - id: ep1\n        url: \"http://127.0.0.1:18080\"\n";
    assert!(
        load_body(invalid_cidr).is_err(),
        "expected config load to fail on invalid CIDR"
    );
    let remote_http = "\nnode:\n  id: node-1\npeers:\n  - id: p1\n    endpoints:\n      - id: ep1\n        url: \"http://example.com:18080\"\n";
    assert!(
        load_body(remote_http).is_err(),
        "expected config load to reject remote plaintext http"
    );
    let zero_heartbeat = "\nnode:\n  id: node-1\npeers:\n  - id: p1\n    endpoints:\n      - id: ep1\n        url: \"http://127.0.0.1:18080\"\ntransport:\n  heartbeat: 0s\n";
    assert!(
        load_body(zero_heartbeat).is_err(),
        "expected config load to reject 0s heartbeat"
    );
}

#[test]
fn spec_config_contracts() {
    let t = tag();
    let env = format!("DBB_C3{t}_CONTRACT_TOKEN");
    std::env::set_var(&env, TEST_TOKEN);
    let dir = scratch();
    let cases: Vec<(&str, String)> = vec![
        (
            "missing_outbound_credential",
            "peers:\n  - {id: b, expected_node_id: b, endpoints: [{id: e, url: 'http://127.0.0.1:18081'}]}\n".into(),
        ),
        (
            "endpoint_with_credentials_path_query_fragment",
            format!("peers:\n  - {{id: b, token_env: {env}, endpoints: [{{id: e, url: 'http://user:pass@127.0.0.1:18081/path?q=x#frag'}}]}}\n"),
        ),
        (
            "duplicate_inbound_identity",
            format!("targets: {{db: {{address: '127.0.0.1:3306'}}}}\nauth:\n  inbound_peers:\n    - {{id: a, token_envs: [{env}], allowed_targets: [db]}}\n    - {{id: a, token_envs: [{env}], allowed_targets: [db]}}\n"),
        ),
        ("negative_session_limit", "limits: {max_sessions: -1}\n".into()),
        (
            "peer_overrides_global_recovery_off",
            format!("transport: {{recovery: {{enabled: false}}}}\npeers:\n  - {{id: b, token_env: {env}, recovery: {{enabled: true}}, endpoints: [{{id: e, url: 'http://127.0.0.1:18081'}}]}}\n"),
        ),
        (
            "insufficient_codec_budget",
            "transport: {codec_buffer_limit: 1}\n".into(),
        ),
        (
            "missing_credentials_file",
            "auth: {credentials_file: /definitely/missing/credential.yaml}\n".into(),
        ),
    ];
    for (name, yaml) in cases {
        let path = dir.join(format!("{name}.yaml"));
        std::fs::write(&path, format!("node: {{id: a}}\n{yaml}")).unwrap();
        assert!(
            load_with_options(&path, true).is_err(),
            "{name}: invalid configuration accepted"
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}

const EGRESS_WITH_INBOUND: &str = "node: {id: B}\nhttp: {enabled: true, listen: \"127.0.0.1:0\"}\ntargets: {db: {network: tcp, address: \"127.0.0.1:3306\", allowed_cidrs: [\"127.0.0.1/32\"]}}\nlimits: {max_sessions: 10}\nauth:\n  inbound_peers:\n";

#[test]
fn spec_duplicate_token_rules() {
    test_load_env(
        &format!("{EGRESS_WITH_INBOUND}    - {{id: A, token_envs: [DBB_TEST_TOKEN, DBB_TEST_TOKEN_NEXT], allowed_targets: [db]}}\n"),
        &[("DBB_TEST_TOKEN_NEXT", TEST_TOKEN)],
    )
    .unwrap_or_else(|e| panic!("{}", e.message));
    let err = test_load_env(
        &format!("{EGRESS_WITH_INBOUND}    - {{id: A, token_envs: [DBB_TEST_TOKEN], allowed_targets: [db], max_sessions: 5}}\n    - {{id: C, token_envs: [DBB_TEST_TOKEN_NEXT], allowed_targets: [db], max_sessions: 5}}\n"),
        &[("DBB_TEST_TOKEN_NEXT", TEST_TOKEN)],
    )
    .expect_err("shared token accepted");
    assert!(
        err.message
            .contains("inbound peers A and C use the same token"),
        "shared token: {}",
        err.message
    );
}

#[test]
fn spec_strict_configuration_bounds() {
    let cases = [
        (
            "network",
            "targets:\n  db: {network: udp, address: '127.0.0.1:3306'}\n",
        ),
        (
            "target_port",
            "targets:\n  db: {network: tcp, address: '127.0.0.1:0'}\n",
        ),
        (
            "target_host",
            "targets:\n  db: {network: tcp, address: ':3306'}\n",
        ),
        (
            "overlap",
            "http: {enabled: true, listen: '0.0.0.0:8888'}\nadmin: {enabled: true, listen: '127.0.0.1:8888'}\n",
        ),
        (
            "receipt_capacity",
            "transport: {up_max_inflight_frames: 32, receipt_limit_per_session: 64}\n",
        ),
        ("unknown_key", "transport: {resume_max_retries: 5}\n"),
    ];
    for (name, yaml) in cases {
        assert!(
            load_body(&format!("node: {{id: A}}\n{yaml}")).is_err(),
            "{name}: invalid configuration accepted"
        );
    }
}

const INT_BIDI: &str = "listeners: [{id: l, listen: '127.0.0.1:13306', peer: B, target: db}]\nhttp: {enabled: true, listen: '127.0.0.1:18443', allow_insecure_listen: true}\ntargets: {db: {address: '127.0.0.1:3306', allowed_cidrs: ['127.0.0.1/32']}}\nauth: {inbound_peers: [{id: B, token_envs: [DBB_TEST_TOKEN], allowed_targets: [db]}]}\n";

#[test]
fn spec_bidirectional_reserve() {
    let url = if cfg!(feature = "tls") {
        "https://b.example.invalid"
    } else {
        "http://127.0.0.1:18081"
    };
    let cfg =
        test_load(&test_peer_config(url, "", INT_BIDI)).unwrap_or_else(|e| panic!("{}", e.message));
    let r = crate::resource::manager::ResourceManager::new(&cfg);
    let (s, m) = r.ingress_reserve();
    assert!(
        s == (r.sessions.limit() / 4).max(1) && m == r.metadata.limit() / 8,
        "reserve {s}/{m} (limits {}/{})",
        r.sessions.limit(),
        r.metadata.limit()
    );
    let mut egress = Vec::new();
    while let Some(lease) = r.try_egress_session() {
        egress.push(lease);
    }
    let free = r.sessions.limit() - r.sessions.used();
    let local = r.sessions.try_acquire(1);
    assert!(
        free == s && local.is_some(),
        "egress left {free} sessions, want {s}"
    );
    drop((egress, local));

    let cfg = test_load(&test_peer_config(
        url,
        "",
        "listeners: [{id: l, listen: '127.0.0.1:13306', peer: B, target: db}]\n",
    ))
    .unwrap_or_else(|e| panic!("{}", e.message));
    let r = crate::resource::manager::ResourceManager::new(&cfg);
    assert_eq!(r.ingress_reserve(), (0, 0), "ingress-only node reserved");
}

fn write(path: &Path, body: &str) {
    std::fs::write(path, body).unwrap();
}

fn authenticator(dir: &Path) -> crate::auth::Authenticator {
    let path = dir.join("peer.yaml");
    let mut cfg = load(&path).unwrap_or_else(|e| panic!("load: {}", e.message));
    cfg.path = path;
    crate::auth::Authenticator::new(Arc::new(cfg))
}

#[test]
fn spec_inline_reload_rejects_added_or_duplicate_peer() {
    let dir = scratch();
    let env = format!("DBB_C3{}_INLINE_TOK", tag());
    std::env::set_var(&env, "inline-token-0123456789abcdef");
    let base = format!("node:\n  id: A\npeers:\n  - id: B\n    expected_node_id: B\n    credential_ref: B\n    token_env: {env}\n    endpoints:\n      - id: e1\n        url: http://127.0.0.1:18080\n");
    write(&dir.join("peer.yaml"), &base);
    let src = authenticator(&dir);
    src.reload("request")
        .unwrap_or_else(|e| panic!("{}", e.message));
    let added = format!("{base}  - id: C\n    expected_node_id: C\n    credential_ref: C\n    token_env: {env}\n    endpoints:\n      - id: e1\n        url: http://127.0.0.1:18081\n");
    write(&dir.join("peer.yaml"), &added);
    assert!(
        src.reload("request").is_err(),
        "inline reload accepted a newly added peer without requiring a restart"
    );
    let dup = format!("{base}  - id: B\n    expected_node_id: B\n    credential_ref: B\n    token_env: {env}\n    endpoints:\n      - id: e1\n        url: http://127.0.0.1:18081\n");
    write(&dir.join("peer.yaml"), &dup);
    assert!(
        src.reload("request").is_err(),
        "inline reload accepted duplicate peer IDs"
    );
    assert!(src.outbound_token("B").is_some(), "previous snapshot lost");
    std::fs::remove_dir_all(&dir).ok();
}

const EGRESS_CREDS: &str = "node: {id: B}\nhttp: {enabled: true, listen: '127.0.0.1:18080'}\ntargets: {db: {address: '127.0.0.1:3306', allowed_cidrs: ['127.0.0.1/32']}}\nauth: {credentials_file: auth.yaml}\n";

#[test]
fn spec_snapshot_validation_shared_with_reload() {
    let dir = scratch();
    write(&dir.join("a.token"), TEST_TOKEN);
    write(&dir.join("c.token"), "another-token-0123456789");
    write(&dir.join("weak.token"), "short");
    let ok = "version: 1\ninbound_peers:\n  - {id: A, token_files: [a.token], allowed_targets: [db], max_sessions: 200}\n";
    write(&dir.join("auth.yaml"), ok);
    write(&dir.join("peer.yaml"), EGRESS_CREDS);
    let src = authenticator(&dir);
    src.reload("request")
        .unwrap_or_else(|e| panic!("valid snapshot rejected: {}", e.message));

    // A second peer with an omitted quota (counted as 200) is refused at
    // runtime exactly as it would be at startup.
    let bad = format!("{ok}  - {{id: C, token_files: [c.token], allowed_targets: [db]}}\n");
    write(&dir.join("auth.yaml"), &bad);
    let startup = load(&dir.join("peer.yaml")).expect_err("over-quota startup accepted");
    let reload = src
        .reload("request")
        .expect_err("over-quota reload accepted");
    for e in [&startup, &reload] {
        assert!(
            e.message.contains("exceeds limits.max_sessions"),
            "over-quota: {}",
            e.message
        );
    }
    assert_eq!(startup.message, reload.message);

    let unknown = "version: 1\ninbound_peers:\n  - {id: A, token_files: [a.token], allowed_targets: [nope], max_sessions: 1}\n";
    write(&dir.join("auth.yaml"), unknown);
    assert!(load(&dir.join("peer.yaml")).is_err());
    assert!(
        src.reload("request").is_err(),
        "unknown ACL target accepted"
    );

    let weak = "version: 1\ninbound_peers:\n  - {id: A, token_files: [weak.token], allowed_targets: [db], max_sessions: 1}\n";
    write(&dir.join("auth.yaml"), weak);
    let cfg = load(&dir.join("peer.yaml"))
        .unwrap_or_else(|e| panic!("weak token rejected: {}", e.message));
    assert!(
        !cfg.warnings.is_empty(),
        "weak token warning missing on reload"
    );
    src.reload("request")
        .unwrap_or_else(|e| panic!("weak token reload rejected: {}", e.message));

    // A missing credential_ref names the reference.
    let refs = scratch();
    write(&refs.join("auth.yaml"), "version: 1\n");
    write(
        &refs.join("peer.yaml"),
        "node: {id: A}\nauth: {credentials_file: auth.yaml}\npeers:\n  - {id: B, expected_node_id: B, credential_ref: cred-b, endpoints: [{id: e, url: 'http://127.0.0.1:18080'}]}\n",
    );
    let err = load(&refs.join("peer.yaml")).expect_err("missing credential_ref accepted");
    assert!(err.message.contains("cred-b"), "{}", err.message);
    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&refs).ok();
}

#[test]
fn spec_credential_digest_tracks_tokens() {
    let dir = scratch();
    write(&dir.join("in.token"), "token-one-0123456789");
    write(&dir.join("out.token"), "out-0123456789abcdef");
    write(&dir.join("auth.yaml"), "version: 1\ninbound_peers:\n  - {id: A, token_files: [in.token], allowed_targets: [db], max_sessions: 1}\noutbound_peers:\n  - {id: B, token_file: out.token}\n");
    write(
        &dir.join("peer.yaml"),
        "node: {id: N}\nhttp: {enabled: true, listen: '127.0.0.1:18080'}\ntargets: {db: {address: '127.0.0.1:3306', allowed_cidrs: ['127.0.0.1/32']}}\nauth: {credentials_file: auth.yaml}\npeers:\n  - {id: B, expected_node_id: B, credential_ref: B, endpoints: [{id: e, url: 'http://127.0.0.1:18081'}]}\n",
    );
    let src = authenticator(&dir);
    assert!(!src.reload("request").unwrap(), "digest not deterministic");
    write(&dir.join("in.token"), "token-two-0123456789");
    assert!(
        src.reload("request").unwrap(),
        "inbound token rotation not reflected in the credential digest"
    );
    write(&dir.join("out.token"), "out-changed-0123456789");
    assert!(
        src.reload("request").unwrap(),
        "outbound token rotation not reflected in the credential digest"
    );
    assert_eq!(
        src.outbound_token("B").as_deref(),
        Some("out-changed-0123456789")
    );
    assert!(!src.reload("request").unwrap(), "digest not deterministic");
    std::fs::remove_dir_all(&dir).ok();
}
