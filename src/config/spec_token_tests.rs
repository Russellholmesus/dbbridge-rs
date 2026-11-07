use super::*;

/// Writes `files` into a fresh directory, sets `env` (names made unique by
/// the caller) and loads `peer.yaml` from it.
fn load_dir(files: &[(&str, &[u8])], offline: bool) -> (PathBuf, Result<Config>) {
    let dir = scratch();
    for (name, body) in files {
        std::fs::write(dir.join(name), body).unwrap();
    }
    let got = load_with_options(&dir.join("peer.yaml"), offline);
    (dir, got)
}

fn unique_env(prefix: &str) -> String {
    format!(
        "{prefix}_{}",
        crate::util::random_hex(5).unwrap().to_ascii_uppercase()
    )
}

#[test]
fn spec_yaml_alias_cannot_bypass_protocol_type() {
    let (_, got) = load_dir(
        &[(
            "peer.yaml",
            b"node:\n  id: &numeric 1.5\ntransport:\n  protocol_version: *numeric\n",
        )],
        false,
    );
    assert!(
        got.is_err(),
        "numeric YAML alias silently accepted as protocol string"
    );
}

#[test]
fn spec_token_validation_across_credential_sources() {
    let max = "x".repeat(8 << 10);
    let over = "x".repeat((8 << 10) + 1);
    let cases: [(&str, &str, bool); 8] = [
        ("ordinary", "a-safe-token_0123", true),
        ("empty", "", false),
        ("space", "has space", false),
        ("tab", "has\ttab", false),
        ("unicode-space", "has\u{a0}space", false),
        ("control", "has\u{1}control", false),
        ("oversized", &over, false),
        ("maximum", &max, true),
    ];
    for (name, token, valid) in cases {
        let env = unique_env("DBB_TEST_SOURCE_TOKEN");
        std::env::set_var(&env, token);
        let token_file = format!("{token}\r\n");
        for source in ["env", "file"] {
            let (out_src, in_src) = if source == "env" {
                (format!("token_env: {env}"), format!("token_envs: [{env}]"))
            } else {
                (
                    "token_file: token".to_string(),
                    "token_files: [token]".to_string(),
                )
            };
            // Inline outbound peer credential.
            let inline = format!(
                "node: {{id: A}}\npeers:\n  - {{id: B, expected_node_id: B, credential_ref: B, {out_src}, endpoints: [{{id: one, url: 'http://127.0.0.1:18080'}}]}}\n"
            );
            let (_, got) = load_dir(
                &[
                    ("peer.yaml", inline.as_bytes()),
                    ("token", token_file.as_bytes()),
                ],
                false,
            );
            assert_eq!(
                got.is_ok(),
                valid,
                "{name} inline {source}: {:?}",
                got.err().map(|e| e.message)
            );
            // Credential snapshot: inbound identity in a credentials file.
            let main_in = "node: {id: A}\nhttp: {enabled: true, listen: '127.0.0.1:18080'}\ntargets: {db: {address: '127.0.0.1:3306'}}\nauth: {credentials_file: creds.yaml}\n";
            let creds_in = format!(
                "version: 1\ninbound_peers:\n  - {{id: A, {in_src}, allowed_targets: [db]}}\n"
            );
            let (_, got) = load_dir(
                &[
                    ("peer.yaml", main_in.as_bytes()),
                    ("creds.yaml", creds_in.as_bytes()),
                    ("token", token_file.as_bytes()),
                ],
                false,
            );
            assert_eq!(
                got.is_ok(),
                valid,
                "{name} snapshot inbound {source}: {:?}",
                got.err().map(|e| e.message)
            );
            // Credential snapshot: outbound credential in a credentials file.
            let main_out = "node: {id: A}\nauth: {credentials_file: creds.yaml}\npeers:\n  - {id: B, expected_node_id: B, credential_ref: B, endpoints: [{id: one, url: 'http://127.0.0.1:18080'}]}\n";
            let creds_out = format!("version: 1\noutbound_peers:\n  - {{id: B, {out_src}}}\n");
            let (_, got) = load_dir(
                &[
                    ("peer.yaml", main_out.as_bytes()),
                    ("creds.yaml", creds_out.as_bytes()),
                    ("token", token_file.as_bytes()),
                ],
                false,
            );
            assert_eq!(
                got.is_ok(),
                valid,
                "{name} snapshot outbound {source}: {:?}",
                got.err().map(|e| e.message)
            );
        }
        std::env::remove_var(&env);
    }
}

#[test]
fn spec_token_files_reject_extra_lines() {
    for body in ["token\n\n", "token\r\n\r\n", "token\nother"] {
        let item = yaml::parse("token_file: token\n").unwrap();
        let dir = scratch();
        std::fs::write(dir.join("token"), body).unwrap();
        assert!(
            reverse::read_token(&item, &dir, CODE_CREDENTIAL, false).is_err(),
            "multiple lines normalized into a credential: {body:?}"
        );
    }
}

fn example_blocks(marker: &str) -> Vec<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/examples.md");
    let content = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .replace("\r\n", "\n");
    let (_, example) = content
        .split_once(&format!("<!-- example:{marker} -->"))
        .unwrap_or_else(|| panic!("missing example {marker}"));
    let mut example = example
        .split_once(&format!("<!-- /example:{marker} -->"))
        .map(|(e, _)| e)
        .unwrap_or(example);
    let mut out = Vec::new();
    while let Some((_, rest)) = example.split_once("```yaml\n") {
        let (body, rest) = rest.split_once("```").expect("unclosed YAML");
        out.push(body.to_string());
        example = rest;
    }
    out
}

#[test]
fn spec_readme_standalone_pair_loads() {
    std::env::set_var("DBB_TOKEN_SECRET", "readme-validation-token");
    let blocks = example_blocks("standalone-pair");
    assert_eq!(
        blocks.len(),
        2,
        "validated {} configs, expected complete pair",
        blocks.len()
    );
    for (i, body) in blocks.iter().enumerate() {
        if cfg!(not(feature = "tls")) && body.contains("https://") {
            continue; // https endpoints need the tls feature
        }
        let (_, got) = load_dir(&[("peer.yaml", body.as_bytes())], false);
        if let Err(e) = got {
            panic!("README standalone config {}: {}", i + 1, e.message);
        }
    }
}

#[test]
fn spec_outbound_whitespace_token_rejected_during_check() {
    let env = unique_env("DBB_TEST_BAD_TOKEN");
    std::env::set_var(&env, "contains a space");
    let body = format!(
        "node: {{id: A}}\npeers:\n  - {{id: B, expected_node_id: B, credential_ref: B, token_env: {env}, endpoints: [{{id: one, url: 'http://127.0.0.1:18080'}}]}}\n"
    );
    let (_, got) = load_dir(&[("peer.yaml", body.as_bytes())], false);
    assert!(
        got.is_err(),
        "check-config accepted an outbound Bearer token that inbound credential validation rejects"
    );
}

#[cfg(feature = "tls")]
#[test]
fn spec_examples_reverse_configs_load() {
    std::env::set_var("DBB_TOKEN_SECRET", "examples-validation-token");
    std::env::set_var("DBB_TOKEN_BRANCH", "examples-branch-token");
    for (marker, want) in [("reverse-pair", 2), ("mixed-node", 1)] {
        let blocks = example_blocks(marker);
        assert_eq!(
            blocks.len(),
            want,
            "{marker}: validated {} configs, want {want}",
            blocks.len()
        );
        for (i, body) in blocks.iter().enumerate() {
            let (_, got) = load_dir(&[("peer.yaml", body.as_bytes())], false);
            let cfg = got.unwrap_or_else(|e| panic!("{marker} config {}: {}", i + 1, e.message));
            assert!(
                cfg.warnings.is_empty(),
                "{marker} config {} warnings: {:?}",
                i + 1,
                cfg.warnings
            );
        }
    }
}

#[test]
fn spec_multi_document_config_rejected() {
    let (_, got) = load_dir(
        &[(
            "peer.yaml",
            b"node:\n  id: first\n---\nunknown_security_option: true\n",
        )],
        false,
    );
    assert!(
        got.is_err(),
        "ignored second YAML document with unknown security field"
    );
}

#[test]
fn spec_mixed_credential_sources_rejected() {
    let env = unique_env("DBB_TEST_MIXED");
    std::env::set_var(&env, "outbound-token");
    let body = format!(
        "node: {{id: A}}\nauth: {{credentials_file: auth.yaml}}\npeers:\n  - {{id: B, expected_node_id: B, credential_ref: B, token_env: {env}, endpoints: [{{id: e, url: 'http://127.0.0.1:18080'}}]}}\n"
    );
    let (_, got) = load_dir(
        &[
            ("peer.yaml", body.as_bytes()),
            ("auth.yaml", b"version: 1\n"),
        ],
        false,
    );
    assert!(
        got.is_err(),
        "credentials_file plus direct peer token_env accepted"
    );
}

#[test]
fn spec_ipv6_default_port_normalization() {
    let env = unique_env("DBB_TEST_IPV6");
    std::env::set_var(&env, "outbound-token");
    let body = format!(
        "node: {{id: A}}\npeers:\n  - {{id: B, expected_node_id: B, credential_ref: B, token_env: {env}, endpoints: [{{id: e, url: 'http://[::1]:80'}}]}}\n"
    );
    let (_, got) = load_dir(&[("peer.yaml", body.as_bytes())], false);
    let cfg = got.unwrap_or_else(|e| panic!("{}", e.message));
    let url = &cfg.peers[0].endpoints[0].url;
    assert_eq!(url.host, "::1", "IPv6 origin corrupted: {url:?}");
    assert_eq!(url.port, 80);
    assert_eq!(url.authority(), "[::1]:80");
}

#[test]
fn spec_zero_healthcheck_timeout_rejected() {
    let env = unique_env("DBB_TEST_HC");
    std::env::set_var(&env, "outbound-token");
    let body = format!(
        "node: {{id: A}}\npeers:\n  - {{id: B, expected_node_id: B, credential_ref: B, token_env: {env}, endpoints: [{{id: e, url: 'http://127.0.0.1:18080'}}], failover: {{healthcheck_timeout: 0s}}}}\n"
    );
    let (_, got) = load_dir(&[("peer.yaml", body.as_bytes())], false);
    assert!(
        got.is_err(),
        "accepted zero healthcheck timeout; all health probes immediately cancel"
    );
}
