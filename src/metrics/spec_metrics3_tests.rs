use std::collections::HashSet;
use std::time::Instant;

use super::*;

fn load(yaml: &str) -> crate::config::Config {
    let dir = std::env::temp_dir().join(format!(
        "dbb-spec-metrics3-{}",
        crate::util::random_hex(6).unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("peer.yaml");
    std::fs::write(&path, yaml).unwrap();
    let cfg = crate::config::load(&path).unwrap_or_else(|e| panic!("{}", e.message));
    std::fs::remove_dir_all(&dir).ok();
    cfg
}

/// The `# TYPE` names of `text`; panics on a duplicate when `unique`.
fn typed(text: &str, unique: bool) -> HashSet<String> {
    let mut typed = HashSet::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() >= 3 && f[0] == "#" && f[1] == "TYPE" {
            assert!(
                typed.insert(f[2].to_string()) || !unique,
                "duplicate TYPE for {}",
                f[2]
            );
        }
    }
    typed
}

/// Every sample line's name (or its histogram/summary base) has a TYPE.
fn assert_samples_typed(text: &str, typed: &HashSet<String>, suffixes: &[&str]) {
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let name = line.split([' ', '{']).find(|s| !s.is_empty()).unwrap();
        let mut base = name;
        for suffix in suffixes {
            base = base.strip_suffix(suffix).unwrap_or(base);
        }
        assert!(
            typed.contains(name) || typed.contains(base),
            "sample {name} has no TYPE"
        );
    }
}

#[test]
fn spec_metrics_exposition() {
    let cfg = load("node: {id: A}\ntargets: {db: {network: tcp, address: '127.0.0.1:3306'}}\n");
    let m = Metrics::new();
    let a = m.render(&cfg, Instant::now(), true);
    let b = m.render(&cfg, Instant::now(), true);
    assert_eq!(a, b, "metric order changes between scrapes");
    for want in [
        "# TYPE dbb_resume_success_total counter\n",
        "# TYPE dbb_resume_failed_total counter\n",
        "# TYPE dbb_client_close_count_total counter\n",
        "# TYPE dbb_dial_total counter\n",
    ] {
        assert!(a.contains(want), "missing {want:?}");
    }
    let typed = typed(&a, true);
    assert_samples_typed(&a, &typed, &["_bucket", "_count", "_sum"]);
}

#[test]
fn spec_metrics_types() {
    let env = format!(
        "DBB_NODE_TEST_TOKEN_{}",
        crate::util::random_hex(4).unwrap().to_ascii_uppercase()
    );
    std::env::set_var(&env, "node-test-token-0123456789abcdef");
    let cfg = load(&format!("node: {{id: A}}\npeers:\n  - {{id: B, expected_node_id: B, credential_ref: B, token_env: {env}, endpoints: [{{id: e, url: 'http://127.0.0.1:9'}}]}}\nlisteners:\n  - {{id: one, listen: '127.0.0.1:0', peer: B, target: db}}\n"));
    let m = Metrics::new();
    m.configure_resources(&cfg);
    let out = m.render(&cfg, Instant::now(), true);
    for want in [
        "# TYPE dbb_ingress_accept_rejected_total counter",
        "# TYPE dbb_ingress_payload_bytes gauge",
        "dbb_resource_limit{resource=\"conn_metadata\"}",
    ] {
        assert!(out.contains(want), "metrics missing {want:?}");
    }
    let typed = typed(&out, false);
    assert_samples_typed(&out, &typed, &["_count", "_sum"]);
    std::env::remove_var(&env);
}
