use super::*;
use std::fs;
use std::path::{Path, PathBuf};

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "dbb-spec-auth-{tag}-{}-{}",
        std::process::id(),
        crate::util::random_hex(4).unwrap()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
}

fn load(dir: &Path, body: &str) -> Authenticator {
    let path = dir.join("peer.yaml");
    write(&path, body);
    let mut cfg = crate::config::load(&path).unwrap_or_else(|e| panic!("load: {}", e.message));
    cfg.path = path;
    Authenticator::new(Arc::new(cfg))
}

fn inline(peers: &[(&str, bool, &[&str])]) -> Authenticator {
    let dir = temp_dir("inline");
    let mut yaml = String::from(
        "node: {id: n}\ntargets: {db: {network: tcp, address: \"127.0.0.1:3306\"}}\nauth:\n  inbound_peers:\n",
    );
    for (id, enabled, _) in peers {
        write(
            &dir.join(format!("{id}.token")),
            &format!("placeholder-token-{id}-0123456789\n"),
        );
        yaml.push_str(&format!(
            "    - {{id: {id}, enabled: {enabled}, token_files: [{id}.token], allowed_targets: [db], max_sessions: 10}}\n"
        ));
    }
    write(&dir.join("peer.yaml"), &yaml);
    let mut cfg = crate::config::load(&dir.join("peer.yaml")).unwrap();
    for (peer, (_, _, tokens)) in cfg.inbound.iter_mut().zip(peers) {
        peer.tokens = tokens.iter().map(|t| t.to_string()).collect();
    }
    fs::remove_dir_all(&dir).ok();
    Authenticator::new(Arc::new(cfg))
}

fn metric(a: &Authenticator, name: &str) -> String {
    let text = a.metrics.render(&a.cfg, std::time::Instant::now(), true);
    text.lines()
        .find_map(|l| l.strip_prefix(&format!("{name} ")))
        .unwrap_or_else(|| panic!("metric {name} missing"))
        .to_string()
}

fn revision(a: &Authenticator) -> u64 {
    a.reload_state.lock().unwrap().revision
}

#[test]
fn spec_reserve_fair_partitions_global_budget() {
    for (global, peers, want) in [
        (16, 1, 16),
        (16, 2, 12),
        (16, 3, 7),
        (4, 3, 1),
        (1, 5, 1),
        (2, 2, 1),
    ] {
        assert_eq!(
            peer_share(global, peers),
            want,
            "PeerShare({global},{peers})"
        );
    }
    let a = inline(&[("A", true, &["token-a"]), ("B", true, &["token-b"])]);
    let mut releases: Vec<FairLease> = (0..3)
        .map(|i| {
            a.reserve_fair_n("A", "create", 4, 1)
                .unwrap_or_else(|| panic!("reservation {i} refused"))
        })
        .collect();
    assert!(
        a.reserve_fair_n("A", "create", 4, 1).is_none(),
        "peer A exceeded its share"
    );
    assert!(
        a.reserve_fair_n("A", "probe", 4, 1).is_some(),
        "kinds must be independent"
    );
    assert!(
        a.reserve_fair_n("B", "create", 4, 1).is_some(),
        "peer B starved"
    );
    drop(releases.remove(0));
    let again = a
        .reserve_fair_n("A", "create", 4, 1)
        .expect("release did not return the slot");
    assert!(
        a.reserve_fair_n("A", "create", 4, 1).is_none(),
        "release returned more than one slot"
    );
    drop(again);
    assert!(
        a.reserve_fair_n("nobody", "create", 4, 1).is_none(),
        "unknown peer admitted"
    );
}

#[test]
fn spec_third_peer_keeps_floor() {
    let a = inline(&[
        ("A", true, &["token-a"]),
        ("B", true, &["token-b"]),
        ("C", true, &["token-c"]),
    ]);
    const GLOBAL: i64 = 16;
    let mut held = Vec::new();
    for peer in ["A", "B"] {
        while let Some(r) = a.reserve_fair_n(peer, "create", GLOBAL, 1) {
            held.push(r);
        }
    }
    assert!(
        GLOBAL - held.len() as i64 >= 1,
        "two greedy peers hold {} of {GLOBAL}",
        held.len()
    );
    assert!(
        a.reserve_fair_n("C", "create", GLOBAL, 1).is_some(),
        "third peer starved"
    );
    assert!(
        a.reserve_fair_n("C", "bytes", 1 << 20, peer_share(1 << 20, 3) + 1)
            .is_none(),
        "amount above the share admitted"
    );
}

#[test]
fn spec_bearer_digest_compare() {
    let a = inline(&[
        ("A", true, &["token-a", "token-a2"]),
        ("D", false, &["token-d"]),
    ]);
    for (tok, want) in [
        ("token-a", Some("A")),
        ("token-a2", Some("A")),
        ("token-a ", None),
        ("token-", None),
        ("token-d", None),
        ("token-aa", None),
    ] {
        assert_eq!(a.authenticate(tok).as_deref(), want, "{tok:?}");
    }
}

const QUOTA_MAIN: &str = "node: {id: n}\ntargets: {db: {network: tcp, address: \"127.0.0.1:3306\"}}\nlimits: {max_sessions: 10}\nauth: {credentials_file: auth.yaml, reload_interval: 1h}\n";

#[test]
fn spec_reload_keeps_quota_partition() {
    let dir = temp_dir("partition");
    write(&dir.join("a.token"), "auth1-token-a-0123456789\n");
    write(&dir.join("b.token"), "auth1-token-b-0123456789\n");
    let creds = |qa: u32, qb: u32| {
        write(
            &dir.join("auth.yaml"),
            &format!("version: 1\ninbound_peers:\n- id: A\n  token_files: [a.token]\n  allowed_targets: [db]\n  max_sessions: {qa}\n- id: B\n  token_files: [b.token]\n  allowed_targets: [db]\n  max_sessions: {qb}\n"),
        )
    };
    creds(5, 5);
    let a = load(&dir, QUOTA_MAIN);
    let rev = revision(&a);
    let failed: u64 = metric(&a, "dbb_auth_reload_failed_total").parse().unwrap();
    creds(10, 5);
    assert!(a.reload("interval").is_err());
    assert_eq!(
        revision(&a),
        rev,
        "reload exceeding limits.max_sessions was installed"
    );
    assert_eq!(a.inbound("A").unwrap().max_sessions, 5);
    assert_eq!(
        metric(&a, "dbb_auth_reload_failed_total")
            .parse::<u64>()
            .unwrap(),
        failed + 1,
        "rejected reload not counted"
    );
    creds(6, 4);
    assert!(a.reload("interval").unwrap());
    assert_ne!(revision(&a), rev, "valid repartition rejected");
    assert_eq!(a.inbound("A").unwrap().max_sessions, 6);
    fs::remove_dir_all(&dir).ok();
}

const OUTBOUND_MAIN: &str = r#"node: {id: A}
auth: {credentials_file: auth.yaml, reload_interval: 1h}
peers:
  - {id: B, expected_node_id: NB, credential_ref: cred-b, endpoints: [{id: e, url: "http://127.0.0.1:1", priority: 1}]}
listeners: [{id: l1, listen: "127.0.0.1:0", peer: B, target: db}]
"#;

#[test]
fn spec_reload_missing_required_outbound_retains_snapshot() {
    let dir = temp_dir("outbound");
    write(&dir.join("b.token"), "valid-outbound-token\n");
    write(
        &dir.join("auth.yaml"),
        "version: 1\noutbound_peers:\n- id: cred-b\n  token_file: b.token\n",
    );
    let a = load(&dir, OUTBOUND_MAIN);
    assert_eq!(
        a.outbound_token("B").as_deref(),
        Some("valid-outbound-token")
    );
    write(&dir.join("auth.yaml"), "version: 1\noutbound_peers: []\n");
    assert!(a.reload("interval").is_err());
    assert_eq!(
        a.outbound_token("B").as_deref(),
        Some("valid-outbound-token"),
        "incomplete candidate replaced last valid outbound snapshot"
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn spec_reload_unknown_acl_retains_snapshot() {
    let dir = temp_dir("acl");
    write(&dir.join("a.token"), "acl-test-secret-0123456789\n");
    let creds = |target: &str| {
        write(
            &dir.join("auth.yaml"),
            &format!("version: 1\ninbound_peers:\n- id: A\n  token_files: [a.token]\n  allowed_targets: [{target}]\n"),
        )
    };
    creds("db");
    let a = load(
        &dir,
        "node: {id: n}\ntargets: {db: {network: tcp, address: \"127.0.0.1:3306\"}}\nauth: {credentials_file: auth.yaml, reload_interval: 1h}\n",
    );
    creds("missing-target");
    assert!(a.reload("interval").is_err());
    assert_eq!(
        a.inbound("A").unwrap().allowed_targets,
        vec!["db".to_string()],
        "invalid ACL candidate replaced last valid snapshot"
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn spec_outbound_credential_refs_that_are_peer_ids_map_deterministically() {
    for _ in 0..30 {
        let dir = temp_dir("remap");
        write(&dir.join("x.token"), "token-for-ref-X-0123456789\n");
        write(&dir.join("y.token"), "token-for-ref-Y-0123456789\n");
        write(
            &dir.join("auth.yaml"),
            "version: 1\noutbound_peers:\n  - {id: X, token_file: x.token}\n  - {id: Y, token_file: y.token}\n",
        );
        let a = load(
            &dir,
            r#"node: {id: A}
auth: {credentials_file: auth.yaml}
peers:
  - {id: X, expected_node_id: NX, credential_ref: Y, endpoints: [{id: e, url: "http://127.0.0.1:1", priority: 1}]}
  - {id: Y, expected_node_id: NY, credential_ref: X, endpoints: [{id: e, url: "http://127.0.0.1:2", priority: 1}]}
listeners: [{id: l1, listen: "127.0.0.1:0", peer: X, target: db}]
"#,
        );
        assert_eq!(
            a.outbound_token("X").as_deref(),
            Some("token-for-ref-Y-0123456789")
        );
        assert_eq!(
            a.outbound_token("Y").as_deref(),
            Some("token-for-ref-X-0123456789")
        );
        fs::remove_dir_all(&dir).ok();
    }
}

fn generated_pair(tag: &str) -> (PathBuf, PathBuf) {
    let dir = temp_dir(tag);
    let o = crate::cli::genconfig::PairOptions {
        output_dir: dir.to_string_lossy().into_owned(),
        ..crate::cli::genconfig::PairOptions::default()
    };
    crate::cli::genconfig::generate_pair(&o).unwrap_or_else(|e| panic!("{}", e.message));
    let path = dir.join("peer-a.yaml");
    (dir, path)
}

fn load_path(path: &Path) -> Authenticator {
    let mut cfg = crate::config::load(path).unwrap_or_else(|e| panic!("load: {}", e.message));
    cfg.path = path.to_path_buf();
    Authenticator::new(Arc::new(cfg))
}

#[test]
fn spec_inline_credentials_rotate_without_restart() {
    let (dir, path) = generated_pair("inline-rotate");
    let a = load_path(&path);
    let old = a.outbound_token("B").unwrap();
    let original = fs::read_to_string(&path).unwrap();
    let new_tok = "rotated-token-0123456789abcdef0123456789";
    write(&dir.join("new.token"), &format!("{new_tok}\n"));
    let edit = |from: &str, to: &str| {
        let b = fs::read_to_string(&path).unwrap();
        let next = b.replacen(from, to, 1);
        assert_ne!(next, b, "{from:?} not found in:\n{b}");
        write(&path, &next);
        a.reload("request")
            .unwrap_or_else(|e| panic!("reload: {}", e.message));
    };
    edit(
        "      token_files:\n        - shared.token\n",
        "      token_files:\n        - shared.token\n        - new.token\n",
    );
    for tok in [old.as_str(), new_tok] {
        assert_eq!(a.authenticate(tok).as_deref(), Some("B"), "during rotation");
    }
    edit(
        "    token_file: shared.token\n",
        "    token_file: new.token\n",
    );
    assert_eq!(
        a.outbound_token("B").as_deref(),
        Some(new_tok),
        "outbound token not switched"
    );
    edit(
        "        - shared.token\n        - new.token\n",
        "        - new.token\n",
    );
    assert!(a.authenticate(&old).is_none(), "old token still accepted");
    write(&path, &original);
    write(&dir.join("shared.token"), &format!("{new_tok}\n"));
    a.reload("request")
        .unwrap_or_else(|e| panic!("reload: {}", e.message));
    assert_eq!(
        a.outbound_token("B").as_deref(),
        Some(new_tok),
        "rewritten token file not re-read"
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn spec_inline_reload_rejects_peer_removal() {
    let (dir, path) = generated_pair("inline-removal");
    let a = load_path(&path);
    let b = fs::read_to_string(&path).unwrap();
    let next = b.replacen(
        "    expected_node_id: B\n    id: B\n",
        "    expected_node_id: B\n    id: C\n",
        1,
    );
    assert_ne!(next, b);
    write(&path, &next);
    let err = a
        .reload("request")
        .expect_err("peer removal must be rejected");
    assert_eq!(err.code, "DBB-CFG-020");
    assert!(
        err.message
            .contains("listeners[database-local] references non-existent peer: B"),
        "peer removal: {}",
        err.message
    );
    assert!(
        a.outbound_token("B").is_some_and(|t| !t.is_empty()),
        "previous snapshot lost"
    );
    fs::remove_dir_all(&dir).ok();
}

const B_NODE_MAIN: &str = r#"node: {id: B}
http: {enabled: true, listen: "127.0.0.1:0"}
targets: {db: {network: tcp, address: "127.0.0.1:3306", allowed_cidrs: ["127.0.0.1/32"]}}
auth: {credentials_file: auth.yaml, reload_interval: 1s}
limits: {max_sessions: 10}
"#;

#[test]
fn spec_disabling_an_identity_works_after_its_token_file_is_removed() {
    let dir = temp_dir("disable-removed");
    let stolen = "stolen-token-0123456789abcdef";
    write(&dir.join("a.token"), &format!("{stolen}\n"));
    write(
        &dir.join("auth.yaml"),
        "version: 1\ninbound_peers:\n  - {id: A, token_files: [a.token], allowed_targets: [db]}\n",
    );
    let a = load(&dir, B_NODE_MAIN);
    assert_eq!(a.authenticate(stolen).as_deref(), Some("A"), "baseline");
    write(
        &dir.join("auth.yaml"),
        "version: 1\ninbound_peers:\n  - {id: A, enabled: false, token_files: [a.token], allowed_targets: [db]}\n",
    );
    fs::remove_file(dir.join("a.token")).unwrap();
    a.reload("request")
        .unwrap_or_else(|e| panic!("revocation rejected: {}", e.message));
    assert!(
        a.authenticate(stolen).is_none(),
        "revoked token still authenticates"
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn spec_rejected_reload_is_reported_and_recovers() {
    let dir = temp_dir("rejected-recovers");
    write(&dir.join("a.token"), "first-token-0123456789abcdef\n");
    write(
        &dir.join("auth.yaml"),
        "version: 1\ninbound_peers:\n  - {id: A, token_files: [a.token], allowed_targets: [db]}\n  - {id: C, token_files: [c.token], allowed_targets: [db], enabled: false}\n",
    );
    let a = load(&dir, B_NODE_MAIN);
    write(
        &dir.join("auth.yaml"),
        "version: 1\ninbound_peers:\n  - {id: A, token_files: [a.token], allowed_targets: [db], max_sessions: 5}\n  - {id: C, token_files: [c.token], allowed_targets: [db], max_sessions: 5}\n",
    );
    let err = a
        .reload("request")
        .expect_err("enabling C without its token file");
    assert_eq!(
        err.code, "DBB-CFG-020",
        "reload error {} lacks code DBB-CFG-020",
        err.message
    );
    assert_eq!(
        metric(&a, "dbb_auth_credentials_stale"),
        "1",
        "stale gauge not set"
    );
    assert_eq!(
        a.authenticate("first-token-0123456789abcdef").as_deref(),
        Some("A"),
        "previous snapshot lost"
    );
    write(&dir.join("c.token"), "second-token-0123456789abcdef\n");
    a.reload("request")
        .unwrap_or_else(|e| panic!("{}", e.message));
    assert_eq!(
        metric(&a, "dbb_auth_credentials_stale"),
        "0",
        "stale gauge not cleared"
    );
    assert_eq!(
        a.authenticate("second-token-0123456789abcdef").as_deref(),
        Some("C"),
        "fixed candidate not installed"
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn spec_hot_reload_deletes_removed_peer() {
    let dir = temp_dir("hot-remove");
    write(&dir.join("t1"), "token-1-0123456789abcdef\n");
    write(&dir.join("t2"), "token-2-0123456789abcdef\n");
    write(
        &dir.join("auth.yaml"),
        "version: 1\ninbound_peers:\n  - id: peer-1\n    enabled: true\n    token_files: [t1]\n    allowed_targets: [db]\n    max_sessions: 10\n  - id: peer-2\n    enabled: true\n    token_files: [t2]\n    allowed_targets: [db]\n    max_sessions: 10\n",
    );
    let a = load(
        &dir,
        "node: {id: n}\ntargets: {db: {network: tcp, address: \"127.0.0.1:3306\"}}\nauth: {credentials_file: auth.yaml, reload_interval: 1s}\n",
    );
    assert_eq!(
        a.authenticate("token-1-0123456789abcdef").as_deref(),
        Some("peer-1")
    );
    assert_eq!(
        a.authenticate("token-2-0123456789abcdef").as_deref(),
        Some("peer-2")
    );
    write(
        &dir.join("auth.yaml"),
        "version: 1\ninbound_peers:\n  - id: peer-1\n    enabled: true\n    token_files: [t1]\n    allowed_targets: [db]\n    max_sessions: 10\n",
    );
    assert!(a.reload("interval").unwrap());
    assert_eq!(
        a.authenticate("token-1-0123456789abcdef").as_deref(),
        Some("peer-1")
    );
    assert!(
        a.authenticate("token-2-0123456789abcdef").is_none(),
        "expected peer-2 to be deleted and revoked after hot reload"
    );
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn spec_dual_token_rotation() {
    let a = inline(&[("peer-alpha", true, &["token-version-2", "token-version-1"])]);
    assert_eq!(
        a.authenticate("token-version-2").as_deref(),
        Some("peer-alpha")
    );
    assert_eq!(
        a.authenticate("token-version-1").as_deref(),
        Some("peer-alpha")
    );
    assert_eq!(
        a.authenticate("invalid-token"),
        None,
        "invalid token accepted"
    );
    let peer = a.inbound("peer-alpha").unwrap();
    assert!(
        peer.allowed_targets.iter().any(|t| t == "db"),
        "target not authorized"
    );
    assert!(
        !peer
            .allowed_targets
            .iter()
            .any(|t| t == "unauthorized-target"),
        "unauthorized target authorized"
    );
}

#[test]
fn spec_disabled_inbound_peer() {
    let a = inline(&[("peer-disabled", false, &["token-disabled"])]);
    assert_eq!(
        a.authenticate("token-disabled"),
        None,
        "disabled peer authenticated"
    );
}
