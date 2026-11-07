use super::*;
use std::fs;

#[test]
fn spec_reload_uses_shared_snapshot_validation() {
    let dir = std::env::temp_dir().join(format!(
        "dbb-spec-auth-reload4-{}-{}",
        std::process::id(),
        crate::util::random_hex(4).unwrap()
    ));
    fs::create_dir_all(&dir).unwrap();
    // Unique identity name so the shared test log capture only counts this
    // test's warning.
    let weak = format!("W{}", crate::util::random_hex(4).unwrap());
    fs::write(dir.join("a.token"), "integration-token-a-0123456789").unwrap();
    fs::write(dir.join("b.token"), "short").unwrap();
    let creds = |body: &str| {
        fs::write(
            dir.join("auth.yaml"),
            format!("version: 1\ninbound_peers:\n{body}"),
        )
        .unwrap()
    };
    creds("- {id: A, token_files: [a.token], allowed_targets: [db], max_sessions: 2}\n");
    let path = dir.join("main.yaml");
    fs::write(
        &path,
        "node: {id: n}\ntargets: {db: {network: tcp, address: \"127.0.0.1:3306\"}}\nlimits: {max_sessions: 4}\nauth: {credentials_file: auth.yaml, reload_interval: 1h}\n",
    )
    .unwrap();
    let mut cfg = crate::config::load(&path).unwrap_or_else(|e| panic!("load: {}", e.message));
    cfg.path = path;
    let a = Authenticator::new(Arc::new(cfg));
    let revision = |a: &Authenticator| a.reload_state.lock().unwrap().revision;
    let warnings = || {
        crate::slog::test_captured()
            .iter()
            .filter(|l| l.contains("credentials reload warning") && l.contains(&weak))
            .count()
    };

    let rev = revision(&a);
    creds(&format!("- {{id: A, token_files: [a.token], allowed_targets: [db], max_sessions: 3}}\n- {{id: {weak}, token_files: [b.token], allowed_targets: [db], max_sessions: 2}}\n"));
    assert!(a.reload("interval").is_err());
    assert_eq!(
        revision(&a),
        rev,
        "quota sum 5 > limits.max_sessions 4 was installed"
    );

    creds(&format!("- {{id: A, token_files: [a.token], allowed_targets: [db], max_sessions: 2}}\n- {{id: {weak}, token_files: [b.token], allowed_targets: [db], max_sessions: 2}}\n"));
    assert!(a.reload("interval").unwrap());
    assert!(!a.reload("interval").unwrap());
    assert_ne!(revision(&a), rev, "valid snapshot not installed");
    assert_eq!(
        warnings(),
        1,
        "weak-token warning logged {} times, want 1",
        warnings()
    );

    creds("- {id: A, token_files: [a.token], allowed_targets: [nope], max_sessions: 2}\n");
    let rev = revision(&a);
    assert!(a.reload("interval").is_err());
    assert_eq!(revision(&a), rev, "unknown ACL target installed");
    fs::remove_dir_all(&dir).ok();
}
