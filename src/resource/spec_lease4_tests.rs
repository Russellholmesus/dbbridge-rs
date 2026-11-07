use super::budget::Budget;
use super::manager::ResourceManager;

const CONN_METADATA_PER_CONN: i64 = 16 << 10;

/// A bidirectional node (one local listener) with `max_sessions` sessions.
fn bidirectional(max_sessions: u32) -> crate::config::Config {
    let dir = std::env::temp_dir().join(format!(
        "dbb-rm-lease4-{}",
        crate::util::random_hex(6).expect("OS random for test fixture")
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("tok"), "abcdefghijklmnop").unwrap();
    let yaml = format!(
        "node:\n  id: B\nhttp:\n  enabled: true\n  listen: \"127.0.0.1:18080\"\nlisteners:\n  - id: l1\n    listen: \"127.0.0.1:13306\"\n    peer: P\n    target: db\npeers:\n  - id: P\n    expected_node_id: P\n    credential_ref: P\n    token_file: tok\n    endpoints:\n      - {{id: p, url: \"http://127.0.0.1:18081\", priority: 1}}\ntargets:\n  db:\n    network: tcp\n    address: \"127.0.0.1:3306\"\nauth:\n  inbound_peers:\n    - id: C\n      token_files: [tok]\n      allowed_targets: [db]\n      max_sessions: 4\nlimits:\n  max_sessions: {max_sessions}\ntransport:\n  metadata_limit: 33554432\n"
    );
    let path = dir.join("config.yaml");
    std::fs::write(&path, yaml).unwrap();
    let cfg = crate::config::load(&path).unwrap_or_else(|e| panic!("{}", e.message));
    std::fs::remove_dir_all(dir).unwrap();
    cfg
}

#[test]
fn spec_role_budgets() {
    let m = ResourceManager::new(&bidirectional(12));
    assert_eq!(
        m.conn_metadata.limit(),
        m.inbound_connections.limit() * CONN_METADATA_PER_CONN,
        "connection metadata pool not sized for every inbound slot"
    );
    let mut conns = Vec::new();
    while let Some(slot) = m.inbound_connections.try_acquire(1) {
        let meta = m
            .conn_metadata
            .try_acquire(CONN_METADATA_PER_CONN)
            .expect("connection pool smaller than connection limit");
        conns.push((slot, meta));
    }
    assert_eq!(
        conns.len() as i64,
        m.inbound_connections.limit(),
        "every connection slot admitted"
    );
    assert_eq!(
        m.metadata.used(),
        0,
        "socket admission charged session metadata"
    );

    let (reserve_sessions, reserve_metadata) = m.ingress_reserve();
    assert_eq!(reserve_sessions, 3, "session reserve");
    assert_eq!(reserve_metadata, m.metadata.limit() / 8, "metadata reserve");
    let egress: Vec<_> = std::iter::from_fn(|| m.try_egress_session())
        .take(100)
        .collect();
    assert_eq!(
        egress.len(),
        9,
        "egress took {} of 12 sessions",
        egress.len()
    );
    let local = m.sessions.try_acquire(1).expect("ingress reserve unusable");

    let egress_md = m
        .try_egress_metadata(m.metadata.limit() - reserve_metadata)
        .expect("egress metadata part refused");
    assert!(
        m.try_egress_metadata(1).is_none(),
        "egress metadata took the ingress reserve"
    );
    let local_md = m
        .metadata
        .try_acquire(reserve_metadata)
        .expect("metadata ingress reserve not honoured");
    assert_eq!(
        m.ingress_reserve(),
        (3, reserve_metadata),
        "reserve not reported"
    );
    drop((egress, local, egress_md, local_md, conns));

    assert!(
        Budget::new(5).try_acquire_keep(1, -1).is_none(),
        "TryKeep negative keep"
    );
    assert!(
        Budget::new(5).try_acquire_keep(5, 0).is_some(),
        "TryKeep all"
    );
    assert!(
        Budget::new(5).try_acquire_keep(5, 1).is_none(),
        "TryKeep beyond keep"
    );
}
