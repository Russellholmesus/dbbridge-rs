use super::*;

fn load_peer(peer_extra: &str, endpoints: &str, global_protocol: &str) -> Config {
    std::env::set_var(
        "DBB_GO_RECOVERY_TOKEN",
        "recovery-test-token-0123456789abcdef",
    );
    let dir = std::env::temp_dir().join(format!(
        "dbb-gorecovery-{}",
        crate::util::random_hex(8).unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("peer.yaml");
    let global = if global_protocol.is_empty() {
        String::new()
    } else {
        format!("transport: {{protocol: {global_protocol}}}\n")
    };
    std::fs::write(
        &path,
        format!(
            "node: {{id: A}}\n{global}peers:\n  - id: B\n    expected_node_id: B\n    credential_ref: B\n    token_env: DBB_GO_RECOVERY_TOKEN\n    endpoints:\n{endpoints}{peer_extra}listeners: [{{id: l, listen: '127.0.0.1:13306', peer: B, target: db}}]\n"
        ),
    )
    .unwrap();
    let cfg = load(&path).unwrap_or_else(|e| panic!("load: {}", e.message));
    std::fs::remove_dir_all(&dir).ok();
    cfg
}

const ONE: &str = "      - {id: a, url: 'http://127.0.0.1:18081', priority: 1}\n";
const TWO: &str = "      - {id: a, url: 'http://127.0.0.1:18081', priority: 1}\n      - {id: b, url: 'http://127.0.0.1:18082', priority: 2}\n";

#[test]
fn spec_single_recovery_carrier_warning() {
    let forced_ws = load_peer("    transport: {protocol: ws}\n", ONE, "auto");
    assert!(
        build::single_recovery_carrier(&forced_ws.peers[0]),
        "forced ws with one endpoint is a single carrier"
    );
    let auto = load_peer("", ONE, "auto");
    assert!(
        !build::single_recovery_carrier(&auto.peers[0]),
        "auto has two carriers per endpoint"
    );
    let no_failover = load_peer("    failover: {enabled: false}\n", TWO, "http-sse");
    assert!(
        build::single_recovery_carrier(&no_failover.peers[0]),
        "failover disabled leaves one endpoint"
    );
}
