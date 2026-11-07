use super::*;

const FRAME: u64 = 256 << 10;
const PEERS: &str = "peers:\n  - id: B\n    expected_node_id: B\n    credential_ref: B\n    token_env: DBB_GO_BUDGET_TOKEN\n    endpoints: [{id: e, url: 'http://127.0.0.1:18081', priority: 1}]\n";
const LISTENERS: &str = "listeners: [{id: l, listen: '127.0.0.1:13306', peer: B, target: db}]\n";

fn egress(transports: &str) -> String {
    format!("http: {{enabled: true, listen: '127.0.0.1:18080', allowed_transports: [{transports}]}}\ntargets: {{db: {{address: '127.0.0.1:3306', allowed_cidrs: ['127.0.0.1/32']}}}}\n")
}

fn load_codec(body: &str, frame: u64, codec: u64) -> Result<Config> {
    std::env::set_var("DBB_GO_BUDGET_TOKEN", "budget-test-token-0123456789abcdef");
    let dir = std::env::temp_dir().join(format!(
        "dbb-gobudget-{}",
        crate::util::random_hex(8).unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("peer.yaml");
    std::fs::write(
        &path,
        format!("node: {{id: A}}\n{body}transport: {{max_frame_size: {frame}, codec_buffer_limit: {codec}}}\n"),
    )
    .unwrap();
    let result = load(&path);
    std::fs::remove_dir_all(&dir).ok();
    result
}

fn assert_boundary(name: &str, body: &str, frame: u64, want: u64) {
    if let Err(e) = load_codec(body, frame, want) {
        panic!("{name}: codec_buffer_limit {want} refused: {}", e.message);
    }
    let e = load_codec(body, frame, want - 1).expect_err(name);
    assert_eq!(e.message, "codec/metadata budget too small", "{name}");
}

#[test]
fn spec_min_codec_budget_follows_transports() {
    let sse = 6 * FRAME + 16384;
    let ws = 2 * FRAME + 56;
    let cases = [
        ("egress ws and sse", egress("ws, http-sse"), sse),
        ("egress ws only", egress("ws"), ws),
        (
            "ws with listeners",
            format!("{}{PEERS}{LISTENERS}", egress("ws")),
            sse,
        ),
        (
            "sse bidirectional",
            format!("{}{PEERS}{LISTENERS}", egress("ws, http-sse")),
            sse + FRAME + 56,
        ),
        ("ws with peers", format!("{}{PEERS}", egress("ws")), sse),
        ("ingress only", format!("{PEERS}{LISTENERS}"), sse),
    ];
    for (name, body, want) in cases {
        assert_boundary(name, &body, FRAME, want);
    }
    assert_boundary("small ws-only frame", &egress("ws"), 1024, 16 << 10);
}
