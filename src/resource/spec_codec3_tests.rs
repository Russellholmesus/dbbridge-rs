use super::*;
use crate::wire::Mode;

fn config(listeners: bool) -> Config {
    let dir = std::env::temp_dir().join(format!(
        "dbb-rm-codec3-{}",
        crate::util::random_hex(6).expect("OS random for test fixture")
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("tok"), "abcdefghijklmnop").unwrap();
    let listeners = if listeners {
        "listeners:\n  - id: l1\n    listen: \"127.0.0.1:13306\"\n    peer: A\n    target: db\npeers:\n  - id: A\n    expected_node_id: A\n    credential_ref: A\n    token_file: tok\n    endpoints:\n      - {id: p, url: \"http://127.0.0.1:18081\", priority: 1}\n"
    } else {
        ""
    };
    let yaml = format!(
        "node:\n  id: B\nhttp:\n  enabled: true\n  listen: \"127.0.0.1:18080\"\n  allowed_transports: [ws, http-sse]\n{listeners}targets:\n  db:\n    network: tcp\n    address: \"127.0.0.1:3306\"\nauth:\n  inbound_peers:\n    - id: C\n      token_files: [tok]\n      allowed_targets: [db]\ntransport:\n  max_frame_size: 1024\n  buffer_per_direction: 4096\n  up_window_bytes: 2048\n  up_max_inflight_frames: 8\n"
    );
    let path = dir.join("config.yaml");
    std::fs::write(&path, yaml).unwrap();
    let cfg = crate::config::load(&path).unwrap_or_else(|e| panic!("{}", e.message));
    std::fs::remove_dir_all(dir).unwrap();
    cfg
}

#[test]
fn spec_downstream_codec_charge_per_transport() {
    assert_eq!(
        ws_down_cost(256 << 10),
        2 * (256 << 10) + WS_BINARY_HEADER_LEN
    );
    assert_eq!(sse_down_cost(256 << 10), 6 * (256 << 10) + 16384);
    let mut cfg = config(false);
    cfg.http.allowed_transports = vec![Mode::Ws];
    assert_eq!(
        max_codec_charge(&cfg),
        16 << 10,
        "ws-only max charge for 1 KiB frames"
    );
    cfg.http.allowed_transports = vec![Mode::Ws, Mode::HttpSse];
    assert_eq!(max_codec_charge(&cfg), sse_down_cost(1024), "max charge");
}

#[test]
fn spec_ingress_codec_reserve_keeps_one_egress_frame() {
    let mut cfg = config(true);
    cfg.transport.codec_buffer_limit = (sse_down_cost(1024) + 2048) as u64;
    let r = ResourceManager::new(&cfg);
    assert!(
        r.egress_codec_limit() >= max_codec_charge(&cfg),
        "egress codec {} below one charge {}",
        r.egress_codec_limit(),
        max_codec_charge(&cfg)
    );
    assert_eq!(r.ingress_codec_reserve(), 2048, "reserve");
}

#[test]
fn spec_ingress_codec_reserve_covers_large_sse_frame() {
    let mut cfg = config(true);
    cfg.transport.max_frame_size = 1 << 20;
    cfg.transport.codec_buffer_limit = 32 << 20;
    let r = ResourceManager::new(&cfg);
    assert_eq!(
        r.ingress_codec_reserve(),
        sse_down_cost(1 << 20),
        "codec reserve"
    );
}
