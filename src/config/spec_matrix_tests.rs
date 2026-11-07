use super::*;

fn spec_configs() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/configs")
}

#[cfg(feature = "tls")]
fn production_example(node: &str, n: usize, failover: bool, recovery: bool) -> Result<Config> {
    let dir = spec_configs().join("production");
    let (cert, key) = test_certificate_pair();
    let text = std::fs::read_to_string(dir.join(format!("peer-{node}.yaml"))).unwrap();
    let text = text
        .replace(&format!("/etc/dbbridge/tls/{node}.crt"), &cert)
        .replace(&format!("/etc/dbbridge/tls/{node}.key"), &key);
    let mut out = Vec::new();
    let mut endpoints = Vec::new();
    let mut insert_at = None;
    for line in text.lines() {
        if line.trim_start().starts_with("- {id: ") && line.contains("url: \"https://") {
            insert_at.get_or_insert(out.len());
            endpoints.push(line.to_string());
            continue;
        }
        out.push(line.to_string());
    }
    if endpoints.len() < 3 {
        endpoints.push(
            "      - {id: tertiary, url: \"https://tertiary.example.invalid\", priority: 3}".into(),
        );
    }
    endpoints.truncate(n);
    let at = insert_at.expect("example has endpoints");
    for (i, e) in endpoints.into_iter().enumerate() {
        out.insert(at + i, e);
    }
    let text = out
        .join("\n")
        .replacen(
            "failover: {enabled: true,",
            &format!("failover: {{enabled: {failover},"),
            1,
        )
        .replacen(
            "recovery: {enabled: true,",
            &format!("recovery: {{enabled: {recovery},"),
            1,
        );
    let work = scratch();
    std::fs::create_dir_all(work.join("tokens")).unwrap();
    for name in ["a-to-b", "b-to-a"] {
        std::fs::write(
            work.join(format!("tokens/{name}.token")),
            format!("example-{name}-0123456789abcdef\n"),
        )
        .unwrap();
    }
    std::fs::copy(
        dir.join(format!("auth-{node}.yaml")),
        work.join(format!("auth-{node}.yaml")),
    )
    .unwrap();
    std::fs::write(work.join("config.yaml"), text).unwrap();
    load(&work.join("config.yaml"))
}

#[cfg(feature = "tls")]
#[test]
fn spec_example_mode_matrix() {
    let mut failures = Vec::new();
    for node in ["a", "b"] {
        for n in 1..=3 {
            for failover in [false, true] {
                for recovery in [false, true] {
                    match production_example(node, n, failover, recovery) {
                        Ok(cfg) => {
                            assert_eq!(cfg.peers[0].endpoints.len(), n);
                            assert_eq!(cfg.peers[0].failover.enabled, failover);
                            assert_eq!(cfg.transport.recovery_enabled, recovery);
                        }
                        Err(e) => failures.push(format!(
                            "{node}/endpoints={n}/failover={failover}/recovery={recovery}: {}",
                            e.message
                        )),
                    }
                }
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[cfg(feature = "tls")]
#[test]
fn spec_tls_certificate_preflight() {
    let (cert, key) = test_certificate_pair();
    let dir = Path::new(&cert).parent().unwrap().to_path_buf();
    let wrong_key = dir.join("other-key.pem");
    std::fs::write(&wrong_key, include_str!("../net/testdata/other-key.pem")).unwrap();
    let wrong_key = wrong_key.to_string_lossy().into_owned();
    let base = |c: &str, k: &str| {
        format!("node: {{id: B}}\nhttp: {{enabled: true, listen: '127.0.0.1:18443', tls: {{enabled: true, cert_file: '{c}', key_file: '{k}'}}}}\n")
    };
    for (name, c, k, valid) in [
        (
            "valid_relative_paths",
            "cert.pem".to_string(),
            "key.pem".to_string(),
            true,
        ),
        ("mismatched_key", cert.clone(), wrong_key.clone(), false),
        ("malformed_certificate", key.clone(), key.clone(), false),
    ] {
        let path = dir.join(format!("{name}.yaml"));
        std::fs::write(&path, base(&c, &k)).unwrap();
        let got = load(&path);
        assert_eq!(
            got.is_ok(),
            valid,
            "{name}: {:?}",
            got.err().map(|e| e.message)
        );
        if let Err(e) = got {
            assert_eq!(e.code, CODE_TLS, "{name}: {}", e.message);
        }
    }
}

#[test]
fn spec_config_validation() {
    std::env::set_var("DBB_TOKEN_TO_HQ", "mock-token-xyz");
    let path = spec_configs().join("peer-a.yaml");
    if cfg!(not(feature = "tls")) && std::fs::read_to_string(&path).unwrap().contains("https://") {
        return;
    }
    let cfg = load(&path).unwrap_or_else(|e| panic!("LoadConfig failed: {}", e.message));
    assert_eq!(cfg.node.id, "plant-a");
    assert_eq!(cfg.transport.frame_size, 32 * 1024);
    assert_eq!(cfg.transport.max_frame_size, 256 * 1024);
}

#[test]
fn spec_boundary_cidr_validation_matches_runtime() {
    let cfg = test_load("node: {id: A}\ntargets: {db: {address: '127.0.0.1:3306', allowed_cidrs: [' 127.0.0.0/8 ']}}\n").unwrap();
    let stored = &cfg.targets[0].allowed_cidrs[0];
    assert!(
        scalars::parse_cidr(stored).is_ok(),
        "check-config accepted but the runtime parser rejects unnormalized value {stored:?}"
    );
}
