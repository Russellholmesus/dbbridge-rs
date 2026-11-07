use super::{generate_pair, PairOptions};

fn out_dir(tag: &str) -> String {
    let dir = std::env::temp_dir().join(format!(
        "dbb-gogen2-{tag}-{}",
        crate::util::random_hex(6).unwrap()
    ));
    format!("{}/out", dir.display())
}

#[test]
fn spec_generate_reverse_rejects_bidirectional() {
    let mut o = PairOptions {
        output_dir: out_dir("bidir"),
        reverse: true,
        ..PairOptions::default()
    };
    let e = generate_pair(&o).expect_err("reverse bidirectional accepted");
    assert!(
        e.message.contains("a-to-b or b-to-a"),
        "err = {}",
        e.message
    );
    o.mode = "a-to-b".into();
    o.b.tls_cert = "x.pem".into();
    o.b.tls_key = "x.key".into();
    let e = generate_pair(&o).expect_err("database-side TLS accepted");
    assert!(e.message.contains("no HTTP server"), "err = {}", e.message);
}
