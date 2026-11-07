use super::{sync_dir, write_new};

fn temp_dir() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "dbb-fileutil-{}",
        crate::util::random_hex(6).unwrap()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn spec_write_new_does_not_replace_existing_file() {
    let dir = temp_dir();
    let path = dir.join("secret");
    let p = path.to_str().unwrap();
    assert_eq!(write_new(p, b"original", 0o600).ok(), Some(true));
    match write_new(p, b"replacement", 0o600) {
        Ok(_) => panic!("existing secret was replaced"),
        Err((created, _)) => assert!(!created, "existing secret reported as created"),
    }
    assert_eq!(
        std::fs::read(&path).unwrap(),
        b"original",
        "existing secret changed"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn spec_sync_dir() {
    let dir = temp_dir();
    sync_dir(dir.to_str().unwrap()).expect("sync existing dir");
    assert!(
        sync_dir(dir.join("missing").to_str().unwrap()).is_err(),
        "missing directory synced"
    );
    let _ = std::fs::remove_dir_all(dir);
}
