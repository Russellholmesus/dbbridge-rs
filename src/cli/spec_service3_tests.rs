use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::signals;

extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
}

#[cfg(target_os = "linux")]
#[test]
fn spec_hangup_triggers_reload_without_terminating() {
    signals::install_hangup();
    let dir = std::env::temp_dir().join(format!(
        "dbb-spec-hup-{}",
        crate::util::random_hex(6).unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let old = "hangup-old-token-0123456789";
    let new = "hangup-new-token-0123456789";
    std::fs::write(dir.join("a.token"), old).unwrap();
    let path = dir.join("peer.yaml");
    std::fs::write(
        &path,
        "node: {id: n}\ntargets: {db: {network: tcp, address: \"127.0.0.1:3306\"}}\nauth:\n  reload_interval: 60s\n  inbound_peers:\n    - {id: a, token_files: [a.token], allowed_targets: [db]}\n",
    )
    .unwrap();
    let mut cfg = crate::config::load(&path).unwrap_or_else(|e| panic!("{}", e.message));
    cfg.path = path;
    let auth = crate::auth::Authenticator::new(Arc::new(cfg));
    assert_eq!(auth.authenticate(old).as_deref(), Some("a"));
    let stop = Arc::new(AtomicBool::new(false));
    let worker = auth.start(stop.clone(), signals::take_hup);
    std::fs::write(dir.join("a.token"), new).unwrap();
    let pid = std::process::id() as i32;
    // SAFETY: kill(2) to our own pid with SIGHUP, whose handler is installed.
    assert_eq!(
        unsafe { kill(pid, 1) },
        0,
        "kill: {}",
        std::io::Error::last_os_error()
    );
    // The hangup request is one process-wide flag: another test running in
    // parallel with its own reload loop may consume it first, so re-signal
    // (still never terminating the process) until this loop has reloaded.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut resend = Instant::now() + Duration::from_millis(250);
    while auth.authenticate(new).is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
        if Instant::now() >= resend {
            // SAFETY: as above.
            unsafe { kill(pid, 1) };
            resend = Instant::now() + Duration::from_millis(250);
        }
    }
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    worker.join().unwrap();
    assert_eq!(
        auth.authenticate(new).as_deref(),
        Some("a"),
        "SIGHUP did not request a reload"
    );
    assert!(auth.authenticate(old).is_none());
    std::fs::remove_dir_all(&dir).ok();
}
