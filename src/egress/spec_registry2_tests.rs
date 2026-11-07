use super::{CreateLookup, RecordLimits, Registry};
use crate::error::Error;
use crate::session::Session;
use crate::wire::{self, Limits, Mode};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn backend() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (backend, _) = listener.accept().unwrap();
    (peer, backend)
}

fn session(id: &str, backend: TcpStream) -> Arc<Session> {
    Session::new(
        id.to_string(),
        "token".to_string(),
        "inst".to_string(),
        "p".to_string(),
        "db".to_string(),
        Mode::Ws,
        Limits {
            max_frame_size: 1024,
            up_max_inflight_frames: 8,
            up_window_bytes: 1024,
            down_buffer_bytes: 1024,
            up_receipt_limit: 64,
            down_max_frames: 8,
        },
        64,
        backend,
        Arc::new(crate::metrics::Metrics::new()),
    )
}

fn registry(ttl: Duration) -> Registry {
    Registry::new_with_ttl(Arc::new(crate::metrics::Metrics::new()), ttl)
}

fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !done() {
        assert!(Instant::now() < deadline, "{what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn spec_create_idempotency_expires_via_heap() {
    let r = registry(Duration::from_millis(20));
    let unbounded = RecordLimits {
        total: 1 << 20,
        pending: 1 << 20,
    };
    for i in 0..100 {
        let k = format!("k{i}");
        assert!(matches!(
            r.reserve_create_with_records(&k, "db", "params".into(), 0, 0, unbounded),
            CreateLookup::Reserved
        ));
        r.fail_create(&k, 502, "x".into());
    }
    wait_until("failed create records not expired by the sweeper", || {
        r.create_record_count() == 0
    });
    assert!(matches!(
        r.reserve_create("k1", "db", "params".into(), 0, 0),
        CreateLookup::Reserved
    ));
}

#[test]
fn spec_tombstone_and_record_expire_in_background() {
    let (_peer, b) = backend();
    let r = registry(Duration::from_millis(30));
    let s = session("s-bg", b);
    r.insert(s.clone());
    assert!(matches!(
        r.reserve_create("key", "p", "params".into(), 0, 0),
        CreateLookup::Reserved
    ));
    r.complete_create("key", s.id.clone(), "{}".into());
    // While the session is live its create record is kept past the TTL.
    std::thread::sleep(Duration::from_millis(60));
    assert_eq!(r.create_record_count(), 1, "live session record dropped");
    s.close(Error::new(wire::ERR_SESSION_CLOSED, "closed").closed(true));
    r.remove(&s.id);
    assert_eq!(r.tombstone_count(), 1);
    wait_until("tombstone/record not expired by the sweeper", || {
        r.tombstone_count() == 0 && r.create_record_count() == 0
    });
}

#[test]
fn pending_create_record_is_not_swept() {
    let r = registry(Duration::from_millis(10));
    assert!(matches!(
        r.reserve_create("pending", "p", "params".into(), 0, 0),
        CreateLookup::Reserved
    ));
    r.fail_create("other", 502, "x".into()); // starts the sweeper; key unknown
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(r.create_record_count(), 1);
    assert!(matches!(
        r.reserve_create("pending", "p", "params".into(), 0, 0),
        CreateLookup::Pending
    ));
}

fn resourced(
    metadata_limit: &str,
    max_sessions: u32,
    ttl: Duration,
) -> (Arc<Registry>, Arc<crate::metrics::Metrics>) {
    let path = std::env::temp_dir().join(format!(
        "dbb-reg2-{}.yaml",
        crate::util::random_hex(6).unwrap()
    ));
    std::fs::write(
        &path,
        format!("node:\n  id: test\ntargets:\n  db:\n    network: tcp\n    address: 127.0.0.1:3306\nlimits:\n  max_sessions: {max_sessions}\ntransport:\n  metadata_limit: {metadata_limit}\n"),
    )
    .unwrap();
    let cfg = crate::config::load(&path).unwrap_or_else(|e| panic!("{}", e.message));
    std::fs::remove_file(path).ok();
    let metrics = Arc::new(crate::metrics::Metrics::new());
    metrics.configure_resources(&cfg);
    let r = Arc::new(Registry::new_with_resource_limits(
        metrics.clone(),
        ttl,
        cfg.transport.suspended_buffer_limit,
        cfg.transport.global_buffer_limit,
        cfg.transport.backpressure_timeout,
    ));
    (r, metrics)
}

fn metadata_used(m: &crate::metrics::Metrics) -> i64 {
    m.resource_manager().unwrap().metadata.used()
}

const UNBOUNDED: RecordLimits = RecordLimits {
    total: 1 << 20,
    pending: 1 << 20,
};

#[test]
fn spec_create_churn_capacity() {
    let (r, _m) = resourced("32MiB", 200, Duration::from_secs(600));
    let (_peer, b) = backend();
    let mut n = 0;
    while n < 40000 {
        let key = format!(r#"["peer","ing","req-{n:06}"]"#);
        if !matches!(
            r.reserve_create_with_records(&key, "p", "db".into(), 0, 0, UNBOUNDED),
            CreateLookup::Reserved
        ) {
            break;
        }
        let s = session(&format!("s{n}"), b.try_clone().unwrap());
        r.insert_created(s.clone(), &key).unwrap();
        r.complete_create(&key, s.id.clone(), "{}".into());
        s.close(Error::new(wire::ERR_SESSION_CLOSED, "closed").closed(true));
        r.remove(&s.id);
        n += 1;
    }
    assert!(
        n >= 15000,
        "only {n} create/close cycles fit the default metadata budget"
    );
}

#[test]
fn spec_tombstone_view_and_normal_retention() {
    let ttl = Duration::from_secs(600);
    let (r, m) = resourced("32MiB", 8, ttl);
    let started = Instant::now();
    let mut ids = Vec::new();
    for (key, code) in [
        ("kn", wire::ERR_SESSION_CLOSED),
        ("ka", wire::ERR_BACKEND_LOST),
    ] {
        let (_peer, b) = backend();
        assert!(matches!(
            r.reserve_create_with_records(key, "p", "t".into(), 0, 0, UNBOUNDED),
            CreateLookup::Reserved
        ));
        let s = session(&format!("s-{key}"), b);
        r.insert_created(s.clone(), key).unwrap();
        r.complete_create(key, s.id.clone(), "{}".into());
        s.close(Error::new(code, "closed").closed(true));
        r.remove(&s.id);
        let Some(super::SessionLookup::Tombstone(t)) = r.get_any(&s.id) else {
            panic!("{key}: no tombstone view");
        };
        assert_eq!((t.token.as_str(), t.epoch), (s.token.as_str(), 1));
        assert_eq!(t.terminal_code, code);
        ids.push((s.id.clone(), key));
    }
    for (id, key) in ids {
        let tomb_at = r.tombstones.lock().unwrap().get(&id).map(|(_, at)| *at);
        let rec_at = r.creates.lock().unwrap().get(key).map(|rec| rec.at);
        let (Some(tomb_at), Some(rec_at)) = (tomb_at, rec_at) else {
            panic!("{key} lost its tombstone or create record inside the guarantee");
        };
        // Both deadlines are `at + ttl` with `at` taken at removal.
        assert!(
            tomb_at >= started && rec_at >= started,
            "{key} retained less than the 10m guarantee"
        );
    }
    assert_eq!(
        metadata_used(&m),
        2 * 2048,
        "metadata: both records charged"
    );
}

#[test]
fn spec_variable_create_metadata_released() {
    for expiry in [false, true] {
        let (r, m) = resourced("32MiB", 8, Duration::from_millis(100));
        let key = "identity-key";
        let target = "x".repeat(12 << 10);
        assert!(matches!(
            r.reserve_create_with_records(key, "p", target.clone(), 0, 0, UNBOUNDED),
            CreateLookup::Reserved
        ));
        r.fail_create(key, 403, "creation refused".into());
        let used = metadata_used(&m);
        assert!(
            used >= (key.len() + target.len() + 1536) as i64,
            "expiry={expiry}: undercharged {used}"
        );
        assert!(matches!(
            r.reserve_create_with_records(key, "p", target.clone(), 0, 0, UNBOUNDED),
            CreateLookup::Replay { .. }
        ));
        assert_eq!(metadata_used(&m), used, "retry charged twice");
        if expiry {
            wait_until("metadata not released by expiry", || metadata_used(&m) == 0);
        } else {
            r.close_all();
            assert_eq!(metadata_used(&m), 0, "metadata not released by shutdown");
        }
    }
}

#[test]
fn spec_resume_tombstone_reservation_refunded() {
    let (r, m) = resourced("32MiB", 8, Duration::from_millis(20));
    let (_peer, b) = backend();
    assert!(matches!(
        r.reserve_create_with_records("key", "p", "db".into(), 0, 0, UNBOUNDED),
        CreateLookup::Reserved
    ));
    let s = session("s-refund", b);
    s.enable_recovery(Duration::from_secs(10));
    r.insert_created(s.clone(), "key").unwrap();
    r.complete_create("key", s.id.clone(), "{}".into());
    s.attach("ws-1").unwrap();
    let q = crate::session::recovery::ResumeRequest {
        resume_request_id: "r".repeat(128),
        expected_epoch: s.epoch(),
        ingress_instance_id: s.instance_id.clone(),
        transport: Mode::Ws,
        known_up_ack_offset: 0,
        up_next_offset: 0,
        down_delivered_offset: 0,
        up_fin: Default::default(),
        down_fin: Default::default(),
    };
    s.resume(&q, Duration::from_secs(1)).unwrap();
    s.close(Error::new(wire::ERR_SESSION_CLOSED, "closed").closed(true));
    r.remove(&s.id);
    wait_until("expired tombstone leaked its metadata reservation", || {
        metadata_used(&m) == 0 && r.get_any(&s.id).is_none() && r.create_record_count() == 0
    });
}
