use super::{unattached, CreateLookup, Registry, SessionLookup};
use crate::error::Error;
use crate::session::recovery::{ResumeFin, ResumeRequest};
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

fn resume_req(s: &Session, id: &str) -> ResumeRequest {
    ResumeRequest {
        resume_request_id: id.into(),
        expected_epoch: s.epoch(),
        ingress_instance_id: s.instance_id.clone(),
        transport: Mode::Ws,
        known_up_ack_offset: 0,
        up_next_offset: 0,
        down_delivered_offset: 0,
        up_fin: ResumeFin::default(),
        down_fin: ResumeFin::default(),
    }
}

fn reserve(r: &Registry, key: &str) -> CreateLookup {
    r.reserve_create(key, "p", "params".into(), 0, 0)
}

#[test]
fn spec_normal_tombstone_must_retain_ten_minutes() {
    let (_peer, b) = backend();
    let r = Registry::new_with_ttl(
        Arc::new(crate::metrics::Metrics::new()),
        Duration::from_secs(600),
    );
    assert!(matches!(
        reserve(&r, "test-credential"),
        CreateLookup::Reserved
    ));
    let s = session("s-normal", b);
    r.insert(s.clone());
    r.complete_create("test-credential", s.id.clone(), "{}".into());
    let started = Instant::now();
    s.close(Error::local("closed_normal"));
    r.remove(&s.id);
    let at = r
        .tombstones
        .lock()
        .unwrap()
        .get(&s.id)
        .expect("tombstone")
        .1;
    let expiry = at + r.tombstone_ttl;
    assert!(
        expiry >= started + Duration::from_secs(600),
        "normal tombstone retained for {:?}; configured guarantee=10m",
        expiry.saturating_duration_since(started)
    );
    assert!(matches!(
        r.get_any(&s.id),
        Some(SessionLookup::Tombstone(_))
    ));
}

#[test]
fn spec_boundary_tombstone_expires_without_new_create() {
    let (_peer, b) = backend();
    let r = Registry::new_with_ttl(
        Arc::new(crate::metrics::Metrics::new()),
        Duration::from_millis(20),
    );
    let s = session("s-expire", b);
    r.insert(s.clone());
    assert!(matches!(reserve(&r, "key"), CreateLookup::Reserved));
    r.complete_create("key", s.id.clone(), "{}".into());
    s.close(Error::new(wire::ERR_SESSION_CLOSED, "closed").closed(true));
    r.remove(&s.id);
    std::thread::sleep(Duration::from_millis(60));
    assert!(
        r.get_any(&s.id).is_none(),
        "expired tombstone is still returned; expiry only runs when another creation is reserved"
    );
}

#[test]
fn spec_active_create_mapping_expiry() {
    let (_peer, b) = backend();
    let r = Registry::new_with_ttl(
        Arc::new(crate::metrics::Metrics::new()),
        Duration::from_secs(600),
    );
    let s = session("s-active", b);
    r.insert(s.clone());
    assert!(matches!(reserve(&r, "key"), CreateLookup::Reserved));
    r.complete_create("key", s.id.clone(), "{}".into());
    r.creates.lock().unwrap().get_mut("key").unwrap().at =
        Instant::now() - Duration::from_secs(11 * 60);
    assert!(
        !matches!(reserve(&r, "key"), CreateLookup::Reserved),
        "same create ID re-reserved while original session still active after 10 minutes"
    );
    // Once the session ends the record's guarantee restarts from then.
    s.close(Error::new(wire::ERR_SESSION_CLOSED, "closed").closed(true));
    r.remove(&s.id);
    assert!(matches!(reserve(&r, "key"), CreateLookup::Replay { .. }));
}

#[test]
fn spec_unattached_timer_stopped_by_resume() {
    let (_peer, b) = backend();
    let r = Arc::new(Registry::new(Arc::new(crate::metrics::Metrics::new())));
    let s = session("s-unattached-resume", b);
    s.enable_recovery(Duration::from_secs(10));
    r.insert(s.clone());
    unattached::schedule(&r, &s, Duration::from_millis(50));
    s.attach("ws-1").unwrap();
    assert!(s.suspend_current());
    s.resume(&resume_req(&s, "r1"), Duration::from_secs(1))
        .unwrap();
    std::thread::sleep(Duration::from_millis(120));
    assert!(
        !s.is_closed(),
        "resumed session closed by the create-time unattached timer"
    );
    assert!(r.get(&s.id).is_some());
    r.remove(&s.id);
}

#[test]
fn spec_resume_id_retained_outside_tombstone_budget() {
    let (_peer, b) = backend();
    let r = Registry::new(Arc::new(crate::metrics::Metrics::new()));
    assert!(matches!(reserve(&r, "create-key"), CreateLookup::Reserved));
    let s = session("s-resume-id", b);
    s.enable_recovery(Duration::from_secs(10));
    r.insert(s.clone());
    r.complete_create("create-key", s.id.clone(), "{}".into());
    s.attach("ws-1").unwrap();
    let big = "r".repeat(12 << 10);
    assert!(
        s.resume(&resume_req(&s, &big), Duration::from_secs(1))
            .is_err(),
        "accepted a 12 KiB resume ID"
    );
    assert_eq!(s.epoch(), 1, "rejected request changed the epoch");
    let id = "r".repeat(128);
    let q = resume_req(&s, &id);
    let response = s.resume(&q, Duration::from_secs(1)).unwrap();
    let replay = s
        .resume(&q, Duration::from_secs(1))
        .expect("bounded resume ID lost idempotency");
    assert_eq!(replay, response, "bounded resume ID lost idempotency");
    s.close(Error::new(wire::ERR_SESSION_CLOSED, "closed").closed(true));
    r.remove(&s.id);
    let Some(SessionLookup::Tombstone(t)) = r.get_any(&s.id) else {
        panic!("tombstone missing");
    };
    assert_eq!(
        t.last_resume_request_id.len(),
        128,
        "tombstone lost its bounded resume ID"
    );
    assert!(matches!(
        reserve(&r, "create-key"),
        CreateLookup::Replay { .. }
    ));
}

fn recovering(id: &str, b: TcpStream) -> Arc<Session> {
    let s = session(id, b);
    s.enable_recovery(Duration::from_secs(60));
    s
}

#[test]
fn spec_registry_suspended_lru_eviction() {
    let (_p1, b1) = backend();
    let (_p2, b2) = backend();
    let r = Registry::new_with_ttl_and_suspended_limit(
        Arc::new(crate::metrics::Metrics::new()),
        Duration::from_secs(600),
        200,
    );
    let s1 = recovering("s-lru-1", b1);
    let s2 = recovering("s-lru-2", b2);
    r.insert(s1.clone());
    r.insert(s2.clone());
    s1.mark_down_produced(&[0u8; 150]).unwrap();
    s2.mark_down_produced(&[0u8; 150]).unwrap();
    assert!(s1.suspend_current());
    assert!(!s1.is_closed(), "s1 should not be evicted yet");
    std::thread::sleep(Duration::from_millis(2));
    assert!(s2.suspend_current());
    assert!(s1.is_closed(), "s1 should have been evicted by LRU limit");
    assert_eq!(
        s1.terminal_error().unwrap().code,
        wire::ERR_BUFFER_EXHAUSTED
    );
    assert!(s1.replay_down_frames().is_empty());
    assert!(!s2.is_closed(), "s2 should remain");
    assert!(r.get(&s2.id).is_some(), "s2 should remain in registry");
    r.close_all();
}

#[test]
fn spec_registry_idempotency_conflict_and_pending() {
    let r = Registry::new(Arc::new(crate::metrics::Metrics::new()));
    let key = "peer-a:inst-1:cr_123";
    let params = |target: &str| format!("{target}|32768|8|1048576|2097152|recovery:30000");
    let reserve = |target: &str| r.reserve_create(key, "peer-a", params(target), 0, 0);
    assert!(matches!(reserve("mysql-primary"), CreateLookup::Reserved));
    assert!(matches!(reserve("mysql-primary"), CreateLookup::Pending));
    assert!(matches!(reserve("mysql-other"), CreateLookup::Conflict));
    r.complete_create(key, "s_123".into(), "{\"session_id\":\"s_123\"}".into());
    match reserve("mysql-primary") {
        CreateLookup::Replay {
            status, session_id, ..
        } => {
            assert_eq!(status, 201);
            assert_eq!(session_id.as_deref(), Some("s_123"));
        }
        _ => panic!("expected the cached response"),
    }
}

#[test]
fn spec_resume_must_retain_activation_deadline() {
    let (_peer, b) = backend();
    let r = Arc::new(Registry::new(Arc::new(crate::metrics::Metrics::new())));
    let s = session("s-activation", b);
    s.enable_recovery(Duration::from_millis(100));
    r.insert(s.clone());
    s.attach("sse-1").unwrap();
    assert!(s.suspend_current());
    unattached::schedule_recovery(&r, &s);
    s.resume(&resume_req(&s, "rr_timeout_test"), Duration::from_secs(1))
        .expect("resume");
    // ATTACHING, never activated: the activation deadline must fire.
    std::thread::sleep(Duration::from_millis(150));
    let until = Instant::now() + Duration::from_secs(2);
    while r.get(&s.id).is_some() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(s.is_closed(), "activation deadline did not fire");
    assert_eq!(s.terminal_error().unwrap().code, wire::ERR_RESUME_EXPIRED);
    assert!(r.get(&s.id).is_none());
}

#[test]
fn spec_create_idempotency_cap_quota() {
    let r = Registry::new(Arc::new(crate::metrics::Metrics::new()));
    let records = super::RecordLimits::without_budget(1);
    for i in 0..records.pending {
        let k = format!("k{i}");
        assert!(
            matches!(
                r.reserve_create_with_records(&k, "p", "x".into(), 0, 0, records),
                CreateLookup::Reserved
            ),
            "i={i}"
        );
        r.fail_create(&k, 502, "{\"code\":\"DBB_DIAL_FAILED\"}".into());
    }
    assert!(
        matches!(
            r.reserve_create_with_records("new", "p", "x".into(), 0, 0, records),
            CreateLookup::Quota("peer idempotency quota")
        ),
        "full table must be a quota error"
    );
    match r.reserve_create_with_records("k1", "p", "x".into(), 0, 0, records) {
        CreateLookup::Replay { status, body, .. } => {
            assert_eq!(status, 502);
            assert!(body.contains(wire::ERR_DIAL_FAILED));
        }
        _ => panic!("cached key did not replay"),
    }
    assert!(r.accepting(), "a full table is not draining");
}

#[test]
fn spec_registry_global_budget_must_be_enforced() {
    let (_peer, b) = backend();
    let r = Registry::new_with_resource_limits(
        Arc::new(crate::metrics::Metrics::new()),
        Duration::from_secs(600),
        1 << 20,
        128,
        Duration::from_millis(10),
    );
    let s = recovering("s-global", b);
    r.insert(s.clone());
    s.mark_down_produced(&[0u8; 100])
        .expect("100 bytes within the 128 byte budget");
    let e = s
        .mark_down_produced(&[0u8; 100])
        .expect_err("exceeded the global buffer limit");
    assert_eq!(e.code, wire::ERR_BUFFER_EXHAUSTED, "{e}");
    r.close_all();
}

#[test]
fn spec_complete_after_close_keeps_guarantee() {
    let (_peer, b) = backend();
    let r = Registry::new(Arc::new(crate::metrics::Metrics::new()));
    assert!(matches!(reserve(&r, "late"), CreateLookup::Reserved));
    r.creates.lock().unwrap().get_mut("late").unwrap().at =
        Instant::now() - Duration::from_secs(9 * 60);
    let s = session("s-late", b);
    r.insert(s.clone());
    let closed = Instant::now();
    s.close(Error::new(wire::ERR_SESSION_CLOSED, "closed").closed(true));
    r.remove(&s.id);
    r.complete_create("late", s.id.clone(), "{}".into());
    let at = r.creates.lock().unwrap().get("late").unwrap().at;
    assert!(
        at + r.tombstone_ttl >= closed + Duration::from_secs(600),
        "record retained {:?} after close; guarantee 10m",
        (at + r.tombstone_ttl).saturating_duration_since(closed)
    );
}

#[test]
fn spec_initial_attach_deadline_fences_ready_and_closes() {
    let r = Arc::new(Registry::new(Arc::new(crate::metrics::Metrics::new())));
    let (_p1, b1) = backend();
    let late = session("s-attach-late", b1);
    r.insert(late.clone());
    unattached::schedule(&r, &late, Duration::from_millis(40));
    let until = Instant::now() + Duration::from_secs(2);
    while !late.is_closed() && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(
        late.is_closed(),
        "timer did not close the unattached session"
    );
    assert_eq!(
        late.attach("ws-1").unwrap_err().code,
        wire::ERR_SESSION_CLOSED,
        "ready after the initial attach deadline activated the session"
    );
    let (_p2, b2) = backend();
    let on_time = session("s-attach-on-time", b2);
    r.insert(on_time.clone());
    unattached::schedule(&r, &on_time, Duration::from_millis(30));
    on_time.attach("ws-1").unwrap();
    std::thread::sleep(Duration::from_millis(60));
    assert!(
        !on_time.is_closed(),
        "activated session closed by the unattached timer"
    );
    r.close_all();
}
