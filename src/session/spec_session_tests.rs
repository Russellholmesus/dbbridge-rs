use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use super::*;

fn backend_pair() -> (std::net::TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server)
}

fn session_with_receipts(backend: TcpStream, receipt_limit: u32) -> Arc<Session> {
    let limits = Limits {
        max_frame_size: 64 * 1024,
        up_max_inflight_frames: 8,
        up_window_bytes: 1024 * 1024,
        down_buffer_bytes: 1024 * 1024,
        up_receipt_limit: receipt_limit,
        down_max_frames: 8,
    };
    Session::new(
        "sess".into(),
        "token".into(),
        "inst".into(),
        "peer".into(),
        "target".into(),
        Mode::HttpSse,
        limits,
        receipt_limit,
        backend,
        Arc::new(crate::metrics::Metrics::new()),
    )
}

#[test]
fn spec_record_checked_refuses_overflow() {
    let (_client, backend) = backend_pair();
    let s = session_with_receipts(backend, 2);
    s.ingest_up(1, 0, b"a")
        .expect("record within capacity refused");
    s.ingest_up(1, 1, b"b")
        .expect("record within capacity refused");
    let e = s.ingest_up(1, 2, b"c").expect_err("overflow accepted");
    assert_eq!(e.code, wire::ERR_WINDOW_EXCEEDED);
    assert_eq!(
        s.inner.lock().unwrap().receipts.len(),
        2,
        "overflow changed the recorded receipts"
    );
    // Both receipts are still present: identical replays are accepted,
    // different bytes at a recorded boundary are conflicts.
    s.ingest_up(1, 0, b"a").unwrap();
    s.ingest_up(1, 1, b"b").unwrap();
    assert_eq!(
        s.ingest_up(1, 0, b"x").unwrap_err().code,
        ERR_FRAME_CONFLICT
    );
    assert_eq!(
        s.ingest_up(1, 1, b"x").unwrap_err().code,
        ERR_FRAME_CONFLICT
    );
}

#[test]
fn spec_unconfirmed_receipt_eviction() {
    let (_client, backend) = backend_pair();
    let s = session_with_receipts(backend, 2);
    s.ingest_up(1, 0, b"a").unwrap();
    s.ingest_up(1, 1, b"b").unwrap();
    assert!(s.ingest_up(1, 2, b"c").is_err());
    let g = s.inner.lock().unwrap();
    assert_eq!(
        g.receipt_floor, 0,
        "unconfirmed receipt evicted, floor advanced"
    );
    assert_eq!(g.receipts.front().map(|r| r.0), Some(0));
}

fn resume_request(s: &Session, id: &str) -> super::recovery::ResumeRequest {
    super::recovery::ResumeRequest {
        resume_request_id: id.into(),
        expected_epoch: s.epoch(),
        ingress_instance_id: s.ingress_instance_id.clone(),
        transport: s.mode,
        known_up_ack_offset: 0,
        up_next_offset: 0,
        down_delivered_offset: 0,
        up_fin: Default::default(),
        down_fin: Default::default(),
    }
}

#[test]
fn spec_resume_without_deadline() {
    let (_client, backend) = backend_pair();
    let s = session_with_receipts(backend, 64);
    s.enable_recovery(Duration::from_secs(2));
    s.attach("first").unwrap();
    let _ = s.resume(&resume_request(&s, "r1"), Duration::from_millis(20));
    assert!(
        s.recovery_deadline().is_some(),
        "resume advanced with no recovery/activation deadline"
    );
}

#[test]
fn spec_forged_up_confirmation() {
    let (_client, backend) = backend_pair();
    let s = session_with_receipts(backend, 64);
    s.enable_recovery(Duration::from_secs(2));
    assert_eq!(
        s.apply_up_confirmation(999).unwrap_err().code,
        wire::ERR_BAD_ACK
    );
    let g = s.inner.lock().unwrap();
    assert!(
        g.receipt_floor <= g.up_flushed,
        "receipt floor={} exceeds written ACK={}",
        g.receipt_floor,
        g.up_flushed
    );
}

#[test]
fn spec_suspend_must_not_refresh_deadline() {
    let (_client, backend) = backend_pair();
    let s = session_with_receipts(backend, 64);
    s.enable_recovery(Duration::from_millis(500));
    s.attach("sse-1").unwrap();
    assert!(s.suspend_current());
    let initial = s.recovery_deadline().expect("suspend arms the deadline");
    std::thread::sleep(Duration::from_millis(50));
    assert!(s.suspend_current());
    assert_eq!(
        s.recovery_deadline(),
        Some(initial),
        "ResumeDeadline was refreshed on repeat Suspend"
    );
}

fn resume_req(s: &Session, id: &str) -> super::recovery::ResumeRequest {
    super::recovery::ResumeRequest {
        resume_request_id: id.into(),
        expected_epoch: s.epoch(),
        ingress_instance_id: s.ingress_instance_id.clone(),
        transport: s.mode,
        known_up_ack_offset: 0,
        up_next_offset: 0,
        down_delivered_offset: 0,
        up_fin: super::recovery::ResumeFin::default(),
        down_fin: super::recovery::ResumeFin::default(),
    }
}

#[test]
fn spec_resume_idempotency_conflict() {
    let (_client, backend) = backend_pair();
    let s = session_with_receipts(backend, 64);
    s.enable_recovery(Duration::from_secs(5));
    s.attach("sse-1").unwrap();
    let req = resume_req(&s, "rr_001");
    let resp = s
        .resume(&req, Duration::from_secs(5))
        .expect("initial resume failed");
    let resp2 = s
        .resume(&req, Duration::from_secs(5))
        .expect("replay resume should succeed idempotently");
    assert_eq!(resp2.epoch, resp.epoch, "replay changed the epoch");
    let mut conflict = req.clone();
    conflict.down_delivered_offset = 1024;
    assert_eq!(
        s.resume(&conflict, Duration::from_secs(5))
            .expect_err("conflicting resume accepted")
            .code,
        wire::ERR_IDEMPOTENCY_CONFLICT
    );
}

#[test]
fn spec_resume_with_both_fins_closes_normally() {
    let (_client, backend) = backend_pair();
    let s = session_with_receipts(backend, 64);
    s.enable_recovery(Duration::from_secs(60));
    s.attach("ws-1").unwrap();
    assert!(s.ingest_up_fin(1, 0).unwrap(), "up FIN not applied");
    s.mark_down_fin();
    assert!(s.suspend_current(), "carrier drop not parked");
    let mut req = resume_req(&s, "r1");
    let fin = super::recovery::ResumeFin {
        seen: true,
        final_offset: Some(0),
        applied: true,
        acked: false,
    };
    req.up_fin = fin.clone();
    req.down_fin = fin;
    let e = s
        .resume(&req, Duration::from_secs(1))
        .expect_err("resume of a finished session opened a new epoch");
    assert_eq!(e.code, wire::ERR_SESSION_CLOSED, "resume err={e}");
    assert!(s.is_closed(), "state not closed");
    assert_eq!(s.epoch(), 1, "epoch");
    assert!(s.finished(), "close reason is not a normal close");
    assert_eq!(
        s.metrics
            .session_event_total("egress", "terminate", "normal"),
        1,
        "terminal category is not normal"
    );
}

#[test]
fn spec_close_with_reason_records_terminal_code() {
    for (code, cat) in [
        (wire::ERR_FRAME_CONFLICT, "protocol"),
        (wire::ERR_FRAME_TOO_LARGE, "protocol"),
        (wire::ERR_TARGET_FORBIDDEN, "forbidden"),
    ] {
        let (_client, backend) = backend_pair();
        let s = session_with_receipts(backend, 64);
        s.close(Error::new(code, "closed").closed(true));
        assert_eq!(
            s.terminal_error().map(|e| e.code).unwrap_or_default(),
            code,
            "CloseWithReason({code}) code"
        );
        assert_eq!(
            s.metrics.session_event_total("egress", "terminate", cat),
            1,
            "CloseWithReason({code}) category"
        );
    }
}

#[test]
fn spec_same_epoch_slot_reuse() {
    let (_client, backend) = backend_pair();
    let s = session_with_receipts(backend, 64);
    s.enable_recovery(Duration::from_secs(1));
    s.attach("first").unwrap();
    assert!(s.suspend_current());
    let e = s.attach("second").expect_err("used epoch 1 slot reopened");
    assert_eq!(e.code, wire::ERR_STALE_EPOCH, "{e}");
}

#[test]
fn spec_inflight_partial_overlap() {
    use std::io::Read;
    let (mut client, backend) = backend_pair();
    let s = session_with_receipts(backend, 64);
    s.attach("ws-1").unwrap();
    s.ingest_up(1, 0, b"abcd").unwrap();
    let r = s.ingest_up(1, 2, b"ZZ");
    assert!(r.is_err(), "accepted frame [2,4) overlapping [0,4)");
    client
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut got = Vec::new();
    let mut buf = [0u8; 16];
    while let Ok(n) = client.read(&mut buf) {
        if n == 0 {
            break;
        }
        got.extend_from_slice(&buf[..n]);
    }
    assert_eq!(got, b"abcd", "backend bytes");
}

#[test]
fn spec_concurrent_resume_single_commit() {
    let (_client, backend) = backend_pair();
    let s = session_with_receipts(backend, 64);
    s.enable_recovery(Duration::from_secs(5));
    s.attach("ws-1").unwrap();
    s.ingest_up(1, 0, b"abcd").unwrap();
    // The backend write of [0,4) is still in flight.
    s.inner.lock().unwrap().up_write_active = true;
    let mut handles = Vec::new();
    for id in ["r1", "r2"] {
        let s = s.clone();
        let mut req = resume_req(&s, id);
        req.up_next_offset = 4;
        handles.push(std::thread::spawn(move || {
            s.resume(&req, Duration::from_secs(1)).is_ok()
        }));
    }
    // Both requests reach the barrier, then the write completes.
    std::thread::sleep(Duration::from_millis(30));
    s.inner.lock().unwrap().up_write_active = false;
    s.cv.notify_all();
    let successes = handles
        .into_iter()
        .map(|h| h.join().unwrap())
        .filter(|ok| *ok)
        .count();
    assert!(
        successes <= 1 && s.epoch() <= 2,
        "two controllers committed {successes} recoveries, final epoch={}",
        s.epoch()
    );
}

#[test]
fn spec_suspend_quota_deadlock() {
    let (_client, backend) = backend_pair();
    let s = session_with_receipts(backend, 64);
    s.enable_recovery(Duration::from_secs(1));
    s.attach("ws-1").unwrap();
    let retention = Arc::new(crate::resource::retention::Retention::new(1));
    s.set_suspended_retention(retention);
    assert!(s.suspend_current());
    let (tx, rx) = std::sync::mpsc::channel();
    let producer = s.clone();
    std::thread::spawn(move || {
        let _ = producer.mark_down_produced(b"xx");
        let _ = tx.send(());
    });
    rx.recv_timeout(Duration::from_millis(100)).expect(
        "AppendDownBytes deadlocked while suspended quota eviction closes the same session",
    );
    s.close(Error::new(wire::ERR_SESSION_CLOSED, "test").closed(true));
}

#[test]
fn spec_boundary_inflight_resume_conflict_is_checked() {
    let (_client, backend) = backend_pair();
    let s = session_with_receipts(backend, 64);
    s.enable_recovery(Duration::from_secs(5));
    s.attach("ws-1").unwrap();
    s.ingest_up(1, 0, b"x").unwrap();
    // The backend write of [0,1) is still in flight.
    s.inner.lock().unwrap().up_write_active = true;
    let mut req = resume_req(&s, "same-id");
    req.up_next_offset = 1;
    let first = {
        let s = s.clone();
        let req = req.clone();
        std::thread::spawn(move || s.resume(&req, Duration::from_millis(500)))
    };
    let until = std::time::Instant::now() + Duration::from_secs(1);
    while s.recovery_state() != super::recovery::RecoveryState::Resuming
        && !s.inner.lock().unwrap().resume_busy
    {
        assert!(std::time::Instant::now() < until, "resume not started");
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(
        s.resume(&req, Duration::from_millis(50)).unwrap_err().code,
        wire::ERR_RESUME_PENDING,
        "same in-flight request must be pending"
    );
    let mut competing = req.clone();
    competing.resume_request_id = "other-id".into();
    assert_eq!(
        s.resume(&competing, Duration::from_millis(50))
            .unwrap_err()
            .code,
        wire::ERR_RESUME_IN_PROGRESS,
        "competing request must be in progress"
    );
    let mut changed = req.clone();
    changed.transport = match req.transport {
        Mode::Ws => Mode::HttpSse,
        _ => Mode::Ws,
    };
    let err = s.resume(&changed, Duration::from_millis(50)).unwrap_err();
    s.close(Error::new(wire::ERR_SESSION_CLOSED, "test").closed(true));
    let _ = first.join().unwrap();
    assert_eq!(err.code, wire::ERR_IDEMPOTENCY_CONFLICT, "{err}");
}

#[test]
fn spec_old_heartbeat_clears_new_recovery_deadline() {
    let (_client, backend) = backend_pair();
    let s = session_with_receipts(backend, 64);
    s.enable_recovery(Duration::from_millis(200));
    s.attach("ws-1").unwrap();
    s.note_ack_control("", "", true);
    let nonce = s.ping_control().unwrap().nonce.unwrap();
    assert!(s.suspend_current());
    let r = s
        .resume(&resume_req(&s, "r2"), Duration::from_millis(20))
        .unwrap();
    s.attach("ws-2").unwrap();
    s.note_ack_control(&nonce, "new-probe", true);
    assert!(
        s.recovery_deadline().is_some(),
        "old epoch heartbeat nonce cleared recovery deadline in epoch={} before any new-channel ping proof",
        r.epoch
    );
}

#[test]
fn spec_boundary_resume_attaching_bypasses_suspended_quota() {
    let (_client, backend) = backend_pair();
    let s = session_with_receipts(backend, 64);
    s.enable_recovery(Duration::from_secs(1));
    s.set_suspended_retention(Arc::new(crate::resource::retention::Retention::new(1)));
    s.attach("ws-1").unwrap();
    s.note_ack_control("", "", true);
    s.mark_down_produced(b"two bytes").unwrap();
    let r = s.resume(&resume_req(&s, "active-resume"), Duration::from_millis(50));
    assert!(
        s.is_closed(),
        "recovery ATTACHING retained data above suspended quota without eviction ({r:?})"
    );
}

#[test]
fn spec_reserved_up_frame_ownership() {
    let (_client, backend) = backend_pair();
    let s = session_with_receipts(backend, 64);
    let raw = crate::resource::budget::Budget::new(8192);
    s.set_global_payload_budget(raw.clone(), Duration::from_secs(5))
        .unwrap();
    s.attach("ws-1").unwrap();
    let data = b"reserved";
    s.ingest_up(1, 8, data).expect("out-of-order frame refused");
    assert_eq!(raw.used(), data.len() as i64, "queued frame not charged");
    s.ingest_up(1, 8, data).expect("duplicate refused");
    assert_eq!(raw.used(), data.len() as i64, "duplicate charged twice");
    let e = s.ingest_up(1, 9, data).expect_err("overlap accepted");
    assert_eq!(e.code, ERR_FRAME_CONFLICT, "{e}");
    s.close(Error::new(wire::ERR_SESSION_CLOSED, "test").closed(true));
    assert_eq!(raw.used(), 0, "payload not returned");
}

#[test]
fn spec_watch_down_reserve_wakes_on_release() {
    let (_client, backend) = backend_pair();
    let s = session_with_receipts(backend, 64);
    s.attach("ws-1").unwrap();
    // Without a payload budget nothing waits.
    assert_eq!(s.reserve_down(10), Some(10));
    let payload = crate::resource::budget::Budget::new(100);
    s.set_global_payload_budget(payload.clone(), Duration::from_secs(5))
        .unwrap();
    let mut held = payload.try_acquire(100).expect("setup");
    let (tx, rx) = std::sync::mpsc::channel();
    let waiter = s.clone();
    std::thread::spawn(move || {
        let _ = tx.send(waiter.reserve_down(10));
    });
    assert!(
        rx.recv_timeout(Duration::from_millis(50)).is_err(),
        "reserved past an exhausted global budget"
    );
    held.release_part(50);
    let got = rx
        .recv_timeout(Duration::from_secs(1))
        .expect("no wake-up on release");
    assert_eq!(got, Some(10), "reserve after release");
}

fn ack(s: &Session, down: u64, ready: bool, nonce: &str, probe: &str) -> Result<()> {
    s.apply_up_confirmation(0)?;
    s.apply_down_ack(down, false)?;
    s.note_ack_control(nonce, probe, ready);
    Ok(())
}

#[test]
fn spec_resume_after_inflight_emit_ready() {
    let (_client, backend) = backend_pair();
    let s = session_with_receipts(backend, 64);
    s.enable_recovery(Duration::from_secs(5));
    s.attach("ws-1").unwrap();
    s.note_ack_control("", "", true);
    assert_eq!(s.mark_down_produced(b"abc").unwrap(), 0);
    assert!(s.suspend_current());
    let mut req = resume_req(&s, "r1");
    req.down_delivered_offset = 3;
    s.resume(&req, Duration::ZERO).expect("resume");
    s.attach("ws-2").unwrap();
    ack(&s, 3, true, "", "").expect("ready ack after resume");
    assert!(
        s.inner.lock().unwrap().data_plane_active,
        "data plane not active after ready ACK"
    );
    assert_eq!(s.mark_down_produced(b"def").unwrap(), 3);
    ack(&s, 6, false, "", "").expect("ack in new epoch");
    assert_eq!(s.snapshot().down_ack_offset, 6, "down ack offset");
}

#[test]
fn spec_resume_barrier_slow_write_terminates() {
    use std::io::Read;
    let (mut client, backend) = backend_pair();
    let s = session_with_receipts(backend, 64);
    s.enable_recovery(Duration::from_secs(5));
    s.attach("ws-1").unwrap();
    s.ingest_up(1, 0, b"slow").unwrap();
    s.inner.lock().unwrap().up_write_active = true;
    let mut req = resume_req(&s, "slow");
    req.up_next_offset = 4;
    let started = std::time::Instant::now();
    let err = s
        .resume(&req, Duration::from_millis(30))
        .expect_err("barrier timeout committed");
    assert_eq!(err.code, wire::ERR_SESSION_CLOSED, "{err}");
    assert!(err.session_closed, "barrier failure is not terminal");
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(s.is_closed(), "state after barrier timeout, want CLOSED");
    // The original backend socket is closed: the peer reads EOF.
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut buf = Vec::new();
    client
        .read_to_end(&mut buf)
        .expect("backend socket not closed");
    s.inner.lock().unwrap().up_write_active = false;
    assert_eq!(
        s.resume(&req, Duration::from_millis(30)).unwrap_err().code,
        wire::ERR_SESSION_CLOSED,
        "retry after barrier failure"
    );
    assert!(s.is_closed());
    assert_eq!(s.epoch(), 1, "epoch after retry");
}

#[test]
fn spec_resume_barrier_grace_expiry_reason() {
    let (_client, backend) = backend_pair();
    let s = session_with_receipts(backend, 64);
    s.enable_recovery(Duration::from_millis(150));
    s.attach("ws-1").unwrap();
    s.ingest_up(1, 0, b"slow").unwrap();
    s.inner.lock().unwrap().up_write_active = true;
    let mut req = resume_req(&s, "slow");
    req.up_next_offset = 4;
    let err = s.resume(&req, Duration::from_secs(1)).unwrap_err();
    assert_eq!(err.code, wire::ERR_RESUME_EXPIRED, "{err}");
    assert!(s.is_closed(), "session not closed at grace deadline");
    assert_eq!(
        s.terminal_error().unwrap().code,
        wire::ERR_RESUME_EXPIRED,
        "terminal code"
    );
}

#[test]
fn spec_session_lifecycle_and_resume() {
    let (_client, backend) = backend_pair();
    let s = session_with_receipts(backend, 64);
    s.enable_recovery(Duration::from_millis(100));
    assert_eq!(s.epoch(), 1, "initial epoch");
    s.attach("sse-1").unwrap();
    s.note_ack_control("", "", true);
    assert_eq!(s.wait_while_attaching(Duration::ZERO), State::Active);
    assert_eq!(s.mark_down_produced(b"database handshake").unwrap(), 0);
    s.ingest_up(1, 0, b"client auth").unwrap();
    assert_eq!(s.snapshot().ack_up_offset, 11, "UpWrittenOffset");
    assert!(s.suspend_current(), "suspend with recovery enabled");
    assert_eq!(
        s.recovery_state(),
        super::recovery::RecoveryState::Suspended
    );
    let mut req = resume_req(&s, "rr_test123");
    req.known_up_ack_offset = 11;
    req.up_next_offset = 11;
    let resp = s.resume(&req, Duration::from_secs(5)).expect("resume");
    assert_eq!(resp.epoch, 2, "new epoch");
    assert_eq!(s.wait_while_attaching(Duration::ZERO), State::Attaching);
    s.attach("sse-2").unwrap();
    s.note_ack_control("", "", true);
    let nonce = s.ping_control().unwrap().nonce.unwrap();
    ack(&s, 0, false, &nonce, "test-probe").unwrap();
    std::thread::sleep(Duration::from_millis(120));
    assert!(
        !s.expire_recovery() && !s.is_closed(),
        "grace fired after data plane activation"
    );
    s.close(Error::new(wire::ERR_SESSION_CLOSED, "closed").closed(true));
    assert!(s.is_closed(), "expected CLOSED");
}

#[test]
fn spec_recovery_requires_current_stream_challenge() {
    let (_client, backend) = backend_pair();
    let s = session_with_receipts(backend, 64);
    s.enable_recovery(Duration::from_secs(1));
    s.attach("ws-1").unwrap();
    s.note_ack_control("", "", true);
    let old = s.ping_control().unwrap().nonce.unwrap();
    assert!(s.suspend_current());
    s.resume(&resume_req(&s, "new-challenge"), Duration::from_secs(1))
        .unwrap();
    s.attach("ws-2").unwrap();
    ack(&s, 0, true, &old, "probe").unwrap();
    assert!(
        s.recovery_deadline().is_some(),
        "old proof cleared deadline"
    );
    let fresh = s.ping_control().unwrap().nonce.unwrap();
    assert_ne!(fresh, old, "challenge not renewed");
    ack(&s, 0, false, &fresh, "probe").unwrap();
    assert!(
        s.recovery_deadline().is_none(),
        "new bidirectional proof did not finish recovery"
    );
}

#[test]
fn spec_old_worker_cannot_close_or_suspend_recovery() {
    use std::io::Read;
    let (mut client, backend) = backend_pair();
    let s = session_with_receipts(backend, 64);
    s.enable_recovery(Duration::from_secs(5));
    s.attach("ws-1").unwrap();
    s.note_ack_control("", "", true);
    let payload = b"original backend socket";
    s.ingest_up(1, 0, payload).unwrap();
    s.inner.lock().unwrap().up_write_active = true;
    let mut req = resume_req(&s, "barrier-recovery");
    req.up_next_offset = payload.len() as u64;
    let resumer = {
        let s = s.clone();
        std::thread::spawn(move || s.resume(&req, Duration::from_secs(1)))
    };
    let until = std::time::Instant::now() + Duration::from_secs(1);
    while !s.inner.lock().unwrap().resume_busy {
        assert!(
            std::time::Instant::now() < until,
            "resume barrier did not start"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    // The old worker ends: its suspend leaves the barrier in charge.
    let _ = s.suspend(1);
    assert!(
        !s.is_closed(),
        "old protocol worker closed the frozen session"
    );
    assert_eq!(
        s.recovery_state(),
        super::recovery::RecoveryState::Suspended,
        "old close callback changed the recovery state"
    );
    assert!(s.inner.lock().unwrap().resume_busy);
    let mut got = vec![0u8; payload.len()];
    client.read_exact(&mut got).unwrap();
    assert_eq!(&got, payload, "backend");
    s.inner.lock().unwrap().up_write_active = false;
    s.cv.notify_all();
    resumer.join().unwrap().expect("resume");
    s.attach("ws-2").unwrap();
    s.note_ack_control("", "", true);
    assert!(!s.suspend(1), "old worker suspended epoch 2");
    assert_eq!(
        s.check_stream(1, "ws-1").unwrap_err().code,
        wire::ERR_STALE_EPOCH,
        "old worker still bound"
    );
    assert!(s.check_stream(2, "ws-2").is_ok());
    assert_eq!(s.wait_while_attaching(Duration::ZERO), State::Active);
    assert!(!s.is_closed(), "new generation lost original backend");
}

#[test]
fn spec_barrier_guards() {
    let (_client, backend) = backend_pair();
    let s = session_with_receipts(backend, 64);
    s.enable_recovery(Duration::from_secs(5));
    s.attach("ws-1").unwrap();
    assert!(s.suspend_current());
    let first = s
        .resume(&resume_req(&s, "r1"), Duration::from_secs(1))
        .unwrap();
    assert_eq!(first.epoch, 2);
    let mut replay = resume_req(&s, "r1");
    replay.expected_epoch = 1;
    {
        let mut g = s.inner.lock().unwrap();
        g.resume_busy = true;
        g.recovery_state_suspended = true;
    }
    assert_eq!(
        s.resume(&replay, Duration::from_secs(1)).unwrap_err().code,
        wire::ERR_RESUME_IN_PROGRESS,
        "replay during barrier"
    );
    assert!(s.attach("ws-2").is_err(), "reserve during barrier");
}

#[test]
fn spec_healthy_ack_skips_recovery_completion() {
    use std::sync::atomic::{AtomicI64, Ordering};
    let (_client, backend) = backend_pair();
    let s = session_with_receipts(backend, 64);
    s.enable_recovery(Duration::from_secs(5));
    let ret = Arc::new(crate::resource::retention::Retention::new(64 << 20));
    let calls = Arc::new(AtomicI64::new(0));
    let counted = calls.clone();
    ret.register(Some(crate::resource::retention::RetentionLease::new(
        std::time::Instant::now(),
        move || {
            counted.fetch_add(1, Ordering::SeqCst);
            0
        },
        || {},
    )));
    s.set_suspended_retention(ret);
    s.attach("ws-1").unwrap();
    s.note_ack_control("", "", true);
    let nonce = s.ping_control().unwrap().nonce.unwrap();
    calls.store(0, Ordering::SeqCst);
    for _ in 0..200 {
        ack(&s, 0, false, &nonce, "p").unwrap();
    }
    std::thread::sleep(Duration::from_millis(50));
    let n = calls.load(Ordering::SeqCst);
    assert!(n <= 10, "200 healthy ACKs caused {n} retention passes");
}

#[test]
fn spec_short_reads_do_not_pin_read_allocation() {
    let (_client, backend) = backend_pair();
    let s = session_with_receipts(backend, 64);
    let payload = crate::resource::budget::Budget::new(64 << 20);
    s.set_global_payload_budget(payload.clone(), Duration::from_secs(5))
        .unwrap();
    s.attach("ws-1").unwrap();
    for i in 0..400 {
        let r = s
            .reserve_down_for_read(1, 32 << 10)
            .unwrap_or_else(|| panic!("frame {i}: session closed"));
        s.mark_down_produced_reserved(b"x", r)
            .unwrap_or_else(|e| panic!("frame {i}: window full after {i} one-byte frames: {e}"));
    }
    assert_eq!(payload.used(), 400, "payload charged for short reads");
    assert_eq!(s.inner.lock().unwrap().down_window.buffered_bytes(), 400);
    assert!(
        s.ack_requested(),
        "400 retained frames should ask for an ACK"
    );
    let r = s.reserve_down_for_read(1, 1024).expect("reserve");
    s.mark_down_produced_reserved(&[0u8; 1000], r).unwrap();
    assert_eq!(payload.used(), 1400, "payload after a 1000 byte read");
}
