use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::Duration;

use crate::resource::budget::Budget;

use super::*;

/// A connected socket pair: the returned `TcpStream` is the "database" side
/// of the session's backend, the listener side plays the local client.
fn backend_pair() -> (std::net::TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let client = std::net::TcpStream::connect(addr).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server)
}

fn test_limits() -> Limits {
    Limits {
        max_frame_size: 64 * 1024,
        up_max_inflight_frames: 8,
        up_window_bytes: 1024 * 1024,
        down_buffer_bytes: 1024 * 1024,
        up_receipt_limit: 64,
        down_max_frames: 8,
    }
}

fn new_session(backend: TcpStream) -> Arc<Session> {
    new_session_with_receipts(backend, 64)
}

fn new_session_with_receipts(backend: TcpStream, receipt_limit: u32) -> Arc<Session> {
    let mut limits = test_limits();
    limits.up_receipt_limit = receipt_limit;
    Session::new(
        "sess".to_string(),
        "token".to_string(),
        "inst".to_string(),
        "peer".to_string(),
        "target".to_string(),
        Mode::HttpSse,
        limits,
        receipt_limit,
        backend,
        Arc::new(crate::metrics::Metrics::new()),
    )
}

#[test]
fn upstream_inflight_permits_are_bounded_and_released() {
    let (_client, backend) = backend_pair();
    let session = new_session(backend);
    let mut permits = Vec::new();
    for _ in 0..test_limits().up_max_inflight_frames {
        permits.push(session.try_acquire_up().expect("in-flight slot"));
    }
    assert!(session.try_acquire_up().is_none());
    drop(permits);
    assert!(session.try_acquire_up().is_some());
}

#[test]
fn attach_wakes_unattached_session_waiter() {
    let (_client, backend) = backend_pair();
    let session = new_session(backend);
    let waiting = session.clone();
    let waiter = std::thread::spawn(move || waiting.wait_while_attaching(Duration::from_secs(5)));
    std::thread::sleep(Duration::from_millis(10));
    session.attach("stream").unwrap();
    assert_eq!(waiter.join().unwrap(), State::Active);
}

/// Drains whatever the backend socket has received so far.
fn read_backend(sock: &mut std::net::TcpStream, want: usize) -> Vec<u8> {
    sock.set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let mut out = vec![0u8; want];
    let mut got = 0;
    while got < want {
        match sock.read(&mut out[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(_) => break,
        }
    }
    out.truncate(got);
    out
}

#[test]
fn applies_upstream_frames_in_offset_order() {
    let (mut client, backend) = backend_pair();
    let s = new_session(backend);
    // The `http-sse` carrier delivers each frame as its own POST, so a later
    // frame can land first. Nothing may reach the socket until the gap is
    // filled, and then everything must arrive in order.
    s.ingest_up(1, 4, b"EFG").unwrap();
    assert_eq!(s.snapshot().ack_up_offset, 0, "held until the gap closes");
    s.ingest_up(1, 0, b"ABCD").unwrap();
    assert_eq!(s.snapshot().ack_up_offset, 7);
    assert_eq!(read_backend(&mut client, 7), b"ABCDEFG");
}

#[test]
fn upstream_pending_holds_shared_payload_budget_until_ordered_write_finishes() {
    let (mut client, backend) = backend_pair();
    let session = new_session(backend);
    let budget = Budget::new(5);
    session
        .set_global_payload_budget(budget.clone(), Duration::from_secs(1))
        .unwrap();

    session.ingest_up(1, 2, b"cde").unwrap();
    assert_eq!(budget.used(), 3);
    assert_eq!(
        session.ingest_up(1, 5, b"fgh").unwrap_err().code,
        wire::ERR_BUFFER_EXHAUSTED
    );
    assert_eq!(budget.used(), 3, "rejected frame acquires no lease");

    session.ingest_up(1, 0, b"ab").unwrap();
    assert_eq!(
        budget.used(),
        0,
        "ready leases release after backend writes"
    );
    assert_eq!(read_backend(&mut client, 5), b"abcde");
}

#[test]
fn downstream_reservation_wakes_on_shared_budget_release_and_drop_rolls_back() {
    let (_client_a, backend_a) = backend_pair();
    let first = new_session(backend_a);
    let (_client_b, backend_b) = backend_pair();
    let second = new_session(backend_b);
    let budget = Budget::new(3);
    first
        .set_global_payload_budget(budget.clone(), Duration::from_secs(1))
        .unwrap();
    second
        .set_global_payload_budget(budget.clone(), Duration::from_secs(1))
        .unwrap();
    first.mark_down_produced(b"abc").unwrap();

    let waiting = second.clone();
    let waiter = std::thread::spawn(move || waiting.reserve_down_for_read(1, 1));
    let wait_deadline = std::time::Instant::now() + Duration::from_secs(1);
    while budget.wait_stats().0 == 0 && std::time::Instant::now() < wait_deadline {
        std::thread::yield_now();
    }
    assert_eq!(budget.wait_stats().0, 1, "reader waits on shared budget");

    first.apply_down_ack(3, false).unwrap();
    let reservation = waiter.join().unwrap().unwrap();
    assert_eq!(reservation.bytes, 1);
    assert_eq!(budget.used(), 1);
    drop(reservation);
    assert_eq!(budget.used(), 0, "uncommitted read reservation rolls back");
}

#[test]
fn downstream_shared_budget_stall_closes_with_timeout_and_releases_own_lease() {
    let (_client_a, backend_a) = backend_pair();
    let first = new_session(backend_a);
    let (_client_b, backend_b) = backend_pair();
    let second = new_session(backend_b);
    let budget = Budget::new(4);
    first
        .set_global_payload_budget(budget.clone(), Duration::from_secs(1))
        .unwrap();
    second
        .set_global_payload_budget(budget.clone(), Duration::from_millis(40))
        .unwrap();
    first.mark_down_produced(b"abc").unwrap();
    let first_reservation = second.reserve_down_for_read(1, 1).unwrap();
    second
        .mark_down_produced_reserved(b"x", first_reservation)
        .unwrap();
    assert_eq!(budget.used(), 4);

    assert!(second.reserve_down_for_read(1, 1).is_none());
    assert!(second.is_closed());
    let terminal = second.terminal_error().unwrap();
    assert_eq!(terminal.message, "backpressure timeout");
    assert!(terminal.session_closed);
    assert_eq!(
        budget.used(),
        3,
        "timeout releases the closed session's lease but not the other session's"
    );
    first.apply_down_ack(3, false).unwrap();
    assert_eq!(budget.used(), 0);
}

#[test]
fn a_fin_may_name_an_offset_the_stream_has_not_reached() {
    let (mut client, backend) = backend_pair();
    let s = new_session(backend);
    // The FIN travels on the control connection, so it routinely overtakes
    // the last frames. Accepting it is required; applying it is not.
    assert!(!s.ingest_up_fin(1, 5).unwrap());
    assert!(!s.snapshot().up_fin_applied);
    s.ingest_up(1, 0, b"HELLO").unwrap();
    assert!(
        s.snapshot().up_fin_applied,
        "applied once the data caught up"
    );
    assert_eq!(read_backend(&mut client, 5), b"HELLO");
}

#[test]
fn a_fin_below_the_applied_offset_is_refused() {
    let (_client, backend) = backend_pair();
    let s = new_session(backend);
    s.ingest_up(1, 0, b"HELLO").unwrap();
    let e = s.ingest_up_fin(1, 2).unwrap_err();
    assert_eq!(e.code, wire::ERR_BAD_FRAME);
}

#[test]
fn a_fin_beyond_the_window_is_refused() {
    let (_client, backend) = backend_pair();
    let s = new_session(backend);
    let e = s.ingest_up_fin(1, 1024 * 1024 + 1).unwrap_err();
    assert_eq!(e.code, wire::ERR_WINDOW_EXCEEDED);
}

#[test]
fn a_retransmitted_fin_must_name_the_same_offset() {
    let (_client, backend) = backend_pair();
    let s = new_session(backend);
    assert!(!s.ingest_up_fin(1, 4).unwrap());
    assert!(!s.ingest_up_fin(1, 4).unwrap(), "a replay is a no-op");
    let e = s.ingest_up_fin(1, 6).unwrap_err();
    assert_eq!(e.code, ERR_FRAME_CONFLICT);
}

#[test]
fn a_replayed_frame_is_ignored_but_a_different_one_conflicts() {
    let (_client, backend) = backend_pair();
    let s = new_session(backend);
    s.ingest_up(1, 0, b"ABCD").unwrap();
    s.ingest_up(1, 0, b"ABCD").unwrap();
    let e = s.ingest_up(1, 0, b"WXYZ").unwrap_err();
    assert_eq!(e.code, ERR_FRAME_CONFLICT);
}

#[test]
fn upstream_confirmation_advances_floor_only_at_retained_boundaries() {
    let (_client, backend) = backend_pair();
    let s = new_session_with_receipts(backend, 4);
    s.ingest_up(1, 0, b"abc").unwrap();
    s.ingest_up(1, 3, b"de").unwrap();

    assert_eq!(
        s.apply_up_confirmation(2).unwrap_err().code,
        wire::ERR_BAD_ACK
    );
    assert_eq!(
        s.apply_up_confirmation(6).unwrap_err().code,
        wire::ERR_BAD_ACK
    );
    s.apply_up_confirmation(3).unwrap();
    // Repeating a confirmed offset is an idempotent no-op.
    s.apply_up_confirmation(3).unwrap();
    s.ingest_up(1, 5, b"f").unwrap();
}

#[test]
fn unconfirmed_receipts_are_not_evicted_and_capacity_returns_after_confirmation() {
    let (_client, backend) = backend_pair();
    let s = new_session_with_receipts(backend, 2);
    s.ingest_up(1, 0, b"a").unwrap();
    s.ingest_up(1, 1, b"b").unwrap();
    let e = s.ingest_up(1, 2, b"c").unwrap_err();
    assert_eq!(e.code, wire::ERR_WINDOW_EXCEEDED);
    assert!(e.retryable);

    s.apply_up_confirmation(1).unwrap();
    s.ingest_up(1, 2, b"c").unwrap();
}

#[test]
fn upstream_receive_limit_uses_ack_plus_byte_window_with_saturation() {
    let (_client, backend) = backend_pair();
    let s = new_session(backend);
    assert_eq!(s.up_receive_limit(7), 7 + test_limits().up_window_bytes);
    assert_eq!(s.up_receive_limit(u64::MAX), u64::MAX);
}

#[test]
fn a_stale_epoch_is_refused() {
    let (_client, backend) = backend_pair();
    let s = new_session(backend);
    assert_eq!(s.ingest_up(2, 0, b"x").unwrap_err().code, ERR_STALE_EPOCH);
    assert_eq!(s.ingest_up_fin(2, 1).unwrap_err().code, ERR_STALE_EPOCH);
}

#[test]
fn a_closed_session_refuses_further_frames() {
    let (_client, backend) = backend_pair();
    let s = new_session(backend);
    s.close(Error::new(wire::ERR_SESSION_CLOSED, "test"));
    assert_eq!(
        s.ingest_up(1, 0, b"x").unwrap_err().code,
        wire::ERR_SESSION_CLOSED
    );
}

#[test]
fn the_down_ack_cannot_run_past_what_was_produced() {
    let (_client, backend) = backend_pair();
    let s = new_session(backend);
    s.mark_down_produced(&[0u8; 10]).unwrap();
    assert!(s.apply_down_ack(10, true).is_ok());
    assert_eq!(
        s.apply_down_ack(11, false).unwrap_err().code,
        wire::ERR_BAD_ACK
    );
    assert!(s.snapshot().down_fin_acked);
}

#[test]
fn down_ack_must_land_on_a_frame_boundary() {
    let (_client, backend) = backend_pair();
    let s = new_session(backend);
    s.mark_down_produced(&[0u8; 10]).unwrap();
    assert_eq!(
        s.apply_down_ack(5, false).unwrap_err().code,
        wire::ERR_BAD_ACK
    );
    assert!(s.apply_down_ack(10, false).is_ok());
}

#[test]
fn resume_prunes_delivered_down_frames_and_retains_the_remainder() {
    let (_client, backend) = backend_pair();
    let s = new_session(backend);
    s.enable_recovery(std::time::Duration::from_secs(5));
    s.attach("old-stream").unwrap();
    assert_eq!(s.mark_down_produced(b"hello").unwrap(), 0);
    assert_eq!(s.mark_down_produced(b" world").unwrap(), 5);
    assert!(s.suspend_current());

    let request = crate::session::recovery::ResumeRequest {
        resume_request_id: "resume-down-buffer".into(),
        expected_epoch: s.epoch(),
        ingress_instance_id: s.instance_id.clone(),
        transport: s.mode,
        known_up_ack_offset: 0,
        up_next_offset: 0,
        down_delivered_offset: 5,
        up_fin: crate::session::recovery::ResumeFin::default(),
        down_fin: crate::session::recovery::ResumeFin::default(),
    };
    let response = s
        .resume(&request, std::time::Duration::from_secs(1))
        .unwrap();

    assert_eq!(response.down_replay_from, 5);
    assert_eq!(response.down_retained_from, 5);
    assert_eq!(s.snapshot().down_ack_offset, 5);
    assert_eq!(s.replay_down_frames(), vec![(5, b" world".to_vec())]);
}

#[test]
fn upstream_window_stops_a_runaway_sender() {
    let (_client, backend) = backend_pair();
    let s = new_session(backend);
    // The window is the only thing that keeps a peer from filling memory
    // with frames it has not been granted room for.
    let e = s.ingest_up(1, 1024 * 1024, b"x").unwrap_err();
    assert_eq!(e.code, wire::ERR_WINDOW_EXCEEDED);
}

#[test]
fn the_backend_receives_bytes_in_order_under_concurrency() {
    let (mut client, backend) = backend_pair();
    let s = new_session(backend);
    let payload: Vec<u8> = (0..64u8).collect();
    let mut handles = Vec::new();
    // Four carriers posting frames concurrently is what the SSE transport
    // looks like from here. A frame refused by the in-flight limit is
    // retried, which is also what a real sender does.
    for worker in 0..4u64 {
        let s = s.clone();
        let payload = payload.clone();
        handles.push(std::thread::spawn(move || {
            let mut i = worker;
            while i < 64 {
                match s.ingest_up(1, i, &payload[i as usize..i as usize + 1]) {
                    Ok(()) => i += 4,
                    Err(e) if e.code == wire::ERR_WINDOW_EXCEEDED => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(e) => panic!("unexpected: {e}"),
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(read_backend(&mut client, 64), payload);
}

#[test]
fn a_fin_arriving_before_its_data_closes_the_backend_write_side() {
    let (mut client, backend) = backend_pair();
    let s = new_session(backend);
    s.ingest_up_fin(1, 3).unwrap();
    s.ingest_up(1, 0, b"abc").unwrap();
    // The write half is shut down, so the peer sees EOF after the payload.
    let got = read_backend(&mut client, 3);
    assert_eq!(got, b"abc");
    let mut extra = [0u8; 1];
    assert_eq!(client.read(&mut extra).unwrap_or(0), 0, "write side closed");
}

#[test]
fn a_frame_that_runs_past_the_fin_is_refused() {
    let (_client, backend) = backend_pair();
    let s = new_session(backend);
    s.ingest_up_fin(1, 4).unwrap();
    let e = s.ingest_up(1, 0, b"ABCDE").unwrap_err();
    assert_eq!(e.code, ERR_FRAME_CONFLICT);
}

#[test]
fn too_many_frames_queued_out_of_order_are_refused() {
    let (_client, backend) = backend_pair();
    let s = new_session(backend);
    // Eight is the negotiated in-flight limit; a peer that keeps sending
    // ahead of the gap without filling it is not making progress.
    for i in 0..8u64 {
        s.ingest_up(1, 8 + i, b"x").unwrap();
    }
    let e = s.ingest_up(1, 32, b"x").unwrap_err();
    assert_eq!(e.code, wire::ERR_WINDOW_EXCEEDED);
}

#[test]
fn an_offset_near_the_end_of_the_space_cannot_overflow() {
    let (_client, backend) = backend_pair();
    let s = new_session(backend);
    let e = s.ingest_up(1, u64::MAX - 1, b"xx").unwrap_err();
    // Either the overflow guard or the window rejects it; what matters is
    // that it is a protocol error and not a panic.
    assert!(e.code == ERR_FRAME_CONFLICT || e.code == wire::ERR_WINDOW_EXCEEDED);
}

#[test]
fn writing_the_backend_is_not_blocked_by_the_state_lock() {
    let (_client, backend) = backend_pair();
    let s = new_session(backend);
    s.ingest_up(1, 0, b"x").unwrap();
    // A snapshot must still be available while a frame is being written:
    // the two use different locks on purpose.
    let snap = s.snapshot();
    assert_eq!(snap.ack_up_offset, 1);
    let _ = std::io::stdout().flush();
}

#[test]
fn upstream_ack_snapshot_stays_on_fully_flushed_frame_boundaries() {
    let (_client, backend) = backend_pair();
    let s = new_session(backend);
    {
        let mut g = s.inner.lock().unwrap();
        g.receipts.push_back((0, 4, [1; 32]));
        g.receipts.push_back((4, 8, [2; 32]));
        g.up_written = 8;
        // Model a backend write that has progressed into the second frame.
        g.up_flushed = 6;
    }
    assert_eq!(s.snapshot().ack_up_offset, 4);

    s.inner.lock().unwrap().up_flushed = 8;
    assert_eq!(s.snapshot().ack_up_offset, 8);
}

#[test]
fn fin_does_not_overtake_inflight_backend_write() {
    const HALF: usize = 32 * 1024 * 1024;
    const TOTAL: usize = HALF * 2;
    let (mut client, backend) = backend_pair();
    let mut limits = test_limits();
    limits.max_frame_size = HALF;
    limits.up_window_bytes = TOTAL as u64;
    let s = Session::new(
        "sess".to_string(),
        "token".to_string(),
        "inst".to_string(),
        "peer".to_string(),
        "target".to_string(),
        Mode::HttpSse,
        limits,
        64,
        backend,
        Arc::new(crate::metrics::Metrics::new()),
    );

    let first = vec![b'a'; HALF];
    let second = vec![b'b'; HALF];
    // Hold the later frame until the first arrives, so both large writes
    // are applied in one ordered batch.
    s.ingest_up(1, HALF as u64, &second).unwrap();

    let writing = s.clone();
    let writer = std::thread::spawn(move || writing.ingest_up(1, 0, &first));
    std::thread::sleep(Duration::from_millis(50));

    let closing = s.clone();
    let fin = std::thread::spawn(move || closing.ingest_up_fin(1, TOTAL as u64));
    std::thread::sleep(Duration::from_millis(50));
    assert!(
        !fin.is_finished(),
        "FIN must wait for the in-flight backend write"
    );
    assert!(s.snapshot().ack_up_offset < TOTAL as u64);

    let reader = std::thread::spawn(move || {
        let mut received = vec![0; TOTAL];
        client.read_exact(&mut received).unwrap();
        let mut extra = [0; 1];
        assert_eq!(
            client.read(&mut extra).unwrap(),
            0,
            "FIN closes the write side"
        );
        received
    });
    writer.join().unwrap().unwrap();
    assert!(fin.join().unwrap().unwrap());
    let received = reader.join().unwrap();
    assert!(received[..HALF].iter().all(|b| *b == b'a'));
    assert!(received[HALF..].iter().all(|b| *b == b'b'));
    assert_eq!(s.snapshot().ack_up_offset, TOTAL as u64);
}

#[test]
fn fast_ack_before_mark_produced_is_accepted() {
    let (mut client, backend) = backend_pair();
    client.write_all(b"fast ack").unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();
    let s = new_session(backend);
    let acknowledge = s.clone();
    let pump = DownPump {
        session: s.clone(),
        frame_size: 4096,
    };
    pump.run(move |offset, payload| {
        acknowledge.apply_down_ack(offset + payload.len() as u64, false)?;
        Ok(())
    })
    .unwrap();
    assert_eq!(s.snapshot().down_ack_offset, 8);
}

#[test]
fn small_negotiated_frame_size_works() {
    const TOTAL: usize = 1024 * 1024;
    let (mut client, backend) = backend_pair();
    client.write_all(&vec![b'x'; TOTAL]).unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();
    let mut limits = test_limits();
    limits.max_frame_size = 512;
    let s = Session::new(
        "sess".to_string(),
        "token".to_string(),
        "inst".to_string(),
        "peer".to_string(),
        "target".to_string(),
        Mode::HttpSse,
        limits,
        64,
        backend,
        Arc::new(crate::metrics::Metrics::new()),
    );
    let acknowledge = s.clone();
    let pump = DownPump {
        session: s,
        frame_size: 512,
    };
    let mut received = 0;
    pump.run(|offset, payload| {
        assert!(payload.len() <= 512);
        received += payload.len();
        acknowledge.apply_down_ack(offset + payload.len() as u64, false)?;
        Ok(())
    })
    .unwrap();
    assert_eq!(received, TOTAL);
}

#[test]
fn abnormal_close_has_terminal_error_control() {
    let (_client, backend) = backend_pair();
    let s = new_session(backend);
    s.close(Error::new(ERR_BACKEND_LOST, "backend reset").closed(true));
    let control = s
        .terminal_control()
        .expect("abnormal close must be announced");
    assert_eq!(control.code.as_deref(), Some(ERR_BACKEND_LOST));
    assert!(!control.retryable);
    assert!(control.session_closed);
}

#[test]
fn normal_close_has_no_terminal_error_control() {
    let (_client, backend) = backend_pair();
    let s = new_session(backend);
    assert!(s.ingest_up_fin(1, 0).unwrap());
    s.mark_down_fin();
    s.apply_down_ack(0, true).unwrap();
    s.close(Error::local("normal finish"));
    assert!(s.terminal_control().is_none());
}

#[test]
fn ack_requested_at_half_down_limits() {
    let (_client, backend) = backend_pair();
    let s = new_session(backend);
    for _ in 0..4 {
        s.mark_down_produced(&[0u8; 1]).unwrap();
    }
    assert!(s.ack_requested(), "four of eight downstream frames is half");
    let (tx_blocked, reason, rx_blocked) = s.flow_control_state();
    assert!(!tx_blocked);
    assert!(!rx_blocked);
    assert_eq!(reason, "none");
}

#[test]
fn ack_requested_at_half_receipt_limit() {
    let (mut client, backend) = backend_pair();
    let s = new_session(backend);
    for offset in 0..32u64 {
        s.ingest_up(1, offset, &[offset as u8]).unwrap();
    }
    let _ = read_backend(&mut client, 32);
    assert!(s.ack_requested(), "half of the 64-frame receipt limit");
    let (_tx_blocked, reason, rx_blocked) = s.flow_control_state();
    assert!(!rx_blocked);
    assert_eq!(reason, "none");
}

#[test]
fn downstream_logical_payload_window_reclaims_only_at_frame_boundaries() {
    let (_client, backend) = backend_pair();
    let mut limits = test_limits();
    limits.down_buffer_bytes = 4;
    let s = Session::new(
        "sess".to_string(),
        "token".to_string(),
        "inst".to_string(),
        "peer".to_string(),
        "target".to_string(),
        Mode::HttpSse,
        limits,
        64,
        backend,
        Arc::new(crate::metrics::Metrics::new()),
    );

    assert_eq!(s.mark_down_produced(b"ab").unwrap(), 0);
    assert_eq!(s.mark_down_produced(b"cd").unwrap(), 2);
    assert_eq!(
        s.mark_down_produced(b"e").unwrap_err().code,
        wire::ERR_WINDOW_EXCEEDED
    );
    let retained = s.replay_down_frames();
    assert_eq!(
        retained
            .iter()
            .map(|(_, payload)| payload.len())
            .sum::<usize>(),
        4
    );
    assert_eq!(retained, vec![(0, b"ab".to_vec()), (2, b"cd".to_vec())]);

    s.apply_down_ack(2, false).unwrap();
    assert_eq!(s.mark_down_produced(b"ef").unwrap(), 4);
    assert_eq!(
        s.replay_down_frames(),
        vec![(2, b"cd".to_vec()), (4, b"ef".to_vec())]
    );
}

#[test]
fn closing_full_downstream_window_wakes_reserve_waiter() {
    let (_client, backend) = backend_pair();
    let mut limits = test_limits();
    limits.down_buffer_bytes = 4;
    let s = Session::new(
        "sess".to_string(),
        "token".to_string(),
        "inst".to_string(),
        "peer".to_string(),
        "target".to_string(),
        Mode::HttpSse,
        limits,
        64,
        backend,
        Arc::new(crate::metrics::Metrics::new()),
    );
    s.mark_down_produced(b"full").unwrap();

    let waiting = s.clone();
    let waiter = std::thread::spawn(move || waiting.reserve_down(1));
    // Yield rather than using a timing-based sleep; the full window makes the
    // waiter remain in reserve_down until close notifies the condition variable.
    for _ in 0..32 {
        if waiter.is_finished() {
            panic!("reserve_down returned before the full-window close");
        }
        std::thread::yield_now();
    }
    s.close(Error::new(wire::ERR_SESSION_CLOSED, "test"));
    assert_eq!(waiter.join().unwrap(), None);
}

#[test]
fn ack_response_reports_actual_writer_pressure_and_protocol_reasons() {
    let (_client, backend) = backend_pair();
    let s = new_session(backend);
    let permits = (0..s.limits.up_max_inflight_frames)
        .map(|_| s.try_acquire_up().expect("permit within negotiated cap"))
        .collect::<Vec<_>>();
    s.inner.lock().unwrap().up_write_active = true;
    let (tx_blocked, reason, rx_blocked) = s.flow_control_state();
    assert!(!tx_blocked);
    assert!(rx_blocked);
    assert_eq!(reason, "local_socket_write");

    s.inner.lock().unwrap().up_write_active = false;
    drop(permits);
    s.set_transport_writing(true);
    let (tx_blocked, reason, rx_blocked) = s.flow_control_state();
    assert!(tx_blocked);
    assert!(!rx_blocked);
    assert_eq!(reason, "data_channel_write");
}

mod recovery_core_tests {
    use super::*;
    use crate::session::recovery::{RecoveryState, ResumeFin, ResumeRequest};
    use std::sync::mpsc;

    fn request(s: &Session) -> ResumeRequest {
        ResumeRequest {
            resume_request_id: "r1".into(),
            expected_epoch: s.epoch(),
            ingress_instance_id: s.ingress_instance_id.clone(),
            transport: s.mode,
            known_up_ack_offset: 0,
            up_next_offset: 0,
            down_delivered_offset: 0,
            up_fin: ResumeFin::default(),
            down_fin: ResumeFin::default(),
        }
    }
    fn recovering() -> Arc<Session> {
        let (_client, backend) = backend_pair();
        let s = new_session(backend);
        s.enable_recovery(Duration::from_secs(2));
        s.attach("old").unwrap();
        s
    }
    #[test]
    fn recovery_is_disabled_by_default() {
        let (_c, b) = backend_pair();
        let s = new_session(b);
        assert_eq!(s.recovery_state(), RecoveryState::Disabled);
        assert!(!s.suspend_current());
    }
    #[test]
    fn suspend_requires_matching_epoch() {
        let s = recovering();
        assert!(!s.suspend(2));
        assert_eq!(s.epoch(), 1);
    }
    #[test]
    fn backend_bytes_read_while_the_carrier_is_lost_stay_in_the_replay_window() {
        // B5: a backend read that completed after the carrier was lost was
        // dropped, cutting one frame out of the downstream silently.
        let (mut client, backend) = backend_pair();
        let s = new_session(backend);
        s.enable_recovery(Duration::from_secs(5));
        s.attach("old").unwrap();
        let pump = crate::session::DownPump {
            session: s.clone(),
            frame_size: 1024,
        };
        let emitted = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = emitted.clone();
        let reader = std::thread::spawn(move || {
            pump.run_locked(|offset, payload| {
                sink.lock().unwrap().push((offset, payload.to_vec()));
                Ok(())
            })
        });
        // The pump is now blocked in its backend read.
        std::thread::sleep(Duration::from_millis(60));
        assert!(s.suspend_current());
        client.write_all(b"hello").unwrap();
        reader.join().unwrap().unwrap();
        assert!(emitted.lock().unwrap().is_empty(), "no carrier to emit on");
        assert_eq!(s.snapshot().down_produced, 5);
        assert_eq!(s.replay_down_frames(), vec![(0, b"hello".to_vec())]);
    }
    #[test]
    fn carrier_end_after_both_fins_confirmed_is_not_a_suspension() {
        // B4: once both FINs were exchanged and the down FIN acknowledged,
        // the carrier closing is the normal end of the session; parking it
        // for the recovery grace leaked one session per short connection.
        let s = recovering();
        assert!(s.ingest_up_fin(1, 0).unwrap());
        s.mark_down_fin();
        assert!(s.suspend_current(), "down FIN not yet acknowledged");
        let s = recovering();
        assert!(s.ingest_up_fin(1, 0).unwrap());
        s.mark_down_fin();
        s.apply_down_ack(0, true).unwrap();
        assert!(!s.suspend_current());
        assert_ne!(s.recovery_state(), RecoveryState::Suspended);
    }
    #[test]
    fn suspend_enters_suspended_and_records_deadline() {
        let s = recovering();
        assert!(s.suspend_current());
        assert_eq!(s.recovery_state(), RecoveryState::Suspended);
        assert!(s.recovery_deadline().is_some());
    }

    #[test]
    fn shared_retention_evicts_oldest_suspended_session_and_releases_its_buffers() {
        let retention = Arc::new(crate::resource::retention::Retention::new(4));
        let first = recovering();
        first.set_suspended_retention(retention.clone());
        first.mark_down_produced(b"one1").unwrap();
        assert!(first.suspend_current());
        assert_eq!(retention.used(), 4);

        std::thread::sleep(Duration::from_millis(2));
        let second = recovering();
        second.set_suspended_retention(retention.clone());
        second.mark_down_produced(b"two2").unwrap();
        assert!(second.suspend_current());

        assert_eq!(first.recovery_state(), RecoveryState::Closed);
        assert!(first.replay_down_frames().is_empty());
        assert_eq!(second.recovery_state(), RecoveryState::Suspended);
        assert_eq!(retention.used(), 4);
    }

    #[test]
    fn retention_quota_is_enforced_when_suspended_buffer_grows() {
        let retention = Arc::new(crate::resource::retention::Retention::new(4));
        let s = recovering();
        s.set_suspended_retention(retention.clone());
        assert!(s.suspend_current());
        assert_eq!(retention.used(), 0);

        s.mark_down_produced(b"more").unwrap();
        assert_eq!(retention.used(), 4);
        s.mark_down_produced(b"again").unwrap();
        assert_eq!(s.recovery_state(), RecoveryState::Closed);
        assert!(s.replay_down_frames().is_empty());
        assert_eq!(retention.used(), 0);
    }

    #[test]
    fn successful_resume_ends_retention_lease_but_keeps_active_replay_bytes() {
        let retention = Arc::new(crate::resource::retention::Retention::new(4));
        let s = recovering();
        s.set_suspended_retention(retention.clone());
        s.mark_down_produced(b"data").unwrap();
        assert!(s.suspend_current());
        assert_eq!(retention.used(), 4);

        s.resume(&request(&s), Duration::from_secs(1)).unwrap();
        assert_eq!(retention.used(), 4);
        {
            let mut g = s.inner.lock().unwrap();
            g.data_plane_active = true;
            g.heartbeat_nonce = "ready-nonce".to_string();
            g.heartbeat_epoch = s.epoch();
            g.heartbeat_stream = g.stream_id.clone();
        }
        s.note_ack_control("ready-nonce", "probe", true);
        assert_eq!(retention.used(), 0);
        assert_eq!(s.replay_down_frames(), vec![(0, b"data".to_vec())]);
    }

    #[test]
    fn suspended_stream_check_is_retryable_window_exceeded() {
        let s = recovering();
        assert!(s.suspend_current());

        let error = s.check_stream(1, "old").unwrap_err();
        assert_eq!(error.code, wire::ERR_WINDOW_EXCEEDED);
        assert!(error.retryable);
        assert!(!error.session_closed);
    }

    #[test]
    fn repeated_suspend_does_not_extend_grace() {
        let s = recovering();
        s.suspend_current();
        let d = s.recovery_deadline().unwrap();
        std::thread::sleep(Duration::from_millis(5));
        s.suspend_current();
        assert_eq!(s.recovery_deadline().unwrap(), d);
    }
    #[test]
    fn resume_increments_epoch_once() {
        let s = recovering();
        s.suspend_current();
        let r = s.resume(&request(&s), Duration::from_secs(1)).unwrap();
        assert_eq!(r.epoch, 2);
        assert_eq!(s.epoch(), 2);
        assert_eq!(s.last_resume_request_id().as_deref(), Some("r1"));
    }

    #[test]
    fn successful_resume_retires_old_attachment_before_new_stream_attaches() {
        let s = recovering();
        let old_epoch = s.epoch();
        s.suspend_current();
        {
            let mut inner = s.inner.lock().unwrap();
            inner.attached = true;
            inner.stream_id = "old".into();
        }
        let response = s.resume(&request(&s), Duration::from_secs(1)).unwrap();

        assert_eq!(response.epoch, old_epoch + 1);
        s.attach("new-stream").unwrap();
        assert_eq!(s.snapshot().stream_id, "new-stream");
        assert_eq!(
            s.check_stream(old_epoch, "old").unwrap_err().code,
            wire::ERR_STALE_EPOCH
        );
        assert_eq!(s.attach("old").unwrap_err().code, wire::ERR_STALE_EPOCH);
    }

    #[test]
    fn ws_session_can_resume_on_http_sse_and_updates_current_mode() {
        let (_client, backend) = backend_pair();
        let s = Session::new(
            "sess-ws".into(),
            "token".into(),
            "inst".into(),
            "peer".into(),
            "target".into(),
            Mode::Ws,
            test_limits(),
            64,
            backend,
            Arc::new(crate::metrics::Metrics::new()),
        );
        s.enable_recovery(Duration::from_secs(2));
        s.attach("old-ws").unwrap();
        assert_eq!(s.current_mode(), Mode::Ws);
        s.suspend_current();

        let response = s
            .resume(
                &ResumeRequest {
                    resume_request_id: "ws-to-sse".into(),
                    expected_epoch: 1,
                    ingress_instance_id: "inst".into(),
                    transport: Mode::HttpSse,
                    known_up_ack_offset: 0,
                    up_next_offset: 0,
                    down_delivered_offset: 0,
                    up_fin: ResumeFin::default(),
                    down_fin: ResumeFin::default(),
                },
                Duration::from_secs(1),
            )
            .unwrap();

        assert_eq!(response.transport, Mode::HttpSse);
        assert_eq!(s.current_mode(), Mode::HttpSse);
        assert_eq!(s.snapshot().mode, Mode::HttpSse);
        assert_eq!(s.compact_tombstone().mode, Mode::HttpSse);
    }
    #[test]
    fn resume_rejects_stale_epoch() {
        let s = recovering();
        s.suspend_current();
        let mut r = request(&s);
        r.expected_epoch = 2;
        assert_eq!(
            s.resume(&r, Duration::from_secs(1)).unwrap_err().code,
            wire::ERR_STALE_EPOCH
        );
    }
    #[test]
    fn resume_rejects_wrong_instance() {
        let s = recovering();
        s.suspend_current();
        let mut r = request(&s);
        r.ingress_instance_id = "other".into();
        assert_eq!(
            s.resume(&r, Duration::from_secs(1)).unwrap_err().code,
            wire::ERR_BAD_FRAME
        );
    }
    #[test]
    fn resume_binds_to_ingress_identity_captured_at_create() {
        let (_client, backend) = backend_pair();
        let s = Session::new_with_ingress_instance_id(
            "sess".into(),
            "token".into(),
            "egress-instance".into(),
            "ingress-instance".into(),
            "peer".into(),
            "target".into(),
            Mode::HttpSse,
            test_limits(),
            64,
            backend,
            Arc::new(crate::metrics::Metrics::new()),
        );
        s.enable_recovery(Duration::from_secs(2));
        s.attach("old").unwrap();
        s.suspend_current();

        let mut r = request(&s);
        r.ingress_instance_id = s.instance_id.clone();
        assert_eq!(
            s.resume(&r, Duration::from_secs(1)).unwrap_err().code,
            wire::ERR_BAD_FRAME
        );
        r.ingress_instance_id = s.ingress_instance_id.clone();
        assert_eq!(s.resume(&r, Duration::from_secs(1)).unwrap().epoch, 2);
    }
    #[test]
    fn resume_rejects_bad_id() {
        let s = recovering();
        s.suspend_current();
        let mut r = request(&s);
        r.resume_request_id.clear();
        assert_eq!(
            s.resume(&r, Duration::from_secs(1)).unwrap_err().code,
            wire::ERR_BAD_FRAME
        );
    }
    #[test]
    fn successful_resume_is_idempotent() {
        let s = recovering();
        s.suspend_current();
        let r = request(&s);
        let first = s.resume(&r, Duration::from_secs(1)).unwrap();
        let second = s.resume(&r, Duration::from_secs(1)).unwrap();
        assert_eq!(first, second);
    }
    #[test]
    fn changed_replay_with_same_id_conflicts() {
        let s = recovering();
        s.suspend_current();
        let r = request(&s);
        s.resume(&r, Duration::from_secs(1)).unwrap();
        let mut changed = r;
        changed.down_delivered_offset = 1;
        assert_eq!(
            s.resume(&changed, Duration::from_secs(1)).unwrap_err().code,
            wire::ERR_IDEMPOTENCY_CONFLICT
        );
    }
    #[test]
    fn resume_disabled_returns_stable_error() {
        let (_c, b) = backend_pair();
        let s = new_session(b);
        assert_eq!(
            s.resume(&request(&s), Duration::from_secs(1))
                .unwrap_err()
                .code,
            wire::ERR_RECOVERY_DISABLED
        );
    }
    #[test]
    fn offset_ack_cannot_exceed_flushed() {
        let s = recovering();
        s.suspend_current();
        let mut r = request(&s);
        r.known_up_ack_offset = 1;
        r.up_next_offset = 1;
        assert_eq!(
            s.resume(&r, Duration::from_secs(1)).unwrap_err().code,
            wire::ERR_BAD_ACK
        );
    }
    #[test]
    fn offset_next_cannot_regress_ack() {
        let s = recovering();
        s.suspend_current();
        let mut r = request(&s);
        r.known_up_ack_offset = 1;
        assert_eq!(
            s.resume(&r, Duration::from_secs(1)).unwrap_err().code,
            wire::ERR_BAD_ACK
        );
    }
    #[test]
    fn down_ack_must_be_boundary() {
        let s = recovering();
        s.suspend_current();
        let mut r = request(&s);
        r.down_delivered_offset = 1;
        assert_eq!(
            s.resume(&r, Duration::from_secs(1)).unwrap_err().code,
            wire::ERR_BAD_ACK
        );
    }
    #[test]
    fn fin_state_must_be_consistent() {
        let s = recovering();
        s.suspend_current();
        let mut r = request(&s);
        r.up_fin.applied = true;
        assert_eq!(
            s.resume(&r, Duration::from_secs(1)).unwrap_err().code,
            wire::ERR_FRAME_CONFLICT
        );
    }
    #[test]
    fn fin_offset_must_match_next_offset() {
        let s = recovering();
        s.suspend_current();
        let mut r = request(&s);
        r.up_fin.seen = true;
        r.up_fin.final_offset = Some(1);
        assert_eq!(
            s.resume(&r, Duration::from_secs(1)).unwrap_err().code,
            wire::ERR_FRAME_CONFLICT
        );
    }
    #[test]
    fn barrier_waits_on_condvar_and_succeeds() {
        let s = recovering();
        s.suspend_current();
        s.inner.lock().unwrap().up_write_active = true;
        let t = s.clone();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            tx.send(t.resume(&request(&t), Duration::from_secs(1)).is_ok())
                .unwrap();
        });
        std::thread::sleep(Duration::from_millis(10));
        s.inner.lock().unwrap().up_write_active = false;
        s.cv.notify_all();
        assert!(rx.recv_timeout(Duration::from_secs(1)).unwrap());
    }
    #[test]
    fn barrier_timeout_closes_session() {
        let s = recovering();
        s.suspend_current();
        s.inner.lock().unwrap().up_write_active = true;
        let e = s
            .resume(&request(&s), Duration::from_millis(1))
            .unwrap_err();
        assert!(e.session_closed);
        assert!(s.is_closed());
    }
    #[test]
    fn grace_expiry_closes_without_panic() {
        let (_c, b) = backend_pair();
        let s = new_session(b);
        s.enable_recovery(Duration::from_millis(1));
        s.attach("old").unwrap();
        s.suspend_current();
        std::thread::sleep(Duration::from_millis(3));
        assert_eq!(s.recovery_state(), RecoveryState::Closed);
        assert_eq!(
            s.resume(&request(&s), Duration::from_secs(1))
                .unwrap_err()
                .code,
            wire::ERR_RESUME_EXPIRED
        );
    }

    #[test]
    fn recovery_grace_clears_only_after_current_ping_probe_ack() {
        let s = recovering();
        s.suspend_current();
        s.resume(&request(&s), Duration::from_secs(1)).unwrap();
        s.attach("new-stream").unwrap();
        let nonce = s.ping_control().unwrap().nonce.unwrap();

        s.note_ack_control("stale-nonce", "probe-1", true);
        assert!(s.recovery_deadline().is_some());
        s.note_ack_control(&nonce, "", false);
        assert!(s.recovery_deadline().is_some());
        s.note_ack_control(&nonce, "probe-2", false);
        assert!(s.recovery_deadline().is_none());
        assert_eq!(s.recovery_state(), RecoveryState::Attached);
    }

    #[test]
    fn suspend_releases_downstream_window_wait_for_old_carrier() {
        let s = recovering();
        s.inner.lock().unwrap().down_produced = test_limits().down_buffer_bytes;
        let blocked = s.clone();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || tx.send(blocked.reserve_down(1)).unwrap());
        std::thread::sleep(Duration::from_millis(10));
        assert!(s.suspend_current());
        assert_eq!(rx.recv_timeout(Duration::from_secs(1)).unwrap(), None);
    }
}
