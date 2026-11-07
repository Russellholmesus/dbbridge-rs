use std::io::Read;
use std::net::TcpListener;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::*;

fn backend_pair() -> (std::net::TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server)
}

fn session(backend: TcpStream, max_frame_size: usize, window: u64) -> Arc<Session> {
    let limits = Limits {
        max_frame_size,
        up_max_inflight_frames: 8,
        up_window_bytes: window,
        down_buffer_bytes: 1024 * 1024,
        up_receipt_limit: 64,
        down_max_frames: 8,
    };
    Session::new(
        "sess".into(),
        "token".into(),
        "inst".into(),
        "peer".into(),
        "target".into(),
        Mode::Ws,
        limits,
        64,
        backend,
        Arc::new(crate::metrics::Metrics::new()),
    )
}

#[test]
fn spec_oversize_up_frame_reports_frame_too_large() {
    let (_client, backend) = backend_pair();
    let s = session(backend, 4, 1024 * 1024);
    let e = s.ingest_up(1, 0, b"hello").unwrap_err();
    assert_eq!(e.code, wire::ERR_FRAME_TOO_LARGE, "oversize frame: {e}");
    assert_ne!(e.code, ERR_FRAME_CONFLICT);
    assert!(
        !s.is_closed(),
        "oversize frame closed the session as a conflict"
    );
    assert_eq!(e.status(), 413);
}

#[test]
fn spec_duplicate_inflight_frame_is_queued_again() {
    let (mut client, backend) = backend_pair();
    // Large enough that the backend write blocks until the client reads.
    let data: Arc<Vec<u8>> = Arc::new((0..16 << 20).map(|i| (i % 251) as u8).collect());
    let s = session(backend, data.len(), data.len() as u64 * 2);
    let first = {
        let (s, data) = (s.clone(), data.clone());
        std::thread::spawn(move || s.ingest_up(1, 0, &data))
    };
    // Wait for the writer to pick the frame and block on the write.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !s.inner.lock().unwrap().up_write_active {
        assert!(Instant::now() < deadline, "first write never started");
        std::thread::sleep(Duration::from_millis(1));
    }
    std::thread::sleep(Duration::from_millis(20));
    assert!(
        s.inner.lock().unwrap().up_flushed < data.len() as u64,
        "the backend write did not block"
    );
    // Retry the identical frame while the write is in flight.
    let retry = {
        let (s, data) = (s.clone(), data.clone());
        std::thread::spawn(move || s.ingest_up(1, 0, &data))
    };
    std::thread::sleep(Duration::from_millis(20));
    // Unblock the writer.
    client
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let mut got = Vec::with_capacity(data.len());
    let mut buf = vec![0u8; 1 << 20];
    loop {
        match client.read(&mut buf) {
            Ok(0) => break,
            Ok(k) => got.extend_from_slice(&buf[..k]),
            Err(_) => break,
        }
    }
    first.join().unwrap().expect("first frame ingest failed");
    retry
        .join()
        .unwrap()
        .expect("retry during inflight write failed");
    // Nothing more may arrive: the retry was not written a second time.
    loop {
        match client.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(k) => got.extend_from_slice(&buf[..k]),
        }
    }
    assert_eq!(got.len(), data.len(), "frame written {} bytes", got.len());
    assert!(got == *data, "backend received different bytes");
    assert_eq!(
        s.inner.lock().unwrap().up_flushed,
        data.len() as u64,
        "UpWrittenOffset"
    );
    assert!(!s.is_closed());
}

#[test]
fn spec_down_read_reservation_follows_allocation() {
    const ALLOCATION: usize = 512;
    let (_client, backend) = backend_pair();
    let s = session(backend, 64 * 1024, 1024 * 1024);
    let payload = crate::resource::budget::Budget::new(ALLOCATION as i64);
    s.set_global_payload_budget(payload.clone(), Duration::from_secs(1))
        .unwrap();
    let epoch = s.epoch();
    let r = s
        .reserve_down_for_read(epoch, ALLOCATION)
        .expect("read reservation failed");
    s.mark_down_produced_reserved(b"x", r).unwrap();
    let retained = |s: &Session| {
        let g = s.inner.lock().unwrap();
        g.down_produced - g.down_ack
    };
    assert!(
        retained(&s) == 1 && payload.used() == 1,
        "short read charge does not follow the retained allocation: retained={} payload={}",
        retained(&s),
        payload.used()
    );
    s.apply_down_ack(1, false).unwrap();
    assert!(
        retained(&s) == 0 && payload.used() == 0,
        "complete frame ACK did not refund the full allocation (payload {})",
        payload.used()
    );
    let r = s
        .reserve_down_for_read(epoch, ALLOCATION)
        .expect("second read reservation failed");
    s.close(Error::new(wire::ERR_SESSION_CLOSED, "closed"));
    assert_eq!(
        payload.used(),
        ALLOCATION as i64,
        "closed session refunded an allocation still owned by its reader"
    );
    let e = s.mark_down_produced_reserved(&[], r).unwrap_err();
    assert_eq!(e.code, wire::ERR_SESSION_CLOSED, "{e}");
    assert!(
        payload.used() == 0 && retained(&s) == 0,
        "closed read leaked its reservation"
    );
}
