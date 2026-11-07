use std::io::Write;
use std::net::TcpListener;
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::*;
use crate::resource::budget::Budget;

fn backend_pair() -> (std::net::TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server)
}

fn session(backend: TcpStream) -> Arc<Session> {
    Session::new(
        "sess".into(),
        "token".into(),
        "bi".into(),
        "A".into(),
        "db".into(),
        Mode::Ws,
        Limits {
            max_frame_size: 512,
            up_max_inflight_frames: 8,
            up_window_bytes: 2048,
            down_buffer_bytes: 4096,
            up_receipt_limit: 64,
            down_max_frames: 64,
        },
        64,
        backend,
        Arc::new(crate::metrics::Metrics::new()),
    )
}

fn resume_req(s: &Session, id: &str, mode: Mode) -> recovery::ResumeRequest {
    recovery::ResumeRequest {
        resume_request_id: id.into(),
        expected_epoch: s.epoch(),
        ingress_instance_id: s.ingress_instance_id.clone(),
        transport: mode,
        known_up_ack_offset: 0,
        up_next_offset: 0,
        down_delivered_offset: 0,
        up_fin: Default::default(),
        down_fin: Default::default(),
    }
}

fn pump(s: &Arc<Session>) -> std::thread::JoinHandle<crate::error::Result<()>> {
    let p = DownPump {
        session: s.clone(),
        frame_size: 512,
    };
    std::thread::spawn(move || p.run(|_, _| Ok(())))
}

fn wait_for(what: &str, limit: Duration, mut f: impl FnMut() -> bool) {
    let until = Instant::now() + limit;
    while !f() {
        assert!(Instant::now() < until, "{what}");
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn spec_backend_normal_eof_still_drains_and_recovers() {
    let (mut db, backend) = backend_pair();
    let s = session(backend);
    s.enable_recovery(Duration::from_secs(2));
    s.attach("ws-1").unwrap();
    db.write_all(b"tail").unwrap();
    db.shutdown(std::net::Shutdown::Write).unwrap();
    let reader = pump(&s);
    wait_for("reader did not stop at EOF", Duration::from_secs(1), || {
        reader.is_finished()
    });
    assert!(reader.join().unwrap().is_ok());
    let snap = s.snapshot();
    assert_eq!(snap.down_produced, 4, "EOF: tail not recorded");
    assert!(s.down_fin(), "EOF not recorded as the downstream FIN");
    std::thread::sleep(Duration::from_millis(20));
    assert!(
        !s.is_closed(),
        "normal EOF closed the session instead of draining"
    );
    let r = s
        .resume(&resume_req(&s, "eof-ok", Mode::Ws), Duration::from_secs(1))
        .expect("resume after normal EOF");
    assert_eq!(r.epoch, 2);
}

#[cfg(target_os = "linux")]
fn reset(sock: std::net::TcpStream) {
    use std::os::fd::AsRawFd;
    #[repr(C)]
    struct Linger {
        l_onoff: i32,
        l_linger: i32,
    }
    extern "C" {
        fn setsockopt(fd: i32, level: i32, name: i32, val: *const Linger, len: u32) -> i32;
    }
    let l = Linger {
        l_onoff: 1,
        l_linger: 0,
    };
    // SOL_SOCKET = 1, SO_LINGER = 13 on Linux: close() then sends RST.
    let rc = unsafe {
        setsockopt(
            sock.as_raw_fd(),
            1,
            13,
            &l,
            std::mem::size_of::<Linger>() as u32,
        )
    };
    assert_eq!(rc, 0);
    drop(sock);
}

#[cfg(target_os = "linux")]
#[test]
fn spec_fatal_backend_read_must_fence_recovery() {
    let (mut db, backend) = backend_pair();
    let s = session(backend);
    s.enable_recovery(Duration::from_secs(2));
    s.attach("ws-1").unwrap();
    let reader = pump(&s);
    db.write_all(b"tail").unwrap();
    wait_for(
        "fixture: tail bytes not recorded",
        Duration::from_secs(1),
        || s.snapshot().down_produced == 4,
    );
    reset(db);
    wait_for("fixture: read did not fail", Duration::from_secs(2), || {
        reader.is_finished()
    });
    assert!(reader.join().unwrap().is_err());
    std::thread::sleep(Duration::from_millis(20));
    let r = s.resume(
        &resume_req(&s, "test-credential", Mode::HttpSse),
        Duration::from_secs(1),
    );
    assert!(
        r.is_err() && s.is_closed(),
        "contract violation: after fatal backend error resume result={r:?}"
    );
    assert_eq!(s.terminal_error().unwrap().code, wire::ERR_BACKEND_LOST);
}

fn stalled(timeout: Duration) -> (Arc<Session>, std::net::TcpStream, Arc<Budget>, BudgetLease) {
    let (db, backend) = backend_pair();
    let s = session(backend);
    let budget = Budget::new(1024);
    let held = budget.try_acquire(1024).unwrap();
    s.set_global_payload_budget(budget.clone(), timeout)
        .unwrap();
    (s, db, budget, held)
}

#[test]
fn spec_reader_stall_closes_attached() {
    let (s, _db, _budget, _held) = stalled(Duration::from_millis(100));
    s.attach("ws-1").unwrap();
    let reader = pump(&s);
    wait_for(
        "attached session not closed by the stall timer",
        Duration::from_secs(3),
        || reader.is_finished(),
    );
    let _ = reader.join();
    assert!(s.is_closed());
    assert_eq!(s.terminal_error().unwrap().code, wire::ERR_BUFFER_EXHAUSTED);
}

#[test]
fn spec_reader_stall_waits_during_recovery() {
    let (s, mut db, _budget, held) = stalled(Duration::from_millis(100));
    s.enable_recovery(Duration::from_secs(5));
    s.attach("ws-1").unwrap();
    assert!(
        s.suspend(1),
        "session not recovering after the carrier loss"
    );
    let reader = pump(&s);
    std::thread::sleep(Duration::from_millis(400));
    assert!(
        !s.is_closed(),
        "suspended session closed by the reader stall timer: {:?}",
        s.terminal_error()
    );
    let _ = reader.join();
    drop(held);
    db.write_all(b"hello").unwrap();
    s.resume(&resume_req(&s, "r1", Mode::Ws), Duration::from_secs(1))
        .unwrap();
    s.attach("ws-2").unwrap();
    let reader = pump(&s);
    wait_for(
        "reader did not resume after the budget freed",
        Duration::from_secs(3),
        || s.snapshot().down_produced >= 5,
    );
    s.close(Error::new(wire::ERR_SESSION_CLOSED, "done").closed(true));
    let _ = reader.join();
}

struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

#[test]
fn spec_randomized_session_accounting_balances() {
    for seed in [1u64, 2, 3, 5, 8, 13, 21, 34] {
        let mut rng = XorShift(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
        let (db, backend) = backend_pair();
        let mut sink = db.try_clone().unwrap();
        let drain = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while matches!(std::io::Read::read(&mut sink, &mut buf), Ok(n) if n > 0) {}
        });
        let s = Session::new(
            "sess".into(),
            "token".into(),
            "i".into(),
            "p".into(),
            "t".into(),
            Mode::Ws,
            Limits {
                max_frame_size: 4096,
                up_max_inflight_frames: 4,
                up_window_bytes: 64 << 10,
                down_buffer_bytes: 256 << 10,
                up_receipt_limit: 8,
                down_max_frames: 64,
            },
            8,
            backend,
            Arc::new(crate::metrics::Metrics::new()),
        );
        let payload = Budget::new(64 << 20);
        let retention = Arc::new(crate::resource::retention::Retention::new(64 << 20));
        s.set_global_payload_budget(payload.clone(), Duration::from_millis(50))
            .unwrap();
        s.set_suspended_retention(retention.clone());
        s.enable_recovery(Duration::from_secs(10));
        let mut stream = 1;
        s.attach("st-1").unwrap();
        let mut up_next = 0u64;
        let mut boundaries: Vec<u64> = Vec::new();
        let mut rid = 0;
        for _ in 0..200 {
            let ep = s.epoch();
            match rng.below(9) {
                0 | 1 => {
                    let n = 1 + rng.below(2000) as usize;
                    let d: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
                    if s.ingest_up(ep, up_next, &d).is_ok() {
                        up_next += n as u64;
                    }
                }
                2 => {
                    let size = 1024usize << rng.below(4);
                    let snap = s.snapshot();
                    let outstanding = snap.down_produced - snap.down_ack_offset;
                    if outstanding + size as u64 <= s.limits.down_buffer_bytes
                        && s.recovery_state() == recovery::RecoveryState::Attached
                    {
                        if let Some(res) = s.reserve_down_for_read(ep, size) {
                            let k = 1 + rng.below(res.bytes as u64) as usize;
                            let buf = vec![b'x'; k];
                            if let Ok(off) = s.mark_down_produced_reserved(&buf, res) {
                                boundaries.push(off + k as u64);
                            }
                        }
                    }
                }
                3 | 4 => {
                    let ack = s.snapshot().down_ack_offset;
                    let candidates: Vec<u64> =
                        boundaries.iter().copied().filter(|b| *b > ack).collect();
                    if !candidates.is_empty() {
                        let to = candidates[rng.below(candidates.len() as u64) as usize];
                        let _ = s.apply_down_ack(to, false);
                    }
                    let _ = s.apply_up_confirmation(s.snapshot().ack_up_offset);
                }
                5 => {
                    s.suspend(ep);
                }
                6 => {
                    rid += 1;
                    let snap = s.snapshot();
                    let known = snap.ack_up_offset;
                    let q = recovery::ResumeRequest {
                        resume_request_id: format!("r{rid}"),
                        expected_epoch: ep,
                        ingress_instance_id: s.ingress_instance_id.clone(),
                        transport: Mode::Ws,
                        known_up_ack_offset: known,
                        up_next_offset: up_next.max(known),
                        down_delivered_offset: snap.down_ack_offset,
                        up_fin: Default::default(),
                        down_fin: Default::default(),
                    };
                    if let Ok(resp) = s.resume(&q, Duration::from_secs(1)) {
                        up_next = resp.ack_up_offset;
                        stream += 1;
                        let _ = s.attach(&format!("st-{stream}"));
                    }
                }
                7 => std::thread::sleep(Duration::from_micros(rng.below(200))),
                _ => {
                    if rng.below(20) == 0 {
                        s.close(Error::new(wire::ERR_SESSION_CLOSED, "random close").closed(true));
                    }
                }
            }
            if s.is_closed() {
                break;
            }
        }
        s.close(Error::new(wire::ERR_SESSION_CLOSED, "done").closed(true));
        std::thread::sleep(Duration::from_millis(2));
        assert_eq!(payload.used(), 0, "seed {seed}: global buffer leak");
        assert_eq!(retention.used(), 0, "seed {seed}: retention leak");
        assert_eq!(
            s.retained_payload_bytes
                .load(std::sync::atomic::Ordering::Acquire),
            0,
            "seed {seed}: retained bytes after close"
        );
        let _ = db.shutdown(std::net::Shutdown::Both);
        drop(s);
        let _ = drain.join();
    }
}
