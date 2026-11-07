use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use super::stream::{available_window, send_window};
use crate::net::Conn;

use super::*;

/// A connected pair of sessions over an in-memory pipe.
fn pair(cfg: MuxConfig) -> (Arc<Session>, Arc<Session>) {
    let (a_r, b_w) = pipe();
    let (b_r, a_w) = pipe();
    let a = Session::new(Box::new(a_r), Box::new(a_w), cfg.clone(), Opener::Odd);
    let b = Session::new(Box::new(b_r), Box::new(b_w), cfg, Opener::Even);
    (a, b)
}

/// A blocking byte pipe: `PipeReader` reads what `PipeWriter` wrote.
struct Pipe {
    buf: Mutex<VecDeque<u8>>,
    cv: Condvar,
    closed: AtomicBool,
}

fn pipe() -> (PipeReader, PipeWriter) {
    let p = Arc::new(Pipe {
        buf: Mutex::new(VecDeque::new()),
        cv: Condvar::new(),
        closed: AtomicBool::new(false),
    });
    (PipeReader { p: p.clone() }, PipeWriter { p })
}

struct PipeReader {
    p: Arc<Pipe>,
}
struct PipeWriter {
    p: Arc<Pipe>,
}

impl Read for PipeReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut g = self.p.buf.lock().unwrap();
        loop {
            if !g.is_empty() {
                let n = out.len().min(g.len());
                for b in out.iter_mut().take(n) {
                    *b = g.pop_front().unwrap();
                }
                return Ok(n);
            }
            if self.p.closed.load(Ordering::Relaxed) {
                return Ok(0);
            }
            g = self.p.cv.wait(g).unwrap();
        }
    }
}

impl Write for PipeWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut g = self.p.buf.lock().unwrap();
        g.extend(data.iter().copied());
        drop(g);
        self.p.cv.notify_all();
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for PipeWriter {
    fn drop(&mut self) {
        self.p.closed.store(true, Ordering::SeqCst);
        self.p.cv.notify_all();
    }
}

fn small() -> MuxConfig {
    MuxConfig {
        max_frame_size: 4096,
        stream_window: 256 * 1024,
        max_streams: 8,
        max_receive_buffer: 8 * 256 * 1024,
        keepalive: Duration::from_secs(30),
        detect: Duration::from_secs(60),
    }
}

struct FuzzRng(u64);

impl FuzzRng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn bytes(&mut self, max_len: usize) -> Vec<u8> {
        let len = self.next() as usize % (max_len + 1);
        (0..len).map(|_| self.next() as u8).collect()
    }
}

fn run_smux_fuzz(iterations: usize) {
    let mut rng = FuzzRng(0x13ed_7b29_a460_5fc1);
    for iteration in 0..iterations {
        let raw = match iteration % 4 {
            0 => rng.bytes(24),
            1 => {
                let mut header = rng.bytes(8);
                header.resize(8, 0);
                header.truncate(8);
                header
            }
            2 => {
                let cmd = match rng.next() % 6 {
                    0 => CMD_SYN,
                    1 => CMD_FIN,
                    2 => CMD_PSH,
                    3 => CMD_NOP,
                    4 => CMD_UPD,
                    _ => 0xff,
                };
                let len = rng.next() as usize % 8192;
                let mut header = encode_header(cmd, rng.next() as u32, len).to_vec();
                if rng.next() & 1 != 0 {
                    header[0] = rng.next() as u8;
                }
                header
            }
            _ => {
                let cmd = [CMD_SYN, CMD_FIN, CMD_PSH, CMD_NOP, CMD_UPD][rng.next() as usize % 5];
                let len = match cmd {
                    CMD_PSH => (rng.next() as usize % 4096) + 1,
                    CMD_UPD => UPD_LEN,
                    _ => 0,
                };
                encode_header(cmd, rng.next() as u32, len).to_vec()
            }
        };
        assert!(raw.len() <= 24, "fuzz input must stay bounded");
        let _ = super::session::decode_header(&raw, 4096);
    }
}

#[test]
fn fuzz_smux_frames() {
    run_smux_fuzz(100_000);
}

#[test]
#[ignore = "one-million iteration parser fuzz run"]
fn fuzz_smux_frames_long() {
    run_smux_fuzz(1_000_000);
}

#[test]
fn opens_a_stream_and_moves_bytes_both_ways() {
    let (a, b) = pair(small());
    let mut sa = a.open().unwrap();
    let mut sb = b.accept(Duration::from_secs(2)).unwrap().unwrap();
    assert_eq!(sa.id(), 3, "the odd side hands out 3 first");

    sa.write_all(b"ping").unwrap();
    let mut got = [0u8; 4];
    sb.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"ping");

    sb.write_all(b"pong").unwrap();
    sa.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"pong");
}

#[test]
fn a_large_transfer_crosses_many_frames() {
    let (a, b) = pair(small());
    let mut sa = a.open().unwrap();
    let mut sb = b.accept(Duration::from_secs(2)).unwrap().unwrap();
    let payload: Vec<u8> = (0..300_000).map(|i| (i % 251) as u8).collect();
    let want = payload.clone();
    let t = std::thread::spawn(move || {
        sa.write_all(&want).unwrap();
        sa.shutdown_write().unwrap();
    });
    let mut got = Vec::new();
    sb.read_to_end(&mut got).unwrap();
    t.join().unwrap();
    assert_eq!(got.len(), payload.len());
    assert_eq!(got, payload);
}

#[test]
fn a_reader_sees_eof_after_fin() {
    let (a, b) = pair(small());
    let sa = a.open().unwrap();
    let mut sb = b.accept(Duration::from_secs(2)).unwrap().unwrap();
    sa.close();
    let mut buf = [0u8; 8];
    assert_eq!(sb.read(&mut buf).unwrap(), 0);
}

#[test]
fn a_read_timeout_reports_would_block_and_keeps_the_stream() {
    let (a, b) = pair(small());
    let mut sa = a.open().unwrap();
    let mut sb = b.accept(Duration::from_secs(2)).unwrap().unwrap();
    sb.set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let mut buf = [0u8; 8];
    let err = sb.read(&mut buf).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    // The stream is still usable.
    sa.write_all(b"late").unwrap();
    sb.set_read_timeout(None).unwrap();
    let mut got = [0u8; 4];
    sb.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"late");
}

#[test]
fn opening_stops_at_the_stream_limit() {
    let cfg = MuxConfig {
        max_streams: 2,
        ..small()
    };
    let (a, _b) = pair(cfg);
    let _first = a.open().unwrap();
    let _second = a.open().unwrap();
    match a.open() {
        Ok(_) => panic!("a third stream must be refused"),
        Err(e) => assert_eq!(e.kind(), io::ErrorKind::WouldBlock),
    }
}

#[test]
fn the_frame_header_is_little_endian() {
    let h = encode_header(CMD_PSH, 0x0102_0304, 0x0506);
    assert_eq!(h[0], VERSION);
    assert_eq!(h[1], CMD_PSH);
    assert_eq!(&h[2..4], &0x0506u16.to_le_bytes());
    assert_eq!(&h[4..8], &0x0102_0304u32.to_le_bytes());
}

#[test]
fn upd_window_semantics() {
    // smux v2 UPD payloads as wire bytes. The written counter crosses 2^32
    // between them and must retain modular in-flight math.
    let spec_frames: &[&[u8]] = &[
        &[
            2, 4, 8, 0, 3, 0, 0, 0, 0xc0, 0xff, 0xff, 0xff, 0x60, 0x00, 0x00, 0x00,
        ],
        &[
            2, 4, 8, 0, 3, 0, 0, 0, 0xf0, 0xff, 0xff, 0xff, 0x60, 0x00, 0x00, 0x00,
        ],
    ];
    let mut written: u32 = 0xffff_ffd0;
    for frame in spec_frames {
        assert_eq!(frame[0], VERSION);
        assert_eq!(frame[1], CMD_UPD);
        assert_eq!(&frame[2..4], &(UPD_LEN as u16).to_le_bytes());
        let consumed = u32::from_le_bytes(frame[8..12].try_into().unwrap());
        let window = u32::from_le_bytes(frame[12..16].try_into().unwrap());
        assert_eq!(available_window(window, written, consumed), 0x50);
        written = written.wrapping_add(0x30);
    }
    // smux writeV2: a peer reporting more consumed than written (here 0x20
    // consumed after the counter wrapped to 0) is ErrConsumed, not a window.
    assert_eq!(written, 0x30);
    assert_eq!(send_window(0x30, 0, 0x20), None);
}

#[test]
fn actual_write_crosses_signed_half_of_smux_counter_space() {
    let (a, b) = pair(small());
    let mut sender = a.open().unwrap();
    let mut receiver = b.accept(Duration::from_secs(2)).unwrap().unwrap();

    // Seed the private counter immediately below 2^31, then perform a real
    // write/read through the framed session rather than testing arithmetic alone.
    {
        let mut state = sender.slot.st.lock().unwrap();
        state.written = 0x7fff_ffff;
        state.peer_consumed = 0x7fff_ffff;
        state.peer_window = 1;
    }
    sender.write_all(b"x").unwrap();
    let mut received = [0u8; 1];
    receiver.read_exact(&mut received).unwrap();
    assert_eq!(&received, b"x");
    assert_eq!(sender.slot.st.lock().unwrap().written, 0x8000_0000);
}

#[test]
fn closed_streams_are_reclaimed() {
    let (a, b) = pair(small());
    for _ in 0..100 {
        let sa = a.open().expect("P0-02 stream slot must be reusable");
        let sb = b.accept(Duration::from_secs(2)).unwrap().unwrap();
        sa.close();
        sb.close();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < deadline {
            if a.num_streams() == 0 && b.num_streams() == 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(a.num_streams(), 0);
        assert_eq!(b.num_streams(), 0);
    }
}

#[test]
fn poc_b1_peer_syn_accepted_after_recycle() {
    let cfg = MuxConfig {
        max_streams: 1,
        ..small()
    };
    let (a, b) = pair(cfg);
    let first = a.open().unwrap();
    let first_peer = b.accept(Duration::from_secs(2)).unwrap().unwrap();
    let first_id = first.id();
    first.close();
    first_peer.close();

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        if a.num_streams() == 0 && b.num_streams() == 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(a.num_streams(), 0);
    assert_eq!(b.num_streams(), 0);

    let second = a.open().expect("stream slot should be reusable");
    let second_peer = b
        .accept(Duration::from_secs(2))
        .expect("accept should not time out")
        .expect("peer SYN after recycle should be accepted");
    assert_ne!(second.id(), first_id);
    assert_eq!(second_peer.id(), second.id());
    assert_eq!(a.num_streams(), 1);
    assert_eq!(b.num_streams(), 1);
}

#[test]
fn syn_over_limit_gets_fin() {
    let cfg = MuxConfig {
        max_streams: 1,
        ..small()
    };
    let (a, b) = pair(cfg);
    let held = a.open().unwrap();
    let _accepted = b.accept(Duration::from_secs(2)).unwrap().unwrap();

    // The peer's second SYN is over the limit.  It must not create a slot;
    // the FIN response is consumed by the peer's reader loop.
    b.inner.send(CMD_SYN, 0xfeed, &[]).unwrap();
    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(a.num_streams(), 1);
    drop(held);
}

#[test]
fn psh_to_closed_stream_is_dropped() {
    let (a, b) = pair(small());
    let mut sa = a.open().unwrap();
    let mut sb = b.accept(Duration::from_secs(2)).unwrap().unwrap();
    sa.shutdown_both().unwrap();
    sb.write_all(b"must not be delivered").unwrap();
    let mut buf = [0u8; 32];
    assert_eq!(sa.read(&mut buf).unwrap(), 0);
    drop(sb);
}

#[test]
fn send_window_uses_smux_signed_modular_arithmetic() {
    // Plain case.
    assert_eq!(send_window(100, 30, 10), Some(80));
    // written wrapped past 2^32, consumed not yet: inflight 0x20.
    assert_eq!(send_window(0x40, 0x10, 0xffff_fff0), Some(0x20));
    // Both wrapped.
    assert_eq!(send_window(0x40, 0x5, 0x1), Some(0x3c));
    // The peer shrank its window below what is in flight: wait (0), never a
    // wrapped-around huge window.
    assert_eq!(send_window(16, 64, 0), Some(0));
    assert_eq!(send_window(0, 1, 0), Some(0));
    // smux ErrConsumed: the peer claims more than was sent.
    assert_eq!(send_window(100, 10, 20), None);
    assert_eq!(available_window(100, 10, 20), 0);
}

#[test]
fn transfer_crosses_the_u32_counter_wrap_on_both_sides() {
    let (a, b) = pair(small());
    let mut sender = a.open().unwrap();
    let mut receiver = b.accept(Duration::from_secs(2)).unwrap().unwrap();
    let start = u32::MAX - 100_000;
    {
        let mut st = sender.slot.st.lock().unwrap();
        st.written = start;
        st.peer_consumed = start;
        st.peer_window = 256 * 1024;
    }
    {
        let mut st = receiver.slot.st.lock().unwrap();
        st.read_total = start;
    }
    let total = 3 * 256 * 1024 + 12_345;
    let data: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
    let expect = data.clone();
    let w = std::thread::spawn(move || {
        sender.write_all(&data).unwrap();
        sender
    });
    let mut got = vec![0u8; total];
    receiver.read_exact(&mut got).unwrap();
    assert!(got == expect, "payload corrupted across the counter wrap");
    let sender = w.join().unwrap();
    let written = sender.slot.st.lock().unwrap().written;
    assert_eq!(written, start.wrapping_add(total as u32));
    assert!(written < start, "counter must have wrapped");
}

#[test]
fn initial_peer_window_is_the_smux_constant_not_the_local_window() {
    let cfg = MuxConfig {
        stream_window: 1024 * 1024,
        max_receive_buffer: 8 * 1024 * 1024,
        ..small()
    };
    let (a, b) = pair(cfg);
    let mut sender = a.open().unwrap();
    assert_eq!(
        sender.slot.st.lock().unwrap().peer_window,
        INITIAL_PEER_WINDOW
    );
    let receiver = b.accept(Duration::from_secs(2)).unwrap().unwrap();
    // The receiver does not read, so no UPD arrives: the sender may only put
    // smux's initialPeerWindow (256 KiB) in flight, not its own 1 MiB.
    sender
        .set_write_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let chunk = vec![7u8; 64 * 1024];
    let mut sent = 0usize;
    loop {
        match sender.write(&chunk) {
            Ok(n) => sent += n,
            Err(e) => {
                assert_eq!(e.kind(), io::ErrorKind::WouldBlock);
                break;
            }
        }
        assert!(sent <= 2 * 1024 * 1024, "flow control never engaged");
    }
    assert_eq!(sent, INITIAL_PEER_WINDOW as usize);
    // Once the receiver reads, its UPD grants its real window (1 MiB).
    let mut receiver = receiver;
    let mut buf = vec![0u8; 4096];
    receiver.read_exact(&mut buf).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while sender.slot.st.lock().unwrap().peer_window != 1024 * 1024 {
        assert!(
            std::time::Instant::now() < deadline,
            "no UPD with the real window"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Records every `write` call separately.
#[derive(Clone, Default)]
struct WriteLog(Arc<Mutex<Vec<Vec<u8>>>>);

impl Write for WriteLog {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().push(data.to_vec());
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A reader that never yields data (the session only writes in these tests).
struct Silent(#[allow(dead_code)] PipeWriter, PipeReader);

impl Read for Silent {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.1.read(out)
    }
}

fn silent() -> Silent {
    let (r, w) = pipe();
    Silent(w, r)
}

#[test]
fn every_frame_is_one_write_call() {
    let log = WriteLog::default();
    let s = Session::new(
        Box::new(silent()),
        Box::new(log.clone()),
        small(),
        Opener::Odd,
    );
    let mut st = s.open().unwrap();
    st.write_all(&[9u8; 10_000]).unwrap();
    st.close();
    let writes = log.0.lock().unwrap().clone();
    // SYN, 3 PSH (4096 + 4096 + 1808), FIN: each one whole frame per write,
    // so a WebSocket sink sends one message per smux frame.
    assert_eq!(
        writes.len(),
        5,
        "{:?}",
        writes.iter().map(Vec::len).collect::<Vec<_>>()
    );
    for w in &writes {
        assert!(w.len() >= HEADER_LEN);
        let len = u16::from_le_bytes([w[2], w[3]]) as usize;
        assert_eq!(w.len(), HEADER_LEN + len, "frame split across writes");
    }
    assert_eq!(writes[0][1], CMD_SYN);
    assert_eq!(writes[1][1], CMD_PSH);
    assert_eq!(writes[1].len(), HEADER_LEN + 4096);
    assert_eq!(writes[4][1], CMD_FIN);
}

/// A writer whose first write blocks until released.
struct Gated {
    log: Arc<Mutex<Vec<u8>>>,
    gate: Arc<(Mutex<bool>, Condvar)>,
    entered: Arc<AtomicBool>,
}

impl Write for Gated {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.entered.store(true, Ordering::SeqCst);
        let (open, cv) = &*self.gate;
        let mut g = open.lock().unwrap();
        while !*g {
            g = cv.wait(g).unwrap();
        }
        drop(g);
        self.log.lock().unwrap().push(data[1]);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn control_frames_spec_before_waiting_data_frames() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let gate = Arc::new((Mutex::new(false), Condvar::new()));
    let entered = Arc::new(AtomicBool::new(false));
    let w = Gated {
        log: log.clone(),
        gate: gate.clone(),
        entered: entered.clone(),
    };
    let cfg = MuxConfig {
        keepalive: Duration::from_secs(3600),
        detect: Duration::from_secs(7200),
        ..small()
    };
    let s = Session::new(Box::new(silent()), Box::new(w), cfg, Opener::Odd);
    let inner = s.inner.clone();
    // A data frame holds the connection (its write is blocked)...
    let first = {
        let inner = inner.clone();
        std::thread::spawn(move || inner.send(CMD_PSH, 3, b"first").unwrap())
    };
    while !entered.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(1));
    }
    // ...more data frames queue behind it...
    let data: Vec<_> = (0..4)
        .map(|_| {
            let inner = inner.clone();
            std::thread::spawn(move || inner.send(CMD_PSH, 3, b"queued").unwrap())
        })
        .collect();
    std::thread::sleep(Duration::from_millis(50));
    // ...and a window update arrives last.
    let upd = {
        let inner = inner.clone();
        std::thread::spawn(move || inner.send(CMD_UPD, 3, &[0u8; UPD_LEN]).unwrap())
    };
    std::thread::sleep(Duration::from_millis(50));
    {
        let (open, cv) = &*gate;
        *open.lock().unwrap() = true;
        cv.notify_all();
    }
    first.join().unwrap();
    upd.join().unwrap();
    for d in data {
        d.join().unwrap();
    }
    let order = log.lock().unwrap().clone();
    assert_eq!(order.len(), 6, "{order:?}");
    assert_eq!(order[0], CMD_PSH);
    assert_eq!(
        order[1], CMD_UPD,
        "UPD waited behind queued data: {order:?}"
    );
}

#[test]
fn one_stream_overrunning_its_window_does_not_end_the_session() {
    let (a, b) = pair(small());
    let flooded = a.open().unwrap();
    let mut flooded_peer = b.accept(Duration::from_secs(2)).unwrap().unwrap();
    let mut other = a.open().unwrap();
    let mut other_peer = b.accept(Duration::from_secs(2)).unwrap().unwrap();
    // Ignore flow control: push 2.5 windows to one stream that is not read.
    let chunk = vec![1u8; 4096];
    let frames = (5 * 256 * 1024 / 2) / chunk.len();
    for _ in 0..frames {
        a.inner.send(CMD_PSH, flooded.id(), &chunk).unwrap();
    }
    // The session and its other streams keep working.
    other.write_all(b"still alive").unwrap();
    let mut got = [0u8; 11];
    other_peer.read_exact(&mut got).unwrap();
    assert_eq!(&got, b"still alive");
    assert!(!a.is_closed() && !b.is_closed());
    // The overrun bytes are all delivered.
    let mut drained = vec![0u8; frames * chunk.len()];
    flooded_peer.read_exact(&mut drained).unwrap();
    // No write on `flooded` afterwards: the overrun was injected below the
    // stream's own accounting, so once the peer's window update for it
    // arrives the sender sees more consumed than written and refuses to
    // write (smux ErrConsumed, "peer consumed more than sent"). Whether that
    // update had arrived yet was a race that made this test flaky.
    drop(flooded);
}

#[test]
fn a_used_up_receive_bucket_pauses_reading_until_streams_consume() {
    let cfg = MuxConfig {
        max_receive_buffer: 16 * 1024,
        ..small()
    };
    let (a, b) = pair(cfg);
    let s1 = a.open().unwrap();
    let mut s1_peer = b.accept(Duration::from_secs(2)).unwrap().unwrap();
    let mut s2 = a.open().unwrap();
    let mut s2_peer = b.accept(Duration::from_secs(2)).unwrap().unwrap();
    for _ in 0..5 {
        a.inner.send(CMD_PSH, s1.id(), &[2u8; 4096]).unwrap();
    }
    std::thread::sleep(Duration::from_millis(50));
    // 20 KiB arrived for a 16 KiB bucket: the read loop paused after it went
    // negative, so a frame for another stream waits...
    s2.write_all(b"queued").unwrap();
    s2_peer
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let mut buf = [0u8; 6];
    assert_eq!(
        s2_peer.read(&mut buf).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(!b.is_closed());
    // ...until the flooded stream is read, which returns the tokens.
    let mut drained = vec![0u8; 5 * 4096];
    s1_peer.read_exact(&mut drained).unwrap();
    s2_peer
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    s2_peer.read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"queued");
    assert_eq!(*b.inner.bucket.lock().unwrap(), 16 * 1024);
    drop(s1);
}

#[test]
fn closing_a_stream_with_unread_data_returns_its_tokens() {
    let cfg = MuxConfig {
        max_receive_buffer: 64 * 1024,
        ..small()
    };
    let (a, b) = pair(cfg);
    let s1 = a.open().unwrap();
    let s1_peer = b.accept(Duration::from_secs(2)).unwrap().unwrap();
    for _ in 0..4 {
        a.inner.send(CMD_PSH, s1.id(), &[3u8; 4096]).unwrap();
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while *b.inner.bucket.lock().unwrap() != 48 * 1024 {
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(2));
    }
    drop(s1_peer);
    assert_eq!(*b.inner.bucket.lock().unwrap(), 64 * 1024);
    drop(s1);
}

#[test]
fn held_values_are_dropped_when_the_session_closes() {
    let (a, b) = pair(MuxConfig::default());
    let budget = crate::resource::budget::Budget::new(10);
    a.hold_until_closed(Box::new(budget.try_acquire(4).unwrap()));
    assert_eq!(budget.used(), 4);
    a.close();
    assert_eq!(budget.used(), 0);
    a.hold_until_closed(Box::new(budget.try_acquire(4).unwrap()));
    assert_eq!(budget.used(), 0);
    b.close();
}
