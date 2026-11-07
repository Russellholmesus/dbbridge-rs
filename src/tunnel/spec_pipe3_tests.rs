use std::io::{Read, Write};
use std::time::Duration;

use super::pipe::{Pipe, ReceiveError, PIPE_CAPACITY};

#[test]
fn spec_pipe_ordering_retransmit_and_gap() {
    let mut p = Pipe::new("a", "b");
    assert_eq!(p.receive(0, b"abc", Duration::ZERO), Ok(3), "receive");
    assert_eq!(p.receive(1, b"bcde", Duration::ZERO), Ok(5), "overlap");
    assert_eq!(p.receive(2, b"cd", Duration::ZERO), Ok(5), "duplicate");
    assert!(
        matches!(
            p.receive(9, b"x", Duration::ZERO),
            Err(ReceiveError::Gap(5))
        ),
        "gap"
    );
    let mut buf = [0u8; 16];
    let n = p.read(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"abcde", "read");
    // The inbound buffer is bounded: a receive beyond it waits, accepts what
    // fits and times out.
    let big = vec![b'9'; PIPE_CAPACITY + 2];
    assert_eq!(
        p.receive(5, &big, Duration::from_millis(50)),
        Err(ReceiveError::Full),
        "full receive"
    );
    assert_eq!(
        p.received(),
        5 + PIPE_CAPACITY as i64,
        "full receive progress"
    );

    p.write_all(b"hello").unwrap();
    assert_eq!(p.pending(0, 3), Some((0, b"hel".to_vec())), "pending");
    p.ack(2).unwrap();
    assert_eq!(p.pending(0, 10), Some((2, b"llo".to_vec())), "after ack");
    assert!(p.ack(1).is_ok(), "stale ack");
    assert!(p.ack(6).is_err(), "ack beyond");
    p.close_with(None);
    assert!(p.write(b"x").is_err(), "write after close");
}

#[test]
fn spec_pipe_concurrent_retransmit() {
    let mut p = Pipe::new("a", "b");
    let data: Vec<u8> = (0..PIPE_CAPACITY * 3 + 17)
        .map(|i| (i % 251) as u8)
        .collect();
    let mut workers = Vec::new();
    for _ in 0..2 {
        let p = p.clone();
        let data = data.clone();
        workers.push(std::thread::spawn(move || {
            p.receive(0, &data, Duration::from_secs(10))
        }));
    }
    let mut got = Vec::with_capacity(data.len());
    let mut buf = [0u8; 3 * 1024];
    while got.len() < data.len() {
        let n = p.read(&mut buf).unwrap();
        got.extend_from_slice(&buf[..n]);
    }
    for w in workers {
        assert_eq!(w.join().unwrap(), Ok(data.len() as i64));
    }
    assert!(got == data, "bytes delivered out of order or twice");
    assert_eq!(p.received(), data.len() as i64);
}

#[test]
fn spec_audit_pipe_rejects_offset_overflow() {
    let p = Pipe::new("a", "b");
    assert!(
        p.receive(i64::MAX, b"x", Duration::ZERO).is_err(),
        "overflowing positive offset accepted as an empty retransmission"
    );
    assert_eq!(p.received(), 0);
}
