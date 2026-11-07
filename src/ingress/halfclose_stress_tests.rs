use super::spec_e2e_harness::*;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Backend that greets, half-closes after `delay_ms`, reads to EOF, reports
/// how many bytes it got and closes a little later.
fn half_close_target(delay_ms: u64) -> Target {
    Target::with(move |mut c: TcpStream, tx: mpsc::SyncSender<Vec<u8>>| {
        let _ = c.write_all(b"server-hello");
        if delay_ms > 0 {
            std::thread::sleep(Duration::from_millis(delay_ms));
        }
        let _ = c.shutdown(Shutdown::Write);
        let mut buf = vec![0u8; 32768];
        let mut total = 0usize;
        loop {
            match c.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => total += n,
            }
        }
        let _ = tx.try_send(total.to_le_bytes().to_vec());
        std::thread::sleep(Duration::from_millis(5));
        drop(c);
    })
}

/// `rounds` connections on one environment: read the greeting and the
/// backend FIN, wait `client_delay`, write `payload` bytes and half-close.
/// Every round must deliver the bytes and leave no egress session.
fn run(
    o: Opts,
    delay_ms: u64,
    client_delay: Duration,
    rounds: usize,
    payload: usize,
) -> Vec<String> {
    let mode = o.mode;
    let target = half_close_target(delay_ms);
    let env = Env::start(&target, o);
    let data = vec![0x5au8; payload];
    let mut failures = Vec::new();
    for i in 0..rounds {
        let mut c = env.dial();
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut got = Vec::new();
        if let Err(e) = c.read_to_end(&mut got) {
            failures.push(format!("{mode} round {i}: read: {e}"));
            continue;
        }
        if got != b"server-hello" {
            failures.push(format!("{mode} round {i}: greeting {} bytes", got.len()));
        }
        std::thread::sleep(client_delay);
        if let Err(e) = c.write_all(&data) {
            failures.push(format!("{mode} round {i}: write: {e}"));
        }
        let _ = c.shutdown(Shutdown::Write);
        let rx = target.received.lock().unwrap();
        match rx.recv_timeout(Duration::from_secs(5)) {
            Ok(b) => {
                let n = usize::from_le_bytes(b[..8].try_into().unwrap());
                if n != payload {
                    failures.push(format!("{mode} round {i}: backend got {n}/{payload}"));
                }
            }
            Err(_) => failures.push(format!("{mode} round {i}: backend never saw EOF")),
        }
        drop(rx);
        let left = env.wait_egress_sessions(0, Duration::from_secs(1));
        if left != 0 {
            failures.push(format!(
                "{mode} round {i}: {left} egress session(s) left behind"
            ));
            break;
        }
    }
    failures
}

/// Default transport settings (recovery on, 10s control timeout), ws: the
/// backend half-closes first, the client writes after it and half-closes.
#[test]
fn ws_backend_half_close_leaves_no_egress_session() {
    let mut failures = Vec::new();
    for (delay, payload) in [(0, 10_000), (2, 200_000), (0, 0)] {
        failures.extend(run(Opts::new("ws"), delay, Duration::ZERO, 15, payload));
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// The same sequence over http-sse.
#[test]
fn sse_backend_half_close_leaves_no_egress_session() {
    let failures = run(Opts::new("http-sse"), 0, Duration::ZERO, 10, 10_000);
    assert!(failures.is_empty(), "{failures:#?}");
}

/// The regression itself: the client keeps its upstream open for longer
/// than control_request_timeout after the backend half-closed. Before the
/// fix the relay ended the session silently (bytes lost, no DELETE) and the
/// egress session stayed registered (default detect 45s / shutdown 30s).
#[test]
fn slow_client_after_backend_half_close_keeps_upstream_and_cleans_egress() {
    let mut failures = Vec::new();
    for mode in ["ws", "http-sse"] {
        let mut o = Opts::new(mode);
        o.ingress_transport
            .insert("control_request_timeout", "200ms".into());
        failures.extend(run(o, 0, Duration::from_millis(500), 2, 50_000));
        failures.extend(run(
            Opts::e2e(mode),
            0,
            Duration::from_millis(400),
            2,
            5_000,
        ));
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Concurrent half-closing sessions on one ws ingress: none may survive.
#[test]
fn ws_half_close_concurrent_default_config() {
    raise_nofile();
    let target = Target::echo("down_fin_first");
    let mut o = Opts::new("ws");
    o.max_sessions = 64;
    let env = Env::start(&target, o);
    let local = env.local;
    let mut hs = Vec::new();
    for t in 0..8 {
        hs.push(std::thread::spawn(move || {
            let mut errs = Vec::new();
            for i in 0..8 {
                let mut c = TcpStream::connect(local).unwrap();
                c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut one = [0u8; 1];
                let r = c.read(&mut one);
                if !matches!(r, Ok(0)) {
                    errs.push(format!("t{t} r{i}: no FIN: {r:?}"));
                    continue;
                }
                let data = vec![7u8; 1000 + 997 * i];
                if let Err(e) = c.write_all(&data) {
                    errs.push(format!("t{t} r{i}: write {e}"));
                }
                let _ = c.shutdown(Shutdown::Write);
                // The ingress closes the client once both FINs settled.
                let started = Instant::now();
                let _ = c.read(&mut one);
                if started.elapsed() > Duration::from_secs(3) {
                    errs.push(format!("t{t} r{i}: close took {:?}", started.elapsed()));
                }
            }
            errs
        }));
    }
    let mut failures = Vec::new();
    for h in hs {
        failures.extend(h.join().unwrap());
    }
    let left = env.wait_egress_sessions(0, Duration::from_secs(2));
    if left != 0 {
        failures.push(format!("{left} egress session(s) left after 2s"));
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
