use super::spec_e2e_harness::*;
use std::io::{Read, Write};
use std::time::{Duration, Instant};

#[test]
fn spec_flow_small_negotiated_window_acked() {
    const TOTAL: usize = 8 << 20;
    let target = Target::with(|mut c, _tx| {
        let chunk = vec![0u8; 64 << 10];
        let mut sent = 0;
        while sent < TOTAL {
            if c.write_all(&chunk).is_err() {
                return;
            }
            sent += chunk.len();
        }
        let mut sink = [0u8; 4096];
        while matches!(c.read(&mut sink), Ok(n) if n > 0) {}
    });
    let mut o = Opts::new("ws");
    o.ingress_transport.insert("ack_max_delay", "2s".into());
    o.egress_transport
        .insert("buffer_per_direction", "512KiB".into());
    let env = Env::start(&target, o);
    let mut c = env.dial();
    c.write_all(&[1]).unwrap();
    let t0 = Instant::now();
    c.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let mut buf = vec![0u8; 64 << 10];
    let mut got = 0usize;
    while got < TOTAL {
        match c.read(&mut buf) {
            Ok(0) => panic!("EOF after {got} bytes"),
            Ok(n) => got += n,
            Err(e) => panic!("read after {got} bytes: {e}"),
        }
    }
    let d = t0.elapsed();
    assert!(
        d <= Duration::from_secs(4),
        "8 MiB through a 512 KiB window took {d:?} (ACK timer bound)"
    );
}
