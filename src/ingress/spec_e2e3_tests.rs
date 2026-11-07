use super::spec_e2e_harness::*;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn is_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

#[test]
fn spec_ready_ack_failure_closes_before_data() {
    let target = Target::echo("");
    let mut o = Opts::e2e("http-sse");
    let cell = o.egress_cell.clone();
    o.hook = Some(Arc::new(move |r: &Req| {
        if r.method == "GET" && r.path.ends_with("/events") {
            if let Some(resp) = injected_events(&cell, r.path, |_, _| String::new()) {
                return Action::RespondHold(resp);
            }
        }
        if r.path.ends_with("/ack")
            && String::from_utf8_lossy(r.body).contains("\"ready_received\":true")
        {
            return Action::Respond(json_response(
                403,
                r#"{"code":"DBB_UNAUTHORIZED","message":"xy","retryable":false,"session_closed":true}"#,
            ));
        }
        Action::Pass
    }));
    let env = Env::start(&target, o);
    let mut c = env.dial();
    let _ = c.write_all(b"unauthorized-write");
    let got = target
        .received
        .lock()
        .unwrap()
        .recv_timeout(Duration::from_millis(300));
    if let Ok(p) = got {
        panic!(
            "backend got {:?} despite rejected ready ACK",
            String::from_utf8_lossy(&p)
        );
    }
}

#[test]
fn spec_bad_ws_identity_must_not_fallback() {
    let target = Target::echo("");
    let mut o = Opts::e2e("auto");
    let cell = o.egress_cell.clone();
    let checks = Arc::new(AtomicUsize::new(0));
    let k = checks.clone();
    let purpose = format!("{}: check", crate::wire::H_WS_PURPOSE.to_ascii_lowercase());
    o.hook = Some(Arc::new(move |r: &Req| {
        if r.path == crate::wire::PATH_WS && r.head.contains(&purpose) {
            k.fetch_add(1, Ordering::SeqCst);
            let header = |name: &str| {
                r.raw
                    .lines()
                    .find_map(|l| {
                        let (n, v) = l.split_once(':')?;
                        n.trim()
                            .eq_ignore_ascii_case(name)
                            .then(|| v.trim().to_string())
                    })
                    .unwrap_or_default()
            };
            let instance = cell
                .get()
                .map(|s| s.cfg.node.instance_id.clone())
                .unwrap_or_default();
            let hello = format!(
                r#"{{"type":"hello","protocol_version":"{}","node_id":"WRONG","instance_id":"{instance}","nonce":"{}","transport":"ws"}}"#,
                crate::wire::PROTOCOL_VERSION,
                header(crate::wire::H_WS_NONCE)
            );
            let mut out = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: {}\r\n\r\n",
                crate::net::ws::accept_key(&header("sec-websocket-key")),
                crate::wire::WS_SUBPROTOCOL
            )
            .into_bytes();
            out.extend_from_slice(&crate::transport::spec_precheck_tests::frame(
                crate::net::ws::OP_TEXT,
                hello.as_bytes(),
            ));
            return Action::RespondRawClose(out);
        }
        Action::Pass
    }));
    let env = Env::start(&target, o);
    let _c = env.dial();
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(checks.load(Ordering::SeqCst) > 0, "fixture: no WS precheck");
    let created = env
        .proxy
        .counts
        .count("POST", |p| p == crate::wire::PATH_SESSIONS);
    assert_eq!(
        created, 0,
        "created {created} session(s) after hello node identity mismatch"
    );
}

#[test]
fn spec_lost_create_response_can_be_retrieved_during_drain() {
    let target = Target::echo("");
    let mut o = Opts::new("auto");
    o.egress_recovery = Some("enabled: false".into());
    o.ingress_recovery = Some("enabled: false".into());
    o.ingress_transport
        .insert("control_request_timeout", "500ms".into());
    o.ingress_transport
        .insert("create_retry_timeout", "2s".into());
    let cell = o.egress_cell.clone();
    let first = Arc::new(AtomicBool::new(true));
    o.hook = Some(Arc::new(move |r: &Req| {
        if r.method == "POST"
            && r.path == crate::wire::PATH_SESSIONS
            && first.swap(false, Ordering::SeqCst)
        {
            let cell = cell.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                if let Some(srv) = cell.get() {
                    srv.registry.set_draining();
                }
            });
            return Action::ForwardThenDrop;
        }
        Action::Pass
    }));
    let env = Env::start(&target, o);
    let mut c = env.dial();
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    echo(&mut c, b"same session").expect("lost create was not retrieved");
    let creates = env
        .proxy
        .counts
        .count("POST", |p| p == crate::wire::PATH_SESSIONS);
    assert!(
        target.dials.load(Ordering::SeqCst) == 1
            && creates >= 2
            && !env.egress.registry.accepting(),
        "dials={} creates={creates} accepting={}",
        target.dials.load(Ordering::SeqCst),
        env.egress.registry.accepting()
    );
}

#[test]
fn spec_byte_threshold_schedules_ack_before_timer() {
    let target = Target::echo("");
    let mut o = Opts::new("http-sse");
    for t in [&mut o.egress_transport, &mut o.ingress_transport] {
        t.insert("heartbeat", "100ms".into());
        t.insert("failure_detect_timeout", "1s".into());
    }
    o.egress_recovery = Some("enabled: false".into());
    o.ingress_recovery = Some("enabled: false".into());
    o.ingress_transport.insert("ack_batch_bytes", "4B".into());
    o.ingress_transport.insert("ack_max_delay", "500ms".into());
    let acked: Arc<Mutex<Option<Instant>>> = Arc::default();
    let a = acked.clone();
    o.hook = Some(Arc::new(move |r: &Req| {
        if r.path.ends_with("/ack")
            && String::from_utf8_lossy(r.body).contains("\"down_delivered_offset\":\"4\"")
        {
            a.lock().unwrap().get_or_insert_with(Instant::now);
        }
        Action::Pass
    }));
    let env = Env::start(&target, o);
    let mut c = env.dial();
    c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let start = Instant::now();
    c.write_all(b"four").unwrap();
    c.read_exact(&mut [0u8; 4]).unwrap();
    let deadline = start + Duration::from_millis(300);
    while acked.lock().unwrap().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(2));
    }
    let at = acked
        .lock()
        .unwrap()
        .expect("byte threshold did not wake control");
    assert!(
        at.duration_since(start) < Duration::from_millis(300),
        "ACK threshold waited {:?} for 500ms timer",
        at.duration_since(start)
    );
    drop(env);
}

#[test]
fn spec_acceptance_200_client_close() {
    raise_nofile();
    const N: usize = 200;
    let target = Target::echo("");
    let mut o = Opts::new("ws");
    o.egress_recovery = Some("enabled: false".into());
    o.ingress_recovery = Some("enabled: false".into());
    o.max_sessions = 256;
    for t in [&mut o.egress_transport, &mut o.ingress_transport] {
        t.insert("heartbeat", "1s".into());
        t.insert("failure_detect_timeout", "10s".into());
        t.insert("control_request_timeout", "5s".into());
    }
    o.ingress_transport
        .insert("create_retry_timeout", "20s".into());
    let env = Env::start(&target, o);
    let clients: Vec<_> = (0..N)
        .map(|_| {
            let c = env.dial();
            c.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
            c
        })
        .collect();
    let clients: Vec<_> = clients
        .into_iter()
        .map(|mut c| std::thread::spawn(move || echo(&mut c, b"ping").map(|_| c)))
        .collect::<Vec<_>>()
        .into_iter()
        .map(|t| t.join().unwrap().expect("fixture echo"))
        .collect();
    assert_eq!(env.egress_sessions(), N, "fixture: egress sessions");
    let start = Instant::now();
    let readers: Vec<_> = clients
        .into_iter()
        .map(|mut c| {
            std::thread::spawn(move || {
                c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                match c.read(&mut [0u8; 1]) {
                    Ok(n) if n > 0 => Err("client stayed readable".to_string()),
                    Err(e) if is_timeout(&e) => Err("client stayed open 3s".to_string()),
                    _ => Ok(start.elapsed()),
                }
            })
        })
        .collect();
    let cut = env.proxy.kill(|p| p == crate::wire::PATH_WS);
    assert_eq!(cut, N, "fixture: carriers cut");
    let mut worst = Duration::ZERO;
    for r in readers {
        worst = worst.max(r.join().unwrap().unwrap());
    }
    assert!(
        worst <= Duration::from_secs(1),
        "200-session close exceeded 1s: {worst:?}"
    );
}

#[test]
fn spec_final_ack_must_not_delay_failure_close() {
    // A backend that keeps its side open after the client's FIN, so the
    // session still waits for confirmations when the fault hits.
    let target = Target::with(|mut c, tx| {
        let mut buf = vec![0u8; 4096];
        loop {
            match c.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let _ = tx.try_send(buf[..n].to_vec());
                    if c.write_all(&buf[..n]).is_err() {
                        return;
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_secs(10));
    });
    let mut o = Opts::new("ws");
    o.egress_recovery = Some("enabled: false".into());
    o.ingress_recovery = Some("enabled: false".into());
    o.ingress_transport
        .insert("control_request_timeout", "2s".into());
    let block = Arc::new(AtomicBool::new(false));
    let b = block.clone();
    o.hook = Some(Arc::new(move |r: &Req| {
        if b.load(Ordering::SeqCst) && r.path.ends_with("/ack") {
            return Action::Hang(Duration::from_secs(5));
        }
        Action::Pass
    }));
    let env = Env::start(&target, o);
    let mut c = env.dial();
    echo(&mut c, b"test-credential").unwrap();
    std::thread::sleep(Duration::from_millis(50));
    block.store(true, Ordering::SeqCst);
    c.shutdown(Shutdown::Write).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    let start = Instant::now();
    assert!(
        env.proxy.kill(|p| p == crate::wire::PATH_WS) > 0,
        "fixture: no carrier to cut"
    );
    c.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
    let got = c.read(&mut [0u8; 1]);
    let d = start.elapsed();
    if let Err(e) = &got {
        assert!(!is_timeout(e), "fixture: client socket did not close");
    }
    assert!(
        d <= Duration::from_secs(1),
        "contract violation: recovery=false local client closed {d:?} after detected carrier failure (>1s)"
    );
}
