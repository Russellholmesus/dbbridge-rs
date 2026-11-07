use super::*;
use crate::config::{Peer, Protocol};
use crate::error::Result as DbbResult;
use crate::transport::spec_precheck_tests::{header_of, hello, upgrade, ws_server};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};

pub(super) struct Fixture {
    pub(super) ingress: Ingress,
    pub(super) peer: Peer,
    pub(super) probes: Arc<AtomicUsize>,
    pub(super) ws_checks: Arc<AtomicUsize>,
    _dir: TempDir,
}

pub(super) struct TempDir(pub(super) std::path::PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Reads one request (head + Content-Length body) from a keep-alive socket.
pub(super) fn read_req(c: &mut TcpStream, first_head: Option<&str>) -> Option<(String, Vec<u8>)> {
    let head = match first_head {
        Some(h) => h.to_string(),
        None => {
            let mut head = Vec::new();
            let mut b = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                match c.read(&mut b) {
                    Ok(1) => head.push(b[0]),
                    _ => return None,
                }
            }
            String::from_utf8_lossy(&head).to_string()
        }
    };
    let n: usize = header_of(&head, "content-length").parse().unwrap_or(0);
    let mut body = vec![0u8; n];
    c.read_exact(&mut body).ok()?;
    Some((head, body))
}

pub(super) fn probe_answer(body: &[u8], transports: &str) -> String {
    probe_answer_accepting(body, transports, true)
}

pub(super) fn probe_answer_accepting(body: &[u8], transports: &str, accepting: bool) -> String {
    let v = crate::util::json::parse_bytes(body).unwrap();
    let nonce = v.get("nonce").and_then(|n| n.as_str()).unwrap_or("");
    let body = format!(
        r#"{{"protocol_version":"1.5","node_id":"B","instance_id":"bi","nonce":"{nonce}","recovery_available":true,"accepting_new_sessions":{accepting},"transports":[{transports}]}}"#
    );
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

/// A scripted peer: probes are answered healthy (ws + http-sse) on keep-alive
/// connections; every `/v1/transport/ws` request goes to `ws`.
pub(super) fn scripted_peer(
    ws: impl Fn(&str, &mut TcpStream) + Send + Sync + 'static,
) -> (SocketAddr, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    let probes = Arc::new(AtomicUsize::new(0));
    let checks = Arc::new(AtomicUsize::new(0));
    let (p, k) = (probes.clone(), checks.clone());
    let addr = ws_server(move |head, c| {
        let mut first = Some(head.to_string());
        loop {
            let Some((head, body)) = read_req(c, first.take().as_deref()) else {
                return;
            };
            let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
            if path.starts_with(wire::PATH_PROBE) {
                p.fetch_add(1, Ordering::SeqCst);
                let _ = c.write_all(probe_answer(&body, r#""ws","http-sse""#).as_bytes());
                continue;
            }
            if path.starts_with(wire::PATH_WS) {
                k.fetch_add(1, Ordering::SeqCst);
                ws(&head, c);
                return;
            }
            let _ =
                c.write_all(b"HTTP/1.1 404 X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            return;
        }
    });
    (addr, probes, checks)
}

pub(super) fn fixture_at(
    addr: SocketAddr,
    probes: Arc<AtomicUsize>,
    ws_checks: Arc<AtomicUsize>,
    mode: &str,
    failover: &str,
) -> Fixture {
    let dir = std::env::temp_dir().join(format!(
        "dbb-ingress-precheck-{}",
        crate::util::random_hex(6).unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("token"), super::spec_e2e_harness::TOKEN).unwrap();
    let path = dir.join("a.yaml");
    std::fs::write(
        &path,
        format!(
            "node:\n  id: A\nlisteners:\n  - id: local\n    listen: \"127.0.0.1:0\"\n    peer: B\n    target: db\npeers:\n  - id: B\n    expected_node_id: B\n    credential_ref: B\n    token_file: token\n    transport:\n      protocol: {mode}\n    failover:\n      healthcheck_timeout: 1s\n{failover}    endpoints:\n      - id: e\n        url: \"http://{addr}\"\ntransport:\n  protocol: {mode}\n  control_request_timeout: 1s\n  dial_timeout: 1s\n"
        ),
    )
    .unwrap();
    let cfg = Arc::new(crate::config::load(&path).expect("ingress config"));
    let peer = cfg.peer("B").unwrap().clone();
    Fixture {
        ingress: Ingress::new(cfg),
        peer,
        probes,
        ws_checks,
        _dir: TempDir(dir),
    }
}

pub(super) fn fixture(
    mode: &str,
    ws: impl Fn(&str, &mut TcpStream) + Send + Sync + 'static,
) -> Fixture {
    let (addr, probes, checks) = scripted_peer(ws);
    fixture_at(addr, probes, checks, mode, "      cooldown: 5s\n")
}

impl Fixture {
    pub(super) fn choose(&self, protocol: Protocol) -> DbbResult<(String, Mode)> {
        let mut peer = self.peer.clone();
        peer.protocol = protocol;
        let (ep, h) = self.ingress.select_endpoint(&peer)?;
        let client = self.ingress.client_for(&peer.id);
        let mode = self.ingress.select_mode(&peer, &ep, &h, &client)?;
        Ok((ep.id, mode))
    }

    pub(super) fn state(&self) -> &'static str {
        self.ingress
            .endpoints
            .get("B", "e")
            .map_or("UNKNOWN", |h| h.state)
    }
}

fn gateway(status: u16) -> impl Fn(&str, &mut TcpStream) + Send + Sync + 'static {
    move |_, c| {
        let _ = c.write_all(
            format!(
                "HTTP/1.1 {status} X\r\nLocation: https://sso.example.com/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        );
    }
}

#[test]
fn spec_precheck_gateway_answer_falls_back_to_sse() {
    for status in [301, 302, 307, 308, 407, 410, 413, 414, 429, 431, 500] {
        let f = fixture("auto", gateway(status));
        let got = f.choose(Protocol::Auto);
        assert!(
            matches!(got, Ok((_, Mode::HttpSse))),
            "auto after a gateway {status}: {got:?}, want http-sse"
        );
        assert!(
            f.state() != "MISMATCHED" && !f.ingress.endpoints.in_cooldown("B", "e"),
            "endpoint isolated after a gateway {status}: {}",
            f.state()
        );
        assert!(
            !f.ingress
                .endpoints
                .transport_available("B", "e", Mode::Ws, Instant::now()),
            "WS carrier not cooled after a gateway {status}"
        );
        let got = f.choose(Protocol::HttpSse);
        assert!(
            matches!(got, Ok((_, Mode::HttpSse))),
            "http-sse right after a gateway {status}: {got:?}"
        );
    }
}

#[test]
fn spec_precheck_raw_401_no_fallback_no_isolation() {
    let f = fixture("auto", gateway(401));
    let got = f.choose(Protocol::Auto);
    assert!(got.is_err(), "raw 401: {got:?}, want no selection");
    assert_ne!(f.state(), "MISMATCHED", "raw 401 marked the endpoint");
    assert!(
        !f.ingress.endpoints.in_cooldown("B", "e"),
        "raw 401 cooled the address"
    );
    let e = got.unwrap_err();
    assert_eq!(classify_precheck(&e), PrecheckVerdict::SessionFailed);
}

#[test]
fn spec_precheck_gateway_refusal_still_falls_back() {
    for status in [400, 404, 405, 426, 501] {
        let f = fixture("auto", gateway(status));
        let got = f.choose(Protocol::Auto);
        let probes = f.probes.load(Ordering::SeqCst);
        assert!(
            matches!(got, Ok((_, Mode::HttpSse))) && probes >= 2,
            "raw {status}: {got:?} probes={probes}, want http-sse after re-probe"
        );
    }
}

#[test]
fn spec_precheck_bad_hello_rejects_candidate() {
    for (name, msg) in [
        (
            "version",
            r#"{"type":"hello","protocol_version":"1.3","node_id":"B","instance_id":"bi","nonce":"%s","transport":"ws"}"#,
        ),
        ("duplicate key", r#"{"type":"hello","type":"hello"}"#),
    ] {
        let f = fixture("auto", move |head, c| {
            upgrade(head, c, true);
            let _ = c.write_all(&crate::transport::spec_precheck_tests::frame(
                crate::net::ws::OP_TEXT,
                msg.as_bytes(),
            ));
            let _ = c.read(&mut [0u8; 16]);
        });
        let got = f.choose(Protocol::Auto);
        match got {
            Err(e) => assert_eq!(e.code, wire::ERR_WS_PROTOCOL_ERROR, "{name}: {e:?}"),
            Ok(v) => panic!("{name}: selected {v:?}, want a protocol error"),
        }
    }
}

#[test]
fn spec_classify_precheck() {
    let remote = |code: &str, status: u16, trusted: bool, retryable: bool| {
        Error::new(code, "x")
            .remote_status(status)
            .trusted(trusted)
            .retryable(retryable)
    };
    let raw = |status: u16| {
        Error::new(wire::ERR_WS_HANDSHAKE_FAILED, format!("status {status}")).remote_status(status)
    };
    let cases = [
        (
            "hello mismatch",
            Error::new(wire::ERR_WS_PROTOCOL_ERROR, "node ID mismatch"),
            PrecheckVerdict::Mismatched,
        ),
        (
            "trusted instance mismatch",
            remote(wire::ERR_INSTANCE_MISMATCH, 409, true, false),
            PrecheckVerdict::Mismatched,
        ),
        (
            "trusted 401",
            remote(wire::ERR_UNAUTHORIZED, 401, true, false),
            PrecheckVerdict::SessionFailed,
        ),
        (
            "trusted 403",
            remote(wire::ERR_UNAUTHORIZED, 403, true, false),
            PrecheckVerdict::SessionFailed,
        ),
        ("raw 401", raw(401), PrecheckVerdict::SessionFailed),
        ("raw 403", raw(403), PrecheckVerdict::WsUnavailable),
        ("raw 302", raw(302), PrecheckVerdict::WsUnavailable),
        ("raw 407", raw(407), PrecheckVerdict::WsUnavailable),
        ("raw 429", raw(429), PrecheckVerdict::WsUnavailable),
        ("raw 500", raw(500), PrecheckVerdict::WsUnavailable),
        (
            "trusted unsupported",
            remote(wire::ERR_TRANSPORT_UNSUPPORTED, 400, true, false),
            PrecheckVerdict::WsUnavailable,
        ),
        (
            "trusted 500",
            remote(wire::ERR_INTERNAL_ERROR, 500, true, false),
            PrecheckVerdict::Temporary,
        ),
        (
            "trusted 429",
            remote(wire::ERR_QUOTA_EXCEEDED, 429, true, true),
            PrecheckVerdict::Temporary,
        ),
        (
            "upgrade rejected",
            Error::new(wire::ERR_WS_HANDSHAKE_FAILED, "status 426"),
            PrecheckVerdict::WsUnavailable,
        ),
        (
            "reset",
            Error::local("read: connection reset by peer"),
            PrecheckVerdict::WsUnavailable,
        ),
        (
            "check timeout",
            Error::local("ws precheck: no hello before the deadline").retryable(true),
            PrecheckVerdict::Temporary,
        ),
    ];
    for (name, e, want) in cases {
        assert_eq!(classify_precheck(&e), want, "{name}");
    }
    assert!(!precheck_cacheable(&raw(429)));
    assert!(!precheck_cacheable(&raw(502)));
    assert!(precheck_cacheable(&raw(426)));
}

/// The precheck against the real hello shape the fixture serves passes
/// (sanity for the fixture itself): auto selects WS.
#[test]
fn spec_precheck_fixture_valid_hello_selects_ws() {
    let f = fixture("auto", |head, c| {
        upgrade(head, c, true);
        let _ = c.write_all(&crate::transport::spec_precheck_tests::frame(
            crate::net::ws::OP_TEXT,
            hello(head).as_bytes(),
        ));
        let _ = c.read(&mut [0u8; 16]);
    });
    let got = f.choose(Protocol::Auto);
    assert!(matches!(got, Ok((_, Mode::Ws))), "{got:?}");
    assert_eq!(f.ws_checks.load(Ordering::SeqCst), 1);
}

#[test]
fn spec_draining_creation_retry_candidate() {
    let probes = Arc::new(AtomicUsize::new(0));
    let p = probes.clone();
    let addr = ws_server(move |head, c| {
        let mut first = Some(head.to_string());
        while let Some((_, body)) = read_req(c, first.take().as_deref()) {
            p.fetch_add(1, Ordering::SeqCst);
            let _ =
                c.write_all(probe_answer_accepting(&body, r#""ws","http-sse""#, false).as_bytes());
        }
    });
    let f = fixture_at(addr, probes, Arc::new(AtomicUsize::new(0)), "http-sse", "");
    assert!(
        f.ingress.select_endpoint_for(&f.peer, false).is_ok(),
        "existing submitted create cannot reach its result while the endpoint drains"
    );
    assert!(
        f.ingress.select_endpoint_for(&f.peer, true).is_err(),
        "a new session selected a draining endpoint"
    );
}

#[test]
fn spec_create_deadline_closes_silent_ws_ready() {
    let addr = ws_server(move |head, c| {
        let mut first = Some(head.to_string());
        while let Some((head, body)) = read_req(c, first.take().as_deref()) {
            let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
            if path.starts_with(wire::PATH_PROBE) {
                let _ = c.write_all(probe_answer(&body, r#""ws","http-sse""#).as_bytes());
            } else if path == wire::PATH_SESSIONS {
                let v = crate::util::json::parse_bytes(&body).unwrap();
                let q = wire::CreateRequest::from_json(&v).unwrap();
                let resp = wire::CreateResponse {
                    node_id: "B".into(),
                    instance_id: "bi".into(),
                    session_id: "silent-ready-session-0000000000".into(),
                    session_token: "session-token".into(),
                    epoch: 1,
                    mode: q.mode,
                    recovery_enabled: q.recovery_enabled,
                    recovery_grace_ms: q.recovery_grace_ms,
                    limits: q.limits,
                    unattached_timeout_ms: 30000,
                }
                .to_json()
                .to_string();
                let _ = c.write_all(
                    format!(
                        "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{resp}",
                        resp.len()
                    )
                    .as_bytes(),
                );
            } else if path.starts_with(wire::PATH_WS) {
                upgrade(&head, c, true);
                if header_of(&head, wire::H_WS_PURPOSE) == "check" {
                    let _ = c.write_all(&crate::transport::spec_precheck_tests::frame(
                        crate::net::ws::OP_TEXT,
                        hello(&head).as_bytes(),
                    ));
                }
                let _ = c.set_read_timeout(Some(Duration::from_secs(5)));
                let _ = c.read(&mut [0u8; 64]);
                return;
            } else {
                return;
            }
        }
    });
    let f = fixture_at(
        addr,
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicUsize::new(0)),
        "ws",
        "",
    );
    let mut cfg = (*f.ingress.cfg).clone();
    cfg.transport.create_retry_timeout = Duration::from_millis(150);
    cfg.transport.ws_handshake_timeout = Duration::from_millis(1400);
    cfg.transport.control_request_timeout = Duration::from_secs(2);
    cfg.transport.recovery_enabled = false;
    let ingress = Ingress::new(Arc::new(cfg));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let threads = ingress.start(stop.clone()).unwrap();
    let local = ingress.accept_addrs.lock().unwrap()[0];
    let start = Instant::now();
    let mut c = TcpStream::connect(local).unwrap();
    c.set_read_timeout(Some(Duration::from_millis(1250)))
        .unwrap();
    let got = c.read(&mut [0u8; 1]);
    let timed_out = matches!(&got, Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut));
    stop.store(true, Ordering::SeqCst);
    ingress.request_shutdown();
    for t in threads {
        let _ = t.join();
    }
    assert!(
        !timed_out,
        "client remains open {:?} after accept; creation deadline=150ms, terminal closure allowance=1s",
        start.elapsed()
    );
}

#[test]
fn spec_suspect_endpoint_ordered_last() {
    let (a, a_probes, _) = scripted_peer(|_, _| {});
    let (b, _, _) = scripted_peer(|_, _| {});
    let dir = std::env::temp_dir().join(format!(
        "dbb-ingress-order-{}",
        crate::util::random_hex(6).unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let _dir = TempDir(dir.clone());
    std::fs::write(dir.join("token"), super::spec_e2e_harness::TOKEN).unwrap();
    let path = dir.join("a.yaml");
    std::fs::write(
        &path,
        format!(
            "node:\n  id: A\nlisteners:\n  - id: local\n    listen: \"127.0.0.1:0\"\n    peer: B\n    target: db\npeers:\n  - id: B\n    expected_node_id: B\n    credential_ref: B\n    token_file: token\n    failover:\n      unhealthy_threshold: 2\n    endpoints:\n      - id: a\n        url: \"http://{a}\"\n        priority: 1\n      - id: b\n        url: \"http://{b}\"\n        priority: 2\ntransport:\n  protocol: http-sse\n"
        ),
    )
    .unwrap();
    let cfg = Arc::new(crate::config::load(&path).expect("config"));
    let ingress = Ingress::new(cfg.clone());
    let peer = cfg.peer("B").unwrap().clone();
    ingress
        .endpoints
        .record_probe_failure("B", "a", Duration::from_secs(5), 2, false);
    assert!(
        !ingress.endpoints.in_cooldown("B", "a"),
        "fixture: below threshold"
    );
    let (ep, _) = ingress.select_endpoint(&peer).unwrap();
    assert_eq!(ep.id, "b", "order after a failed primary probe");
    assert_eq!(
        a_probes.load(Ordering::SeqCst),
        0,
        "the suspect primary was probed before the healthy backup"
    );
    let mut single = peer.clone();
    single.failover.enabled = false;
    let (ep, _) = ingress.select_endpoint(&single).unwrap();
    assert_eq!(
        ep.id, "a",
        "failover disabled must use only the first endpoint"
    );
}

#[test]
fn spec_metrics_format() {
    let f = fixture("http-sse", |_, _| {});
    f.ingress
        .metrics
        .observe_ingress_phase("B", "e", "probe", true, Duration::from_millis(3));
    f.ingress.metrics.set_endpoint_state("B", "e", "UNKNOWN");
    let out = f
        .ingress
        .metrics
        .render(&f.ingress.cfg, Instant::now(), true);
    for want in [
        "# TYPE dbb_endpoint_state gauge",
        "# TYPE dbb_phase_duration_seconds summary",
        "# TYPE dbb_ingress_bound_sessions gauge",
        "state=\"UNKNOWN\"} 1",
        "state=\"HEALTHY\"} 0",
        "state=\"MISMATCHED\"} 0",
        "phase=\"probe\",success=\"true\"} 1",
    ] {
        assert!(out.contains(want), "metrics missing {want:?}:\n{out}");
    }
    assert_eq!(
        out.matches("# TYPE dbb_phase_duration_seconds").count(),
        1,
        "phase family declared more than once"
    );
}
