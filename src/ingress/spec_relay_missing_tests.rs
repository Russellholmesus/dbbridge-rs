use super::*;
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::sync::atomic::AtomicI64;

/// A relay for `sid` on epoch 1 / stream "stream" / ws, bound to an egress
/// instance "bi" at `url`, with the given ingress `transport:` YAML keys.
pub(super) fn unit_relay(url: &str, transport: &str) -> Arc<Relay> {
    let dir = std::env::temp_dir().join(format!(
        "dbb-unit-relay-{}",
        crate::util::random_hex(6).unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("token"), "test-token-0123456789abcdef012345").unwrap();
    let path = dir.join("a.yaml");
    std::fs::write(
        &path,
        format!(
            "node:\n  id: A\nlisteners:\n  - id: local\n    listen: \"127.0.0.1:0\"\n    peer: B\n    target: db\npeers:\n  - id: B\n    expected_node_id: B\n    credential_ref: B\n    token_file: token\n    endpoints:\n      - id: e1\n        url: \"{url}\"\ntransport:\n  protocol: ws\n{transport}"
        ),
    )
    .unwrap();
    let cfg = Arc::new(crate::config::load(&path).expect("unit relay config"));
    let _ = std::fs::remove_dir_all(&dir);
    let peer = cfg.peers[0].clone();
    let endpoint = peer.endpoints[0].clone();
    let client = Arc::new(crate::net::http1::Client::new(
        Duration::from_secs(1),
        cfg.transport.control_request_timeout,
    ));
    let control = ControlClient::new(
        client,
        endpoint.url.clone(),
        "test-token-0123456789abcdef012345".into(),
        "bi".into(),
        peer.tls.clone(),
    );
    let metrics = Arc::new(crate::metrics::Metrics::new());
    metrics.configure_resources(&cfg);
    let created = wire::CreateResponse {
        node_id: "B".into(),
        instance_id: "bi".into(),
        session_id: "sid".into(),
        session_token: "token".into(),
        epoch: 1,
        mode: wire::Mode::Ws,
        recovery_enabled: false,
        recovery_grace_ms: 0,
        limits: crate::transport::requested_limits(&cfg.transport),
        unattached_timeout_ms: 5000,
    };
    Arc::new(Relay::new(RelayInit {
        cfg,
        control,
        peer,
        endpoint,
        metrics,
        created: &created,
        stream: "stream",
        implicit_ready: true,
    }))
}

/// A carrier writer that accepts and drops everything.
struct NullWriter;

impl CarrierWriter for NullWriter {
    fn send_data(&mut self, _: u64, _: u64, _: &[u8]) -> Result<Option<u64>> {
        Ok(None)
    }
    fn send_control(&mut self, _: &wire::Control) -> Result<()> {
        Ok(())
    }
    fn shutdown(&mut self) {}
}

/// Minimal HTTP/1.1 control endpoint: every request is answered by
/// `answer(n, probe_id)` (n counts requests from 1) as a JSON 200.
fn control_server(
    answer: impl Fn(i64, &str) -> String + Send + Sync + 'static,
) -> (String, Arc<AtomicI64>) {
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", ln.local_addr().unwrap());
    let calls = Arc::new(AtomicI64::new(0));
    let answer = Arc::new(answer);
    let c = calls.clone();
    std::thread::spawn(move || {
        for conn in ln.incoming() {
            let Ok(conn) = conn else { return };
            let (c, answer) = (c.clone(), answer.clone());
            std::thread::spawn(move || {
                let mut w = conn.try_clone().unwrap();
                let mut r = BufReader::new(conn);
                loop {
                    let mut len = 0usize;
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    loop {
                        let mut h = String::new();
                        if r.read_line(&mut h).unwrap_or(0) == 0 {
                            return;
                        }
                        let h = h.trim_end();
                        if h.is_empty() {
                            break;
                        }
                        if let Some((k, v)) = h.split_once(':') {
                            if k.eq_ignore_ascii_case("content-length") {
                                len = v.trim().parse().unwrap_or(0);
                            }
                        }
                    }
                    let mut body = vec![0u8; len];
                    if r.read_exact(&mut body).is_err() {
                        return;
                    }
                    let probe = crate::util::json::parse_bytes(&body)
                        .ok()
                        .and_then(|v| {
                            v.get("probe_id")
                                .and_then(|p| p.as_str())
                                .map(str::to_string)
                        })
                        .unwrap_or_default();
                    let n = c.fetch_add(1, Ordering::SeqCst) + 1;
                    let out = answer(n, &probe);
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{out}",
                        out.len()
                    );
                    if w.write_all(resp.as_bytes()).is_err() {
                        return;
                    }
                }
            });
        }
    });
    (url, calls)
}

fn ack_json(probe: &str, ack: u64, rx_blocked: bool) -> String {
    wire::AckResponse {
        session_id: "sid".into(),
        instance_id: "bi".into(),
        epoch: 1,
        stream_id: "stream".into(),
        mode: wire::Mode::Ws,
        ack_up_offset: ack,
        up_fin_applied: false,
        down_ack_offset: 0,
        down_fin_acked: false,
        probe_id: probe.into(),
        data_tx_blocked: false,
        data_rx_blocked: rx_blocked,
        backpressure_reason: "none".into(),
    }
    .to_json()
    .to_string()
}

#[test]
fn spec_released_frame_still_retained() {
    let relay = unit_relay("http://127.0.0.1:1", "");
    let res = relay.metrics.resource_manager().unwrap();
    let payload = vec![b'x'; 256 << 10];
    let lease = res.payload.try_acquire(payload.len() as i64).unwrap();
    {
        let mut g = relay.state.lock().unwrap();
        g.up_frames.push_back(RetainedUpFrame {
            offset: 0,
            end: payload.len() as u64,
            payload: payload.clone(),
            _cost: Some(Arc::new(lease)),
        });
        g.up_next = payload.len() as u64;
    }
    assert!(relay.advance_up_ack(payload.len() as u64));
    assert_eq!(res.payload.used(), 0, "probe expected accounting release");
    let g = relay.state.lock().unwrap();
    let retained: usize = g.up_frames.iter().map(|f| f.payload.len()).sum();
    assert!(
        g.up_frames.is_empty() && retained == 0,
        "payload budget=0 but the retention queue keeps {retained} payload bytes"
    );
}

#[test]
fn spec_upstream_detection_allows_healthy_waiting() {
    for kind in ["idle", "queued", "backend-backpressure", "ack-progress"] {
        let (url, calls) = control_server(move |n, probe| {
            let ack = if kind == "ack-progress" {
                n.min(8) as u64
            } else {
                0
            };
            ack_json(probe, ack, kind == "backend-backpressure")
        });
        let relay = unit_relay(
            &url,
            "  failure_detect_timeout: 250ms\n  backpressure_timeout: 3s\n  heartbeat: 50ms\n  ack_max_delay: 50ms\n  control_request_timeout: 1s\n  dial_timeout: 1s\n",
        );
        {
            let mut g = relay.state.lock().unwrap();
            if kind != "idle" {
                g.up_next = 8;
                for i in 0..8u64 {
                    g.up_frames.push_back(RetainedUpFrame {
                        offset: i,
                        end: i + 1,
                        payload: b"x".to_vec(),
                        _cost: None,
                    });
                }
            }
            if kind == "backend-backpressure" || kind == "ack-progress" {
                g.up_sent = 8;
                g.up_pending_since = Some(Instant::now());
            }
            g.last_activity = Instant::now();
        }
        let stop = Arc::new(AtomicBool::new(false));
        let ctl = {
            let (relay, stop) = (relay.clone(), stop.clone());
            std::thread::spawn(move || {
                relay.control_loop(stop, SharedWriter::new(Box::new(NullWriter)))
            })
        };
        let activity = {
            let (relay, stop) = (relay.clone(), stop.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    relay.state.lock().unwrap().last_activity = Instant::now();
                    std::thread::sleep(Duration::from_millis(10));
                }
            })
        };
        std::thread::sleep(Duration::from_millis(800));
        let (error, lost) = {
            let g = relay.state.lock().unwrap();
            (g.error.clone(), g.carrier_lost)
        };
        stop.store(true, Ordering::SeqCst);
        relay.cv.notify_all();
        let _ = ctl.join();
        let _ = activity.join();
        assert!(
            error.is_none() && !lost,
            "{kind} incorrectly classified as broken upstream: {error:?} lost={lost}"
        );
        assert!(
            calls.load(Ordering::SeqCst) >= 8,
            "{kind}: control fixture made insufficient progress ({})",
            calls.load(Ordering::SeqCst)
        );
        if kind == "ack-progress" {
            let g = relay.state.lock().unwrap();
            assert!(
                g.up_acked == 8 && g.up_pending_since.is_none(),
                "confirmed upstream bytes left an active stall timer (ack {} pending {:?})",
                g.up_acked,
                g.up_pending_since
            );
        }
    }
}

#[test]
fn spec_failed_attach_restores_generation() {
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", ln.local_addr().unwrap());
    std::thread::spawn(move || {
        for conn in ln.incoming() {
            let Ok(conn) = conn else { return };
            std::thread::spawn(move || {
                let mut w = conn.try_clone().unwrap();
                let mut r = BufReader::new(conn);
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 || line.trim().is_empty() {
                        break;
                    }
                }
                let _ = w.write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            });
        }
    });
    let relay = unit_relay(&url, "");
    let before = {
        let g = relay.state.lock().unwrap();
        (g.epoch, g.mode, g.carrier_lost)
    };
    let route = {
        let r = relay.route.lock().unwrap();
        Route {
            control: super::super::control_client_clone(&r.control),
            endpoint: r.endpoint.clone(),
        }
    };
    let endpoint_before = format!("{:?}", route.endpoint);
    for mode in [wire::Mode::HttpSse, wire::Mode::Ws] {
        let deadline = Instant::now() + Duration::from_secs(1);
        assert!(
            relay.redial(&route, before.0 + 1, mode, deadline).is_err(),
            "{mode:?}: attach unexpectedly succeeded"
        );
        let g = relay.state.lock().unwrap();
        assert_eq!(
            (g.epoch, g.mode, g.carrier_lost),
            before,
            "{mode:?}: failed attach changed the current generation"
        );
        drop(g);
        assert_eq!(
            format!("{:?}", relay.route.lock().unwrap().endpoint),
            endpoint_before,
            "{mode:?}: route replaced"
        );
    }
}
