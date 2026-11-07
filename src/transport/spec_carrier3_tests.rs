use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::config::ClientTls;
use crate::error::Error;
use crate::net::http1::Client;
use crate::net::Url;
use crate::wire;

use super::control::ControlClient;
use super::spec_precheck_tests::{frame, header_of, hello_with, precheck, upgrade, ws_server};
use super::ws_carrier;
use super::{CarrierReader, CarrierWriter, Incoming};

/// A keep-alive HTTP/1.1 server answering every request with `respond`
/// (request head -> whole raw response). Returns its address and the heads.
pub(crate) fn http_server(
    respond: impl Fn(&str) -> String + Send + Sync + 'static,
) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = ln.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s = seen.clone();
    let respond = Arc::new(respond);
    std::thread::spawn(move || {
        for c in ln.incoming() {
            let Ok(mut c) = c else { return };
            let (s, respond) = (s.clone(), respond.clone());
            std::thread::spawn(move || loop {
                let _ = c.set_read_timeout(Some(Duration::from_secs(5)));
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match c.read(&mut b) {
                        Ok(1) => head.push(b[0]),
                        _ => return,
                    }
                }
                let text = String::from_utf8_lossy(&head).to_string();
                let len: usize = header_of(&text, "content-length").parse().unwrap_or(0);
                let mut body = vec![0u8; len];
                if c.read_exact(&mut body).is_err() {
                    return;
                }
                s.lock().unwrap().push(text.clone());
                if c.write_all(respond(&text).as_bytes()).is_err() {
                    return;
                }
            });
        }
    });
    (addr, seen)
}

pub(crate) fn json_ok(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\n{}: bi\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        wire::H_INSTANCE_ID,
        body.len()
    )
}

fn control_for(addr: SocketAddr) -> ControlClient {
    ControlClient::new(
        Arc::new(Client::new(Duration::from_secs(1), Duration::from_secs(1))),
        Url::parse(&format!("http://{addr}")).unwrap(),
        "secret".into(),
        "bi".into(),
        ClientTls::default(),
    )
}

fn dial_session(url: &str, timeout: Duration) -> crate::error::Result<ws_carrier::WsAttach> {
    let url = Url::parse(url).unwrap();
    let client = Client::new(Duration::from_secs(1), Duration::from_secs(1));
    let headers = vec![
        (wire::H_PEER_AUTH.to_string(), "Bearer tok".to_string()),
        (wire::H_SESSION_TOKEN.to_string(), "secret".to_string()),
        (wire::H_INSTANCE_ID.to_string(), "bi".to_string()),
        (wire::H_WS_PURPOSE.to_string(), "session".to_string()),
        (wire::H_WS_SESSION_ID.to_string(), "sid".to_string()),
        (wire::H_WS_EPOCH.to_string(), "1".to_string()),
    ];
    ws_carrier::dial_session_via_with_leases(&*client.dialer(), &url, &headers, timeout, Vec::new())
}

/// An error the data plane treats as a protocol violation (never a carrier
/// loss, never an SSE fallback).
fn is_protocol(e: &Error) -> bool {
    matches!(
        e.code.as_str(),
        wire::ERR_WS_PROTOCOL_ERROR | wire::ERR_PROTOCOL_MISMATCH | wire::ERR_TLS_FAILED
    )
}

#[test]
fn spec_invalid_precheck_must_not_permit_fallback() {
    for kind in ["subprotocol", "protocol_version", "malformed_hello"] {
        let addr = ws_server(move |head, c| {
            upgrade(head, c, kind != "subprotocol");
            let msg = match kind {
                "malformed_hello" => r#"{"type":"hello","type":"hello"}"#.to_string(),
                "protocol_version" => hello_with(head, |f| f[1].1 = "1.3".into()),
                _ => hello_with(head, |_| {}),
            };
            let _ = c.write_all(&frame(crate::net::ws::OP_TEXT, msg.as_bytes()));
            let _ = c.read(&mut [0u8; 64]);
        });
        let e = precheck(addr, Duration::from_secs(2)).unwrap_err();
        assert!(
            e.code == wire::ERR_WS_PROTOCOL_ERROR && e.code != wire::ERR_WS_HANDSHAKE_FAILED,
            "contract violation: invalid {kind} classified as fallback-eligible: {e:?}"
        );
    }
}

#[test]
fn spec_initial_ready_protocol_classification() {
    for kind in ["duplicate", "binary", "syntax", "limit", "disconnect"] {
        let addr = ws_server(move |head, c| {
            upgrade(head, c, true);
            let f = match kind {
                "duplicate" => frame(
                    crate::net::ws::OP_TEXT,
                    br#"{"type":"ready","type":"ready"}"#,
                ),
                "binary" => frame(crate::net::ws::OP_BINARY, b"{}"),
                "syntax" => frame(crate::net::ws::OP_TEXT, br#"{"type":"#),
                "limit" => {
                    // A syntactically valid ready, padded past 16 KiB, so only
                    // the size limit can refuse it.
                    let pad = " ".repeat(17 << 10);
                    let ready = format!(
                        r#"{{"type":"ready","protocol_version":"{}","session_id":"sid","instance_id":"bi","epoch":"1","stream_id":"st","transport":"ws"{pad}}}"#,
                        wire::PROTOCOL_VERSION
                    );
                    frame(crate::net::ws::OP_TEXT, ready.as_bytes())
                }
                _ => Vec::new(),
            };
            let _ = c.write_all(&f);
            let _ = c.flush();
            std::thread::sleep(Duration::from_millis(50));
        });
        let e = match dial_session(&format!("http://{addr}"), Duration::from_secs(2)) {
            Ok(_) => panic!("{kind}: ready accepted"),
            Err(e) => e,
        };
        assert_eq!(
            is_protocol(&e),
            kind != "disconnect",
            "{kind}: protocol classification: {e:?}"
        );
    }
}

fn resume_response(remaining: &str) -> String {
    format!(
        r#"{{"session_id":"sid","instance_id":"bi","resume_request_id":"request","epoch":"2","transport":{{"mode":"ws"}},"up_written_offset":"0","ack_up_offset":"0","down_replay_from":"0","down_produced_offset":"0","down_retained_from":"0","up_fin":{{"received":false,"final_offset":null,"applied":false}},"down_fin":{{"seen":false,"final_offset":null,"applied":false,"acked":false}},"resume_remaining_ms":{remaining}}}"#
    )
}

#[test]
fn spec_resume_rejects_unrepresentable_remaining_budget() {
    for remaining in ["0", "-1", "9223372036854775807", "1000"] {
        let body = resume_response(remaining);
        let (addr, _) = http_server(move |_| json_ok(&body));
        let req = crate::session::recovery::ResumeRequest {
            resume_request_id: "request".into(),
            expected_epoch: 1,
            ingress_instance_id: "ai".into(),
            transport: wire::Mode::Ws,
            known_up_ack_offset: 0,
            up_next_offset: 0,
            down_delivered_offset: 0,
            up_fin: Default::default(),
            down_fin: Default::default(),
        };
        let got = control_for(addr).resume("sid", "secret", &req);
        if remaining == "1000" {
            let r = got.unwrap_or_else(|e| panic!("valid budget refused: {e:?}"));
            assert_eq!(r.resume_remaining, Duration::from_millis(1000));
        } else {
            let e = got
                .err()
                .unwrap_or_else(|| panic!("invalid remaining budget accepted: {remaining}"));
            assert!(is_protocol(&e), "{remaining}: {e:?}");
        }
    }
}

#[test]
fn spec_response_binding_mismatch_is_err_protocol() {
    for op in ["ack", "up", "fin"] {
        let body = match op {
            "ack" => {
                r#"{"session_id":"s","instance_id":"bi","epoch":"1","stream_id":"other-stream","transport":{"mode":"ws"},"ack_up_offset":"0","up_fin_applied":false,"down_ack_offset":"0","down_fin_acked":false,"probe_id":"p1"}"#
            }
            "up" => {
                r#"{"session_id":"s","instance_id":"bi","epoch":"2","stream_id":"st","transport":{"mode":"http-sse"},"frame_accepted":true,"ack_up_offset":"1","down_ack_offset":"0","up_fin_applied":false}"#
            }
            _ => {
                r#"{"session_id":"other","instance_id":"bi","epoch":"1","stream_id":"st","transport":{"mode":"ws"},"up_fin_applied":true}"#
            }
        };
        let (addr, _) = http_server(move |_| json_ok(body));
        let c = control_for(addr);
        let err = match op {
            "ack" => {
                let req = wire::AckRequest {
                    probe_id: "p1".into(),
                    ready_received: true,
                    ..Default::default()
                };
                c.ack("s", "tok", 1, "st", &req).err()
            }
            "up" => {
                let provider: super::control::TokenProvider = Arc::new(|| Ok("secret".into()));
                let mut poster = super::sse_carrier::SseUpPoster::new(
                    c.client.clone(),
                    c.url.clone(),
                    "s".into(),
                    Some(provider),
                    "tok".into(),
                    "bi".into(),
                    1,
                    "st".into(),
                    Arc::new(Default::default()),
                    Arc::new(Default::default()),
                );
                poster.send_data(1, 0, b"x").err()
            }
            _ => c.fin("s", "tok", 1, "st", 0).err(),
        };
        let e = err.unwrap_or_else(|| panic!("{op}: mismatched binding accepted"));
        assert!(
            is_protocol(&e) && e.message.contains("binding mismatch"),
            "{op} binding mismatch err={e:?}, want a protocol error"
        );
    }
}

/// A raw WebSocket client over `stream`: the reader of the carrier.
fn ws_reader_over(stream: TcpStream) -> super::ws_carrier::WsCarrierReader {
    let conn = crate::net::BufferedConn::from_boxed(Box::new(stream));
    let (reader, writer) = crate::net::ws::split(conn, true).unwrap();
    drop(writer);
    super::ws_carrier::reader_for_tests(reader)
}

fn tcp_pair() -> (TcpStream, TcpStream) {
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = TcpStream::connect(ln.local_addr().unwrap()).unwrap();
    let (b, _) = ln.accept().unwrap();
    (a, b)
}

#[test]
fn spec_classify_ws_read_error_close_sent() {
    // Close sent by us, then the peer answers its Close and goes away.
    let (client, mut server) = tcp_pair();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let conn = crate::net::BufferedConn::from_boxed(Box::new(client));
    let (reader, writer) = crate::net::ws::split(conn, true).unwrap();
    let mut w = super::ws_carrier::writer_for_tests(writer);
    let mut r = super::ws_carrier::reader_for_tests(reader);
    w.shutdown();
    let mut buf = [0u8; 64];
    let n = server.read(&mut buf).unwrap();
    assert!(n >= 2 && buf[0] & 0x0f == 0x8, "no close frame sent");
    server
        .write_all(&frame(0x8, &1000u16.to_be_bytes()))
        .unwrap();
    drop(server);
    for _ in 0..2 {
        match r.recv() {
            Ok(Incoming::Closed(_)) | Ok(Incoming::Idle) => {}
            Ok(_) => panic!("unexpected message after close"),
            Err(e) => assert!(
                !is_protocol(&e),
                "close-sent read classified as protocol: {e:?}"
            ),
        }
    }
    // A reserved opcode is a framing violation.
    let (client, mut server) = tcp_pair();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut r = ws_reader_over(client);
    server.write_all(&[0x83, 0x00]).unwrap();
    let e = r.recv().err().expect("bad opcode accepted");
    assert!(
        is_protocol(&e),
        "framing error no longer a protocol error: {e:?}"
    );
}

#[test]
fn spec_ws_read_truncated_tls_record_is_carrier_loss() {
    let assert_loss = |got: crate::error::Result<Incoming>, what: &str| match got {
        Ok(Incoming::Closed(_)) => {}
        Ok(_) => panic!("{what}: truncated frame produced a message"),
        Err(e) => assert!(
            !is_protocol(&e) && (e.is_local() || e.code == wire::ERR_BACKEND_LOST),
            "{what}: truncated frame classified as {e:?}"
        ),
    };
    let (client, mut server) = tcp_pair();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut r = ws_reader_over(client);
    let whole = frame(crate::net::ws::OP_BINARY, &[7u8; 300]);
    server.write_all(&whole[..100]).unwrap();
    drop(server);
    assert_loss(r.recv(), "tcp");

    #[cfg(feature = "tls")]
    {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/net/testdata");
        let ln = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = ln.local_addr().unwrap();
        let server_cfg = Arc::new(
            crate::net::tls::server_config(
                &dir.join("localhost-cert.pem"),
                &dir.join("localhost-key.pem"),
            )
            .unwrap(),
        );
        let t = std::thread::spawn(move || {
            let (s, _) = ln.accept().unwrap();
            let raw = s.try_clone().unwrap();
            let mut tls =
                crate::net::tls::TlsConn::accept_with_config(s, server_cfg, Duration::from_secs(5))
                    .unwrap();
            tls.write_all(&whole[..100]).unwrap();
            tls.flush().unwrap();
            std::thread::sleep(Duration::from_millis(50));
            // The stream ends without close_notify.
            let _ = raw.shutdown(std::net::Shutdown::Both);
        });
        let s = TcpStream::connect(addr).unwrap();
        let cfg = Arc::new(
            crate::net::tls::client_config(Some(&dir.join("localhost-ca.pem")), true).unwrap(),
        );
        let tls = crate::net::tls::TlsConn::connect_with_config(
            s,
            "localhost",
            cfg,
            Duration::from_secs(5),
        )
        .unwrap();
        use crate::net::Conn;
        tls.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let conn = crate::net::BufferedConn::from_boxed(Box::new(tls));
        let (reader, _writer) = crate::net::ws::split(conn, true).unwrap();
        let mut r = super::ws_carrier::reader_for_tests(reader);
        assert_loss(r.recv(), "tls");
        t.join().unwrap();
    }
}

#[cfg(feature = "tls")]
fn tls_http_server(answer_websocket: bool) -> SocketAddr {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/net/testdata");
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = ln.local_addr().unwrap();
    let cfg = Arc::new(
        crate::net::tls::server_config(
            &dir.join("localhost-cert.pem"),
            &dir.join("localhost-key.pem"),
        )
        .unwrap(),
    );
    std::thread::spawn(move || {
        for s in ln.incoming() {
            let Ok(s) = s else { return };
            let cfg = cfg.clone();
            std::thread::spawn(move || {
                let Ok(mut tls) =
                    crate::net::tls::TlsConn::accept_with_config(s, cfg, Duration::from_secs(5))
                else {
                    return;
                };
                use crate::net::Conn;
                let _ = tls.set_read_timeout(Some(Duration::from_secs(5)));
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match tls.read(&mut b) {
                        Ok(1) => head.push(b[0]),
                        _ => return,
                    }
                }
                let _ = answer_websocket;
                let _ = tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
                let _ = tls.flush();
                std::thread::sleep(Duration::from_millis(100));
            });
        }
    });
    addr
}

#[cfg(feature = "tls")]
#[test]
fn spec_ca_file_trusts_private_ca() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/net/testdata");
    let addr = tls_http_server(false);
    let url = Url::parse(&format!("https://localhost:{}", addr.port())).unwrap();
    let trusted = Client::new_with_tls(
        Duration::from_secs(2),
        Duration::from_secs(2),
        ClientTls {
            verify: true,
            ca_file: Some(dir.join("localhost-ca.pem")),
            allow_insecure_skip_verify: false,
        },
    );
    let resp = trusted
        .request(&url, "GET", "/", &[], None)
        .unwrap_or_else(|e| panic!("private CA not trusted: {e:?}"));
    assert_eq!(resp.status, 200);
    let missing = Client::new_with_tls(
        Duration::from_secs(2),
        Duration::from_secs(2),
        ClientTls {
            verify: true,
            ca_file: Some(dir.join("missing.pem")),
            allow_insecure_skip_verify: false,
        },
    );
    assert!(
        missing.request(&url, "GET", "/", &[], None).is_err(),
        "unreadable ca_file must fail closed"
    );
}

#[cfg(feature = "tls")]
#[test]
fn spec_dial_ws_session_tls_verify_failure_is_fatal() {
    let addr = tls_http_server(true);
    let url = format!("https://localhost:{}", addr.port());
    let e = match dial_session(&url, Duration::from_secs(2)) {
        Ok(_) => panic!("untrusted certificate accepted"),
        Err(e) => e,
    };
    assert!(
        is_protocol(&e) && e.code != wire::ERR_WS_HANDSHAKE_FAILED,
        "session dial with untrusted cert: {e:?}, want a protocol error"
    );
    let client = Client::new(Duration::from_secs(1), Duration::from_secs(1));
    let nonce = crate::util::random_hex(16).unwrap();
    let headers = vec![
        (wire::H_PEER_AUTH.to_string(), "Bearer tok".to_string()),
        (wire::H_INSTANCE_ID.to_string(), "bi".to_string()),
        (wire::H_WS_PURPOSE.to_string(), "check".to_string()),
        (wire::H_WS_NONCE.to_string(), nonce),
    ];
    let e = ws_carrier::precheck_via_node(
        &*client.dialer(),
        &Url::parse(&url).unwrap(),
        &headers,
        Duration::from_secs(2),
        Vec::new(),
        "B",
    )
    .unwrap_err();
    assert!(
        is_protocol(&e) && e.code != wire::ERR_WS_HANDSHAKE_FAILED,
        "precheck with untrusted cert: {e:?}"
    );
}

#[cfg(feature = "tls")]
fn ingress_config(
    dir: &std::path::Path,
    name: &str,
    tls: &str,
    hosts: [&str; 2],
) -> Arc<crate::config::Config> {
    std::fs::write(dir.join("token"), "test-token-0123456789abcdef012345").unwrap();
    let path = dir.join(name);
    std::fs::write(
        &path,
        format!(
            "node:\n  id: A\nlisteners:\n  - id: local\n    listen: \"127.0.0.1:0\"\n    peer: B\n    target: db\npeers:\n  - id: B\n    expected_node_id: B\n    credential_ref: B\n    token_file: token\n    tls: {tls}\n    endpoints:\n      - id: e1\n        url: \"https://{}\"\n      - id: e2\n        url: \"https://{}\"\n        priority: 2\n",
            hosts[0], hosts[1]
        ),
    )
    .unwrap();
    Arc::new(crate::config::load(&path).expect("ingress config"))
}

#[cfg(feature = "tls")]
#[test]
fn spec_insecure_tls_warns() {
    let dir = std::env::temp_dir().join(format!(
        "dbb-insecure-warn-{}",
        crate::util::random_hex(6).unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let mentions = |host: &str| {
        crate::slog::test_captured()
            .iter()
            .filter(|l| l.contains("verification is DISABLED") && l.contains(host))
            .count()
    };
    let secure = ingress_config(
        &dir,
        "secure.yaml",
        "{verify: true}",
        ["verified-peer.example:8443", "verified-backup.example"],
    );
    drop(crate::ingress::Ingress::new(secure));
    assert_eq!(
        mentions("verified-peer.example") + mentions("verified-backup.example"),
        0,
        "warned with verification on"
    );
    let insecure = ingress_config(
        &dir,
        "insecure.yaml",
        "{verify: false, allow_insecure_skip_verify: true}",
        ["insecure-peer.example:8443", "insecure-backup.example"],
    );
    drop(crate::ingress::Ingress::new(insecure));
    assert_eq!(mentions("insecure-peer.example:8443"), 1, "primary warning");
    assert_eq!(mentions("insecure-backup.example"), 1, "backup warning");
    assert!(crate::slog::test_captured()
        .iter()
        .filter(|l| l.contains("insecure-peer.example"))
        .all(|l| l.contains("WARN")));
    let _ = std::fs::remove_dir_all(&dir);
}
