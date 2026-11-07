use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use crate::error::Error;
use crate::net::http1::Client;
use crate::net::Url;
use crate::wire;

use super::ws_carrier;

/// One accepted precheck connection: the request head and the socket.
type Serve = dyn Fn(&str, &mut TcpStream) + Send + Sync;

/// A server that hands every connection's request head to `serve`.
pub(crate) fn ws_server(
    serve: impl Fn(&str, &mut TcpStream) + Send + Sync + 'static,
) -> SocketAddr {
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = ln.local_addr().unwrap();
    let serve: std::sync::Arc<Serve> = std::sync::Arc::new(serve);
    std::thread::spawn(move || {
        for c in ln.incoming() {
            let Ok(mut c) = c else { return };
            let serve = serve.clone();
            std::thread::spawn(move || {
                let _ = c.set_read_timeout(Some(Duration::from_secs(5)));
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match c.read(&mut b) {
                        Ok(1) => head.push(b[0]),
                        _ => return,
                    }
                }
                serve(&String::from_utf8_lossy(&head), &mut c);
            });
        }
    });
    addr
}

pub(crate) fn header_of<'a>(head: &'a str, name: &str) -> &'a str {
    head.lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
        })
        .unwrap_or("")
}

/// Writes a 101 answer (with or without the DBBridge subprotocol).
pub(crate) fn upgrade(head: &str, c: &mut TcpStream, subprotocol: bool) {
    let key = header_of(head, "sec-websocket-key");
    let mut resp = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n",
        crate::net::ws::accept_key(key)
    );
    if subprotocol {
        resp.push_str(&format!(
            "Sec-WebSocket-Protocol: {}\r\n",
            wire::WS_SUBPROTOCOL
        ));
    }
    resp.push_str("\r\n");
    let _ = c.write_all(resp.as_bytes());
}

/// An unmasked server frame.
pub(crate) fn frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0x80 | opcode];
    match payload.len() {
        n if n < 126 => f.push(n as u8),
        n if n <= u16::MAX as usize => {
            f.push(126);
            f.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            f.push(127);
            f.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    f.extend_from_slice(payload);
    f
}

pub(crate) fn hello(head: &str) -> String {
    hello_with(head, |_| {})
}

pub(crate) fn hello_with(
    head: &str,
    edit: impl FnOnce(&mut [(&'static str, String); 6]),
) -> String {
    let mut fields = [
        ("type", "hello".to_string()),
        ("protocol_version", wire::PROTOCOL_VERSION.to_string()),
        ("node_id", "B".to_string()),
        ("instance_id", "bi".to_string()),
        ("nonce", header_of(head, wire::H_WS_NONCE).to_string()),
        ("transport", "ws".to_string()),
    ];
    edit(&mut fields);
    let body = fields
        .iter()
        .map(|(k, v)| format!("\"{k}\":\"{v}\""))
        .collect::<Vec<_>>()
        .join(",");
    format!("{{{body}}}")
}

pub(crate) fn precheck(addr: SocketAddr, timeout: Duration) -> crate::error::Result<()> {
    let url = Url::parse(&format!("http://{addr}")).unwrap();
    let client = Client::new(Duration::from_secs(1), Duration::from_secs(1));
    let dialer = client.dialer();
    let nonce = crate::util::random_hex(16).unwrap();
    let headers = vec![
        (wire::H_PEER_AUTH.to_string(), "Bearer tok".to_string()),
        (wire::H_INSTANCE_ID.to_string(), "bi".to_string()),
        (wire::H_WS_PURPOSE.to_string(), "check".to_string()),
        (wire::H_WS_NONCE.to_string(), nonce),
    ];
    ws_carrier::precheck_via_node(&*dialer, &url, &headers, timeout, Vec::new(), "B")
}

fn is_rejected(e: &Error) -> bool {
    e.code == wire::ERR_WS_HANDSHAKE_FAILED
}

fn is_protocol(e: &Error) -> bool {
    e.code == wire::ERR_WS_PROTOCOL_ERROR
}

fn raw_status(status: u16, location: bool, body: &str) -> String {
    format!(
        "HTTP/1.1 {status} X\r\n{}Content-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        if location {
            "Location: https://sso.example.com/login\r\n"
        } else {
            ""
        },
        body.len()
    )
}

fn trusted_status(status: u16, code: &str) -> String {
    let body = format!(r#"{{"code":"{code}","message":"m","retryable":false}}"#);
    format!(
        "HTTP/1.1 {status} X\r\n{}: bi\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        wire::H_INSTANCE_ID,
        body.len()
    )
}

#[test]
fn spec_precheck_allowed_fallbacks_stay_upgrade_rejected() {
    let mut cases: Vec<(u16, bool)> = [400, 403, 404, 405, 426, 501, 200]
        .iter()
        .map(|s| (*s, false))
        .collect();
    cases.push((409, true));
    for s in [301, 302, 307, 308, 407, 410, 413, 414, 429, 431, 502] {
        cases.push((s, false));
    }
    for (status, trusted) in cases {
        let addr = ws_server(move |_, c| {
            let resp = if trusted {
                trusted_status(status, wire::ERR_TRANSPORT_UNSUPPORTED)
            } else {
                raw_status(status, status / 100 == 3, "<html>gateway</html>")
            };
            let _ = c.write_all(resp.as_bytes());
        });
        let e = precheck(addr, Duration::from_secs(2)).unwrap_err();
        if trusted {
            assert_eq!(e.code, wire::ERR_TRANSPORT_UNSUPPORTED, "{status}: {e:?}");
            assert!(e.trusted, "{status}: {e:?}");
            continue;
        }
        assert!(
            is_rejected(&e) && !is_protocol(&e),
            "{status}: {e:?}, want upgrade rejection only"
        );
        assert!(!e.trusted, "plain answer {status} must not be trusted");
        assert_eq!(e.remote_status, Some(status), "{status}");
        let want_transient = status == 429 || status >= 500;
        assert_eq!(
            ws_carrier::transient_upgrade_refusal(&e),
            want_transient,
            "status {status} transient"
        );
    }
}

#[test]
fn spec_precheck_raw_unauthorized_and_trusted_errors_are_not_upgrade_rejections() {
    for (status, trusted) in [(401, false), (401, true), (403, true), (429, true)] {
        let addr = ws_server(move |_, c| {
            let resp = if trusted {
                trusted_status(status, wire::ERR_UNAUTHORIZED)
            } else {
                // Same JSON body, but without the instance header.
                let body = format!(r#"{{"code":"{}"}}"#, wire::ERR_UNAUTHORIZED);
                format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
            };
            let _ = c.write_all(resp.as_bytes());
        });
        let e = precheck(addr, Duration::from_secs(2)).unwrap_err();
        assert_eq!(e.remote_status, Some(status), "{status}/{trusted}: {e:?}");
        assert_eq!(e.trusted, trusted, "{status}/{trusted}: {e:?}");
        assert!(
            !ws_carrier::transient_upgrade_refusal(&e),
            "{status}/{trusted}"
        );
        if trusted {
            assert_eq!(e.code, wire::ERR_UNAUTHORIZED);
        } else {
            assert!(e.message.contains("401"), "{e:?}");
        }
    }
}

#[test]
fn spec_precheck_illegal_frames_after_upgrade_are_protocol_errors() {
    for case in ["reserved opcode", "oversized hello"] {
        let addr = ws_server(move |head, c| {
            upgrade(head, c, true);
            if case == "reserved opcode" {
                let _ = c.write_all(&[0x83, 0x00]);
            } else {
                let msg = format!(r#"{{"type":"hello","pad":"{}"}}"#, "x".repeat(20 << 10));
                let _ = c.write_all(&frame(crate::net::ws::OP_TEXT, msg.as_bytes()));
            }
            let _ = c.read(&mut [0u8; 64]);
        });
        let e = precheck(addr, Duration::from_secs(2)).unwrap_err();
        assert!(
            is_protocol(&e) && !is_rejected(&e),
            "{case}: {e:?}, want protocol error only"
        );
    }
}

#[test]
fn spec_precheck_error_classification() {
    #[derive(Clone, Copy, PartialEq, Debug)]
    enum Want {
        Ok,
        Rejected,
        Fatal,
        Deadline,
    }
    type Send = fn(&str, &mut TcpStream);
    let cases: Vec<(&str, bool, Send, Want)> = vec![
        ("valid", true, |h, c| send_text(c, &hello(h)), Want::Ok),
        (
            "subprotocol stripped",
            false,
            |h, c| send_text(c, &hello(h)),
            Want::Fatal,
        ),
        (
            "binary hello",
            true,
            |_, c| {
                let _ = c.write_all(&frame(crate::net::ws::OP_BINARY, b"x"));
            },
            Want::Fatal,
        ),
        (
            "garbled hello",
            true,
            |_, c| send_text(c, "<html>"),
            Want::Fatal,
        ),
        (
            "wrong version",
            true,
            |h, c| send_text(c, &hello_with(h, |f| f[1].1 = "0.9".into())),
            Want::Fatal,
        ),
        (
            "closed after 101",
            true,
            |_, c| {
                let _ = c.shutdown(std::net::Shutdown::Both);
            },
            Want::Rejected,
        ),
        (
            "wrong nonce",
            true,
            |h, c| send_text(c, &hello_with(h, |f| f[4].1 = "forged".into())),
            Want::Fatal,
        ),
        (
            "wrong node",
            true,
            |h, c| send_text(c, &hello_with(h, |f| f[2].1 = "X".into())),
            Want::Fatal,
        ),
        (
            "wrong instance",
            true,
            |h, c| send_text(c, &hello_with(h, |f| f[3].1 = "other".into())),
            Want::Fatal,
        ),
        ("hello withheld", true, |_, _| {}, Want::Deadline),
    ];
    for (name, subprotocol, send, want) in cases {
        let addr = ws_server(move |head, c| {
            upgrade(head, c, subprotocol);
            send(head, c);
            let _ = c.set_read_timeout(Some(Duration::from_millis(800)));
            let _ = c.read(&mut [0u8; 64]);
        });
        let got = precheck(addr, Duration::from_millis(400));
        match want {
            Want::Ok => assert!(got.is_ok(), "{name}: {got:?}"),
            Want::Rejected => {
                let e = got.unwrap_err();
                assert!(is_rejected(&e) && !is_protocol(&e), "{name}: {e:?}");
            }
            Want::Fatal => {
                let e = got.unwrap_err();
                assert!(is_protocol(&e) && !is_rejected(&e), "{name}: {e:?}");
            }
            Want::Deadline => {
                let e = got.unwrap_err();
                assert!(
                    e.is_local() && e.retryable && !is_rejected(&e) && !is_protocol(&e),
                    "{name}: {e:?}, want an unclassified deadline error"
                );
            }
        }
    }
}

fn send_text(c: &mut TcpStream, s: &str) {
    let _ = c.write_all(&frame(crate::net::ws::OP_TEXT, s.as_bytes()));
}
