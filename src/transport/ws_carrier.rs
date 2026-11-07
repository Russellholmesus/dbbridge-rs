//! The WebSocket carrier: one connection per session, binary frames for data
//! and text frames for control.
//!
//! Both directions are plain blocking reads and writes on cloned socket
//! handles, so a slow write never blocks the read side and vice versa.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::net::ws::{self, Message, WsReader, WsWriter};
use crate::net::{http1, BufferedConn, Url};
use crate::resource::budget::BudgetLease;
use crate::wire::{self, Control, ControlKind};

use super::{CarrierReader, CarrierWriter, Incoming};

#[derive(Clone)]
pub struct WsCarrierWriter {
    inner: Arc<Mutex<WsWriter>>,
    close_sent: Arc<AtomicBool>,
    _connection_leases: Option<Arc<Vec<BudgetLease>>>,
}

impl WsCarrierWriter {
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.inner
            .lock()
            .map_err(|_| Error::local("websocket writer poisoned"))?
            .set_write_timeout(timeout)
            .map_err(|error| Error::local(format!("websocket write timeout: {error}")))
    }
}

impl CarrierWriter for WsCarrierWriter {
    fn send_data(&mut self, epoch: u64, offset: u64, payload: &[u8]) -> Result<Option<u64>> {
        let frame = wire::encode_ws_frame(epoch, offset, payload)?;
        let mut w = self
            .inner
            .lock()
            .map_err(|_| Error::local("websocket writer poisoned"))?;
        w.write_binary(&frame).map_err(|e| {
            Error::new(wire::ERR_BACKEND_LOST, format!("ws write: {e}")).closed(true)
        })?;
        Ok(None)
    }

    fn send_control(&mut self, c: &Control) -> Result<()> {
        let text = c.to_json().to_string();
        let mut w = self
            .inner
            .lock()
            .map_err(|_| Error::local("websocket writer poisoned"))?;
        w.write_text(&text)
            .map_err(|e| Error::new(wire::ERR_BACKEND_LOST, format!("ws write: {e}")).closed(true))
    }

    fn send_text(&mut self, text: &str) -> Result<()> {
        let mut w = self
            .inner
            .lock()
            .map_err(|_| Error::local("websocket writer poisoned"))?;
        w.write_text(text)
            .map_err(|e| Error::new(wire::ERR_BACKEND_LOST, format!("ws write: {e}")))
    }

    fn send_close(&mut self, code: u16, reason: &str) -> Result<()> {
        if self.close_sent.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let mut w = self
            .inner
            .lock()
            .map_err(|_| Error::local("websocket writer poisoned"))?;
        w.write_close(code, reason)
            .map_err(|e| Error::new(wire::ERR_BACKEND_LOST, format!("ws close: {e}")))
    }

    fn shutdown(&mut self) {
        if !self.close_sent.swap(true, Ordering::AcqRel) {
            if let Ok(mut w) = self.inner.lock() {
                let _ = w.write_close(1000, "");
            }
        }
    }
}

pub struct WsCarrierReader {
    inner: WsReader,
    _connection_leases: Option<Arc<Vec<BudgetLease>>>,
}

impl WsCarrierReader {
    pub fn set_read_deadline(&mut self, deadline: Option<Instant>) {
        self.inner.set_read_deadline(deadline);
    }

    pub fn set_message_limit(&mut self, limit: usize) {
        self.inner.set_message_limit(limit);
    }

    pub fn set_message_timeout(&mut self, timeout: Option<Duration>) {
        self.inner.set_message_timeout(timeout);
    }
}

impl CarrierReader for WsCarrierReader {
    fn interrupt_handle(&self) -> Option<Box<dyn crate::net::Conn>> {
        self.inner.try_clone_conn().ok()
    }

    fn recv(&mut self) -> Result<Incoming> {
        match self.inner.read_message() {
            Ok(None) => Ok(Incoming::Idle),
            Ok(Some(Message::Binary(b))) => {
                let frame = wire::decode_ws_frame(&b)?;
                Ok(Incoming::Data {
                    epoch: frame.epoch,
                    offset: frame.offset,
                    payload: frame.payload.to_vec(),
                })
            }
            Ok(Some(Message::Text(t))) => Ok(Incoming::Control(Control::parse(&t)?)),
            Ok(Some(Message::Close(code, reason))) => Ok(Incoming::Closed(Some(Error::local(
                format!("peer closed the carrier: {code} {reason}"),
            )))),
            Err(e) => {
                if e.is_local() && e.message.contains("websocket closed") {
                    return Ok(Incoming::Closed(None));
                }
                Err(e)
            }
        }
    }
}

pub struct WsAttach {
    pub reader: WsCarrierReader,
    pub writer: WsCarrierWriter,
    pub ready: Control,
    pub implicit_ready: bool,
}

/// Dials a session carrier while keeping the physical connection charges alive
/// for both split socket halves and every writer clone.
pub fn dial_session_via_with_leases(
    dialer: &dyn crate::net::http1::Dialer,
    url: &Url,
    headers: &[(String, String)],
    timeout: Duration,
    resource_leases: Vec<BudgetLease>,
) -> Result<WsAttach> {
    let stream = dialer.dial(url, timeout).map_err(|e| {
        if url.is_tls() && tls_verification_failure(&e) {
            Error::new(wire::ERR_TLS_FAILED, format!("dial: {e}"))
        } else {
            Error::new(wire::ERR_WS_HANDSHAKE_FAILED, format!("dial: {e}"))
        }
    })?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let mut conn = BufferedConn::from_boxed(stream);

    let (head, key) = ws::client_handshake_head(url, wire::PATH_WS, headers)?;
    conn.write_all(head.as_bytes())?;
    conn.flush()?;

    let (status, resp_headers) = http1::read_response_head(&mut conn)?;
    ws::verify_server_handshake(status, &resp_headers, &key)?;
    let implicit_ready = crate::net::header(&resp_headers, wire::H_IMPLICIT_READY)
        .map(|v| v.trim() == "1")
        .unwrap_or(false);

    let (mut reader, writer) = ws::split(conn, true)?;
    reader.set_message_limit(READY_MESSAGE_LIMIT);
    let ready = match reader.read_message()? {
        Some(Message::Text(t)) => Control::parse(&t)?,
        Some(_) => {
            return Err(Error::new(
                wire::ERR_WS_PROTOCOL_ERROR,
                "expected a text ready message",
            ))
        }
        None => {
            return Err(Error::new(
                wire::ERR_WS_HANDSHAKE_FAILED,
                "no ready message within the handshake timeout",
            ))
        }
    };
    if ready.kind != ControlKind::Ready {
        return Err(Error::new(
            wire::ERR_WS_PROTOCOL_ERROR,
            "first message was not ready",
        ));
    }
    reader.set_message_limit(usize::MAX);
    let connection_leases = (!resource_leases.is_empty()).then(|| Arc::new(resource_leases));
    // Socket options live on the socket, so the timeout set before splitting
    // applies to both halves. Liveness from here on comes from control
    // messages and backpressure, so reads poll rather than time out.
    Ok(WsAttach {
        reader: WsCarrierReader {
            inner: reader,
            _connection_leases: connection_leases.clone(),
        },
        writer: WsCarrierWriter {
            inner: writer,
            close_sent: Arc::new(AtomicBool::new(false)),
            _connection_leases: connection_leases,
        },
        ready,
        implicit_ready,
    })
}

const READY_MESSAGE_LIMIT: usize = 16 << 10;

/// Whether a dial failed in the TLS handshake itself (certificate, name or
/// protocol verification), as opposed to the TCP connect or a timeout.
pub(crate) fn tls_verification_failure(e: &Error) -> bool {
    let m = e.message.to_ascii_lowercase();
    m.contains("tls handshake:") && !m.contains("timed out")
}

#[cfg(test)]
pub(crate) fn reader_for_tests(inner: WsReader) -> WsCarrierReader {
    WsCarrierReader {
        inner,
        _connection_leases: None,
    }
}

#[cfg(test)]
pub(crate) fn writer_for_tests(inner: Arc<Mutex<WsWriter>>) -> WsCarrierWriter {
    WsCarrierWriter {
        inner,
        close_sent: Arc::new(AtomicBool::new(false)),
        _connection_leases: None,
    }
}

/// Checks whether a path can carry WebSocket, without creating a session.
/// The dialer is the caller's for the same reason as in `dial_session_via`:
/// a reverse peer's precheck travels inside its tunnel instead of trying to
/// resolve an endpoint host that never exists.
#[cfg(test)]
pub fn precheck_via(
    dialer: &dyn crate::net::http1::Dialer,
    url: &Url,
    headers: &[(String, String)],
    timeout: Duration,
) -> Result<()> {
    precheck_via_with_leases(dialer, url, headers, timeout, Vec::new())
}

/// Performs a short WebSocket precheck while holding the caller's physical
/// connection charges through the complete upgrade and hello exchange.
#[cfg(test)]
pub fn precheck_via_with_leases(
    dialer: &dyn crate::net::http1::Dialer,
    url: &Url,
    headers: &[(String, String)],
    timeout: Duration,
    resource_leases: Vec<BudgetLease>,
) -> Result<()> {
    precheck_via_node(dialer, url, headers, timeout, resource_leases, "")
}

const PRECHECK_HELLO_LIMIT: usize = 16 << 10;
/// The most of a refusal body read to look for a DBBridge error.
const PRECHECK_REFUSAL_BODY_LIMIT: usize = 64 << 10;

pub fn precheck_via_node(
    dialer: &dyn crate::net::http1::Dialer,
    url: &Url,
    headers: &[(String, String)],
    timeout: Duration,
    resource_leases: Vec<BudgetLease>,
    expected_node: &str,
) -> Result<()> {
    let _resource_leases = resource_leases;
    let deadline = Instant::now().checked_add(timeout);
    let stream = dialer.dial(url, timeout).map_err(|e| {
        let error = if url.is_tls() {
            Error::new(wire::ERR_TLS_FAILED, "TLS handshake failed")
        } else {
            Error::local(format!("precheck dial: {e}"))
        };
        mark_precheck_timeout(error, deadline)
    })?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let mut conn = BufferedConn::from_boxed(stream);
    conn.set_read_deadline(deadline);

    let (head, key) = ws::client_handshake_head(url, wire::PATH_WS, headers)?;
    conn.write_all(head.as_bytes())
        .map_err(|e| mark_precheck_timeout(upgrade_aborted(e.into()), deadline))?;
    conn.flush()
        .map_err(|e| mark_precheck_timeout(upgrade_aborted(e.into()), deadline))?;

    let (status, resp_headers) = http1::read_response_head(&mut conn)
        .map_err(|e| mark_precheck_timeout(upgrade_aborted(e), deadline))?;
    let expected_instance = crate::net::header(headers, wire::H_INSTANCE_ID).unwrap_or("");
    if status != 101 {
        return Err(precheck_refusal(
            &mut conn,
            status,
            &resp_headers,
            expected_instance,
        ));
    }
    ws::verify_server_handshake(status, &resp_headers, &key)?;
    let (mut reader, _writer) = ws::split(conn, true)?;
    reader.set_read_deadline(deadline);
    reader.set_message_limit(PRECHECK_HELLO_LIMIT);
    let message = match reader.read_message() {
        Ok(Some(message)) => message,
        Ok(None) => {
            return Err(Error::local("ws precheck: no hello before the deadline").retryable(true))
        }
        Err(e) if e.is_local() && e.message.contains("websocket closed") => {
            return Err(Error::new(
                wire::ERR_WS_HANDSHAKE_FAILED,
                "websocket upgrade rejected: closed after upgrade",
            ))
        }
        Err(e) => return Err(mark_precheck_timeout(e, deadline)),
    };
    let text = match message {
        Message::Text(t) => t,
        Message::Close(code, reason) => {
            return Err(Error::new(
                wire::ERR_WS_HANDSHAKE_FAILED,
                format!("websocket upgrade rejected: after upgrade: close {code} {reason}"),
            ))
        }
        Message::Binary(_) => {
            return Err(Error::new(
                wire::ERR_WS_PROTOCOL_ERROR,
                "ws precheck hello expected text message",
            ))
        }
    };
    let protocol = |what: String| Error::new(wire::ERR_WS_PROTOCOL_ERROR, what);
    let v = crate::util::json::parse(&text).map_err(|e| protocol(format!("hello: {e}")))?;
    let field = |name: &str| v.str_field(name).map(str::to_string).unwrap_or_default();
    if field("type") != "hello"
        || field("protocol_version") != wire::PROTOCOL_VERSION
        || field("transport") != "ws"
    {
        return Err(protocol("unexpected hello".to_string()));
    }
    let nonce = crate::net::header(headers, wire::H_WS_NONCE).unwrap_or("");
    if field("nonce") != nonce {
        return Err(protocol("ws precheck hello nonce mismatch".to_string()));
    }
    if !expected_node.is_empty() && field("node_id") != expected_node {
        return Err(protocol(format!(
            "node ID mismatch in hello: expected {expected_node:?}, got {:?}",
            field("node_id")
        )));
    }
    if !expected_instance.is_empty() && field("instance_id") != expected_instance {
        return Err(protocol(format!(
            "instance ID mismatch in hello: expected {expected_instance:?}, got {:?}",
            field("instance_id")
        )));
    }
    Ok(())
}

fn upgrade_aborted(error: Error) -> Error {
    let m = error.message.to_ascii_lowercase();
    if error.is_local()
        && (m.contains("reset")
            || m.contains("eof")
            || m.contains("connection closed")
            || m.contains("broken pipe"))
    {
        return Error::new(
            wire::ERR_WS_HANDSHAKE_FAILED,
            format!("websocket upgrade rejected: {}", error.message),
        );
    }
    error
}

fn precheck_refusal(
    conn: &mut BufferedConn,
    status: u16,
    resp_headers: &[(String, String)],
    expected_instance: &str,
) -> Error {
    let body = match http1::read_body(conn, status, resp_headers) {
        Ok((body, _)) if body.len() <= PRECHECK_REFUSAL_BODY_LIMIT => body,
        _ => Vec::new(),
    };
    let retry_after = crate::net::header(resp_headers, "Retry-After")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or_default();
    if let Some(parsed) = wire::ErrorBody::parse(&String::from_utf8_lossy(&body)) {
        let trusted = !expected_instance.is_empty()
            && parsed.code.starts_with("DBB_")
            && crate::net::header(resp_headers, wire::H_INSTANCE_ID) == Some(expected_instance);
        if trusted {
            return parsed
                .to_error()
                .remote_status(status)
                .trusted(true)
                .retry_after(retry_after);
        }
    }
    if status == 401 {
        // A raw 401 on the authenticated Upgrade: an authentication refusal,
        // never tolerated by falling back to SSE.
        return Error::new(
            wire::ERR_WS_HANDSHAKE_FAILED,
            "ws precheck refused: status 401",
        )
        .remote_status(401);
    }
    Error::new(
        wire::ERR_WS_HANDSHAKE_FAILED,
        format!("websocket upgrade rejected: status {status}"),
    )
    .remote_status(status)
}

#[cfg(test)]
pub fn transient_upgrade_refusal(error: &Error) -> bool {
    !error.trusted
        && error.code == wire::ERR_WS_HANDSHAKE_FAILED
        && matches!(error.remote_status, Some(408 | 425 | 429) | Some(500..=599))
}

fn mark_precheck_timeout(error: Error, deadline: Option<Instant>) -> Error {
    if error.is_local() && deadline.is_some_and(|at| Instant::now() >= at) {
        error.retryable(true)
    } else {
        error
    }
}

/// Server side: completes the upgrade and returns both halves. `headers` must
/// already carry `Sec-WebSocket-Accept` and the chosen subprotocol.
pub fn accept(
    conn: BufferedConn,
    headers: &[(String, String)],
) -> Result<(WsCarrierReader, WsCarrierWriter)> {
    let mut conn = conn;
    http1::write_upgrade(&mut conn, headers)?;
    let (reader, writer) = ws::split(conn, false)?;
    Ok((
        WsCarrierReader {
            inner: reader,
            _connection_leases: None,
        },
        WsCarrierWriter {
            inner: writer,
            close_sent: Arc::new(AtomicBool::new(false)),
            _connection_leases: None,
        },
    ))
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use crate::net::ws::{self, Message};
    use crate::net::BufferedConn;
    use crate::transport::{CarrierReader, CarrierWriter};

    use super::{WsCarrierReader, WsCarrierWriter};

    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (server, client)
    }

    fn server_frame(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![(if fin { 0x80 } else { 0 }) | opcode];
        match payload.len() {
            n if n < 126 => frame.push(n as u8),
            n if n <= u16::MAX as usize => {
                frame.push(126);
                frame.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                frame.push(127);
                frame.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn terminal_close_reason_is_sent_once() {
        let (server, client) = pair();
        client
            .set_read_timeout(Some(Duration::from_millis(30)))
            .unwrap();
        let (_server_reader, server_writer) = ws::split(BufferedConn::new(server), false).unwrap();
        let (mut client_reader, _client_writer) =
            ws::split(BufferedConn::new(client), true).unwrap();
        let mut carrier = WsCarrierWriter {
            inner: server_writer,
            close_sent: Arc::new(AtomicBool::new(false)),
            _connection_leases: None,
        };

        carrier.send_close(1000, "DBB_BACKEND_LOST").unwrap();
        carrier.shutdown();
        assert!(matches!(
            client_reader.read_message().unwrap(),
            Some(Message::Close(1000, reason)) if reason == "DBB_BACKEND_LOST"
        ));
        assert!(client_reader.read_message().unwrap().is_none());
    }

    #[test]
    fn outbound_connection_lease_lives_until_both_carrier_halves_drop() {
        let budget = crate::resource::budget::Budget::new(1);
        let leases = Arc::new(vec![budget.try_acquire(1).unwrap()]);
        let (server, client) = pair();
        let (reader, writer) = ws::split(BufferedConn::new(server), false).unwrap();
        let reader = WsCarrierReader {
            inner: reader,
            _connection_leases: Some(leases.clone()),
        };
        let writer = WsCarrierWriter {
            inner: writer,
            close_sent: Arc::new(AtomicBool::new(false)),
            _connection_leases: Some(leases.clone()),
        };
        let _client = client;
        drop(leases);
        let writer_clone = writer.clone();

        drop(writer);
        drop(reader);
        assert_eq!(budget.used(), 1);
        drop(writer_clone);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn spec_test_boundary_ws_message_read_honors_read_deadline() {
        let (mut server, client) = pair();
        let (reader, _client_writer) = ws::split(BufferedConn::new(client), true).unwrap();
        let mut carrier = super::WsCarrierReader {
            inner: reader,
            _connection_leases: None,
        };
        let payload = vec![b'x'; 8192];
        let message = crate::wire::encode_ws_frame(1, 0, &payload).unwrap();

        server
            .write_all(&server_frame(false, ws::OP_BINARY, &message[..5000]))
            .unwrap();
        carrier.set_read_deadline(Some(Instant::now() + Duration::from_millis(40)));
        assert!(matches!(
            carrier.recv().unwrap(),
            crate::transport::Incoming::Idle
        ));

        carrier.set_read_deadline(None);
        server
            .write_all(&server_frame(true, 0x0, &message[5000..]))
            .unwrap();
        match carrier.recv().unwrap() {
            crate::transport::Incoming::Data {
                epoch,
                offset,
                payload: got,
            } => {
                assert_eq!(epoch, 1);
                assert_eq!(offset, 0);
                assert_eq!(got, payload);
            }
            _ => panic!("expected the fragmented DATA message after the read deadline"),
        }
    }

    #[test]
    fn spec_test_boundary_small_frame_still_allows_text_controls() {
        let (server, client) = pair();
        let (_server_reader, server_writer) = ws::split(BufferedConn::new(server), false).unwrap();
        let (reader, _client_writer) = ws::split(BufferedConn::new(client), true).unwrap();
        let mut carrier = super::WsCarrierReader {
            inner: reader,
            _connection_leases: None,
        };
        // Egress keeps the control-message allowance at 16 KiB even when the
        // negotiated DATA payload limit is only 64 bytes.
        carrier.set_message_limit(16 * 1024);
        let mut ping =
            crate::wire::Control::base(crate::wire::ControlKind::Ping, "sid", "bi", 1, "stream");
        ping.nonce = Some("0123456789abcdef0123456789abcdef".to_string());
        let json = ping.to_json().to_string();
        assert!(json.len() > 64 + crate::wire::WS_HEADER_LEN);
        server_writer.lock().unwrap().write_text(&json).unwrap();

        match carrier.recv().unwrap() {
            crate::transport::Incoming::Control(control) => {
                assert_eq!(control.kind, crate::wire::ControlKind::Ping);
                assert_eq!(
                    control.nonce.as_deref(),
                    Some("0123456789abcdef0123456789abcdef")
                );
            }
            _ => panic!("expected text ping control with a small DATA frame limit"),
        }
    }

    #[test]
    fn spec_test_ws_shutdown_sends_normal_close_frame() {
        let (server, client) = pair();
        let (_server_reader, server_writer) = ws::split(BufferedConn::new(server), false).unwrap();
        client
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let (mut client_reader, _client_writer) =
            ws::split(BufferedConn::new(client), true).unwrap();
        let mut carrier = WsCarrierWriter {
            inner: server_writer,
            close_sent: Arc::new(AtomicBool::new(false)),
            _connection_leases: None,
        };

        carrier.shutdown();
        assert!(matches!(
            client_reader.read_message().unwrap(),
            Some(Message::Close(1000, reason)) if reason.is_empty()
        ));
        assert!(client_reader.read_message().unwrap().is_none());
    }
}
