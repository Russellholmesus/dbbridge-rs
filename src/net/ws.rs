//! WebSocket (RFC 6455): the opening handshake and binary/text framing.
//!
//! Only what the protocol needs: text and binary messages, close and ping
//! control frames, fragmentation on receive, and masking in the direction the
//! RFC requires (clients mask, servers do not).

use std::io;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::net::{BufferedConn, Conn, Url};
use crate::util::{base64, random_bytes, sha1};
use crate::wire::{ERR_WS_HANDSHAKE_FAILED, ERR_WS_PROTOCOL_ERROR, WS_SUBPROTOCOL};

const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_MESSAGE: usize = 2 << 20;

pub const OP_TEXT: u8 = 0x1;
pub const OP_BINARY: u8 = 0x2;
pub const OP_CLOSE: u8 = 0x8;
pub const OP_PING: u8 = 0x9;
pub const OP_PONG: u8 = 0xA;

/// `Sec-WebSocket-Accept` for a client key.
pub fn accept_key(key: &str) -> String {
    let mut data = key.trim().as_bytes().to_vec();
    data.extend_from_slice(GUID.as_bytes());
    base64::encode(&sha1::digest(&data))
}

/// Builds the client handshake request head.
pub fn client_handshake_head(
    url: &Url,
    path: &str,
    extra: &[(String, String)],
) -> Result<(String, String)> {
    client_handshake_head_proto(url, path, WS_SUBPROTOCOL, extra)
}

/// The same with an explicit subprotocol, for the reverse tunnel, which
/// negotiates `dbbridge.reverse.v1.5` rather than the session protocol.
pub fn client_handshake_head_proto(
    url: &Url,
    path: &str,
    subprotocol: &str,
    extra: &[(String, String)],
) -> Result<(String, String)> {
    let key = base64::encode(&random_bytes(16).map_err(crate::util::random_error)?);
    let mut head = format!("GET {} HTTP/1.1\r\n", url.path(path));
    head.push_str(&format!("Host: {}\r\n", url.authority()));
    head.push_str("Upgrade: websocket\r\n");
    head.push_str("Connection: Upgrade\r\n");
    head.push_str(&format!("Sec-WebSocket-Key: {key}\r\n"));
    head.push_str("Sec-WebSocket-Version: 13\r\n");
    head.push_str(&format!("Sec-WebSocket-Protocol: {subprotocol}\r\n"));
    let mut has_ua = false;
    for (k, v) in extra {
        if k.eq_ignore_ascii_case("host")
            || k.eq_ignore_ascii_case("upgrade")
            || k.eq_ignore_ascii_case("connection")
            || k.eq_ignore_ascii_case("sec-websocket-key")
            || k.eq_ignore_ascii_case("sec-websocket-version")
            || k.eq_ignore_ascii_case("sec-websocket-protocol")
            || k.eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        if k.eq_ignore_ascii_case("user-agent") {
            has_ua = true;
        }
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    if !has_ua {
        head.push_str(&format!("User-Agent: {}\r\n", crate::user_agent()));
    }
    head.push_str("\r\n");
    Ok((head, key))
}

/// Verifies a server's 101 response against the key we sent.
pub fn verify_server_handshake(status: u16, headers: &[(String, String)], key: &str) -> Result<()> {
    verify_server_handshake_proto(status, headers, key, WS_SUBPROTOCOL)
}

/// As `verify_server_handshake`, but the negotiated subprotocol is the
/// caller's: a reverse tunnel asks for `dbbridge.reverse.v1.5` instead of the
/// session protocol, and the server must echo exactly what was offered.
pub fn verify_server_handshake_proto(
    status: u16,
    headers: &[(String, String)],
    key: &str,
    expect: &str,
) -> Result<()> {
    if status != 101 {
        return Err(Error::new(
            ERR_WS_HANDSHAKE_FAILED,
            format!("expected 101, got {status}"),
        ));
    }
    let accept = crate::net::header(headers, "sec-websocket-accept")
        .ok_or_else(|| Error::new(ERR_WS_HANDSHAKE_FAILED, "missing Sec-WebSocket-Accept"))?;
    if accept.trim() != accept_key(key) {
        return Err(Error::new(
            ERR_WS_HANDSHAKE_FAILED,
            "Sec-WebSocket-Accept mismatch",
        ));
    }
    let proto = crate::net::header(headers, "sec-websocket-protocol").unwrap_or("");
    if proto != expect {
        return Err(Error::new(
            ERR_WS_PROTOCOL_ERROR,
            format!("unexpected subprotocol {proto:?}"),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub enum Message {
    Text(String),
    Binary(Vec<u8>),
    Close(u16, String),
}

/// The write half: a cloned connection handle, so reads and writes never
/// contend. The handle is a `Conn` rather than a socket so the same framing
/// works over a tunnel stream.
pub struct WsWriter {
    stream: Box<dyn Conn>,
    mask: bool,
    pending_pongs: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl WsWriter {
    pub fn new(stream: Box<dyn Conn>, mask: bool) -> Self {
        WsWriter {
            stream,
            mask,
            pending_pongs: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.stream.set_write_timeout(timeout)
    }

    fn write_frame(&mut self, opcode: u8, payload: &[u8]) -> io::Result<()> {
        self.flush_pending_pongs()?;
        self.write_frame_raw(opcode, payload)
    }

    fn write_frame_raw(&mut self, opcode: u8, payload: &[u8]) -> io::Result<()> {
        use std::io::Write;
        let mut head = Vec::with_capacity(14);
        head.push(0x80 | opcode);
        let mask_bit = if self.mask { 0x80 } else { 0x00 };
        match payload.len() {
            n if n < 126 => head.push(mask_bit | n as u8),
            n if n <= 0xffff => {
                head.push(mask_bit | 126);
                head.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                head.push(mask_bit | 127);
                head.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        let mut masked;
        let body: &[u8] = if self.mask {
            let key = random_bytes(4)?;
            head.extend_from_slice(&key);
            masked = Vec::with_capacity(payload.len());
            for (i, b) in payload.iter().enumerate() {
                masked.push(b ^ key[i & 3]);
            }
            &masked
        } else {
            payload
        };
        self.stream.write_all(&head)?;
        if !body.is_empty() {
            self.stream.write_all(body)?;
        }
        self.stream.flush()
    }

    pub fn write_text(&mut self, s: &str) -> io::Result<()> {
        self.write_frame(OP_TEXT, s.as_bytes())
    }

    pub fn write_binary(&mut self, b: &[u8]) -> io::Result<()> {
        self.write_frame(OP_BINARY, b)
    }

    pub fn write_close(&mut self, code: u16, reason: &str) -> io::Result<()> {
        let mut payload = Vec::with_capacity(2 + reason.len());
        payload.extend_from_slice(&code.to_be_bytes());
        payload.extend_from_slice(reason.as_bytes());
        self.write_frame(OP_CLOSE, &payload)
    }

    fn flush_pending_pongs(&mut self) -> io::Result<()> {
        let pending = {
            let mut p = self
                .pending_pongs
                .lock()
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "pong queue poisoned"))?;
            std::mem::take(&mut *p)
        };
        for payload in pending {
            self.write_frame_raw(OP_PONG, &payload)?;
        }
        Ok(())
    }

    fn queue_pong(&self, payload: Vec<u8>) {
        if let Ok(mut p) = self.pending_pongs.lock() {
            p.push(payload);
        }
    }
}

/// The read half. Auto-answers pings through the shared writer, because the
/// reader thread is the only place a ping is noticed.
pub struct WsReader {
    conn: BufferedConn,
    writer: Arc<Mutex<WsWriter>>,
    pending_pongs: Arc<Mutex<Vec<Vec<u8>>>>,
    expect_mask: bool,
    frag_opcode: Option<u8>,
    frag: Vec<u8>,
    max_message: usize,
    /// The caller's absolute read deadline (restored between messages).
    base_deadline: Option<Instant>,
    message_timeout: Option<Duration>,
    message_deadline: Option<Instant>,
}

impl WsReader {
    pub fn new(conn: BufferedConn, writer: Arc<Mutex<WsWriter>>) -> Self {
        let (expect_mask, pending_pongs) = writer
            .lock()
            .map(|w| (!w.mask, w.pending_pongs.clone()))
            .unwrap_or((false, Arc::new(Mutex::new(Vec::new()))));
        WsReader {
            conn,
            writer,
            pending_pongs,
            expect_mask,
            frag_opcode: None,
            frag: Vec::new(),
            max_message: MAX_MESSAGE,
            base_deadline: None,
            message_timeout: None,
            message_deadline: None,
        }
    }

    /// A second handle on the connection (see
    /// `CarrierReader::interrupt_handle`).
    pub fn try_clone_conn(&self) -> std::io::Result<Box<dyn crate::net::Conn>> {
        self.conn.try_clone()
    }

    pub fn set_read_deadline(&mut self, deadline: Option<Instant>) {
        self.base_deadline = deadline;
        self.apply_deadline();
    }

    pub fn set_message_timeout(&mut self, timeout: Option<Duration>) {
        self.message_timeout = timeout.filter(|t| !t.is_zero());
    }

    fn apply_deadline(&mut self) {
        let d = match (self.base_deadline, self.message_deadline) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        self.conn.set_read_deadline(d);
    }

    /// Starts the message timer when part of a message is buffered.
    fn arm_message_timer(&mut self) {
        if let Some(t) = self.message_timeout {
            if self.message_deadline.is_none()
                && (!self.conn.buffered().is_empty() || self.frag_opcode.is_some())
            {
                self.message_deadline = Some(Instant::now() + t);
                self.apply_deadline();
            }
        }
    }

    fn disarm_message_timer(&mut self) {
        if self.message_deadline.take().is_some() {
            self.apply_deadline();
            // The absolute deadline left a short socket timeout behind; poll
            // at a sane interval again.
            if let Some(t) = self.message_timeout {
                let _ = self
                    .conn
                    .set_read_timeout(Some(t.min(Duration::from_secs(1))));
            }
        }
    }

    /// A control frame between messages does not start the message timer.
    fn control_frame_done(&mut self) {
        if self.frag_opcode.is_none() && self.conn.buffered().is_empty() {
            self.disarm_message_timer();
        }
    }

    fn message_timer_expired(&self) -> bool {
        self.message_deadline.is_some_and(|d| Instant::now() >= d)
    }

    pub fn set_message_limit(&mut self, limit: usize) {
        self.max_message = limit.clamp(1, MAX_MESSAGE);
    }

    /// Reads one whole message. Returns `Ok(None)` when the read timed out
    /// before a complete frame arrived, so a reader loop can check for
    /// shutdown without losing partial data.
    pub fn read_message(&mut self) -> Result<Option<Message>> {
        let r = self.read_message_inner();
        match &r {
            Ok(Some(_)) => self.disarm_message_timer(),
            Ok(None) if self.message_timer_expired() => {
                return Err(Error::local("websocket message body timeout"));
            }
            _ => {}
        }
        r
    }

    fn read_message_inner(&mut self) -> Result<Option<Message>> {
        loop {
            if self.message_timer_expired() {
                return Ok(None);
            }
            let (fin, opcode, payload) = match self.read_frame()? {
                Some(f) => f,
                None => return Ok(None),
            };
            match opcode {
                OP_CLOSE => {
                    if payload.len() == 1 {
                        return Err(Error::new(
                            ERR_WS_PROTOCOL_ERROR,
                            "close payload has one byte",
                        ));
                    }
                    let code = if payload.len() >= 2 {
                        u16::from_be_bytes([payload[0], payload[1]])
                    } else {
                        1005
                    };
                    let reason = if payload.len() > 2 {
                        String::from_utf8_lossy(&payload[2..]).into_owned()
                    } else {
                        String::new()
                    };
                    return Ok(Some(Message::Close(code, reason)));
                }
                OP_PING => {
                    if let Ok(w) = self.writer.try_lock() {
                        w.queue_pong(payload);
                    } else if let Ok(mut p) = self.pending_pongs.lock() {
                        p.push(payload);
                    }
                    self.control_frame_done();
                    continue;
                }
                OP_PONG => {
                    self.control_frame_done();
                    continue;
                }
                OP_TEXT | OP_BINARY => {
                    if self.frag_opcode.is_some() {
                        return Err(Error::new(
                            ERR_WS_PROTOCOL_ERROR,
                            "new data frame inside fragment",
                        ));
                    }
                    if fin {
                        return Ok(Some(finish(opcode, payload)?));
                    }
                    self.frag_opcode = Some(opcode);
                    self.frag = payload;
                }
                0x0 => {
                    if self.frag_opcode.is_none() {
                        return Err(Error::new(
                            ERR_WS_PROTOCOL_ERROR,
                            "continuation frame without a start",
                        ));
                    }
                    self.frag.extend_from_slice(&payload);
                    if self.frag.len() > self.max_message {
                        return Err(Error::new(ERR_WS_PROTOCOL_ERROR, "message too large"));
                    }
                    if fin {
                        let op = self.frag_opcode.take().expect("checked above");
                        let payload = std::mem::take(&mut self.frag);
                        return Ok(Some(finish(op, payload)?));
                    }
                }
                other => {
                    return Err(Error::new(
                        ERR_WS_PROTOCOL_ERROR,
                        format!("unsupported opcode 0x{other:02x}"),
                    ))
                }
            }
        }
    }

    fn read_frame(&mut self) -> Result<Option<(bool, u8, Vec<u8>)>> {
        // The whole frame is buffered before anything is consumed, so a read
        // timeout in the middle of a frame resumes exactly where it stopped.
        if self.conn.buffered().len() < 2 {
            match self.fill_to(2) {
                Ok(true) => {}
                Ok(false) => return Ok(None),
                Err(e) => return Err(e.into()),
            }
        }
        let head = self.conn.buffered();
        let fin = head[0] & 0x80 != 0;
        if head[0] & 0x70 != 0 {
            return Err(Error::new(ERR_WS_PROTOCOL_ERROR, "reserved bits set"));
        }
        let opcode = head[0] & 0x0f;
        let masked = head[1] & 0x80 != 0;
        if masked != self.expect_mask {
            return Err(Error::new(
                ERR_WS_PROTOCOL_ERROR,
                "invalid WebSocket mask direction",
            ));
        }
        let len7 = (head[1] & 0x7f) as usize;
        if opcode >= 0x8 && (!fin || len7 > 125) {
            return Err(Error::new(ERR_WS_PROTOCOL_ERROR, "invalid control frame"));
        }
        let mut need = 2;
        let payload_len = match len7 {
            126 => {
                need += 2;
                if self.conn.buffered().len() < need && !self.fill_to(need)? {
                    return Ok(None);
                }
                let b = self.conn.buffered();
                u16::from_be_bytes([b[2], b[3]]) as usize
            }
            127 => {
                need += 8;
                if self.conn.buffered().len() < need && !self.fill_to(need)? {
                    return Ok(None);
                }
                let b = self.conn.buffered();
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&b[2..10]);
                let v = u64::from_be_bytes(arr);
                if v > self.max_message as u64 {
                    return Err(Error::new(ERR_WS_PROTOCOL_ERROR, "frame too large"));
                }
                v as usize
            }
            n => n,
        };
        if payload_len > self.max_message {
            return Err(Error::new(ERR_WS_PROTOCOL_ERROR, "frame too large"));
        }
        if masked {
            need += 4;
        }
        need += payload_len;
        if need > self.max_message.saturating_add(14) {
            return Err(Error::new(ERR_WS_PROTOCOL_ERROR, "frame too large"));
        }
        if self.conn.buffered().len() < need && !self.fill_to(need)? {
            return Ok(None);
        }
        let buf = self.conn.buffered();
        let mut pos = if len7 == 126 {
            4
        } else if len7 == 127 {
            10
        } else {
            2
        };
        let mask_key = if masked {
            let k = [buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]];
            pos += 4;
            Some(k)
        } else {
            None
        };
        let mut payload = buf[pos..pos + payload_len].to_vec();
        if let Some(k) = mask_key {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= k[i & 3];
            }
        }
        self.conn.consume(need);
        Ok(Some((fin, opcode, payload)))
    }

    /// Ensures at least `n` buffered bytes. `Ok(false)` means the socket
    /// timed out first; the buffer is left intact.
    fn fill_to(&mut self, n: usize) -> io::Result<bool> {
        while self.conn.buffered().len() < n {
            self.arm_message_timer();
            match self.conn.fill() {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "websocket closed",
                    ))
                }
                Ok(_) => {}
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    return Ok(false)
                }
                Err(e) => return Err(e),
            }
        }
        Ok(true)
    }
}

fn finish(opcode: u8, payload: Vec<u8>) -> Result<Message> {
    if opcode == OP_BINARY {
        Ok(Message::Binary(payload))
    } else {
        String::from_utf8(payload)
            .map(Message::Text)
            .map_err(|_| Error::new(ERR_WS_PROTOCOL_ERROR, "invalid UTF-8 in text frame"))
    }
}

/// Splits a connection into a reader and a writer that share one socket.
pub fn split(conn: BufferedConn, mask: bool) -> Result<(WsReader, Arc<Mutex<WsWriter>>)> {
    let stream = conn.try_clone()?;
    let writer = Arc::new(Mutex::new(WsWriter::new(stream, mask)));
    Ok((WsReader::new(conn, writer.clone()), writer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::time::Duration;

    fn test_pair() -> (WsReader, TcpStream) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        server
            .set_read_timeout(Some(Duration::from_millis(30)))
            .unwrap();
        let (reader, _) = split(BufferedConn::new(server), false).unwrap();
        (reader, peer)
    }

    fn frame(fin: bool, opcode: u8, payload: &[u8], masked: bool) -> Vec<u8> {
        let mut out = vec![(if fin { 0x80 } else { 0 }) | opcode];
        let mask_bit = if masked { 0x80 } else { 0 };
        match payload.len() {
            n if n < 126 => out.push(mask_bit | n as u8),
            n if n <= 0xffff => {
                out.push(mask_bit | 126);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                out.push(mask_bit | 127);
                out.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        if masked {
            let key = [1, 2, 3, 4];
            out.extend_from_slice(&key);
            out.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i & 3]));
        } else {
            out.extend_from_slice(payload);
        }
        out
    }

    struct FuzzConn {
        input: Cursor<Vec<u8>>,
        output: Arc<Mutex<Vec<u8>>>,
    }

    impl FuzzConn {
        fn new(input: Vec<u8>, output: Arc<Mutex<Vec<u8>>>) -> Self {
            FuzzConn {
                input: Cursor::new(input),
                output,
            }
        }
    }

    impl Read for FuzzConn {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for FuzzConn {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.output.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl crate::net::Conn for FuzzConn {
        fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
            Ok(())
        }

        fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
            Ok(())
        }

        fn try_clone(&self) -> io::Result<Box<dyn crate::net::Conn>> {
            Err(io::Error::other("fuzz connection is not cloneable"))
        }

        fn shutdown_write(&self) -> io::Result<()> {
            Ok(())
        }

        fn shutdown_both(&self) -> io::Result<()> {
            Ok(())
        }

        fn describe(&self) -> String {
            "fuzz-memory".to_string()
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

    fn run_ws_fuzz(iterations: usize) {
        let mut rng = FuzzRng(0xc9a4_52ef_137b_608d);
        for iteration in 0..iterations {
            let payload = rng.bytes(96);
            let raw = match iteration % 4 {
                0 => rng.bytes(192),
                1 => frame(true, (rng.next() & 0x0f) as u8, &payload, true),
                2 => frame(
                    rng.next() & 1 != 0,
                    (rng.next() & 0x0f) as u8,
                    &payload,
                    rng.next() & 1 != 0,
                ),
                _ => {
                    let mut input = frame(true, OP_PING, &payload[..payload.len().min(125)], true);
                    input.extend_from_slice(&frame(true, OP_BINARY, &rng.bytes(64), true));
                    input
                }
            };
            assert!(raw.len() <= 224, "fuzz input must stay bounded");
            let output = Arc::new(Mutex::new(Vec::new()));
            let writer = Arc::new(Mutex::new(WsWriter::new(
                Box::new(FuzzConn::new(Vec::new(), output.clone())),
                false,
            )));
            let conn = BufferedConn::new(FuzzConn::new(raw, output));
            let mut reader = WsReader::new(conn, writer);
            reader.set_message_limit(128);
            let _ = reader.read_message();
        }
    }

    #[test]
    fn fuzz_websocket_frames() {
        run_ws_fuzz(100_000);
    }

    #[test]
    #[ignore = "one-million iteration parser fuzz run"]
    fn fuzz_websocket_frames_long() {
        run_ws_fuzz(1_000_000);
    }

    #[test]
    fn accept_matches_rfc_example() {
        // RFC 6455 §1.3.
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn ping_between_fragments_keeps_message() {
        let (mut reader, mut peer) = test_pair();
        peer.write_all(&frame(false, OP_TEXT, b"hel", true))
            .unwrap();
        peer.write_all(&frame(true, OP_PING, b"p", true)).unwrap();
        peer.write_all(&frame(true, 0, b"lo", true)).unwrap();
        assert!(matches!(reader.read_message().unwrap(), Some(Message::Text(s)) if s == "hello"));
    }

    #[test]
    fn timeout_between_fragments_keeps_message() {
        let (mut reader, mut peer) = test_pair();
        peer.write_all(&frame(false, OP_BINARY, b"left", true))
            .unwrap();
        assert!(reader.read_message().unwrap().is_none());
        peer.write_all(&frame(true, 0, b"right", true)).unwrap();
        assert!(
            matches!(reader.read_message().unwrap(), Some(Message::Binary(b)) if b == b"leftright")
        );
    }

    #[test]
    fn configured_message_limit_rejects_single_and_fragmented_messages() {
        let (mut reader, mut peer) = test_pair();
        reader.set_message_limit(2);
        peer.write_all(&frame(true, OP_BINARY, b"abc", true))
            .unwrap();
        assert_eq!(
            reader.read_message().unwrap_err().code,
            ERR_WS_PROTOCOL_ERROR
        );

        let (mut reader, mut peer) = test_pair();
        reader.set_message_limit(2);
        peer.write_all(&frame(false, OP_BINARY, b"ab", true))
            .unwrap();
        peer.write_all(&frame(true, 0, b"c", true)).unwrap();
        assert_eq!(
            reader.read_message().unwrap_err().code,
            ERR_WS_PROTOCOL_ERROR
        );
    }

    #[test]
    fn control_frame_over_125_is_protocol_error() {
        let (mut reader, mut peer) = test_pair();
        peer.write_all(&frame(true, OP_PING, &[0; 126], true))
            .unwrap();
        let err = reader.read_message().unwrap_err();
        assert_eq!(err.code, ERR_WS_PROTOCOL_ERROR);
    }

    #[test]
    fn unmasked_client_frame_rejected_by_server() {
        let (mut reader, mut peer) = test_pair();
        peer.write_all(&frame(true, OP_BINARY, b"x", false))
            .unwrap();
        let err = reader.read_message().unwrap_err();
        assert_eq!(err.code, ERR_WS_PROTOCOL_ERROR);
    }

    #[test]
    fn new_data_frame_inside_fragment_rejected() {
        let (mut reader, mut peer) = test_pair();
        peer.write_all(&frame(false, OP_TEXT, b"a", true)).unwrap();
        peer.write_all(&frame(true, OP_BINARY, b"b", true)).unwrap();
        let err = reader.read_message().unwrap_err();
        assert_eq!(err.code, ERR_WS_PROTOCOL_ERROR);
    }
}
