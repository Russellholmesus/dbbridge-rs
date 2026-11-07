//! The `http-sse` carrier: upstream frames travel as individual POSTs, the
//! downstream as a Server-Sent Events stream.
//!
//! This is the fallback for paths that cannot carry a WebSocket — a proxy that
//! strips `Upgrade`, a gateway that answers `405`, an HTTP/1.1 load balancer.
//! It costs one connection per event stream and one request per frame, which
//! is why `ws` is preferred whenever it works.

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::error::{Error, Result};
use crate::net::http1::Client;
use crate::net::{http1, BufferedConn, Url};
use crate::wire::{self, Control, ControlKind};

use super::control;
use super::{CarrierReader, CarrierWriter, Incoming};

/// Writes SSE events onto an open response body (egress side).
pub struct SseEventSink {
    conn: BufferedConn,
    idle_timeout: std::time::Duration,
}

impl SseEventSink {
    pub fn new(conn: BufferedConn, idle_timeout: std::time::Duration) -> Self {
        SseEventSink { conn, idle_timeout }
    }

    /// Writes the response head. Called once, before the first event.
    pub fn write_head(&mut self, instance_id: &str) -> Result<()> {
        let headers = vec![
            (
                "Content-Type".to_string(),
                "text/event-stream; charset=utf-8".to_string(),
            ),
            (
                "Cache-Control".to_string(),
                "no-store, no-transform".to_string(),
            ),
            ("X-Accel-Buffering".to_string(), "no".to_string()),
            (wire::H_IMPLICIT_READY.to_string(), "1".to_string()),
            (wire::H_INSTANCE_ID.to_string(), instance_id.to_string()),
        ];
        http1::write_stream_head(&mut self.conn, 200, &headers)?;
        Ok(())
    }

    pub(crate) fn write_raw(&mut self, bytes: &[u8]) -> Result<()> {
        let idle = self.idle_timeout;
        super::sse_progress::write_sse_progress(self, bytes, idle)
    }

    fn event(&mut self, kind: &str, data: &str, id: Option<&str>) -> Result<()> {
        let mut buf = Vec::with_capacity(data.len() + 64);
        if let Some(id) = id {
            let _ = writeln!(buf, "id: {id}");
        }
        let _ = write!(buf, "event: {kind}\ndata: {data}\n\n");
        self.write_raw(&buf)
    }
}

impl super::sse_progress::SsePieceSink for SseEventSink {
    fn arm_idle_deadline(&mut self, idle: std::time::Duration) -> Result<()> {
        self.conn.set_write_timeout(Some(idle))?;
        Ok(())
    }

    fn write_piece(&mut self, piece: &[u8]) -> Result<()> {
        self.conn.write_all(piece)?;
        Ok(())
    }

    fn flush_piece(&mut self) -> Result<()> {
        self.conn.flush()?;
        Ok(())
    }
}

impl CarrierWriter for SseEventSink {
    fn send_data(&mut self, epoch: u64, offset: u64, payload: &[u8]) -> Result<Option<u64>> {
        let body = wire::format_sse_data(offset, payload)?;
        let id = format!("{epoch}:{}", offset + payload.len() as u64);
        self.event("data", &body, Some(&id))?;
        Ok(None)
    }

    fn send_control(&mut self, c: &Control) -> Result<()> {
        let data = c.to_json().to_string();
        self.event(c.kind.as_str(), &data, None)
    }

    fn shutdown(&mut self) {
        let _ = self.conn.shutdown_write();
    }
}

/// Sends upstream frames as POSTs (ingress side).
pub struct SseUpPoster {
    client: Arc<Client>,
    url: Url,
    sid: String,
    /// Peer credentials, sent as the bearer on every POST.
    peer_token: Option<control::TokenProvider>,
    /// Session credentials, sent in `X-DBB-Session-Token`.
    session_token: String,
    instance: String,
    epoch: u64,
    stream: String,
    down_ack: Arc<AtomicU64>,
    up_confirm: Arc<AtomicU64>,
}

impl SseUpPoster {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client: Arc<Client>,
        url: Url,
        sid: String,
        peer_token: Option<control::TokenProvider>,
        session_token: String,
        instance: String,
        epoch: u64,
        stream: String,
        down_ack: Arc<AtomicU64>,
        up_confirm: Arc<AtomicU64>,
    ) -> Self {
        SseUpPoster {
            client,
            url,
            sid,
            peer_token,
            session_token,
            instance,
            epoch,
            stream,
            down_ack,
            up_confirm,
        }
    }
}

impl CarrierWriter for SseUpPoster {
    fn send_data(&mut self, _epoch: u64, offset: u64, payload: &[u8]) -> Result<Option<u64>> {
        let down = self.down_ack.load(Ordering::Relaxed);
        let confirm = self.up_confirm.load(Ordering::Relaxed);
        let peer_token = match &self.peer_token {
            Some(provider) => provider()?,
            None => {
                return Err(Error::new(
                    crate::config::CODE_CREDENTIAL,
                    "missing outbound credential",
                ))
            }
        };
        let (status, body) = control::post_up(
            &self.client,
            &self.url,
            &self.sid,
            &peer_token,
            &self.session_token,
            &self.instance,
            self.epoch,
            &self.stream,
            offset,
            payload,
            down,
            confirm,
        )?;
        if status != 200 && status != 202 {
            if let Some(e) = wire::ErrorBody::parse(&String::from_utf8_lossy(&body)) {
                return Err(e.to_error());
            }
            return Err(Error::local(format!("/up answered {status}")));
        }
        control::check_up_binding(&body, &self.sid, &self.instance, self.epoch, &self.stream)?;
        let ack = control::parse_up_response(&body)?;
        self.up_confirm.store(ack, Ordering::Relaxed);
        Ok(Some(ack))
    }

    fn send_control(&mut self, _c: &Control) -> Result<()> {
        // Control travels on its own HTTP requests (/ack, /fin), never on the
        // event stream, so there is nothing to do here.
        Ok(())
    }

    fn shutdown(&mut self) {}
}

/// Reads the downstream event stream (ingress side).
pub struct SseEventReader {
    body: http1::BodyReader,
    /// Longest single line this reader will accept.
    line_limit: usize,
    /// Epoch is bound to the generation whose ready event opened this stream.
    epoch: u64,
    /// The event being parsed. `recv` may return `Idle` mid-event and must
    /// resume the same event on the next call.
    partial: SseParse,
    /// The previous line ended with a CR (a following LF belongs to it).
    skip_lf: bool,
    /// When the reader last handed control back to its caller; a stream of
    /// comments still returns `Idle` at least this often.
    returned_at: std::time::Instant,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct SseEvent {
    pub(crate) event: String,
    pub(crate) id: String,
    pub(crate) data: String,
}

/// Fields of the event being parsed.
#[derive(Default)]
struct SseParse {
    ev: SseEvent,
    seen_event: bool,
    seen_id: bool,
    seen_data: bool,
    /// Field bytes of this event so far, and its field-line count.
    total: usize,
    lines: usize,
}

/// One step of the event-stream parser.
pub(crate) enum SseStep {
    Event(SseEvent),
    /// A read timed out; the partial event is kept.
    Idle,
    /// The stream ended between events.
    Eof,
}

/// A comment-only stream hands control back to the carrier's caller at least
/// this often, so liveness checks run although bytes keep arriving.
const COMMENT_IDLE_EVERY: std::time::Duration = std::time::Duration::from_millis(25);

const SSE_MAX_LINES: usize = 64;

fn sse_protocol(message: impl Into<String>) -> Error {
    Error::new(wire::ERR_BAD_FRAME, message)
}

pub fn sse_line_limit(max_frame_size: usize) -> usize {
    max_frame_size
        .saturating_mul(4)
        .saturating_div(3)
        .saturating_add(4096)
        .max(16 * 1024)
}

const SSE_CONTROL_EVENT_LIMIT: usize = 16 * 1024 + 4096;

impl SseEventReader {
    pub fn new(body: http1::BodyReader, max_frame_size: usize, epoch: u64) -> Self {
        SseEventReader {
            body,
            line_limit: sse_line_limit(max_frame_size),
            epoch,
            partial: SseParse::default(),
            skip_lf: false,
            returned_at: std::time::Instant::now(),
        }
    }

    #[cfg(test)]
    pub(crate) fn next_event(&mut self) -> Result<SseStep> {
        self.next_event_or_comment(false)
    }

    /// Like `next_event`; with `idle_on_comment` a comment line returns
    /// `Idle` instead of being skipped silently.
    fn next_event_or_comment(&mut self, idle_on_comment: bool) -> Result<SseStep> {
        let limit = self.line_limit;
        let small = SSE_CONTROL_EVENT_LIMIT.min(limit);
        loop {
            let line = match self.body.read_sse_line(limit, &mut self.skip_lf) {
                Ok(l) => l,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    return Ok(SseStep::Idle)
                }
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(SseStep::Eof),
                Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                    return Err(sse_protocol(format!(
                        "sse line exceeds {limit} bytes before its terminator"
                    )))
                }
                Err(e) => return Err(Error::local(format!("sse read: {e}"))),
            };
            if line.is_empty() {
                let p = std::mem::take(&mut self.partial);
                if !p.seen_data {
                    continue; // keep-alive, stray blank line, or no data
                }
                if !p.seen_event {
                    return Err(sse_protocol("sse event without an event field"));
                }
                return Ok(SseStep::Event(p.ev));
            }
            if line[0] == b':' {
                if idle_on_comment && self.returned_at.elapsed() >= COMMENT_IDLE_EVERY {
                    self.returned_at = std::time::Instant::now();
                    return Ok(SseStep::Idle);
                }
                continue;
            }
            let p = &mut self.partial;
            p.lines += 1;
            let text = match String::from_utf8(line) {
                Ok(t) if p.lines <= SSE_MAX_LINES => t,
                Ok(_) => return Err(sse_protocol("sse event has too many lines")),
                Err(_) => return Err(sse_protocol("sse line is not UTF-8")),
            };
            let (key, value) = match text.split_once(':') {
                Some((k, v)) => (k, v.strip_prefix(' ').unwrap_or(v)),
                None => (text.as_str(), ""),
            };
            p.total += text.len() + 1;
            let data_event = p.ev.event == "data" || (!p.seen_event && key == "data");
            let cap = if data_event { limit } else { small };
            if p.total > cap {
                return Err(sse_protocol(format!(
                    "sse event exceeds {cap} bytes before its terminator"
                )));
            }
            match key {
                "data" => {
                    if p.seen_data {
                        p.ev.data.push('\n');
                    }
                    p.seen_data = true;
                    p.ev.data.push_str(value);
                }
                "event" => {
                    if std::mem::replace(&mut p.seen_event, true) {
                        return Err(sse_protocol("duplicate sse event field"));
                    }
                    p.ev.event = value.to_string();
                }
                "id" => {
                    if std::mem::replace(&mut p.seen_id, true) {
                        return Err(sse_protocol("duplicate sse id field"));
                    }
                    p.ev.id = value.to_string();
                }
                _ => {} // retry and unknown fields are ignored
            }
        }
    }
}

impl CarrierReader for SseEventReader {
    fn interrupt_handle(&self) -> Option<Box<dyn crate::net::Conn>> {
        self.body.try_clone_conn().ok()
    }

    fn recv(&mut self) -> Result<Incoming> {
        let step = self.next_event_or_comment(true);
        self.returned_at = std::time::Instant::now();
        match step? {
            SseStep::Idle => Ok(Incoming::Idle),
            SseStep::Eof => Ok(Incoming::Closed(None)),
            SseStep::Event(ev) => {
                if ev.event != "data" && ev.data.len() > SSE_CONTROL_EVENT_LIMIT {
                    return Err(Error::new(
                        wire::ERR_BAD_FRAME,
                        format!("sse control event exceeds {SSE_CONTROL_EVENT_LIMIT} bytes"),
                    ));
                }
                dispatch(&ev.event, &ev.data, self.epoch)
            }
        }
    }
}

fn dispatch(kind: &str, data: &str, epoch: u64) -> Result<Incoming> {
    if kind == "data" {
        let (offset, payload) = wire::parse_sse_data(data)?;
        return Ok(Incoming::Data {
            epoch,
            offset,
            payload,
        });
    }
    let c = Control::parse(data)?;
    if c.kind == ControlKind::Error {
        return Ok(Incoming::Closed(Some(Error {
            code: c.code.clone().unwrap_or_default(),
            message: "peer ended the session".to_string(),
            retryable: c.retryable,
            session_closed: c.session_closed,
            remote_status: None,
            trusted: false,
            retry_after: std::time::Duration::ZERO,
        })));
    }
    Ok(Incoming::Control(c))
}

#[cfg(test)]
mod tests {
    use super::sse_line_limit;
    use crate::transport::CarrierReader;
    use crate::wire::ControlKind;
    use std::io::{Read, Write};
    use std::time::Duration;

    /// A connection backed by a byte slice, so the reader can be driven
    /// without a socket.
    struct SliceConn {
        data: Vec<u8>,
        pos: usize,
    }

    impl Read for SliceConn {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = (self.data.len() - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    impl Write for SliceConn {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl crate::net::Conn for SliceConn {
        fn set_read_timeout(&self, _: Option<Duration>) -> std::io::Result<()> {
            Ok(())
        }
        fn set_write_timeout(&self, _: Option<Duration>) -> std::io::Result<()> {
            Ok(())
        }
        fn try_clone(&self) -> std::io::Result<Box<dyn crate::net::Conn>> {
            Err(std::io::Error::other("not cloneable"))
        }
        fn shutdown_write(&self) -> std::io::Result<()> {
            Ok(())
        }
        fn shutdown_both(&self) -> std::io::Result<()> {
            Ok(())
        }
        fn describe(&self) -> String {
            "slice".to_string()
        }
    }

    /// Deterministic stream script: bytes and injected read errors, with no
    /// sleeps or real sockets involved.
    struct ScriptedConn {
        actions: Vec<Result<Vec<u8>, std::io::ErrorKind>>,
    }

    impl Read for ScriptedConn {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.actions.remove(0) {
                Ok(bytes) => {
                    buf[..bytes.len()].copy_from_slice(&bytes);
                    Ok(bytes.len())
                }
                Err(kind) => Err(std::io::Error::new(kind, "injected read state")),
            }
        }
    }

    impl Write for ScriptedConn {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl crate::net::Conn for ScriptedConn {
        fn set_read_timeout(&self, _: Option<Duration>) -> std::io::Result<()> {
            Ok(())
        }
        fn set_write_timeout(&self, _: Option<Duration>) -> std::io::Result<()> {
            Ok(())
        }
        fn try_clone(&self) -> std::io::Result<Box<dyn crate::net::Conn>> {
            Err(std::io::Error::other("not cloneable"))
        }
        fn shutdown_write(&self) -> std::io::Result<()> {
            Ok(())
        }
        fn shutdown_both(&self) -> std::io::Result<()> {
            Ok(())
        }
        fn describe(&self) -> String {
            "scripted".to_string()
        }
    }

    /// An event that arrived in the same read as the response head is
    /// delivered from the connection's buffer without another socket read
    /// (rs->rs http-sse: the ready event otherwise waited for the next ping,
    /// one heartbeat, under 20 concurrent sessions).
    #[test]
    fn event_buffered_with_the_response_head_is_read_without_blocking() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n".to_vec();
        let mut raw = head.clone();
        raw.extend_from_slice(b"event: ping\ndata: {\"type\":\"ping\",\"session_id\":\"sid\",\"instance_id\":\"bi\",\"epoch\":\"1\",\"stream_id\":\"st\",\"nonce\":\"n\"}\n\n");
        let mut conn = crate::net::BufferedConn::new(ScriptedConn {
            actions: vec![Ok(raw), Err(std::io::ErrorKind::WouldBlock)],
        });
        assert!(conn.fill().unwrap() > head.len());
        conn.consume(head.len());
        let body = crate::net::http1::BodyReader::new(conn, &[]);
        let mut reader = super::SseEventReader::new(body, 32 * 1024, 1);
        match reader.recv().unwrap() {
            super::Incoming::Control(control) => {
                assert_eq!(control.nonce.as_deref(), Some("n"));
            }
            _ => panic!("expected the buffered ping"),
        }
    }

    fn reader_over(raw: Vec<u8>, frame: usize, epoch: u64) -> super::SseEventReader {
        let conn = crate::net::BufferedConn::new(SliceConn { data: raw, pos: 0 });
        let body = crate::net::http1::BodyReader::new(conn, &[]);
        super::SseEventReader::new(body, frame, epoch)
    }

    fn reader_over_script(
        actions: Vec<Result<Vec<u8>, std::io::ErrorKind>>,
        frame: usize,
        epoch: u64,
    ) -> super::SseEventReader {
        let conn = crate::net::BufferedConn::new(ScriptedConn { actions });
        let body = crate::net::http1::BodyReader::new(conn, &[]);
        super::SseEventReader::new(body, frame, epoch)
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

    fn run_sse_fuzz(iterations: usize) {
        let mut rng = FuzzRng(0x6c19_d3a7_805e_42bf);
        for iteration in 0..iterations {
            let fuzz = rng.bytes(192);
            let mut raw = match iteration % 4 {
                1 => b"event: data\ndata: ".to_vec(),
                2 => b"event: ping\ndata: ".to_vec(),
                3 => b": keepalive\n".to_vec(),
                _ => Vec::new(),
            };
            raw.extend_from_slice(&fuzz);
            if iteration % 4 != 0 {
                raw.extend_from_slice(b"\n\n");
            }
            assert!(raw.len() <= 224, "fuzz input must stay bounded");
            let mut reader = reader_over(raw, 256, iteration as u64);
            let _ = reader.recv();
        }
    }

    #[test]
    fn fuzz_sse_lines() {
        run_sse_fuzz(100_000);
    }

    #[test]
    #[ignore = "one-million iteration parser fuzz run"]
    fn fuzz_sse_lines_long() {
        run_sse_fuzz(1_000_000);
    }

    /// A data event is `data: <offset>:<length>:<sha256>:<base64>\n`.
    fn data_line_len(payload: usize) -> usize {
        let offset = 20; // u64 in decimal, upper bound
        let length = 20;
        let sha = 64;
        let base64 = payload.div_ceil(3) * 4;
        6 + offset + 1 + length + 1 + sha + 1 + base64
    }

    /// Every legal `frame_size` has to fit in one line. The reader used to cap
    /// at a flat 64 KiB, which silently broke the carrier for any frame above
    /// ~48 KiB — a configuration the validator accepted.
    #[test]
    fn every_legal_frame_size_fits_in_one_line() {
        for frame in [
            1024usize,
            32 * 1024,
            48 * 1024,
            64 * 1024,
            256 * 1024,
            1024 * 1024,
        ] {
            let line = data_line_len(frame);
            let limit = sse_line_limit(frame);
            assert!(
                line <= limit,
                "frame {frame}: a {line}-byte data line exceeds the {limit}-byte read limit"
            );
        }
    }

    /// The floor keeps small frames from being limited by the formula itself.
    #[test]
    fn the_limit_has_a_floor() {
        assert_eq!(sse_line_limit(0), 16 * 1024);
        assert_eq!(sse_line_limit(1024), 16 * 1024);
    }

    #[test]
    fn reads_a_data_event() {
        let payload = b"hello";
        let body = crate::wire::format_sse_data(0, payload).unwrap();
        let raw = format!("event: data\ndata: {body}\n\n").into_bytes();
        let mut reader = reader_over(raw, 32 * 1024, 7);
        match reader.recv().unwrap() {
            super::Incoming::Data {
                epoch,
                offset,
                payload: got,
                ..
            } => {
                assert_eq!(epoch, 7);
                assert_eq!(offset, 0);
                assert_eq!(got, payload);
            }
            _ => panic!("expected a data event"),
        }
    }

    #[test]
    fn data_event_survives_timed_out_mid_data_line() {
        let payload = b"hello";
        let body = crate::wire::format_sse_data(0, payload).unwrap();
        let raw = format!("event: data\ndata: {body}\n\n").into_bytes();
        let split = raw.iter().position(|&b| b == b'0').unwrap() + 3;
        let mut reader = reader_over_script(
            vec![
                Ok(raw[..split].to_vec()),
                Err(std::io::ErrorKind::TimedOut),
                Ok(raw[split..].to_vec()),
            ],
            32 * 1024,
            7,
        );
        assert!(matches!(reader.recv().unwrap(), super::Incoming::Idle));
        match reader.recv().unwrap() {
            super::Incoming::Data {
                epoch,
                offset,
                payload: got,
            } => {
                assert_eq!((epoch, offset, got), (7, 0, payload.to_vec()));
            }
            _ => panic!("expected resumed data event"),
        }
    }

    #[test]
    fn control_event_survives_would_block_mid_data_line() {
        let raw = b"event: ping\ndata: {\"type\":\"ping\",\"session_id\":\"s\",\"instance_id\":\"i\",\"epoch\":\"1\",\"stream_id\":\"st\",\"nonce\":\"n\"}\n\n".to_vec();
        let split = raw.iter().position(|&b| b == b'{').unwrap() + 10;
        let mut reader = reader_over_script(
            vec![
                Ok(raw[..split].to_vec()),
                Err(std::io::ErrorKind::WouldBlock),
                Ok(raw[split..].to_vec()),
            ],
            32 * 1024,
            1,
        );
        assert!(matches!(reader.recv().unwrap(), super::Incoming::Idle));
        match reader.recv().unwrap() {
            super::Incoming::Control(control) => {
                assert_eq!(control.kind, ControlKind::Ping);
                assert_eq!(control.nonce.as_deref(), Some("n"));
            }
            _ => panic!("expected resumed control event"),
        }
    }

    /// An event only ends at a blank line, and the grammar does not bound how
    /// many `data:` lines may precede it. Each line here is legal on its own;
    /// together they must not be able to grow the buffer without bound.
    #[test]
    fn an_event_that_never_terminates_is_refused() {
        let mut raw = Vec::new();
        raw.extend_from_slice(b"event: data\n");
        for _ in 0..64 {
            raw.extend_from_slice(b"data: ");
            raw.extend_from_slice(&[b'a'; 4096]);
            raw.push(b'\n');
        }
        let mut reader = reader_over(raw, 32 * 1024, 1);
        let err = match reader.recv() {
            Err(e) => e,
            Ok(_) => panic!("an unterminated event must be refused"),
        };
        assert!(
            err.message.contains("exceeds"),
            "unexpected error: {}",
            err.message
        );
    }

    #[test]
    fn spec_test_sse_declared_reservation_accepts_legal_layouts() {
        let large_payload = vec![b'y'; 200 * 1024];
        let large_line = crate::wire::format_sse_data(0, &large_payload).unwrap();
        let no_space = crate::wire::format_sse_data(0, b"z").unwrap();
        let data_first = crate::wire::format_sse_data(0, b"z").unwrap();
        let cases = [
            (
                "maximum negotiated frame",
                format!("event: data\ndata: {large_line}\n\n"),
                256 * 1024,
                Some((large_payload.as_slice(), 0)),
            ),
            (
                "no space after colon",
                format!("event: data\ndata:{no_space}\n\n"),
                1024,
                Some((b"z".as_slice(), 0)),
            ),
            (
                "data before event and id",
                format!("data: {data_first}\nid: 1:1\nevent: data\n\n"),
                1024,
                Some((b"z".as_slice(), 0)),
            ),
            (
                "control event",
                "id: 1:1\nevent: ping\ndata: {\"type\":\"ping\",\"session_id\":\"sid\",\"instance_id\":\"bi\",\"epoch\":\"1\",\"stream_id\":\"st\",\"nonce\":\"n\"}\n\n".to_string(),
                1024,
                None,
            ),
        ];

        for (name, raw, frame_limit, expected_data) in cases {
            let mut reader = reader_over(raw.into_bytes(), frame_limit, 1);
            match (expected_data, reader.recv().unwrap()) {
                (
                    Some((payload, offset)),
                    super::Incoming::Data {
                        epoch,
                        offset: got_offset,
                        payload: got_payload,
                    },
                ) => {
                    assert_eq!(epoch, 1, "{name}");
                    assert_eq!(got_offset, offset, "{name}");
                    assert_eq!(got_payload, payload, "{name}");
                }
                (None, super::Incoming::Control(control)) => {
                    assert_eq!(control.kind, ControlKind::Ping, "{name}");
                    assert_eq!(control.nonce.as_deref(), Some("n"), "{name}");
                }
                (Some(_), _other) => panic!("{name}: expected data, got another incoming item"),
                (None, _) => panic!("{name}: expected a control event"),
            }
        }
    }

    #[test]
    fn spec_test_sse_data_line_longer_than_declared_is_rejected() {
        let mut line = crate::wire::format_sse_data(0, b"x").unwrap();
        line.push_str(&"A".repeat(8 * 1024));
        let raw = format!("event: data\ndata: {line}\n\n").into_bytes();
        let mut reader = reader_over(raw, 256 * 1024, 1);

        let error = match reader.recv() {
            Err(error) => error,
            Ok(_) => panic!("a data line longer than its declared length was accepted"),
        };
        assert_eq!(error.code, crate::wire::ERR_BAD_FRAME);
    }

    #[test]
    fn spec_test_sse_comments_and_empty_blocks_do_not_hide_next_event() {
        let mut raw = ": keepalive\n\n".repeat(2000);
        raw.push_str(&"retry: 1000\n\n".repeat(200));
        raw.push_str("event: ping\ndata: {\"type\":\"ping\",\"session_id\":\"sid\",\"instance_id\":\"bi\",\"epoch\":\"1\",\"stream_id\":\"st\",\"nonce\":\"n\"}\n\n");

        let mut reader = reader_over(raw.into_bytes(), 1024, 1);
        match reader.recv().unwrap() {
            super::Incoming::Control(control) => {
                assert_eq!(control.kind, ControlKind::Ping);
                assert_eq!(control.nonce.as_deref(), Some("n"));
            }
            _ => panic!("expected the ping after comments and empty blocks"),
        }
    }

    #[test]
    fn spec_test_sse_small_frame_still_accepts_control_event() {
        let mut ping = crate::wire::Control::base(ControlKind::Ping, "sid", "bi", 1, "stream");
        ping.nonce = Some("0123456789abcdef0123456789abcdef".to_string());
        let json = ping.to_json().to_string();
        let raw = format!("event: ping\ndata: {json}\n\n").into_bytes();
        let mut reader = reader_over(raw, 64, 1);

        match reader.recv().unwrap() {
            super::Incoming::Control(control) => {
                assert_eq!(control.kind, ControlKind::Ping);
                assert_eq!(
                    control.nonce.as_deref(),
                    Some("0123456789abcdef0123456789abcdef")
                );
            }
            _ => panic!("expected a control event with a small negotiated frame"),
        }
    }

    #[test]
    fn spec_test_sse_oversized_control_event_is_protocol_error() {
        let data = "a".repeat(16 * 1024 + 4096 + 1);
        let raw = format!("event: ping\ndata: {data}\n\n").into_bytes();
        let mut reader = reader_over(raw, 256 * 1024, 1);

        let error = match reader.recv() {
            Err(error) => error,
            Ok(_) => panic!("an oversized control event was accepted"),
        };
        assert_eq!(error.code, crate::wire::ERR_BAD_FRAME);
    }
}
