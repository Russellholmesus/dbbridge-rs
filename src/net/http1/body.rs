//! Response bodies: `Content-Length`, chunked, or read-until-close.

use std::io;
use std::time::Duration;

use crate::net::{header, BufferedConn};
use crate::resource::budget::BudgetLease;

use super::MAX_HEAD;

pub struct BodyReader {
    conn: BufferedConn,
    chunked: bool,
    content_left: Option<usize>,
    /// Decoded bytes not yet handed out.
    buf: Vec<u8>,
    start: usize,
    /// Bytes still owed by the chunk currently being decoded.
    chunk_left: usize,
    done: bool,
    resource_leases: Vec<BudgetLease>,
}

impl BodyReader {
    pub fn new(conn: BufferedConn, headers: &[(String, String)]) -> Self {
        let chunked = header(headers, "transfer-encoding")
            .map(|v| v.to_ascii_lowercase().contains("chunked"))
            .unwrap_or(false);
        let content_left = if chunked {
            None
        } else {
            header(headers, "content-length").and_then(|v| v.trim().parse().ok())
        };
        BodyReader {
            conn,
            chunked,
            content_left,
            buf: Vec::new(),
            start: 0,
            chunk_left: 0,
            done: false,
            resource_leases: Vec::new(),
        }
    }

    pub fn hold_resource_leases(mut self, leases: Vec<BudgetLease>) -> Self {
        self.resource_leases = leases;
        self
    }

    /// A second handle on the body's connection (see
    /// `CarrierReader::interrupt_handle`).
    pub fn try_clone_conn(&self) -> io::Result<Box<dyn crate::net::Conn>> {
        self.conn.try_clone()
    }

    pub fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        self.conn.set_read_timeout(d)
    }

    fn compact(&mut self) {
        if self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        }
    }

    /// Decodes more body bytes into `buf`. Returns how many were added; 0 means
    /// the body ended.
    fn fill(&mut self) -> io::Result<usize> {
        if self.done {
            return Ok(0);
        }
        self.compact();
        if !self.chunked {
            if let Some(left) = self.content_left {
                if left == 0 {
                    self.done = true;
                    return Ok(0);
                }
                let want = left.min(16 * 1024);
                let bytes = self.conn.read_exact_vec(want)?;
                self.content_left = Some(left - want);
                self.buf.extend_from_slice(&bytes);
                return Ok(want);
            }
            // Bytes the connection already buffered (read together with
            // the response head) come first: a read here would block until
            // the peer sends more, e.g. an SSE ready event arriving in the
            // head's segment waited for the next heartbeat ping.
            if self.conn.buffered_len() == 0 && self.conn.fill()? == 0 {
                self.done = true;
                return Ok(0);
            }
            let bytes = self.conn.take_buffered();
            let n = bytes.len();
            self.buf.extend_from_slice(&bytes);
            return Ok(n);
        }
        if self.chunk_left == 0 {
            // A chunk header is `<hex size>[;ext]`. Blank lines between chunks
            // are tolerated, as the grammar allows them around the trailer.
            loop {
                let line = self.conn.read_line(MAX_HEAD)?;
                if line.is_empty() {
                    continue;
                }
                let size_text = line.split(';').next().unwrap_or("").trim();
                let size = usize::from_str_radix(size_text, 16).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("malformed chunk size {size_text:?}"),
                    )
                })?;
                if size == 0 {
                    // Trailer section, then end of body.
                    while !self.conn.read_line(MAX_HEAD)?.is_empty() {}
                    self.done = true;
                    return Ok(0);
                }
                self.chunk_left = size;
                break;
            }
        }
        let want = self.chunk_left.min(16 * 1024);
        let data = self.conn.read_exact_vec(want)?;
        self.chunk_left -= want;
        if self.chunk_left == 0 {
            // The CRLF that closes the chunk must be present and empty.
            if !self.conn.read_line(2)?.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "missing chunk CRLF",
                ));
            }
        }
        self.buf.extend_from_slice(&data);
        Ok(want)
    }

    /// Reads one event-stream line (WHATWG): terminated by CRLF, LF or a
    /// lone CR, returned raw without its terminator. `skip_lf` carries a CR
    /// that ended the previous line across calls, so the LF of a CRLF that
    /// arrives in a later read is not taken for an empty line. A line longer
    /// than `max` is `InvalidData`; a read timeout leaves the partial line
    /// buffered for the next call.
    pub fn read_sse_line(&mut self, max: usize, skip_lf: &mut bool) -> io::Result<Vec<u8>> {
        // Bytes after `start` already searched for a terminator: a long line
        // arriving in many small reads is scanned once, not once per read.
        let mut scanned = 0usize;
        loop {
            if *skip_lf && self.start < self.buf.len() {
                *skip_lf = false;
                if self.buf[self.start] == b'\n' {
                    self.start += 1;
                    self.compact();
                    scanned = 0;
                    continue;
                }
            }
            if !*skip_lf {
                let from = (self.start + scanned).min(self.buf.len());
                if let Some(pos) = self.buf[from..]
                    .iter()
                    .position(|&b| b == b'\n' || b == b'\r')
                    .map(|p| p + from - self.start)
                {
                    if pos > max {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
                    }
                    let line = self.buf[self.start..self.start + pos].to_vec();
                    *skip_lf = self.buf[self.start + pos] == b'\r';
                    self.start += pos + 1;
                    self.compact();
                    return Ok(line);
                }
                if self.buf.len() - self.start > max {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
                }
                scanned = self.buf.len() - self.start;
            }
            if self.fill()? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed mid-line",
                ));
            }
            if self.start == 0 && self.buf.len() < scanned {
                scanned = 0;
            }
        }
    }

    /// Reads up to `\n`, returning the line without its terminator.
    pub fn read_line(&mut self, max: usize) -> io::Result<String> {
        loop {
            if let Some(pos) = self.buf[self.start..].iter().position(|&b| b == b'\n') {
                if pos > max {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
                }
                let mut line = self.buf[self.start..self.start + pos].to_vec();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                self.start += pos + 1;
                self.compact();
                return String::from_utf8(line)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid UTF-8"));
            }
            if self.buf.len() - self.start > max {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
            }
            if self.fill()? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed mid-line",
                ));
            }
        }
    }
}
