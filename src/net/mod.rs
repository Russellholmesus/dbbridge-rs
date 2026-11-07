//! Network layer: a hand-written HTTP/1.1 server and client plus WebSocket
//! framing, over `std::net::TcpStream`.
//!
//! `BufferedConn` owns the socket together with any bytes already read past a
//! protocol boundary. That is what makes the WebSocket upgrade safe: the HTTP
//! request head and the first frames may arrive in the same TCP segment, and
//! the leftover bytes are handed to the frame reader instead of being dropped
//! with a `BufReader`.
//!
//! TLS is not implemented: v1 runs plaintext and is meant to sit behind a TLS
//! terminating proxy, or on a private link. `BufferedConn` is the seam where a
//! TLS backend would plug in.

pub mod http1;
#[cfg(feature = "tls")]
pub mod tls;
pub mod ws;

use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// Wakes a blocking TCP listener by connecting to its bound address. Wildcard
/// binds are redirected to loopback so the wake connection stays local.
pub(crate) fn wake_tcp_listener(addr: SocketAddr) -> io::Result<()> {
    let target = match addr.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
        }
        IpAddr::V6(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), addr.port())
        }
        _ => addr,
    };
    TcpStream::connect_timeout(&target, Duration::from_secs(1)).map(drop)
}

/// The byte stream under an HTTP connection.
///
/// Forward mode dials a socket; reverse mode hands out a stream of a tunnel
/// the peer dialed in. Both are the same thing to everything above this
/// trait, which is what lets the whole session protocol — HTTP framing,
/// WebSocket upgrade, chunked bodies — run unchanged over either.
///
/// `try_clone` returns a second handle to the same stream, the way
/// `TcpStream::try_clone` does. A tunnel stream shares its multiplexer
/// window with the clone; both halves of a WebSocket upgrade therefore
/// count against the same flow-control budget.
pub trait Conn: Read + Write + Send {
    fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()>;
    fn set_write_timeout(&self, d: Option<Duration>) -> io::Result<()>;
    fn try_clone(&self) -> io::Result<Box<dyn Conn>>;
    /// Half-close: the peer sees EOF, this side may still read.
    fn shutdown_write(&self) -> io::Result<()>;
    /// Close both directions.
    fn shutdown_both(&self) -> io::Result<()>;
    /// A short label for logs, e.g. `127.0.0.1:5432` or `tunnel tn_ab...`.
    fn describe(&self) -> String;
}

impl Conn for TcpStream {
    fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, d)
    }
    fn set_write_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        TcpStream::set_write_timeout(self, d)
    }
    fn try_clone(&self) -> io::Result<Box<dyn Conn>> {
        Ok(Box::new(TcpStream::try_clone(self)?))
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.shutdown(std::net::Shutdown::Write)
    }
    fn shutdown_both(&self) -> io::Result<()> {
        self.shutdown(std::net::Shutdown::Both)
    }
    fn describe(&self) -> String {
        match self.peer_addr() {
            Ok(a) => a.to_string(),
            Err(_) => "tcp".to_string(),
        }
    }
}

impl Conn for Box<dyn Conn> {
    fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        (**self).set_read_timeout(d)
    }
    fn set_write_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        (**self).set_write_timeout(d)
    }
    fn try_clone(&self) -> io::Result<Box<dyn Conn>> {
        (**self).try_clone()
    }
    fn shutdown_write(&self) -> io::Result<()> {
        (**self).shutdown_write()
    }
    fn shutdown_both(&self) -> io::Result<()> {
        (**self).shutdown_both()
    }
    fn describe(&self) -> String {
        (**self).describe()
    }
}

pub struct LeasedConn {
    inner: Box<dyn Conn>,
    _lease: std::sync::Arc<dyn std::any::Any + Send + Sync>,
}

impl LeasedConn {
    pub fn new(inner: Box<dyn Conn>, lease: impl std::any::Any + Send + Sync) -> LeasedConn {
        LeasedConn {
            inner,
            _lease: std::sync::Arc::new(lease),
        }
    }
}

impl Read for LeasedConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for LeasedConn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl Conn for LeasedConn {
    fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(d)
    }
    fn set_write_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        self.inner.set_write_timeout(d)
    }
    fn try_clone(&self) -> io::Result<Box<dyn Conn>> {
        Ok(Box::new(LeasedConn {
            inner: self.inner.try_clone()?,
            _lease: self._lease.clone(),
        }))
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.inner.shutdown_write()
    }
    fn shutdown_both(&self) -> io::Result<()> {
        self.inner.shutdown_both()
    }
    fn describe(&self) -> String {
        self.inner.describe()
    }
}

/// A parsed `scheme://host:port/prefix` endpoint.
#[derive(Debug, Clone, PartialEq)]
pub struct Url {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    /// Path prefix without a trailing slash, e.g. `/dbbridge`.
    pub prefix: String,
}

impl Url {
    pub fn parse(raw: &str) -> Result<Url, String> {
        let (scheme, rest) = raw
            .split_once("://")
            .ok_or_else(|| format!("endpoint URL {raw:?} has no scheme"))?;
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(format!("unsupported scheme {scheme:?}"));
        }
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, ""),
        };
        if authority.is_empty() {
            return Err(format!("endpoint URL {raw:?} has no host"));
        }
        // Strip userinfo; it is not part of this protocol.
        let authority = authority.rsplit('@').next().unwrap_or(authority);
        let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
            // IPv6 literal.
            let (h, tail) = stripped
                .split_once(']')
                .ok_or_else(|| format!("malformed IPv6 host in {raw:?}"))?;
            let p = tail.strip_prefix(':').and_then(|p| p.parse().ok());
            (h.to_string(), p)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => match p.parse::<u16>() {
                    Ok(port) => (h.to_string(), Some(port)),
                    Err(_) => (authority.to_string(), None),
                },
                None => (authority.to_string(), None),
            }
        };
        let port = port.unwrap_or(if scheme == "https" { 443 } else { 80 });
        Ok(Url {
            scheme,
            host,
            port,
            prefix: path.trim_end_matches('/').to_string(),
        })
    }

    pub fn is_tls(&self) -> bool {
        self.scheme == "https"
    }

    /// `host:port`, the HTTP `Host` header value.
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Joins a protocol path onto the endpoint prefix.
    pub fn path(&self, path: &str) -> String {
        format!("{}{}", self.prefix, path)
    }
}

/// Opens a TCP connection, trying every resolved address.
pub fn dial(host: &str, port: u16, timeout: Duration) -> io::Result<TcpStream> {
    let mut last = io::Error::new(io::ErrorKind::NotFound, "no address resolved");
    let addrs: Vec<_> = (host, port).to_socket_addrs()?.collect();
    if addrs.is_empty() {
        return Err(last);
    }
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => {
                let _ = set_nodelay(&s);
                return Ok(s);
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// Apply the socket options required by every DBBridge TCP connection.
pub fn set_nodelay(stream: &TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)
}

/// The largest single read this protocol ever asks for: an HTTP request body
/// capped at 64 MiB. Nothing legitimate is bigger, so a request above this is
/// either a bug or an attack.
pub const MAX_READ: usize = 64 << 20;

/// A connection plus the bytes read past the last consumed boundary.
pub struct BufferedConn {
    stream: Box<dyn Conn>,
    buf: Vec<u8>,
    start: usize,
    read_deadline: Option<Instant>,
    resp_http10: bool,
    /// The last request was HEAD: responses carry no body.
    resp_head: bool,
}

impl BufferedConn {
    pub fn new(stream: impl Conn + 'static) -> Self {
        BufferedConn {
            stream: Box::new(stream),
            buf: Vec::with_capacity(16 * 1024),
            start: 0,
            read_deadline: None,
            resp_http10: false,
            resp_head: false,
        }
    }

    /// Wraps a connection that is already boxed, as a tunnel stream is.
    pub fn from_boxed(stream: Box<dyn Conn>) -> Self {
        BufferedConn {
            stream,
            buf: Vec::with_capacity(16 * 1024),
            start: 0,
            read_deadline: None,
            resp_http10: false,
            resp_head: false,
        }
    }

    pub fn describe(&self) -> String {
        self.stream.describe()
    }

    /// Records how responses to the request just read must look.
    pub fn set_response_style(&mut self, http10: bool, head: bool) {
        self.resp_http10 = http10;
        self.resp_head = head;
    }

    /// (HTTP/1.0 request, HEAD request) of the request just read.
    pub fn response_style(&self) -> (bool, bool) {
        (self.resp_http10, self.resp_head)
    }

    /// How many bytes are buffered but not consumed.
    pub fn buffered_len(&self) -> usize {
        self.buf.len() - self.start
    }

    pub fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        self.stream.set_read_timeout(d)
    }

    /// Applies an absolute deadline to subsequent socket reads. Unlike a
    /// socket read timeout, this is not reset by each successfully read byte.
    pub fn set_read_deadline(&mut self, deadline: Option<Instant>) {
        self.read_deadline = deadline;
    }

    pub fn set_write_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        self.stream.set_write_timeout(d)
    }

    pub fn try_clone(&self) -> io::Result<Box<dyn Conn>> {
        self.stream.try_clone()
    }

    /// Bytes already read but not consumed.
    pub fn buffered(&self) -> &[u8] {
        &self.buf[self.start..]
    }

    pub fn consume(&mut self, n: usize) {
        self.start += n;
        if self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        }
    }

    /// Reads more bytes into the buffer, returning how many arrived (0 = EOF).
    pub fn fill(&mut self) -> io::Result<usize> {
        if self.start > 0 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        let mut tmp = [0u8; 16 * 1024];
        loop {
            if let Some(deadline) = self.read_deadline {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "absolute read deadline exceeded",
                    ));
                }
                self.stream.set_read_timeout(Some(remaining))?;
            }
            match self.stream.read(&mut tmp) {
                Ok(0) => return Ok(0),
                Ok(n) => {
                    self.buf.extend_from_slice(&tmp[..n]);
                    return Ok(n);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// Reads exactly `n` bytes.
    ///
    /// `n` must already be bounded by the caller's own limit — every caller in
    /// this protocol has one (`max_body`, the chunk remainder, the frame size).
    /// The check below is a backstop: an arithmetic mistake upstream must fail
    /// the connection, not turn into an unbounded allocation.
    pub fn read_exact_vec(&mut self, n: usize) -> io::Result<Vec<u8>> {
        if n > MAX_READ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "requested read exceeds the largest message this protocol carries",
            ));
        }
        while self.buf.len() - self.start < n {
            if self.fill()? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection closed mid-message",
                ));
            }
        }
        let out = self.buf[self.start..self.start + n].to_vec();
        self.consume(n);
        Ok(out)
    }

    /// Reads up to `\n`, returning the line without the terminator.
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
                self.consume(pos + 1);
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

    /// Takes every buffered byte, for handing a connection to another reader.
    pub fn take_buffered(&mut self) -> Vec<u8> {
        let out = self.buf[self.start..].to_vec();
        self.buf.clear();
        self.start = 0;
        out
    }

    pub fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        self.stream.write_all(data)
    }

    /// One write call; returns how many bytes the connection took.
    pub fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.stream.write(data)
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }

    pub fn shutdown_write(&mut self) -> io::Result<()> {
        self.stream.shutdown_write()
    }
}

/// Percent-decodes a query value; `+` becomes a space as in form encoding.
///
/// Inspecting the input as bytes prevents a percent sign before a multi-byte
/// UTF-8 character from ever splitting a Rust `str` slice. Invalid UTF-8
/// produced by a valid escape is reported to the HTTP parser.
pub fn percent_decode(s: &str) -> Result<String, ()> {
    const fn hex_value(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }

    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => match (hex_value(b[i + 1]), hex_value(b[i + 2])) {
                (Some(hi), Some(lo)) => {
                    let v = (hi << 4) | lo;
                    out.push(v);
                    i += 3;
                }
                _ => {
                    out.push(b[i]);
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| ())
}

/// Case-insensitive header lookup over a name/value list.
pub fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_urls() {
        let u = Url::parse("http://127.0.0.1:18080").unwrap();
        assert_eq!((u.host.as_str(), u.port), ("127.0.0.1", 18080));
        assert_eq!(u.path("/v1/peer/probe"), "/v1/peer/probe");

        let u = Url::parse("https://b.example.com/base/").unwrap();
        assert_eq!(u.port, 443);
        assert_eq!(u.prefix, "/base");
        assert_eq!(u.path("/v1/sessions"), "/base/v1/sessions");

        let u = Url::parse("http://[::1]:9000").unwrap();
        assert_eq!(u.host, "::1");
        assert_eq!(u.port, 9000);
        assert_eq!(u.authority(), "[::1]:9000");
    }

    #[test]
    fn decodes_query() {
        assert_eq!(percent_decode("a%2Fb+c").unwrap(), "a/b c");
    }

    #[test]
    fn percent_decode_never_panics_on_multibyte() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        for input in ["%aé", "%+F", "%", "%%"] {
            assert!(catch_unwind(AssertUnwindSafe(|| percent_decode(input))).is_ok());
        }

        let mut state = 0x9e37_79b9_u32;
        for _ in 0..10_000 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            let input = String::from_utf8_lossy(&state.to_le_bytes()).into_owned();
            assert!(catch_unwind(AssertUnwindSafe(|| percent_decode(&input))).is_ok());
        }
    }
}
