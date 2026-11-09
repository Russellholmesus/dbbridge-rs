//! HTTP/1.1: just enough of the server and client to carry the protocol.
//!
//! The server parses a request head, a `Content-Length` or chunked body, and
//! writes fixed-length or streamed responses. The client keeps a small pool of
//! idle connections per authority, because every session's control traffic
//! (probe, create, ack, fin, delete) is a separate request.

use std::io;

use crate::net::{header, BufferedConn};

mod body;
mod client;
#[cfg(feature = "h2")]
mod h2;

pub use body::BodyReader;
pub(crate) use client::read_body;
pub use client::{read_response_head, Client, Dialer, Response};
pub const MAX_HEAD: usize = 16 * 1024;

#[derive(Debug, Clone)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        header(&self.headers, name)
    }

    pub fn query(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn is_websocket_upgrade(&self) -> bool {
        header(&self.headers, "upgrade")
            .map(|v| v.eq_ignore_ascii_case("websocket"))
            .unwrap_or(false)
            && header(&self.headers, "connection")
                .map(|v| {
                    v.split(',')
                        .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
                })
                .unwrap_or(false)
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        417 => "Expectation Failed",
        426 => "Upgrade Required",
        431 => "Request Header Fields Too Large",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        307 => "Temporary Redirect",
        _ => "Status",
    }
}

/// Reads one request. Returns `Ok(None)` when the peer closed cleanly before a
/// request line (an idle keep-alive connection going away).
#[cfg(test)]
pub fn read_request(conn: &mut BufferedConn, max_body: usize) -> io::Result<Option<Request>> {
    let mut req = match read_request_head(conn)? {
        Some(r) => r,
        None => return Ok(None),
    };
    read_request_body(conn, &mut req, max_body)?;
    Ok(Some(req))
}

/// Reads and validates only the request head; callers can authenticate before consuming a body.
pub fn read_request_head(conn: &mut BufferedConn) -> io::Result<Option<Request>> {
    read_request_head_with_limit(conn, MAX_HEAD)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpReject {
    /// Status code of the refusal.
    pub status: u16,
    pub detail: Option<&'static str>,
    /// Internal reason for logs.
    pub reason: String,
}

impl std::fmt::Display for HttpReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl std::error::Error for HttpReject {}

impl HttpReject {
    fn error(status: u16, detail: Option<&'static str>, reason: impl Into<String>) -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            HttpReject {
                status,
                detail,
                reason: reason.into(),
            },
        )
    }

    pub fn raw(&self) -> Vec<u8> {
        const ERROR_HEADERS: &str =
            "\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n";
        match self.status {
            417 => format!(
                "HTTP/1.1 417 Expectation Failed\r\nConnection: close\r\nContent-Length: 0\r\nDate: {}\r\n\r\n",
                http_date(std::time::SystemTime::now())
            )
            .into_bytes(),
            501 => format!("HTTP/1.1 501 Not Implemented{ERROR_HEADERS}Unsupported transfer encoding")
                .into_bytes(),
            status => {
                let public = match self.detail {
                    Some(d) => format!("{status} {}: {d}", reason(status)),
                    None => format!("{status} {}", reason(status)),
                };
                format!("HTTP/1.1 {public}{ERROR_HEADERS}{public}").into_bytes()
            }
        }
    }
}

pub fn reject_of(e: &io::Error) -> Option<&HttpReject> {
    e.get_ref()
        .and_then(|inner| inner.downcast_ref::<HttpReject>())
}

pub fn write_reject(conn: &mut BufferedConn, r: &HttpReject) {
    let _ = conn.write_all(&r.raw());
    let _ = conn.flush();
    let _ = conn.shutdown_write();
    let end = std::time::Instant::now() + std::time::Duration::from_millis(500);
    let _ = conn.set_read_timeout(Some(std::time::Duration::from_millis(100)));
    while std::time::Instant::now() < end {
        match conn.fill() {
            Ok(0) => break,
            Ok(_) => {
                let _ = conn.take_buffered();
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                continue
            }
            Err(_) => break,
        }
    }
}

fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn valid_host_header(h: &str) -> bool {
    h.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"!$%&'()*+,-.:;=[]_~".contains(&b))
}

fn parse_http_version(v: &str) -> Option<(u8, u8)> {
    match v {
        "HTTP/1.1" => return Some((1, 1)),
        "HTTP/1.0" => return Some((1, 0)),
        _ => {}
    }
    let rest = v.strip_prefix("HTTP/")?.as_bytes();
    if rest.len() != 3 || rest[1] != b'.' || !rest[0].is_ascii_digit() || !rest[2].is_ascii_digit()
    {
        return None;
    }
    Some((rest[0] - b'0', rest[2] - b'0'))
}

fn parse_request_uri(method: &str, uri: &str) -> Option<(String, Option<String>)> {
    if uri.is_empty() || uri.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return None;
    }
    if uri == "*" {
        return Some(("*".to_string(), None));
    }
    let (rest, query) = match uri.split_once('?') {
        Some((p, q)) => (p, Some(q.to_string())),
        None => (uri, None),
    };
    let raw_path = if rest.starts_with('/') {
        rest
    } else if method == "CONNECT" {
        // authority-form: no path
        ""
    } else {
        // absolute-form: scheme ":" ...
        let colon = rest.find(':')?;
        let scheme = &rest[..colon];
        let mut sb = scheme.bytes();
        if !sb.next()?.is_ascii_alphabetic()
            || !sb.all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.')
        {
            return None;
        }
        let after = &rest[colon + 1..];
        match after.strip_prefix("//") {
            Some(auth_path) => match auth_path.find('/') {
                Some(i) => &auth_path[i..],
                None => "",
            },
            None => "",
        }
    };
    let path = percent_decode_path(raw_path)?;
    Some((path, query))
}

fn percent_decode_path(p: &str) -> Option<String> {
    if !p.contains('%') {
        return Some(p.to_string());
    }
    let b = p.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = b.get(i + 1..i + 3)?;
            if !h[0].is_ascii_hexdigit() || !h[1].is_ascii_hexdigit() {
                return None;
            }
            let v = u8::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok()?;
            out.push(v);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    Some(String::from_utf8(out).unwrap_or_else(|_| p.to_string()))
}

pub fn read_request_head_with_limit(
    conn: &mut BufferedConn,
    max_head: usize,
) -> io::Result<Option<Request>> {
    let limit = max_head.saturating_add(4096);
    let too_large = || HttpReject::error(431, None, "request head too large");
    let bad = |why: &str| HttpReject::error(400, None, why.to_string());
    let read_line = |conn: &mut BufferedConn, used: usize| -> io::Result<String> {
        let room = limit.saturating_sub(used);
        match conn.read_line(room) {
            Ok(l) => Ok(l),
            Err(e)
                if e.kind() == io::ErrorKind::InvalidData && e.to_string() == "line too long" =>
            {
                Err(too_large())
            }
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                Err(bad("invalid bytes in request head"))
            }
            Err(e) => Err(e),
        }
    };
    let line = match read_line(conn, 0) {
        Ok(l) => l,
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof && conn.buffered_len() == 0 => {
            return Ok(None)
        }
        Err(e) => return Err(e),
    };
    let mut used = line.len() + 2;
    let (method, rest) = line
        .split_once(' ')
        .ok_or_else(|| bad("malformed HTTP request"))?;
    let (uri, proto) = rest
        .split_once(' ')
        .ok_or_else(|| bad("malformed HTTP request"))?;
    let (major, minor) = parse_http_version(proto).ok_or_else(|| bad("malformed HTTP version"))?;
    if method.is_empty() || !method.bytes().all(is_token_byte) {
        return Err(bad("invalid method"));
    }
    let (path, raw_query) = parse_request_uri(method, uri).ok_or_else(|| bad("invalid URI"))?;

    // textproto.ReadMIMEHeader
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut bad_name = false;
    let mut first = true;
    loop {
        let h = read_line(conn, used)?;
        used += h.len() + 2;
        if used > limit {
            return Err(too_large());
        }
        if h.is_empty() {
            break;
        }
        if h.starts_with(' ') || h.starts_with('\t') {
            if first {
                return Err(bad("malformed MIME header initial line"));
            }
            // obs-fold continuation: joined with one space.
            let cont = h.trim_matches(|c| c == ' ' || c == '\t');
            if let Some(last) = headers.last_mut() {
                if !cont.is_empty() {
                    if !last.1.is_empty() {
                        last.1.push(' ');
                    }
                    last.1.push_str(cont);
                }
            }
            continue;
        }
        first = false;
        let (name, value) = h
            .split_once(':')
            .ok_or_else(|| bad("malformed MIME header line"))?;
        if name.is_empty() {
            return Err(bad("malformed MIME header line"));
        }
        if !name.bytes().all(is_token_byte) {
            bad_name = true;
        }
        let value = value.trim_matches(|c| c == ' ' || c == '\t');
        if value.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f) {
            return Err(bad("invalid header value"));
        }
        headers.push((name.to_string(), value.to_string()));
    }
    let count = |n: &str| {
        headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(n))
            .count()
    };
    if count("host") > 1 {
        return Err(bad("too many Host headers"));
    }

    // readTransfer / fixLength
    let mut force_close = false;
    let tes: Vec<String> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"))
        .map(|(_, v)| v.clone())
        .collect();
    let chunked = if (major, minor) >= (1, 1) && !tes.is_empty() {
        if tes.len() != 1 || !tes[0].eq_ignore_ascii_case("chunked") {
            return Err(HttpReject::error(
                501,
                None,
                "unsupported transfer encoding",
            ));
        }
        true
    } else {
        headers.retain(|(k, _)| !k.eq_ignore_ascii_case("transfer-encoding"));
        false
    };
    let cls: Vec<String> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .map(|(_, v)| v.clone())
        .collect();
    if cls.len() > 1 && cls.iter().any(|v| *v != cls[0]) {
        return Err(bad("multiple Content-Length headers"));
    }
    if chunked && !cls.is_empty() {
        headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-length"));
        force_close = true;
    } else if let Some(cl) = cls.first() {
        if cl.is_empty()
            || !cl.bytes().all(|b| b.is_ascii_digit())
            || cl.parse::<u64>().map_or(true, |n| n > i64::MAX as u64)
        {
            return Err(bad("bad Content-Length"));
        }
        if cls.len() > 1 {
            let keep = cl.clone();
            headers.retain(|(k, _)| !k.eq_ignore_ascii_case("content-length"));
            headers.push(("Content-Length".to_string(), keep));
        }
    }

    // net/http server checks
    if major != 1 {
        return Err(HttpReject::error(
            505,
            Some("unsupported protocol version"),
            "unsupported protocol version",
        ));
    }
    let host = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.as_str());
    match host {
        None if minor >= 1 && method != "CONNECT" => {
            return Err(HttpReject::error(
                400,
                Some("missing required Host header"),
                "missing required Host header",
            ))
        }
        Some(h) if !valid_host_header(h) => {
            return Err(HttpReject::error(
                400,
                Some("malformed Host header"),
                "malformed Host header",
            ))
        }
        _ => {}
    }
    if bad_name {
        return Err(HttpReject::error(
            400,
            Some("invalid header name"),
            "invalid header name",
        ));
    }
    if let Some(expect) = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("expect"))
        .map(|(_, v)| v.as_str())
    {
        if !expect.eq_ignore_ascii_case("100-continue") && !expect.is_empty() {
            return Err(HttpReject::error(417, None, "unsupported Expect"));
        }
    }
    if force_close
        && !headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("connection") && v.eq_ignore_ascii_case("close"))
    {
        headers.retain(|(k, _)| !k.eq_ignore_ascii_case("connection"));
        headers.push(("Connection".to_string(), "close".to_string()));
    }
    let query = raw_query.as_deref().map(parse_query).unwrap_or_default();
    conn.set_response_style(minor == 0, method == "HEAD");
    Ok(Some(Request {
        method: method.to_string(),
        path,
        query,
        version: format!("HTTP/{major}.{minor}"),
        headers,
        body: Vec::new(),
    }))
}

pub fn read_request_body(
    conn: &mut BufferedConn,
    req: &mut Request,
    max_body: usize,
) -> io::Result<()> {
    let has_body = header(&req.headers, "transfer-encoding").is_some()
        || header(&req.headers, "content-length").is_some_and(|v| v != "0");
    if has_body
        && req.version == "HTTP/1.1"
        && header(&req.headers, "expect").is_some_and(|v| v.eq_ignore_ascii_case("100-continue"))
    {
        conn.write_all(b"HTTP/1.1 100 Continue\r\n\r\n")?;
        conn.flush()?;
    }
    if header(&req.headers, "transfer-encoding").is_some() {
        req.body = read_chunked(conn, max_body)?;
    } else if let Some(len) = header(&req.headers, "content-length") {
        let n: usize = len.parse().map_err(|_| invalid("invalid content-length"))?;
        if n > max_body {
            return Err(invalid("request body too large"));
        }
        if n > 0 {
            req.body = conn.read_exact_vec(n)?;
        }
    }
    Ok(())
}

fn parse_query(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|s| !s.is_empty())
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let k = crate::net::percent_decode(k).ok()?;
            let v = crate::net::percent_decode(v).ok()?;
            Some((k, v))
        })
        .collect()
}

fn read_chunked(conn: &mut BufferedConn, max_body: usize) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line = conn.read_line(1024)?;
        let size_str = line.split(';').next().unwrap_or("").trim();
        let size =
            usize::from_str_radix(size_str, 16).map_err(|_| invalid("invalid chunk size"))?;
        if size == 0 {
            // Trailers share the 16 KiB head budget.
            let mut trailer_total = 0usize;
            loop {
                let t = conn.read_line(MAX_HEAD)?;
                trailer_total += t.len() + 2;
                if trailer_total > MAX_HEAD {
                    return Err(invalid("trailers too large"));
                }
                if t.is_empty() {
                    break;
                }
            }
            return Ok(body);
        }
        // `size` comes straight off the wire, so it has to be bounded *before*
        // it takes part in any arithmetic. `body.len() + size` overflows: debug
        // panics, and release wraps to a small number that passes the check and
        // then asks `read_exact_vec` for an unbounded read — a remote OOM with
        // no token required, because this runs before authentication.
        if size > max_body || body.len() > max_body - size {
            return Err(invalid("chunked body too large"));
        }
        body.extend_from_slice(&conn.read_exact_vec(size)?);
        // Trailing CRLF after the chunk data must be exactly CRLF.
        let line = conn.read_line(8)?;
        if !line.is_empty() {
            return Err(invalid("missing chunk CRLF"));
        }
    }
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

/// `Date` header value in RFC 7231 IMF-fixdate (`Mon, 02 Jan 2006 15:04:05 GMT`).
pub fn http_date(t: std::time::SystemTime) -> String {
    let secs = t
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // civil_from_days (Howard Hinnant)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    const WD: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MO: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        WD[days.rem_euclid(7) as usize],
        d,
        MO[(m - 1) as usize],
        y,
        rem / 3600,
        (rem / 60) % 60,
        rem % 60
    )
}

fn response_head(
    conn: &BufferedConn,
    status: u16,
    headers: &[(String, String)],
    keep_alive: bool,
) -> String {
    let (http10, _) = conn.response_style();
    let mut head = format!(
        "HTTP/1.{} {} {}\r\n",
        if http10 { 0 } else { 1 },
        status,
        reason(status)
    );
    let mut has_connection = false;
    let mut has_date = false;
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("connection") {
            if has_connection {
                continue;
            }
            has_connection = true;
        }
        has_date |= k.eq_ignore_ascii_case("date");
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    if !has_date {
        head.push_str(&format!(
            "Date: {}\r\n",
            http_date(std::time::SystemTime::now())
        ));
    }
    if !has_connection {
        if !keep_alive {
            if !http10 {
                head.push_str("Connection: close\r\n");
            }
        } else if http10 {
            head.push_str("Connection: keep-alive\r\n");
        }
    }
    head
}

pub fn write_response(
    conn: &mut BufferedConn,
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
    keep_alive: bool,
) -> io::Result<()> {
    let mut head = response_head(conn, status, headers, keep_alive);
    let head_request = conn.response_style().1;
    if !headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        && !(head_request && body.is_empty())
    {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    let mut out = head.into_bytes();
    if !conn.response_style().1 {
        out.extend_from_slice(body);
    }
    conn.write_all(&out)?;
    conn.flush()
}

pub const COMPAT_CHUNKING_THRESHOLD: usize = 2048;

pub fn write_response_spec_framed(
    conn: &mut BufferedConn,
    status: u16,
    headers: &[(String, String)],
    body: &[u8],
    keep_alive: bool,
) -> io::Result<()> {
    if body.len() <= COMPAT_CHUNKING_THRESHOLD {
        return write_response(conn, status, headers, body, keep_alive);
    }
    let head_request = conn.response_style().1;
    let http10 = conn.response_style().0;
    let keep_alive = keep_alive && !http10;
    let mut head = response_head(conn, status, headers, keep_alive);
    if !head_request && !http10 {
        head.push_str("Transfer-Encoding: chunked\r\n");
    }
    head.push_str("\r\n");
    let mut out = head.into_bytes();
    if !head_request {
        if http10 {
            out.extend_from_slice(body);
        } else {
            out.extend_from_slice(format!("{:x}\r\n", body.len()).as_bytes());
            out.extend_from_slice(body);
            out.extend_from_slice(b"\r\n0\r\n\r\n");
        }
    }
    conn.write_all(&out)?;
    conn.flush()
}

/// Writes a response head for a streamed body (SSE): no length, the body is
/// delimited by the connection closing.
pub fn write_stream_head(
    conn: &mut BufferedConn,
    status: u16,
    headers: &[(String, String)],
) -> io::Result<()> {
    let mut head = response_head(conn, status, headers, false);
    head.push_str("\r\n");
    conn.write_all(head.as_bytes())?;
    conn.flush()
}

/// Writes the 101 handshake response and leaves the socket for WebSocket use.
pub fn write_upgrade(conn: &mut BufferedConn, headers: &[(String, String)]) -> io::Result<()> {
    let mut head = String::from("HTTP/1.1 101 Switching Protocols\r\n");
    for (k, v) in headers {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    conn.write_all(head.as_bytes())?;
    conn.flush()
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::time::Duration;

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

    fn run_http1_fuzz(iterations: usize) {
        let mut rng = FuzzRng(0x8f31_6a2d_7419_c5e7);
        for iteration in 0..iterations {
            let mut raw = rng.bytes(160);
            match iteration % 4 {
                1 => {
                    raw = b"GET /".to_vec();
                    raw.extend_from_slice(&rng.bytes(40));
                    raw.extend_from_slice(b" HTTP/1.1\r\nHost: x\r\nX-Fuzz: ");
                    raw.extend_from_slice(&rng.bytes(80));
                    raw.extend_from_slice(b"\r\n\r\n");
                }
                2 => {
                    raw = b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
                        .to_vec();
                    raw.extend_from_slice(&rng.bytes(80));
                }
                3 => {
                    raw = b"GET /?x=".to_vec();
                    raw.extend_from_slice(&rng.bytes(80));
                    raw.extend_from_slice(b" HTTP/1.1\r\nHost: x\r\nContent-Length: ");
                    raw.extend_from_slice(&rng.bytes(24));
                    raw.extend_from_slice(b"\r\n\r\n");
                }
                _ => {}
            }
            assert!(raw.len() <= 256, "fuzz input must stay bounded");
            let mut conn = conn_from(&raw);
            let _ = read_request(&mut conn, 256);
        }
    }

    #[test]
    fn fuzz_http1_parser() {
        run_http1_fuzz(100_000);
    }

    #[test]
    #[ignore = "one-million iteration parser fuzz run"]
    fn fuzz_http1_parser_long() {
        run_http1_fuzz(1_000_000);
    }

    /// A connection backed by a byte slice, so the parser can be driven
    /// without a socket.
    struct SliceConn {
        data: Vec<u8>,
        pos: usize,
    }

    impl Read for SliceConn {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = (self.data.len() - self.pos).min(buf.len());
            buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    impl Write for SliceConn {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl crate::net::Conn for SliceConn {
        fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
        fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
        fn try_clone(&self) -> io::Result<Box<dyn crate::net::Conn>> {
            Err(io::Error::other("not cloneable"))
        }
        fn shutdown_write(&self) -> io::Result<()> {
            Ok(())
        }
        fn shutdown_both(&self) -> io::Result<()> {
            Ok(())
        }
        fn describe(&self) -> String {
            "slice".to_string()
        }
    }

    fn conn_from(raw: &[u8]) -> BufferedConn {
        BufferedConn::new(SliceConn {
            data: raw.to_vec(),
            pos: 0,
        })
    }

    /// Records every write call, so a test can see how a response was split.
    #[derive(Clone)]
    struct WriteLog(std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>);

    impl Read for WriteLog {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }

    impl Write for WriteLog {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().push(buf.to_vec());
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl crate::net::Conn for WriteLog {
        fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
        fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
        fn try_clone(&self) -> io::Result<Box<dyn crate::net::Conn>> {
            Ok(Box::new(self.clone()))
        }
        fn shutdown_write(&self) -> io::Result<()> {
            Ok(())
        }
        fn shutdown_both(&self) -> io::Result<()> {
            Ok(())
        }
        fn describe(&self) -> String {
            "write-log".to_string()
        }
    }

    #[test]
    fn fixed_body_response_is_written_in_one_write() {
        let log = WriteLog(Default::default());
        let mut conn = BufferedConn::new(log.clone());
        let body = br#"{"ack_up_offset":"42"}"#;
        write_response(
            &mut conn,
            200,
            &[("Content-Type".to_string(), "application/json".to_string())],
            body,
            true,
        )
        .unwrap();
        let writes = log.0.lock().unwrap();
        assert_eq!(writes.len(), 1, "head and body must leave in one write");
        assert!(writes[0].starts_with(b"HTTP/1.1 200 "));
        assert!(writes[0].ends_with(body));
    }

    #[test]
    fn parses_query_pairs() {
        let q = parse_query("epoch=1&x=a%2Fb");
        assert_eq!(q[0], ("epoch".into(), "1".into()));
        assert_eq!(q[1], ("x".into(), "a/b".into()));
    }

    #[test]
    fn reads_a_chunked_body() {
        let raw = b"POST /v1/sessions HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n\
                    5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let mut conn = conn_from(raw);
        let req = read_request(&mut conn, 64 * 1024).unwrap().unwrap();
        assert_eq!(req.body, b"hello world");
    }

    /// A chunk size straight off the wire must not reach the addition in
    /// `body.len() + size`: `0xFFFF_FFFF_FFFF_FFFF` overflows, which panics in a
    /// debug build and wraps in a release build — and a wrapped size passes the
    /// limit check, so the reader then allocates as fast as the peer sends.
    #[test]
    fn a_chunk_size_that_would_overflow_is_refused() {
        let raw = b"POST /v1/sessions HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n\
                    FFFFFFFFFFFFFFFF\r\n";
        let mut conn = conn_from(raw);
        let err = read_request(&mut conn, 64 * 1024).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    /// The same bug reached through accumulation rather than a single chunk.
    #[test]
    fn chunks_that_add_up_past_the_limit_are_refused() {
        let mut raw = Vec::new();
        raw.extend_from_slice(
            b"POST /v1/sessions HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n",
        );
        for _ in 0..4 {
            raw.extend_from_slice(b"1000\r\n");
            raw.extend_from_slice(&[b'x'; 0x1000]);
            raw.extend_from_slice(b"\r\n");
        }
        let mut conn = conn_from(&raw);
        let err = read_request(&mut conn, 3 * 0x1000).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn conflicting_content_length_rejected() {
        let raw = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\n";
        assert!(read_request_head(&mut conn_from(raw)).is_err());
    }

    #[test]
    fn cl_and_te_chunked_wins_and_closes() {
        let raw = b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n";
        let req = read_request_head(&mut conn_from(raw)).unwrap().unwrap();
        assert!(req.header("content-length").is_none());
        assert_eq!(req.header("connection"), Some("close"));
    }

    #[test]
    fn te_must_end_with_chunked() {
        let raw = b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, gzip\r\n\r\n";
        assert!(read_request_head(&mut conn_from(raw)).is_err());
    }

    #[test]
    fn chunk_missing_crlf_rejected() {
        let raw = b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcXX\r\n0\r\n\r\n";
        let err = read_request(&mut conn_from(raw), 1024).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn trailer_limit() {
        let mut raw =
            b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n".to_vec();
        raw.extend(std::iter::repeat_n(b'x', MAX_HEAD));
        raw.extend_from_slice(b"\r\n\r\n");
        let err = read_request(&mut conn_from(&raw), 1024).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn request_head_limit_is_respected() {
        let mut raw = b"GET / HTTP/1.1\r\nHost: x\r\nX-Pad: ".to_vec();
        raw.extend(std::iter::repeat_n(b'x', 13 * 1024));
        raw.extend_from_slice(b"\r\n\r\n");
        let err = read_request_head_with_limit(&mut conn_from(&raw), 8 * 1024).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    fn reject(raw: &[u8]) -> Option<(u16, Option<&'static str>)> {
        match read_request_head(&mut conn_from(raw)) {
            Ok(_) => None,
            Err(e) => reject_of(&e).map(|r| (r.status, r.detail)),
        }
    }

    #[test]
    #[allow(clippy::type_complexity)]
    fn request_refusals_match_spec_net_http() {
        let p = |d| Some((400u16, Some(d)));
        let plain = Some((400u16, None));
        let cases: Vec<(&[u8], Option<(u16, Option<&str>)>)> = vec![
            (
                b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5, 10\r\n\r\n",
                plain,
            ),
            (
                b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5, 5\r\n\r\n",
                plain,
            ),
            (
                b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: +5\r\n\r\n",
                plain,
            ),
            (
                b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: -1\r\n\r\n",
                plain,
            ),
            (
                b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n",
                plain,
            ),
            (
                b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\n\r\n",
                Some((501, None)),
            ),
            (
                b"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, chunked\r\n\r\n",
                Some((501, None)),
            ),
            (
                b"GET /x HTTP/1.1\r\n\r\n",
                p("missing required Host header"),
            ),
            (b"GET /x HTTP/1.1\r\nHost: x\r\nHost: x\r\n\r\n", plain),
            (
                b"GET /x HTTP/1.1\r\nHost: a b\r\n\r\n",
                p("malformed Host header"),
            ),
            (
                b"GET /x HTTP/1.1\r\nHost: x\r\nBad Header: x\r\n\r\n",
                p("invalid header name"),
            ),
            (
                b"GET /x HTTP/1.1\r\nHost: x\r\nX-A : b\r\n\r\n",
                p("invalid header name"),
            ),
            (b"GET /x HTTP/1.1\r\nHost: x\r\nNoColon\r\n\r\n", plain),
            (b"GET /x HTTP/1.1\r\nHost: x\r\nX-A: a\x01b\r\n\r\n", plain),
            (b"FOO\r\n\r\n", plain),
            (b"GET /x HTTP/1.x\r\nHost: x\r\n\r\n", plain),
            (
                b"GET /x HTTP/2.0\r\nHost: x\r\n\r\n",
                Some((505, Some("unsupported protocol version"))),
            ),
            (b"GET nope HTTP/1.1\r\nHost: x\r\n\r\n", plain),
            (b"GET /a%zz HTTP/1.1\r\nHost: x\r\n\r\n", plain),
            (
                b"POST / HTTP/1.1\r\nHost: x\r\nExpect: foo\r\n\r\n",
                Some((417, None)),
            ),
            (b"GET /x HTTP/1.0\r\n\r\n", None),
            (b"GET /x HTTP/1.2\r\nHost: x\r\n\r\n", None),
            (b"get /x HTTP/1.1\r\nHost: x\r\n\r\n", None),
            (b"OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n", None),
            (b"GET http://x/nope HTTP/1.1\r\nHost: x\r\n\r\n", None),
            (b"CONNECT x:443 HTTP/1.1\r\nHost: x\r\n\r\n", None),
            (b"GET /x?a=%zz HTTP/1.1\r\nHost: x\r\n\r\n", None),
            (b"GET /x HTTP/1.1\nHost: x\n\n", None),
            (b"GET /x HTTP/1.1\r\nHost: x\r\nX-A: a\r\n b\r\n\r\n", None),
            (
                b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\n",
                None,
            ),
            (
                b"POST / HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\nContent-Length: 0\r\n\r\n",
                None,
            ),
        ];
        for (raw, want) in cases {
            assert_eq!(reject(raw), want, "{}", String::from_utf8_lossy(raw));
        }
        let mut big = b"GET /x HTTP/1.1\r\nHost: x\r\nX-Big: ".to_vec();
        big.extend(std::iter::repeat_n(b'a', MAX_HEAD + 4096));
        big.extend_from_slice(b"\r\n\r\n");
        assert_eq!(reject(&big), Some((431, None)));
    }

    #[test]
    fn parsed_request_uses_spec_routing_view() {
        let req = read_request_head(&mut conn_from(
            b"GET http://h/v1/a%2Fb?x=1 HTTP/1.1\r\nHost: x\r\nX-A: a\r\n  b\r\n\r\n",
        ))
        .unwrap()
        .unwrap();
        assert_eq!(req.path, "/v1/a/b");
        assert_eq!(req.query("x"), Some("1"));
        assert_eq!(req.header("x-a"), Some("a b"));
    }

    #[test]
    fn spec_refusal_bytes() {
        let r = HttpReject {
            status: 400,
            detail: Some("missing required Host header"),
            reason: String::new(),
        };
        assert_eq!(
            r.raw(),
            b"HTTP/1.1 400 Bad Request: missing required Host header\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request: missing required Host header".to_vec()
        );
        let r = HttpReject {
            status: 501,
            detail: None,
            reason: String::new(),
        };
        assert!(r.raw().ends_with(b"\r\n\r\nUnsupported transfer encoding"));
    }

    #[test]
    fn http_date_is_imf_fixdate() {
        let t = |s| http_date(std::time::UNIX_EPOCH + std::time::Duration::from_secs(s));
        assert_eq!(t(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(t(1_793_336_653), "Fri, 30 Oct 2026 05:04:13 GMT");
        assert_eq!(t(951_782_400), "Tue, 29 Feb 2000 00:00:00 GMT");
    }

    #[test]
    fn response_has_one_connection_header_and_no_head_body() {
        let log = WriteLog(std::sync::Arc::new(std::sync::Mutex::new(Vec::new())));
        let mut conn = BufferedConn::new(log.clone());
        let hdrs = vec![("Connection".to_string(), "close".to_string())];
        write_response(&mut conn, 404, &hdrs, b"{}\n", false).unwrap();
        conn.set_response_style(true, true);
        write_response(&mut conn, 200, &[], b"body", true).unwrap();
        let writes = log.0.lock().unwrap();
        let first = String::from_utf8_lossy(&writes[0]).to_string();
        assert_eq!(first.matches("Connection:").count(), 1, "{first}");
        assert!(first.contains("\r\nDate: "));
        assert!(!first.contains("keep-alive"));
        let second = String::from_utf8_lossy(&writes[1]).to_string();
        assert!(second.starts_with("HTTP/1.0 200 OK\r\n"), "{second}");
        assert!(second.contains("Connection: keep-alive\r\n"));
        assert!(second.ends_with("Content-Length: 4\r\n\r\n"), "{second}");
    }
}
