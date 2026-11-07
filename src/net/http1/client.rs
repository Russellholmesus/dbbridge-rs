//! The client half: one request at a time, over a pooled connection.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::ClientTls;
use crate::error::{Error, Result};
use crate::net::{header, BufferedConn, Conn, Url};
use crate::resource::budget::BudgetLease;
use crate::resource::manager::ResourceManager;
use crate::wire;

use super::{body::BodyReader, read_chunked, MAX_HEAD};

/// Keep pooled HTTP/1 streams shorter than the egress server's 5 s idle read timeout.
const IDLE_CONN_TTL: Duration = Duration::from_secs(4);

struct IdleConnection {
    returned_at: Instant,
    stream: Box<dyn Conn>,
    resource_leases: Vec<BudgetLease>,
}

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        header(&self.headers, name)
    }
}

/// How a peer client opens the connection one request runs on.
///
/// Forward mode connects to the endpoint's address. Reverse mode opens a
/// stream on the tunnel the peer dialed in, and the address only names the
/// virtual endpoint, so it is never resolved.
pub trait Dialer: Send + Sync {
    fn dial(&self, url: &Url, timeout: Duration) -> Result<Box<dyn Conn>>;
}

/// The forward-mode dialer: a TCP connect to the endpoint.
struct TcpDialer {
    #[allow(dead_code)]
    tls: ClientTls,
}

impl Dialer for TcpDialer {
    fn dial(&self, url: &Url, timeout: Duration) -> Result<Box<dyn Conn>> {
        crate::net::dial(&url.host, url.port, timeout)
            .and_then(|s| {
                if url.is_tls() {
                    #[cfg(feature = "tls")]
                    {
                        let config = crate::net::tls::client_config(
                            self.tls.ca_file.as_deref(),
                            self.tls.verify,
                        )
                        .map_err(|e| std::io::Error::other(format!("TLS config: {e}")))?;
                        crate::net::tls::TlsConn::connect_with_config(
                            s,
                            &url.host,
                            std::sync::Arc::new(config),
                            timeout,
                        )
                        .map(|c| Box::new(c) as Box<dyn Conn>)
                        .map_err(|e| std::io::Error::new(e.kind(), format!("TLS handshake: {e}")))
                    }
                    #[cfg(not(feature = "tls"))]
                    {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::Unsupported,
                            "TLS support not compiled in",
                        ))
                    }
                } else {
                    Ok(Box::new(s) as Box<dyn Conn>)
                }
            })
            .map_err(|e| Error::local(format!("connect {}: {e}", url.authority())))
    }
}

/// A pooled HTTP/1.1 client. Control requests are short and frequent, so
/// reusing a connection per peer saves a handshake on every ack.
pub struct Client {
    idle: Mutex<HashMap<String, Vec<IdleConnection>>>,
    connect_timeout: Duration,
    request_timeout: Duration,
    dialer: Mutex<Arc<dyn Dialer>>,
    resource_manager: Mutex<Option<Arc<ResourceManager>>>,
    #[cfg(feature = "h2")]
    h2_pool: Mutex<Option<Arc<super::h2::H2Pool>>>,
}

impl Client {
    pub fn new(connect_timeout: Duration, request_timeout: Duration) -> Self {
        Self::new_with_tls(
            connect_timeout,
            request_timeout,
            ClientTls {
                verify: true,
                ..ClientTls::default()
            },
        )
    }

    pub fn new_with_tls(
        connect_timeout: Duration,
        request_timeout: Duration,
        tls: ClientTls,
    ) -> Self {
        Client {
            idle: Mutex::new(HashMap::new()),
            connect_timeout,
            request_timeout,
            dialer: Mutex::new(Arc::new(TcpDialer { tls })),
            resource_manager: Mutex::new(None),
            #[cfg(feature = "h2")]
            h2_pool: Mutex::new(None),
        }
    }

    pub fn with_h2_pool_size(self, size: u32) -> Self {
        let _ = size;
        self
    }

    pub fn new_with_tls_and_h2(
        connect_timeout: Duration,
        request_timeout: Duration,
        tls: ClientTls,
        pool_size: u32,
        heartbeat: Duration,
    ) -> Self {
        #[cfg(not(feature = "h2"))]
        {
            let _ = pool_size;
            let _ = heartbeat;
            Self::new_with_tls(connect_timeout, request_timeout, tls)
        }
        #[cfg(feature = "h2")]
        {
            let c = Self::new_with_tls(connect_timeout, request_timeout, tls.clone());
            *c.h2_pool.lock().unwrap() =
                super::h2::H2Pool::new(pool_size, connect_timeout, heartbeat, tls).map(Arc::new);
            c
        }
    }

    /// Replaces how this client opens connections, for a reverse peer.
    pub fn set_dialer(&self, d: Arc<dyn Dialer>) {
        *self.dialer.lock().unwrap() = d;
        #[cfg(feature = "h2")]
        {
            *self.h2_pool.lock().unwrap() = None;
        }
    }

    pub fn set_resource_manager(&self, resources: Arc<ResourceManager>) {
        *self
            .resource_manager
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(resources.clone());
        #[cfg(feature = "h2")]
        if let Some(pool) = self
            .h2_pool
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            pool.set_resource_manager(resources);
        }
    }

    /// The dialer this client opens connections with.
    pub fn dialer(&self) -> Arc<dyn Dialer> {
        self.dialer.lock().unwrap().clone()
    }

    fn take_idle(&self, authority: &str) -> Option<(Box<dyn Conn>, Vec<BudgetLease>)> {
        let mut map = self.idle.lock().unwrap();
        let slot = map.get_mut(authority)?;
        while let Some(idle) = slot.pop() {
            if idle.returned_at.elapsed() < IDLE_CONN_TTL {
                return Some((idle.stream, idle.resource_leases));
            }
        }
        None
    }

    fn put_idle(&self, authority: &str, stream: Box<dyn Conn>, resource_leases: Vec<BudgetLease>) {
        let mut map = self.idle.lock().unwrap();
        let slot = map.entry(authority.to_string()).or_default();
        // Bound the pool: a handful of connections covers control traffic.
        if slot.len() < 4 {
            slot.push(IdleConnection {
                returned_at: Instant::now(),
                stream,
                resource_leases,
            });
        }
    }

    fn acquire_connection_leases(&self, data: bool) -> Result<Vec<BudgetLease>> {
        self.acquire_connection_leases_with_timeout(data, self.request_timeout)
    }

    fn acquire_data_request_leases(&self) -> Result<Vec<BudgetLease>> {
        let Some(resources) = self.resource_manager_handle() else {
            return Ok(Vec::new());
        };
        resources.mark_instrumented("data_requests");
        let request = resources
            .data_requests
            .acquire_timeout(1, Some(self.request_timeout))
            .map_err(|_| {
                Error::new(wire::ERR_QUOTA_EXCEEDED, "data request budget").retryable(true)
            })?;
        Ok(vec![request])
    }

    pub(crate) fn acquire_data_connection_leases(
        &self,
        timeout: Duration,
    ) -> Result<Vec<BudgetLease>> {
        self.acquire_connection_leases_with_timeout(true, timeout)
    }

    pub(crate) fn resource_manager_handle(&self) -> Option<Arc<ResourceManager>> {
        self.resource_manager
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    pub(crate) fn acquire_data_connection_leases_from(
        resources: &ResourceManager,
        timeout: Duration,
    ) -> Result<Vec<BudgetLease>> {
        resources.mark_instrumented("data_connections");
        resources.mark_instrumented("metadata");
        let connection = resources
            .data_connections
            .acquire_timeout(1, Some(timeout))
            .map_err(|_| {
                Error::new(wire::ERR_QUOTA_EXCEEDED, "data connection budget").retryable(true)
            })?;
        let metadata = resources
            .metadata
            .acquire_timeout(8 << 10, Some(timeout))
            .map_err(|_| {
                Error::new(wire::ERR_QUOTA_EXCEEDED, "data connection metadata budget")
                    .retryable(true)
            })?;
        Ok(vec![connection, metadata])
    }

    fn acquire_connection_leases_with_timeout(
        &self,
        data: bool,
        timeout: Duration,
    ) -> Result<Vec<BudgetLease>> {
        let resources = self
            .resource_manager
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let Some(resources) = resources else {
            return Ok(Vec::new());
        };
        let (connection_name, connections, metadata) = if data {
            resources.mark_instrumented("data_connections");
            ("data", &resources.data_connections, &resources.metadata)
        } else {
            resources.mark_instrumented("control_connections");
            resources.mark_instrumented("control_metadata");
            (
                "control",
                &resources.control_connections,
                &resources.control_metadata,
            )
        };
        let timeout = Some(timeout);
        let connection = connections.acquire_timeout(1, timeout).map_err(|_| {
            Error::new(
                crate::wire::ERR_QUOTA_EXCEEDED,
                format!("{connection_name} connection budget"),
            )
            .retryable(true)
        })?;
        let metadata = metadata.acquire_timeout(8 << 10, timeout).map_err(|_| {
            Error::new(
                crate::wire::ERR_QUOTA_EXCEEDED,
                format!("{connection_name} connection metadata"),
            )
            .retryable(true)
        })?;
        Ok(vec![connection, metadata])
    }

    pub fn drop_idle(&self, authority: &str) {
        let mut map = self.idle.lock().unwrap();
        map.remove(authority);
    }

    /// Sends a request and reads the whole response.
    pub fn request(
        &self,
        url: &Url,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
    ) -> Result<Response> {
        self.request_within(url, method, path, headers, body, self.request_timeout)
    }

    /// `request` bounded by `timeout` instead of the client's request timeout
    /// (a health probe is bounded by the peer's `healthcheck_timeout`).
    pub fn request_within(
        &self,
        url: &Url,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<Response> {
        let authority = url.authority();
        let mut attempt = 0;
        loop {
            attempt += 1;
            let reused = self.take_idle(&authority);
            let fresh = reused.is_none();
            let (stream, resource_leases) = match reused {
                Some((stream, leases)) => (stream, leases),
                None => {
                    let leases = self.acquire_connection_leases(false)?;
                    let stream = self.dialer().dial(url, self.connect_timeout.min(timeout))?;
                    (stream, leases)
                }
            };
            let mut conn = BufferedConn::from_boxed(stream);
            conn.set_read_timeout(Some(timeout))?;
            conn.set_write_timeout(Some(timeout))?;
            match self.exchange(&mut conn, url, method, path, headers, body) {
                Ok((resp, keep_alive)) => {
                    if keep_alive {
                        if let Ok(s) = conn.try_clone() {
                            self.put_idle(&authority, s, resource_leases);
                        }
                    }
                    return Ok(resp);
                }
                Err((e, head_written)) => {
                    if !fresh
                        && attempt < 2
                        && (!head_written || (e.is_local() && !method.eq_ignore_ascii_case("POST")))
                    {
                        if !head_written {
                            // Its pool siblings are as stale as it was.
                            self.drop_idle(&authority);
                        }
                        continue;
                    }
                    return Err(e);
                }
            }
        }
    }

    fn exchange(
        &self,
        conn: &mut BufferedConn,
        url: &Url,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
    ) -> std::result::Result<(Response, bool), (Error, bool)> {
        let mut head_written = false;
        self.exchange_inner(conn, url, method, path, headers, body, &mut head_written)
            .map_err(|e| (e, head_written))
    }

    #[allow(clippy::too_many_arguments)]
    fn exchange_inner(
        &self,
        conn: &mut BufferedConn,
        url: &Url,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
        head_written: &mut bool,
    ) -> Result<(Response, bool)> {
        let mut head = format!("{method} {} HTTP/1.1\r\n", url.path(path));
        head.push_str(&format!("Host: {}\r\n", url.authority()));
        let mut has_ua = false;
        for (k, v) in headers {
            if k.eq_ignore_ascii_case("host") || k.eq_ignore_ascii_case("content-length") {
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
        if let Some(b) = body {
            head.push_str(&format!("Content-Length: {}\r\n", b.len()));
        }
        head.push_str("Connection: keep-alive\r\n\r\n");
        // A failure of the very first write means nothing reached the peer.
        let first = conn.write(head.as_bytes())?;
        *head_written = true;
        conn.write_all(&head.as_bytes()[first..])?;
        if let Some(b) = body {
            conn.write_all(b)?;
        }
        conn.flush()?;

        let (status, headers) = read_response_head(conn)?;
        let mut keep_alive = header(&headers, "connection")
            .map(|v| !v.eq_ignore_ascii_case("close"))
            .unwrap_or(true);
        let (body, framed) = read_body(conn, status, &headers)?;
        if !framed {
            keep_alive = false;
        }
        Ok((
            Response {
                status,
                headers,
                body,
            },
            keep_alive,
        ))
    }

    /// Sends a request and returns the connection positioned at the body, for
    /// streamed responses (SSE).
    ///
    /// `idle_timeout` replaces the request timeout once the response head has
    /// arrived. A stream is idle by design between heartbeats, so bounding it
    /// by the request timeout would tear down a healthy session; the idle
    /// timeout is what the caller's failure detector needs to get a turn.
    pub fn stream(
        &self,
        url: &Url,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        idle_timeout: Duration,
    ) -> Result<(BodyReader, Response)> {
        let mut request_leases = self.acquire_data_request_leases()?;
        #[cfg(feature = "h2")]
        if url.is_tls() {
            if let Some(pool) = self.h2_pool.lock().unwrap().clone() {
                if let Ok((body, response)) = pool.stream(url, method, path, headers, idle_timeout)
                {
                    let body = body.hold_resource_leases(request_leases);
                    return Ok((body, response));
                }
            }
        }
        // Same dialer as `request`: an SSE stream to a reverse peer has to
        // travel inside its tunnel too, not to a host that never resolves.
        request_leases.extend(self.acquire_connection_leases(true)?);
        let stream = self.dialer().dial(url, self.connect_timeout)?;
        let mut conn = BufferedConn::from_boxed(stream);
        conn.set_read_timeout(Some(self.request_timeout))?;
        conn.set_write_timeout(Some(self.request_timeout))?;

        let mut head = format!("{method} {} HTTP/1.1\r\n", url.path(path));
        head.push_str(&format!("Host: {}\r\n", url.authority()));
        let mut has_ua = false;
        for (k, v) in headers {
            if k.eq_ignore_ascii_case("host") {
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
        head.push_str("Connection: close\r\n\r\n");
        conn.write_all(head.as_bytes())?;
        conn.flush()?;

        let (status, headers) = read_response_head(&mut conn)?;
        let error_body = if !(200..300).contains(&status) {
            read_body(&mut conn, status, &headers)?.0
        } else {
            Vec::new()
        };
        let body = BodyReader::new(conn, &headers).hold_resource_leases(request_leases);
        body.set_read_timeout(Some(idle_timeout))?;
        Ok((
            body,
            Response {
                status,
                headers,
                body: error_body,
            },
        ))
    }
}

pub fn read_response_head(conn: &mut BufferedConn) -> Result<(u16, Vec<(String, String)>)> {
    let line = conn.read_line(MAX_HEAD)?;
    let mut parts = line.split_whitespace();
    let version = parts.next().unwrap_or("");
    if !version.starts_with("HTTP/1.") {
        return Err(Error::local(format!("malformed status line {line:?}")));
    }
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| Error::local("malformed status code"))?;
    let mut headers = Vec::new();
    let mut total = line.len();
    loop {
        let h = conn.read_line(MAX_HEAD)?;
        total += h.len() + 2;
        if total > MAX_HEAD {
            return Err(Error::local("response head too large"));
        }
        if h.is_empty() {
            break;
        }
        if let Some((k, v)) = h.split_once(':') {
            headers.push((k.to_string(), v.trim().to_string()));
        }
    }
    Ok((status, headers))
}

pub(crate) fn read_body(
    conn: &mut BufferedConn,
    status: u16,
    headers: &[(String, String)],
) -> Result<(Vec<u8>, bool)> {
    if (100..200).contains(&status) || status == 204 || status == 304 {
        return Ok((Vec::new(), true));
    }
    if header(headers, "transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
    {
        return read_chunked(conn, 64 << 20)
            .map(|b| (b, true))
            .map_err(Error::from);
    }
    if let Some(v) = header(headers, "content-length") {
        let n = v
            .trim()
            .parse::<usize>()
            .map_err(|_| Error::local("invalid content-length"))?;
        return conn
            .read_exact_vec(n)
            .map(|b| (b, true))
            .map_err(Error::from);
    }
    let mut out = Vec::new();
    loop {
        let n = conn.fill()?;
        if n == 0 {
            break;
        }
        out.extend_from_slice(&conn.take_buffered());
    }
    Ok((out, false))
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor, Read, Write};
    use std::time::Duration;

    use super::{Client, Dialer};
    use crate::error::Result;
    use crate::net::{Conn, Url};

    struct StaticConn(Cursor<Vec<u8>>);

    impl Read for StaticConn {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    impl Write for StaticConn {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Conn for StaticConn {
        fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
        fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
        fn try_clone(&self) -> io::Result<Box<dyn Conn>> {
            Err(io::Error::other("not cloneable"))
        }
        fn shutdown_write(&self) -> io::Result<()> {
            Ok(())
        }
        fn shutdown_both(&self) -> io::Result<()> {
            Ok(())
        }
        fn describe(&self) -> String {
            "static test connection".to_string()
        }
    }

    struct StaticDialer(Vec<u8>);

    impl Dialer for StaticDialer {
        fn dial(&self, _: &Url, _: Duration) -> Result<Box<dyn Conn>> {
            Ok(Box::new(StaticConn(Cursor::new(self.0.clone()))))
        }
    }

    fn client_with_response(response: &[u8]) -> Client {
        let client = Client::new(Duration::from_secs(1), Duration::from_secs(1));
        client.set_dialer(std::sync::Arc::new(StaticDialer(response.to_vec())));
        client
    }

    #[test]
    fn idle_connections_expire_before_server_idle_timeout() {
        let client = client_with_response(b"");
        client.idle.lock().unwrap().insert(
            "peer.example:80".to_string(),
            vec![super::IdleConnection {
                returned_at: std::time::Instant::now()
                    - super::IDLE_CONN_TTL
                    - Duration::from_millis(1),
                stream: Box::new(StaticConn(Cursor::new(Vec::new()))),
                resource_leases: Vec::new(),
            }],
        );
        assert!(client.take_idle("peer.example:80").is_none());

        client.put_idle(
            "peer.example:80",
            Box::new(StaticConn(Cursor::new(Vec::new()))),
            Vec::new(),
        );
        assert!(client.take_idle("peer.example:80").is_some());
    }

    #[test]
    fn client_bad_content_length_not_pooled() {
        let client = client_with_response(b"HTTP/1.1 200 OK\r\nContent-Length: nope\r\n\r\n");
        let url = Url::parse("http://example.test").unwrap();
        assert!(client.request(&url, "GET", "/", &[], None).is_err());
        assert!(client.idle.lock().unwrap().is_empty());
    }

    #[test]
    fn client_reads_error_body_of_sse_get() {
        let body = br#"{"code":"DBB_UNAUTHORIZED"}"#;
        let response = format!(
            "HTTP/1.1 401 Unauthorized\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            std::str::from_utf8(body).unwrap()
        );
        let client = client_with_response(response.as_bytes());
        let url = Url::parse("http://example.test").unwrap();
        let (_, response) = client
            .stream(&url, "GET", "/events", &[], Duration::from_secs(1))
            .unwrap();
        assert_eq!(response.status, 401);
        assert!(String::from_utf8_lossy(&response.body).contains("DBB_UNAUTHORIZED"));
    }

    /// A writer that fails on the first write: a pooled connection whose
    /// path is gone (a stream of a replaced reverse tunnel).
    struct DeadConn;

    impl Read for DeadConn {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }

    impl Write for DeadConn {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "tunnel stream closed",
            ))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Conn for DeadConn {
        fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
        fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
        fn try_clone(&self) -> io::Result<Box<dyn Conn>> {
            Err(io::Error::other("not cloneable"))
        }
        fn shutdown_write(&self) -> io::Result<()> {
            Ok(())
        }
        fn shutdown_both(&self) -> io::Result<()> {
            Ok(())
        }
        fn describe(&self) -> String {
            "dead test connection".to_string()
        }
    }

    #[test]
    fn post_on_dead_pooled_connection_is_retried_on_a_fresh_one() {
        let client = client_with_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        for _ in 0..3 {
            client.put_idle("example.test:80", Box::new(DeadConn), Vec::new());
        }
        let url = Url::parse("http://example.test").unwrap();
        let resp = client
            .request(&url, "POST", "/v1/sessions", &[], Some(b"{}"))
            .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"ok");
    }
}
