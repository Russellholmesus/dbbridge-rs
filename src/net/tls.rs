//! TLS 1.2+ transport adapter.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rustls::{ClientConfig, RootCertStore, ServerConfig, ServerConnection, StreamOwned};

use super::Conn;

const POLL: Duration = Duration::from_millis(50);
type ServerStream = StreamOwned<ServerConnection, TcpStream>;
type ClientStream = StreamOwned<rustls::ClientConnection, TcpStream>;

enum Inner {
    Server(ServerStream),
    Client(ClientStream),
}

struct WriteIntent<'a> {
    waiters: &'a AtomicUsize,
}

impl<'a> WriteIntent<'a> {
    fn new(waiters: &'a AtomicUsize) -> Self {
        waiters.fetch_add(1, Ordering::SeqCst);
        Self { waiters }
    }
}

impl Drop for WriteIntent<'_> {
    fn drop(&mut self) {
        self.waiters.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct TlsConn {
    inner: Arc<Mutex<Inner>>,
    read_timeout: Arc<Mutex<Option<Duration>>>,
    write_timeout: Arc<Mutex<Option<Duration>>>,
    write_waiters: Arc<AtomicUsize>,
    /// A second handle on the socket, used to wait for readable data without
    /// holding the TLS lock (see `Read for TlsConn`).
    readiness: Arc<TcpStream>,
    desc: String,
}

impl TlsConn {
    pub fn accept_with_config(
        stream: TcpStream,
        config: Arc<ServerConfig>,
        timeout: Duration,
    ) -> io::Result<Self> {
        let conn = ServerConnection::new(config).map_err(other)?;
        stream.set_read_timeout(Some(POLL))?;
        stream.set_write_timeout(Some(POLL))?;
        let mut stream = StreamOwned::new(conn, stream);
        handshake_server(&mut stream, timeout)?;
        let desc = stream
            .get_ref()
            .peer_addr()
            .map(|x| x.to_string())
            .unwrap_or_else(|_| "tls".into());
        configure_poll(&stream.sock)?;
        let readiness = Arc::new(stream.sock.try_clone()?);
        Ok(Self {
            inner: Arc::new(Mutex::new(Inner::Server(stream))),
            read_timeout: Arc::new(Mutex::new(None)),
            write_timeout: Arc::new(Mutex::new(None)),
            write_waiters: Arc::new(AtomicUsize::new(0)),
            readiness,
            desc,
        })
    }

    /// The negotiated ALPN protocol, if the peer supplied one.
    #[cfg(feature = "h2")]
    pub fn alpn_protocol(&self) -> Option<Vec<u8>> {
        let g = self.inner.lock().ok()?;
        match &*g {
            Inner::Server(s) => s.conn.alpn_protocol().map(|p| p.to_vec()),
            Inner::Client(s) => s.conn.alpn_protocol().map(|p| p.to_vec()),
        }
    }

    pub fn connect_with_config(
        stream: TcpStream,
        host: &str,
        config: Arc<ClientConfig>,
        timeout: Duration,
    ) -> io::Result<Self> {
        let name =
            rustls::ServerName::try_from(host).map_err(|_| other("invalid TLS server name"))?;
        let conn = rustls::ClientConnection::new(config, name).map_err(other)?;
        stream.set_read_timeout(Some(POLL))?;
        stream.set_write_timeout(Some(POLL))?;
        let mut stream = StreamOwned::new(conn, stream);
        handshake_client(&mut stream, timeout)?;
        configure_poll(&stream.sock)?;
        let readiness = Arc::new(stream.sock.try_clone()?);
        Ok(Self {
            inner: Arc::new(Mutex::new(Inner::Client(stream))),
            read_timeout: Arc::new(Mutex::new(None)),
            write_timeout: Arc::new(Mutex::new(None)),
            write_waiters: Arc::new(AtomicUsize::new(0)),
            readiness,
            desc: format!("tls://{host}"),
        })
    }
}

fn other(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}
fn configure_poll(sock: &TcpStream) -> io::Result<()> {
    sock.set_read_timeout(Some(POLL))?;
    sock.set_write_timeout(Some(POLL))
}

fn handshake_server(stream: &mut ServerStream, timeout: Duration) -> io::Result<()> {
    let end = Instant::now() + timeout;
    while stream.conn.is_handshaking() {
        match stream.conn.complete_io(&mut stream.sock) {
            Ok(_) => {}
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                if Instant::now() >= end {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "TLS handshake timed out",
                    ));
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
fn handshake_client(stream: &mut ClientStream, timeout: Duration) -> io::Result<()> {
    let end = Instant::now() + timeout;
    while stream.conn.is_handshaking() {
        match stream.conn.complete_io(&mut stream.sock) {
            Ok(_) => {}
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                if Instant::now() >= end {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "TLS handshake timed out",
                    ));
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

pub fn server_config(cert_path: &Path, key_path: &Path) -> io::Result<ServerConfig> {
    let open = |path: &Path| {
        std::fs::read(path).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("open {}: {}", path.display(), os_text(&e)),
            )
        })
    };
    let cert = open(cert_path)?;
    let key = open(key_path)?;
    let mut cr = std::io::BufReader::new(cert.as_slice());
    let certs: Vec<rustls::Certificate> = rustls_pemfile::certs(&mut cr)
        .map_err(other)?
        .into_iter()
        .map(rustls::Certificate)
        .collect();
    if certs.is_empty() {
        return Err(other("TLS certificate file contains no certificates"));
    }
    let key = read_key(&key)?;
    let mut c = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(other)?;
    c.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(c)
}

fn os_text(e: &io::Error) -> String {
    let text = e.to_string();
    let text = match (e.raw_os_error(), text.rfind(" (os error ")) {
        (Some(_), Some(at)) => &text[..at],
        _ => text.as_str(),
    };
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_lowercase().chain(chars).collect(),
        None => String::new(),
    }
}

fn read_key(bytes: &[u8]) -> io::Result<rustls::PrivateKey> {
    let mut r = std::io::BufReader::new(bytes);
    if let Some(k) = rustls_pemfile::pkcs8_private_keys(&mut r)
        .map_err(other)?
        .into_iter()
        .next()
    {
        return Ok(rustls::PrivateKey(k));
    }
    let mut r = std::io::BufReader::new(bytes);
    rustls_pemfile::rsa_private_keys(&mut r)
        .map_err(other)?
        .into_iter()
        .next()
        .map(rustls::PrivateKey)
        .ok_or_else(|| other("TLS private key file contains no supported private key"))
}

pub fn client_config(ca_file: Option<&Path>, verify: bool) -> io::Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    if let Some(path) = ca_file {
        let bytes = std::fs::read(path)?;
        let mut r = std::io::BufReader::new(bytes.as_slice());
        for c in rustls_pemfile::certs(&mut r).map_err(other)? {
            roots.add(&rustls::Certificate(c)).map_err(other)?;
        }
        if roots.is_empty() {
            return Err(other("TLS CA file contains no certificates"));
        }
    } else {
        for cert in rustls_native_certs::load_native_certs().map_err(other)? {
            roots.add(&rustls::Certificate(cert.0)).map_err(other)?;
        }
    }
    let mut c = if verify {
        ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_no_client_auth()
    } else {
        struct NoVerify;
        impl rustls::client::ServerCertVerifier for NoVerify {
            fn verify_server_cert(
                &self,
                _: &rustls::Certificate,
                _: &[rustls::Certificate],
                _: &rustls::ServerName,
                _: &mut dyn Iterator<Item = &[u8]>,
                _: &[u8],
                _: std::time::SystemTime,
            ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
                Ok(rustls::client::ServerCertVerified::assertion())
            }
        }
        let mut c = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(roots)
            .with_no_client_auth();
        c.dangerous().set_certificate_verifier(Arc::new(NoVerify));
        c
    };
    // The synchronous client paths always speak HTTP/1.1 (including WebSocket
    // Upgrade). The dedicated H2 pool opts into h2 explicitly.
    c.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(c)
}

impl Read for TlsConn {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        let deadline = self.deadline(&self.read_timeout)?;
        loop {
            check_deadline(deadline)?;
            // StreamOwned's TLS state is shared with writers. If a write is
            // waiting for the lock, let it run before the next polling read.
            while self.write_waiters.load(Ordering::SeqCst) != 0 {
                check_deadline(deadline)?;
                std::thread::yield_now();
            }
            // Wait for the peer without holding the TLS lock: a read that
            // blocks inside the lock for a whole poll interval stalls every
            // writer of this connection (one SSE event per 50 ms on an
            // HTTP/2 connection whose peer is otherwise silent).
            let buffered = {
                let g = self.inner.lock().map_err(|_| other("TLS state poisoned"))?;
                g.has_buffered_input()
            };
            if !buffered {
                match self.readiness.peek(&mut [0u8; 1]) {
                    Err(e) if is_poll_timeout(&e) => continue,
                    // EOF and errors are reported by the TLS read below.
                    _ => {}
                }
            }
            let result = {
                let mut g = self.inner.lock().map_err(|_| other("TLS state poisoned"))?;
                match &mut *g {
                    Inner::Server(s) => s.read(b),
                    Inner::Client(s) => s.read(b),
                }
            };
            match result {
                Err(e) if is_poll_timeout(&e) => {
                    check_deadline(deadline)?;
                    std::thread::yield_now();
                }
                result => return result,
            }
        }
    }
}
impl Write for TlsConn {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let deadline = self.deadline(&self.write_timeout)?;
        loop {
            check_deadline(deadline)?;
            let result = {
                let _write_intent = WriteIntent::new(&self.write_waiters);
                let mut g = self.inner.lock().map_err(|_| other("TLS state poisoned"))?;
                match &mut *g {
                    Inner::Server(s) => s.write(b),
                    Inner::Client(s) => s.write(b),
                }
            };
            match result {
                Err(e) if is_poll_timeout(&e) => {
                    check_deadline(deadline)?;
                    std::thread::yield_now();
                }
                result => return result,
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_shared()
    }
}

fn is_poll_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
    )
}

fn check_deadline(deadline: Option<Instant>) -> io::Result<()> {
    if deadline.is_some_and(|end| Instant::now() >= end) {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "TLS I/O deadline exceeded",
        ))
    } else {
        Ok(())
    }
}

impl TlsConn {
    fn deadline(&self, timeout: &Mutex<Option<Duration>>) -> io::Result<Option<Instant>> {
        Ok(timeout
            .lock()
            .map_err(|_| other("TLS timeout state poisoned"))?
            .map(|d| Instant::now() + d))
    }

    fn flush_shared(&self) -> io::Result<()> {
        let deadline = self.deadline(&self.write_timeout)?;
        loop {
            check_deadline(deadline)?;
            let result = {
                let _write_intent = WriteIntent::new(&self.write_waiters);
                let mut g = self.inner.lock().map_err(|_| other("TLS state poisoned"))?;
                match &mut *g {
                    Inner::Server(s) => s.flush(),
                    Inner::Client(s) => s.flush(),
                }
            };
            match result {
                Err(e) if is_poll_timeout(&e) => {
                    check_deadline(deadline)?;
                    std::thread::yield_now();
                }
                result => return result,
            }
        }
    }
}

impl Conn for TlsConn {
    fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        *self
            .read_timeout
            .lock()
            .map_err(|_| other("TLS timeout state poisoned"))? = d;
        Ok(())
    }
    fn set_write_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        *self
            .write_timeout
            .lock()
            .map_err(|_| other("TLS timeout state poisoned"))? = d;
        Ok(())
    }
    fn try_clone(&self) -> io::Result<Box<dyn Conn>> {
        Ok(Box::new(Self {
            inner: self.inner.clone(),
            read_timeout: self.read_timeout.clone(),
            write_timeout: self.write_timeout.clone(),
            write_waiters: self.write_waiters.clone(),
            readiness: self.readiness.clone(),
            desc: self.desc.clone(),
        }))
    }
    fn shutdown_write(&self) -> io::Result<()> {
        {
            let _write_intent = WriteIntent::new(&self.write_waiters);
            let mut g = self.inner.lock().map_err(|_| other("TLS state poisoned"))?;
            g.send_close_notify();
        }
        self.flush_shared()?;
        self.shutdown_socket(std::net::Shutdown::Write)
    }
    fn shutdown_both(&self) -> io::Result<()> {
        self.shutdown_socket(std::net::Shutdown::Both)
    }
    fn describe(&self) -> String {
        self.desc.clone()
    }
}

impl TlsConn {
    fn shutdown_socket(&self, how: std::net::Shutdown) -> io::Result<()> {
        let _write_intent = WriteIntent::new(&self.write_waiters);
        let g = self.inner.lock().map_err(|_| other("TLS state poisoned"))?;
        g.shutdown(how)
    }
}

impl Inner {
    fn send_close_notify(&mut self) {
        match self {
            Inner::Server(s) => s.conn.send_close_notify(),
            Inner::Client(s) => s.conn.send_close_notify(),
        }
    }

    /// Decrypted bytes (or a close) are waiting, or TLS records were already
    /// read from the socket: the next read can make progress without
    /// waiting for the peer.
    fn has_buffered_input(&self) -> bool {
        match self {
            Inner::Server(s) => !s.conn.wants_read(),
            Inner::Client(s) => !s.conn.wants_read(),
        }
    }

    fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()> {
        match self {
            Inner::Server(s) => s.sock.shutdown(how),
            Inner::Client(s) => s.sock.shutdown(how),
        }
    }
}

#[cfg(all(test, feature = "tls"))]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;

    fn fixture_paths() -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/net/testdata");
        (
            dir.join("localhost-cert.pem"),
            dir.join("localhost-key.pem"),
            dir.join("localhost-ca.pem"),
        )
    }

    fn connected_pair() -> (TlsConn, TlsConn) {
        let (cert, key, ca) = fixture_paths();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server_config = Arc::new(server_config(&cert, &key).unwrap());
        let (tx, rx) = mpsc::channel();
        let server_thread = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let stream =
                TlsConn::accept_with_config(socket, server_config, Duration::from_secs(5)).unwrap();
            tx.send(stream).unwrap();
        });

        let socket = TcpStream::connect(addr).unwrap();
        let config = Arc::new(client_config(Some(&ca), true).unwrap());
        let client =
            TlsConn::connect_with_config(socket, "localhost", config, Duration::from_secs(5))
                .unwrap();
        let server = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        server_thread.join().unwrap();
        (client, server)
    }

    #[test]
    fn tls_handshake_and_full_duplex_clone_io() {
        let (mut client, mut server) = connected_pair();
        assert_eq!(client.alpn_protocol(), Some(b"http/1.1".to_vec()));
        assert_eq!(server.alpn_protocol(), Some(b"http/1.1".to_vec()));
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        server
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let mut reader = server.try_clone().unwrap();
        let read_thread = std::thread::spawn(move || {
            let mut bytes = [0u8; 4];
            reader.read_exact(&mut bytes).unwrap();
            bytes
        });
        server.write_all(b"pong").unwrap();
        server.flush().unwrap();
        client.write_all(b"ping").unwrap();
        client.flush().unwrap();

        let mut response = [0u8; 4];
        client.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"pong");
        assert_eq!(&read_thread.join().unwrap(), b"ping");
    }

    #[test]
    fn writes_are_not_delayed_by_a_reader_waiting_on_a_silent_peer() {
        // A reader blocked on a silent peer used to hold the TLS lock for a
        // whole 50 ms poll, delaying each write behind it (rs -> rs TLS
        // http-sse: 1 MiB took ~14 s).
        let (mut client, server) = connected_pair();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut reader = server.try_clone().unwrap();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_reader = stop.clone();
        let read_thread = std::thread::spawn(move || {
            reader
                .set_read_timeout(Some(Duration::from_millis(20)))
                .unwrap();
            let mut buf = [0u8; 16];
            while !stop_reader.load(Ordering::Relaxed) {
                let _ = reader.read(&mut buf);
            }
        });
        std::thread::sleep(Duration::from_millis(20));
        let mut writer = server;
        let started = Instant::now();
        for _ in 0..40 {
            writer.write_all(b"event").unwrap();
            writer.flush().unwrap();
            let mut got = [0u8; 5];
            client.read_exact(&mut got).unwrap();
            assert_eq!(&got, b"event");
        }
        let elapsed = started.elapsed();
        stop.store(true, Ordering::Relaxed);
        read_thread.join().unwrap();
        assert!(
            elapsed < Duration::from_millis(1000),
            "40 writes took {elapsed:?}"
        );
    }

    #[test]
    fn tls_blocked_reader_does_not_starve_clone_writer() {
        let (client, mut server) = connected_pair();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        let mut reader = client.try_clone().unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let reader_thread = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            let mut byte = [0u8; 1];
            reader.read_exact(&mut byte).unwrap();
            byte[0]
        });
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        std::thread::sleep(Duration::from_millis(100));

        let mut writer = client.try_clone().unwrap();
        let start = Instant::now();
        writer.write_all(b"x").unwrap();
        writer.flush().unwrap();
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "TLS write waited for the blocked read"
        );

        let mut got = [0u8; 1];
        server.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"x");
        server.write_all(b"y").unwrap();
        server.flush().unwrap();
        assert_eq!(reader_thread.join().unwrap(), b'y');
    }

    #[test]
    fn tls_short_poll_honors_logical_read_timeout() {
        let (mut client, _server) = connected_pair();
        client
            .set_read_timeout(Some(Duration::from_millis(120)))
            .unwrap();
        let start = Instant::now();
        let mut byte = [0u8; 1];
        let error = client.read(&mut byte).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() >= Duration::from_millis(100));
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
