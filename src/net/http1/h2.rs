#![cfg(feature = "h2")]

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http_body_util::{BodyExt, Empty};
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::sync::{mpsc as tmpsc, oneshot};
use tokio_rustls::rustls;
use tokio_rustls::TlsConnector;

use crate::config::ClientTls;
use crate::error::{Error, Result};
use crate::net::http1::{BodyReader, Response};
use crate::net::{Conn, Url};
use crate::resource::budget::BudgetLease;
use crate::resource::manager::ResourceManager;

struct Command {
    url: Url,
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    reply: oneshot::Sender<Result<(Response, H2Body)>>,
}

pub struct H2Pool {
    runtime: Arc<tokio::runtime::Runtime>,
    shards: Vec<tmpsc::Sender<Command>>,
    resource_manager: Arc<Mutex<Option<Arc<ResourceManager>>>>,
}

impl H2Pool {
    pub fn new(
        size: u32,
        connect_timeout: Duration,
        heartbeat: Duration,
        tls: ClientTls,
    ) -> Option<Self> {
        let size = size.clamp(1, 64) as usize;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(size.min(4))
            .enable_io()
            .enable_time()
            .build()
            .ok()?;
        let runtime = Arc::new(runtime);
        let resource_manager = Arc::new(Mutex::new(None));
        let mut shards = Vec::with_capacity(size);
        for _ in 0..size {
            let (tx, rx) = tmpsc::channel(64);
            let tls = tls.clone();
            runtime.spawn(shard(
                rx,
                connect_timeout,
                heartbeat,
                tls,
                resource_manager.clone(),
            ));
            shards.push(tx);
        }
        Some(H2Pool {
            runtime,
            shards,
            resource_manager,
        })
    }

    pub fn set_resource_manager(&self, resources: Arc<ResourceManager>) {
        *self
            .resource_manager
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(resources);
    }

    pub fn stream(
        &self,
        url: &Url,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        idle_timeout: Duration,
    ) -> Result<(BodyReader, Response)> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let cmd = Command {
            url: url.clone(),
            method: method.to_string(),
            path: path.to_string(),
            headers: headers.to_vec(),
            reply: reply_tx,
        };
        // Keep every authority on a stable slot. Each slot owns at most one live
        // H2 connection, so pool_size remains a meaningful connection bound while
        // failover endpoints can never share the wrong TLS connection.
        let mut hasher = DefaultHasher::new();
        url.authority().hash(&mut hasher);
        let idx = (hasher.finish() as usize) % self.shards.len();
        let send = self.runtime.block_on(self.shards[idx].send(cmd));
        if send.is_err() {
            return Err(Error::local("HTTP/2 shard stopped"));
        }
        let (response, body) = self.runtime.block_on(async {
            reply_rx
                .await
                .map_err(|_| Error::local("HTTP/2 connection stopped"))?
        })?;
        let conn = H2BodyConn::new(body, idle_timeout);
        Ok((
            BodyReader::new(crate::net::BufferedConn::new(conn), &[]),
            response,
        ))
    }
}

async fn shard(
    mut rx: tmpsc::Receiver<Command>,
    timeout: Duration,
    heartbeat: Duration,
    tls: ClientTls,
    resource_manager: Arc<Mutex<Option<Arc<ResourceManager>>>>,
) {
    let mut sender: Option<(String, H2Sender)> = None;
    while let Some(cmd) = rx.recv().await {
        let authority = cmd.url.authority();
        if sender
            .as_ref()
            .map(|(a, _)| a != &authority)
            .unwrap_or(true)
        {
            let resources = resource_manager
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            match connect(&cmd.url, timeout, heartbeat, &tls, resources).await {
                Ok(s) => sender = Some((authority.clone(), s)),
                Err(e) => {
                    let _ = cmd
                        .reply
                        .send(Err(Error::local(format!("HTTP/2 connect: {e}"))));
                    continue;
                }
            }
        }
        let uri = match format!("https://{}{}", cmd.url.authority(), cmd.url.path(&cmd.path))
            .parse::<Uri>()
        {
            Ok(u) => u,
            Err(e) => {
                let _ = cmd
                    .reply
                    .send(Err(Error::local(format!("HTTP/2 URI: {e}"))));
                continue;
            }
        };
        let method = cmd
            .method
            .parse::<hyper::Method>()
            .map_err(|e| Error::local(format!("HTTP/2 method: {e}")));
        let mut builder = match method {
            Ok(method) => Request::builder().method(method).uri(uri),
            Err(e) => {
                let _ = cmd.reply.send(Err(e));
                continue;
            }
        };
        let mut has_ua = false;
        for (k, v) in &cmd.headers {
            if k.eq_ignore_ascii_case("user-agent") {
                has_ua = true;
            }
            if let (Ok(k), Ok(v)) = (
                hyper::header::HeaderName::try_from(k.as_str()),
                hyper::header::HeaderValue::try_from(v.as_str()),
            ) {
                builder = builder.header(k, v);
            }
        }
        if !has_ua {
            builder = builder.header("user-agent", crate::user_agent());
        }
        let request = match builder.body(Empty::<Bytes>::new()) {
            Ok(r) => r,
            Err(e) => {
                let _ = cmd
                    .reply
                    .send(Err(Error::local(format!("HTTP/2 request: {e}"))));
                continue;
            }
        };
        let ready = match sender.as_mut() {
            Some((_, sender)) => Some(std::future::poll_fn(|cx| sender.poll_ready(cx)).await),
            None => None,
        };
        match ready {
            Some(Ok(())) => {}
            Some(Err(e)) => {
                sender = None;
                let _ = cmd
                    .reply
                    .send(Err(Error::local(format!("HTTP/2 request: {e}"))));
                continue;
            }
            None => {
                let _ = cmd
                    .reply
                    .send(Err(Error::local("HTTP/2 sender is not connected")));
                continue;
            }
        }
        let response = match sender.as_mut() {
            Some((_, sender)) => sender.send_request(request).await,
            None => {
                let _ = cmd
                    .reply
                    .send(Err(Error::local("HTTP/2 sender is not connected")));
                continue;
            }
        };
        match response {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let headers = resp
                    .headers()
                    .iter()
                    .filter_map(|(k, v)| {
                        Some((k.as_str().to_string(), v.to_str().ok()?.to_string()))
                    })
                    .collect();
                let body = resp.into_body();
                if !(200..300).contains(&status) {
                    match collect_body(body).await {
                        Ok(bytes) => {
                            let response = Response {
                                status,
                                headers,
                                body: bytes,
                            };
                            let empty = H2Body::empty(tokio::runtime::Handle::current());
                            let _ = cmd.reply.send(Ok((response, empty)));
                        }
                        Err(e) => {
                            let _ = cmd
                                .reply
                                .send(Err(Error::local(format!("HTTP/2 response body: {e}"))));
                        }
                    }
                } else {
                    let handle = tokio::runtime::Handle::current();
                    let body = H2Body::from(body, handle);
                    let response = Response {
                        status,
                        headers,
                        body: Vec::new(),
                    };
                    let _ = cmd.reply.send(Ok((response, body)));
                }
            }
            Err(e) => {
                sender = None;
                let _ = cmd
                    .reply
                    .send(Err(Error::local(format!("HTTP/2 request: {e}"))));
            }
        }
    }
}

/// The next DATA frame of `body`; trailers end the data, as
/// `HttpBody::data` did in hyper 0.14.
async fn next_data(body: &mut Incoming) -> Option<std::result::Result<Bytes, hyper::Error>> {
    match body.frame().await? {
        Ok(frame) => frame.into_data().ok().map(Ok),
        Err(e) => Some(Err(e)),
    }
}

async fn collect_body(mut body: Incoming) -> std::result::Result<Vec<u8>, hyper::Error> {
    const MAX_ERROR_BODY: usize = 64 << 20;
    let mut out = Vec::new();
    while let Some(chunk) = next_data(&mut body).await {
        let chunk = chunk?;
        if out.len().saturating_add(chunk.len()) > MAX_ERROR_BODY {
            out.extend_from_slice(&chunk[..MAX_ERROR_BODY - out.len()]);
            break;
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

type H2Sender = hyper::client::conn::http2::SendRequest<Empty<Bytes>>;

async fn connect(
    url: &Url,
    timeout: Duration,
    heartbeat: Duration,
    tls: &ClientTls,
    resources: Option<Arc<ResourceManager>>,
) -> io::Result<H2Sender> {
    let mut resource_leases: Vec<BudgetLease> = Vec::new();
    if let Some(resources) = resources {
        resources.mark_instrumented("data_connections");
        resources.mark_instrumented("metadata");
        let connection = resources.data_connections.try_acquire(1).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "data connection budget exhausted",
            )
        })?;
        let metadata = resources.metadata.try_acquire(8 << 10).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "data connection metadata budget exhausted",
            )
        })?;
        resource_leases.push(connection);
        resource_leases.push(metadata);
    }
    let tcp = tokio::time::timeout(
        timeout,
        tokio::net::TcpStream::connect((url.host.as_str(), url.port)),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP connect timed out"))??;
    let mut config = crate::net::tls::client_config(tls.ca_file.as_deref(), tls.verify)?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));
    let name = rustls::pki_types::ServerName::try_from(url.host.clone())
        .map_err(|_| io::Error::other("invalid TLS server name"))?;
    let stream = tokio::time::timeout(timeout, connector.connect(name, tcp))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))??;
    if stream.get_ref().1.alpn_protocol() != Some(b"h2") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "peer did not negotiate HTTP/2",
        ));
    }
    let mut builder = hyper::client::conn::http2::Builder::new(TokioExecutor::new());
    builder
        .timer(TokioTimer::new())
        .keep_alive_interval(heartbeat)
        .keep_alive_timeout(Duration::from_secs(5))
        .keep_alive_while_idle(true);
    let (sender, connection) = builder
        .handshake(TokioIo::new(stream))
        .await
        .map_err(|e| io::Error::other(e.to_string()))?;
    tokio::spawn(async move {
        let _resource_leases = resource_leases;
        let _ = connection.await;
    });
    Ok(sender)
}

struct H2Body {
    rx: tmpsc::Receiver<std::result::Result<Vec<u8>, String>>,
    runtime: tokio::runtime::Handle,
    buf: Vec<u8>,
}
impl H2Body {
    fn empty(runtime: tokio::runtime::Handle) -> Self {
        let (_tx, rx) = tmpsc::channel(1);
        H2Body {
            rx,
            runtime,
            buf: Vec::new(),
        }
    }
    fn from(mut body: Incoming, runtime: tokio::runtime::Handle) -> Self {
        // A bounded channel is important here: awaiting send stops polling the
        // hyper body and therefore lets HTTP/2 flow control apply upstream.
        let (tx, rx) = tmpsc::channel(16);
        tokio::spawn(async move {
            while let Some(chunk) = next_data(&mut body).await {
                let item = chunk.map(|b| b.to_vec()).map_err(|e| e.to_string());
                if tx.send(item).await.is_err() {
                    return;
                }
            }
        });
        H2Body {
            rx,
            runtime,
            buf: Vec::new(),
        }
    }
}
struct H2BodyConn {
    body: std::sync::Mutex<H2Body>,
    timeout: Duration,
}
impl H2BodyConn {
    fn new(body: H2Body, timeout: Duration) -> Self {
        Self {
            body: std::sync::Mutex::new(body),
            timeout,
        }
    }
}
impl io::Read for H2BodyConn {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut body = self
            .body
            .lock()
            .map_err(|_| io::Error::other("HTTP/2 body poisoned"))?;
        loop {
            if !body.buf.is_empty() {
                let n = out.len().min(body.buf.len());
                out[..n].copy_from_slice(&body.buf[..n]);
                body.buf.drain(..n);
                return Ok(n);
            }
            let runtime = body.runtime.clone();
            match runtime
                .block_on(async { tokio::time::timeout(self.timeout, body.rx.recv()).await })
            {
                Ok(Some(Ok(bytes))) => body.buf = bytes,
                Ok(Some(Err(e))) => return Err(io::Error::other(e)),
                Ok(None) => return Ok(0),
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "HTTP/2 body idle timeout",
                    ))
                }
            }
        }
    }
}
impl io::Write for H2BodyConn {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("HTTP/2 response is read-only"))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Conn for H2BodyConn {
    fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
    fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
    fn try_clone(&self) -> io::Result<Box<dyn Conn>> {
        Err(io::Error::other("HTTP/2 stream is not cloneable"))
    }
    fn shutdown_write(&self) -> io::Result<()> {
        Ok(())
    }
    fn shutdown_both(&self) -> io::Result<()> {
        Ok(())
    }
    fn describe(&self) -> String {
        "http2 stream".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc as std_mpsc, Arc};
    use tokio_rustls::TlsAcceptor;

    #[test]
    fn local_tls_h2_pool_consumes_20_concurrent_sse_streams() {
        let cert = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src/net/testdata/localhost-cert.pem");
        let key = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src/net/testdata/localhost-key.pem");
        let ca = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src/net/testdata/localhost-ca.pem");
        let config = crate::net::tls::server_config(&cert, &key).unwrap();
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(AtomicUsize::new(0));
        let requests_for_server = requests.clone();
        let server = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let (socket, _) = listener.accept().await.unwrap();
                let tls = TlsAcceptor::from(Arc::new(config));
                let stream = tls.accept(socket).await.unwrap();
                let count = requests_for_server;
                let service = hyper::service::service_fn(move |_request| {
                    count.fetch_add(1, Ordering::SeqCst);
                    async {
                        Ok::<_, hyper::Error>(hyper::Response::new(http_body_util::Full::new(
                            Bytes::from("data: local-h2\n\n"),
                        )))
                    }
                });
                let connection = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service);
                // The client drops its pooled TLS connection after all stream
                // bodies have been consumed; Hyper reports that as EOF.
                let _ = connection.await;
            });
        });
        let pool = Arc::new(
            H2Pool::new(
                2,
                Duration::from_secs(5),
                Duration::from_secs(30),
                ClientTls {
                    ca_file: Some(ca),
                    verify: true,
                    allow_insecure_skip_verify: false,
                },
            )
            .unwrap(),
        );
        let cfg_path = std::env::temp_dir().join(format!(
            "dbb-h2-resource-{}.yaml",
            crate::util::random_hex(4).unwrap()
        ));
        std::fs::write(
            &cfg_path,
            "node:\n  id: test\ntargets:\n  db:\n    network: tcp\n    address: 127.0.0.1:3306\n",
        )
        .unwrap();
        let cfg = crate::config::load(&cfg_path).unwrap();
        std::fs::remove_file(cfg_path).ok();
        let resources = ResourceManager::new(&cfg);
        pool.set_resource_manager(resources.clone());
        let url = Url::parse(&format!("https://localhost:{port}")).unwrap();
        let (result_tx, result_rx) = std_mpsc::channel();
        let mut workers = Vec::new();
        for _ in 0..20 {
            let pool = pool.clone();
            let url = url.clone();
            let result_tx = result_tx.clone();
            workers.push(std::thread::spawn(move || {
                let result = pool
                    .stream(
                        &url,
                        "GET",
                        "/events",
                        &[("accept".into(), "text/event-stream".into())],
                        Duration::from_secs(5),
                    )
                    .and_then(|(mut body, response)| {
                        let first = body.read_line(1024).map_err(Error::from)?;
                        let second = body.read_line(1024).map_err(Error::from)?;
                        if response.status != 200 || first != "data: local-h2" || !second.is_empty()
                        {
                            return Err(Error::local("unexpected H2 SSE response"));
                        }
                        Ok(())
                    });
                result_tx.send(result).unwrap();
            }));
        }
        drop(result_tx);
        for worker in workers {
            worker.join().unwrap();
        }
        for result in result_rx {
            result.unwrap();
        }
        assert_eq!(requests.load(Ordering::SeqCst), 20);
        assert!(resources.data_connections.used() > 0);
        assert_eq!(
            resources.metadata.used(),
            resources.data_connections.used() as i64 * (8 << 10)
        );
        drop(pool);
        server.join().unwrap();
        assert_eq!(resources.data_connections.used(), 0);
        assert_eq!(resources.metadata.used(), 0);
    }
}
