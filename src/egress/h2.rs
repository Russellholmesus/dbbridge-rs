use std::collections::VecDeque;
use std::future::Future;
use std::io::{self, Read, Write};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Body as _, Bytes, Frame, Incoming};
use hyper::service::service_fn;
use hyper::{Request as HRequest, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;

use crate::error::Error;
use crate::net::tls::TlsConn;
use crate::net::Conn;
use crate::transport::{CarrierWriter, SharedWriter};
use crate::wire::{self, Control, Mode};

use super::accept::error_response;
use super::pump::{ready_control, run_downstream};
use super::{ConnectionPermit, Server, SessionLease};

/// An HTTP/2 response body: either a complete buffer or the SSE stream.
type Body = BoxBody<Bytes, hyper::Error>;

fn full(bytes: impl Into<Bytes>) -> Body {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed()
}

/// Run one already-handshaken TLS connection as an HTTP/2-only server.
///
/// Hyper owns the multiplexed connection. Each SSE request gets an independent
/// response body and downstream pump, while HTTP/2 PINGs are emitted by Hyper.
pub(super) fn serve(
    server: Arc<Server>,
    tls: TlsConn,
    permit: Option<ConnectionPermit>,
) -> io::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_io()
        .enable_time()
        .build()
        .map_err(|e| io::Error::other(e.to_string()))?;
    runtime.block_on(async move {
        let io = TokioConn::new(tls)?;
        let permit = Arc::new(Mutex::new(permit));
        let heartbeat = server.cfg.transport.heartbeat;
        let svc = service_fn(move |req| {
            let server = server.clone();
            let permit = permit.clone();
            async move { Ok::<_, hyper::Error>(handle(server, req, permit).await) }
        });
        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .timer(TokioTimer::new())
            .max_concurrent_streams(Some(64))
            .keep_alive_interval(heartbeat)
            .keep_alive_timeout(Duration::from_secs(5))
            .serve_connection(TokioIo::new(io), svc)
            .await
            .map_err(|e| io::Error::other(e.to_string()))
    })
}

async fn handle(
    server: Arc<Server>,
    req: HRequest<Incoming>,
    permit: Arc<Mutex<Option<ConnectionPermit>>>,
) -> Response<Body> {
    let (parts, mut body) = req.into_parts();
    let headers = parts
        .headers
        .iter()
        .filter_map(|(name, value)| {
            Some((name.as_str().to_string(), value.to_str().ok()?.to_string()))
        })
        .collect::<Vec<_>>();
    let (path, query) = match parts.uri.path_and_query().map(|x| x.as_str()) {
        Some(target) => match target.split_once('?') {
            Some((p, q)) => (
                p.to_string(),
                q.split('&')
                    .filter_map(|x| {
                        x.split_once('=')
                            .map(|(k, v)| (k.to_string(), v.to_string()))
                    })
                    .collect(),
            ),
            None => (target.to_string(), Vec::new()),
        },
        None => ("/".to_string(), Vec::new()),
    };
    let mut internal = crate::net::http1::Request {
        method: parts.method.to_string(),
        path,
        query,
        version: "HTTP/2".into(),
        headers,
        body: Vec::new(),
    };
    if let Some(error) = super::accept::invalid_binding_headers(&internal) {
        return h2_error(&error, Some(&internal), &server);
    }
    if (internal.method == "GET" || internal.method == "HEAD")
        && (super::accept::request_has_body(&internal) || !body.is_end_stream())
    {
        return h2_error(
            &Error::new(wire::ERR_BAD_FRAME, "request body not allowed"),
            Some(&internal),
            &server,
        );
    }
    let Some(expected) = super::accept::expected_method(&internal.path) else {
        return h2_error(
            &Error::new(wire::ERR_BAD_FRAME, "not found"),
            Some(&internal),
            &server,
        );
    };
    if internal.method != expected {
        let mut response = h2_error(
            &Error::new(wire::ERR_BAD_FRAME, "method"),
            Some(&internal),
            &server,
        );
        response.headers_mut().insert(
            hyper::header::ALLOW,
            hyper::header::HeaderValue::try_from(expected)
                .unwrap_or_else(|_| hyper::header::HeaderValue::from_static("POST")),
        );
        return response;
    }
    let authenticated_peer = match server.authenticate(&internal) {
        Ok(peer) => peer,
        Err(_) => {
            let mut response = h2_error(
                &Error::new(wire::ERR_UNAUTHORIZED, "invalid credentials"),
                Some(&internal),
                &server,
            );
            response.headers_mut().insert(
                hyper::header::WWW_AUTHENTICATE,
                hyper::header::HeaderValue::from_static("Bearer realm=\"dbbridge\""),
            );
            return response;
        }
    };
    let _request_leases = match server.request_resource_leases(&internal, &authenticated_peer.id) {
        Ok(leases) => leases,
        Err(error) => return h2_error(&error, Some(&internal), &server),
    };
    if let Ok(mut guard) = permit.lock() {
        if let Some(p) = guard.as_mut() {
            p.mark_authenticated();
        }
    }
    if super::accept::requires_instance_binding(&internal.path) {
        if let Err(error) = server.check_instance(&internal) {
            return h2_error(&error, Some(&internal), &server);
        }
    }
    let max_body = server.cfg.transport.max_frame_size.max(32 * 1024);
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let chunk = match frame.map(Frame::into_data) {
            Ok(Ok(chunk)) => Ok(chunk),
            // Trailers end the data, as `HttpBody::data` did.
            Ok(Err(_)) => break,
            Err(e) => Err(e),
        };
        match chunk {
            Ok(chunk) if bytes.len().saturating_add(chunk.len()) <= max_body => {
                bytes.extend_from_slice(&chunk)
            }
            Ok(_) => {
                return h2_error(
                    &Error::new(wire::ERR_BAD_FRAME, "request body too large"),
                    Some(&internal),
                    &server,
                )
            }
            Err(_) => {
                return h2_error(
                    &Error::new(wire::ERR_BAD_FRAME, "invalid request body"),
                    Some(&internal),
                    &server,
                )
            }
        }
    }
    internal.body = bytes;
    if internal.path.starts_with(wire::PATH_SESSIONS) && internal.path.ends_with("/events") {
        return handle_events(server, internal).await;
    }
    let (status, body, headers) = server.route(&internal);
    let mut response = response_from_parts(status, body, headers);
    response.headers_mut().insert(
        hyper::header::CACHE_CONTROL,
        hyper::header::HeaderValue::from_static("no-store"),
    );
    response.headers_mut().insert(
        instance_id_header_name(),
        hyper::header::HeaderValue::try_from(server.cfg.node.instance_id.as_str())
            .unwrap_or_else(|_| hyper::header::HeaderValue::from_static("")),
    );
    response
}

fn h2_error(
    error: &Error,
    req: Option<&crate::net::http1::Request>,
    server: &Server,
) -> Response<Body> {
    let (status, body, headers) =
        super::accept::response_for(error, req, false, &server.cfg.node.instance_id);
    response_from_parts(status, body, headers)
}

fn instance_id_header_name() -> hyper::header::HeaderName {
    hyper::header::HeaderName::from_static("x-dbb-instance-id")
}

fn response_from_parts(
    status: u16,
    body: Vec<u8>,
    headers: Vec<(String, String)>,
) -> Response<Body> {
    let mut builder = Response::builder().status(status);
    for (k, v) in headers {
        if let (Ok(k), Ok(v)) = (
            hyper::header::HeaderName::try_from(k),
            hyper::header::HeaderValue::try_from(v),
        ) {
            builder = builder.header(k, v);
        }
    }
    builder
        .body(full(body))
        .unwrap_or_else(|_| simple(StatusCode::INTERNAL_SERVER_ERROR, b"response error"))
}

fn h2_session_error(error: &Error, server: &Server) -> Response<Body> {
    let (status, body, mut headers) = error_response(error);
    headers.push((
        wire::H_INSTANCE_ID.to_string(),
        server.cfg.node.instance_id.clone(),
    ));
    response_from_parts(status, body, headers)
}

async fn handle_events(server: Arc<Server>, req: crate::net::http1::Request) -> Response<Body> {
    let session = match server
        .session_from_path(&req)
        .and_then(|(session, action)| {
            if action != "events" {
                return Err(Error::new(wire::ERR_BAD_FRAME, "action"));
            }
            let epoch = Server::epoch_from_query(&req)?;
            if epoch != session.epoch() {
                return Err(Error::new(wire::ERR_STALE_EPOCH, "epoch"));
            }
            if session.current_mode() != Mode::HttpSse {
                return Err(Error::new(wire::ERR_TRANSPORT_MISMATCH, "mode"));
            }
            Ok(session)
        }) {
        Ok(session) => session,
        Err(error) => {
            return h2_session_error(&error, &server);
        }
    };

    let stream_id = match crate::util::random_id(16)
        .map_err(crate::util::random_error)
        .and_then(|id| session.attach(&id).map(|_| id))
    {
        Ok(id) => id,
        Err(error) => {
            return h2_session_error(&error, &server);
        }
    };

    let (tx, rx) = mpsc::channel::<Result<Vec<u8>, hyper::Error>>(32);
    let pump_server = server.clone();
    let pump_session = session.clone();
    let pump_id = stream_id.clone();
    let lease = SessionLease::new(server.registry.clone(), session.id.clone());
    let handle = tokio::runtime::Handle::try_current().ok();
    let idle = server.cfg.transport.sse_write_idle_timeout;
    let spawn = crate::util::spawn_connection(move || {
        let mut writer = H2SseWriter {
            tx,
            handle,
            idle,
            deadline_idle: idle,
        };
        let _lease = lease;
        let _ = writer.send_control(&ready_control(&pump_session, &pump_id, Mode::HttpSse));
        let shared = SharedWriter::new(Box::new(writer));
        let codec = pump_server.codec_for(&pump_session.owner_peer);
        let _ = run_downstream(&pump_server.cfg, pump_session, shared, codec);
    });
    if spawn.is_err() {
        let error = Error::local("cannot start the downstream pump");
        session.close(error.clone());
        return h2_session_error(&error, &server);
    }

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream; charset=utf-8")
        .header("cache-control", "no-store, no-transform")
        .header("x-accel-buffering", "no")
        .header(wire::H_IMPLICIT_READY, "1")
        .header(wire::H_INSTANCE_ID, server.cfg.node.instance_id.clone())
        .body(BodyExt::boxed(StreamBody::new(
            ReceiverStream::new(rx).map(|chunk| chunk.map(|bytes| Frame::data(Bytes::from(bytes)))),
        )))
        .unwrap_or_else(|_| simple(StatusCode::INTERNAL_SERVER_ERROR, b"response error"))
}

fn simple(status: StatusCode, body: &'static [u8]) -> Response<Body> {
    Response::builder().status(status).body(full(body)).unwrap()
}

/// The HTTP/2 SSE response body of one events stream. Hyper owns the
/// stream; this side hands it body chunks through a bounded channel.
pub(super) struct H2SseWriter {
    pub(super) tx: mpsc::Sender<Result<Vec<u8>, hyper::Error>>,
    /// The connection's runtime, used to bound a piece hand-off by the
    /// write-idle deadline. Without one a hand-off waits for room.
    pub(super) handle: Option<tokio::runtime::Handle>,
    /// `sse_write_idle_timeout`.
    pub(super) idle: Duration,
    /// The deadline armed for the next piece.
    pub(super) deadline_idle: Duration,
}

impl H2SseWriter {
    pub(super) fn send_bytes(&mut self, bytes: Vec<u8>) -> crate::error::Result<()> {
        let idle = self.idle;
        crate::transport::sse_progress::write_sse_progress(self, &bytes, idle)
    }
    fn event(&mut self, kind: &str, data: &str, id: Option<&str>) -> crate::error::Result<()> {
        let mut buf = Vec::with_capacity(data.len() + 64);
        if let Some(id) = id {
            buf.extend_from_slice(format!("id: {id}\n").as_bytes());
        }
        buf.extend_from_slice(format!("event: {kind}\ndata: {data}\n\n").as_bytes());
        self.send_bytes(buf)
    }
}

impl crate::transport::sse_progress::SsePieceSink for H2SseWriter {
    fn arm_idle_deadline(&mut self, idle: Duration) -> crate::error::Result<()> {
        self.deadline_idle = idle;
        Ok(())
    }

    fn write_piece(&mut self, piece: &[u8]) -> crate::error::Result<()> {
        let closed = || Error::local("HTTP/2 stream closed");
        let chunk = Ok(piece.to_vec());
        match &self.handle {
            Some(handle) if !self.deadline_idle.is_zero() => {
                let (tx, idle) = (&self.tx, self.deadline_idle);
                // The timer is created inside the runtime (a Sleep built on
                // this plain thread would find no time driver).
                match handle
                    .block_on(async move { tokio::time::timeout(idle, tx.send(chunk)).await })
                {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(_)) => Err(closed()),
                    Err(_) => Err(Error::local("sse write idle timeout")),
                }
            }
            _ => self.tx.blocking_send(chunk).map_err(|_| closed()),
        }
    }

    fn flush_piece(&mut self) -> crate::error::Result<()> {
        // Hyper writes each body chunk as it is taken.
        Ok(())
    }
}

impl CarrierWriter for H2SseWriter {
    fn send_data(
        &mut self,
        epoch: u64,
        offset: u64,
        payload: &[u8],
    ) -> crate::error::Result<Option<u64>> {
        let body = wire::format_sse_data(offset, payload)?;
        self.event(
            "data",
            &body,
            Some(&format!("{epoch}:{}", offset + payload.len() as u64)),
        )?;
        Ok(None)
    }
    fn send_control(&mut self, c: &Control) -> crate::error::Result<()> {
        self.event(c.kind.as_str(), &c.to_json().to_string(), None)
    }
    fn shutdown(&mut self) {}
}

struct TokioConn {
    read_rx: tokio::sync::mpsc::Receiver<io::Result<Vec<u8>>>,
    write_tx: Arc<WriteQueue>,
    pending: VecDeque<u8>,
    flush_rx: Option<tokio::sync::oneshot::Receiver<io::Result<()>>>,
    shutdown_rx: Option<tokio::sync::oneshot::Receiver<io::Result<()>>>,
}

enum WriteMsg {
    Data(Vec<u8>),
    Flush(tokio::sync::oneshot::Sender<io::Result<()>>),
    Shutdown(tokio::sync::oneshot::Sender<io::Result<()>>),
}

struct WriteState {
    messages: VecDeque<WriteMsg>,
    blocked: Option<std::task::Waker>,
    error: Option<(io::ErrorKind, String)>,
    closed: bool,
}

struct WriteQueue {
    state: Mutex<WriteState>,
    available: Condvar,
}

impl WriteQueue {
    fn new() -> Self {
        Self {
            state: Mutex::new(WriteState {
                messages: VecDeque::with_capacity(32),
                blocked: None,
                error: None,
                closed: false,
            }),
            available: Condvar::new(),
        }
    }

    fn push(&self, msg: WriteMsg, cx: &std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => {
                return std::task::Poll::Ready(Err(io::Error::other("TLS writer queue poisoned")))
            }
        };
        if let Some((kind, message)) = &state.error {
            return std::task::Poll::Ready(Err(io::Error::new(*kind, message.clone())));
        }
        if state.closed {
            return std::task::Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TLS writer is closed",
            )));
        }
        if state.messages.len() >= 32 {
            state.blocked = Some(cx.waker().clone());
            return std::task::Poll::Pending;
        }
        state.messages.push_back(msg);
        self.available.notify_one();
        std::task::Poll::Ready(Ok(()))
    }

    fn pop(&self) -> Option<WriteMsg> {
        let mut state = self.state.lock().ok()?;
        loop {
            if let Some(msg) = state.messages.pop_front() {
                let waker = state.blocked.take();
                drop(state);
                if let Some(waker) = waker {
                    waker.wake();
                }
                return Some(msg);
            }
            if state.closed {
                return None;
            }
            state = self.available.wait(state).ok()?;
        }
    }

    fn fail(&self, error: &io::Error) {
        let waker = match self.state.lock() {
            Ok(mut state) => {
                state
                    .error
                    .get_or_insert_with(|| (error.kind(), error.to_string()));
                state.closed = true;
                state.blocked.take()
            }
            Err(_) => None,
        };
        self.available.notify_all();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn close(&self) {
        let waker = match self.state.lock() {
            Ok(mut state) => {
                state.closed = true;
                state.blocked.take()
            }
            Err(_) => None,
        };
        self.available.notify_all();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn error(&self) -> io::Error {
        match self.state.lock() {
            Ok(state) => match &state.error {
                Some((kind, message)) => io::Error::new(*kind, message.clone()),
                None => io::Error::new(io::ErrorKind::BrokenPipe, "TLS writer stopped"),
            },
            Err(_) => io::Error::other("TLS writer queue poisoned"),
        }
    }
}

impl TokioConn {
    fn new(tls: TlsConn) -> io::Result<Self> {
        let reader = tls
            .try_clone()
            .map_err(|e| io::Error::other(e.to_string()))?;
        let (read_tx, read_rx) = tokio::sync::mpsc::channel(8);
        thread::spawn(move || {
            let mut reader = reader;
            let mut buf = [0u8; 16 * 1024];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => {
                        let _ = read_tx.blocking_send(Ok(Vec::new()));
                        break;
                    }
                    Ok(n) => {
                        if read_tx.blocking_send(Ok(buf[..n].to_vec())).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        let _ = read_tx.blocking_send(Err(e));
                        break;
                    }
                }
            }
        });
        let write_tx = Arc::new(WriteQueue::new());
        let write_rx = write_tx.clone();
        thread::spawn(move || {
            let mut writer = tls;
            while let Some(msg) = write_rx.pop() {
                match msg {
                    WriteMsg::Data(data) => {
                        if let Err(error) = writer.write_all(&data) {
                            write_rx.fail(&error);
                            break;
                        }
                    }
                    WriteMsg::Flush(done) => {
                        let result = writer.flush();
                        if let Err(error) = &result {
                            write_rx.fail(error);
                        }
                        let failed = result.is_err();
                        let _ = done.send(result);
                        if failed {
                            break;
                        }
                    }
                    WriteMsg::Shutdown(done) => {
                        let result = writer.shutdown_both();
                        if let Err(error) = &result {
                            write_rx.fail(error);
                        } else {
                            write_rx.close();
                        }
                        let _ = done.send(result);
                        break;
                    }
                }
            }
        });
        Ok(Self {
            read_rx,
            write_tx,
            pending: VecDeque::new(),
            flush_rx: None,
            shutdown_rx: None,
        })
    }
}

impl AsyncRead for TokioConn {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        if dst.remaining() == 0 {
            return std::task::Poll::Ready(Ok(()));
        }
        if !self.pending.is_empty() {
            let n = self.pending.len().min(dst.remaining());
            let (head, tail) = self.pending.as_slices();
            let first = head.len().min(n);
            dst.put_slice(&head[..first]);
            dst.put_slice(&tail[..n - first]);
            self.pending.drain(..n);
            return std::task::Poll::Ready(Ok(()));
        }
        match self.read_rx.poll_recv(cx) {
            std::task::Poll::Ready(Some(Ok(data))) if data.is_empty() => {
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(Some(Ok(data))) => {
                let n = data.len().min(dst.remaining());
                dst.put_slice(&data[..n]);
                self.pending.extend(&data[n..]);
                std::task::Poll::Ready(Ok(()))
            }
            std::task::Poll::Ready(Some(Err(e))) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Ready(None) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl AsyncWrite for TokioConn {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        src: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        if src.is_empty() {
            return std::task::Poll::Ready(Ok(0));
        }
        match self.write_tx.push(WriteMsg::Data(src.to_vec()), cx) {
            std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(src.len())),
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if this.flush_rx.is_none() {
            let (done, rx) = tokio::sync::oneshot::channel();
            match this.write_tx.push(WriteMsg::Flush(done), cx) {
                std::task::Poll::Ready(Ok(())) => this.flush_rx = Some(rx),
                std::task::Poll::Ready(Err(error)) => {
                    return std::task::Poll::Ready(Err(error));
                }
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
        let result = std::pin::Pin::new(this.flush_rx.as_mut().unwrap()).poll(cx);
        match result {
            std::task::Poll::Ready(Ok(result)) => {
                this.flush_rx = None;
                std::task::Poll::Ready(result)
            }
            std::task::Poll::Ready(Err(_)) => {
                this.flush_rx = None;
                std::task::Poll::Ready(Err(this.write_tx.error()))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if this.shutdown_rx.is_none() {
            let (done, rx) = tokio::sync::oneshot::channel();
            match this.write_tx.push(WriteMsg::Shutdown(done), cx) {
                std::task::Poll::Ready(Ok(())) => this.shutdown_rx = Some(rx),
                std::task::Poll::Ready(Err(error)) => {
                    return std::task::Poll::Ready(Err(error));
                }
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
        let result = std::pin::Pin::new(this.shutdown_rx.as_mut().unwrap()).poll(cx);
        match result {
            std::task::Poll::Ready(Ok(result)) => {
                this.shutdown_rx = None;
                std::task::Poll::Ready(result)
            }
            std::task::Poll::Ready(Err(_)) => {
                this.shutdown_rx = None;
                std::task::Poll::Ready(Err(this.write_tx.error()))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::ControlKind;

    #[test]
    fn h2_sse_writer_emits_ready_and_data_events() {
        let (tx, mut rx) = mpsc::channel(4);
        let mut writer = H2SseWriter {
            tx,
            handle: None,
            idle: Duration::from_secs(60),
            deadline_idle: Duration::from_secs(60),
        };
        let ready = Control::base(ControlKind::Ready, "s_test", "i_test", 7, "stream");
        writer.send_control(&ready).unwrap();
        writer.send_data(7, 0, b"hello").unwrap();

        let first = rx.blocking_recv().unwrap().unwrap();
        let second = rx.blocking_recv().unwrap().unwrap();
        let first = String::from_utf8(first).unwrap();
        let second = String::from_utf8(second).unwrap();
        assert!(first.starts_with("event: ready\ndata: "));
        assert!(first.ends_with("\n\n"));
        assert!(second.starts_with("id: 7:5\nevent: data\ndata: "));
        assert!(second.ends_with("\n\n"));
    }

    #[test]
    fn h2_instance_id_header_name_is_lowercase_and_valid() {
        assert_eq!(instance_id_header_name().as_str(), "x-dbb-instance-id");
    }
}

#[cfg(test)]
mod poll_read_tests {
    use super::*;

    #[test]
    fn leftover_bytes_are_returned_even_when_no_new_chunk_is_ready() {
        // B3: bytes kept from a chunk larger than the caller's buffer were
        // copied and then dropped by a Pending return, losing HTTP/2 frames.
        let (tx, read_rx) = tokio::sync::mpsc::channel(8);
        let mut conn = TokioConn {
            read_rx,
            write_tx: Arc::new(WriteQueue::new()),
            pending: VecDeque::new(),
            flush_rx: None,
            shutdown_rx: None,
        };
        tx.try_send(Ok((0u8..10).collect())).unwrap();
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        let mut got = Vec::new();
        for _ in 0..3 {
            let mut storage = [0u8; 4];
            let mut buf = ReadBuf::new(&mut storage);
            match std::pin::Pin::new(&mut conn).poll_read(&mut cx, &mut buf) {
                std::task::Poll::Ready(Ok(())) => got.extend_from_slice(buf.filled()),
                other => panic!("leftover bytes not returned: {other:?}"),
            }
        }
        assert_eq!(got, (0u8..10).collect::<Vec<_>>());
        let mut storage = [0u8; 4];
        let mut buf = ReadBuf::new(&mut storage);
        assert!(std::pin::Pin::new(&mut conn)
            .poll_read(&mut cx, &mut buf)
            .is_pending());
        assert!(buf.filled().is_empty());
    }
}
