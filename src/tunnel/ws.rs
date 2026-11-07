//! The tunnel as a byte pipe.
//!
//! The tunnel is a WebSocket because that is what passes through an HTTP
//! proxy; inside, the multiplexer only wants a byte stream. These two adapters
//! are the whole seam between those two views.

use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::error::Result;
use crate::mux::{MuxConfig, Opener, Session};
use crate::net::ws::{Message, WsReader, WsWriter};

/// Presents a WebSocket as the byte stream the multiplexer runs on: one
/// binary message per write, message payloads concatenated on read.
struct WsSource {
    reader: WsReader,
    pending: Vec<u8>,
    pos: usize,
    /// Held until the multiplexer drops its source (the tunnel ended).
    _guard: Option<Box<dyn std::any::Any + Send + Sync>>,
}

impl Read for WsSource {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.pos < self.pending.len() {
                let n = out.len().min(self.pending.len() - self.pos);
                out[..n].copy_from_slice(&self.pending[self.pos..self.pos + n]);
                self.pos += n;
                if self.pos == self.pending.len() {
                    self.pending.clear();
                    self.pos = 0;
                }
                return Ok(n);
            }
            match self.reader.read_message() {
                Ok(Some(Message::Binary(b))) => {
                    self.pending = b;
                    self.pos = 0;
                    if self.pending.is_empty() {
                        continue;
                    }
                }
                Ok(Some(Message::Text(_))) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "tunnel: non-binary WebSocket message",
                    ))
                }
                Ok(Some(Message::Close(_, _))) | Ok(None) => return Ok(0),
                Err(e) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        format!("tunnel read: {}", e.message),
                    ))
                }
            }
        }
    }
}

struct WsSink {
    writer: Arc<Mutex<WsWriter>>,
}

impl Write for WsSink {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut w = self
            .writer
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "writer poisoned"))?;
        w.write_binary(data)?;
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Splits an upgraded tunnel connection into the reader and writer the
/// multiplexer needs.
pub fn split_tunnel(
    conn: crate::net::BufferedConn,
    mask: bool,
    cfg: MuxConfig,
    opener: Opener,
) -> Result<Arc<Session>> {
    split_tunnel_guarded(conn, mask, cfg, opener, None)
}

/// `split_tunnel` that keeps `guard` (e.g. the accepted socket's connection
/// slot) alive for the tunnel's lifetime.
pub fn split_tunnel_guarded(
    conn: crate::net::BufferedConn,
    mask: bool,
    cfg: MuxConfig,
    opener: Opener,
    guard: Option<Box<dyn std::any::Any + Send + Sync>>,
) -> Result<Arc<Session>> {
    // The handshake timeouts are far too short for a long-lived tunnel: an
    // idle tunnel would look like a dead socket. The multiplexer's own
    // liveness signal is the keepalive, so the socket timeout is set to the
    // failure-detection window instead. It also doubles as the only way to
    // unblock the reader thread: the multiplexer holds no socket handle, so a
    // timeout is what ends `read_loop` when the peer goes silent.
    let io_timeout = cfg.detect.max(cfg.keepalive * 2) + Duration::from_secs(1);
    let _ = conn.set_read_timeout(Some(io_timeout));
    let _ = conn.set_write_timeout(Some(io_timeout));
    let killer = conn.try_clone().ok();
    let (reader, writer) = crate::net::ws::split(conn, mask)?;
    let close_writer = writer.clone();
    let session = Session::new(
        Box::new(WsSource {
            reader,
            pending: Vec::new(),
            pos: 0,
            _guard: guard,
        }),
        Box::new(WsSink { writer }),
        cfg,
        opener,
    );
    // Closing the tunnel ends its WebSocket: a close frame when the writer
    // is free (never waiting behind a stalled write), then the socket itself.
    session.set_closer(Box::new(move || {
        if let Some(conn) = &killer {
            let _ = conn.set_write_timeout(Some(Duration::from_millis(200)));
        }
        if let Ok(mut w) = close_writer.try_lock() {
            let _ = w.write_close(1000, "");
        }
        if let Some(conn) = killer {
            let _ = conn.shutdown_both();
        }
    }));
    Ok(session)
}

/// Starts smux on a request-based carrier. HTTP reconnects are handled by the
/// carrier loops while smux sees one ordinary byte stream.
pub fn split_pipe(pipe: crate::tunnel::pipe::Pipe, cfg: MuxConfig, opener: Opener) -> Arc<Session> {
    Session::new(Box::new(pipe.clone()), Box::new(pipe), cfg, opener)
}
