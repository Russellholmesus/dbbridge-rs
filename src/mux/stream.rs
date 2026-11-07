//! One stream of a session: independent read and write halves over a slot.

use std::io::{self, Read, Write};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::net::Conn;

use super::session::{Inner, Slot};
use super::{would_block, CMD_FIN, CMD_PSH, CMD_UPD, UPD_LEN};

/// One stream of a session. Reads and writes are independent, so the two
/// halves of an upgraded connection can share it.
pub struct Stream {
    pub(super) inner: Arc<Inner>,
    pub(super) slot: Arc<Slot>,
}

pub(super) fn send_window(peer_window: u32, written: u32, peer_consumed: u32) -> Option<u32> {
    let inflight = written.wrapping_sub(peer_consumed) as i32;
    if inflight < 0 {
        return None;
    }
    let win = (peer_window as i32).wrapping_sub(inflight);
    Some(if win > 0 { win as u32 } else { 0 })
}

/// [`send_window`] with `ErrConsumed` read as no window.
#[cfg(test)]
pub(super) fn available_window(peer_window: u32, written: u32, peer_consumed: u32) -> u32 {
    send_window(peer_window, written, peer_consumed).unwrap_or(0)
}

impl Stream {
    pub fn id(&self) -> u32 {
        self.slot.id
    }

    pub(super) fn send_upd(&self, consumed: u32) -> io::Result<()> {
        let mut payload = [0u8; UPD_LEN];
        payload[0..4].copy_from_slice(&consumed.to_le_bytes());
        payload[4..8].copy_from_slice(&self.inner.cfg.stream_window.to_le_bytes());
        self.inner.send(CMD_UPD, self.slot.id, &payload)
    }

    /// Blocks until `n` bytes have arrived or the stream ends. The reader
    /// half of `read_exact` for callers that must not see a short read.
    pub fn close(&self) {
        let reclaim = {
            let mut st = self.slot.st.lock().unwrap();
            if st.dead || st.write_closed {
                return;
            }
            st.write_closed = true;
            st.fin
        };
        let _ = self.inner.send(CMD_FIN, self.slot.id, &[]);
        if reclaim {
            self.inner.remove_slot(self.slot.id);
        }
        self.slot.cv_write.notify_all();
        self.slot.cv_read.notify_all();
    }

    pub(super) fn clone_handle(&self) -> Stream {
        self.slot.handles.fetch_add(1, Ordering::Relaxed);
        Stream {
            inner: self.inner.clone(),
            slot: self.slot.clone(),
        }
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        if self.slot.handles.fetch_sub(1, Ordering::AcqRel) != 1 {
            return;
        }
        let should_send_fin = {
            let mut st = self.slot.st.lock().unwrap();
            if st.dead || st.write_closed {
                false
            } else {
                st.write_closed = true;
                true
            }
        };
        if should_send_fin {
            let _ = self.inner.send(CMD_FIN, self.slot.id, &[]);
        }
        // The final owned handle no longer keeps this stream open locally.
        // A peer FIN may still be in flight, but no new stream can use this
        // slot and any subsequent PSH is intentionally discarded.
        self.inner.remove_slot(self.slot.id);
        self.slot.cv_read.notify_all();
        self.slot.cv_write.notify_all();
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            let n = {
                let mut st = self.slot.st.lock().unwrap();
                if !st.inbox.is_empty() {
                    let n = buf.len().min(st.inbox.len());
                    for b in buf.iter_mut().take(n) {
                        *b = st.inbox.pop_front().unwrap();
                    }
                    let was_empty = st.read_total == 0;
                    // smux returnTokens: the session may read on.
                    self.inner.return_tokens(n);
                    st.read_total = st.read_total.wrapping_add(n as u32);
                    st.read_incr = st.read_incr.wrapping_add(n as u32);
                    // Report progress once half a window has been consumed, and
                    // on the very first read so the peer learns the real window
                    // instead of guessing.
                    if st.read_incr >= self.inner.cfg.stream_window / 2 || was_empty {
                        let consumed = st.read_total;
                        st.read_incr = 0;
                        drop(st);
                        // A failed window update means the tunnel is gone; the
                        // bytes are already in the caller's buffer, so report
                        // the read and let the next call surface the error.
                        let _ = self.send_upd(consumed);
                    }
                    return Ok(n);
                }
                if st.fin || st.dead {
                    return Ok(0);
                }
                let when = st.read_timeout.map(|d| Instant::now() + d);
                match when {
                    None => {
                        drop(self.slot.cv_read.wait(st).unwrap());
                        0
                    }
                    Some(when) => {
                        let now = Instant::now();
                        if when <= now {
                            return Err(would_block("tunnel stream read timed out"));
                        }
                        let (_next, res) = self.slot.cv_read.wait_timeout(st, when - now).unwrap();
                        if res.timed_out() {
                            return Err(would_block("tunnel stream read timed out"));
                        }
                        0
                    }
                }
            };
            let _ = n;
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            let n = {
                let mut st = self.slot.st.lock().unwrap();
                if st.dead || st.write_closed {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "tunnel stream closed",
                    ));
                }
                // smux keeps these counters as uint32. Subtraction is
                // deliberately modular so a counter crossing 2^32 does not
                // make an otherwise-valid window look exhausted.
                let Some(available) = send_window(st.peer_window, st.written, st.peer_consumed)
                else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "peer consumed more than sent",
                    ));
                };
                if available != 0 {
                    let n = buf
                        .len()
                        .min(available as usize)
                        .min(self.inner.cfg.max_frame_size);
                    st.written = st.written.wrapping_add(n as u32);
                    n
                } else {
                    let when = st.write_timeout.map(|d| Instant::now() + d);
                    match when {
                        None => {
                            drop(self.slot.cv_write.wait(st).unwrap());
                            0
                        }
                        Some(when) => {
                            let now = Instant::now();
                            if when <= now {
                                return Err(would_block("tunnel stream write timed out"));
                            }
                            let (_next, res) =
                                self.slot.cv_write.wait_timeout(st, when - now).unwrap();
                            if res.timed_out() {
                                return Err(would_block("tunnel stream write timed out"));
                            }
                            0
                        }
                    }
                }
            };
            if n == 0 {
                continue;
            }
            self.inner.send(CMD_PSH, self.slot.id, &buf[..n])?;
            return Ok(n);
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A stream is a connection: the whole session protocol above it is unaware
/// that its socket is a tunnel.
impl Conn for Stream {
    fn set_read_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        self.slot.st.lock().unwrap().read_timeout = d;
        self.slot.cv_read.notify_all();
        Ok(())
    }
    fn set_write_timeout(&self, d: Option<Duration>) -> io::Result<()> {
        self.slot.st.lock().unwrap().write_timeout = d;
        self.slot.cv_write.notify_all();
        Ok(())
    }
    fn try_clone(&self) -> io::Result<Box<dyn Conn>> {
        Ok(Box::new(self.clone_handle()))
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.close();
        Ok(())
    }
    fn shutdown_both(&self) -> io::Result<()> {
        {
            let mut st = self.slot.st.lock().unwrap();
            st.dead = true;
        }
        let _ = self.inner.send(CMD_FIN, self.slot.id, &[]);
        self.inner.remove_slot(self.slot.id);
        self.slot.cv_read.notify_all();
        self.slot.cv_write.notify_all();
        Ok(())
    }
    fn describe(&self) -> String {
        format!("tunnel stream {}", self.slot.id)
    }
}
