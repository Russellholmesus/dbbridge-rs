//! Reliable, bounded byte pipe used by the HTTP reverse carriers.
use crate::net::Conn;
use std::io::{self, Read, Write};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

pub const PIPE_CAPACITY: usize = 512 * 1024;

#[derive(Debug)]
struct State {
    out: Vec<u8>,
    out_base: i64,
    in_buf: Vec<u8>,
    in_next: i64,
    closed: bool,
    err: Option<io::ErrorKind>,
}
#[derive(Clone)]
pub struct Pipe {
    inner: Arc<(Mutex<State>, Condvar)>,
    local: String,
    remote: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveError {
    Gap(i64),
    Closed,
    Full,
}
impl Pipe {
    pub fn new(local: impl Into<String>, remote: impl Into<String>) -> Self {
        Self {
            inner: Arc::new((
                Mutex::new(State {
                    out: Vec::new(),
                    out_base: 0,
                    in_buf: Vec::new(),
                    in_next: 0,
                    closed: false,
                    err: None,
                }),
                Condvar::new(),
            )),
            local: local.into(),
            remote: remote.into(),
        }
    }
    pub fn close_with(&self, kind: Option<io::ErrorKind>) {
        let (m, cv) = &*self.inner;
        let mut s = m.lock().unwrap();
        if !s.closed {
            s.closed = true;
            s.err = kind;
            cv.notify_all();
        }
    }
    pub fn is_closed(&self) -> bool {
        self.inner.0.lock().unwrap().closed
    }
    pub fn ack(&self, off: i64) -> Result<(), ()> {
        let (m, cv) = &*self.inner;
        let mut s = m.lock().unwrap();
        if off <= s.out_base {
            return Ok(());
        }
        let end = s.out_base + s.out.len() as i64;
        if off > end {
            return Err(());
        }
        let n = (off - s.out_base) as usize;
        s.out.drain(..n);
        s.out_base = off;
        cv.notify_all();
        Ok(())
    }
    #[cfg(test)]
    pub fn pending(&self, from: i64, max: usize) -> Option<(i64, Vec<u8>)> {
        let s = self.inner.0.lock().unwrap();
        let from = from.max(s.out_base);
        let start = (from - s.out_base) as usize;
        if start >= s.out.len() {
            None
        } else {
            Some((from, s.out[start..(start + max).min(s.out.len())].to_vec()))
        }
    }
    pub fn received(&self) -> i64 {
        self.inner.0.lock().unwrap().in_next
    }
    pub fn receive(&self, off: i64, data: &[u8], wait: Duration) -> Result<i64, ReceiveError> {
        let (m, cv) = &*self.inner;
        let mut s = m.lock().unwrap();
        if off < 0 || off > s.in_next {
            return Err(ReceiveError::Gap(s.in_next));
        }
        let end = off.saturating_add(data.len() as i64);
        while s.in_next < end {
            if s.closed {
                return Err(ReceiveError::Closed);
            }
            if s.in_next < off {
                return Err(ReceiveError::Gap(s.in_next));
            }
            if s.in_buf.len() >= PIPE_CAPACITY {
                let (g, timeout) = cv.wait_timeout(s, wait).unwrap();
                s = g;
                if timeout.timed_out() && s.in_buf.len() >= PIPE_CAPACITY {
                    return Err(ReceiveError::Full);
                }
                continue;
            }
            let start = (s.in_next - off) as usize;
            let n = (PIPE_CAPACITY - s.in_buf.len()).min(data.len() - start);
            s.in_buf.extend_from_slice(&data[start..start + n]);
            s.in_next += n as i64;
            cv.notify_all();
        }
        Ok(s.in_next)
    }
    pub fn wait_for_data(&self, from: i64, wait: Duration) -> Option<(i64, Vec<u8>)> {
        let (m, cv) = &*self.inner;
        let mut s = m.lock().unwrap();
        let from = from.max(s.out_base);
        let until = std::time::Instant::now() + wait;
        loop {
            let start = (from - s.out_base) as usize;
            if start < s.out.len() {
                return Some((from, s.out[start..].to_vec()));
            }
            if s.closed {
                return None;
            }
            let left = until.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return None;
            }
            let (g, t) = cv.wait_timeout(s, left).unwrap();
            s = g;
            if t.timed_out() {
                return None;
            }
        }
    }
}
impl Read for Pipe {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        let (m, cv) = &*self.inner;
        let mut s = m.lock().unwrap();
        loop {
            if !s.in_buf.is_empty() {
                let n = b.len().min(s.in_buf.len());
                b[..n].copy_from_slice(&s.in_buf[..n]);
                s.in_buf.drain(..n);
                cv.notify_all();
                return Ok(n);
            }
            if s.closed {
                return Ok(0);
            }
            s = cv.wait(s).unwrap();
        }
    }
}
impl Write for Pipe {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        let (m, cv) = &*self.inner;
        let mut s = m.lock().unwrap();
        while s.out.len() + b.len() > PIPE_CAPACITY && !s.closed {
            s = cv.wait(s).unwrap();
        }
        if s.closed {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "pipe closed"));
        }
        s.out.extend_from_slice(b);
        cv.notify_all();
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Conn for Pipe {
    fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
    fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
    fn try_clone(&self) -> io::Result<Box<dyn Conn>> {
        Ok(Box::new(self.clone()))
    }
    fn shutdown_write(&self) -> io::Result<()> {
        Ok(())
    }
    fn shutdown_both(&self) -> io::Result<()> {
        self.close_with(None);
        Ok(())
    }
    fn describe(&self) -> String {
        format!("{} -> {}", self.local, self.remote)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn overlap_and_gap() {
        let p = Pipe::new("a", "b");
        assert_eq!(p.receive(0, b"abc", Duration::ZERO), Ok(3));
        assert_eq!(p.receive(1, b"bc", Duration::ZERO), Ok(3));
        assert_eq!(
            p.receive(5, b"x", Duration::ZERO),
            Err(ReceiveError::Gap(3))
        );
    }
    #[test]
    fn ack_bounds() {
        let mut p = Pipe::new("a", "b");
        p.write_all(b"abc").unwrap();
        assert!(p.ack(4).is_err());
        p.ack(2).unwrap();
        assert_eq!(p.pending(0, 9).unwrap().1, b"c");
    }
}
