//! Session state: the stream table, flow-control accounting and the two
//! background loops that keep a tunnel alive.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use super::{
    encode_header, MuxConfig, Opener, Stream, CMD_FIN, CMD_NOP, CMD_PSH, CMD_SYN, CMD_UPD,
    HEADER_LEN, INITIAL_PEER_WINDOW, UPD_LEN, VERSION,
};

// Per-stream state
// ---------------------------------------------------------------------------

pub(super) struct StreamState {
    /// Bytes received and not yet read.
    pub(super) inbox: VecDeque<u8>,
    /// The peer sent `FIN`.
    pub(super) fin: bool,
    /// The stream or its session is gone; every wait returns at once.
    pub(super) dead: bool,
    /// Bytes this side has handed to its reader, for `UPD`.
    pub(super) read_total: u32,
    /// Bytes consumed since the last `UPD`.
    pub(super) read_incr: u32,
    /// Bytes handed to the session for sending.
    pub(super) written: u32,
    /// What the peer's last `UPD` said it consumed.
    pub(super) peer_consumed: u32,
    /// What the peer's last `UPD` said its window is.
    pub(super) peer_window: u32,
    /// This side sent `FIN`.
    pub(super) write_closed: bool,
    pub(super) read_timeout: Option<Duration>,
    pub(super) write_timeout: Option<Duration>,
}

pub(super) struct Slot {
    pub(super) id: u32,
    /// Number of live `Stream` handles.  This intentionally excludes the
    /// session map and temporary references held by the reader loop.
    pub(super) handles: AtomicUsize,
    pub(super) st: Mutex<StreamState>,
    pub(super) cv_read: Condvar,
    pub(super) cv_write: Condvar,
}

impl Slot {
    fn new(id: u32) -> Arc<Slot> {
        Arc::new(Slot {
            id,
            handles: AtomicUsize::new(0),
            st: Mutex::new(StreamState {
                inbox: VecDeque::new(),
                fin: false,
                dead: false,
                read_total: 0,
                read_incr: 0,
                written: 0,
                peer_consumed: 0,
                peer_window: INITIAL_PEER_WINDOW,
                write_closed: false,
                read_timeout: None,
                write_timeout: None,
            }),
            cv_read: Condvar::new(),
            cv_write: Condvar::new(),
        })
    }
}

pub(super) struct Streams {
    map: HashMap<u32, Arc<Slot>>,
    /// Streams the peer opened and this side has not accepted yet.
    accept_q: VecDeque<u32>,
    next_sid: u32,
}

pub(super) struct Inner {
    pub(super) cfg: MuxConfig,
    pub(super) out: Mutex<Box<dyn Write + Send>>,
    pub(super) streams: Mutex<Streams>,
    pub(super) accept_cv: Condvar,
    pub(super) closed: AtomicBool,
    pub(super) last_rx: Mutex<Instant>,
    /// smux token bucket: receive bytes still available before the read
    /// loop pauses (MaxReceiveBuffer minus bytes buffered and unread).
    pub(super) bucket: Mutex<i64>,
    pub(super) bucket_cv: Condvar,
    /// Control frames waiting for the connection; data frames yield to them
    /// (smux shaper: CLSCTRL before CLSDATA).
    pub(super) ctrl_waiting: AtomicUsize,
    pub(super) data_gate: Mutex<()>,
    pub(super) data_cv: Condvar,
    pub(super) held: Mutex<Vec<Box<dyn std::any::Any + Send>>>,
    pub(super) closer: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

/// One multiplexed session: a byte-oriented connection carrying many streams.
pub struct Session {
    pub(super) inner: Arc<Inner>,
}

impl Session {
    /// Wraps a connection. `opener` decides stream-id parity: the side that
    /// accepts the tunnel uses odd ids and the side that dials it uses even
    /// ones, so the two never collide (smux's client/server split).
    pub fn new(
        reader: Box<dyn Read + Send>,
        writer: Box<dyn Write + Send>,
        cfg: MuxConfig,
        opener: Opener,
    ) -> Arc<Session> {
        let cfg_receive = cfg.max_receive_buffer.max(1);
        let next_sid = match opener {
            Opener::Odd => 3,
            Opener::Even => 2,
        };
        let inner = Arc::new(Inner {
            cfg,
            out: Mutex::new(writer),
            streams: Mutex::new(Streams {
                map: HashMap::new(),
                accept_q: VecDeque::new(),
                next_sid,
            }),
            accept_cv: Condvar::new(),
            closed: AtomicBool::new(false),
            last_rx: Mutex::new(Instant::now()),
            bucket: Mutex::new(i64::try_from(cfg_receive).unwrap_or(i64::MAX)),
            bucket_cv: Condvar::new(),
            ctrl_waiting: AtomicUsize::new(0),
            data_gate: Mutex::new(()),
            data_cv: Condvar::new(),
            held: Mutex::new(Vec::new()),
            closer: Mutex::new(None),
        });
        let session = Arc::new(Session {
            inner: inner.clone(),
        });
        let r = inner.clone();
        std::thread::spawn(move || read_loop(r, reader));
        let k = inner.clone();
        std::thread::spawn(move || keepalive_loop(k));
        session
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Relaxed)
    }

    pub fn num_streams(&self) -> usize {
        self.inner.streams.lock().unwrap().map.len()
    }

    pub fn close(&self) {
        self.inner.shutdown();
    }

    /// Keeps `item` (typically a budget lease) alive until the session
    /// closes, however it closes; dropped at once when already closed.
    pub fn hold_until_closed(&self, item: Box<dyn std::any::Any + Send>) {
        let mut held = self
            .inner
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.inner.closed.load(Ordering::SeqCst) {
            drop(held);
            drop(item);
            return;
        }
        held.push(item);
    }

    /// Installs the hook that closes the carrier connection on shutdown. If
    /// the session is already closed the hook runs now.
    pub fn set_closer(&self, closer: Box<dyn FnOnce() + Send>) {
        let mut slot = self.inner.closer.lock().unwrap();
        if self.is_closed() {
            drop(slot);
            closer();
            return;
        }
        *slot = Some(closer);
    }

    /// Opens a stream towards the peer.
    pub fn open(&self) -> io::Result<Stream> {
        let sid = {
            let mut g = self.inner.streams.lock().unwrap();
            if self.is_closed() {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "session closed"));
            }
            if g.map.len() >= self.inner.cfg.max_streams {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "stream limit of this tunnel reached",
                ));
            }
            // Ids advance by two; skipping one keeps the parity of the role.
            let sid = g.next_sid;
            if sid >= u32::MAX - 1 {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "stream ids exhausted",
                ));
            }
            g.next_sid += 2;
            let slot = Slot::new(sid);
            slot.handles.store(1, Ordering::Relaxed);
            g.map.insert(sid, slot);
            sid
        };
        if let Err(e) = self.inner.send(CMD_SYN, sid, &[]) {
            self.inner.remove_slot(sid);
            return Err(e);
        }
        let slot = self
            .inner
            .streams
            .lock()
            .unwrap()
            .map
            .get(&sid)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "session closed"))?;
        Ok(Stream {
            inner: self.inner.clone(),
            slot,
        })
    }

    /// Waits for a stream the peer opened. `timeout` bounds the wait so a
    /// caller can notice shutdown.
    pub fn accept(&self, timeout: Duration) -> io::Result<Option<Stream>> {
        let deadline = Instant::now() + timeout;
        loop {
            let mut g = self.inner.streams.lock().unwrap();
            while g.accept_q.is_empty() {
                if self.is_closed() {
                    return Ok(None);
                }
                let now = Instant::now();
                if now >= deadline {
                    return Ok(None);
                }
                let (next, _) = self
                    .inner
                    .accept_cv
                    .wait_timeout(g, deadline - now)
                    .unwrap();
                g = next;
            }
            let sid = g.accept_q.pop_front().unwrap();
            if let Some(slot) = g.map.get(&sid).cloned() {
                slot.handles.fetch_add(1, Ordering::Relaxed);
                return Ok(Some(Stream {
                    inner: self.inner.clone(),
                    slot,
                }));
            }
            // The stream was closed between the SYN and now; look for another.
        }
    }
}

impl Inner {
    pub(super) fn remove_slot(&self, sid: u32) {
        let slot = self.streams.lock().unwrap().map.remove(&sid);
        if let Some(slot) = slot {
            // smux recycleTokens: unread bytes of a closed stream go back to
            // the session bucket.
            let unread = {
                let mut st = slot.st.lock().unwrap();
                let n = st.inbox.len();
                st.inbox.clear();
                n
            };
            self.return_tokens(unread);
            slot.cv_read.notify_all();
            slot.cv_write.notify_all();
        }
    }

    /// smux returnTokens: `n` buffered bytes left the session.
    pub(super) fn return_tokens(&self, n: usize) {
        if n == 0 {
            return;
        }
        let mut b = self.bucket.lock().unwrap();
        let was_empty = *b <= 0;
        *b = b.saturating_add(n as i64);
        drop(b);
        if was_empty {
            self.bucket_cv.notify_all();
        }
    }

    /// Writes one frame with a single `write_all` of header and payload (one
    /// WebSocket message per frame, like smux sendLoop). Control frames are
    /// prioritized over data frames waiting for the connection.
    pub(super) fn send(&self, cmd: u8, sid: u32, payload: &[u8]) -> io::Result<()> {
        if self.closed.load(Ordering::Relaxed) && cmd != CMD_FIN {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "session closed"));
        }
        let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
        frame.extend_from_slice(&encode_header(cmd, sid, payload.len()));
        frame.extend_from_slice(payload);
        let control = !matches!(cmd, CMD_PSH | CMD_FIN);
        if control {
            self.ctrl_waiting.fetch_add(1, Ordering::SeqCst);
            let result = self.write_frame(&frame);
            if self.ctrl_waiting.fetch_sub(1, Ordering::SeqCst) == 1 {
                let _g = self.data_gate.lock().unwrap();
                self.data_cv.notify_all();
            }
            return result;
        }
        loop {
            {
                let mut out = self.out.lock().unwrap();
                // A data frame takes the connection only when no control
                // frame is waiting for it; otherwise it lets go and waits.
                if self.ctrl_waiting.load(Ordering::SeqCst) == 0
                    || self.closed.load(Ordering::Relaxed)
                {
                    out.write_all(&frame)?;
                    return out.flush();
                }
            }
            let mut g = self.data_gate.lock().unwrap();
            while self.ctrl_waiting.load(Ordering::SeqCst) > 0
                && !self.closed.load(Ordering::Relaxed)
            {
                g = self
                    .data_cv
                    .wait_timeout(g, Duration::from_millis(50))
                    .unwrap()
                    .0;
            }
        }
    }

    fn write_frame(&self, frame: &[u8]) -> io::Result<()> {
        let mut out = self.out.lock().unwrap();
        out.write_all(frame)?;
        out.flush()
    }

    fn shutdown(&self) {
        if self.closed.swap(true, Ordering::SeqCst) {
            return;
        }
        let held = std::mem::take(
            &mut *self
                .held
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        drop(held);
        self.bucket_cv.notify_all();
        self.data_cv.notify_all();
        // Wake every waiter: readers see EOF, writers see a broken pipe.
        {
            let mut g = self.streams.lock().unwrap();
            for slot in g.map.values() {
                let mut st = slot.st.lock().unwrap();
                st.dead = true;
                drop(st);
                slot.cv_read.notify_all();
                slot.cv_write.notify_all();
            }
            g.map.clear();
            g.accept_q.clear();
        }
        self.accept_cv.notify_all();
        let closer = self
            .closer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(closer) = closer {
            closer();
        }
        // Never wait for a writer stalled on a dead carrier here.
        if let Ok(mut out) = self.out.try_lock() {
            let _ = out.flush();
        }
    }
}

/// Decodes and validates the fixed-size smux header before the read loop can
/// allocate or consume any command payload.
pub(super) fn decode_header(raw: &[u8], max_frame_size: usize) -> Option<(u8, usize, u32)> {
    if raw.len() != HEADER_LEN || raw[0] != VERSION {
        return None;
    }
    let cmd = raw[1];
    let len = u16::from_le_bytes([raw[2], raw[3]]) as usize;
    let sid = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
    let valid_len = match cmd {
        CMD_SYN | CMD_FIN | CMD_NOP => len == 0,
        CMD_PSH => len > 0 && len <= max_frame_size,
        CMD_UPD => len == UPD_LEN,
        _ => false,
    };
    valid_len.then_some((cmd, len, sid))
}

fn read_loop(inner: Arc<Inner>, mut reader: Box<dyn Read + Send>) {
    let mut head = [0u8; HEADER_LEN];
    loop {
        if inner.closed.load(Ordering::Relaxed) {
            return;
        }
        // smux recvLoop: no frame is read while the receive bucket is used
        // up; reading resumes as streams consume (or close).
        {
            let mut b = inner.bucket.lock().unwrap();
            while *b <= 0 && !inner.closed.load(Ordering::Relaxed) {
                b = inner
                    .bucket_cv
                    .wait_timeout(b, Duration::from_millis(200))
                    .unwrap()
                    .0;
            }
        }
        if inner.closed.load(Ordering::Relaxed) {
            return;
        }
        if let Err(e) = read_exact(&mut reader, &mut head) {
            if e.kind() != io::ErrorKind::Interrupted {
                break;
            }
            continue;
        }
        *inner.last_rx.lock().unwrap() = Instant::now();
        let Some((cmd, len, sid)) = decode_header(&head, inner.cfg.max_frame_size) else {
            break;
        };

        match cmd {
            CMD_NOP => {}
            CMD_SYN => {
                let (accepted, over_limit) = {
                    let mut g = inner.streams.lock().unwrap();
                    if g.map.contains_key(&sid) {
                        (false, false)
                    } else if g.map.len() < inner.cfg.max_streams {
                        g.map.insert(sid, Slot::new(sid));
                        g.accept_q.push_back(sid);
                        (true, false)
                    } else {
                        (false, true)
                    }
                };
                if accepted {
                    inner.accept_cv.notify_all();
                } else if over_limit {
                    // smux explicitly rejects an over-limit peer SYN.
                    let _ = inner.send(CMD_FIN, sid, &[]);
                }
            }
            CMD_FIN => {
                let slot = inner.streams.lock().unwrap().map.get(&sid).cloned();
                if let Some(slot) = slot {
                    let reclaim = {
                        let mut st = slot.st.lock().unwrap();
                        st.fin = true;
                        st.write_closed
                    };
                    if reclaim {
                        inner.remove_slot(sid);
                    }
                    slot.cv_read.notify_all();
                }
            }
            CMD_PSH => {
                let mut payload = vec![0u8; len];
                if read_exact(&mut reader, &mut payload).is_err() {
                    break;
                }
                *inner.last_rx.lock().unwrap() = Instant::now();
                // smux pushes the data to the stream whatever its window and
                // charges the session bucket: a peer that overruns one
                // stream's window only pauses the read loop (bucket), it does
                // not end the session and its other streams.
                let streams = inner.streams.lock().unwrap();
                if let Some(slot) = streams.map.get(&sid).cloned() {
                    let mut st = slot.st.lock().unwrap();
                    if st.dead {
                        continue;
                    }
                    st.inbox.extend(payload);
                    drop(st);
                    *inner.bucket.lock().unwrap() -= len as i64;
                    drop(streams);
                    slot.cv_read.notify_all();
                }
                // Data for a stream this side already closed is dropped, as
                // smux does: the peer may still have frames in flight.
            }
            CMD_UPD => {
                let mut upd = [0u8; UPD_LEN];
                if read_exact(&mut reader, &mut upd).is_err() {
                    break;
                }
                *inner.last_rx.lock().unwrap() = Instant::now();
                let consumed = u32::from_le_bytes([upd[0], upd[1], upd[2], upd[3]]);
                let window = u32::from_le_bytes([upd[4], upd[5], upd[6], upd[7]]);
                let slot = inner.streams.lock().unwrap().map.get(&sid).cloned();
                if let Some(slot) = slot {
                    let mut st = slot.st.lock().unwrap();
                    st.peer_consumed = consumed;
                    st.peer_window = window;
                    drop(st);
                    slot.cv_write.notify_all();
                }
            }
            _ => unreachable!("decode_header rejects unknown smux commands"),
        }
    }
    inner.shutdown();
}

fn read_exact(r: &mut Box<dyn Read + Send>, buf: &mut [u8]) -> io::Result<()> {
    let mut got = 0;
    while got < buf.len() {
        match r.read(&mut buf[got..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "tunnel closed",
                ))
            }
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn keepalive_loop(inner: Arc<Inner>) {
    let tick = inner.cfg.keepalive.max(Duration::from_millis(50));
    loop {
        std::thread::sleep(tick);
        if inner.closed.load(Ordering::Relaxed) {
            return;
        }
        let silent = inner.last_rx.lock().unwrap().elapsed();
        if silent > inner.cfg.detect {
            inner.shutdown();
            return;
        }
        if inner.send(CMD_NOP, 0, &[]).is_err() {
            inner.shutdown();
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Stream I/O
// ---------------------------------------------------------------------------
