//! Session state machine and the offset accounting both sides rely on.
//!
//! A session is one database connection. Bytes in each direction form a
//! contiguous stream addressed by offset:
//!
//! * upstream — the ingress reads the client socket, frames it, and the egress
//!   writes the bytes to the backend in offset order (`up_flushed`);
//! * downstream — the egress reads the backend and emits frames
//!   (`down_produced`), while the ingress reports what it delivered
//!   (`down_ack`), which bounds how far ahead the egress may read.
//!
//! Recovery state is kept here, while transition and validation logic lives in
//! [`recovery`]. Transport integration can attach to that API without copying
//! backend buffers.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::Write;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::Instant;

use crate::error::{Error, Result};
use crate::resource::budget::BudgetLease;
use crate::resource::retention::{Retention, RetentionLease};
use crate::stream::byte_window::ByteWindow;
use crate::wire::{
    self, Limits, Mode, ERR_BACKEND_LOST, ERR_FRAME_CONFLICT, ERR_SESSION_CLOSED, ERR_STALE_EPOCH,
};

mod down;
mod pump;
pub mod recovery;

pub use pump::DownPump;

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "spec_session_tests.rs"]
mod spec_session_tests;

#[cfg(test)]
#[path = "spec_session3_tests.rs"]
mod spec_session3_tests;

#[cfg(test)]
#[path = "spec_pump2_tests.rs"]
mod spec_pump2_tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Attaching,
    Active,
    Closed,
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub session_id: String,
    pub instance_id: String,
    pub stream_id: String,
    // Kept in the snapshot schema for consumers; runtime routing reads the
    // session's active mode directly.
    #[allow(dead_code)]
    pub mode: Mode,
    pub ack_up_offset: u64,
    pub up_fin_applied: bool,
    pub down_ack_offset: u64,
    pub down_fin_acked: bool,
    pub down_produced: u64,
}

pub(crate) struct SessionMetricsSnapshot {
    pub state: &'static str,
    pub carrier: &'static str,
    pub up_pending_frames: u64,
    pub down_retained_frames: u64,
    pub digest_receipts: u64,
    pub down_unconfirmed_bytes: u64,
}

/// Bounded terminal metadata retained by the registry after a session closes.
/// It deliberately contains no backend socket, byte buffers, receipt table or
/// timers, so terminal routing cannot keep live resources pinned until TTL.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Tombstone {
    pub id: String,
    pub token: String,
    pub instance_id: String,
    pub owner_peer: String,
    pub target_id: String,
    pub mode: Mode,
    pub epoch: u64,
    pub stream_id: String,
    pub up_written: u64,
    pub up_flushed: u64,
    pub up_fin: bool,
    pub up_fin_final: Option<u64>,
    pub down_produced: u64,
    pub down_ack: u64,
    pub down_fin: bool,
    pub down_fin_acked: bool,
    pub ack_up: u64,
    pub last_resume_request_id: String,
    pub terminal_code: String,
    pub terminal_retryable: bool,
}

impl Tombstone {
    pub fn closed_normally_for(&self, epoch: u64, stream: &str) -> bool {
        self.up_fin
            && self.down_fin_acked
            && !stream.is_empty()
            && self.stream_id == stream
            && epoch == self.epoch
    }

    pub fn terminal_error(&self) -> Error {
        Error::new(&self.terminal_code, "session closed")
            .closed(true)
            .retryable(self.terminal_retryable)
    }
}

/// One out-of-order /up frame waiting for its turn: payload, digest and
/// its payload budget lease.
type PendingUp = (Vec<u8>, [u8; 32], Option<BudgetLease>);

#[allow(dead_code)]
struct Inner {
    state: State,
    change_generation: u64,
    stream_id: String,
    active_mode: Mode,
    /// Highest contiguous offset claimed by an upstream write operation.
    up_written: u64,
    /// Highest contiguous offset whose backend `write_all` has completed.
    up_flushed: u64,
    up_fin: bool,
    /// The offset a FIN named, once one has arrived. May lead `up_written`.
    up_fin_final: Option<u64>,
    down_produced: u64,
    down_ack: u64,
    /// Frame end offsets still eligible for downstream acknowledgement.
    down_boundaries: BTreeSet<u64>,
    /// Unacknowledged downstream bytes retained for a replacement carrier.
    /// The backing window charges full allocation capacity.
    down_window: ByteWindow,
    down_fin: bool,
    down_fin_acked: bool,
    terminal: Option<Error>,
    last_resume_request_id: String,
    attached: bool,
    /// Stream ID retired by the most recent generation change. Keeping this
    /// fence prevents an old carrier racing a successful resume from
    /// re-attaching itself after the new generation has been committed.
    retired_stream_id: Option<String>,
    last_control: Instant,
    heartbeat_nonce: String,
    heartbeat_epoch: u64,
    heartbeat_stream: String,
    data_plane_active: bool,
    /// Recently written upstream frames, for duplicate detection and ACK
    /// boundaries. Entries are retained until the peer confirms them.
    receipts: VecDeque<(u64, u64, [u8; 32])>,
    /// Highest upstream offset explicitly confirmed by the peer.
    receipt_floor: u64,
    receipt_limit: usize,
    /// Frames that arrived ahead of the stream, keyed by offset.
    ///
    /// The `http-sse` carrier sends each upstream frame as its own POST, so
    /// several can be in flight on different pooled connections at once and
    /// arrive out of order. Reordering them here is not an optimisation: a
    /// session cannot make progress at all unless the frames are put back into
    /// offset order before they reach the backend.
    up_pending: BTreeMap<u64, PendingUp>,
    up_pending_bytes: usize,
    up_write_active: bool,
    transport_writing: bool,
    transport_rx_blocked: bool,
    recovery_enabled: bool,
    recovery_grace: std::time::Duration,
    recovery_deadline: Option<Instant>,
    recovery_lease: Option<Arc<RetentionLease>>,
    recovery_state_suspended: bool,
    resume_busy: bool,
    resume_pending_id: Option<String>,
    resume_pending_fingerprint: Option<String>,
    last_resume_id: Option<String>,
    last_resume_fingerprint: Option<String>,
    last_resume_response: Option<recovery::ResumeResponse>,
}

/// Returns the highest upstream frame boundary whose bytes are fully flushed
/// to the backend. `up_flushed` may advance partway through a frame while
/// `write_all` is in progress, but protocol ACKs must always name whole frames.
fn ack_up_boundary(g: &Inner) -> u64 {
    g.receipts
        .iter()
        .take_while(|(_, end, _)| *end <= g.up_flushed)
        .last()
        .map(|(_, end, _)| *end)
        .unwrap_or(g.receipt_floor)
}

pub struct Session {
    pub id: String,
    pub token: String,
    pub instance_id: String,
    ingress_instance_id: String,
    pub owner_peer: String,
    pub target_id: String,
    // Public compatibility field; resumed sessions track the active carrier
    // mode in `Inner::active_mode`.
    #[allow(dead_code)]
    pub mode: Mode,
    pub limits: Limits,
    pub(crate) epoch: std::sync::atomic::AtomicU64,
    self_weak: Weak<Session>,
    backend: Arc<TcpStream>,
    /// Serialises upstream application. Held for the whole of `ingest_up`,
    /// including the backend write, so frames reach the socket in offset
    /// order; it is *not* the state lock, so the downstream pump keeps
    /// running while a slow backend drains.
    up_lock: Mutex<()>,
    /// Only one generation may read the backend stream at a time.
    down_lock: Mutex<()>,
    inner: Mutex<Inner>,
    cv: Condvar,
    closed: AtomicBool,
    up_inflight: AtomicUsize,
    suspended_retention: Mutex<Option<Arc<Retention>>>,
    retained_payload_bytes: Arc<AtomicUsize>,
    resource_leases: Mutex<Vec<BudgetLease>>,
    /// Frame and byte counters for the admin endpoint.
    pub metrics: Arc<crate::metrics::Metrics>,
}

impl Session {
    #[allow(clippy::too_many_arguments)]
    // Retained for compatibility/test callers; production ingress paths use
    // `new_with_ingress_instance_id`.
    #[allow(dead_code)]
    pub fn new(
        id: String,
        token: String,
        instance_id: String,
        owner_peer: String,
        target_id: String,
        mode: Mode,
        limits: Limits,
        receipt_limit: u32,
        backend: TcpStream,
        metrics: Arc<crate::metrics::Metrics>,
    ) -> Arc<Session> {
        Self::new_with_ingress_instance_id(
            id,
            token,
            instance_id.clone(),
            instance_id,
            owner_peer,
            target_id,
            mode,
            limits,
            receipt_limit,
            backend,
            metrics,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_ingress_instance_id(
        id: String,
        token: String,
        instance_id: String,
        ingress_instance_id: String,
        owner_peer: String,
        target_id: String,
        mode: Mode,
        limits: Limits,
        receipt_limit: u32,
        backend: TcpStream,
        metrics: Arc<crate::metrics::Metrics>,
    ) -> Arc<Session> {
        let down_capacity = i64::try_from(limits.down_buffer_bytes).unwrap_or(i64::MAX);
        Arc::new_cyclic(|weak| Session {
            id,
            token,
            instance_id,
            ingress_instance_id,
            owner_peer,
            target_id,
            mode,
            limits,
            epoch: std::sync::atomic::AtomicU64::new(1),
            self_weak: weak.clone(),
            backend: Arc::new(backend),
            up_lock: Mutex::new(()),
            down_lock: Mutex::new(()),
            inner: Mutex::new(Inner {
                state: State::Attaching,
                change_generation: 0,
                stream_id: String::new(),
                active_mode: mode,
                up_written: 0,
                up_flushed: 0,
                up_fin: false,
                up_fin_final: None,
                down_produced: 0,
                down_ack: 0,
                down_boundaries: BTreeSet::new(),
                down_window: ByteWindow::new(0, down_capacity),
                down_fin: false,
                down_fin_acked: false,
                terminal: None,
                last_resume_request_id: String::new(),
                attached: false,
                retired_stream_id: None,
                last_control: Instant::now(),
                heartbeat_nonce: String::new(),
                heartbeat_epoch: 0,
                heartbeat_stream: String::new(),
                data_plane_active: false,
                receipts: VecDeque::new(),
                receipt_floor: 0,
                receipt_limit: receipt_limit.max(1) as usize,
                up_pending: BTreeMap::new(),
                up_pending_bytes: 0,
                up_write_active: false,
                transport_writing: false,
                transport_rx_blocked: false,
                recovery_enabled: false,
                recovery_grace: std::time::Duration::ZERO,
                recovery_deadline: None,
                recovery_lease: None,
                recovery_state_suspended: false,
                resume_busy: false,
                resume_pending_id: None,
                resume_pending_fingerprint: None,
                last_resume_id: None,
                last_resume_fingerprint: None,
                last_resume_response: None,
            }),
            cv: Condvar::new(),
            closed: AtomicBool::new(false),
            up_inflight: AtomicUsize::new(0),
            suspended_retention: Mutex::new(None),
            retained_payload_bytes: Arc::new(AtomicUsize::new(0)),
            resource_leases: Mutex::new(Vec::new()),
            metrics,
        })
    }

    pub(crate) fn hold_resource_lease(&self, lease: BudgetLease) {
        self.resource_leases
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(lease);
    }

    pub(crate) fn release_resource_leases(&self) {
        self.resource_leases
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }

    pub(crate) fn set_suspended_retention(&self, retention: Arc<Retention>) {
        *self
            .suspended_retention
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(retention);
    }

    fn sync_retained_payload_bytes(&self, g: &Inner) {
        self.retained_payload_bytes.store(
            g.up_pending_bytes
                .saturating_add(g.down_window.buffered_bytes()),
            Ordering::Release,
        );
    }

    fn enforce_suspended_retention(&self) {
        let retention = self
            .suspended_retention
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(retention) = retention {
            retention.enforce_used();
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::Acquire)
    }

    /// Returns the carrier mode currently attached to this session.
    pub fn current_mode(&self) -> Mode {
        self.inner.lock().unwrap().active_mode
    }

    pub fn backend(&self) -> Arc<TcpStream> {
        self.backend.clone()
    }

    pub(crate) fn lock_downstream(&self) -> std::sync::MutexGuard<'_, ()> {
        self.down_lock.lock().unwrap()
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub fn try_acquire_up(&self) -> Option<UpPermit<'_>> {
        let limit = self.limits.up_max_inflight_frames as usize;
        // The permit is built only on success: dropping one releases a slot.
        if crate::util::increment_below(&self.up_inflight, limit) {
            Some(UpPermit { session: self })
        } else {
            None
        }
    }

    pub fn terminal_error(&self) -> Option<Error> {
        self.inner.lock().unwrap().terminal.clone()
    }

    pub fn compact_tombstone(&self) -> Tombstone {
        let g = self.inner.lock().unwrap();
        let (terminal_code, terminal_retryable) = g
            .terminal
            .as_ref()
            .map(|error| (error.code.clone(), error.retryable))
            .unwrap_or_else(|| (ERR_SESSION_CLOSED.to_string(), false));
        Tombstone {
            id: self.id.clone(),
            token: self.token.clone(),
            instance_id: self.instance_id.clone(),
            owner_peer: self.owner_peer.clone(),
            target_id: self.target_id.clone(),
            mode: g.active_mode,
            epoch: self.epoch(),
            stream_id: g.stream_id.clone(),
            up_written: g.up_written,
            up_flushed: g.up_flushed,
            up_fin: g.up_fin,
            up_fin_final: g.up_fin_final,
            down_produced: g.down_produced,
            down_ack: g.down_ack,
            down_fin: g.down_fin,
            down_fin_acked: g.down_fin_acked,
            ack_up: ack_up_boundary(&g),
            last_resume_request_id: bounded_utf8_prefix(&g.last_resume_request_id, 128),
            terminal_code,
            terminal_retryable,
        }
    }

    /// Marks the session attached to a carrier and picks the stream ID.
    pub fn attach(&self, stream_id: &str) -> Result<()> {
        self.expire_recovery();
        let mut g = self.inner.lock().unwrap();
        if g.state == State::Closed {
            return Err(g
                .terminal
                .clone()
                .unwrap_or_else(|| Error::new(ERR_SESSION_CLOSED, "session closed")));
        }
        if g.retired_stream_id.as_deref() == Some(stream_id) {
            return Err(Error::new(ERR_STALE_EPOCH, "carrier epoch replaced"));
        }
        if g.recovery_state_suspended || g.resume_busy {
            return Err(Error::new(ERR_STALE_EPOCH, "carrier epoch suspended"));
        }
        if g.attached && g.stream_id != stream_id {
            return Err(Error::new(
                wire::ERR_STREAM_EXISTS,
                "session already attached",
            ));
        }
        g.attached = true;
        g.stream_id = stream_id.to_string();
        g.state = State::Active;
        g.last_control = Instant::now();
        g.data_plane_active = false;
        g.heartbeat_nonce.clear();
        g.heartbeat_epoch = 0;
        g.heartbeat_stream.clear();
        drop(g);
        self.notify_change();
        Ok(())
    }

    pub fn check_stream(&self, epoch: u64, stream: &str) -> Result<()> {
        self.expire_recovery();
        let g = self.inner.lock().unwrap();
        if g.state == State::Closed {
            return Err(g
                .terminal
                .clone()
                .unwrap_or_else(|| Error::new(ERR_SESSION_CLOSED, "session closed")));
        }
        if epoch != self.epoch() {
            return Err(Error::new(ERR_STALE_EPOCH, "epoch"));
        }
        if g.stream_id.is_empty() || g.stream_id != stream {
            return Err(
                Error::new(wire::ERR_WINDOW_EXCEEDED, "data plane not active").retryable(true),
            );
        }
        Ok(())
    }

    pub fn snapshot(&self) -> Snapshot {
        let g = self.inner.lock().unwrap();
        Snapshot {
            session_id: self.id.clone(),
            instance_id: self.instance_id.clone(),
            stream_id: g.stream_id.clone(),
            mode: g.active_mode,
            ack_up_offset: ack_up_boundary(&g),
            up_fin_applied: g.up_fin,
            down_ack_offset: g.down_ack,
            down_fin_acked: g.down_fin_acked,
            down_produced: g.down_produced,
        }
    }

    pub(crate) fn metrics_snapshot(&self, draining: bool) -> SessionMetricsSnapshot {
        let g = self.inner.lock().unwrap();
        let state = if g.state == State::Closed {
            "CLOSED"
        } else if g.resume_busy {
            "RESUMING"
        } else if g.recovery_state_suspended {
            "SUSPENDED"
        } else if g.state == State::Attaching {
            "ATTACHING"
        } else if g.down_fin || draining {
            "DRAINING"
        } else {
            "ACTIVE"
        };
        SessionMetricsSnapshot {
            state,
            carrier: g.active_mode.as_str(),
            up_pending_frames: g.up_pending.len() as u64,
            down_retained_frames: g.down_boundaries.len() as u64,
            digest_receipts: g.receipts.len() as u64,
            down_unconfirmed_bytes: g.down_produced.saturating_sub(g.down_ack),
        }
    }

    /// Writes one upstream frame to the backend, in offset order.
    ///
    /// A frame that was already applied is accepted and ignored, which is what
    /// makes a retried POST harmless. A partial overlap is a protocol error:
    /// the stream is contiguous by construction.
    ///
    /// A frame that arrives *ahead* of the stream is not an error. The
    /// `http-sse` carrier sends every upstream frame as its own POST on a
    /// pooled connection, so several are in flight at once and their arrival
    /// order has nothing to do with their offsets. Such a frame is held in
    /// `up_pending` and applied once the frames before it arrive.
    ///
    /// The backend write happens under `up_lock` rather than the state lock.
    /// The backend socket is one ordered byte stream, so the decision to write
    /// and the write itself have to be one step: splitting them lets a later
    /// frame reach the socket first, and lets a FIN that closes the write side
    /// overtake a frame still on its way. Using a separate lock keeps the state
    /// lock free, so a slow backend delays acks without stalling the
    /// downstream pump.
    ///
    /// `up_written` reserves contiguous ranges while writes are in progress;
    /// `up_flushed` advances only after each complete backend write, and is the
    /// offset exposed to acknowledgements and FIN settlement.
    pub fn ingest_up(&self, epoch: u64, offset: u64, payload: &[u8]) -> Result<()> {
        match self.ingest_up_inner(epoch, offset, payload) {
            Err(error) if error.code == ERR_FRAME_CONFLICT => {
                let terminal = error.closed(true);
                self.close(terminal.clone());
                Err(terminal)
            }
            result => result,
        }
    }

    fn ingest_up_inner(&self, epoch: u64, offset: u64, payload: &[u8]) -> Result<()> {
        if epoch != self.epoch() {
            return Err(Error::new(ERR_STALE_EPOCH, "epoch"));
        }
        let _serial = self.up_lock.lock().unwrap();
        let digest = crate::util::sha256::digest(payload);
        // Frames to write, in offset order. Usually just the one that arrived,
        // plus anything the arrival unblocked from the reorder queue.
        let mut ready: Vec<(Vec<u8>, [u8; 32], Option<BudgetLease>)> = Vec::new();
        {
            let mut g = self.inner.lock().unwrap();
            if g.state == State::Closed {
                return Err(g
                    .terminal
                    .clone()
                    .unwrap_or_else(|| Error::new(ERR_SESSION_CLOSED, "session closed")));
            }
            let end = match offset.checked_add(payload.len() as u64) {
                Some(e) => e,
                None => {
                    return Err(Error::new(
                        ERR_FRAME_CONFLICT,
                        format!("frame at {offset} runs past the end of the offset space"),
                    ))
                }
            };
            // The window is measured from the applied offset, not from the
            // previous frame: a peer must not queue frames arbitrarily far
            // ahead of what it has been granted room for.
            let horizon = g.up_written.saturating_add(self.limits.up_window_bytes);
            if end > horizon {
                return Err(Error::new(
                    wire::ERR_WINDOW_EXCEEDED,
                    format!("frame ends at {end}, beyond the window edge {horizon}"),
                ));
            }
            // Data past a FIN that has already been seen is a contradiction:
            // the peer has declared where the stream ends.
            if let Some(fin) = g.up_fin_final {
                if end > fin {
                    return Err(Error::new(
                        ERR_FRAME_CONFLICT,
                        format!("frame ends at {end}, past the FIN at {fin}"),
                    ));
                }
            }
            if self.limits.max_frame_size > 0 && payload.len() > self.limits.max_frame_size {
                return Err(Error::new(
                    wire::ERR_FRAME_TOO_LARGE,
                    format!(
                        "frame of {} bytes exceeds negotiated max_frame_size {}",
                        payload.len(),
                        self.limits.max_frame_size
                    ),
                ));
            }
            if end <= g.up_written {
                if let Some((_, e, prev)) = g.receipts.iter().find(|(o, _, _)| *o == offset) {
                    if *e != end || prev != &digest {
                        return Err(Error::new(
                            ERR_FRAME_CONFLICT,
                            "replayed frame differs from the applied one",
                        ));
                    }
                    return Ok(());
                }
                if end <= g.up_flushed {
                    return Err(Error::new(
                        wire::ERR_REPLAY_TOO_OLD,
                        "replayed frame is no longer retained",
                    ));
                }
                return Err(Error::new(
                    ERR_FRAME_CONFLICT,
                    format!("frame [{offset},{end}) overlaps an in-flight frame"),
                ));
            }
            if offset < g.up_written {
                return Err(Error::new(
                    ERR_FRAME_CONFLICT,
                    format!(
                        "frame [{offset},{end}) overlaps applied offset {}",
                        g.up_written
                    ),
                ));
            }
            if g.up_pending.iter().any(|(queued, (buf, _, _))| {
                *queued != offset
                    && offset < queued.saturating_add(buf.len() as u64)
                    && end > *queued
            }) {
                return Err(Error::new(
                    ERR_FRAME_CONFLICT,
                    format!("frame [{offset},{end}) overlaps a queued frame"),
                ));
            }
            if offset > g.up_written {
                // Ahead of the stream: hold it until the gap is filled.
                if let Some((prev, _, _)) = g.up_pending.get(&offset) {
                    if prev.as_slice() == payload {
                        return Ok(());
                    }
                    return Err(Error::new(
                        ERR_FRAME_CONFLICT,
                        "queued frame replayed with different bytes",
                    ));
                }
                if g.up_pending.len() >= self.limits.up_max_inflight_frames as usize {
                    return Err(Error::new(
                        wire::ERR_WINDOW_EXCEEDED,
                        format!("{} frames already queued out of order", g.up_pending.len()),
                    ));
                }
                if g.up_pending_bytes + payload.len() > self.limits.up_window_bytes as usize {
                    return Err(Error::new(
                        wire::ERR_WINDOW_EXCEEDED,
                        format!(
                            "{} bytes queued out of order exceeds the window",
                            g.up_pending_bytes + payload.len()
                        ),
                    ));
                }
                let payload_lease = g.down_window.reserve_payload(payload.len()).map_err(|_| {
                    Error::new(
                        wire::ERR_BUFFER_EXHAUSTED,
                        "global payload budget exhausted",
                    )
                })?;
                g.up_pending
                    .insert(offset, (payload.to_vec(), digest, payload_lease));
                g.up_pending_bytes += payload.len();
                self.sync_retained_payload_bytes(&g);
                g.last_control = Instant::now();
                drop(g);
                self.notify_change();
                return Ok(());
            }
            // In order. Claim this frame and everything the queue can now
            // deliver, then write them in one pass outside the state lock.
            // Never evict an unconfirmed receipt. The peer must confirm some
            // retained frame boundary before more upstream frames can be
            // admitted, otherwise duplicate detection would silently regress.
            let mut ready_count = 1usize;
            let mut next = end;
            while let Some((buf, _, _)) = g.up_pending.get(&next) {
                ready_count += 1;
                next = next
                    .checked_add(buf.len() as u64)
                    .ok_or_else(|| Error::new(ERR_FRAME_CONFLICT, "upstream offset overflow"))?;
            }
            if g.receipts.len().saturating_add(ready_count) > g.receipt_limit {
                return Err(Error::new(
                    wire::ERR_WINDOW_EXCEEDED,
                    "unconfirmed upstream receipt window exceeded",
                )
                .retryable(true));
            }
            let payload_lease = g.down_window.reserve_payload(payload.len()).map_err(|_| {
                Error::new(
                    wire::ERR_BUFFER_EXHAUSTED,
                    "global payload budget exhausted",
                )
            })?;
            g.up_written = end;
            g.receipts.push_back((offset, end, digest));
            ready.push((payload.to_vec(), digest, payload_lease));
            while let Some((buf, sum, payload_lease)) = {
                let at = g.up_written;
                g.up_pending.remove(&at)
            } {
                let at = g.up_written;
                g.up_written = at + buf.len() as u64;
                g.up_pending_bytes -= buf.len();
                self.sync_retained_payload_bytes(&g);
                let end = at + buf.len() as u64;
                g.receipts.push_back((at, end, sum));
                ready.push((buf, sum, payload_lease));
            }
            g.last_control = Instant::now();
        }
        {
            let mut g = self.inner.lock().unwrap();
            g.up_write_active = true;
        }
        let mut sock: &TcpStream = &self.backend;
        let mut fin_due = false;
        let write_result = (|| -> Result<()> {
            for (buf, _, _payload_lease) in &ready {
                sock.write_all(buf).map_err(|e| {
                    let err =
                        Error::new(ERR_BACKEND_LOST, format!("backend write: {e}")).closed(true);
                    self.close(err.clone());
                    err
                })?;
                self.metrics.upstream(buf.len());
                let mut g = self.inner.lock().unwrap();
                g.up_flushed = g
                    .up_flushed
                    .checked_add(buf.len() as u64)
                    .ok_or_else(|| Error::new(ERR_FRAME_CONFLICT, "upstream offset overflow"))?;
                let mut fin_applied_now = false;
                if !g.up_fin && g.up_fin_final == Some(g.up_flushed) {
                    g.up_fin = true;
                    fin_due = true;
                    fin_applied_now = true;
                }
                drop(g);
                if fin_applied_now {
                    self.metrics.upstream_fin_applied();
                }
            }
            Ok(())
        })();
        self.inner.lock().unwrap().up_write_active = false;
        write_result?;
        if fin_due {
            let _ = self.backend.shutdown(std::net::Shutdown::Write);
        }
        self.notify_change();
        Ok(())
    }

    /// Applies the upstream FIN.
    ///
    /// The FIN travels on the control connection, which has no ordering
    /// relationship with the data carrier, so it routinely arrives while the
    /// last frames are still in flight. A FIN naming an offset *ahead* of what
    /// has been applied is therefore normal: it is recorded and applied once
    /// the gap closes. A FIN naming an offset *behind* the applied offset is a
    /// real contradiction and is refused.
    pub fn ingest_up_fin(&self, epoch: u64, final_offset: u64) -> Result<bool> {
        match self.ingest_up_fin_inner(epoch, final_offset) {
            Err(error) if error.code == ERR_FRAME_CONFLICT => {
                let terminal = error.closed(true);
                self.close(terminal.clone());
                Err(terminal)
            }
            result => result,
        }
    }

    fn ingest_up_fin_inner(&self, epoch: u64, final_offset: u64) -> Result<bool> {
        if epoch != self.epoch() {
            return Err(Error::new(ERR_STALE_EPOCH, "epoch"));
        }
        // Match ingest_up's lock order. FIN cannot shut down the backend while
        // an already-claimed write is still in flight.
        let _serial = self.up_lock.lock().unwrap();
        let mut g = self.inner.lock().unwrap();
        if g.state == State::Closed {
            return Err(g
                .terminal
                .clone()
                .unwrap_or_else(|| Error::new(ERR_SESSION_CLOSED, "session closed")));
        }
        if let Some(seen) = g.up_fin_final {
            // A retransmitted FIN must name the same offset.
            if seen != final_offset {
                return Err(Error::new(
                    ERR_FRAME_CONFLICT,
                    format!("FIN replayed with {final_offset}, first seen {seen}"),
                )
                .closed(true));
            }
            return Ok(false);
        }
        if g.up_pending.iter().any(|(queued_offset, (payload, _, _))| {
            queued_offset
                .checked_add(payload.len() as u64)
                .is_none_or(|queued_end| queued_end > final_offset)
        }) {
            return Err(Error::new(
                ERR_FRAME_CONFLICT,
                format!("queued upstream frame extends past FIN at {final_offset}"),
            ));
        }
        if final_offset < g.up_flushed {
            return Err(Error::new(
                wire::ERR_BAD_FRAME,
                format!(
                    "FIN at {final_offset} is below applied offset {}",
                    g.up_flushed
                ),
            ));
        }
        let window_edge = g.up_flushed.saturating_add(self.limits.up_window_bytes);
        if final_offset > window_edge {
            return Err(Error::new(
                wire::ERR_WINDOW_EXCEEDED,
                format!(
                    "FIN at {final_offset} is beyond the receive window from {}",
                    g.up_flushed
                ),
            ));
        }
        g.up_fin_final = Some(final_offset);
        g.last_control = Instant::now();
        let apply_now = final_offset == g.up_flushed;
        let fin_applied_now = apply_now && !g.up_fin;
        if fin_applied_now {
            g.up_fin = true;
        }
        drop(g);
        self.notify_change();
        if apply_now {
            if fin_applied_now {
                self.metrics.upstream_fin_applied();
            }
            let _ = self.backend.shutdown(std::net::Shutdown::Write);
            return Ok(true);
        }
        Ok(false)
    }
}

pub struct UpPermit<'a> {
    session: &'a Session,
}

fn bounded_utf8_prefix(value: &str, max_bytes: usize) -> String {
    let end = value
        .char_indices()
        .take_while(|(index, ch)| index + ch.len_utf8() <= max_bytes)
        .last()
        .map(|(index, ch)| index + ch.len_utf8())
        .unwrap_or(0);
    value[..end].to_string()
}

impl Drop for UpPermit<'_> {
    fn drop(&mut self) {
        self.session.up_inflight.fetch_sub(1, Ordering::AcqRel);
    }
}
