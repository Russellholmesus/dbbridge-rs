//! The downstream half of a session: how far the peer has delivered, how
//! much room is left, and the control messages that report both.

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::resource::budget::{Budget, BudgetLease};
use crate::stream::byte_window::ByteWindowError;
use crate::wire::{self, Control, ControlKind};

use super::{Inner, Session, State};

pub(super) fn prune_down_ack_locked(g: &mut Inner, offset: u64) {
    g.down_ack = g.down_ack.max(offset);
    g.down_window.acknowledge(g.down_ack);
    let acknowledged: Vec<u64> = g.down_boundaries.range(..=g.down_ack).copied().collect();
    for boundary in acknowledged {
        g.down_boundaries.remove(&boundary);
    }
}

pub(super) struct DownReservation {
    pub(super) bytes: usize,
    pub(super) payload_lease: Option<BudgetLease>,
}

impl Session {
    pub(crate) fn set_global_payload_budget(
        &self,
        budget: Arc<Budget>,
        backpressure_timeout: Duration,
    ) -> std::result::Result<(), ByteWindowError> {
        let g = self.inner.lock().unwrap();
        g.down_window.set_backpressure_timeout(backpressure_timeout);
        g.down_window.set_payload_budget(budget)
    }

    /// Returns the byte-based upstream receive edge granted after `ack`.
    pub fn up_receive_limit(&self, ack: u64) -> u64 {
        ack.saturating_add(self.limits.up_window_bytes)
    }

    /// Records what the ingress has delivered downstream and wakes the pump.
    pub fn apply_down_ack(&self, offset: u64, fin_applied: bool) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        // Old ACKs are harmless duplicates; a new offset must be both within
        // the produced range and exactly at a frame boundary.
        if offset < g.down_ack || (offset == g.down_ack && !fin_applied) {
            g.last_control = Instant::now();
            drop(g);
            self.notify_change();
            return Ok(());
        }
        if offset > g.down_produced
            || (offset != g.down_ack && !g.down_boundaries.contains(&offset))
        {
            return Err(Error::new(
                wire::ERR_BAD_ACK,
                format!(
                    "down ack {offset} is not an emitted frame boundary (produced {})",
                    g.down_produced
                ),
            ));
        }
        if offset > g.down_ack {
            prune_down_ack_locked(&mut g, offset);
            self.sync_retained_payload_bytes(&g);
        }
        let fin_acked_now = fin_applied && !g.down_fin_acked;
        if fin_applied {
            g.down_fin_acked = true;
        }
        g.last_control = Instant::now();
        drop(g);
        if fin_acked_now {
            self.metrics.downstream_fin_acked();
        }
        self.notify_change();
        Ok(())
    }

    /// Confirms retained upstream frames and advances the receipt floor. A
    /// confirmation is valid only at a retained frame end (or at the current
    /// floor), and never beyond the flushed backend offset.
    pub fn apply_up_confirmation(&self, offset: u64) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        if offset > g.up_flushed {
            return Err(Error::new(
                wire::ERR_BAD_ACK,
                format!(
                    "up confirmation {offset} exceeds flushed offset {}",
                    g.up_flushed
                ),
            ));
        }
        if offset <= g.receipt_floor {
            g.last_control = Instant::now();
            drop(g);
            self.notify_change();
            return Ok(());
        }
        if !g.receipts.iter().any(|(_, end, _)| *end == offset) {
            return Err(Error::new(
                wire::ERR_BAD_ACK,
                format!("up confirmation {offset} is not a retained frame boundary"),
            ));
        }
        g.receipt_floor = offset;
        while g
            .receipts
            .front()
            .is_some_and(|(_, end, _)| *end <= g.receipt_floor)
        {
            g.receipts.pop_front();
        }
        g.last_control = Instant::now();
        drop(g);
        self.notify_change();
        Ok(())
    }

    pub fn note_control(&self, _nonce: &str) {
        let mut g = self.inner.lock().unwrap();
        g.last_control = Instant::now();
        drop(g);
        self.notify_change();
    }

    /// Records an ingress ACK and retires recovery grace only after the ready
    /// data plane has answered the current carrier's ping with a probe ID.
    pub fn note_ack_control(&self, nonce: &str, probe_id: &str, ready_received: bool) {
        self.expire_recovery();
        let mut g = self.inner.lock().unwrap();
        g.last_control = Instant::now();
        if ready_received {
            g.data_plane_active = true;
        }
        let recovered = g.state != State::Closed
            && g.recovery_deadline.is_some()
            && g.data_plane_active
            && !g.heartbeat_nonce.is_empty()
            && g.heartbeat_epoch == self.epoch()
            && g.heartbeat_stream == g.stream_id
            && !nonce.is_empty()
            && nonce == g.heartbeat_nonce
            && !probe_id.is_empty();
        let ended_lease = if recovered {
            g.recovery_lease.take()
        } else {
            None
        };
        if recovered {
            g.recovery_deadline = None;
            g.recovery_state_suspended = false;
            g.heartbeat_nonce.clear();
            g.heartbeat_epoch = 0;
            g.heartbeat_stream.clear();
        }
        drop(g);
        if let Some(lease) = ended_lease {
            self.retire_retention_lease(&lease);
        }
        self.notify_change();
    }

    /// Marks an in-progress write to the data carrier for ACK diagnostics.
    pub fn set_transport_writing(&self, writing: bool) {
        self.inner.lock().unwrap().transport_writing = writing;
    }

    pub fn set_transport_rx_blocked(&self, epoch: u64, blocked: bool) {
        let mut g = self.inner.lock().unwrap();
        if epoch == self.epoch() && g.state != State::Closed {
            g.transport_rx_blocked = blocked;
        }
    }

    /// Returns the egress-side pressure state used in ACK responses.
    pub fn flow_control_state(&self) -> (bool, String, bool) {
        let g = self.inner.lock().unwrap();
        let tx_blocked = g.transport_writing;
        let inflight = self.up_inflight.load(Ordering::Acquire);
        let rx_blocked = g.transport_rx_blocked
            || g.up_write_active && inflight >= self.limits.up_max_inflight_frames.max(1) as usize;
        let reason = if g.transport_rx_blocked {
            "global_buffer"
        } else if rx_blocked {
            "local_socket_write"
        } else if tx_blocked {
            "data_channel_write"
        } else {
            "none"
        };
        (tx_blocked, reason.to_string(), rx_blocked)
    }

    pub fn ack_requested(&self) -> bool {
        let g = self.inner.lock().unwrap();
        let down_bytes = g.down_produced.saturating_sub(g.down_ack);
        down_bytes.saturating_mul(2) >= self.limits.down_buffer_bytes.max(1)
            || g.down_boundaries.len().saturating_mul(2)
                >= self.limits.down_max_frames.max(1) as usize
            || g.receipts.len().saturating_mul(2) >= self.limits.up_receipt_limit.max(1) as usize
    }

    pub fn control_expired(&self, detect: Duration) -> bool {
        let g = self.inner.lock().unwrap();
        g.state != State::Closed && g.last_control.elapsed() > detect
    }

    pub fn control_wait_remaining(&self, detect: Duration) -> Duration {
        let g = self.inner.lock().unwrap();
        if g.state == State::Closed {
            Duration::ZERO
        } else {
            detect.saturating_sub(g.last_control.elapsed())
        }
    }

    pub fn change_generation(&self) -> u64 {
        self.inner.lock().unwrap().change_generation
    }

    pub fn wait_for_change_since(&self, generation: u64, timeout: Duration) {
        let guard = self.inner.lock().unwrap();
        let _ = self
            .cv
            .wait_timeout_while(guard, timeout, |inner| {
                inner.change_generation == generation
            })
            .unwrap();
    }

    pub fn notify_change(&self) {
        let mut g = self.inner.lock().unwrap();
        g.change_generation = g.change_generation.wrapping_add(1);
        drop(g);
        self.cv.notify_all();
    }

    /// Waits until a carrier attaches or the session closes, or the deadline
    /// expires. The state predicate is checked under the same lock as the
    /// Condvar wait, so attach/close notifications cannot be lost.
    pub fn wait_while_attaching(&self, timeout: Duration) -> State {
        let guard = self.inner.lock().unwrap();
        let (guard, _) = self
            .cv
            .wait_timeout_while(guard, timeout, |inner| inner.state == State::Attaching)
            .unwrap();
        guard.state
    }

    /// Waits for terminal closure, returning false when the timeout expires.
    pub fn wait_until_closed(&self, timeout: Duration) -> bool {
        let guard = self.inner.lock().unwrap();
        let (guard, _) = self
            .cv
            .wait_timeout_while(guard, timeout, |inner| inner.state != State::Closed)
            .unwrap();
        guard.state == State::Closed
    }

    /// Waits until the downstream window has room and returns how many bytes
    /// may be produced. Returns `None` once a recovery-enabled carrier detaches
    /// or the session closes, so an old epoch pump can leave its window wait.
    #[cfg(test)]
    pub fn reserve_down(&self, max: usize) -> Option<usize> {
        self.reserve_down_for_read(self.epoch(), max)
            .map(|reservation| reservation.bytes)
    }

    pub(super) fn reserve_down_for_read(&self, epoch: u64, max: usize) -> Option<DownReservation> {
        const SAFETY_POLL: Duration = Duration::from_millis(250);
        if max == 0 {
            return Some(DownReservation {
                bytes: 0,
                payload_lease: None,
            });
        }
        let timeout = self
            .inner
            .lock()
            .unwrap()
            .down_window
            .backpressure_timeout();
        let mut deadline = Instant::now().checked_add(timeout);
        let mut counted_wait = false;
        loop {
            let g = self.inner.lock().unwrap();
            if self.epoch() != epoch
                || g.state == State::Closed
                || g.recovery_state_suspended
                || g.resume_busy
                || (g.recovery_enabled && !g.attached)
            {
                return None;
            }
            let outstanding = g.down_produced - g.down_ack;
            let room = self.limits.down_buffer_bytes.saturating_sub(outstanding);
            let allocation_capacity =
                usize::try_from(g.down_window.available_allocation_capacity().max(0))
                    .unwrap_or(usize::MAX);
            let payload_capacity =
                usize::try_from(g.down_window.available_payload_capacity().max(0))
                    .unwrap_or(usize::MAX);
            let allowed = max
                .min(usize::try_from(room).unwrap_or(usize::MAX))
                .min(allocation_capacity)
                .min(payload_capacity);
            if allowed > 0 {
                match g.down_window.reserve_payload(allowed) {
                    Ok(payload_lease) => {
                        return Some(DownReservation {
                            bytes: allowed,
                            payload_lease,
                        });
                    }
                    Err(ByteWindowError::BudgetExhausted) => {
                        if !counted_wait {
                            self.metrics.backpressure_waited();
                            counted_wait = true;
                        }
                        let budget = g.down_window.payload_budget_handle();
                        let remaining = deadline
                            .map(|deadline| deadline.saturating_duration_since(Instant::now()));
                        drop(g);
                        if let Some(budget) = budget {
                            let wait = remaining.unwrap_or(SAFETY_POLL).min(SAFETY_POLL);
                            let _ = budget.wait_for_available(1, Some(wait));
                        }
                        continue;
                    }
                    Err(_) => return None,
                }
            }
            let remaining =
                deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));
            if remaining.is_some_and(|remaining| remaining.is_zero()) {
                drop(g);
                if self.close_backpressure_timeout() {
                    return None;
                }
                deadline = Instant::now().checked_add(timeout);
                continue;
            }
            if g.down_window.has_payload_budget() && payload_capacity == 0 {
                if !counted_wait {
                    self.metrics.backpressure_waited();
                    counted_wait = true;
                }
                let budget = g.down_window.payload_budget_handle();
                drop(g);
                if let Some(budget) = budget {
                    let wait = remaining.unwrap_or(SAFETY_POLL).min(SAFETY_POLL);
                    let _ = budget.wait_for_available(1, Some(wait));
                }
                continue;
            }
            if !counted_wait {
                self.metrics.backpressure_waited();
                counted_wait = true;
            }
            match remaining {
                Some(remaining) => {
                    let (guard, _) = self.cv.wait_timeout(g, remaining).unwrap();
                    drop(guard);
                }
                None => {
                    let guard = self.cv.wait(g).unwrap();
                    drop(guard);
                }
            }
        }
    }

    /// Reserves the offset range before handing the frame to the carrier.
    /// Returning its starting offset makes the accounting and emission order
    /// explicit, so a sufficiently fast peer may acknowledge it immediately.
    #[cfg(test)]
    pub fn mark_down_produced(&self, payload: &[u8]) -> Result<u64> {
        self.mark_down_produced_inner(payload, None, None)
    }

    pub(super) fn mark_down_produced_reserved(
        &self,
        payload: &[u8],
        reservation: DownReservation,
    ) -> Result<u64> {
        let DownReservation {
            bytes,
            payload_lease,
        } = reservation;
        if payload.len() > bytes {
            return Err(Error::new(
                wire::ERR_WINDOW_EXCEEDED,
                "downstream read exceeded its reserved capacity",
            ));
        }
        self.mark_down_produced_inner(payload, payload_lease, Some(bytes))
    }

    fn mark_down_produced_inner(
        &self,
        payload: &[u8],
        payload_lease: Option<BudgetLease>,
        reserved_bytes: Option<usize>,
    ) -> Result<u64> {
        let mut g = self.inner.lock().unwrap();
        if g.state == State::Closed {
            return Err(g
                .terminal
                .clone()
                .unwrap_or_else(|| Error::new(wire::ERR_SESSION_CLOSED, "session closed")));
        }
        if reserved_bytes.is_some_and(|reserved| payload.len() > reserved) {
            return Err(Error::new(
                wire::ERR_WINDOW_EXCEEDED,
                "downstream read exceeded its reserved capacity",
            ));
        }
        let start = g.down_produced;
        let length = u64::try_from(payload.len()).map_err(|_| {
            Error::new(wire::ERR_FRAME_CONFLICT, "downstream frame length overflow")
        })?;
        let end = start
            .checked_add(length)
            .ok_or_else(|| Error::new(wire::ERR_FRAME_CONFLICT, "downstream offset overflow"))?;
        if end.saturating_sub(g.down_ack) > self.limits.down_buffer_bytes {
            return Err(Error::new(
                wire::ERR_WINDOW_EXCEEDED,
                "downstream frame exceeds the retained window",
            ));
        }
        g.down_window
            .append_reserved(start, payload, payload_lease)
            .map_err(|error| match error {
                ByteWindowError::BudgetExhausted => Error::new(
                    wire::ERR_BUFFER_EXHAUSTED,
                    "global payload budget exhausted",
                ),
                _ => Error::new(
                    wire::ERR_WINDOW_EXCEEDED,
                    "downstream frame exceeds the retained allocation window",
                ),
            })?;
        g.down_produced = end;
        g.down_boundaries.insert(end);
        let enforce_retention = g
            .recovery_lease
            .as_ref()
            .is_some_and(|lease| lease.active());
        self.sync_retained_payload_bytes(&g);
        drop(g);
        if enforce_retention {
            self.enforce_suspended_retention();
        }
        self.notify_change();
        Ok(start)
    }

    pub fn replay_down_frames(&self) -> Vec<(u64, Vec<u8>)> {
        let g = self.inner.lock().unwrap();
        let mut start = g.down_window.start_offset();
        let mut frames = Vec::with_capacity(g.down_boundaries.len());
        for end in g.down_boundaries.range(start..).copied() {
            let length = match usize::try_from(end.saturating_sub(start)) {
                Ok(length) => length,
                Err(_) => break,
            };
            let Some((payload, next, _)) = g.down_window.read_range(start, length) else {
                break;
            };
            if next != end {
                break;
            }
            frames.push((start, payload));
            start = end;
        }
        frames
    }

    pub fn mark_down_fin(&self) {
        let mut g = self.inner.lock().unwrap();
        g.down_fin = true;
        drop(g);
        self.notify_change();
    }

    pub fn down_fin(&self) -> bool {
        self.inner.lock().unwrap().down_fin
    }

    pub fn close(&self, reason: Error) {
        let mut g = self.inner.lock().unwrap();
        if g.state == State::Closed {
            return;
        }
        let normal = g.up_fin && g.down_fin && g.down_fin_acked;
        let mode = g.active_mode;
        let event_reason = terminal_event_reason(&reason, normal);
        g.state = State::Closed;
        g.terminal = Some(reason);
        g.down_window.reset();
        g.down_boundaries.clear();
        g.up_pending.clear();
        g.up_pending_bytes = 0;
        self.sync_retained_payload_bytes(&g);
        let lease = g.recovery_lease.take();
        self.closed.store(true, Ordering::Release);
        drop(g);
        self.release_resource_leases();
        self.metrics.record_session_event(
            "egress",
            "terminate",
            event_reason,
            mode.as_str(),
            "none",
        );
        if let Some(lease) = lease {
            self.retire_retention_lease(&lease);
        }
        let _ = self.backend.shutdown(std::net::Shutdown::Both);
        self.notify_change();
    }

    fn close_backpressure_timeout(&self) -> bool {
        let mut g = self.inner.lock().unwrap();
        if g.state == State::Closed {
            return true;
        }
        if g.recovery_state_suspended
            || g.resume_busy
            || g.recovery_deadline.is_some()
            || (g.recovery_enabled && (!g.attached || !g.data_plane_active))
        {
            return false;
        }
        let mode = g.active_mode;
        let terminal = Error::new(wire::ERR_BUFFER_EXHAUSTED, "backpressure timeout").closed(true);
        let event_reason = terminal_event_reason(&terminal, false);
        g.state = State::Closed;
        g.terminal = Some(terminal);
        g.down_window.reset();
        g.down_boundaries.clear();
        g.up_pending.clear();
        g.up_pending_bytes = 0;
        self.sync_retained_payload_bytes(&g);
        let lease = g.recovery_lease.take();
        self.closed.store(true, Ordering::Release);
        drop(g);
        self.release_resource_leases();
        self.metrics.record_session_event(
            "egress",
            "terminate",
            event_reason,
            mode.as_str(),
            "none",
        );
        if let Some(lease) = lease {
            self.retire_retention_lease(&lease);
        }
        let _ = self.backend.shutdown(std::net::Shutdown::Both);
        self.notify_change();
        true
    }

    /// Builds the `ack_up` control message for this session.
    pub fn ack_up_control(&self) -> Control {
        let s = self.snapshot();
        let mut c = Control::base(
            ControlKind::AckUp,
            &self.id,
            &self.instance_id,
            self.epoch(),
            &s.stream_id,
        );
        c.ack_up_offset = Some(s.ack_up_offset);
        c.up_fin_applied = s.up_fin_applied;
        c.ack_requested = self.ack_requested();
        c
    }

    pub fn fin_control(&self, offset: u64) -> Control {
        let s = self.snapshot();
        let mut c = Control::base(
            ControlKind::Fin,
            &self.id,
            &self.instance_id,
            self.epoch(),
            &s.stream_id,
        );
        c.final_offset = Some(offset);
        c
    }

    pub fn ping_control(&self) -> crate::error::Result<Control> {
        let epoch = self.epoch();
        let s = self.snapshot();
        let nonce = crate::util::random_hex(8).map_err(crate::util::random_error)?;
        let mut g = self.inner.lock().unwrap();
        if g.state == State::Closed {
            return Err(g
                .terminal
                .clone()
                .unwrap_or_else(|| Error::new(wire::ERR_SESSION_CLOSED, "session closed")));
        }
        if self.epoch() != epoch || !g.attached || g.stream_id != s.stream_id {
            return Err(Error::new(wire::ERR_STALE_EPOCH, "carrier epoch replaced"));
        }
        g.heartbeat_nonce = nonce.clone();
        g.heartbeat_epoch = epoch;
        g.heartbeat_stream = s.stream_id.clone();
        drop(g);
        let mut c = Control::base(
            ControlKind::Ping,
            &self.id,
            &self.instance_id,
            epoch,
            &s.stream_id,
        );
        c.nonce = Some(nonce);
        Ok(c)
    }

    /// The bound terminal `error` message announcing why this node ended the
    /// session, or `None` for a normal close.
    pub fn terminal_control(&self) -> Option<Control> {
        let g = self.inner.lock().unwrap();
        if g.state != State::Closed || (g.up_fin && g.down_fin && g.down_fin_acked) {
            return None;
        }
        let reason = g.terminal.clone()?;
        if reason.code.is_empty() {
            return None;
        }
        let mut c = Control::base(
            ControlKind::Error,
            &self.id,
            &self.instance_id,
            self.epoch(),
            &g.stream_id,
        );
        c.code = Some(reason.code.clone());
        c.retryable = false;
        c.session_closed = true;
        Some(c)
    }

    pub fn closed_normally_for(&self, epoch: u64, stream: &str) -> bool {
        let g = self.inner.lock().unwrap();
        g.state == State::Closed
            && g.up_fin
            && g.down_fin
            && g.down_fin_acked
            && !stream.is_empty()
            && g.stream_id == stream
            && epoch == self.epoch()
    }

    /// True when both directions finished normally.
    pub fn finished(&self) -> bool {
        let g = self.inner.lock().unwrap();
        g.up_fin && g.down_fin && g.down_fin_acked
    }
}

fn terminal_event_reason(error: &Error, normal: bool) -> &'static str {
    if normal {
        return "normal";
    }
    if error.message.contains("shutdown") {
        return "shutdown";
    }
    match error.code.as_str() {
        wire::ERR_BACKEND_LOST => "backend_lost",
        wire::ERR_RESUME_EXPIRED => "timeout",
        wire::ERR_TARGET_FORBIDDEN => "forbidden",
        wire::ERR_BUFFER_EXHAUSTED => "buffer",
        wire::ERR_QUOTA_EXCEEDED => "quota",
        wire::ERR_DIAL_FAILED => "dial_failed",
        wire::ERR_DRAINING => "draining",
        wire::ERR_BAD_ACK
        | wire::ERR_FRAME_CONFLICT
        | wire::ERR_BAD_FRAME
        | wire::ERR_PROTOCOL_MISMATCH
        | wire::ERR_FRAME_TOO_LARGE => "protocol",
        _ if error.message.contains("timeout") || error.message.contains("deadline") => "timeout",
        _ if error.is_local() && error.message.contains("socket") => "local_socket",
        _ => "failed",
    }
}
