//! Session-level recovery state machine.
#![allow(dead_code)]
//!
//! This module intentionally stops at the session boundary.  HTTP/WS/SSE
//! parsing and carrier ownership remain transport responsibilities, while
//! this API makes the state transition and all offset/FIN checks atomic.
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::wire::{self, Mode};

use super::{Session, State};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryState {
    Disabled,
    Attached,
    Suspended,
    Resuming,
    Closed,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResumeFin {
    pub seen: bool,
    pub final_offset: Option<u64>,
    pub applied: bool,
    pub acked: bool,
}

#[derive(Debug, Clone)]
pub struct ResumeRequest {
    pub resume_request_id: String,
    pub expected_epoch: u64,
    pub ingress_instance_id: String,
    pub transport: Mode,
    pub known_up_ack_offset: u64,
    pub up_next_offset: u64,
    pub down_delivered_offset: u64,
    pub up_fin: ResumeFin,
    pub down_fin: ResumeFin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeResponse {
    pub session_id: String,
    pub instance_id: String,
    pub resume_request_id: String,
    pub epoch: u64,
    pub transport: Mode,
    pub up_written_offset: u64,
    pub ack_up_offset: u64,
    pub down_replay_from: u64,
    pub down_produced_offset: u64,
    pub down_retained_from: u64,
    pub up_fin: ResumeFin,
    pub down_fin: ResumeFin,
    pub resume_remaining: Duration,
}

impl ResumeRequest {
    /// Stable request fingerprint without retaining a copy of the request or
    /// requiring a serialization dependency.  All fields which affect the
    /// transition are included and encoded unambiguously.
    pub fn fingerprint(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}:{:?}:{}:{}|{}:{:?}:{}:{}",
            self.resume_request_id,
            self.expected_epoch,
            self.ingress_instance_id,
            self.transport.as_str(),
            self.known_up_ack_offset,
            self.up_next_offset,
            self.down_delivered_offset,
            self.up_fin.seen,
            self.up_fin.final_offset,
            self.up_fin.applied,
            self.up_fin.acked,
            self.down_fin.seen,
            self.down_fin.final_offset,
            self.down_fin.applied,
            self.down_fin.acked
        )
    }
}

impl Session {
    fn recovery_lock(&self) -> std::sync::MutexGuard<'_, super::Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Enable recovery for a newly created session.  A non-positive grace
    /// keeps recovery disabled, preserving the pre-recovery behaviour.
    pub fn enable_recovery(&self, grace: Duration) {
        let mut g = self.recovery_lock();
        g.recovery_enabled = grace > Duration::ZERO;
        g.recovery_grace = grace;
    }

    pub fn recovery_state(&self) -> RecoveryState {
        let mut g = self.recovery_lock();
        self.expire_recovery_locked(&mut g);
        if g.state == State::Closed {
            RecoveryState::Closed
        } else if !g.recovery_enabled {
            RecoveryState::Disabled
        } else if g.recovery_state_suspended {
            RecoveryState::Suspended
        } else if g.resume_busy {
            RecoveryState::Resuming
        } else {
            RecoveryState::Attached
        }
    }

    pub fn recovery_deadline(&self) -> Option<Instant> {
        self.recovery_lock().recovery_deadline
    }

    pub fn last_resume_request_id(&self) -> Option<String> {
        let id = self.recovery_lock().last_resume_request_id.clone();
        (!id.is_empty()).then_some(id)
    }

    pub fn expire_recovery(&self) -> bool {
        let mut g = self.recovery_lock();
        let was_closed = g.state == State::Closed;
        self.expire_recovery_locked(&mut g);
        !was_closed && g.state == State::Closed
    }

    pub fn suspend(&self, expected_epoch: u64) -> bool {
        let retention = self
            .suspended_retention
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let mut register_lease = None;
        let mut g = self.recovery_lock();
        self.expire_recovery_locked(&mut g);
        if g.state == State::Closed || expected_epoch != self.epoch() || !g.recovery_enabled {
            return false;
        }
        // Both FINs exchanged and confirmed: the carrier ending now is the
        // normal end of the session, not a loss to recover from. The caller
        // closes it (as a normal close) instead of parking it for the grace.
        if g.up_fin && g.down_fin && g.down_fin_acked {
            return false;
        }
        if g.recovery_state_suspended || g.resume_busy {
            return true;
        }
        if g.recovery_deadline.is_none() {
            let started = Instant::now();
            g.recovery_deadline = Some(started + g.recovery_grace);
            if let Some(retention) = retention {
                let lease = self.new_recovery_lease(started);
                g.recovery_lease = Some(lease.clone());
                register_lease = Some((retention, lease));
            }
        }
        g.recovery_state_suspended = true;
        if !g.stream_id.is_empty() {
            g.retired_stream_id = Some(g.stream_id.clone());
        }
        g.attached = false;
        g.stream_id.clear();
        g.transport_writing = false;
        g.change_generation = g.change_generation.wrapping_add(1);
        self.cv.notify_all();
        drop(g);
        if let Some((retention, lease)) = register_lease {
            retention.register(Some(lease));
        }
        true
    }

    fn new_recovery_lease(&self, started: Instant) -> std::sync::Arc<super::RetentionLease> {
        let retained_bytes = self.retained_payload_bytes.clone();
        let session = self.self_weak.clone();
        super::RetentionLease::new_validated(
            started,
            move || {
                i64::try_from(retained_bytes.load(std::sync::atomic::Ordering::Acquire))
                    .unwrap_or(i64::MAX)
            },
            move |lease| {
                if let Some(session) = session.upgrade() {
                    session.close_for_retention(lease);
                }
            },
        )
    }

    fn close_for_retention(&self, lease: &super::RetentionLease) {
        let mut g = self.recovery_lock();
        let current = g
            .recovery_lease
            .as_ref()
            .is_some_and(|registered| std::ptr::eq(registered.as_ref(), lease));
        if !current || !lease.active() || g.state == State::Closed {
            return;
        }
        g.terminal = Some(
            Error::new(
                wire::ERR_BUFFER_EXHAUSTED,
                "suspended recovery buffer quota exceeded",
            )
            .closed(true),
        );
        g.state = State::Closed;
        g.recovery_state_suspended = false;
        g.resume_busy = false;
        g.down_window.reset();
        g.down_boundaries.clear();
        g.up_pending.clear();
        g.up_pending_bytes = 0;
        self.sync_retained_payload_bytes(&g);
        g.change_generation = g.change_generation.wrapping_add(1);
        self.closed
            .store(true, std::sync::atomic::Ordering::Release);
        if let Some(lease) = g.recovery_lease.take() {
            lease.end();
        }
        drop(g);
        let _ = self.backend.shutdown(std::net::Shutdown::Both);
        self.cv.notify_all();
    }

    pub(super) fn retire_retention_lease(&self, lease: &std::sync::Arc<super::RetentionLease>) {
        let retention = self
            .suspended_retention
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(retention) = retention {
            retention.remove_lease(lease);
        } else {
            lease.end();
        }
    }

    pub fn suspend_current(&self) -> bool {
        self.suspend(self.epoch())
    }

    /// Atomically validates and starts a resume.  The barrier is bounded by
    /// the original grace deadline and waits on the existing condition
    /// variable; there is no polling loop or duplicated session buffer.
    pub fn resume(&self, req: &ResumeRequest, barrier: Duration) -> Result<ResumeResponse> {
        if req.resume_request_id.is_empty() || req.resume_request_id.len() > 128 {
            return Err(Error::new(wire::ERR_BAD_FRAME, "resume request id"));
        }
        let fingerprint = req.fingerprint();
        let retention = self
            .suspended_retention
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let mut g = self.recovery_lock();
        self.expire_recovery_locked(&mut g);
        if g.state == State::Closed {
            return Err(g
                .terminal
                .clone()
                .unwrap_or_else(|| Error::new(wire::ERR_SESSION_CLOSED, "session closed")));
        }
        if !g.recovery_enabled {
            return Err(Error::new(
                wire::ERR_RECOVERY_DISABLED,
                "session recovery is disabled",
            ));
        }
        if let Some(deadline) = g.recovery_deadline {
            if Instant::now() >= deadline {
                return Err(
                    Error::new(wire::ERR_RESUME_EXPIRED, "resume grace expired").closed(true)
                );
            }
        }
        if g.last_resume_id.as_deref() == Some(req.resume_request_id.as_str()) {
            if g.last_resume_fingerprint.as_deref() != Some(fingerprint.as_str()) {
                return Err(Error::new(
                    wire::ERR_IDEMPOTENCY_CONFLICT,
                    "resume request differs",
                ));
            }
            if g.resume_busy {
                return Err(
                    Error::new(wire::ERR_RESUME_IN_PROGRESS, "resume in progress").retryable(true),
                );
            }
            return g.last_resume_response.clone().ok_or_else(|| {
                Error::new(wire::ERR_RESUME_PENDING, "resume response pending").retryable(true)
            });
        }
        if g.resume_busy {
            if g.resume_pending_id.as_deref() == Some(req.resume_request_id.as_str()) {
                if g.resume_pending_fingerprint.as_deref() != Some(fingerprint.as_str()) {
                    return Err(Error::new(
                        wire::ERR_IDEMPOTENCY_CONFLICT,
                        "resume request differs",
                    ));
                }
                return Err(
                    Error::new(wire::ERR_RESUME_PENDING, "resume barrier pending").retryable(true),
                );
            }
            return Err(
                Error::new(wire::ERR_RESUME_IN_PROGRESS, "resume in progress").retryable(true),
            );
        }
        if req.expected_epoch != self.epoch() {
            return Err(Error::new(wire::ERR_STALE_EPOCH, "epoch"));
        }
        if req.ingress_instance_id != self.ingress_instance_id {
            return Err(Error::new(wire::ERR_BAD_FRAME, "ingress instance"));
        }
        let mut register_lease = None;
        let deadline = match g.recovery_deadline {
            Some(deadline) => deadline,
            None => {
                let started = Instant::now();
                if let Some(retention) = retention {
                    let lease = self.new_recovery_lease(started);
                    g.recovery_lease = Some(lease.clone());
                    register_lease = Some((retention, lease));
                }
                started + g.recovery_grace
            }
        };
        g.recovery_deadline = Some(deadline);
        g.resume_busy = true;
        g.resume_pending_id = Some(req.resume_request_id.clone());
        g.resume_pending_fingerprint = Some(fingerprint.clone());
        g.recovery_state_suspended = true;
        if !g.stream_id.is_empty() {
            g.retired_stream_id = Some(g.stream_id.clone());
        }
        g.attached = false;
        g.stream_id.clear();
        g.change_generation = g.change_generation.wrapping_add(1);
        self.cv.notify_all();
        if let Some((retention, lease)) = register_lease {
            drop(g);
            retention.register(Some(lease));
            g = self.recovery_lock();
            if g.state == State::Closed {
                return Err(Error::new(wire::ERR_SESSION_CLOSED, "session closed").closed(true));
            }
        }
        let until = deadline
            .saturating_duration_since(Instant::now())
            .min(barrier);
        let barrier_timer = self.metrics.operation_timer("egress", "barrier");
        while g.up_write_active {
            let (next, timed) = self
                .cv
                .wait_timeout(g, until)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            g = next;
            if timed.timed_out() {
                break;
            }
        }
        drop(barrier_timer);
        if g.up_write_active {
            let code = if Instant::now() >= deadline {
                wire::ERR_RESUME_EXPIRED
            } else {
                wire::ERR_SESSION_CLOSED
            };
            let err = Error::new(code, "resume write barrier timed out").closed(true);
            return self.resume_close_locked(&mut g, err);
        }
        if Instant::now() >= deadline {
            let err = Error::new(wire::ERR_RESUME_EXPIRED, "resume grace expired").closed(true);
            return self.resume_close_locked(&mut g, err);
        }
        if req.known_up_ack_offset > g.up_flushed
            || req.up_next_offset < g.up_flushed
            || req.known_up_ack_offset > req.up_next_offset
            || req.down_delivered_offset < g.down_ack
            || req.down_delivered_offset > g.down_produced
            || !g.down_boundaries.contains(&req.down_delivered_offset)
                && req.down_delivered_offset != g.down_ack
        {
            if std::env::var_os("DBBRIDGE_TRACE").is_some() {
                eprintln!(
                    "egress resume offsets rejected session={} expected_epoch={} session_epoch={} known_up_ack={} request_up_next={} up_flushed={} up_written={} down_delivered={} down_ack={} down_produced={}",
                    self.id,
                    req.expected_epoch,
                    self.epoch(),
                    req.known_up_ack_offset,
                    req.up_next_offset,
                    g.up_flushed,
                    g.up_written,
                    req.down_delivered_offset,
                    g.down_ack,
                    g.down_produced
                );
            }
            return self.resume_fail_locked(&mut g, wire::ERR_BAD_ACK, "resume offsets");
        }
        if let Err(e) = validate_fin(req, &g) {
            return self.resume_fail_locked(&mut g, e.code.as_str(), &e.message);
        }
        // The API layer has already enforced the configured transport
        // capability. Once all resume checks pass, atomically make the
        // requested carrier the active mode for this session.
        g.active_mode = req.transport;
        super::down::prune_down_ack_locked(&mut g, req.down_delivered_offset);
        let mut fin_acked_now = false;
        if req.down_fin.applied && g.down_fin && !g.down_fin_acked {
            g.down_fin_acked = true;
            fin_acked_now = true;
        }
        if g.up_fin && g.down_fin && g.down_fin_acked && g.down_ack == g.down_produced {
            g.resume_busy = false;
            g.resume_pending_id = None;
            g.resume_pending_fingerprint = None;
            drop(g);
            if fin_acked_now {
                self.metrics.downstream_fin_acked();
            }
            self.close(Error::local("session finished"));
            return Err(Error::new(wire::ERR_SESSION_CLOSED, "session closed").closed(true));
        }
        if self.epoch() == u64::MAX {
            return self.resume_fail_locked(&mut g, wire::ERR_STALE_EPOCH, "epoch exhausted");
        }
        g.up_pending.clear();
        g.up_pending_bytes = 0;
        self.sync_retained_payload_bytes(&g);
        self.epoch.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        g.state = State::Attaching;
        g.recovery_state_suspended = false;
        g.resume_busy = false;
        // Commit the new generation with no carrier attached. The old stream
        // remains fenced by retired_stream_id, so a racing old carrier cannot
        // recreate DBB_STREAM_EXISTS for the new one.
        g.attached = false;
        g.stream_id.clear();
        g.data_plane_active = false;
        g.heartbeat_nonce.clear();
        g.heartbeat_epoch = 0;
        g.heartbeat_stream.clear();
        g.resume_pending_id = None;
        g.resume_pending_fingerprint = None;
        g.last_resume_request_id = req.resume_request_id.clone();
        g.last_resume_id = Some(req.resume_request_id.clone());
        g.last_resume_fingerprint = Some(fingerprint);
        let response = ResumeResponse {
            session_id: self.id.clone(),
            instance_id: self.instance_id.clone(),
            resume_request_id: req.resume_request_id.clone(),
            epoch: self.epoch(),
            transport: req.transport,
            up_written_offset: g.up_written,
            ack_up_offset: super::ack_up_boundary(&g),
            down_replay_from: req.down_delivered_offset,
            down_produced_offset: g.down_produced,
            down_retained_from: if g.down_window.buffered_bytes() == 0 {
                g.down_produced
            } else {
                g.down_window.start_offset()
            },
            up_fin: ResumeFin {
                seen: g.up_fin_final.is_some(),
                final_offset: g.up_fin_final,
                applied: g.up_fin,
                acked: g.up_fin,
            },
            down_fin: ResumeFin {
                seen: g.down_fin,
                final_offset: if g.down_fin {
                    Some(g.down_produced)
                } else {
                    None
                },
                applied: g.down_fin,
                acked: g.down_fin_acked,
            },
            resume_remaining: deadline.saturating_duration_since(Instant::now()),
        };
        g.last_resume_response = Some(response.clone());
        self.cv.notify_all();
        Ok(response)
    }

    fn resume_fail_locked(
        &self,
        g: &mut super::Inner,
        code: &str,
        message: &str,
    ) -> Result<ResumeResponse> {
        let err = Error::new(code, message).closed(code == wire::ERR_FRAME_CONFLICT);
        self.resume_close_locked(g, err)
    }

    fn resume_close_locked(&self, g: &mut super::Inner, err: Error) -> Result<ResumeResponse> {
        g.terminal = Some(err.clone());
        g.state = State::Closed;
        g.resume_busy = false;
        g.down_window.reset();
        g.down_boundaries.clear();
        g.up_pending.clear();
        g.up_pending_bytes = 0;
        self.sync_retained_payload_bytes(g);
        if let Some(lease) = g.recovery_lease.take() {
            lease.end();
        }
        self.closed
            .store(true, std::sync::atomic::Ordering::Release);
        let _ = self.backend.shutdown(std::net::Shutdown::Both);
        self.cv.notify_all();
        Err(err)
    }

    fn expire_recovery_locked(&self, g: &mut super::Inner) {
        if g.state != State::Closed && g.recovery_deadline.is_some_and(|d| Instant::now() >= d) {
            let err = Error::new(wire::ERR_RESUME_EXPIRED, "resume grace expired").closed(true);
            g.terminal = Some(err);
            g.state = State::Closed;
            g.down_window.reset();
            g.down_boundaries.clear();
            g.up_pending.clear();
            g.up_pending_bytes = 0;
            self.sync_retained_payload_bytes(g);
            if let Some(lease) = g.recovery_lease.take() {
                lease.end();
            }
            self.closed
                .store(true, std::sync::atomic::Ordering::Release);
            g.change_generation = g.change_generation.wrapping_add(1);
            let _ = self.backend.shutdown(std::net::Shutdown::Both);
            self.cv.notify_all();
        }
    }
}

fn validate_fin(req: &ResumeRequest, g: &super::Inner) -> Result<()> {
    if req.up_fin.applied && !req.up_fin.seen
        || req.up_fin.acked && !req.up_fin.applied
        || req.down_fin.applied && !req.down_fin.seen
        || req.down_fin.acked && !req.down_fin.applied
    {
        return Err(Error::new(
            wire::ERR_FRAME_CONFLICT,
            "inconsistent FIN state",
        ));
    }
    if req.up_fin.seen && req.up_fin.final_offset != Some(req.up_next_offset) {
        return Err(Error::new(wire::ERR_FRAME_CONFLICT, "up FIN offset"));
    }
    if let Some(n) = req.up_fin.final_offset {
        if n < g.up_flushed {
            return Err(Error::new(wire::ERR_FRAME_CONFLICT, "up FIN regressed"));
        }
    }
    if g.up_fin_final.is_some() && req.up_fin.final_offset != g.up_fin_final {
        return Err(Error::new(wire::ERR_FRAME_CONFLICT, "up FIN differs"));
    }
    if req.down_fin.seen && !g.down_fin {
        return Err(Error::new(
            wire::ERR_FRAME_CONFLICT,
            "down FIN not recorded",
        ));
    }
    Ok(())
}
