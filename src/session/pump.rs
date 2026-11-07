//! Reads the backend and turns it into downstream frames.

use std::io::Read;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::wire::{self, ERR_BACKEND_LOST};

use super::Session;

/// Reads the backend and hands out downstream frames.
pub struct DownPump {
    pub session: Arc<Session>,
    pub frame_size: usize,
}

impl DownPump {
    /// Runs the downstream producer. `emit` receives each frame's offset and
    /// payload and returns once the carrier accepted it.
    // Retained for callers that own the pump lifecycle; the egress path uses
    // `run_locked` while coordinating carrier generation locks.
    #[allow(dead_code)]
    pub fn run<F>(&self, mut emit: F) -> Result<()>
    where
        F: FnMut(u64, &[u8]) -> Result<()>,
    {
        let _reader = self.session.lock_downstream();
        self.run_locked(&mut emit)
    }

    pub(crate) fn run_locked<F>(&self, emit: F) -> Result<()>
    where
        F: FnMut(u64, &[u8]) -> Result<()>,
    {
        self.run_locked_capped(usize::MAX, emit)
    }

    pub(crate) fn adaptive_bounds(&self, cap: usize) -> (usize, usize) {
        let max = self
            .session
            .limits
            .max_frame_size
            .min(wire::MAX_FRAME_PAYLOAD)
            .min(cap)
            .max(1);
        let base = if self.frame_size == 0 {
            32 * 1024
        } else {
            self.frame_size
        };
        (base.min(max), max)
    }

    pub(crate) fn run_locked_capped<F>(&self, cap: usize, mut emit: F) -> Result<()>
    where
        F: FnMut(u64, &[u8]) -> Result<()>,
    {
        let epoch = self.session.epoch();
        for (offset, payload) in self.session.replay_down_frames() {
            if self.session.is_closed() || self.session.epoch() != epoch {
                return Ok(());
            }
            emit(offset, &payload)?;
        }
        let sock = self.session.backend();
        let mut sock: &TcpStream = &sock;
        let _ = sock.set_read_timeout(Some(Duration::from_millis(250)));
        let (base, max) = self.adaptive_bounds(cap);
        let mut size = base;
        let mut buf = vec![0u8; base];
        loop {
            if self.session.is_closed()
                || self.session.epoch() != epoch
                || matches!(
                    self.session.recovery_state(),
                    super::recovery::RecoveryState::Suspended
                        | super::recovery::RecoveryState::Resuming
                )
            {
                return Ok(());
            }
            if buf.len() < size {
                buf.resize(size, 0);
            }
            let reservation = match self.session.reserve_down_for_read(epoch, size) {
                Some(reservation) if reservation.bytes > 0 => reservation,
                Some(_) => continue,
                None => return Ok(()),
            };
            let reservation_bytes = reservation.bytes;
            let n = match sock.read(&mut buf[..reservation_bytes]) {
                Ok(0) => {
                    drop(reservation);
                    self.session.mark_down_fin();
                    return Ok(());
                }
                Ok(n) => n,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    drop(reservation);
                    continue;
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                    drop(reservation);
                    continue;
                }
                Err(e) => {
                    drop(reservation);
                    let err =
                        Error::new(ERR_BACKEND_LOST, format!("backend read: {e}")).closed(true);
                    self.session.close(err.clone());
                    return Err(err);
                }
            };
            if self.session.is_closed() {
                drop(reservation);
                return Ok(());
            }
            // Bytes taken from the backend are part of the stream whatever
            // happened to the carrier meanwhile: record them as produced so
            // they stay in the replay window. Dropping them here when the
            // carrier was lost during the read (suspended / resuming / new
            // epoch) silently cut one frame (32 KiB) out of the stream (B5).
            let offset = match self
                .session
                .mark_down_produced_reserved(&buf[..n], reservation)
            {
                Ok(offset) => offset,
                Err(e) => {
                    self.session.close(e.clone());
                    return Err(e);
                }
            };
            if self.session.epoch() != epoch
                || matches!(
                    self.session.recovery_state(),
                    super::recovery::RecoveryState::Suspended
                        | super::recovery::RecoveryState::Resuming
                )
            {
                // The next carrier generation replays it.
                return Ok(());
            }
            emit(offset, &buf[..n])?;
            if n == size {
                size = size.saturating_mul(2).min(max);
            } else if n < reservation_bytes {
                size = base;
            }
        }
    }
}
