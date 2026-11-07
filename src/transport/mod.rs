//! Carriers: the two ways a session's bytes cross the network.
//!
//! The data plane never knows which carrier it is using. It asks for a
//! `CarrierWriter` and a `CarrierReader`; `ws` gives it a WebSocket pair,
//! `http-sse` gives it a POST-per-frame writer and an event-stream reader.
//! Everything above this module — the session accounting, the ingress relay,
//! the egress relay — is carrier-agnostic.

pub mod control;
pub mod sse_carrier;
pub mod sse_progress;
pub mod ws_carrier;

#[cfg(test)]
#[path = "spec_transport_tests.rs"]
mod spec_transport_tests;

#[cfg(test)]
#[path = "spec_precheck_tests.rs"]
pub(crate) mod spec_precheck_tests;

#[cfg(test)]
#[path = "spec_carrier3_tests.rs"]
pub(crate) mod spec_carrier3_tests;

use std::sync::Arc;

use crate::config::Transport;
use crate::error::{Error, Result};
use crate::wire::{self, Control, Limits};

/// One inbound item from a carrier.
pub enum Incoming {
    Data {
        epoch: u64,
        offset: u64,
        payload: Vec<u8>,
    },
    Control(Control),
    /// Nothing arrived before the read timeout; the caller should re-check its
    /// shutdown flag and call again.
    Idle,
    /// The carrier is gone. `code` is set when the peer said why.
    Closed(Option<Error>),
}

/// The write half of a carrier.
pub trait CarrierWriter: Send {
    fn send_data(&mut self, epoch: u64, offset: u64, payload: &[u8]) -> Result<Option<u64>>;
    fn send_control(&mut self, c: &Control) -> Result<()>;
    /// Sends an already-encoded text message (the WebSocket precheck hello).
    fn send_text(&mut self, _text: &str) -> Result<()> {
        Err(Error::new(
            wire::ERR_TRANSPORT_UNSUPPORTED,
            "carrier has no text channel",
        ))
    }
    /// Sends a carrier-level close after a terminal error notice. Non-WebSocket
    /// carriers have no close frame and keep the default no-op implementation.
    fn send_close(&mut self, _code: u16, _reason: &str) -> Result<()> {
        Ok(())
    }
    /// Best-effort graceful shutdown of the underlying stream.
    fn shutdown(&mut self);
}

/// The read half of a carrier.
pub trait CarrierReader: Send {
    fn recv(&mut self) -> Result<Incoming>;
    /// A handle on the carrier's read connection that another thread may
    /// shut down to end a blocked `recv` (the ingress uses it to release a
    /// carrier it keeps reading after the down FIN). `None` when the
    /// carrier has no such handle.
    fn interrupt_handle(&self) -> Option<Box<dyn crate::net::Conn>> {
        None
    }
}

#[derive(Clone)]
pub struct SharedWriter {
    inner: Arc<std::sync::Mutex<Box<dyn CarrierWriter>>>,
}

impl SharedWriter {
    pub fn new(writer: Box<dyn CarrierWriter>) -> Self {
        SharedWriter {
            inner: Arc::new(std::sync::Mutex::new(writer)),
        }
    }

    pub fn send_data(&self, epoch: u64, offset: u64, payload: &[u8]) -> Result<Option<u64>> {
        let mut w = self
            .inner
            .lock()
            .map_err(|_| Error::local("carrier writer poisoned"))?;
        w.send_data(epoch, offset, payload)
    }

    /// Replace the underlying carrier without replacing the per-session data
    /// pump. This is the recovery hand-off required by thread-per-connection.
    pub fn replace(&self, mut writer: Box<dyn CarrierWriter>) -> Result<()> {
        let mut current = match self.inner.lock() {
            Ok(current) => current,
            Err(_) => {
                writer.shutdown();
                return Err(Error::local("carrier writer poisoned"));
            }
        };
        current.shutdown();
        *current = writer;
        Ok(())
    }

    pub fn send_control(&self, c: &Control) -> Result<()> {
        let mut w = self
            .inner
            .lock()
            .map_err(|_| Error::local("carrier writer poisoned"))?;
        w.send_control(c)
    }

    pub fn send_close(&self, code: u16, reason: &str) -> Result<()> {
        let mut w = self
            .inner
            .lock()
            .map_err(|_| Error::local("carrier writer poisoned"))?;
        w.send_close(code, reason)
    }

    pub fn shutdown(&self) {
        if let Ok(mut w) = self.inner.lock() {
            w.shutdown();
        }
    }
}

/// The limits the ingress proposes for a new session.
pub fn requested_limits(t: &Transport) -> Limits {
    Limits {
        max_frame_size: t.max_frame_size,
        up_max_inflight_frames: t.up_max_inflight_frames,
        up_window_bytes: t.up_window_bytes,
        down_buffer_bytes: t.buffer_per_direction,
        up_receipt_limit: 0,
        down_max_frames: 0,
    }
}

/// The limits the egress settles on: the smaller value of each pair wins, and
/// a frame must fit both windows.
pub fn negotiate_limits(t: &Transport, requested: &Limits) -> Result<Limits> {
    let max_frame_size = requested.max_frame_size.min(t.max_frame_size);
    let up_max_inflight = requested
        .up_max_inflight_frames
        .min(t.up_max_inflight_frames);
    let up_window = requested.up_window_bytes.min(t.up_window_bytes);
    let down_buffer = requested.down_buffer_bytes.min(t.buffer_per_direction);
    if max_frame_size == 0 || up_max_inflight == 0 || up_window == 0 || down_buffer == 0 {
        return Err(Error::new(
            wire::ERR_BAD_FRAME,
            "creation refused: zero limit",
        ));
    }
    if max_frame_size > wire::MAX_FRAME_PAYLOAD {
        return Err(Error::new(
            wire::ERR_BAD_FRAME,
            "creation refused: frame too large",
        ));
    }
    if max_frame_size as u64 > up_window {
        return Err(Error::new(
            wire::ERR_BAD_FRAME,
            "creation refused: max_frame_size exceeds up_window_bytes",
        ));
    }
    if max_frame_size as u64 > down_buffer {
        return Err(Error::new(
            wire::ERR_BAD_FRAME,
            "creation refused: max_frame_size exceeds down_buffer_bytes",
        ));
    }
    Ok(Limits {
        max_frame_size,
        up_max_inflight_frames: up_max_inflight,
        up_window_bytes: up_window,
        down_buffer_bytes: down_buffer,
        up_receipt_limit: t.receipt_limit_per_session,
        down_max_frames: 512,
    })
}

#[cfg(test)]
#[path = "spec_sse_parser_tests.rs"]
mod spec_sse_parser_tests;
