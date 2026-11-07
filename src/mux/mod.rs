use std::io;
use std::time::Duration;

mod session;
mod stream;

pub use session::Session;
pub use stream::Stream;

pub const VERSION: u8 = 2;

pub const CMD_SYN: u8 = 0;
pub const CMD_FIN: u8 = 1;
pub const CMD_PSH: u8 = 2;
pub const CMD_NOP: u8 = 3;
pub const CMD_UPD: u8 = 4;

pub const HEADER_LEN: usize = 8;
const UPD_LEN: usize = 8;

/// The window the sender assumes before the first `UPD` arrives. smux uses
/// the same constant, and it is never larger than a real window (the
/// configured window has a 256 KiB floor), so the guess is always safe.
pub const INITIAL_PEER_WINDOW: u32 = 262_144;

#[derive(Debug, Clone)]
pub struct MuxConfig {
    /// Largest `PSH` payload this side will send.
    pub max_frame_size: usize,
    /// Receive window of one stream: how far ahead of the reader the peer may
    /// get, and therefore how many bytes one stream can hold in memory.
    pub stream_window: u32,
    /// Streams open at once on one session.
    pub max_streams: usize,
    /// smux `MaxReceiveBuffer`: bytes received and not yet read, summed over
    /// every stream of the session. The read loop stops reading the
    /// connection while it is used up (smux's token bucket); one stream that
    /// overruns its window never ends the session.
    pub max_receive_buffer: usize,
    pub keepalive: Duration,
    pub detect: Duration,
}

impl Default for MuxConfig {
    fn default() -> Self {
        MuxConfig {
            max_frame_size: 32 * 1024,
            stream_window: INITIAL_PEER_WINDOW,
            max_streams: 1024,
            max_receive_buffer: INITIAL_PEER_WINDOW as usize * 1024,
            keepalive: Duration::from_secs(15),
            detect: Duration::from_secs(45),
        }
    }
}

pub(super) fn would_block(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, msg)
}

pub(super) fn encode_header(cmd: u8, sid: u32, len: usize) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0] = VERSION;
    h[1] = cmd;
    h[2..4].copy_from_slice(&(len as u16).to_le_bytes());
    h[4..8].copy_from_slice(&sid.to_le_bytes());
    h
}

/// Which stream ids this side hands out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opener {
    /// Ids 3, 5, 7… — the side that accepted the tunnel (smux "client").
    Odd,
    /// Ids 2, 4, 6… — the side that dialed the tunnel (smux "server").
    Even,
}

#[cfg(test)]
mod tests;
