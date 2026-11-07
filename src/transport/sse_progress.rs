use std::time::{Duration, Instant};

use crate::error::Result;

pub const SSE_PIECE_MIN: usize = 1 << 10;
pub const SSE_PIECE_MAX: usize = 64 << 10;

/// The carrier side of [`write_sse_progress`]: an SSE response body that can
/// arm a per-piece write deadline, take a piece and flush it.
pub trait SsePieceSink {
    fn arm_idle_deadline(&mut self, idle: Duration) -> Result<()>;
    fn write_piece(&mut self, piece: &[u8]) -> Result<()>;
    fn flush_piece(&mut self) -> Result<()>;
}

/// The next piece size after one took `elapsed` against `idle`: grow while
/// the link keeps well ahead of the idle deadline (< idle/8), shrink when it
/// does not (> idle/4).
pub fn next_piece(piece: usize, elapsed: Duration, idle: Duration) -> usize {
    if elapsed < idle / 8 {
        piece.saturating_mul(2).min(SSE_PIECE_MAX)
    } else if elapsed > idle / 4 {
        (piece / 2).max(SSE_PIECE_MIN)
    } else {
        piece
    }
}

pub fn write_sse_progress<S: SsePieceSink + ?Sized>(
    sink: &mut S,
    mut event: &[u8],
    idle: Duration,
) -> Result<()> {
    let mut piece = SSE_PIECE_MIN;
    while !event.is_empty() {
        sink.arm_idle_deadline(idle)?;
        let n = event.len().min(piece);
        let start = Instant::now();
        sink.write_piece(&event[..n])?;
        sink.flush_piece()?;
        event = &event[n..];
        piece = next_piece(piece, start.elapsed(), idle);
    }
    Ok(())
}
