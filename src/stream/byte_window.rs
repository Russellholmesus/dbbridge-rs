use std::collections::VecDeque;
use std::convert::TryFrom;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use crate::resource::budget::{Budget, BudgetLease};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByteWindowError {
    InvalidRange,
    CapacityExceeded,
    BudgetExhausted,
    AllocationFailed,
}

struct Block {
    start: u64,
    data: Vec<u8>,
    _charge: BudgetLease,
}
struct PayloadCharge {
    start: u64,
    end: u64,
    lease: BudgetLease,
}
struct State {
    start_offset: u64,
    blocks: VecDeque<Block>,
    size: usize,
    allocated: i64,
    max_capacity: i64,
    budget: Arc<Budget>,
    payload_budget: Option<Arc<Budget>>,
    payload_charges: VecDeque<PayloadCharge>,
    backpressure_timeout: Duration,
    chunk_size: usize,
    final_offset: Option<u64>,
}

/// A contiguous retained byte range. Capacity is charged by each retained Vec's
/// allocation, not only its logical length. Partial ACKs keep the original Vec
/// alive and charged until its entire block is acknowledged.
pub struct ByteWindow {
    state: Mutex<State>,
}
impl ByteWindow {
    pub fn new(offset: u64, max_capacity: i64) -> Self {
        Self::with_budget(offset, max_capacity, Budget::new(max_capacity))
    }

    /// Creates a window with its own cap and an additional shared budget. Each
    /// stored block holds an RAII charge in `budget` until that block is freed.
    pub fn with_budget(offset: u64, max_capacity: i64, budget: Arc<Budget>) -> Self {
        Self {
            state: Mutex::new(State {
                start_offset: offset,
                blocks: VecDeque::new(),
                size: 0,
                allocated: 0,
                max_capacity,
                budget,
                payload_budget: None,
                payload_charges: VecDeque::new(),
                backpressure_timeout: Duration::from_secs(120),
                chunk_size: 32 * 1024,
                final_offset: None,
            }),
        }
    }

    #[cfg(test)]
    pub fn set_chunk_size(&self, size: usize) {
        if size > 0 {
            self.state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .chunk_size = size;
        }
    }

    /// Binds a shared process payload budget. Existing bytes are charged
    /// atomically; partial ACKs later return logical bytes while allocation
    /// capacity remains charged until each backing block is wholly freed.
    pub fn set_payload_budget(&self, budget: Arc<Budget>) -> Result<(), ByteWindowError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state
            .payload_budget
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &budget))
        {
            return Ok(());
        }
        let start = state.start_offset;
        let end = start
            .checked_add(state.size as u64)
            .ok_or(ByteWindowError::InvalidRange)?;
        let logical = i64::try_from(state.size).map_err(|_| ByteWindowError::CapacityExceeded)?;
        let lease = if logical > 0 {
            Some(
                budget
                    .try_acquire(logical)
                    .ok_or(ByteWindowError::BudgetExhausted)?,
            )
        } else {
            None
        };
        state.payload_charges.clear();
        state.payload_budget = Some(budget);
        if let Some(lease) = lease {
            state
                .payload_charges
                .push_back(PayloadCharge { start, end, lease });
        }
        Ok(())
    }

    pub fn set_backpressure_timeout(&self, timeout: Duration) {
        if !timeout.is_zero() {
            self.state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .backpressure_timeout = timeout;
        }
    }

    /// Reserves logical payload bytes from the same shared budget for a
    /// companion buffer (for example an upstream out-of-order frame). The
    /// returned lease is owned by that buffer and releases on drop.
    pub fn reserve_payload(&self, amount: usize) -> Result<Option<BudgetLease>, ByteWindowError> {
        if amount == 0 {
            return Ok(None);
        }
        let amount = i64::try_from(amount).map_err(|_| ByteWindowError::CapacityExceeded)?;
        let budget = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .payload_budget
            .clone();
        match budget {
            Some(budget) => budget
                .try_acquire(amount)
                .map(Some)
                .ok_or(ByteWindowError::BudgetExhausted),
            None => Ok(None),
        }
    }

    /// Copies a contiguous range into blocks no larger than the configured
    /// chunk size. The operation is atomic: errors leave offsets and accounting
    /// unchanged.
    #[cfg(test)]
    pub fn append(&self, offset: u64, data: &[u8]) -> Result<(), ByteWindowError> {
        self.append_reserved(offset, data, None)
    }

    /// Appends data with an optional pre-reserved global payload lease. Any
    /// unused reservation is returned before the lease enters the ACK ledger.
    pub fn append_reserved(
        &self,
        offset: u64,
        data: &[u8],
        reserved: Option<BudgetLease>,
    ) -> Result<(), ByteWindowError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let end = state
            .start_offset
            .checked_add(state.size as u64)
            .ok_or(ByteWindowError::InvalidRange)?;
        let end_after = offset
            .checked_add(u64::try_from(data.len()).map_err(|_| ByteWindowError::InvalidRange)?)
            .ok_or(ByteWindowError::InvalidRange)?;
        if offset != end {
            return Err(ByteWindowError::InvalidRange);
        }
        let logical = i64::try_from(data.len()).map_err(|_| ByteWindowError::CapacityExceeded)?;
        if logical > state.max_capacity.saturating_sub(state.allocated) {
            return Err(ByteWindowError::CapacityExceeded);
        }
        let new_size = state
            .size
            .checked_add(data.len())
            .ok_or(ByteWindowError::InvalidRange)?;
        if data.is_empty() {
            return Ok(());
        }
        let payload_lease = match (&state.payload_budget, reserved) {
            (Some(_), Some(mut lease)) => {
                if lease.amount() < logical {
                    return Err(ByteWindowError::BudgetExhausted);
                }
                lease.release_part(lease.amount().saturating_sub(logical));
                Some(lease)
            }
            (Some(budget), None) => Some(
                budget
                    .try_acquire(logical)
                    .ok_or(ByteWindowError::BudgetExhausted)?,
            ),
            (None, Some(lease)) => {
                lease.release();
                None
            }
            (None, None) => None,
        };

        let mut new_blocks = VecDeque::new();
        let mut charged = 0i64;
        let mut pos = 0usize;
        while pos < data.len() {
            let end_pos = data.len().min(pos.saturating_add(state.chunk_size));
            let mut block = Vec::new();
            block
                .try_reserve_exact(end_pos - pos)
                .map_err(|_| ByteWindowError::AllocationFailed)?;
            block.extend_from_slice(&data[pos..end_pos]);
            charged = charged
                .checked_add(
                    i64::try_from(block.capacity())
                        .map_err(|_| ByteWindowError::CapacityExceeded)?,
                )
                .ok_or(ByteWindowError::CapacityExceeded)?;
            new_blocks.push_back((offset + pos as u64, block));
            pos = end_pos;
        }
        if charged > state.max_capacity.saturating_sub(state.allocated) {
            return Err(ByteWindowError::CapacityExceeded);
        }
        let mut charged_blocks = VecDeque::new();
        for (start, data) in new_blocks {
            let amount =
                i64::try_from(data.capacity()).map_err(|_| ByteWindowError::CapacityExceeded)?;
            let charge = state
                .budget
                .try_acquire(amount)
                .ok_or(ByteWindowError::CapacityExceeded)?;
            charged_blocks.push_back(Block {
                start,
                data,
                _charge: charge,
            });
        }
        state.blocks.append(&mut charged_blocks);
        state.size = new_size;
        state.allocated = state.allocated.saturating_add(charged);
        if let Some(lease) = payload_lease {
            state.payload_charges.push_back(PayloadCharge {
                start: offset,
                end: end_after,
                lease,
            });
        }
        debug_assert_eq!(offset + data.len() as u64, end_after);
        Ok(())
    }

    /// Adopts an allocation owned by the caller. On success the caller must not
    /// modify or reuse the vector. Its full capacity is charged.
    #[cfg(test)]
    pub fn append_owned(&self, offset: u64, data: Vec<u8>) -> Result<(), ByteWindowError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let end = state
            .start_offset
            .checked_add(state.size as u64)
            .ok_or(ByteWindowError::InvalidRange)?;
        let end_after = offset
            .checked_add(u64::try_from(data.len()).map_err(|_| ByteWindowError::InvalidRange)?)
            .ok_or(ByteWindowError::InvalidRange)?;
        if offset != end || data.is_empty() {
            return Err(ByteWindowError::InvalidRange);
        }
        let logical = i64::try_from(data.len()).map_err(|_| ByteWindowError::CapacityExceeded)?;
        let new_size = state
            .size
            .checked_add(data.len())
            .ok_or(ByteWindowError::InvalidRange)?;
        let charged =
            i64::try_from(data.capacity()).map_err(|_| ByteWindowError::CapacityExceeded)?;
        if charged > state.max_capacity.saturating_sub(state.allocated) {
            return Err(ByteWindowError::CapacityExceeded);
        }
        let charge = state
            .budget
            .try_acquire(charged)
            .ok_or(ByteWindowError::CapacityExceeded)?;
        let payload_lease = match &state.payload_budget {
            Some(budget) => Some(
                budget
                    .try_acquire(logical)
                    .ok_or(ByteWindowError::BudgetExhausted)?,
            ),
            None => None,
        };
        state.size = new_size;
        state.allocated = state.allocated.saturating_add(charged);
        state.blocks.push_back(Block {
            start: offset,
            data,
            _charge: charge,
        });
        if let Some(lease) = payload_lease {
            state.payload_charges.push_back(PayloadCharge {
                start: offset,
                end: end_after,
                lease,
            });
        }
        debug_assert_eq!(
            offset + state.blocks.back().unwrap().data.len() as u64,
            end_after
        );
        Ok(())
    }

    /// Acknowledges any byte offset. Values at/before the current start are
    /// harmless; values after end are clamped to end. A partially acknowledged
    /// allocation stays charged until its block is wholly removed.
    pub fn acknowledge(&self, offset: u64) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if offset <= state.start_offset {
            return;
        }
        let end = state.start_offset.saturating_add(state.size as u64);
        let acknowledged = offset.min(end);
        let delta = (acknowledged - state.start_offset) as usize;
        while let Some(charge) = state.payload_charges.front_mut() {
            if acknowledged <= charge.start {
                break;
            }
            let released_end = acknowledged.min(charge.end);
            let released = released_end.saturating_sub(charge.start);
            if released > 0 {
                charge
                    .lease
                    .release_part(i64::try_from(released).unwrap_or(i64::MAX));
                charge.start = released_end;
            }
            if charge.start == charge.end {
                state.payload_charges.pop_front();
            } else {
                break;
            }
        }
        state.size = state.size.saturating_sub(delta);
        state.start_offset = acknowledged;
        while state.blocks.front().is_some_and(|block| {
            block.start.saturating_add(block.data.len() as u64) <= acknowledged
        }) {
            if let Some(block) = state.blocks.pop_front() {
                state.allocated = state
                    .allocated
                    .saturating_sub(i64::try_from(block.data.capacity()).unwrap_or(i64::MAX));
                drop(block);
            }
        }
    }

    /// Returns a copied range, its next offset, and whether it reaches the FIN
    /// offset. `None` means `offset` is outside the retained range.
    pub fn read_range(&self, offset: u64, max: usize) -> Option<(Vec<u8>, u64, bool)> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let end = state.start_offset.checked_add(state.size as u64)?;
        if offset < state.start_offset || offset > end {
            return None;
        }
        let length = usize::try_from(end - offset).ok()?.min(max);
        let mut result = Vec::with_capacity(length);
        let mut cursor = offset;
        for block in &state.blocks {
            let block_end = block.start.checked_add(block.data.len() as u64)?;
            if block_end <= cursor {
                continue;
            }
            if cursor < block.start {
                return None;
            }
            let start = usize::try_from(cursor - block.start).ok()?;
            let take = (block.data.len() - start).min(length - result.len());
            result.extend_from_slice(&block.data[start..start + take]);
            cursor = cursor.checked_add(take as u64)?;
            if result.len() == length {
                break;
            }
        }
        let reaches_final = state
            .final_offset
            .is_some_and(|final_offset| cursor == final_offset);
        Some((result, cursor, reaches_final))
    }

    /// Returns copied segments for a range; useful to preserve frame grouping
    /// without exposing mutable aliases to retained storage.
    #[cfg(test)]
    pub fn segments(&self, offset: u64, limit: usize) -> Option<(Vec<Vec<u8>>, u64)> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let end = state.start_offset.checked_add(state.size as u64)?;
        if offset < state.start_offset || offset > end {
            return None;
        }
        let mut remaining = limit.min(usize::try_from(end - offset).ok()?);
        let mut cursor = offset;
        let mut segments = Vec::new();
        for block in &state.blocks {
            if remaining == 0 {
                break;
            }
            let block_end = block.start.checked_add(block.data.len() as u64)?;
            if block_end <= cursor {
                continue;
            }
            if cursor < block.start {
                return None;
            }
            let start = usize::try_from(cursor - block.start).ok()?;
            let take = (block.data.len() - start).min(remaining);
            segments.push(block.data[start..start + take].to_vec());
            cursor = cursor.checked_add(take as u64)?;
            remaining -= take;
        }
        Some((segments, cursor))
    }

    /// Drops all blocks and the FIN marker, keeping the window positioned at its
    /// prior end so the next append remains contiguous.
    pub fn reset(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.start_offset = state.start_offset.saturating_add(state.size as u64);
        state.blocks.clear();
        state.payload_charges.clear();
        state.size = 0;
        state.allocated = 0;
        state.final_offset = None;
    }

    #[cfg(test)]
    pub fn set_final_offset(&self, offset: u64) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .final_offset = Some(offset);
    }
    pub fn start_offset(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .start_offset
    }
    #[cfg(test)]
    pub fn end_offset(&self) -> u64 {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.start_offset.saturating_add(state.size as u64)
    }
    pub fn buffered_bytes(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .size
    }
    #[cfg(test)]
    pub fn allocated_bytes(&self) -> i64 {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .allocated
    }

    pub fn available_allocation_capacity(&self) -> i64 {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state
            .max_capacity
            .saturating_sub(state.allocated)
            .min(state.budget.available())
    }

    pub fn available_payload_capacity(&self) -> i64 {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .payload_budget
            .as_ref()
            .map_or(i64::MAX, |budget| budget.available())
    }

    pub fn has_payload_budget(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .payload_budget
            .is_some()
    }

    pub fn payload_budget_handle(&self) -> Option<Arc<Budget>> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .payload_budget
            .clone()
    }

    pub fn backpressure_timeout(&self) -> Duration {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .backpressure_timeout
    }

    #[cfg(test)]
    pub fn available_capacity(&self) -> i64 {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let payload_available = state
            .payload_budget
            .as_ref()
            .map_or(i64::MAX, |budget| budget.available());
        state
            .max_capacity
            .saturating_sub(state.allocated)
            .min(state.budget.available())
            .min(payload_available)
    }

    #[cfg(test)]
    fn block_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .blocks
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::budget::Budget;

    #[test]
    fn accepts_arbitrary_byte_ack_and_retains_allocation_until_block_end() {
        let window = ByteWindow::new(0, 32);
        let mut data = Vec::with_capacity(32);
        data.extend_from_slice(b"data");
        window.append_owned(0, data).unwrap();
        assert_eq!(window.allocated_bytes(), 32);
        window.acknowledge(2);
        assert_eq!(window.start_offset(), 2);
        assert_eq!(window.buffered_bytes(), 2);
        assert_eq!(window.allocated_bytes(), 32);
        assert_eq!(window.read_range(2, 2).unwrap().0, b"ta");
        window.acknowledge(4);
        assert_eq!(window.allocated_bytes(), 0);
        assert_eq!(window.available_capacity(), 32);
    }

    #[test]
    fn shared_budget_is_charged_by_capacity_and_refunded_on_full_block_ack() {
        let budget = Budget::new(8);
        let first = ByteWindow::with_budget(0, 8, budget.clone());
        let second = ByteWindow::with_budget(0, 8, budget.clone());
        first.append(0, b"123456").unwrap();
        assert_eq!(budget.used(), 6);
        assert_eq!(
            second.append(0, b"abc"),
            Err(ByteWindowError::CapacityExceeded)
        );
        first.acknowledge(3);
        assert_eq!(budget.used(), 6, "partial ACK preserves the allocation");
        first.acknowledge(6);
        assert_eq!(budget.used(), 0);
        second.append(0, b"abc").unwrap();
        assert_eq!(budget.used(), 3);
    }

    #[test]
    fn shared_payload_budget_charges_logical_bytes_and_returns_partial_ack() {
        let payload = Budget::new(8);
        let first = ByteWindow::new(0, 32);
        let second = ByteWindow::new(0, 32);
        first.set_payload_budget(payload.clone()).unwrap();
        second.set_payload_budget(payload.clone()).unwrap();

        first.append(0, b"abcd").unwrap();
        second.append(0, b"efgh").unwrap();
        assert_eq!(payload.used(), 8);
        assert_eq!(
            second.append(4, b"i"),
            Err(ByteWindowError::BudgetExhausted)
        );

        first.acknowledge(2);
        assert_eq!(payload.used(), 6);
        second.append(4, b"ij").unwrap();
        assert_eq!(payload.used(), 8);

        first.reset();
        assert_eq!(payload.used(), 6);
        second.acknowledge(5);
        assert_eq!(payload.used(), 1);
        second.reset();
        assert_eq!(payload.used(), 0);
    }

    #[test]
    fn shared_payload_budget_counts_logical_len_not_vec_capacity() {
        let payload = Budget::new(8);
        let window = ByteWindow::new(0, 32);
        window.set_payload_budget(payload.clone()).unwrap();
        let mut data = Vec::with_capacity(16);
        data.extend_from_slice(b"data");
        window.append_owned(0, data).unwrap();

        assert_eq!(window.buffered_bytes(), 4);
        assert_eq!(window.allocated_bytes(), 16);
        assert_eq!(payload.used(), 4);
        window.acknowledge(2);
        assert_eq!(window.allocated_bytes(), 16);
        assert_eq!(payload.used(), 2);
        window.acknowledge(4);
        assert_eq!(window.allocated_bytes(), 0);
        assert_eq!(payload.used(), 0);
    }

    #[test]
    fn binding_payload_budget_charges_existing_bytes_atomically() {
        let window = ByteWindow::new(0, 32);
        window.append(0, b"data").unwrap();

        let too_small = Budget::new(3);
        assert_eq!(
            window.set_payload_budget(too_small.clone()),
            Err(ByteWindowError::BudgetExhausted)
        );
        assert_eq!(too_small.used(), 0);
        assert_eq!(window.buffered_bytes(), 4);

        let payload = Budget::new(4);
        window.set_payload_budget(payload.clone()).unwrap();
        window.set_payload_budget(payload.clone()).unwrap();
        assert_eq!(payload.used(), 4);
        window.acknowledge(2);
        assert_eq!(payload.used(), 2);
    }

    #[test]
    fn companion_payload_reservation_shares_budget_and_releases_on_drop() {
        let payload = Budget::new(4);
        let window = ByteWindow::new(0, 8);
        window.set_payload_budget(payload.clone()).unwrap();
        let lease = window.reserve_payload(3).unwrap().unwrap();
        assert_eq!(payload.used(), 3);
        assert!(window.reserve_payload(2).is_err());
        drop(lease);
        assert_eq!(payload.used(), 0);
        assert!(window.reserve_payload(4).is_ok());
    }

    #[test]
    fn append_reserved_transfers_only_read_bytes_into_window_lease() {
        let payload = Budget::new(8);
        let window = ByteWindow::new(0, 16);
        window.set_payload_budget(payload.clone()).unwrap();
        let reservation = window.reserve_payload(8).unwrap();
        assert_eq!(payload.used(), 8);

        window.append_reserved(0, b"abc", reservation).unwrap();
        assert_eq!(payload.used(), 3);
        window.acknowledge(1);
        assert_eq!(payload.used(), 2);
    }

    #[test]
    fn append_is_contiguous_bounded_and_atomic_on_failure() {
        let window = ByteWindow::new(10, 4);
        window.append(10, b"ab").unwrap();
        assert_eq!(window.append(13, b"x"), Err(ByteWindowError::InvalidRange));
        assert_eq!(
            window.append(12, b"cde"),
            Err(ByteWindowError::CapacityExceeded)
        );
        assert_eq!(window.end_offset(), 12);
        assert_eq!(window.buffered_bytes(), 2);
        assert_eq!(window.allocated_bytes(), 2);
    }

    #[test]
    fn ack_clamps_to_end_and_releases_only_fully_acked_blocks() {
        let window = ByteWindow::new(0, 32);
        window.set_chunk_size(4);
        window.append(0, b"abcdefgh").unwrap();
        assert_eq!(window.allocated_bytes(), 8);
        window.acknowledge(6);
        assert_eq!(window.start_offset(), 6);
        assert_eq!(window.allocated_bytes(), 4);
        assert_eq!(window.read_range(6, 2).unwrap().0, b"gh");
        window.acknowledge(u64::MAX);
        assert_eq!(window.start_offset(), 8);
        assert_eq!(window.allocated_bytes(), 0);
        window.acknowledge(0);
        assert_eq!(window.start_offset(), 8);
    }

    #[test]
    fn reset_releases_storage_and_preserves_contiguous_position() {
        let window = ByteWindow::new(20, 100);
        window.append(20, b"hello").unwrap();
        window.set_final_offset(25);
        assert_eq!(window.block_count(), 1);
        window.reset();
        assert_eq!(window.start_offset(), 25);
        assert_eq!(window.allocated_bytes(), 0);
        assert_eq!(window.read_range(25, 10), Some((Vec::new(), 25, false)));
        window.append(25, b"! ").unwrap();
        assert_eq!(window.end_offset(), 27);
    }

    #[test]
    fn overflow_and_out_of_range_reads_are_rejected() {
        let window = ByteWindow::new(u64::MAX - 1, 8);
        assert_eq!(
            window.append(u64::MAX - 1, b"xx"),
            Err(ByteWindowError::InvalidRange)
        );
        assert!(window.read_range(u64::MAX - 1, 1).is_some());
        assert!(window.read_range(0, 1).is_none());
    }
}
