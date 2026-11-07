use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant};

static UNBALANCED_RELEASES: AtomicU64 = AtomicU64::new(0);

/// Number of over-releases observed by all budgets in this process.
pub fn unbalanced_releases() -> u64 {
    UNBALANCED_RELEASES.load(Ordering::Relaxed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetError {
    Limit,
    Timeout,
}

impl fmt::Display for BudgetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limit => f.write_str("resource budget exhausted"),
            Self::Timeout => f.write_str("resource budget wait timed out"),
        }
    }
}
impl Error for BudgetError {}

/// A concurrent unit/byte budget. Shares are charged to their parent as well as
/// locally; a parent keep amount remains available to direct parent users.
pub struct Budget {
    limit: AtomicI64,
    used: AtomicI64,
    parent: Option<Arc<Budget>>,
    parent_keep: Option<Arc<dyn Fn() -> i64 + Send + Sync>>,
    wait_lock: Mutex<()>,
    changed: Condvar,
    children: Mutex<Vec<Weak<Budget>>>,
    waits: AtomicU64,
    wait_nanos: AtomicU64,
    overreleases: AtomicU64,
}

impl Budget {
    pub fn new(limit: i64) -> Arc<Self> {
        Arc::new(Self {
            limit: AtomicI64::new(limit),
            used: AtomicI64::new(0),
            parent: None,
            parent_keep: None,
            wait_lock: Mutex::new(()),
            changed: Condvar::new(),
            children: Mutex::new(Vec::new()),
            waits: AtomicU64::new(0),
            wait_nanos: AtomicU64::new(0),
            overreleases: AtomicU64::new(0),
        })
    }

    pub fn new_share(
        parent: Arc<Budget>,
        limit: i64,
        keep: impl Fn() -> i64 + Send + Sync + 'static,
    ) -> Arc<Self> {
        let budget = Arc::new(Self {
            limit: AtomicI64::new(limit),
            used: AtomicI64::new(0),
            parent: Some(parent.clone()),
            parent_keep: Some(Arc::new(keep)),
            wait_lock: Mutex::new(()),
            changed: Condvar::new(),
            children: Mutex::new(Vec::new()),
            waits: AtomicU64::new(0),
            wait_nanos: AtomicU64::new(0),
            overreleases: AtomicU64::new(0),
        });
        parent
            .children
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Arc::downgrade(&budget));
        budget
    }

    /// Changes the cap without revoking already-held capacity. Negative limits
    /// are clamped to zero, and new acquisitions remain blocked until usage fits.
    pub fn set_limit(&self, limit: i64) {
        self.limit.store(limit.max(0), Ordering::Release);
        self.notify_waiters();
    }

    pub fn limit(&self) -> i64 {
        self.limit.load(Ordering::Acquire)
    }
    pub fn used(&self) -> i64 {
        self.used.load(Ordering::Acquire)
    }
    pub fn available(&self) -> i64 {
        let local = self.limit().saturating_sub(self.used()).max(0);
        match &self.parent {
            Some(parent) => local.min(parent.available().saturating_sub(self.keep()).max(0)),
            None => local,
        }
    }
    #[cfg(test)]
    pub fn overreleases(&self) -> u64 {
        self.overreleases.load(Ordering::Relaxed)
    }
    pub fn wait_stats(&self) -> (u64, Duration) {
        (
            self.waits.load(Ordering::Relaxed),
            Duration::from_nanos(self.wait_nanos.load(Ordering::Relaxed)),
        )
    }

    /// Nonblocking acquisition. A negative amount is rejected; zero is a valid
    /// no-op lease when the local and parent constraints currently permit it.
    pub fn try_acquire(self: &Arc<Self>, amount: i64) -> Option<BudgetLease> {
        if !self.try_reserve(amount) {
            return None;
        }
        Some(BudgetLease {
            budget: Some(self.clone()),
            amount,
        })
    }

    pub fn try_acquire_keep(self: &Arc<Self>, amount: i64, keep: i64) -> Option<BudgetLease> {
        if !self.try_keep_chain(amount, keep) {
            return None;
        }
        Some(BudgetLease {
            budget: Some(self.clone()),
            amount,
        })
    }

    #[cfg(test)]
    pub fn try_take(&self, amount: i64) -> bool {
        self.try_reserve(amount)
    }

    /// Releases units. An over-release clamps this budget at zero, is counted,
    /// and does not panic. For a share, the parent is released as well.
    pub fn put(&self, amount: i64) {
        if amount <= 0 {
            return;
        }
        self.release_local(amount, true);
        if let Some(parent) = &self.parent {
            parent.put(amount);
        }
    }

    /// Waits for capacity until timeout. `None` waits without a time limit.
    /// Permanently impossible requests return `Limit` immediately.
    pub fn acquire_timeout(
        self: &Arc<Self>,
        amount: i64,
        timeout: Option<Duration>,
    ) -> Result<BudgetLease, BudgetError> {
        if !self.fits(amount) {
            return Err(BudgetError::Limit);
        }
        let started = Instant::now();
        let deadline = timeout.and_then(|d| started.checked_add(d));
        let mut recorded_wait = false;
        loop {
            let guard = self
                .wait_lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(lease) = self.try_acquire(amount) {
                drop(guard);
                if recorded_wait {
                    self.wait_nanos.fetch_add(
                        started.elapsed().as_nanos().min(u64::MAX as u128) as u64,
                        Ordering::Relaxed,
                    );
                }
                return Ok(lease);
            }
            if !recorded_wait {
                self.waits.fetch_add(1, Ordering::Relaxed);
                recorded_wait = true;
            }
            match deadline {
                Some(deadline) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        drop(guard);
                        self.wait_nanos.fetch_add(
                            started.elapsed().as_nanos().min(u64::MAX as u128) as u64,
                            Ordering::Relaxed,
                        );
                        return Err(BudgetError::Timeout);
                    }
                    let (guard, result) = self
                        .changed
                        .wait_timeout(guard, remaining)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    drop(guard);
                    if result.timed_out() && Instant::now() >= deadline {
                        self.wait_nanos.fetch_add(
                            started.elapsed().as_nanos().min(u64::MAX as u128) as u64,
                            Ordering::Relaxed,
                        );
                        return Err(BudgetError::Timeout);
                    }
                }
                None => {
                    let guard = self
                        .changed
                        .wait(guard)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    drop(guard);
                }
            }
        }
    }

    /// Waits until at least `amount` units are available without reserving
    /// them. Callers must still acquire atomically after waking and retry if a
    /// competing consumer wins the race.
    pub fn wait_for_available(
        &self,
        amount: i64,
        timeout: Option<Duration>,
    ) -> Result<(), BudgetError> {
        if !self.fits(amount) {
            return Err(BudgetError::Limit);
        }
        let started = Instant::now();
        let deadline = timeout.and_then(|duration| started.checked_add(duration));
        let mut recorded_wait = false;
        loop {
            let guard = self
                .wait_lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if self.available() >= amount {
                drop(guard);
                if recorded_wait {
                    self.wait_nanos.fetch_add(
                        started.elapsed().as_nanos().min(u64::MAX as u128) as u64,
                        Ordering::Relaxed,
                    );
                }
                return Ok(());
            }
            if !recorded_wait {
                self.waits.fetch_add(1, Ordering::Relaxed);
                recorded_wait = true;
            }
            match deadline {
                Some(deadline) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        drop(guard);
                        self.wait_nanos.fetch_add(
                            started.elapsed().as_nanos().min(u64::MAX as u128) as u64,
                            Ordering::Relaxed,
                        );
                        return Err(BudgetError::Timeout);
                    }
                    let (guard, result) = self
                        .changed
                        .wait_timeout(guard, remaining)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    drop(guard);
                    if result.timed_out() && Instant::now() >= deadline {
                        self.wait_nanos.fetch_add(
                            started.elapsed().as_nanos().min(u64::MAX as u128) as u64,
                            Ordering::Relaxed,
                        );
                        return Err(BudgetError::Timeout);
                    }
                }
                None => {
                    let guard = self
                        .changed
                        .wait(guard)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    drop(guard);
                }
            }
        }
    }

    fn keep(&self) -> i64 {
        self.parent_keep.as_ref().map(|f| f().max(0)).unwrap_or(0)
    }

    fn fits(&self, amount: i64) -> bool {
        if amount < 0 || amount > self.limit() {
            return false;
        }
        match &self.parent {
            Some(parent) => parent.fits_with_keep(amount, self.keep()),
            None => true,
        }
    }

    fn fits_with_keep(&self, amount: i64, keep: i64) -> bool {
        if amount < 0 || amount > self.limit().saturating_sub(keep.max(0)) {
            return false;
        }
        match &self.parent {
            Some(parent) => parent.fits_with_keep(amount, self.keep()),
            None => true,
        }
    }

    fn try_reserve(&self, amount: i64) -> bool {
        if amount < 0 || !self.try_local(amount, 0) {
            return false;
        }
        if let Some(parent) = &self.parent {
            if !parent.try_keep_chain(amount, self.keep()) {
                // This is a private rollback, not a release by the owner.
                self.release_local(amount, false);
                return false;
            }
        }
        true
    }

    fn try_keep_chain(&self, amount: i64, keep: i64) -> bool {
        if amount < 0 || !self.try_local(amount, keep) {
            return false;
        }
        if let Some(parent) = &self.parent {
            if !parent.try_keep_chain(amount, self.keep()) {
                self.release_local(amount, false);
                return false;
            }
        }
        true
    }

    fn try_local(&self, amount: i64, keep: i64) -> bool {
        if amount < 0 || keep < 0 {
            return false;
        }
        loop {
            let used = self.used.load(Ordering::Acquire);
            let room = self
                .limit
                .load(Ordering::Acquire)
                .saturating_sub(used)
                .saturating_sub(keep);
            if amount > room {
                return false;
            }
            let Some(next) = used.checked_add(amount) else {
                return false;
            };
            if self
                .used
                .compare_exchange_weak(used, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return true;
            }
        }
    }

    fn release_local(&self, amount: i64, notify: bool) {
        let mut overrelease = None;
        loop {
            let used = self.used.load(Ordering::Acquire);
            let next = used.saturating_sub(amount).max(0);
            if self
                .used
                .compare_exchange_weak(used, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                if amount > used {
                    self.overreleases.fetch_add(1, Ordering::Relaxed);
                    UNBALANCED_RELEASES.fetch_add(1, Ordering::Relaxed);
                    overrelease = Some(used);
                }
                break;
            }
        }
        if let Some(held) = overrelease {
            crate::slog::error(
                "unbalanced resource release",
                &[("held", held.into()), ("released", amount.into())],
            );
        }
        if notify {
            self.notify_waiters();
        }
    }

    fn notify_waiters(&self) {
        {
            let _guard = self
                .wait_lock
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.changed.notify_all();
        }
        let children = {
            let mut children = self
                .children
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let live: Vec<_> = children.iter().filter_map(Weak::upgrade).collect();
            children.retain(|child| child.strong_count() > 0);
            live
        };
        for child in children {
            child.notify_waiters();
        }
    }
}

/// RAII hold returned by `Budget::try_acquire` / `acquire_timeout`.
pub struct BudgetLease {
    budget: Option<Arc<Budget>>,
    amount: i64,
}
impl fmt::Debug for BudgetLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BudgetLease")
            .field("amount", &self.amount)
            .field("active", &self.budget.is_some())
            .finish()
    }
}
impl BudgetLease {
    pub fn amount(&self) -> i64 {
        self.amount
    }

    /// Returns at most `amount` units while keeping the remaining reservation
    /// attached to this lease. Dropping the lease releases only its remainder.
    pub fn release_part(&mut self, amount: i64) -> i64 {
        let released = amount.max(0).min(self.amount);
        if released == 0 {
            return 0;
        }
        if let Some(budget) = self.budget.as_ref() {
            budget.put(released);
        }
        self.amount -= released;
        if self.amount == 0 {
            self.budget.take();
        }
        released
    }

    pub fn release(mut self) {
        if let Some(budget) = self.budget.take() {
            budget.put(self.amount);
        }
    }
}
impl Drop for BudgetLease {
    fn drop(&mut self) {
        if let Some(budget) = self.budget.take() {
            budget.put(self.amount);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::thread;

    #[test]
    fn overrelease_clamps_counts_and_budget_remains_usable() {
        let b = Budget::new(100);
        assert!(b.try_take(10));
        let before = unbalanced_releases();
        b.put(30);
        assert_eq!(b.used(), 0);
        assert_eq!(b.overreleases(), 1);
        assert_eq!(unbalanced_releases(), before + 1);
        assert!(b.try_take(100));
    }

    #[test]
    fn lowered_limit_does_not_revoke_existing_holds_and_lease_drops_once() {
        let b = Budget::new(20);
        let lease = b.try_acquire(15).unwrap();
        b.set_limit(5);
        assert_eq!(b.used(), 15);
        assert_eq!(b.available(), 0);
        assert!(b.try_acquire(1).is_none());
        drop(lease);
        assert_eq!(b.used(), 0);
        assert_eq!(b.limit(), 5);
        assert!(b.try_acquire(5).is_some());
    }

    #[test]
    fn lease_can_release_partial_amount_and_drop_only_its_remainder() {
        let budget = Budget::new(20);
        let mut lease = budget.try_acquire(10).unwrap();
        assert_eq!(lease.amount(), 10);
        assert_eq!(lease.release_part(3), 3);
        assert_eq!(lease.amount(), 7);
        assert_eq!(budget.used(), 7);
        assert_eq!(lease.release_part(20), 7);
        assert_eq!(lease.release_part(1), 0);
        assert_eq!(budget.used(), 0);
        drop(lease);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn share_charges_parent_and_preserves_keep() {
        let parent = Budget::new(100);
        let keep = Arc::new(AtomicI64::new(30));
        let share = Budget::new_share(parent.clone(), 80, {
            let keep = keep.clone();
            move || keep.load(Ordering::Acquire)
        });
        assert!(share.try_take(70));
        assert_eq!(share.used(), 70);
        assert_eq!(parent.used(), 70);
        assert!(!share.try_take(1));
        share.put(70);
        assert_eq!(parent.used(), 0);
        keep.store(0, Ordering::Release);
        assert!(share.try_take(80));
        assert_eq!(parent.used(), 80);
    }

    #[test]
    fn parent_release_wakes_waiting_share_and_timeout_is_reported() {
        let parent = Budget::new(10);
        assert!(parent.try_take(10));
        let share = Budget::new_share(parent.clone(), 10, || 0);
        let waiting = share.clone();
        let waiter =
            thread::spawn(move || waiting.acquire_timeout(5, Some(Duration::from_secs(1))));
        thread::sleep(Duration::from_millis(20));
        parent.put(5);
        let held = waiter.join().unwrap().unwrap();
        assert_eq!(share.used(), 5);
        drop(held);
        assert_eq!(parent.used(), 5);
        assert!(matches!(
            share.acquire_timeout(11, Some(Duration::ZERO)),
            Err(BudgetError::Limit)
        ));
    }

    #[test]
    fn availability_wait_wakes_on_parent_release_without_reserving_units() {
        let parent = Budget::new(10);
        assert!(parent.try_take(10));
        let share = Budget::new_share(parent.clone(), 10, || 0);
        let waiting = share.clone();
        let waiter =
            thread::spawn(move || waiting.wait_for_available(5, Some(Duration::from_secs(1))));
        let deadline = Instant::now() + Duration::from_secs(1);
        while share.wait_stats().0 == 0 && Instant::now() < deadline {
            thread::yield_now();
        }
        assert_eq!(share.wait_stats().0, 1);
        parent.put(5);
        waiter.join().unwrap().unwrap();
        assert_eq!(share.used(), 0, "availability wait does not acquire");
        assert_eq!(parent.used(), 5);
        let (waits, elapsed) = share.wait_stats();
        assert_eq!(waits, 1);
        assert!(!elapsed.is_zero());
        assert_eq!(
            share.wait_for_available(11, Some(Duration::ZERO)),
            Err(BudgetError::Limit)
        );
    }

    #[test]
    fn local_wait_times_out_without_leaking_units() {
        let b = Budget::new(1);
        assert!(b.try_take(1));
        assert_eq!(
            b.acquire_timeout(1, Some(Duration::from_millis(1)))
                .unwrap_err(),
            BudgetError::Timeout
        );
        assert_eq!(b.used(), 1);
        assert_eq!(b.wait_stats().0, 1);
    }
}
