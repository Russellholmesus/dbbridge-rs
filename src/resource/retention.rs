use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// One recovery cycle's participation in a shared retained-byte quota.
pub struct RetentionLease {
    active: AtomicBool,
    started: Instant,
    size: Box<dyn Fn() -> i64 + Send + Sync>,
    evict: Box<dyn Fn(&RetentionLease) + Send + Sync>,
}
impl RetentionLease {
    #[cfg(test)]
    pub fn new(
        started: Instant,
        size: impl Fn() -> i64 + Send + Sync + 'static,
        evict: impl Fn() + Send + Sync + 'static,
    ) -> Arc<Self> {
        Self::new_validated(started, size, move |_| evict())
    }

    /// Variant for lifecycle owners that must validate this exact lease at the
    /// terminal gate before acting on a possibly late eviction callback.
    pub fn new_validated(
        started: Instant,
        size: impl Fn() -> i64 + Send + Sync + 'static,
        evict: impl Fn(&RetentionLease) + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            active: AtomicBool::new(true),
            started,
            size: Box::new(size),
            evict: Box::new(evict),
        })
    }

    pub fn end(&self) {
        self.active.store(false, Ordering::Release);
    }
    pub fn active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }
    fn size(&self) -> i64 {
        (self.size)()
    }
    fn evict(&self) {
        (self.evict)(self)
    }
}

/// Process-wide retention quota shared by recovery cycles.
pub struct Retention {
    limit: AtomicI64,
    leases: Mutex<Vec<Arc<RetentionLease>>>,
}
impl Retention {
    pub fn new(limit: i64) -> Self {
        Self {
            limit: AtomicI64::new(limit),
            leases: Mutex::new(Vec::new()),
        }
    }

    pub fn register(&self, lease: Option<Arc<RetentionLease>>) {
        let Some(lease) = lease else { return };
        {
            let mut leases = self
                .leases
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if lease.active()
                && !leases
                    .iter()
                    .any(|registered| Arc::ptr_eq(registered, &lease))
            {
                leases.push(lease);
            }
        }
        self.enforce_used();
    }

    /// Ends and removes one lease without running a quota sweep. Lifecycle
    /// owners call this after leaving their own state lock.
    pub fn remove_lease(&self, lease: &Arc<RetentionLease>) -> bool {
        lease.end();
        let mut leases = self
            .leases
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = leases.len();
        leases.retain(|registered| !Arc::ptr_eq(registered, lease));
        leases.len() != before
    }

    pub fn limit(&self) -> i64 {
        self.limit.load(Ordering::Acquire)
    }

    pub fn used(&self) -> i64 {
        let leases = self
            .leases
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        leases
            .iter()
            .filter(|lease| lease.active())
            .map(|lease| lease.size().max(0))
            .fold(0i64, i64::saturating_add)
    }

    #[cfg(test)]
    pub fn enforce(&self) -> i64 {
        self.enforce_used()
    }

    /// Removes ended leases, then evicts oldest active leases that currently
    /// retain bytes until the positive limit is met. Callbacks run after unlock.
    pub fn enforce_used(&self) -> i64 {
        struct SizedLease {
            lease: Arc<RetentionLease>,
            size: i64,
            ordinal: usize,
        }
        let mut callbacks = Vec::new();
        let total_after;
        {
            let mut leases = self
                .leases
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            leases.retain(|lease| lease.active());
            let mut live: Vec<_> = leases
                .iter()
                .enumerate()
                .map(|(ordinal, lease)| SizedLease {
                    lease: lease.clone(),
                    size: lease.size().max(0),
                    ordinal,
                })
                .collect();
            let mut total = live
                .iter()
                .map(|entry| entry.size)
                .fold(0i64, i64::saturating_add);
            let limit = self.limit();
            if limit > 0 && total > limit {
                live.sort_by(|a, b| {
                    a.lease
                        .started
                        .cmp(&b.lease.started)
                        .then_with(|| a.ordinal.cmp(&b.ordinal))
                });
                for entry in live {
                    if total <= limit {
                        break;
                    }
                    if entry.size <= 0 {
                        continue;
                    }
                    total = total.saturating_sub(entry.size);
                    if let Some(index) = leases
                        .iter()
                        .position(|registered| Arc::ptr_eq(registered, &entry.lease))
                    {
                        leases.remove(index);
                        callbacks.push(entry.lease);
                    }
                }
            }
            total_after = total;
        }
        for lease in callbacks {
            lease.evict();
        }
        total_after
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn shared_quota_evicts_oldest_nonempty_lease() {
        let retention = Retention::new(200);
        let first_size = Arc::new(AtomicI64::new(150));
        let second_size = Arc::new(AtomicI64::new(150));
        let first_slot = Arc::new(Mutex::new(None::<Arc<RetentionLease>>));
        let first_evicted_size = first_size.clone();
        let first_slot_cb = first_slot.clone();
        let first = RetentionLease::new(
            Instant::now() - Duration::from_secs(1),
            {
                let size = first_size.clone();
                move || size.load(Ordering::Acquire)
            },
            move || {
                if let Some(lease) = first_slot_cb.lock().unwrap().as_ref() {
                    lease.end();
                }
                first_evicted_size.store(0, Ordering::Release);
            },
        );
        *first_slot.lock().unwrap() = Some(first.clone());
        let second_slot = Arc::new(Mutex::new(None::<Arc<RetentionLease>>));
        let second_slot_cb = second_slot.clone();
        let second = RetentionLease::new(
            Instant::now(),
            {
                let size = second_size.clone();
                move || size.load(Ordering::Acquire)
            },
            move || {
                if let Some(lease) = second_slot_cb.lock().unwrap().as_ref() {
                    lease.end();
                }
            },
        );
        *second_slot.lock().unwrap() = Some(second.clone());
        retention.register(Some(first.clone()));
        retention.register(Some(second.clone()));
        assert!(!first.active());
        assert!(second.active());
        assert_eq!(retention.used(), 150);
        second.end();
        assert_eq!(retention.enforce(), 0);
    }

    #[test]
    fn remove_lease_ends_and_unregisters_without_eviction() {
        let retention = Retention::new(10);
        let evictions = Arc::new(AtomicUsize::new(0));
        let eviction_count = evictions.clone();
        let lease = RetentionLease::new(
            Instant::now(),
            || 10,
            move || {
                eviction_count.fetch_add(1, Ordering::Relaxed);
            },
        );
        retention.register(Some(lease.clone()));
        assert_eq!(retention.used(), 10);
        assert!(retention.remove_lease(&lease));
        assert!(!lease.active());
        assert_eq!(retention.used(), 0);
        assert_eq!(evictions.load(Ordering::Relaxed), 0);
        assert!(!retention.remove_lease(&lease));
    }

    #[test]
    fn empty_and_ended_leases_are_not_evicted_or_reregistered() {
        let retention = Retention::new(1);
        let empty_evictions = Arc::new(AtomicUsize::new(0));
        let empty_count = empty_evictions.clone();
        let empty = RetentionLease::new(
            Instant::now(),
            || 0,
            move || {
                empty_count.fetch_add(1, Ordering::Relaxed);
            },
        );
        let ended_evictions = Arc::new(AtomicUsize::new(0));
        let ended_count = ended_evictions.clone();
        let ended = RetentionLease::new(
            Instant::now(),
            || 100,
            move || {
                ended_count.fetch_add(1, Ordering::Relaxed);
            },
        );
        ended.end();
        retention.register(Some(empty.clone()));
        retention.register(Some(ended));
        assert!(empty.active());
        assert_eq!(ended_evictions.load(Ordering::Relaxed), 0);
        assert_eq!(retention.used(), 0);
    }

    #[test]
    fn eviction_callback_runs_outside_retention_lock() {
        let retention = Arc::new(Retention::new(1));
        let (tx, rx) = mpsc::channel();
        let retention_in_callback = retention.clone();
        let lease = RetentionLease::new(
            Instant::now(),
            || 2,
            move || {
                let tx = tx.clone();
                let retention = retention_in_callback.clone();
                thread::spawn(move || tx.send(retention.used()).unwrap());
            },
        );
        retention.register(Some(lease));
        assert_eq!(rx.recv_timeout(Duration::from_millis(200)).unwrap(), 0);
    }
}
