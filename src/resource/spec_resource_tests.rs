use super::retention::{Retention, RetentionLease};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[test]
fn spec_zero_sized_lease_not_evicted() {
    let r = Retention::new(100);
    let a_evicted = Arc::new(AtomicBool::new(false));
    let b_evicted = Arc::new(AtomicBool::new(false));
    let (ae, be) = (a_evicted.clone(), b_evicted.clone());
    let a = RetentionLease::new_validated(
        Instant::now() - Duration::from_secs(1),
        || 0,
        move |l| {
            ae.store(true, Ordering::SeqCst);
            l.end();
        },
    );
    let b = RetentionLease::new_validated(
        Instant::now(),
        || 150,
        move |l| {
            be.store(true, Ordering::SeqCst);
            l.end();
        },
    );
    r.register(Some(a));
    r.register(Some(b));
    assert!(
        !a_evicted.load(Ordering::SeqCst) && b_evicted.load(Ordering::SeqCst),
        "evicted zero={} big={}",
        a_evicted.load(Ordering::SeqCst),
        b_evicted.load(Ordering::SeqCst)
    );
    assert_eq!(r.enforce_used(), 0);
}

#[test]
fn spec_enforce_used_fast_path() {
    let r = Retention::new(1000);
    assert_eq!(r.enforce_used(), 0);
    assert_eq!(r.used(), 0);
    let calls = Arc::new(AtomicI64::new(0));
    let c = calls.clone();
    let l = RetentionLease::new(
        Instant::now(),
        move || {
            c.fetch_add(1, Ordering::SeqCst);
            40
        },
        || {},
    );
    r.register(Some(l.clone()));
    assert_eq!(r.enforce_used(), 40);
    l.end();
    r.enforce();
    calls.store(0, Ordering::SeqCst);
    for _ in 0..100 {
        r.enforce_used();
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0, "ended lease still swept");
}

use super::budget::{Budget, BudgetError};

#[test]
fn spec_share_is_bounded_by_its_limit_and_parent() {
    let parent = Budget::new(100);
    let a = Budget::new_share(parent.clone(), 60, || 0);
    let b = Budget::new_share(parent.clone(), 60, || 0);
    assert!(a.try_take(60) && !a.try_take(1), "share limit not applied");
    assert!(
        !b.try_take(41) && b.try_take(40),
        "parent limit not applied"
    );
    assert_eq!((parent.used(), a.used(), b.used()), (100, 60, 40));
    a.put(60);
    b.put(40);
    assert_eq!(
        (parent.used(), a.used(), b.used()),
        (0, 0, 0),
        "release did not reach both budgets"
    );
}

#[test]
fn spec_share_leaves_parent_reserve() {
    let parent = Budget::new(100);
    let s = Budget::new_share(parent.clone(), 100, || 25);
    assert!(
        !s.try_take(76) && s.try_take(75),
        "share took the parent reserve"
    );
    assert!(
        parent.try_take(25),
        "direct parent user cannot use the reserve"
    );
    parent.put(25);
    assert!(
        !s.try_take(1),
        "TryKeep on a share ignored the parent reserve"
    );
    assert_eq!(
        s.acquire_timeout(76, None).unwrap_err(),
        BudgetError::Limit,
        "Take beyond the reserve"
    );
}

#[test]
fn spec_set_limit_lowers_and_raises_share() {
    let parent = Budget::new(100);
    let s = Budget::new_share(parent, 10, || 0);
    assert!(s.try_take(10), "setup");
    s.set_limit(5);
    s.put(10);
    assert!(!s.try_take(6) && s.try_take(5), "lowered limit not applied");
    s.set_limit(50);
    assert!(s.try_take(45), "raised limit not applied");
}

#[test]
fn spec_put_wakes_only_waiters() {
    let b = Budget::new(1);
    assert!(b.try_take(1));
    b.put(1);
    assert_eq!(b.wait_stats().0, 0, "uncontended Put registered a waiter");
    assert!(b.try_take(1));
    let waiter = {
        let b = b.clone();
        std::thread::spawn(move || b.acquire_timeout(1, Some(Duration::from_secs(5))))
    };
    let until = Instant::now() + Duration::from_secs(1);
    while b.wait_stats().0 != 1 {
        assert!(Instant::now() < until, "waiter never blocked");
        std::thread::sleep(Duration::from_millis(1));
    }
    b.put(1);
    let lease = waiter.join().unwrap().expect("waiter not woken");
    assert_eq!(b.used(), 1, "take after wake-up did not hold the unit");
    assert_eq!(b.wait_stats().0, 1, "more than one wait recorded");
    drop(lease);
    assert_eq!(b.used(), 0);
}
