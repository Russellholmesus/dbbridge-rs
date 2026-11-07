use super::*;

#[test]
fn spec_precheck_rate_burst_and_idempotent_release() {
    let q = ProbeBudget::new();
    let now = Instant::now();
    for i in 0..4 {
        let permit = q
            .try_acquire_precheck_at("peer", 1, now)
            .unwrap_or_else(|e| panic!("request {i} rejected inside burst: {e}"));
        drop(permit);
    }
    assert!(
        q.try_acquire_precheck_at("peer", 1, now).is_err(),
        "unbounded rate after releasing connections"
    );
    let permit = q
        .try_acquire_precheck_at("peer", 1, now + Duration::from_millis(250))
        .expect("rate allowance did not refill");
    drop(permit);
    assert!(
        q.precheck_active.lock().unwrap().get("peer").is_none(),
        "duplicate release corrupted concurrency accounting"
    );
}

#[test]
fn spec_precheck_concurrent_admission() {
    let q = std::sync::Arc::new(ProbeBudget::new());
    let now = Instant::now();
    let admitted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let held = std::sync::Arc::new(std::sync::Barrier::new(25));
    let release = std::sync::Arc::new(std::sync::Barrier::new(25));
    let threads: Vec<_> = (0..24)
        .map(|_| {
            let (q, admitted, held, release) =
                (q.clone(), admitted.clone(), held.clone(), release.clone());
            std::thread::spawn(move || {
                let permit = q.try_acquire_precheck_at("peer", 1, now).ok();
                if permit.is_some() {
                    admitted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                held.wait();
                release.wait();
                drop(permit);
            })
        })
        .collect();
    held.wait();
    assert_eq!(admitted.load(std::sync::atomic::Ordering::SeqCst), 2);
    release.wait();
    for t in threads {
        t.join().unwrap();
    }
}
