use super::serve::{AcceptSource, ACCEPT_FATAL_AFTER};
use super::spec_precheck_tests::{fixture, Fixture};
use super::*;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn spec_health_threshold_affects_actual_choice() {
    let f: Fixture = fixture("http-sse", |_, _| {});
    assert_eq!(f.peer.failover.healthy_threshold, 2, "fixture default");
    let threshold = f.peer.failover.unhealthy_threshold;
    for _ in 0..threshold {
        f.ingress.endpoints.record_probe_failure(
            "B",
            "e",
            Duration::from_secs(5),
            threshold,
            false,
        );
    }
    assert_eq!(f.state(), "UNHEALTHY", "fixture: two failures");
    // A fresh past-cooldown state.
    {
        let mut g = f.ingress.endpoints.inner.lock().unwrap();
        let h = g.get_mut(&("B".to_string(), "e".to_string())).unwrap();
        h.cooldown_until = Instant::now().checked_sub(Duration::from_secs(1));
    }
    let before = f.probes.load(Ordering::SeqCst);
    let got = f.ingress.select_endpoint(&f.peer);
    assert_eq!(f.probes.load(Ordering::SeqCst), before + 1, "no probe made");
    assert!(
        !(got.is_ok() && f.state() == "UNHEALTHY"),
        "actual scheduler selected UNHEALTHY endpoint after one success (required={})",
        f.peer.failover.healthy_threshold
    );
    assert!(
        got.is_err(),
        "UNHEALTHY endpoint selected: {:?}",
        got.map(|g| g.0.id)
    );
    // The second consecutive success ends UNHEALTHY and the endpoint is a
    // candidate again.
    let (ep, _) = f
        .ingress
        .select_endpoint(&f.peer)
        .expect("endpoint not selected after healthy_threshold probes");
    assert_eq!((ep.id.as_str(), f.state()), ("e", "HEALTHY"));
}

struct FlakyListener {
    raw: TcpListener,
    calls: AtomicUsize,
    errs: Vec<fn() -> std::io::Error>,
}

impl AcceptSource for FlakyListener {
    fn accept_conn(&self) -> std::io::Result<(TcpStream, std::net::SocketAddr)> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(make) = self.errs.get(n) {
            return Err(make());
        }
        self.raw.accept()
    }
}

fn emfile() -> std::io::Error {
    std::io::Error::from_raw_os_error(24)
}

fn conn_aborted() -> std::io::Error {
    std::io::Error::from(std::io::ErrorKind::ConnectionAborted)
}

fn permanent() -> std::io::Error {
    std::io::Error::other("accept: permanent failure")
}

fn accept_fixture() -> (Arc<Ingress>, crate::config::Listener) {
    let Fixture { ingress, .. } = fixture("http-sse", |_, _| {});
    let listener = ingress.cfg.listeners[0].clone();
    (Arc::new(ingress), listener)
}

#[test]
fn spec_accept_loop_survives_transient_errors() {
    let (ingress, listener) = accept_fixture();
    let raw = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = raw.local_addr().unwrap();
    let fl = Arc::new(FlakyListener {
        raw,
        calls: AtomicUsize::new(0),
        errs: vec![emfile, emfile, conn_aborted],
    });
    let stop = Arc::new(AtomicBool::new(false));
    let loop_thread = {
        let (ingress, fl, stop) = (ingress.clone(), fl.clone(), stop.clone());
        std::thread::spawn(move || {
            let stopped = || stop.load(Ordering::SeqCst);
            ingress.accept_loop(&*fl, &listener, &stopped, Duration::from_secs(1));
        })
    };
    let _c = TcpStream::connect(addr).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while ingress.count() == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        ingress.count() > 0,
        "connection not accepted after transient errors (accept calls={})",
        fl.calls.load(Ordering::SeqCst)
    );
    assert!(
        fl.calls.load(Ordering::SeqCst) > 3,
        "transient errors ended the loop"
    );
    stop.store(true, Ordering::SeqCst);
    let _wake = TcpStream::connect(addr);
    let deadline = Instant::now() + Duration::from_secs(2);
    while !loop_thread.is_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        loop_thread.is_finished(),
        "accept loop did not return after its listener was stopped"
    );
    ingress.request_shutdown();
}

#[test]
fn spec_accept_loop_reports_permanent_failure() {
    let (ingress, listener) = accept_fixture();
    let raw = TcpListener::bind("127.0.0.1:0").unwrap();
    let fl = Arc::new(FlakyListener {
        raw,
        calls: AtomicUsize::new(0),
        errs: vec![permanent as fn() -> std::io::Error; ACCEPT_FATAL_AFTER as usize],
    });
    let (tx, rx) = std::sync::mpsc::channel();
    let tx = Mutex::new(tx);
    ingress.set_fatal_handler(Arc::new(move |e: Error| {
        let _ = tx.lock().unwrap().send(e);
    }));
    let loop_thread = {
        let (ingress, fl) = (ingress.clone(), fl.clone());
        std::thread::spawn(move || {
            ingress.accept_loop(&*fl, &listener, &|| false, Duration::from_millis(10));
        })
    };
    let e = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("permanent accept failure was never reported");
    assert!(
        e.message.contains("accept keeps failing"),
        "fatal error: {e:?}"
    );
    loop_thread.join().unwrap();
    assert_eq!(
        fl.calls.load(Ordering::SeqCst),
        ACCEPT_FATAL_AFTER as usize,
        "the loop kept accepting after reporting the listener dead"
    );
}
