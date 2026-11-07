use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::{Admin, Config, Http, Limits, Node, Reverse, Transport};
use crate::error::{Error, Result};
use crate::net::{BufferedConn, Conn};
use crate::session::Session;
use crate::transport::sse_carrier::SseEventSink;
use crate::transport::sse_progress::{write_sse_progress, SsePieceSink};
use crate::transport::{CarrierWriter, SharedWriter};
use crate::wire::{Control, ControlKind, Limits as WireLimits, Mode};

use super::pump::run_downstream;

fn config() -> Config {
    Config {
        path: PathBuf::new(),
        node: Node {
            id: "B".to_string(),
            instance_id: "instance".to_string(),
        },
        http: Http {
            enabled: false,
            listen: "127.0.0.1:0".to_string(),
            allowed_transports: vec![Mode::Ws, Mode::HttpSse],
            tls: crate::config::HttpTls::default(),
        },
        admin: Admin {
            enabled: false,
            listen: "127.0.0.1:0".to_string(),
        },
        peers: Vec::new(),
        listeners: Vec::new(),
        targets: Vec::new(),
        inbound: Vec::new(),
        warnings: Vec::new(),
        auth_reload_interval: Duration::from_secs(5),
        transport: Transport::default(),
        limits: Limits {
            max_sessions: 8,
            max_endpoints_per_peer: 16,
        },
        reverse: Reverse::default(),
    }
}

/// A connected loopback pair: (session backend, database side).
fn backend_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (backend, _) = listener.accept().unwrap();
    (backend, peer)
}

fn session(
    id: &str,
    owner: &str,
    mode: Mode,
    limits: WireLimits,
    backend: TcpStream,
) -> Arc<Session> {
    Session::new(
        id.to_string(),
        "token".to_string(),
        "instance".to_string(),
        owner.to_string(),
        "db".to_string(),
        mode,
        limits,
        8,
        backend,
        Arc::new(crate::metrics::Metrics::new()),
    )
}

type DataHook = Box<dyn FnMut(u64, &[u8]) -> Result<()> + Send>;

/// Records every control and hands each data frame to `hook`.
struct HookWriter {
    controls: Arc<Mutex<Vec<Control>>>,
    hook: DataHook,
}

impl CarrierWriter for HookWriter {
    fn send_data(&mut self, _epoch: u64, offset: u64, payload: &[u8]) -> Result<Option<u64>> {
        (self.hook)(offset, payload)?;
        Ok(None)
    }

    fn send_control(&mut self, control: &Control) -> Result<()> {
        self.controls.lock().unwrap().push(control.clone());
        Ok(())
    }

    fn shutdown(&mut self) {}
}

fn hook_writer(hook: DataHook) -> (SharedWriter, Arc<Mutex<Vec<Control>>>) {
    let controls = Arc::new(Mutex::new(Vec::new()));
    let writer = SharedWriter::new(Box::new(HookWriter {
        controls: controls.clone(),
        hook,
    }));
    (writer, controls)
}

#[test]
fn spec_downstream_adaptive_frames() {
    let mut cfg = config();
    cfg.transport.frame_size = 32 << 10;
    let (backend, mut peer) = backend_pair();
    let s = session(
        "s_adaptive",
        "A",
        Mode::Ws,
        WireLimits {
            max_frame_size: 256 << 10,
            up_max_inflight_frames: 8,
            up_window_bytes: 2 << 20,
            down_buffer_bytes: 4 << 20,
            up_receipt_limit: 64,
            down_max_frames: 1024,
        },
        backend,
    );
    s.attach("stream").unwrap();
    let sizes = Arc::new(Mutex::new(Vec::<usize>::new()));
    let seen = sizes.clone();
    let (writer, _) = hook_writer(Box::new(move |_, payload| {
        seen.lock().unwrap().push(payload.len());
        Ok(())
    }));
    let pump_session = s.clone();
    let pump_cfg = cfg.clone();
    let pump = std::thread::spawn(move || run_downstream(&pump_cfg, pump_session, writer, None));
    std::thread::spawn(move || {
        let _ = peer.write_all(&vec![0u8; 1 << 20]);
        std::thread::sleep(Duration::from_secs(3));
    });
    let until = Instant::now() + Duration::from_secs(1);
    while s.snapshot().down_produced < 1 << 20 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(
        s.snapshot().down_produced,
        1 << 20,
        "backend read incomplete"
    );
    let frames = s.replay_down_frames();
    let mut off = 0u64;
    let mut max_size = 0usize;
    for (offset, payload) in &frames {
        assert_eq!(*offset, off, "missing frame");
        assert!(!payload.is_empty(), "missing frame");
        max_size = max_size.max(payload.len());
        off += payload.len() as u64;
    }
    assert_eq!(off, 1 << 20, "frames do not cover the produced bytes");
    let emitted_max = sizes.lock().unwrap().iter().copied().max().unwrap_or(0);
    eprintln!(
        "continuous 1 MiB write -> frames={} max_frame={max_size} emitted_max={emitted_max} negotiated_max={}",
        frames.len(),
        s.limits.max_frame_size
    );
    s.close(Error::local("test complete"));
    let _ = pump.join().unwrap();
    assert!(
        max_size > 32 << 10 && emitted_max > 32 << 10,
        "downstream never increased frame size under continuous full reads"
    );
    assert!(max_size <= 256 << 10, "frame above the negotiated maximum");
}

#[derive(Default)]
struct FlushCounter {
    flushes: usize,
    written: usize,
}

impl SsePieceSink for FlushCounter {
    fn arm_idle_deadline(&mut self, _idle: Duration) -> Result<()> {
        Ok(())
    }
    fn write_piece(&mut self, piece: &[u8]) -> Result<()> {
        self.written += piece.len();
        Ok(())
    }
    fn flush_piece(&mut self) -> Result<()> {
        self.flushes += 1;
        Ok(())
    }
}

#[test]
fn spec_sse_adaptive_pieces() {
    let mut w = FlushCounter::default();
    let event = format!("event: data\ndata: {}\n\n", "x".repeat(1 << 20));
    write_sse_progress(&mut w, event.as_bytes(), Duration::from_secs(60)).unwrap();
    assert_eq!(w.written, event.len());
    assert!(w.flushes <= 64, "{} flushes for a 1 MiB event", w.flushes);
}

struct SlowConn {
    inner: TcpStream,
    slow: Arc<AtomicBool>,
    deadline: Mutex<Option<Instant>>,
}

impl Read for SlowConn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for SlowConn {
    fn write(&mut self, p: &[u8]) -> std::io::Result<usize> {
        let deadline = *self.deadline.lock().unwrap();
        let expired = || deadline.is_some_and(|d| Instant::now() >= d);
        if !self.slow.load(Ordering::SeqCst) {
            return self.inner.write(p);
        }
        let mut total = 0;
        for chunk in p.chunks(512) {
            if expired() {
                if total > 0 {
                    return Ok(total);
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "i/o timeout",
                ));
            }
            self.inner.write_all(chunk)?;
            total += chunk.len();
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(total)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl Conn for SlowConn {
    fn set_read_timeout(&self, d: Option<Duration>) -> std::io::Result<()> {
        self.inner.set_read_timeout(d)
    }
    fn set_write_timeout(&self, d: Option<Duration>) -> std::io::Result<()> {
        *self.deadline.lock().unwrap() = d.map(|d| Instant::now() + d);
        Ok(())
    }
    fn try_clone(&self) -> std::io::Result<Box<dyn Conn>> {
        Ok(Box::new(self.inner.try_clone()?))
    }
    fn shutdown_write(&self) -> std::io::Result<()> {
        self.inner.shutdown(std::net::Shutdown::Write)
    }
    fn shutdown_both(&self) -> std::io::Result<()> {
        self.inner.shutdown(std::net::Shutdown::Both)
    }
    fn describe(&self) -> String {
        "slow".to_string()
    }
}

#[test]
fn spec_sse_write_idle_progress_http1() {
    let event = format!("event: data\ndata: {}\n\n", "x".repeat(32 << 10));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    let reader = std::thread::spawn(move || {
        let mut client = client;
        client
            .set_read_timeout(Some(Duration::from_secs(4)))
            .unwrap();
        let mut got = Vec::new();
        let _ = client.read_to_end(&mut got);
        got
    });
    let slow = Arc::new(AtomicBool::new(true));
    let mut sink = SseEventSink::new(
        BufferedConn::new(SlowConn {
            inner: server,
            slow: slow.clone(),
            deadline: Mutex::new(None),
        }),
        Duration::from_millis(80),
    );
    let started = Instant::now();
    let result = sink.write_raw(event.as_bytes());
    let elapsed = started.elapsed();
    sink.shutdown();
    drop(sink);
    let got = reader.join().unwrap();
    assert!(
        result.is_ok() && got == event.as_bytes(),
        "received={} expected={} error={:?}",
        got.len(),
        event.len(),
        result.err()
    );
    assert!(
        elapsed > Duration::from_millis(80),
        "the fixture link was not slow: {elapsed:?}"
    );

    // Control: one deadline for the whole event does time out.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    let mut conn = SlowConn {
        inner: server,
        slow,
        deadline: Mutex::new(None),
    };
    conn.set_write_timeout(Some(Duration::from_millis(80)))
        .unwrap();
    let whole = conn.write_all(event.as_bytes());
    drop(client);
    assert!(
        whole.is_err(),
        "single-deadline write of the event did not time out"
    );
}

#[cfg(feature = "h2")]
#[test]
fn spec_sse_write_idle_progress_http2() {
    use super::h2::H2SseWriter;
    let event = format!("event: data\ndata: {}\n\n", "x".repeat(32 << 10));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_time()
        .build()
        .unwrap();
    let idle = Duration::from_millis(80);

    let (tx, mut rx) = tokio::sync::mpsc::channel::<std::result::Result<Vec<u8>, hyper::Error>>(32);
    let consumer = std::thread::spawn(move || {
        let mut got = Vec::new();
        while let Some(Ok(chunk)) = rx.blocking_recv() {
            for part in chunk.chunks(512) {
                got.extend_from_slice(part);
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        got
    });
    let mut writer = H2SseWriter {
        tx,
        handle: Some(runtime.handle().clone()),
        idle,
        deadline_idle: idle,
    };
    let result = writer.send_bytes(event.as_bytes().to_vec());
    drop(writer);
    let got = consumer.join().unwrap();
    assert!(
        result.is_ok() && got == event.as_bytes(),
        "received={} expected={} error={:?}",
        got.len(),
        event.len(),
        result.err()
    );

    // A stalled stream: nothing takes pieces, so the bounded body fills and
    // the next piece misses its idle deadline.
    let (tx, _rx) = tokio::sync::mpsc::channel::<std::result::Result<Vec<u8>, hyper::Error>>(1);
    let mut writer = H2SseWriter {
        tx,
        handle: Some(runtime.handle().clone()),
        idle,
        deadline_idle: idle,
    };
    let started = Instant::now();
    let err = writer.send_bytes(event.as_bytes().to_vec()).unwrap_err();
    assert!(
        started.elapsed() >= idle,
        "stalled stream failed before its idle deadline: {err:?}"
    );
}

#[test]
fn spec_continuous_downstream_must_yield_to_controls() {
    let mut cfg = config();
    cfg.transport.heartbeat = Duration::from_millis(10);
    cfg.transport.up_ack_max_delay = Duration::from_millis(1);
    let (backend, peer) = backend_pair();
    let s = session(
        "s_yield",
        "A",
        Mode::Ws,
        WireLimits {
            max_frame_size: 1 << 20,
            up_max_inflight_frames: 8,
            up_window_bytes: 1 << 20,
            down_buffer_bytes: 1 << 20,
            up_receipt_limit: 64,
            down_max_frames: 64,
        },
        backend,
    );
    s.attach("stream").unwrap();
    let epoch = s.epoch();
    let mut drain = peer.try_clone().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while matches!(drain.read(&mut buf), Ok(n) if n > 0) {}
    });
    let mut db = peer.try_clone().unwrap();
    db.write_all(b"x").unwrap();
    let frames = Arc::new(Mutex::new(0usize));
    let counted = frames.clone();
    let hook_session = s.clone();
    let (writer, controls) = hook_writer(Box::new(move |offset, payload| {
        let mut frames = counted.lock().unwrap();
        *frames += 1;
        if *frames == 1 {
            hook_session.ingest_up(epoch, 0, b"u")?;
            let until = Instant::now() + Duration::from_secs(1);
            while hook_session.snapshot().ack_up_offset != 1 && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(1));
            }
            if hook_session.snapshot().ack_up_offset != 1 {
                return Err(Error::local("fixture backend did not acknowledge"));
            }
        }
        hook_session.apply_down_ack(offset + payload.len() as u64, false)?;
        std::thread::sleep(Duration::from_millis(10));
        if *frames >= 20 {
            return Err(Error::local("closed pipe"));
        }
        db.write_all(b"x")
            .map_err(|e| Error::local(format!("database write: {e}")))?;
        Ok(())
    }));
    let start = Instant::now();
    let result = run_downstream(&cfg, s.clone(), writer, None);
    let elapsed = start.elapsed();
    let controls = controls.lock().unwrap().clone();
    let pings = controls
        .iter()
        .filter(|c| c.kind == ControlKind::Ping)
        .count();
    let ack_one = controls
        .iter()
        .any(|c| c.kind == ControlKind::AckUp && c.ack_up_offset == Some(1));
    let frames = *frames.lock().unwrap();
    eprintln!(
        "continuous_down_frames={frames} elapsed={elapsed:?} ping_count={pings} ack_up_1_emitted={ack_one} exit={:?}",
        result.as_ref().err()
    );
    s.close(Error::local("test complete"));
    drop(peer);
    assert_eq!(frames, 20, "the data loop stopped early: {result:?}");
    assert!(
        ack_one && pings >= 2,
        "continuous downstream loop starved frame-boundary ACK/ping scheduling"
    );
}

#[test]
fn spec_idle_readers_starve_codec() {
    let dir = std::env::temp_dir().join(format!(
        "dbb-egress-goadapt-{}",
        crate::util::random_hex(6).unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("tok-A"), "tokA").unwrap();
    let text = "node:\n  id: B\nhttp:\n  enabled: true\n  listen: \"127.0.0.1:0\"\n  allowed_transports: [ws, http-sse]\ntargets:\n  db:\n    network: tcp\n    address: \"127.0.0.1:3306\"\nauth:\n  inbound_peers:\n    - id: A\n      token_files: [tok-A]\n      allowed_targets: [db]\nlimits:\n  max_sessions: 16\ntransport:\n  frame_size: 32768\n  max_frame_size: 32768\n  codec_buffer_limit: 256KiB\n  heartbeat: 20ms\n  failure_detect_timeout: 3s\n";
    let path = dir.join("config.yaml");
    std::fs::write(&path, text).unwrap();
    let cfg = Arc::new(crate::config::load(&path).unwrap_or_else(|e| panic!("{}", e.message)));
    let metrics = Arc::new(crate::metrics::Metrics::new());
    metrics.configure_resources(&cfg);
    let server = Arc::new(super::Server::new(cfg.clone(), metrics));
    let res = server.metrics.resource_manager().expect("resources");
    let codec = server.codec_for("A").expect("codec share");

    let (got_tx, got_rx) = mpsc::channel::<Vec<u8>>();
    let mut sessions = Vec::new();
    let mut peers = Vec::new();
    let mut pumps = Vec::new();
    for i in 0..8 {
        let (backend, peer) = backend_pair();
        let s = session(
            &format!("s_idle_{i}"),
            "A",
            Mode::Ws,
            WireLimits {
                max_frame_size: 32768,
                up_max_inflight_frames: 8,
                up_window_bytes: 2 << 20,
                down_buffer_bytes: cfg.transport.buffer_per_direction,
                up_receipt_limit: 64,
                down_max_frames: 64,
            },
            backend,
        );
        server.registry.insert(s.clone());
        s.attach("stream").unwrap();
        let tx = got_tx.clone();
        let (writer, _) = hook_writer(Box::new(move |_, payload| {
            if i == 0 {
                let _ = tx.send(payload.to_vec());
            }
            Ok(())
        }));
        let pump_cfg = cfg.clone();
        let pump_session = s.clone();
        let pump_codec = Some(codec.clone());
        pumps.push(std::thread::spawn(move || {
            run_downstream(&pump_cfg, pump_session, writer, pump_codec)
        }));
        sessions.push(s);
        peers.push(peer);
    }
    let cleanup = |sessions: &[Arc<Session>]| {
        for s in sessions {
            s.close(Error::local("test complete"));
        }
    };
    let until = Instant::now() + Duration::from_secs(1);
    while res.payload.used() != 8 * 32768 && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(1));
    }
    if res.payload.used() != 8 * 32768 {
        cleanup(&sessions);
        panic!(
            "fixture did not start all eight reserved backend reads: payload={}",
            res.payload.used()
        );
    }
    peers[0].write_all(b"database-hello").unwrap();
    let first = got_rx.recv_timeout(Duration::from_millis(150));
    let mut failure = None;
    if first.is_err() {
        eprintln!(
            "8 idle readers: codec={}/{}, produced={}, data not emitted",
            codec.used(),
            codec.limit(),
            sessions[0].snapshot().down_produced
        );
        // Free an unrelated idle reader: the same data should then progress.
        sessions[7].close(Error::local("unrelated release"));
        failure = Some(match got_rx.recv_timeout(Duration::from_secs(1)) {
            Ok(b) => format!(
                "valid codec configuration deadlocked data until unrelated session closed; then delivered {:?}",
                String::from_utf8_lossy(&b)
            ),
            Err(_) => "data still blocked after unrelated session released".to_string(),
        });
    }
    cleanup(&sessions);
    drop(peers);
    for p in pumps {
        let _ = p.join();
    }
    server.registry.close_all();
    let _ = std::fs::remove_dir_all(&dir);
    if let Some(failure) = failure {
        panic!("{failure}");
    }
    assert_eq!(first.unwrap(), b"database-hello");
}
