//! The downstream pump and the control ticker: the two threads that keep a
//! session moving after its carrier is up.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::error::{Error, Result};
use crate::resource::budget::{Budget, BudgetLease};
use crate::session::{DownPump, Session};
use crate::transport::SharedWriter;
use crate::wire::{self, Control, ControlKind, Mode};

pub(super) fn ready_control(session: &Arc<Session>, stream: &str, mode: Mode) -> Control {
    let mut c = Control::base(
        ControlKind::Ready,
        &session.id,
        &session.instance_id,
        session.epoch(),
        stream,
    );
    c.protocol_version = Some(wire::PROTOCOL_VERSION.to_string());
    c.transport = Some(mode.as_str().to_string());
    c.resume_request_id = session.last_resume_request_id();
    c
}

/// Produces downstream frames under the session window.
///
/// The control ticker runs on its own thread: `ack_up` must reach the ingress
/// as soon as upstream bytes are applied, even while nothing is flowing
/// downstream. Without it the ingress would never learn that its last frames
/// landed, and could not send a FIN that matches the applied offset.
pub(super) fn run_downstream(
    cfg: &Config,
    session: Arc<Session>,
    writer: SharedWriter,
    codec: Option<Arc<Budget>>,
) -> Result<()> {
    let trace = std::env::var_os("DBBRIDGE_TRACE").is_some();
    let epoch = session.epoch();
    if trace {
        eprintln!(
            "egress downstream waiting for reader lock session={} epoch={}",
            session.id, epoch
        );
    }
    let detect = cfg.transport.failure_detect_timeout;

    let control = {
        let session = session.clone();
        let writer = writer.clone();
        let cfg = cfg.clone();
        std::thread::spawn(move || control_ticker(&cfg, session, writer, epoch))
    };

    // Start the generation's control path before waiting for the backend
    // reader lock. A prior generation may still hold that lock until its
    // bounded backend read wakes; delaying AckUp until then can exhaust the
    // peer's receipt window during a fast recovery replay.
    let _downstream_reader = session.lock_downstream();
    if session.epoch() != epoch
        || session.recovery_state() == crate::session::recovery::RecoveryState::Suspended
    {
        writer.shutdown();
        let _ = control.join();
        return Ok(());
    }
    if trace {
        eprintln!(
            "egress downstream started session={} epoch={} retained_frames={}",
            session.id,
            epoch,
            session.replay_down_frames().len()
        );
    }

    let pump = DownPump {
        session: session.clone(),
        frame_size: cfg.transport.frame_size.min(session.limits.max_frame_size),
    };
    let ws = session.current_mode() == Mode::Ws;
    let tick = cfg.transport.up_ack_max_delay.max(Duration::from_millis(1));
    let cap = codec
        .as_ref()
        .map(|codec| max_down_frame_for_codec(ws, codec.limit()))
        .unwrap_or(usize::MAX);
    let mut result = pump.run_locked_capped(cap, |offset, payload| {
        if session.epoch() != epoch {
            return Err(Error::new(wire::ERR_STALE_EPOCH, "carrier epoch replaced"));
        }
        let _codec = match &codec {
            Some(codec) => Some(take_down_codec(
                codec,
                down_codec_cost(ws, payload.len()),
                &session,
                epoch,
                tick,
            )?),
            None => None,
        };
        session.set_transport_writing(true);
        let result = writer.send_data(epoch, offset, payload).map(|_| ());
        session.set_transport_writing(false);
        result
    });

    if result.is_ok() && session.down_fin() {
        let produced = session.snapshot().down_produced;
        result = writer.send_control(&session.fin_control(produced));
    }

    if let Err(error) = result {
        if session.epoch() == epoch && !session.is_closed() && !session.suspend(epoch) {
            session.close(error.clone());
        }
        writer.shutdown();
        let _ = control.join();
        return Err(error);
    }

    // Hold the carrier open while the upstream half finishes: the peer still
    // has to deliver its FIN and read the acknowledgements.
    let deadline = Instant::now() + cfg.transport.shutdown_timeout.min(Duration::from_secs(120));
    while !session.is_closed() {
        if session.epoch() != epoch
            || session.recovery_state() == crate::session::recovery::RecoveryState::Suspended
        {
            break;
        }
        let generation = session.change_generation();
        if session.finished() {
            break;
        }
        if session.control_expired(detect) {
            let error = Error::new(wire::ERR_SESSION_CLOSED, "control timeout");
            if !session.suspend(epoch) {
                session.close(error);
            }
            break;
        }
        let shutdown_wait = deadline.saturating_duration_since(Instant::now());
        if shutdown_wait.is_zero() {
            break;
        }
        let wait = shutdown_wait
            .min(session.control_wait_remaining(detect))
            .max(Duration::from_millis(1));
        session.wait_for_change_since(generation, wait);
    }
    if session.epoch() != epoch
        || session.recovery_state() == crate::session::recovery::RecoveryState::Suspended
    {
        writer.shutdown();
        let _ = control.join();
        return Ok(());
    }
    if let Some(notice) = session.terminal_control() {
        let _ = writer.send_control(&notice);
        if session.current_mode() == Mode::Ws {
            let reason = notice.code.as_deref().unwrap_or("");
            let _ = writer.send_close(1000, reason);
        }
    }
    session.close(Error::local("session finished"));
    writer.shutdown();
    let _ = control.join();
    result
}

fn down_codec_cost(ws: bool, size: usize) -> i64 {
    let size = i64::try_from(size).unwrap_or(i64::MAX);
    if ws {
        size.saturating_mul(2)
            .saturating_add(wire::WS_HEADER_LEN as i64)
    } else {
        size.saturating_mul(6).saturating_add(16384)
    }
}

/// The largest frame payload whose `down_codec_cost` fits `limit` (at
/// least 1 byte, so a degenerate share still makes progress).
pub(super) fn max_down_frame_for_codec(ws: bool, limit: i64) -> usize {
    let room = if ws {
        (limit - wire::WS_HEADER_LEN as i64) / 2
    } else {
        (limit - 16384) / 6
    };
    usize::try_from(room.max(1)).unwrap_or(usize::MAX)
}

fn take_down_codec(
    codec: &Arc<Budget>,
    cost: i64,
    session: &Arc<Session>,
    epoch: u64,
    tick: Duration,
) -> Result<BudgetLease> {
    if cost > codec.limit().max(0) && cost > 0 {
        return Err(Error::new(wire::ERR_BUFFER_EXHAUSTED, "codec budget").closed(true));
    }
    loop {
        if let Some(lease) = codec.try_acquire(cost) {
            return Ok(lease);
        }
        if session.epoch() != epoch {
            return Err(Error::new(wire::ERR_STALE_EPOCH, "carrier epoch replaced"));
        }
        if session.is_closed() {
            return Err(Error::new(wire::ERR_SESSION_CLOSED, "session closed"));
        }
        std::thread::sleep(tick);
    }
}

/// Sends `ack_up` when the applied upstream offset moves, and `ping` on the
/// heartbeat, for the lifetime of the session.
pub(super) fn control_ticker(
    cfg: &Config,
    session: Arc<Session>,
    writer: SharedWriter,
    epoch: u64,
) {
    let hb = cfg.transport.heartbeat;
    let detect = cfg.transport.failure_detect_timeout;
    let trace = std::env::var_os("DBBRIDGE_TRACE").is_some();
    if trace {
        eprintln!(
            "egress control ticker started session={} epoch={}",
            session.id, epoch
        );
    }
    let mut last_ack = u64::MAX;
    let now = Instant::now();
    // Recovery attachment is not complete for an ingress until it receives a
    // ping on the new carrier; do not make it wait a full heartbeat interval.
    let mut last_ping = if session.last_resume_request_id().is_some() {
        now.checked_sub(hb).unwrap_or(now)
    } else {
        now
    };
    while !session.is_closed() {
        if session.epoch() != epoch
            || session.recovery_state() == crate::session::recovery::RecoveryState::Suspended
        {
            return;
        }
        let generation = session.change_generation();
        if session.is_closed() {
            return;
        }
        if session.control_expired(detect) {
            let error = Error::new(wire::ERR_SESSION_CLOSED, "control timeout");
            if !session.suspend(epoch) {
                session.close(error);
            }
            return;
        }
        let snap = session.snapshot();
        if snap.ack_up_offset != last_ack {
            if writer.send_control(&session.ack_up_control()).is_err() {
                if session.epoch() == epoch && !session.is_closed() && !session.suspend(epoch) {
                    session.close(Error::local("carrier control write failed"));
                }
                return;
            }
            last_ack = snap.ack_up_offset;
            if trace {
                eprintln!(
                    "egress ack_up sent session={} epoch={} offset={}",
                    session.id, epoch, last_ack
                );
            }
        }
        if last_ping.elapsed() >= hb {
            let ping = match session.ping_control() {
                Ok(ping) => ping,
                Err(error) => {
                    if session.epoch() == epoch && !session.is_closed() && !session.suspend(epoch) {
                        session.close(error);
                    }
                    return;
                }
            };
            if let Err(error) = writer.send_control(&ping) {
                if session.epoch() == epoch && !session.is_closed() && !session.suspend(epoch) {
                    session.close(error);
                }
                return;
            }
            if trace {
                eprintln!("egress ping sent session={} epoch={}", session.id, epoch);
            }
            last_ping = Instant::now();
        }
        let heartbeat_wait = hb.saturating_sub(last_ping.elapsed());
        let wait = heartbeat_wait
            .min(session.control_wait_remaining(detect))
            .max(Duration::from_millis(1));
        session.wait_for_change_since(generation, wait);
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use crate::config::{Admin, Config, Http, Limits, Node, Reverse, Transport};
    use crate::error::Error;
    use crate::session::recovery::{RecoveryState, ResumeFin, ResumeRequest};
    use crate::session::Session;
    use crate::transport::{CarrierWriter, SharedWriter};
    use crate::wire::{self, Control, Limits as WireLimits, Mode};

    use super::{down_codec_cost, ready_control, run_downstream, take_down_codec};
    use crate::resource::budget::Budget;

    #[derive(Default)]
    struct Writes {
        controls: Vec<Control>,
        closes: Vec<(u16, String)>,
    }

    struct RecordingWriter(Arc<Mutex<Writes>>);

    impl CarrierWriter for RecordingWriter {
        fn send_data(
            &mut self,
            _epoch: u64,
            _offset: u64,
            _payload: &[u8],
        ) -> crate::error::Result<Option<u64>> {
            Ok(None)
        }

        fn send_control(&mut self, control: &Control) -> crate::error::Result<()> {
            self.0.lock().unwrap().controls.push(control.clone());
            Ok(())
        }

        fn send_close(&mut self, code: u16, reason: &str) -> crate::error::Result<()> {
            self.0
                .lock()
                .unwrap()
                .closes
                .push((code, reason.to_string()));
            Ok(())
        }

        fn shutdown(&mut self) {}
    }

    struct FailingDataWriter;

    impl CarrierWriter for FailingDataWriter {
        fn send_data(
            &mut self,
            _epoch: u64,
            _offset: u64,
            _payload: &[u8],
        ) -> crate::error::Result<Option<u64>> {
            Err(Error::local("carrier disconnected"))
        }

        fn send_control(&mut self, _control: &Control) -> crate::error::Result<()> {
            Ok(())
        }

        fn send_close(&mut self, _code: u16, _reason: &str) -> crate::error::Result<()> {
            Ok(())
        }

        fn shutdown(&mut self) {}
    }

    fn backend() -> TcpStream {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (backend, _) = listener.accept().unwrap();
        drop(client);
        backend
    }

    fn config() -> Config {
        Config {
            path: PathBuf::new(),
            node: Node {
                id: "test".to_string(),
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
            auth_reload_interval: std::time::Duration::from_secs(5),
            transport: Transport::default(),
            limits: Limits {
                max_sessions: 1,
                max_endpoints_per_peer: 16,
            },
            reverse: Reverse::default(),
        }
    }

    fn run_terminal(mode: Mode) -> Arc<Mutex<Writes>> {
        let session = Session::new(
            "s_test".to_string(),
            "token".to_string(),
            "instance".to_string(),
            "peer".to_string(),
            "target".to_string(),
            mode,
            WireLimits {
                max_frame_size: 1024,
                up_max_inflight_frames: 1,
                up_window_bytes: 1024,
                down_buffer_bytes: 1024,
                up_receipt_limit: 1,
                down_max_frames: 1,
            },
            4,
            backend(),
            Arc::new(crate::metrics::Metrics::new()),
        );
        session.attach("stream").unwrap();
        session.close(Error::new(wire::ERR_BACKEND_LOST, "backend reset").closed(true));

        let writes = Arc::new(Mutex::new(Writes::default()));
        let writer = SharedWriter::new(Box::new(RecordingWriter(writes.clone())));
        run_downstream(&config(), session, writer, None).unwrap();
        writes
    }

    #[test]
    fn ready_control_echoes_resume_request_id_only_after_resume() {
        let session = Session::new(
            "s_ready".to_string(),
            "token".to_string(),
            "instance".to_string(),
            "peer".to_string(),
            "target".to_string(),
            Mode::Ws,
            WireLimits {
                max_frame_size: 1024,
                up_max_inflight_frames: 1,
                up_window_bytes: 1024,
                down_buffer_bytes: 1024,
                up_receipt_limit: 1,
                down_max_frames: 1,
            },
            4,
            backend(),
            Arc::new(crate::metrics::Metrics::new()),
        );
        session.enable_recovery(Duration::from_secs(5));
        session.attach("old-stream").unwrap();
        assert_eq!(
            ready_control(&session, "old-stream", Mode::Ws)
                .resume_request_id
                .as_deref(),
            None
        );
        session.suspend_current();
        session
            .resume(
                &ResumeRequest {
                    resume_request_id: "resume-ready-1".into(),
                    expected_epoch: 1,
                    ingress_instance_id: "instance".into(),
                    transport: Mode::Ws,
                    known_up_ack_offset: 0,
                    up_next_offset: 0,
                    down_delivered_offset: 0,
                    up_fin: ResumeFin::default(),
                    down_fin: ResumeFin::default(),
                },
                Duration::from_secs(1),
            )
            .unwrap();
        session.attach("new-stream").unwrap();
        assert_eq!(
            ready_control(&session, "new-stream", Mode::Ws)
                .resume_request_id
                .as_deref(),
            Some("resume-ready-1")
        );
    }

    #[test]
    fn resumed_generation_emits_ping_before_heartbeat() {
        let mut cfg = config();
        cfg.transport.heartbeat = Duration::from_secs(60);
        let session = Session::new(
            "s_resume_ping".to_string(),
            "token".to_string(),
            "instance".to_string(),
            "peer".to_string(),
            "target".to_string(),
            Mode::Ws,
            WireLimits {
                max_frame_size: 1024,
                up_max_inflight_frames: 1,
                up_window_bytes: 1024,
                down_buffer_bytes: 1024,
                up_receipt_limit: 1,
                down_max_frames: 1,
            },
            4,
            backend(),
            Arc::new(crate::metrics::Metrics::new()),
        );
        session.enable_recovery(Duration::from_secs(5));
        session.attach("old-stream").unwrap();
        session.suspend_current();
        session
            .resume(
                &ResumeRequest {
                    resume_request_id: "resume-ping-1".into(),
                    expected_epoch: 1,
                    ingress_instance_id: "instance".into(),
                    transport: Mode::Ws,
                    known_up_ack_offset: 0,
                    up_next_offset: 0,
                    down_delivered_offset: 0,
                    up_fin: ResumeFin::default(),
                    down_fin: ResumeFin::default(),
                },
                Duration::from_secs(1),
            )
            .unwrap();
        session.attach("new-stream").unwrap();

        let writes = Arc::new(Mutex::new(Writes::default()));
        let writer = SharedWriter::new(Box::new(RecordingWriter(writes.clone())));
        std::thread::scope(|scope| {
            let ticker_session = session.clone();
            let ticker_epoch = ticker_session.epoch();
            let ticker = scope
                .spawn(move || super::control_ticker(&cfg, ticker_session, writer, ticker_epoch));
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            let mut ping_seen = false;
            while std::time::Instant::now() < deadline {
                ping_seen = writes
                    .lock()
                    .unwrap()
                    .controls
                    .iter()
                    .any(|control| control.kind == wire::ControlKind::Ping);
                if ping_seen {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            session.close(Error::local("test complete"));
            ticker.join().unwrap();
            assert!(ping_seen, "resumed generation must ping before heartbeat");
        });
    }

    #[test]
    fn backend_reset_sends_terminal_error_ws() {
        let writes = run_terminal(Mode::Ws);
        let writes = writes.lock().unwrap();
        assert_eq!(writes.controls.len(), 1);
        assert_eq!(writes.controls[0].kind, wire::ControlKind::Error);
        assert_eq!(
            writes.controls[0].code.as_deref(),
            Some(wire::ERR_BACKEND_LOST)
        );
        assert_eq!(
            writes.closes,
            vec![(1000, wire::ERR_BACKEND_LOST.to_string())]
        );
    }

    #[test]
    fn backend_reset_sends_terminal_error_sse() {
        let writes = run_terminal(Mode::HttpSse);
        let writes = writes.lock().unwrap();
        assert_eq!(writes.controls.len(), 1);
        assert_eq!(writes.controls[0].kind, wire::ControlKind::Error);
        assert_eq!(
            writes.controls[0].code.as_deref(),
            Some(wire::ERR_BACKEND_LOST)
        );
        assert!(writes.closes.is_empty());
    }

    #[test]
    fn carrier_write_failure_suspends_recovery_enabled_session() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (backend, _) = listener.accept().unwrap();
        peer.write_all(b"payload").unwrap();
        let session = Session::new(
            "s_recovery".to_string(),
            "token".to_string(),
            "instance".to_string(),
            "peer".to_string(),
            "target".to_string(),
            Mode::Ws,
            WireLimits {
                max_frame_size: 1024,
                up_max_inflight_frames: 1,
                up_window_bytes: 1024,
                down_buffer_bytes: 1024,
                up_receipt_limit: 1,
                down_max_frames: 1,
            },
            4,
            backend,
            Arc::new(crate::metrics::Metrics::new()),
        );
        // Keep the session alive even when the full test suite is heavily
        // parallelized; the test asserts suspension, not recovery expiry.
        session.enable_recovery(std::time::Duration::from_secs(60));
        session.attach("stream").unwrap();
        let writer = SharedWriter::new(Box::new(FailingDataWriter));

        assert!(run_downstream(&config(), session.clone(), writer, None).is_err());
        assert!(!session.is_closed());
        assert_eq!(session.recovery_state(), RecoveryState::Suspended);

        session.close(Error::local("test cleanup"));
        drop(peer);
    }

    #[test]
    fn resumed_generation_sends_ack_up_while_reader_lock_is_held() {
        let mut cfg = config();
        cfg.transport.heartbeat = Duration::from_secs(60);
        cfg.transport.failure_detect_timeout = Duration::from_secs(5);

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (backend, _) = listener.accept().unwrap();
        let session = Session::new(
            "s_lock_recovery".to_string(),
            "token".to_string(),
            "instance".to_string(),
            "peer".to_string(),
            "target".to_string(),
            Mode::Ws,
            WireLimits {
                max_frame_size: 1024,
                up_max_inflight_frames: 1,
                up_window_bytes: 1024,
                down_buffer_bytes: 1024,
                up_receipt_limit: 8,
                down_max_frames: 1,
            },
            4,
            backend,
            Arc::new(crate::metrics::Metrics::new()),
        );
        session.enable_recovery(Duration::from_secs(5));
        session.attach("old-stream").unwrap();
        session.ingest_up(1, 0, b"hello").unwrap();
        session.suspend_current();
        let response = session
            .resume(
                &ResumeRequest {
                    resume_request_id: "resume-lock-ack".into(),
                    expected_epoch: 1,
                    ingress_instance_id: "instance".into(),
                    transport: Mode::Ws,
                    known_up_ack_offset: 0,
                    up_next_offset: 5,
                    down_delivered_offset: 0,
                    up_fin: ResumeFin::default(),
                    down_fin: ResumeFin::default(),
                },
                Duration::from_secs(1),
            )
            .unwrap();
        assert_eq!(response.ack_up_offset, 5);
        session.attach("new-stream").unwrap();

        // Model an old generation that has not yet released the reader lock.
        // The new generation's control ticker must still send the applied ACK.
        let held_reader = session.lock_downstream();
        let writes = Arc::new(Mutex::new(Writes::default()));
        let writer = SharedWriter::new(Box::new(RecordingWriter(writes.clone())));
        let worker_session = session.clone();
        let worker = std::thread::spawn(move || run_downstream(&cfg, worker_session, writer, None));

        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        let mut ack_seen = false;
        while std::time::Instant::now() < deadline {
            ack_seen = writes.lock().unwrap().controls.iter().any(|control| {
                control.kind == wire::ControlKind::AckUp && control.ack_up_offset == Some(5)
            });
            if ack_seen {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }

        drop(held_reader);
        session.close(Error::local("test complete"));
        let _ = worker.join().unwrap();
        drop(peer);
        assert!(ack_seen, "recovery AckUp must not wait for the reader lock");
    }

    /// Records the owner's codec use while each data frame is written, then
    /// fails the carrier so the pump returns.
    struct CodecProbeWriter {
        codec: Arc<Budget>,
        seen: Arc<Mutex<Vec<i64>>>,
    }

    impl CarrierWriter for CodecProbeWriter {
        fn send_data(
            &mut self,
            _epoch: u64,
            _offset: u64,
            _payload: &[u8],
        ) -> crate::error::Result<Option<u64>> {
            self.seen.lock().unwrap().push(self.codec.used());
            Err(Error::local("carrier disconnected"))
        }

        fn send_control(&mut self, _control: &Control) -> crate::error::Result<()> {
            Ok(())
        }

        fn shutdown(&mut self) {}
    }

    fn backend_with(data: &[u8]) -> TcpStream {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (backend, _) = listener.accept().unwrap();
        client.write_all(data).unwrap();
        drop(client);
        backend
    }

    fn charged_frame(mode: Mode) -> (Vec<i64>, i64) {
        let session = Session::new(
            "s_codec".to_string(),
            "token".to_string(),
            "instance".to_string(),
            "peer".to_string(),
            "target".to_string(),
            mode,
            WireLimits {
                max_frame_size: 1024,
                up_max_inflight_frames: 1,
                up_window_bytes: 1024,
                down_buffer_bytes: 1024,
                up_receipt_limit: 1,
                down_max_frames: 1,
            },
            4,
            backend_with(b"hello"),
            Arc::new(crate::metrics::Metrics::new()),
        );
        session.attach("stream").unwrap();
        let codec = Budget::new(1 << 20);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let writer = SharedWriter::new(Box::new(CodecProbeWriter {
            codec: codec.clone(),
            seen: seen.clone(),
        }));
        assert!(run_downstream(&config(), session, writer, Some(codec.clone())).is_err());
        let seen = seen.lock().unwrap().clone();
        (seen, codec.used())
    }

    #[test]
    fn ws_downstream_frame_holds_owner_codec_share_while_written() {
        let (seen, after) = charged_frame(Mode::Ws);
        assert_eq!(seen, vec![2 * 5 + wire::WS_HEADER_LEN as i64]);
        assert_eq!(after, 0);
    }

    #[test]
    fn sse_downstream_frame_holds_owner_codec_share_while_written() {
        let (seen, after) = charged_frame(Mode::HttpSse);
        assert_eq!(seen, vec![6 * 5 + 16384]);
        assert_eq!(after, 0);
    }

    #[test]
    fn downstream_codec_waits_for_room_and_refuses_impossible_charge() {
        assert_eq!(down_codec_cost(true, 10), 20 + wire::WS_HEADER_LEN as i64);
        assert_eq!(down_codec_cost(false, 10), 60 + 16384);
        let session = Session::new(
            "s_codec_wait".to_string(),
            "token".to_string(),
            "instance".to_string(),
            "peer".to_string(),
            "target".to_string(),
            Mode::Ws,
            WireLimits {
                max_frame_size: 1024,
                up_max_inflight_frames: 1,
                up_window_bytes: 1024,
                down_buffer_bytes: 1024,
                up_receipt_limit: 1,
                down_max_frames: 1,
            },
            4,
            backend(),
            Arc::new(crate::metrics::Metrics::new()),
        );
        let codec = Budget::new(100);
        let held = codec.try_acquire(100).unwrap();
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            drop(held);
        });
        let started = std::time::Instant::now();
        let lease = take_down_codec(&codec, 60, &session, 1, Duration::from_millis(5)).unwrap();
        assert!(started.elapsed() >= Duration::from_millis(40));
        assert_eq!(codec.used(), 60);
        drop(lease);
        release.join().unwrap();
        let err = take_down_codec(&codec, 101, &session, 1, Duration::from_millis(5)).unwrap_err();
        assert_eq!(err.code, wire::ERR_BUFFER_EXHAUSTED);
        // A closed session stops waiting.
        let _all = codec.try_acquire(100).unwrap();
        session.close(Error::local("gone"));
        let err = take_down_codec(&codec, 50, &session, 1, Duration::from_millis(5)).unwrap_err();
        assert_eq!(err.code, wire::ERR_SESSION_CLOSED);
    }
}
