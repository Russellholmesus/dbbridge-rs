//! The relay: one session's bytes, in both directions, plus the control ticker
//! that keeps the two sides agreeing on offsets.

use std::collections::{HashSet, VecDeque};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::config::{Config, Endpoint, Peer};
use crate::error::{Error, Result};
use crate::resource::budget::{Budget, BudgetLease};
use crate::transport::control::ControlClient;
use crate::transport::{CarrierReader, CarrierWriter, Incoming, SharedWriter};
use crate::wire::{self, AckRequest, ControlKind};

// ---------------------------------------------------------------------------
// Relay
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct RetainedUpFrame {
    offset: u64,
    end: u64,
    payload: Vec<u8>,
    _cost: Option<Arc<BudgetLease>>,
}

type RedialedCarrier = (
    Box<dyn CarrierReader>,
    Box<dyn CarrierWriter>,
    wire::Control,
    bool,
);

/// A redialed carrier is owned by the recovery attempt until the hand-off is
/// committed. Dropping a failed candidate must close the remote attachment so
/// the next retry can claim a fresh stream ID.
struct PendingCarrierWriter(Option<Box<dyn CarrierWriter>>);

impl PendingCarrierWriter {
    fn new(writer: Box<dyn CarrierWriter>) -> Self {
        Self(Some(writer))
    }

    fn writer(&mut self) -> &mut dyn CarrierWriter {
        self.0
            .as_mut()
            .expect("candidate carrier writer already committed")
            .as_mut()
    }

    fn take(&mut self) -> Box<dyn CarrierWriter> {
        self.0
            .take()
            .expect("candidate carrier writer already committed")
    }
}

impl Drop for PendingCarrierWriter {
    fn drop(&mut self) {
        if let Some(writer) = self.0.as_mut() {
            writer.shutdown();
        }
    }
}

pub(super) fn control_interval(t: &crate::config::Transport) -> Duration {
    let ack = if t.ack_max_delay.is_zero() {
        Duration::from_millis(200)
    } else {
        t.ack_max_delay
    };
    let hb = if t.heartbeat.is_zero() {
        Duration::from_secs(15)
    } else {
        t.heartbeat
    };
    ack.min(hb)
}

pub(super) fn control_idle_interval(t: &crate::config::Transport) -> Duration {
    let hb = if t.heartbeat.is_zero() {
        Duration::from_secs(15)
    } else {
        t.heartbeat
    };
    let detect = if t.failure_detect_timeout.is_zero() {
        Duration::from_secs(45)
    } else {
        t.failure_detect_timeout
    };
    control_interval(t).max(hb.min(detect / 3))
}

pub(super) fn down_frames_ack_threshold(l: &wire::Limits) -> u64 {
    (l.down_max_frames / 4).clamp(1, 32) as u64
}

pub(super) fn down_bytes_ack_threshold(batch: u64, l: &wire::Limits) -> u64 {
    if batch == 0 {
        return 0;
    }
    if l.down_buffer_bytes > 1 {
        return batch.min(l.down_buffer_bytes / 2);
    }
    batch
}

pub(super) fn up_frames_ack_threshold(l: &wire::Limits) -> u64 {
    (l.up_max_inflight_frames.max(1).saturating_add(4))
        .min(l.up_receipt_limit / 2)
        .max(1) as u64
}

fn recovery_deadline(current: Option<Instant>, now: Instant, grace: Duration) -> Instant {
    current.unwrap_or_else(|| now + grace)
}

fn committed_recovery_deadline() -> Option<Instant> {
    None
}

fn ack_response_matches_generation(
    current_epoch: u64,
    current_stream: &str,
    carrier_lost: bool,
    closed: bool,
    request_epoch: u64,
    request_stream: &str,
) -> bool {
    !carrier_lost && !closed && current_epoch == request_epoch && current_stream == request_stream
}

fn is_confirmed_duplicate_frame(error: &Error) -> bool {
    error.code == wire::ERR_REPLAY_TOO_OLD
}

struct RelayState {
    epoch: u64,
    stream: String,
    mode: wire::Mode,
    up_next: u64,
    up_acked: u64,
    /// Payloads remain available until the peer confirms the exact frame end,
    /// so a replacement carrier can replay them at their original offsets.
    up_frames: VecDeque<RetainedUpFrame>,
    up_frames_unconfirmed: u64,
    down_delivered: u64,
    pending_down: VecDeque<Incoming>,
    up_fin: bool,
    down_fin: bool,
    down_fin_offset: Option<u64>,
    up_fin_applied: bool,
    down_fin_applied: bool,
    down_fin_acked: bool,
    closed: bool,
    owner_closed_normal: bool,
    carrier_lost: bool,
    recovery_deadline: Option<Instant>,
    error: Option<Error>,
    heartbeat_nonce: String,
    ack_requested: bool,
    down_frames: u64,
    down_reported: u64,
    down_frames_reported: u64,
    rx_blocked: bool,
    tx_blocked: bool,
    rx_blocked_at: Option<Instant>,
    rx_block_reason: &'static str,
    last_activity: Instant,
    up_sent: u64,
    up_pending_since: Option<Instant>,
    remote_tx_blocked: bool,
    remote_rx_blocked: bool,
    remote_blocked_at: Option<Instant>,
    last_control: Option<Instant>,
    ready_ack_pending: bool,
    fault_source: String,
    fault_reason: &'static str,
    fault_time: Option<std::time::SystemTime>,
    /// When the session's end was decided (first terminal error).
    terminal_at: Option<std::time::SystemTime>,
    recovery_attempts: u32,
    outcome_unknown: bool,
}

impl RelayState {
    fn initial(epoch: u64, stream: String, mode: wire::Mode) -> Self {
        RelayState {
            epoch,
            stream,
            mode,
            up_next: 0,
            up_acked: 0,
            up_frames: VecDeque::new(),
            up_frames_unconfirmed: 0,
            down_delivered: 0,
            pending_down: VecDeque::new(),
            up_fin: false,
            down_fin: false,
            down_fin_offset: None,
            up_fin_applied: false,
            down_fin_applied: false,
            down_fin_acked: false,
            closed: false,
            owner_closed_normal: false,
            carrier_lost: false,
            recovery_deadline: None,
            error: None,
            heartbeat_nonce: String::new(),
            ack_requested: false,
            down_frames: 0,
            down_reported: 0,
            down_frames_reported: 0,
            rx_blocked: false,
            tx_blocked: false,
            rx_blocked_at: None,
            rx_block_reason: "",
            last_activity: Instant::now(),
            up_sent: 0,
            up_pending_since: None,
            remote_tx_blocked: false,
            remote_rx_blocked: false,
            remote_blocked_at: None,
            last_control: None,
            ready_ack_pending: true,
            fault_source: String::new(),
            fault_reason: "",
            fault_time: None,
            terminal_at: None,
            recovery_attempts: 0,
            outcome_unknown: false,
        }
    }

    fn normal_close_confirmed(&self) -> bool {
        self.up_fin && self.up_fin_applied && self.down_fin && self.down_fin_acked
    }
}

pub(super) struct Route {
    control: ControlClient,
    endpoint: Endpoint,
}

pub struct Relay {
    cfg: Arc<Config>,
    route: Mutex<Route>,
    peer: Peer,
    metrics: Arc<crate::metrics::Metrics>,
    owner_instance: String,
    sid: String,
    token: String,
    recovery_enabled: bool,
    recovery_grace: Duration,
    limits: wire::Limits,
    state: Mutex<RelayState>,
    /// Serializes each upstream carrier write with recovery's writer/epoch handoff.
    carrier_handoff: Mutex<()>,
    cv: Condvar,
    /// For SSE: published so the POST can piggyback progress.
    sse_down_ack: Arc<AtomicU64>,
    sse_up_confirm: Arc<AtomicU64>,
    /// Whether the peer said it activates the initial attach on our first
    /// upstream frame (`X-DBB-Implicit-Ready`). Without it the data plane only
    /// opens once the peer has accepted our ready ACK, so the upstream pump
    /// must wait for the first successful ack before reading the local socket.
    implicit_ready: bool,
    /// Set by the control loop once an ack has been accepted.
    attached: AtomicBool,
    /// The local client socket, so an ingress shutdown closes it at once.
    local_conn: Mutex<Option<TcpStream>>,
    /// The carrier the next resume asks for instead of the current one (a
    /// failed first WS attach resumes onto SSE).
    resume_mode: Mutex<Option<wire::Mode>>,
    endpoints: Option<Arc<super::EndpointTable>>,
    prechecks: Option<Arc<Mutex<super::PrecheckCache>>>,
    cleanups: Option<Arc<super::serve::cleanup::CleanupTracker>>,
}

pub(super) struct RelayInit<'a> {
    pub(super) cfg: Arc<Config>,
    pub(super) control: ControlClient,
    pub(super) peer: Peer,
    pub(super) endpoint: Endpoint,
    pub(super) metrics: Arc<crate::metrics::Metrics>,
    pub(super) created: &'a wire::CreateResponse,
    pub(super) stream: &'a str,
    pub(super) implicit_ready: bool,
}

impl Relay {
    pub(super) fn new(init: RelayInit<'_>) -> Self {
        let RelayInit {
            cfg,
            control,
            peer,
            endpoint,
            metrics,
            created,
            stream,
            implicit_ready,
        } = init;
        Relay {
            cfg,
            route: Mutex::new(Route { control, endpoint }),
            peer,
            metrics,
            owner_instance: created.instance_id.clone(),
            sid: created.session_id.clone(),
            token: created.session_token.clone(),
            recovery_enabled: created.recovery_enabled,
            recovery_grace: Duration::from_millis(created.recovery_grace_ms),
            limits: created.limits,
            state: Mutex::new(RelayState::initial(
                created.epoch,
                stream.to_string(),
                created.mode,
            )),
            carrier_handoff: Mutex::new(()),
            cv: Condvar::new(),
            sse_down_ack: Arc::new(AtomicU64::new(0)),
            sse_up_confirm: Arc::new(AtomicU64::new(0)),
            implicit_ready,
            attached: AtomicBool::new(false),
            local_conn: Mutex::new(None),
            resume_mode: Mutex::new(None),
            endpoints: None,
            prechecks: None,
            cleanups: None,
        }
    }

    /// The control client of the session's current endpoint.
    fn control(&self) -> ControlClient {
        super::control_client_clone(&self.route.lock().unwrap().control)
    }

    /// The id of the session's current endpoint.
    fn endpoint_id(&self) -> String {
        self.route.lock().unwrap().endpoint.id.clone()
    }

    pub(super) fn with_failed_first_attach(self, resume_mode: wire::Mode) -> Self {
        {
            // No carrier exists: the control ticker must not ACK a
            // generation that never attached while recovery runs.
            let mut g = self.state.lock().unwrap();
            g.stream.clear();
            g.carrier_lost = true;
        }
        *self.resume_mode.lock().unwrap() = Some(resume_mode);
        self
    }

    pub(super) fn with_cleanups(
        mut self,
        cleanups: Arc<super::serve::cleanup::CleanupTracker>,
    ) -> Self {
        self.cleanups = Some(cleanups);
        self
    }

    pub(super) fn with_endpoints(
        mut self,
        endpoints: Arc<super::EndpointTable>,
        prechecks: Arc<Mutex<super::PrecheckCache>>,
    ) -> Self {
        self.endpoints = Some(endpoints);
        self.prechecks = Some(prechecks);
        self
    }

    fn cool_dropped_carrier(&self, from_mode: wire::Mode, cause: &Error) {
        let Some(table) = self.endpoints.as_ref() else {
            return;
        };
        if !super::link::first_attach_carrier_failure(cause) {
            return;
        }
        let ep = self.endpoint_id();
        table.record_transport_failure(&self.peer.id, &ep, from_mode, self.peer.failover.cooldown);
        if from_mode == wire::Mode::Ws {
            if let Some(cache) = &self.prechecks {
                let key = format!("{}|{}|{}", self.peer.id, ep, self.owner_instance);
                cache.lock().unwrap().remove(&key);
            }
        }
    }

    /// The carriers a recovery may use under the peer's protocol, in
    /// preference order.
    fn policy_modes(&self) -> Vec<wire::Mode> {
        match self.peer.protocol {
            crate::config::Protocol::Ws => vec![wire::Mode::Ws],
            crate::config::Protocol::HttpSse | crate::config::Protocol::LongPoll => {
                vec![wire::Mode::HttpSse]
            }
            crate::config::Protocol::Auto => vec![wire::Mode::Ws, wire::Mode::HttpSse],
        }
    }

    fn choose_recovery_route(
        &self,
        policy: &[wire::Mode],
        attempted: &HashSet<String>,
        deadline: Instant,
    ) -> Result<(Route, wire::Mode)> {
        let Some(table) = self.endpoints.as_ref() else {
            let route = self.route.lock().unwrap();
            return Ok((
                Route {
                    control: super::control_client_clone(&route.control),
                    endpoint: route.endpoint.clone(),
                },
                policy[0],
            ));
        };
        let peer = self.peer.id.as_str();
        let mut ordered = super::Ingress::peer_endpoints(&self.peer);
        ordered.sort_by_key(|e| e.priority);
        if !self.peer.failover.enabled {
            ordered.truncate(1);
        }
        if ordered.len() > 1 {
            ordered.sort_by_key(|e| table.get(peer, &e.id).is_some_and(|h| h.failures > 0));
        }
        let mut last = Error::local("no eligible endpoint for recovery");
        let (mut pending, mut owner_seen, mut mismatch) = (false, false, false);
        for ep in ordered {
            if attempted.contains(&ep.id) || table.in_cooldown(peer, &ep.id) {
                pending = true;
                continue;
            }
            let mut ctl = self.control();
            ctl.url = ep.url.clone();
            ctl.expected_instance = String::new();
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let probe = ctl.probe_within(
                &self.peer.expected_node_id,
                Some(self.peer.failover.healthcheck_timeout.min(remaining)),
            );
            let p = match probe {
                Ok(p) => p,
                Err(e) => {
                    if !e.is_local() || !e.message.contains("budget") {
                        let mismatched =
                            super::classify_precheck(&e) == super::PrecheckVerdict::Mismatched;
                        let state = table.record_probe_failure(
                            peer,
                            &ep.id,
                            self.peer.failover.cooldown,
                            self.peer.failover.unhealthy_threshold,
                            mismatched,
                        );
                        self.metrics.set_endpoint_state(peer, &ep.id, state);
                    }
                    last = e;
                    pending = true;
                    continue;
                }
            };
            let transports: Vec<wire::Mode> = p
                .transports
                .iter()
                .filter_map(|t| wire::Mode::parse(t))
                .collect();
            let state = table.put(
                peer,
                &ep.id,
                super::Health {
                    instance_id: p.instance_id.clone(),
                    transports: transports.clone(),
                    accepting_new_sessions: p.accepting_new_sessions,
                    probed_at: Instant::now(),
                    cooldown_until: None,
                    failures: 0,
                    probe_failures: 0,
                    successes: 0,
                    state: "UNKNOWN",
                },
                self.peer.failover.healthy_threshold,
            );
            self.metrics.set_endpoint_state(peer, &ep.id, state);
            if p.instance_id != self.owner_instance {
                // A different instance (e.g. an HA backup) is simply not a
                // candidate for this session.
                last = Error::new(
                    wire::ERR_PROTOCOL_MISMATCH,
                    format!("endpoint {} instance mismatch", ep.id),
                );
                mismatch = true;
                continue;
            }
            owner_seen = true;
            if super::select::excluded_state(state) {
                pending = true;
                continue;
            }
            let now = Instant::now();
            if let Some(mode) = policy.iter().copied().find(|m| {
                transports.contains(m) && table.transport_available(peer, &ep.id, *m, now)
            }) {
                ctl.expected_instance = self.owner_instance.clone();
                return Ok((
                    Route {
                        control: ctl,
                        endpoint: ep,
                    },
                    mode,
                ));
            }
            pending = true;
        }
        if mismatch && !pending && !owner_seen {
            return Err(Error::local(
                "protocol: the session owner is absent from every reachable endpoint",
            ));
        }
        Err(last)
    }

    fn recovery_pause(&self, attempt: u32, policy: &[wire::Mode], deadline: Instant) {
        let now = Instant::now();
        let mut wait = Duration::from_millis(25 * (1u64 << attempt.min(4)));
        if let Some(table) = self.endpoints.as_ref() {
            if let Some(next) = super::Ingress::peer_endpoints(&self.peer)
                .iter()
                .filter_map(|e| table.next_eligible(&self.peer.id, &e.id, policy, now))
                .min()
            {
                wait = wait.min(next.saturating_duration_since(now));
            }
        }
        let wait = wait
            .min(deadline.saturating_duration_since(now))
            .max(Duration::from_millis(1));
        std::thread::sleep(wait);
    }

    pub(super) fn with_sse(mut self, down: Arc<AtomicU64>, up: Arc<AtomicU64>) -> Self {
        self.sse_down_ack = down;
        self.sse_up_confirm = up;
        self
    }

    fn fail(&self, e: Error) {
        let mut g = self.state.lock().unwrap();
        if g.error.is_none() {
            g.error = Some(e);
            if g.terminal_at.is_none() {
                g.terminal_at = Some(std::time::SystemTime::now());
            }
        }
        g.closed = true;
        drop(g);
        self.cv.notify_all();
    }

    /// Waits until `done` holds, the session failed or closed, `stop` is set,
    /// or `deadline` passes.
    fn wait_state(&self, stop: &AtomicBool, deadline: Instant, done: impl Fn(&RelayState) -> bool) {
        let finished = |g: &RelayState| {
            done(g) || g.error.is_some() || g.closed || stop.load(Ordering::Relaxed)
        };
        let mut g = self.state.lock().unwrap();
        while !finished(&g) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            g = self
                .cv
                .wait_timeout_while(g, remaining, |g| !finished(g))
                .unwrap()
                .0;
        }
    }

    fn record_ingress_fault(&self, source: &str, error: &Error) {
        let reason = super::errors::reason_category(error);
        let mode = {
            let mut g = self.state.lock().unwrap();
            if !g.closed {
                if g.fault_time.is_none() {
                    g.fault_time = Some(std::time::SystemTime::now());
                }
                if g.fault_source.is_empty() {
                    g.fault_source = source.to_string();
                    g.fault_reason = reason;
                }
            }
            g.mode
        };
        self.metrics
            .record_session_event("ingress", "fault", reason, mode.as_str(), "none");
        self.metrics.record_ingress_fault(source, reason);
    }

    fn record_end_fault(&self, source: &str, error: &Error) {
        let reason = super::errors::reason_category(error);
        let mode = {
            let mut g = self.state.lock().unwrap();
            if g.closed || !g.fault_source.is_empty() {
                return;
            }
            if g.fault_time.is_none() {
                g.fault_time = Some(std::time::SystemTime::now());
            }
            g.fault_source = source.to_string();
            g.fault_reason = reason;
            g.mode
        };
        self.metrics
            .record_session_event("ingress", "fault", reason, mode.as_str(), "none");
        self.metrics.record_ingress_fault(source, reason);
    }

    /// The uncontended case of [`Self::acquire_codec_lease`]: `Some(lease)`
    /// (no lease without a resource manager) when codec room is available
    /// at once, `None` when the caller has to wait for it.
    fn try_codec_lease(
        &self,
        bytes: usize,
    ) -> Option<Option<crate::resource::budget::BudgetLease>> {
        let Some(resources) = self.metrics.resource_manager() else {
            return Some(None);
        };
        resources.mark_instrumented("codec");
        let amount = i64::try_from(bytes).unwrap_or(i64::MAX);
        resources.codec.try_acquire(amount).map(Some)
    }

    fn acquire_codec_lease(
        &self,
        bytes: usize,
    ) -> Result<Option<crate::resource::budget::BudgetLease>> {
        let Some(resources) = self.metrics.resource_manager() else {
            return Ok(None);
        };
        resources.mark_instrumented("codec");
        let amount = i64::try_from(bytes).unwrap_or(i64::MAX);
        resources
            .codec
            .acquire_timeout(amount, Some(self.cfg.transport.backpressure_timeout))
            .map(Some)
            .map_err(|_| {
                Error::new(wire::ERR_QUOTA_EXCEEDED, "codec budget exhausted").retryable(true)
            })
    }

    pub(super) fn run(
        self,
        client_conn: TcpStream,
        reader: Box<dyn CarrierReader>,
        writer: Box<dyn CarrierWriter>,
    ) -> Result<()> {
        let read_half = client_conn.try_clone()?;
        let local = client_conn.try_clone()?;
        let write_half = client_conn;
        let _ = read_half.set_read_timeout(Some(Duration::from_millis(200)));
        *self.local_conn.lock().unwrap() = local.try_clone().ok();
        let relay = Arc::new(self);
        let gauge: std::sync::Weak<dyn crate::metrics::IngressGauge> =
            Arc::<Relay>::downgrade(&relay);
        let gauge_id = relay.metrics.register_ingress(gauge);
        let stop = Arc::new(AtomicBool::new(false));

        // Upstream: local socket -> carrier.
        let shared_writer = SharedWriter::new(writer);
        let up = {
            let relay = relay.clone();
            let stop = stop.clone();
            let writer = shared_writer.clone();
            std::thread::Builder::new()
                .stack_size(crate::util::CONNECTION_STACK)
                .spawn(move || {
                    relay.upstream(read_half, writer, stop);
                })
                .ok()
        };
        // Control: periodic ack, which is also what keeps the peer's control
        // watchdog satisfied.
        let ctl = {
            let relay = relay.clone();
            let stop = stop.clone();
            let writer = shared_writer.clone();
            std::thread::Builder::new()
                .stack_size(crate::util::CONNECTION_STACK)
                .spawn(move || {
                    relay.control_loop(stop, writer);
                })
                .ok()
        };
        // A thread that cannot be started (fd/thread limit) must end the
        // session, not leave it half-wired: without an upstream pump the client
        // would sit there until the peer's watchdog fired.
        if up.is_none() || ctl.is_none() {
            relay.fail(Error::local("cannot start a relay thread"));
        }
        // Downstream runs here: it is the side that decides the session is
        // over.
        // The carrier reader is handed back and kept alive until the session
        // is settled: dropping it closes the carrier, and a carrier that ends
        // before the peer has seen our down-FIN ACK is a carrier loss to it.
        let _reader = relay.downstream(write_half, reader, shared_writer);
        let down_finished = {
            let g = relay.state.lock().unwrap();
            g.down_fin && g.error.is_none()
        };
        let up_fin_wait = if down_finished {
            Duration::from_secs(365 * 24 * 3600)
        } else {
            relay.cfg.transport.control_request_timeout
        };
        relay.wait_state(&stop, Instant::now() + up_fin_wait, |g| g.up_fin);
        let up_fin = relay.state.lock().unwrap().up_fin;
        if up_fin {
            let deadline = Instant::now() + relay.cfg.transport.control_request_timeout;
            relay.wait_state(&stop, deadline, RelayState::normal_close_confirmed);
        }
        stop.store(true, Ordering::Relaxed);
        relay.cv.notify_all();
        if relay.state.lock().unwrap().error.is_some() {
            let _ = local.shutdown(std::net::Shutdown::Both);
        }
        if let Some(h) = up {
            let _ = h.join();
        }
        if let Some(h) = ctl {
            let _ = h.join();
        }
        if relay.state.lock().unwrap().normal_close_confirmed() {
            relay.record_end_fault("control", &Error::local("closed_normal"));
        }
        let terminal_decided = std::time::SystemTime::now();
        let _ = local.shutdown(std::net::Shutdown::Both);
        drop(local);
        let local_closed = std::time::SystemTime::now();
        relay.log_termination(terminal_decided, local_closed);
        relay.metrics.unregister_ingress(gauge_id);
        let g = relay.state.lock().unwrap();
        // A normal FIN/FIN close is already settled at the egress. Any other
        // termination must release the remote session; DELETE is idempotent
        // and the egress tombstone makes late cleanup safe.
        let cleanup =
            if g.owner_closed_normal || g.normal_close_confirmed() {
                None
            } else {
                // A session that ends without both FINs confirmed must release
                // the remote session even when no error was recorded (e.g. the
                // FIN confirmation did not arrive in time); otherwise the egress
                // keeps it until its own timeouts.
                Some(g.error.clone().unwrap_or_else(|| {
                    Error::local("session ended before both FINs were confirmed")
                }))
            };
        let cleanup_epoch = g.epoch;
        let cleanup_mode = g.mode;
        let cleanup_recovering = g.recovery_deadline.is_some();
        drop(g);
        if cleanup.is_some() {
            let _cleanup_track = relay.cleanups.as_ref().map(|c| c.track());
            let _cleanup_timer = relay.metrics.operation_timer("ingress", "cleanup");
            let cleanup_control = relay.control();
            let run_cleanup = || {
                super::serve::cleanup::cleanup_with_failover(
                    &relay.peer,
                    cleanup_control.client.clone(),
                    &cleanup_control,
                    &relay.sid,
                    &relay.token,
                    &relay.owner_instance,
                    cleanup_epoch,
                    cleanup_recovering,
                    relay.cfg.transport.control_request_timeout,
                )
            };
            let cleanup_result = if let Some(resources) = relay.metrics.resource_manager() {
                resources.mark_instrumented("cleanup");
                match resources
                    .cleanup
                    .acquire_timeout(1, Some(relay.cfg.transport.control_request_timeout))
                {
                    Ok(_lease) => run_cleanup(),
                    Err(_) => super::serve::cleanup::CleanupResult::Unknown,
                }
            } else {
                run_cleanup()
            };
            match cleanup_result {
                super::serve::cleanup::CleanupResult::Confirmed => {
                    relay.metrics.record_session_event(
                        "ingress",
                        "cleanup",
                        "success",
                        cleanup_mode.as_str(),
                        "none",
                    );
                }
                super::serve::cleanup::CleanupResult::Unknown => {
                    relay.metrics.record_session_event(
                        "ingress",
                        "cleanup",
                        "unknown",
                        cleanup_mode.as_str(),
                        "none",
                    );
                    relay.metrics.remote_cleanup_unknown();
                    crate::egress::log_debug(&format!(
                        "remote cleanup outcome unknown for session {}",
                        relay.sid
                    ));
                }
                super::serve::cleanup::CleanupResult::Failed => {
                    relay.metrics.record_session_event(
                        "ingress",
                        "cleanup",
                        "failed",
                        cleanup_mode.as_str(),
                        "none",
                    );
                    relay.metrics.remote_cleanup_failed();
                    crate::egress::log_debug(&format!(
                        "remote cleanup failed for session {}",
                        relay.sid
                    ));
                }
            }
        } else {
            relay.metrics.record_session_event(
                "ingress",
                "cleanup",
                "not_needed",
                cleanup_mode.as_str(),
                "none",
            );
        }
        let g = relay.state.lock().unwrap();
        let error = g.error.clone();
        let mode = g.mode;
        let normal = g.up_fin && g.down_fin && g.down_fin_acked;
        let recovering = g.recovery_deadline.is_some();
        drop(g);
        let reason = if normal {
            "normal"
        } else {
            error
                .as_ref()
                .map(super::errors::reason_category)
                .unwrap_or("failed")
        };
        relay
            .metrics
            .record_session_event("ingress", "terminate", reason, mode.as_str(), "none");
        super::termination::count_termination(
            &relay.metrics,
            reason,
            relay.recovery_enabled,
            recovering,
        );
        // Every failure is the caller's business, including the local ones.
        // A local error must not be broadcast to the peer (`fail` already keeps
        // it off the wire), but it still ended the session: reporting `Ok` here
        // made a relay that died mid-stream indistinguishable from a clean
        // close, so the log said `err=None` while the client saw a reset.
        match error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn log_termination(&self, decided: std::time::SystemTime, local_closed: std::time::SystemTime) {
        let g = self.state.lock().unwrap();
        let normal = g.up_fin && g.down_fin && g.down_fin_acked;
        let reason = if normal {
            "normal"
        } else {
            g.error
                .as_ref()
                .map(super::errors::reason_category)
                .unwrap_or("failed")
        };
        let recovering = g.carrier_lost && g.recovery_deadline.is_some();
        let record = super::termination::Termination {
            session: self.sid.clone(),
            peer: self.peer.id.clone(),
            endpoint: self.endpoint_id(),
            owner: self.owner_instance.clone(),
            epoch: g.epoch,
            transport: g.mode.as_str(),
            recovery_enabled: self.recovery_enabled,
            attempts: g.recovery_attempts,
            deadline: g
                .recovery_deadline
                .filter(|_| g.carrier_lost)
                .map(super::termination::wall),
            outcome_unknown: g.outcome_unknown,
            reason,
            fault_source: g.fault_source.clone(),
            fault_reason: g.fault_reason,
            fault_time: g.fault_time,
            terminal: if normal {
                decided
            } else {
                g.terminal_at.unwrap_or(decided)
            },
            local_closed,
        };
        drop(g);
        let record = record.settle(recovering);
        let close = record
            .local_closed
            .duration_since(record.terminal)
            .unwrap_or_default();
        self.metrics.client_closed(close.as_millis() as i64);
        self.metrics
            .observe_operation("ingress", "local_close", close);
        record.log();
    }

    fn upstream(&self, mut sock: TcpStream, writer: SharedWriter, stop: Arc<AtomicBool>) {
        let frame = self
            .cfg
            .transport
            .frame_size
            .min(self.limits.max_frame_size);
        let mut buf = vec![0u8; frame];
        if !self.await_attached(&stop) {
            return;
        }
        let payload_budget = self.metrics.resource_manager().map(|r| r.payload.clone());
        loop {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            // Upstream window: never more than up_window_bytes ahead of what
            // the peer confirmed.
            {
                let mut g = self.state.lock().unwrap();
                while !g.closed
                    && !stop.load(Ordering::Relaxed)
                    && g.up_next.saturating_sub(g.up_acked) >= self.limits.up_window_bytes
                {
                    g = self.cv.wait(g).unwrap();
                }
                if g.closed || stop.load(Ordering::Relaxed) {
                    return;
                }
            }
            let mut cost = match &payload_budget {
                Some(budget) => match self.take_payload(budget, frame, &stop) {
                    Some(lease) => Some(lease),
                    None => return,
                },
                None => None,
            };
            let n = match sock.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    continue
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    self.fail(Error::local(format!(
                        "local client socket error: read: {e}"
                    )));
                    return;
                }
            };
            let offset = {
                let mut g = self.state.lock().unwrap();
                let o = g.up_next;
                let Some(next) = o.checked_add(n as u64) else {
                    drop(g);
                    self.fail(Error::new(
                        wire::ERR_FRAME_CONFLICT,
                        "upstream offset overflow",
                    ));
                    return;
                };
                g.up_next = next;
                if let Some(lease) = cost.as_mut() {
                    lease.release_part(frame.saturating_sub(n) as i64);
                }
                g.up_frames.push_back(RetainedUpFrame {
                    offset: o,
                    end: next,
                    payload: buf[..n].to_vec(),
                    _cost: cost.take().map(Arc::new),
                });
                o
            };
            {
                let mut g = self.state.lock().unwrap();
                g.tx_blocked = true;
                drop(g);
                self.cv.notify_all();
            }
            let frame_end = offset + n as u64;
            let mut backpressure_deadline = None;
            let mut backpressure_delay = Duration::from_millis(25);
            loop {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                // Keep the epoch snapshot and its write on the same side of a
                // carrier handoff. Otherwise recovery could replace the writer
                // after this snapshot, sending an old-epoch frame on the new
                // carrier and causing the peer to close the session.
                let handoff = self.carrier_handoff.lock().unwrap();
                let (epoch, mode, carrier_lost, closed) = {
                    let g = self.state.lock().unwrap();
                    (g.epoch, g.mode, g.carrier_lost, g.closed)
                };
                if carrier_lost || closed {
                    {
                        let mut g = self.state.lock().unwrap();
                        g.tx_blocked = false;
                    }
                    self.cv.notify_all();
                    drop(handoff);
                    if closed || !self.wait_for_recovery(&stop) {
                        return;
                    }
                    if self.upstream_acked_at_least(frame_end) {
                        break;
                    }
                    continue;
                }
                let send_result = if mode == wire::Mode::Ws {
                    match self.acquire_codec_lease(n.saturating_add(wire::WS_HEADER_LEN)) {
                        Ok(lease) => {
                            let result = writer.send_data(epoch, offset, &buf[..n]);
                            drop(lease);
                            result
                        }
                        Err(error) => Err(error),
                    }
                } else {
                    writer.send_data(epoch, offset, &buf[..n])
                };
                drop(handoff);
                {
                    let mut g = self.state.lock().unwrap();
                    g.tx_blocked = false;
                    drop(g);
                    self.cv.notify_all();
                }
                if send_result.is_ok() {
                    self.note_up_sent(epoch, frame_end);
                }
                match send_result {
                    Ok(Some(ack)) => {
                        if !self.advance_up_ack(ack) {
                            return;
                        }
                        break;
                    }
                    Ok(None) => break,
                    Err(e) if self.is_carrier_failure(&e) => {
                        self.record_ingress_fault("upstream", &e);
                        self.signal_carrier_loss();
                        if !self.recovery_enabled {
                            return;
                        }
                        if !self.wait_for_recovery(&stop) {
                            return;
                        }
                        if self.upstream_acked_at_least(frame_end) {
                            break;
                        }
                    }
                    Err(e) if is_confirmed_duplicate_frame(&e) => {
                        // A peer returns this only when the complete frame ends
                        // at or before its confirmed receipt floor. The original
                        // POST may have succeeded while its response was lost;
                        // reconcile only this exact local frame boundary.
                        if !self.advance_up_ack(frame_end) {
                            return;
                        }
                        break;
                    }
                    Err(e)
                        if e.code == wire::ERR_STALE_EPOCH
                            && self.stale_generation_in_handoff(epoch) =>
                    {
                        // A stale response is retryable only when this send was
                        // made by a generation that is known to be handing over
                        // (or has already been replaced).  It must never relax
                        // the epoch or offset checks for an otherwise-live
                        // carrier.
                        if !self.recovery_enabled {
                            self.fail(e);
                            return;
                        }
                        if !self.wait_for_recovery(&stop) {
                            return;
                        }
                        if self.upstream_acked_at_least(frame_end) {
                            break;
                        }
                    }
                    Err(e)
                        if e.code == wire::ERR_WINDOW_EXCEEDED
                            && e.retryable
                            && !e.session_closed =>
                    {
                        let deadline = *backpressure_deadline.get_or_insert_with(|| {
                            Instant::now() + self.cfg.transport.backpressure_timeout
                        });
                        let now = Instant::now();
                        if now >= deadline {
                            self.fail(e);
                            return;
                        }
                        if self.recovery_enabled && self.carrier_is_lost() {
                            if !self.wait_for_recovery(&stop) {
                                return;
                            }
                            if self.upstream_acked_at_least(frame_end) {
                                break;
                            }
                            continue;
                        }
                        let delay = e
                            .retry_after
                            .max(backpressure_delay)
                            .min(deadline.saturating_duration_since(now));
                        std::thread::sleep(delay);
                        backpressure_delay = backpressure_delay
                            .saturating_mul(2)
                            .min(Duration::from_millis(200));
                    }
                    Err(e) => {
                        self.fail(e);
                        return;
                    }
                }
            }
        }
        // Local client half-closed. Before telling the peer, wait until every
        // upstream byte is confirmed applied: the FIN travels on the control
        // connection, which has no ordering relationship with the data
        // carrier, so a FIN that overtook the last frames would name an offset
        // the peer has not reached.
        let deadline = Instant::now() + self.cfg.transport.control_request_timeout;
        loop {
            {
                let g = self.state.lock().unwrap();
                if g.closed || g.up_acked >= g.up_next {
                    break;
                }
            }
            if Instant::now() >= deadline {
                break;
            }
            let guard = self.state.lock().unwrap();
            let remaining = deadline.saturating_duration_since(Instant::now());
            let _guard_and_timeout = self
                .cv
                .wait_timeout_while(guard, remaining, |g| !g.closed && g.up_acked < g.up_next)
                .unwrap();
        }
        let (final_offset, epoch, stream) = {
            let mut g = self.state.lock().unwrap();
            g.up_fin = true;
            (g.up_next, g.epoch, g.stream.clone())
        };
        let fin_started = Instant::now();
        let fin_deadline = fin_started + self.cfg.transport.control_request_timeout;
        let mut fin_attempt = 0u32;
        let fin_result = loop {
            let result = self
                .control()
                .fin(&self.sid, &self.token, epoch, &stream, final_offset);
            if let Err(e) = &result {
                if super::errors::safe_retry(e) {
                    let backoff = if e.retry_after.is_zero() {
                        Duration::from_millis(25u64 << fin_attempt.min(4))
                    } else {
                        e.retry_after
                    };
                    let wait = backoff.min(fin_deadline.saturating_duration_since(Instant::now()));
                    if !wait.is_zero() && !self.state.lock().unwrap().closed {
                        std::thread::sleep(wait);
                        fin_attempt = fin_attempt.saturating_add(1);
                        continue;
                    }
                }
            }
            break result;
        };
        let fin_elapsed = fin_started.elapsed();
        self.metrics
            .observe_operation("ingress", "control", fin_elapsed);
        self.metrics.observe_phase(
            &self.peer.id,
            &self.endpoint_id(),
            "control",
            fin_result.is_ok(),
            fin_elapsed,
        );
        match fin_result {
            Ok(response) => {
                let mut g = self.state.lock().unwrap();
                g.up_fin_applied |= response.up_fin_applied;
                // Learn whether our down-FIN ACK was confirmed as well.
                if !g.normal_close_confirmed() {
                    g.ack_requested = true;
                }
            }
            Err(e) => {
                // A closed session needs no FIN; anything else ends it.
                if e.code != wire::ERR_SESSION_CLOSED && e.code != wire::ERR_SESSION_NOT_FOUND {
                    self.record_ingress_fault("control", &e);
                    self.fail(e);
                }
            }
        }
        self.cv.notify_all();
    }

    fn take_payload(
        &self,
        budget: &Arc<Budget>,
        amount: usize,
        stop: &AtomicBool,
    ) -> Option<BudgetLease> {
        let amount = i64::try_from(amount).unwrap_or(i64::MAX);
        let deadline = Instant::now() + self.cfg.transport.backpressure_timeout;
        loop {
            if stop.load(Ordering::Relaxed) || self.state.lock().unwrap().closed {
                return None;
            }
            let slice = deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(50));
            match budget.acquire_timeout(amount, Some(slice)) {
                Ok(lease) => return Some(lease),
                Err(crate::resource::budget::BudgetError::Timeout) if Instant::now() < deadline => {
                }
                Err(_) => {
                    self.record_ingress_fault(
                        "upstream",
                        &Error::new(wire::ERR_BUFFER_EXHAUSTED, "payload budget"),
                    );
                    self.fail(
                        Error::new(
                            wire::ERR_BUFFER_EXHAUSTED,
                            "upstream payload budget exhausted",
                        )
                        .closed(true),
                    );
                    return None;
                }
            }
        }
    }

    fn downstream(
        &self,
        sock: TcpStream,
        mut reader: Box<dyn CarrierReader>,
        writer: SharedWriter,
    ) -> Box<dyn CarrierReader> {
        let done = AtomicBool::new(false);
        let interrupted = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let release = |handle: Box<dyn crate::net::Conn>| {
                let (done, interrupted) = (&done, &interrupted);
                std::thread::Builder::new()
                    .stack_size(crate::util::CONNECTION_STACK)
                    .spawn_scoped(scope, move || {
                        self.release_after_fin(handle, done, interrupted)
                    })
                    .is_ok()
            };
            self.downstream_loop(sock, &mut reader, &writer, &release, &interrupted);
            done.store(true, Ordering::SeqCst);
            self.cv.notify_all();
        });
        reader
    }

    fn release_after_fin(
        &self,
        handle: Box<dyn crate::net::Conn>,
        done: &AtomicBool,
        interrupted: &AtomicBool,
    ) {
        let grace = self.cfg.transport.control_request_timeout;
        let mut up_fin_at: Option<Instant> = None;
        let mut g = self.state.lock().unwrap();
        loop {
            if done.load(Ordering::SeqCst) {
                return;
            }
            if g.closed || g.normal_close_confirmed() {
                break;
            }
            if g.up_fin && up_fin_at.get_or_insert_with(Instant::now).elapsed() >= grace {
                break;
            }
            g = self
                .cv
                .wait_timeout(g, Duration::from_millis(20))
                .unwrap()
                .0;
        }
        drop(g);
        interrupted.store(true, Ordering::SeqCst);
        let _ = handle.shutdown_both();
    }

    fn downstream_loop(
        &self,
        mut sock: TcpStream,
        reader: &mut Box<dyn CarrierReader>,
        writer: &SharedWriter,
        release: &dyn Fn(Box<dyn crate::net::Conn>) -> bool,
        interrupted: &AtomicBool,
    ) {
        let _ = sock.set_write_timeout(Some(Duration::from_secs(60)));
        // After the down FIN the loop keeps reading until the upstream half
        // settles too (see release_after_fin). Without a release helper it
        // ends once the upstream FIN is out, as before.
        let mut fin_delivered = false;
        let mut released = false;
        let mut start_release = |reader: &dyn CarrierReader, fin_delivered: &mut bool| {
            *fin_delivered = true;
            if !self.state.lock().unwrap().up_fin {
                if let Some(handle) = reader.interrupt_handle() {
                    released = release(handle);
                }
            }
            released
        };
        let mut keep_reading = false;
        loop {
            {
                let g = self.state.lock().unwrap();
                if g.closed || (fin_delivered && !keep_reading && g.up_fin) {
                    break;
                }
            }
            if interrupted.load(Ordering::SeqCst) {
                break;
            }
            // A carrier loss signalled by another pump (upstream write failure,
            // the control loop's liveness watchdog) is handled at once, even
            // while the carrier keeps delivering messages.
            let lost = self.state.lock().unwrap().carrier_lost;
            if lost {
                let cause = Error::new(wire::ERR_BACKEND_LOST, "carrier lost");
                if self.recover_carrier(reader, writer, cause.clone()) {
                    continue;
                }
                self.fail(cause);
                break;
            }
            let queued = self.state.lock().unwrap().pending_down.pop_front();
            let incoming = match queued {
                Some(item) => Ok(item),
                None => reader.recv(),
            };
            if matches!(
                incoming,
                Ok(Incoming::Data { .. }) | Ok(Incoming::Control(_))
            ) {
                self.state.lock().unwrap().last_activity = Instant::now();
            }
            match incoming {
                Ok(Incoming::Data {
                    epoch,
                    offset,
                    payload,
                }) => {
                    let mode = self.state.lock().unwrap().mode;
                    let codec_charge = match mode {
                        wire::Mode::Ws => payload.len().saturating_add(wire::WS_HEADER_LEN),
                        _ => payload.len(),
                    };
                    let codec_lease = if let Some(fast) = self.try_codec_lease(codec_charge) {
                        fast
                    } else {
                        {
                            let mut state = self.state.lock().unwrap();
                            state.rx_blocked = true;
                            state.rx_blocked_at = Some(Instant::now());
                            state.rx_block_reason = "global_buffer";
                            self.cv.notify_all();
                        }
                        let lease = self.acquire_codec_lease(codec_charge);
                        {
                            let mut state = self.state.lock().unwrap();
                            state.rx_blocked = false;
                            state.rx_blocked_at = None;
                            state.rx_block_reason = "";
                            state.last_activity = Instant::now();
                            self.cv.notify_all();
                        }
                        match lease {
                            Ok(lease) => lease,
                            Err(error) => {
                                self.fail(error);
                                break;
                            }
                        }
                    };
                    let mut g = self.state.lock().unwrap();
                    if epoch != g.epoch {
                        let expected = g.epoch;
                        drop(g);
                        self.fail(Error::new(
                            wire::ERR_STALE_EPOCH,
                            format!("downstream frame epoch {epoch}, expected {expected}"),
                        ));
                        break;
                    }
                    if g.down_delivered != offset {
                        drop(g);
                        self.fail(Error::new(
                            wire::ERR_OFFSET_GAP,
                            format!("downstream frame at {offset}, expected {}", {
                                self.state.lock().unwrap().down_delivered
                            }),
                        ));
                        break;
                    }
                    let n = payload.len() as u64;
                    let Some(delivered) = g.down_delivered.checked_add(n) else {
                        drop(g);
                        self.fail(Error::new(
                            wire::ERR_OFFSET_GAP,
                            "downstream offset overflow",
                        ));
                        break;
                    };
                    g.down_delivered = delivered;
                    g.down_frames = g.down_frames.saturating_add(1);
                    let delivered = g.down_delivered;
                    let done = g.down_fin && g.down_fin_offset == Some(delivered);
                    drop(g);
                    {
                        let mut state = self.state.lock().unwrap();
                        state.rx_blocked = true;
                        state.rx_blocked_at = Some(Instant::now());
                        state.rx_block_reason = "local_socket_write";
                        self.cv.notify_all();
                    }
                    let write_result = sock.write_all(&payload);
                    drop(codec_lease);
                    {
                        let mut state = self.state.lock().unwrap();
                        state.rx_blocked = false;
                        state.rx_blocked_at = None;
                        state.rx_block_reason = "";
                        state.last_activity = Instant::now();
                        self.cv.notify_all();
                    }
                    if let Err(e) = write_result {
                        self.fail(Error::local(format!(
                            "local client socket error: write: {e}"
                        )));
                        break;
                    }
                    self.metrics.downstream(payload.len());
                    self.sse_down_ack.store(delivered, Ordering::Relaxed);
                    self.schedule_threshold_ack();
                    if done {
                        let _ = sock.shutdown(std::net::Shutdown::Write);
                        self.request_ack();
                        keep_reading = start_release(reader.as_ref(), &mut fin_delivered);
                    }
                }
                Ok(Incoming::Control(c)) => match c.kind {
                    ControlKind::AckUp => {
                        if !self.accept_ack_up(&c) {
                            break;
                        }
                    }
                    ControlKind::Ping => {
                        let mut g = self.state.lock().unwrap();
                        g.heartbeat_nonce = c.nonce.unwrap_or_default();
                    }
                    ControlKind::Fin => {
                        let mut g = self.state.lock().unwrap();
                        g.down_fin = true;
                        g.down_fin_offset = c.final_offset;
                        let delivered = g.down_delivered;
                        let finished = c.final_offset == Some(delivered);
                        drop(g);
                        if finished && !fin_delivered {
                            let _ = sock.shutdown(std::net::Shutdown::Write);
                            self.request_ack();
                            keep_reading = start_release(reader.as_ref(), &mut fin_delivered);
                        }
                    }
                    ControlKind::Error => {
                        self.fail(Error {
                            code: c.code.unwrap_or_default(),
                            message: "peer ended the session".to_string(),
                            retryable: c.retryable,
                            session_closed: true,
                            remote_status: None,
                            trusted: false,
                            retry_after: Duration::ZERO,
                        });
                        break;
                    }
                    ControlKind::Ready => {}
                },
                Ok(Incoming::Idle) => {
                    let loss = {
                        let g = self.state.lock().unwrap();
                        if g.closed {
                            break;
                        }
                        g.carrier_lost
                    };
                    if loss {
                        let cause = Error::new(wire::ERR_BACKEND_LOST, "carrier write failed");
                        if self.recover_carrier(reader, writer, cause.clone()) {
                            continue;
                        }
                        self.fail(cause);
                        break;
                    }
                }
                Ok(Incoming::Closed(_)) | Err(_) if interrupted.load(Ordering::SeqCst) => {
                    // The settled session's carrier was released on purpose.
                    break;
                }
                Ok(Incoming::Closed(e)) => {
                    let g = self.state.lock().unwrap();
                    if g.down_fin && g.up_fin {
                        drop(g);
                        self.record_end_fault("data", &Error::local("carrier closed"));
                    } else {
                        drop(g);
                        let carrier_error = e.unwrap_or_else(|| {
                            Error::new(wire::ERR_BACKEND_LOST, "carrier closed").closed(true)
                        });
                        self.record_ingress_fault("data", &carrier_error);
                        if self.recover_carrier(reader, writer, carrier_error.clone()) {
                            continue;
                        }
                        self.fail(carrier_error);
                    }
                    break;
                }
                Err(e) => {
                    if std::env::var("DBBRIDGE_TRACE").is_ok() {
                        eprintln!("downstream recv error: {e}");
                    }
                    self.record_ingress_fault("data", &e);
                    if self.is_carrier_failure(&e)
                        && self.recover_carrier(reader, writer, e.clone())
                    {
                        continue;
                    }
                    self.fail(e);
                    break;
                }
            }
        }
        self.cv.notify_all();
    }

    fn schedule_threshold_ack(&self) {
        let bytes_threshold =
            down_bytes_ack_threshold(self.cfg.transport.ack_batch_bytes, &self.limits);
        let frame_threshold = down_frames_ack_threshold(&self.limits);
        let mut g = self.state.lock().unwrap();
        let bytes = g.down_delivered.saturating_sub(g.down_reported);
        let frames = g.down_frames.saturating_sub(g.down_frames_reported);
        if bytes > 0
            && !g.ack_requested
            && (bytes_threshold == 0 || bytes >= bytes_threshold || frames >= frame_threshold)
        {
            g.ack_requested = true;
            drop(g);
            self.cv.notify_all();
        }
    }

    fn request_ack(&self) {
        self.state.lock().unwrap().ack_requested = true;
        self.cv.notify_all();
    }

    fn attach_failed(
        &self,
        route: &Route,
        mode: wire::Mode,
        error: &Error,
        request: &mut Option<crate::session::recovery::ResumeRequest>,
        attempted: &mut HashSet<String>,
    ) {
        if let Some(table) = self.endpoints.as_ref() {
            if self.is_carrier_failure(error) || super::link::first_attach_carrier_failure(error) {
                table.record_transport_failure(
                    &self.peer.id,
                    &route.endpoint.id,
                    mode,
                    self.peer.failover.cooldown,
                );
                if mode == wire::Mode::Ws {
                    if let Some(cache) = &self.prechecks {
                        let key = format!(
                            "{}|{}|{}",
                            self.peer.id, route.endpoint.id, self.owner_instance
                        );
                        cache.lock().unwrap().remove(&key);
                    }
                }
            }
        }
        *request = None;
        attempted.clear();
    }

    fn is_carrier_failure(&self, e: &Error) -> bool {
        carrier_failure(e)
    }

    fn signal_carrier_loss(&self) {
        let mut g = self.state.lock().unwrap();
        g.carrier_lost = true;
        g.recovery_deadline = Some(recovery_deadline(
            g.recovery_deadline,
            Instant::now(),
            self.recovery_grace,
        ));
        drop(g);
        self.cv.notify_all();
    }

    fn carrier_is_lost(&self) -> bool {
        self.state.lock().unwrap().carrier_lost
    }

    fn stale_generation_in_handoff(&self, sent_epoch: u64) -> bool {
        if !self.recovery_enabled {
            return false;
        }
        let g = self.state.lock().unwrap();
        g.carrier_lost || g.recovery_deadline.is_some() || g.epoch != sent_epoch
    }

    fn upstream_acked_at_least(&self, end: u64) -> bool {
        self.state.lock().unwrap().up_acked >= end
    }

    fn wait_for_recovery(&self, stop: &AtomicBool) -> bool {
        let mut g = self.state.lock().unwrap();
        while g.carrier_lost && !g.closed && !stop.load(Ordering::Relaxed) {
            g = self.cv.wait(g).unwrap();
        }
        !g.closed && !stop.load(Ordering::Relaxed)
    }

    fn redial(
        &self,
        route: &Route,
        epoch: u64,
        mode: wire::Mode,
        deadline: Instant,
    ) -> Result<RedialedCarrier> {
        let token = route.control.current_token()?;
        let client = route.control.client.clone();
        let remaining = || {
            deadline
                .saturating_duration_since(Instant::now())
                .max(Duration::from_millis(1))
        };
        match mode {
            wire::Mode::Ws => {
                let headers = vec![
                    (wire::H_PEER_AUTH.to_string(), format!("Bearer {token}")),
                    (wire::H_SESSION_TOKEN.to_string(), self.token.clone()),
                    (wire::H_INSTANCE_ID.to_string(), self.owner_instance.clone()),
                    (wire::H_WS_PURPOSE.to_string(), "session".to_string()),
                    (wire::H_WS_SESSION_ID.to_string(), self.sid.clone()),
                    (wire::H_WS_EPOCH.to_string(), epoch.to_string()),
                ];
                let timeout = self
                    .cfg
                    .transport
                    .ws_handshake_timeout
                    .max(Duration::from_secs(10))
                    .min(remaining());
                let resource_leases = client.acquire_data_connection_leases(timeout)?;
                let a = crate::transport::ws_carrier::dial_session_via_with_leases(
                    &*client.dialer(),
                    &route.endpoint.url,
                    &headers,
                    timeout,
                    resource_leases,
                )?;
                if a.ready.session_id != self.sid
                    || a.ready.instance_id != self.owner_instance
                    || a.ready.epoch != epoch
                    || a.ready.transport.as_deref() != Some("ws")
                    || a.ready.resume_request_id.is_none()
                {
                    return Err(Error::new(
                        wire::ERR_WS_PROTOCOL_ERROR,
                        "resume ready mismatch",
                    ));
                }
                Ok((
                    Box::new(a.reader),
                    Box::new(a.writer),
                    a.ready,
                    a.implicit_ready,
                ))
            }
            wire::Mode::HttpSse => {
                let path = format!(
                    "{}/{}/events?epoch={}",
                    wire::PATH_SESSIONS,
                    self.sid,
                    epoch
                );
                let headers = vec![
                    (wire::H_PEER_AUTH.to_string(), format!("Bearer {token}")),
                    (wire::H_SESSION_TOKEN.to_string(), self.token.clone()),
                    (wire::H_INSTANCE_ID.to_string(), self.owner_instance.clone()),
                    ("Accept".to_string(), "text/event-stream".to_string()),
                ];
                let (conn, resp) = client.stream(
                    &route.endpoint.url,
                    "GET",
                    &path,
                    &headers,
                    self.cfg.transport.failure_detect_timeout.min(remaining()),
                )?;
                if resp.status != 200 {
                    if let Some(e) = wire::ErrorBody::parse(&String::from_utf8_lossy(&resp.body)) {
                        return Err(e.to_error().remote_status(resp.status));
                    }
                    return Err(Error::local(format!(
                        "carrier attach: resume event stream answered {}",
                        resp.status
                    )));
                }
                let implicit = resp
                    .header(wire::H_IMPLICIT_READY)
                    .map(|v| v.trim() == "1")
                    .unwrap_or(false);
                let mut r = crate::transport::sse_carrier::SseEventReader::new(
                    conn,
                    self.limits.max_frame_size,
                    epoch,
                );
                let ready = loop {
                    match r.recv()? {
                        Incoming::Control(c) if c.kind == ControlKind::Ready => break c,
                        Incoming::Idle if Instant::now() < deadline => continue,
                        Incoming::Idle => {
                            return Err(Error::local(
                                "resume SSE ready not received before the recovery deadline",
                            ))
                        }
                        _ => {
                            return Err(Error::new(
                                wire::ERR_PROTOCOL_MISMATCH,
                                "resume SSE ready missing",
                            ))
                        }
                    }
                };
                if ready.session_id != self.sid
                    || ready.instance_id != self.owner_instance
                    || ready.epoch != epoch
                    || ready.transport.as_deref() != Some("http-sse")
                    || ready.resume_request_id.is_none()
                {
                    return Err(Error::new(
                        wire::ERR_PROTOCOL_MISMATCH,
                        "resume ready mismatch",
                    ));
                }
                let g = self.state.lock().unwrap();
                self.sse_down_ack.store(g.down_delivered, Ordering::Relaxed);
                self.sse_up_confirm.store(g.up_acked, Ordering::Relaxed);
                let w = crate::transport::sse_carrier::SseUpPoster::new(
                    client,
                    route.endpoint.url.clone(),
                    self.sid.clone(),
                    route.control.token_provider.clone(),
                    self.token.clone(),
                    self.owner_instance.clone(),
                    epoch,
                    ready.stream_id.clone(),
                    self.sse_down_ack.clone(),
                    self.sse_up_confirm.clone(),
                );
                drop(g);
                Ok((Box::new(r), Box::new(w), ready, implicit))
            }
        }
    }

    fn ready_ack(&self, control: &ControlClient, epoch: u64, stream: &str) -> Result<()> {
        self.ready_ack_with_nonce(control, epoch, stream, String::new(), None)
    }

    fn ready_ack_with_nonce(
        &self,
        control: &ControlClient,
        epoch: u64,
        stream: &str,
        nonce: String,
        up_confirmed_offset: Option<u64>,
    ) -> Result<()> {
        let g = self.state.lock().unwrap();
        let req = AckRequest {
            down_delivered_offset: g.down_delivered,
            up_confirmed_offset: up_confirmed_offset.unwrap_or(g.up_acked),
            down_fin_applied: g.down_fin && g.down_fin_offset == Some(g.down_delivered),
            ready_received: true,
            heartbeat_nonce: nonce,
            probe_id: crate::util::random_hex(8).map_err(crate::util::random_error)?,
            data_rx_blocked: false,
            data_tx_blocked: false,
            backpressure_reason: "none".to_string(),
        };
        drop(g);
        control
            .ack(&self.sid, &self.token, epoch, stream, &req)
            .map(|_| ())
    }

    /// Recovers only a lost data carrier. The deadline is anchored at the
    /// first loss and the request id is deliberately kept across all retries.
    fn recover_carrier(
        &self,
        reader: &mut Box<dyn CarrierReader>,
        writer: &SharedWriter,
        cause: Error,
    ) -> bool {
        if !self.recovery_enabled {
            return false;
        }
        let _recovery_timer = self.metrics.operation_timer("ingress", "recovery");
        let from_mode = self.state.lock().unwrap().mode;
        let deadline = {
            let mut g = self.state.lock().unwrap();
            g.recovery_deadline = Some(recovery_deadline(
                g.recovery_deadline,
                Instant::now(),
                self.recovery_grace,
            ));
            g.carrier_lost = true;
            g.recovery_deadline.unwrap()
        };
        let _recovery_lease = if let Some(resources) = self.metrics.resource_manager() {
            resources.mark_instrumented("recovery");
            match resources
                .recovery
                .acquire_timeout(1, Some(deadline.saturating_duration_since(Instant::now())))
            {
                Ok(lease) => Some(lease),
                Err(_) => {
                    self.fail(Error::new(
                        wire::ERR_QUOTA_EXCEEDED,
                        "recovery budget exhausted",
                    ));
                    return false;
                }
            }
        } else {
            None
        };
        let override_mode = self.resume_mode.lock().unwrap().take();
        self.cool_dropped_carrier(from_mode, &cause);
        let strategy = match override_mode {
            Some(mode) => vec![mode],
            None if self.endpoints.is_none() => vec![from_mode],
            None => self.policy_modes(),
        };
        let mut pending_request: Option<crate::session::recovery::ResumeRequest> = None;
        let mut attempted: HashSet<String> = HashSet::new();
        let mut confirmed_epoch: Option<u64> = None;
        let mut deadline = deadline;
        let mut attempt = 0u32;
        let trace = std::env::var_os("DBBRIDGE_TRACE").is_some();
        if trace {
            let epoch = self.state.lock().unwrap().epoch;
            eprintln!(
                "ingress recovery started session={} epoch={} cause={}: {}",
                self.sid, epoch, cause.code, cause.message
            );
        }
        let mut last = cause;
        let recovery_started = Instant::now();
        {
            let mut g = self.state.lock().unwrap();
            if g.fault_time.is_none() {
                g.fault_time = Some(std::time::SystemTime::now());
            }
        }
        while Instant::now() < deadline {
            if let Some(e) = {
                let g = self.state.lock().unwrap();
                g.closed.then(|| g.error.clone()).flatten()
            } {
                last = e;
                break;
            }
            attempt = attempt.saturating_add(1);
            let policy = match &pending_request {
                Some(r) => vec![r.transport],
                None => strategy.clone(),
            };
            let (route, mode) = match self.choose_recovery_route(&policy, &attempted, deadline) {
                Ok(v) => v,
                Err(e) => {
                    if super::errors::fatal_error(&e) {
                        last = e;
                        break;
                    }
                    if trace {
                        eprintln!(
                            "ingress recovery found no candidate session={} error={}",
                            self.sid, e
                        );
                    }
                    attempted.clear();
                    self.recovery_pause(attempt, &policy, deadline);
                    continue;
                }
            };
            if pending_request.is_none() {
                let request_id = match crate::util::random_id(24) {
                    Ok(id) => id,
                    Err(e) => {
                        self.fail(crate::util::random_error(e));
                        return false;
                    }
                };
                let g = self.state.lock().unwrap();
                pending_request = Some(crate::session::recovery::ResumeRequest {
                    resume_request_id: request_id,
                    expected_epoch: confirmed_epoch.unwrap_or(g.epoch),
                    ingress_instance_id: self.cfg.node.instance_id.clone(),
                    transport: mode,
                    known_up_ack_offset: g.up_acked,
                    up_next_offset: g.up_next,
                    down_delivered_offset: g.down_delivered,
                    up_fin: crate::session::recovery::ResumeFin {
                        seen: g.up_fin,
                        final_offset: g.up_fin.then_some(g.up_next),
                        applied: g.up_fin_applied,
                        acked: g.up_fin_applied,
                    },
                    down_fin: crate::session::recovery::ResumeFin {
                        seen: g.down_fin,
                        final_offset: g.down_fin_offset,
                        applied: g.down_fin_applied,
                        acked: g.down_fin_acked,
                    },
                });
            }
            let request = pending_request.clone().expect("resume request built above");
            let resume_started = Instant::now();
            {
                let mut g = self.state.lock().unwrap();
                g.recovery_attempts += 1;
                g.outcome_unknown = true;
            }
            let resume_result = route.control.resume(&self.sid, &self.token, &request);
            if resume_result.is_ok() {
                self.state.lock().unwrap().outcome_unknown = false;
            }
            let resume_elapsed = resume_started.elapsed();
            self.metrics.observe_phase(
                &self.peer.id,
                &route.endpoint.id,
                "recovery",
                resume_result.is_ok(),
                resume_elapsed,
            );
            let response = match resume_result {
                Ok(r) => {
                    if trace {
                        eprintln!(
                            "ingress resume accepted session={} endpoint={} epoch={} up_written={} ack_up={} down_from={}",
                            self.sid, route.endpoint.id, r.epoch, r.up_written_offset, r.ack_up_offset, r.down_replay_from
                        );
                    }
                    r
                }
                Err(e) => {
                    self.record_ingress_fault("control", &e);
                    last = e.clone();
                    if super::errors::fatal_error(&e)
                        || super::errors::terminal_remote(&e)
                        || (e.remote_status.is_none() && e.code == wire::ERR_PROTOCOL_MISMATCH)
                    {
                        if e.trusted && e.code == wire::ERR_SESSION_CLOSED {
                            let mut g = self.state.lock().unwrap();
                            g.owner_closed_normal = (g.up_fin && g.up_fin_applied && g.down_fin)
                                || e.message == wire::SESSION_CLOSED_NORMAL_MESSAGE;
                        }
                        break;
                    }
                    if !super::errors::safe_retry(&e) {
                        attempted.insert(route.endpoint.id.clone());
                    }
                    std::thread::sleep(Duration::from_millis(25));
                    continue;
                }
            };
            let peer_deadline = resume_started + response.resume_remaining;
            if peer_deadline < deadline {
                deadline = peer_deadline;
                self.state.lock().unwrap().recovery_deadline = Some(deadline);
            }
            confirmed_epoch = Some(response.epoch);
            if Instant::now() >= deadline {
                last = Error::local(format!(
                    "recovery deadline passed after resume: {}",
                    last.message
                ));
                break;
            }
            if response.down_replay_from != self.state.lock().unwrap().down_delivered {
                last = Error::new(wire::ERR_BAD_ACK, "resume downstream replay offset");
                break;
            }
            {
                let g = self.state.lock().unwrap();
                if response.session_id != self.sid || response.instance_id != self.owner_instance {
                    last = Error::new(wire::ERR_PROTOCOL_MISMATCH, "resume identity mismatch");
                    break;
                }
                if response.ack_up_offset > g.up_next {
                    last = Error::new(wire::ERR_BAD_ACK, "resume upstream acknowledgement");
                    break;
                }
            }
            if !self.advance_up_ack(response.ack_up_offset) {
                return false;
            }
            let (mut new_reader, new_writer, ready, implicit) =
                match self.redial(&route, response.epoch, response.transport, deadline) {
                    Ok(v) => v,
                    Err(e) => {
                        last = e.clone();
                        if !e.retryable && !self.is_carrier_failure(&e) {
                            break;
                        }
                        self.attach_failed(&route, mode, &e, &mut pending_request, &mut attempted);
                        std::thread::sleep(Duration::from_millis(25));
                        continue;
                    }
                };
            let new_writer = PendingCarrierWriter::new(new_writer);
            if trace {
                eprintln!(
                    "ingress resume carrier ready session={} epoch={} stream={} resume_id_match={}",
                    self.sid,
                    response.epoch,
                    ready.stream_id,
                    ready.resume_request_id.as_deref() == Some(request.resume_request_id.as_str())
                );
            }
            if ready.resume_request_id.as_deref() != Some(request.resume_request_id.as_str()) {
                last = Error::new(wire::ERR_PROTOCOL_MISMATCH, "resume request id mismatch");
                continue;
            }
            if implicit {
                // Recovery never accepts implicit-ready: the explicit ACK and
                // subsequent ping/echo are the generation barrier.
            }
            let barrier_timer = self.metrics.operation_timer("ingress", "barrier");
            let ack = self.ready_ack(&route.control, response.epoch, &ready.stream_id);
            if let Err(e) = ack {
                self.attach_failed(&route, mode, &e, &mut pending_request, &mut attempted);
                last = e;
                continue;
            }
            let mut pending_generation = VecDeque::new();
            let mut pending_bytes = 0u64;
            let mut expected_down = self.state.lock().unwrap().down_delivered;
            let nonce = loop {
                match new_reader.recv() {
                    Ok(Incoming::Control(c)) if c.kind == ControlKind::Ping => {
                        if trace {
                            eprintln!(
                                "ingress resume barrier ping session={} epoch={} nonce_present={}",
                                self.sid,
                                response.epoch,
                                c.nonce.as_ref().is_some_and(|n| !n.is_empty())
                            );
                        }
                        break c.nonce.unwrap_or_default();
                    }
                    Ok(Incoming::Control(c)) if c.kind == ControlKind::AckUp => {
                        if trace {
                            eprintln!(
                                "ingress resume barrier ack_up session={} offset={:?}",
                                self.sid, c.ack_up_offset
                            );
                        }
                        if !self.accept_ack_up(&c) {
                            return false;
                        }
                    }
                    Ok(Incoming::Data {
                        epoch,
                        offset,
                        payload,
                    }) => {
                        if trace {
                            eprintln!(
                                "ingress resume barrier data session={} epoch={} offset={} len={}",
                                self.sid,
                                epoch,
                                offset,
                                payload.len()
                            );
                        }
                        if epoch != response.epoch || offset != expected_down {
                            self.fail(Error::new(
                                wire::ERR_STALE_EPOCH,
                                "unexpected data frame during resume barrier",
                            ));
                            return false;
                        }
                        let n = payload.len() as u64;
                        let Some(next_bytes) = pending_bytes.checked_add(n) else {
                            self.fail(Error::new(
                                wire::ERR_FRAME_TOO_LARGE,
                                "resume data buffer overflow",
                            ));
                            return false;
                        };
                        let Some(next_offset) = expected_down.checked_add(n) else {
                            self.fail(Error::new(
                                wire::ERR_OFFSET_GAP,
                                "resume downstream offset overflow",
                            ));
                            return false;
                        };
                        if next_bytes > self.limits.down_buffer_bytes {
                            self.fail(Error::new(
                                wire::ERR_FRAME_TOO_LARGE,
                                "resume data exceeds downstream buffer",
                            ));
                            return false;
                        }
                        pending_bytes = next_bytes;
                        expected_down = next_offset;
                        pending_generation.push_back(Incoming::Data {
                            epoch,
                            offset,
                            payload,
                        });
                    }
                    Ok(Incoming::Control(c)) if c.kind == ControlKind::Fin => {
                        pending_generation.push_back(Incoming::Control(c));
                    }
                    Ok(Incoming::Control(c)) if c.kind == ControlKind::Error => {
                        let code = c
                            .code
                            .unwrap_or_else(|| wire::ERR_SESSION_CLOSED.to_string());
                        self.fail(Error::new(&code, "peer ended the session").closed(true));
                        return false;
                    }
                    Ok(Incoming::Idle) if Instant::now() < deadline => continue,
                    Ok(Incoming::Closed(error)) => {
                        last = error.unwrap_or_else(|| {
                            Error::new(wire::ERR_BACKEND_LOST, "carrier closed before resume ping")
                        });
                        break String::new();
                    }
                    Ok(_) => {
                        last = Error::new(wire::ERR_PROTOCOL_MISMATCH, "resume ping missing");
                        break String::new();
                    }
                    Err(e) => {
                        last = e;
                        break String::new();
                    }
                }
            };
            if nonce.is_empty() {
                if trace {
                    eprintln!(
                        "ingress resume barrier ended without ping session={} epoch={} last={}",
                        self.sid, response.epoch, last
                    );
                }
                self.attach_failed(&route, mode, &last, &mut pending_request, &mut attempted);
                continue;
            }
            let confirmed_up = {
                let g = self.state.lock().unwrap();
                g.up_acked.max(response.ack_up_offset)
            };
            if let Err(e) = self.ready_ack_with_nonce(
                &route.control,
                response.epoch,
                &ready.stream_id,
                nonce,
                Some(confirmed_up),
            ) {
                if trace {
                    eprintln!(
                        "ingress resume nonce ack failed session={} epoch={} up_confirmed={} error={}",
                        self.sid, response.epoch, confirmed_up, e
                    );
                }
                self.attach_failed(&route, mode, &e, &mut pending_request, &mut attempted);
                last = e;
                continue;
            }
            drop(barrier_timer);
            let replay = {
                let g = self.state.lock().unwrap();
                // ACK_UP events can advance the live ACK while the recovery
                // barrier is being drained. ResumeResponse is a snapshot from
                // before that barrier, so replay from whichever boundary is
                // farther ahead rather than rejecting a now-stale snapshot.
                let replay_from = response.up_written_offset.max(g.up_acked);
                let boundary = replay_from == g.up_acked
                    || replay_from == g.up_next
                    || g.up_frames
                        .iter()
                        .any(|f| f.offset == replay_from || f.end == replay_from);
                if replay_from > g.up_next || !boundary {
                    None
                } else {
                    Some(
                        g.up_frames
                            .iter()
                            .filter(|f| f.offset >= replay_from)
                            .cloned()
                            .collect::<Vec<_>>(),
                    )
                }
            };
            let Some(replay) = replay else {
                if trace {
                    let g = self.state.lock().unwrap();
                    eprintln!(
                        "ingress resume replay boundary rejected session={} epoch={} response_written={} live_acked={} up_next={}",
                        self.sid, response.epoch, response.up_written_offset, g.up_acked, g.up_next
                    );
                }
                last = Error::new(wire::ERR_BAD_ACK, "resume upstream replay boundary");
                continue;
            };
            let mut candidate = new_writer;
            let mut replay_ok = true;
            for frame in replay {
                let send_result = if response.transport == wire::Mode::Ws {
                    match self.acquire_codec_lease(
                        frame.payload.len().saturating_add(wire::WS_HEADER_LEN),
                    ) {
                        Ok(lease) => {
                            let result = candidate.writer().send_data(
                                response.epoch,
                                frame.offset,
                                &frame.payload,
                            );
                            drop(lease);
                            result
                        }
                        Err(error) => Err(error),
                    }
                } else {
                    candidate
                        .writer()
                        .send_data(response.epoch, frame.offset, &frame.payload)
                };
                if let Err(e) = send_result {
                    last = e;
                    replay_ok = false;
                    break;
                }
            }
            if !replay_ok {
                self.attach_failed(&route, mode, &last, &mut pending_request, &mut attempted);
                continue;
            }
            // The upstream pump snapshots the active epoch while holding this
            // same gate. Swap the carrier and publish the new epoch together,
            // so no old-generation frame can reach the replacement carrier.
            let handoff = self.carrier_handoff.lock().unwrap();
            if writer.replace(candidate.take()).is_err() {
                return false;
            }
            *reader = new_reader;
            let route_id = route.endpoint.id.clone();
            *self.route.lock().unwrap() = route;
            {
                let mut g = self.state.lock().unwrap();
                g.epoch = response.epoch;
                g.stream = ready.stream_id.clone();
                g.mode = response.transport;
                g.up_acked = g.up_acked.max(response.ack_up_offset);
                while g.up_frames.front().is_some_and(|f| f.end <= g.up_acked) {
                    g.up_frames.pop_front();
                }
                // The nonce ACK above synchronously confirmed this offset to
                // egress; do not carry pre-recovery receipt debt into the new
                // generation.
                g.up_frames_unconfirmed = 0;
                self.sse_up_confirm.store(g.up_acked, Ordering::Relaxed);
                g.up_fin_applied = response.up_fin.applied;
                g.down_fin_applied = response.down_fin.applied;
                g.down_fin_acked = response.down_fin.acked;
                g.pending_down.extend(pending_generation);
                // The new generation replayed every retained frame.
                g.up_sent = g
                    .up_frames
                    .back()
                    .map_or(g.up_acked, |f| f.end)
                    .max(g.up_acked);
                g.up_pending_since = (g.up_sent > g.up_acked).then(Instant::now);
                g.last_activity = Instant::now();
                g.remote_tx_blocked = false;
                g.remote_rx_blocked = false;
                g.remote_blocked_at = None;
                // The resume handshake's own ACK confirmed the ready event.
                g.ready_ack_pending = false;
                g.carrier_lost = false;
                g.recovery_deadline = committed_recovery_deadline();
                g.fault_time = None;
                g.fault_source.clear();
                g.fault_reason = "";
                g.recovery_attempts = 0;
                // The control ticker may still remember the pre-cut
                // (down, up) report as its last sent snapshot.  Force one ACK
                // for the committed generation so the egress immediately
                // retires receipts accumulated before/during the hand-off;
                // otherwise a large upload can fill the bounded receipt
                // window before the ticker's normal dirty/threshold path runs.
                g.ack_requested = true;
            }
            drop(handoff);
            self.attached.store(true, Ordering::Release);
            self.cv.notify_all();
            if trace {
                eprintln!(
                    "ingress recovery committed session={} epoch={} stream={}",
                    self.sid, response.epoch, ready.stream_id
                );
            }
            crate::slog::info(
                "session recovered",
                &[
                    ("session", super::termination::short_id(&self.sid).into()),
                    ("role", "ingress".into()),
                    ("peer", self.peer.id.as_str().into()),
                    ("endpoint", route_id.as_str().into()),
                    (
                        "owner",
                        super::termination::short_id(&self.owner_instance).into(),
                    ),
                    ("epoch", response.epoch.into()),
                    ("from", from_mode.as_str().into()),
                    ("transport", response.transport.as_str().into()),
                    (
                        "resume_id",
                        super::termination::short_id(&request.resume_request_id).into(),
                    ),
                    (
                        "elapsed_ms",
                        (recovery_started.elapsed().as_millis() as i64).into(),
                    ),
                ],
            );
            self.metrics.record_session_event(
                "ingress",
                "resume",
                "success",
                from_mode.as_str(),
                response.transport.as_str(),
            );
            self.metrics.resume_succeeded();
            return true;
        }
        if trace {
            eprintln!(
                "ingress recovery exhausted session={} error={}",
                self.sid, last
            );
        }
        self.fail(Error::new(
            &last.code,
            format!("carrier recovery exhausted: {}", last.message),
        ));
        false
    }

    fn accept_ack_up(&self, control: &wire::Control) -> bool {
        {
            let mut g = self.state.lock().unwrap();
            if control.ack_requested {
                g.ack_requested = true;
            }
            if control.up_fin_applied {
                g.up_fin_applied = true;
            }
        }
        if let Some(offset) = control.ack_up_offset {
            if !self.advance_up_ack(offset) {
                return false;
            }
        }
        self.cv.notify_all();
        true
    }

    fn advance_up_ack(&self, ack: u64) -> bool {
        let mut g = self.state.lock().unwrap();
        if ack > g.up_next {
            let sent = g.up_next;
            drop(g);
            self.fail(Error::new(
                wire::ERR_BAD_ACK,
                format!("ack_up {ack} is past the {sent} bytes sent"),
            ));
            return false;
        }
        if ack > g.up_acked && !g.up_frames.iter().any(|frame| frame.end == ack) {
            drop(g);
            self.fail(Error::new(
                wire::ERR_BAD_ACK,
                format!("ack_up {ack} is not a retained upstream frame boundary"),
            ));
            return false;
        }
        if ack > g.up_acked {
            g.up_acked = ack;
            g.up_pending_since = (g.up_sent > ack).then(Instant::now);
            let mut frames = 0u64;
            while g.up_frames.front().is_some_and(|frame| frame.end <= ack) {
                g.up_frames.pop_front();
                frames = frames.saturating_add(1);
            }
            g.up_frames_unconfirmed = g.up_frames_unconfirmed.saturating_add(frames);
            self.sse_up_confirm.store(ack, Ordering::Relaxed);
        }
        drop(g);
        self.cv.notify_all();
        true
    }

    /// Applies an HTTP ACK response only while it still belongs to the live
    /// carrier generation. A response from the previous carrier can complete
    /// after recovery has selected replay frames; letting it advance `up_acked`
    /// would retire frames that are already in the replay snapshot.
    fn advance_up_ack_for_generation(
        &self,
        ack: u64,
        request_epoch: u64,
        request_stream: &str,
        confirmed_frames: u64,
    ) -> Option<bool> {
        let mut g = self.state.lock().unwrap();
        if !ack_response_matches_generation(
            g.epoch,
            &g.stream,
            g.carrier_lost,
            g.closed,
            request_epoch,
            request_stream,
        ) {
            return None;
        }
        g.up_frames_unconfirmed = g.up_frames_unconfirmed.saturating_sub(confirmed_frames);
        if ack > g.up_next {
            let sent = g.up_next;
            drop(g);
            self.fail(Error::new(
                wire::ERR_BAD_ACK,
                format!("ack_up {ack} is past the {sent} bytes sent"),
            ));
            return Some(false);
        }
        if ack > g.up_acked && !g.up_frames.iter().any(|frame| frame.end == ack) {
            drop(g);
            self.fail(Error::new(
                wire::ERR_BAD_ACK,
                format!("ack_up {ack} is not a retained upstream frame boundary"),
            ));
            return Some(false);
        }
        if ack > g.up_acked {
            g.up_acked = ack;
            g.up_pending_since = (g.up_sent > ack).then(Instant::now);
            let mut frames = 0u64;
            while g.up_frames.front().is_some_and(|frame| frame.end <= ack) {
                g.up_frames.pop_front();
                frames = frames.saturating_add(1);
            }
            g.up_frames_unconfirmed = g.up_frames_unconfirmed.saturating_add(frames);
            self.sse_up_confirm.store(ack, Ordering::Relaxed);
        }
        drop(g);
        self.cv.notify_all();
        Some(true)
    }

    /// Blocks until the data plane may carry upstream bytes.
    ///
    /// A peer that advertises implicit ready activates the attach on the first
    /// frame, so there is nothing to wait for. Otherwise the attach only
    /// completes once the peer accepts the ready ACK, and sending earlier would
    /// make the peer reject frames for a stream it has not bound yet.
    fn await_attached(&self, stop: &AtomicBool) -> bool {
        if self.implicit_ready {
            return true;
        }
        let deadline = Instant::now() + self.cfg.transport.unattached_timeout;
        while Instant::now() < deadline {
            if self.attached.load(Ordering::Relaxed) {
                return true;
            }
            let guard = self.state.lock().unwrap();
            if stop.load(Ordering::Relaxed) || guard.closed {
                return false;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let (_guard, timeout) = self
                .cv
                .wait_timeout_while(guard, remaining, |g| {
                    !stop.load(Ordering::Relaxed)
                        && !g.closed
                        && !self.attached.load(Ordering::Relaxed)
                })
                .unwrap();
            if timeout.timed_out() {
                break;
            }
        }
        self.fail(Error::new(
            wire::ERR_SESSION_CLOSED,
            "peer never accepted the ready ACK",
        ));
        false
    }

    fn note_up_sent(&self, epoch: u64, end: u64) {
        let mut g = self.state.lock().unwrap();
        if g.epoch != epoch || g.carrier_lost {
            return;
        }
        g.up_sent = g.up_sent.max(end);
        if g.up_sent > g.up_acked && g.up_pending_since.is_none() {
            g.up_pending_since = Some(Instant::now());
        }
    }

    fn watch_activity(
        &self,
        detect: Duration,
        last_ok: Instant,
    ) -> Option<(&'static str, Error, bool)> {
        let g = self.state.lock().unwrap();
        if g.closed || g.carrier_lost {
            return None;
        }
        let stall = if self.cfg.transport.backpressure_timeout.is_zero() {
            Duration::from_secs(120)
        } else {
            self.cfg.transport.backpressure_timeout
        };
        let control_recent = g.last_control.is_some() && last_ok.elapsed() < detect;
        if g.up_sent > g.up_acked {
            if let Some(since) = g.up_pending_since {
                if g.remote_rx_blocked && control_recent {
                    if since.elapsed() >= stall {
                        return Some((
                            "upstream",
                            Error::local("upstream backpressure timeout"),
                            true,
                        ));
                    }
                } else if since.elapsed() >= detect {
                    return Some((
                        "upstream",
                        Error::new(
                            wire::ERR_BACKEND_LOST,
                            format!(
                                "upstream confirmation timeout: {} bytes unconfirmed for {:?}",
                                g.up_sent - g.up_acked,
                                since.elapsed()
                            ),
                        ),
                        false,
                    ));
                }
            }
        }
        let blocked = g.rx_blocked_at.is_some() || g.remote_tx_blocked;
        if blocked && control_recent {
            let mut blocked_at = match (g.rx_blocked_at, g.remote_blocked_at) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            };
            if let Some(at) = blocked_at {
                if g.last_activity > at {
                    blocked_at = Some(g.last_activity);
                }
            }
            if blocked_at.is_some_and(|at| at.elapsed() >= stall) {
                return Some(("data", Error::local("backpressure timeout"), true));
            }
            return None;
        }
        if g.last_activity.elapsed() >= detect {
            return Some((
                "liveness",
                Error::new(
                    wire::ERR_BACKEND_LOST,
                    format!("no session traffic for {:?}", g.last_activity.elapsed()),
                ),
                false,
            ));
        }
        None
    }

    fn generation_fault(
        &self,
        source: &str,
        error: Error,
        fatal: bool,
        writer: &SharedWriter,
    ) -> bool {
        self.record_ingress_fault(source, &error);
        let done = fatal || !self.recovery_enabled;
        if done {
            self.fail(error);
        } else {
            self.signal_carrier_loss();
        }
        writer.shutdown();
        done
    }

    fn control_loop(&self, stop: Arc<AtomicBool>, writer: SharedWriter) {
        let ack_delay = control_interval(&self.cfg.transport);
        let keepalive = control_idle_interval(&self.cfg.transport);
        // The peer is declared gone when no ack has been accepted for this long.
        // Without it a session whose peer vanished silently would never end: the
        // ack request keeps failing and the retry loop never gives up.
        let detect = self.cfg.transport.failure_detect_timeout;
        let watch_tick = (detect / 4)
            .min(Duration::from_millis(250))
            .max(Duration::from_millis(1));
        let mut last = Instant::now();
        let mut last_ok = Instant::now();
        let mut last_reported = (u64::MAX, u64::MAX);
        let mut last_reported_frames = 0u64;
        let mut last_sent_nonce = String::new();
        while !stop.load(Ordering::Relaxed) {
            let wait_for = ack_delay
                .min(keepalive)
                .min(watch_tick)
                .max(Duration::from_millis(1));
            {
                let guard = self.state.lock().unwrap();
                // Test the predicate while holding the same lock used by
                // notify_all().  An unconditional wait here can miss a
                // recovery-commit notification that arrived just before the
                // control thread started waiting, delaying the first ACK by
                // ack_delay while the peer's bounded receipt window fills.
                if !guard.ack_requested && !guard.closed && !guard.carrier_lost {
                    let _ = self
                        .cv
                        .wait_timeout_while(guard, wait_for, |state| {
                            !state.ack_requested && !state.closed && !state.carrier_lost
                        })
                        .unwrap();
                }
            }
            let (
                down,
                up,
                nonce,
                fin_applied,
                closed,
                carrier_lost,
                up_unconfirmed_frames,
                epoch,
                stream,
            ) = {
                let g = self.state.lock().unwrap();
                (
                    g.down_delivered,
                    g.up_acked,
                    g.heartbeat_nonce.clone(),
                    g.down_fin && g.down_fin_offset == Some(g.down_delivered),
                    g.closed,
                    g.carrier_lost,
                    g.up_frames_unconfirmed,
                    g.epoch,
                    g.stream.clone(),
                )
            };
            if closed || self.state.lock().unwrap().normal_close_confirmed() {
                self.cv.notify_all();
                return;
            }
            if carrier_lost {
                last = Instant::now();
                last_ok = Instant::now();
                // Recovery owns the session until it commits or fails: sleep
                // on the state instead of spinning through this loop.
                let guard = self.state.lock().unwrap();
                let _ = self
                    .cv
                    .wait_timeout_while(guard, wait_for, |state| {
                        state.carrier_lost && !state.closed && !stop.load(Ordering::Relaxed)
                    })
                    .unwrap();
                continue;
            }
            if last_ok.elapsed() >= detect {
                let error =
                    Error::local(format!("no control response for {:?}", last_ok.elapsed()));
                if self.generation_fault("liveness", error, false, &writer) {
                    return;
                }
                last = Instant::now();
                last_ok = Instant::now();
                continue;
            }
            if let Some((source, error, fatal)) = self.watch_activity(detect, last_ok) {
                if self.generation_fault(source, error, fatal, &writer) {
                    return;
                }
                last = Instant::now();
                last_ok = Instant::now();
                continue;
            }
            let (ack_requested, down_frames) = {
                let mut g = self.state.lock().unwrap();
                let requested = g.ack_requested;
                g.ack_requested = false;
                (requested, g.down_frames)
            };
            let dirty = (down, up) != last_reported;
            let down_bytes = down.saturating_sub(last_reported.0.min(down));
            let unacked_frames = down_frames.saturating_sub(last_reported_frames);
            let bytes_threshold =
                down_bytes_ack_threshold(self.cfg.transport.ack_batch_bytes, &self.limits);
            let frame_threshold = down_frames_ack_threshold(&self.limits);
            let up_frame_threshold = up_frames_ack_threshold(&self.limits);
            let threshold_due = up_unconfirmed_frames >= up_frame_threshold
                || (dirty
                    && (bytes_threshold == 0
                        || down_bytes >= bytes_threshold
                        || unacked_frames >= frame_threshold));
            let outstanding = dirty || {
                let g = self.state.lock().unwrap();
                (g.down_fin && !g.down_fin_acked)
                    || (g.up_fin && !g.up_fin_applied)
                    || g.up_next > g.up_acked
                    || g.heartbeat_nonce != last_sent_nonce
                    || g.rx_blocked
                    || g.remote_tx_blocked
                    || g.remote_rx_blocked
            };
            let due = outstanding && last.elapsed() >= ack_delay;
            let keepalive_due = last.elapsed() >= keepalive;
            let ready_due = self.state.lock().unwrap().ready_ack_pending;
            if !ack_requested && !threshold_due && !due && !keepalive_due && !ready_due {
                continue;
            }
            let probe_id = match crate::util::random_hex(8) {
                Ok(id) => id,
                Err(e) => {
                    self.fail(crate::util::random_error(e));
                    return;
                }
            };
            last_sent_nonce = nonce.clone();
            let ready_received = std::mem::take(&mut self.state.lock().unwrap().ready_ack_pending);
            let req = AckRequest {
                down_delivered_offset: down,
                up_confirmed_offset: up,
                down_fin_applied: fin_applied,
                ready_received,
                heartbeat_nonce: nonce,
                probe_id,
                data_rx_blocked: {
                    let g = self.state.lock().unwrap();
                    g.rx_blocked
                },
                data_tx_blocked: {
                    let g = self.state.lock().unwrap();
                    g.tx_blocked
                },
                backpressure_reason: {
                    let g = self.state.lock().unwrap();
                    if g.rx_blocked {
                        if g.rx_block_reason.is_empty() {
                            "local_socket_write".to_string()
                        } else {
                            g.rx_block_reason.to_string()
                        }
                    } else if g.tx_blocked {
                        "data_channel_write".to_string()
                    } else {
                        "none".to_string()
                    }
                },
            };
            let control_started = Instant::now();
            let ack_result = self
                .control()
                .ack(&self.sid, &self.token, epoch, &stream, &req);
            let control_elapsed = control_started.elapsed();
            self.metrics
                .observe_operation("ingress", "control", control_elapsed);
            self.metrics.observe_phase(
                &self.peer.id,
                &self.endpoint_id(),
                "control",
                ack_result.is_ok(),
                control_elapsed,
            );
            match ack_result {
                Ok(resp) => {
                    last = Instant::now();
                    last_ok = Instant::now();
                    {
                        let mut g = self.state.lock().unwrap();
                        g.last_control = Some(last_ok);
                        if resp.data_tx_blocked {
                            g.remote_blocked_at.get_or_insert(last_ok);
                        } else {
                            g.remote_blocked_at = None;
                        }
                        g.remote_tx_blocked = resp.data_tx_blocked;
                        g.remote_rx_blocked = resp.data_rx_blocked;
                    }
                    let Some(ack_valid) = self.advance_up_ack_for_generation(
                        resp.ack_up_offset,
                        epoch,
                        &stream,
                        up_unconfirmed_frames,
                    ) else {
                        if std::env::var_os("DBBRIDGE_TRACE").is_some() {
                            eprintln!(
                                "ingress stale ACK response ignored session={} request_epoch={} request_stream={}",
                                self.sid, epoch, stream
                            );
                        }
                        continue;
                    };
                    if !ack_valid {
                        return;
                    }
                    {
                        let mut g = self.state.lock().unwrap();
                        g.up_fin_applied |= resp.up_fin_applied;
                        if fin_applied {
                            g.down_fin_acked |= resp.down_fin_acked;
                        }
                        if g.normal_close_confirmed() {
                            drop(g);
                            self.attached.store(true, Ordering::Relaxed);
                            self.cv.notify_all();
                            return;
                        }
                    }
                    last_reported = (down, up);
                    last_reported_frames = down_frames;
                    {
                        let mut g = self.state.lock().unwrap();
                        g.down_reported = g.down_reported.max(down);
                        g.down_frames_reported = g.down_frames_reported.max(down_frames);
                    }
                    self.attached.store(true, Ordering::Relaxed);
                }
                Err(e) => {
                    if ready_received {
                        // Not confirmed yet: the next ACK carries it again.
                        let mut g = self.state.lock().unwrap();
                        if g.epoch == epoch && g.stream == stream {
                            g.ready_ack_pending = true;
                        }
                    }
                    if e.code == wire::ERR_SESSION_CLOSED || e.code == wire::ERR_SESSION_NOT_FOUND {
                        self.record_ingress_fault("control", &e);
                        self.fail(e);
                        return;
                    }
                    // The ACK request is deliberately built from one carrier
                    // generation.  A resume can commit while this HTTP call
                    // is in flight, making the response stale (or, on a
                    // peer that validates stream before epoch, a transport
                    // mismatch).  Do not spend the normal 200 ms retry
                    // backoff in that hand-off window: the egress receipt
                    // window is bounded, and delaying the first ACK for the
                    // new generation can exhaust it under a large upload.
                    // Re-read epoch/stream on the next iteration and retry
                    // immediately; a mismatch on a live generation remains
                    // subject to the watchdog just as before.
                    let generation_changed = {
                        let g = self.state.lock().unwrap();
                        g.carrier_lost || g.epoch != epoch || g.stream != stream
                    };
                    if generation_changed
                        && (e.code == wire::ERR_STALE_EPOCH
                            || e.code == wire::ERR_TRANSPORT_MISMATCH)
                    {
                        if std::env::var_os("DBBRIDGE_TRACE").is_some() {
                            eprintln!(
                                "ingress ACK generation changed session={} old_epoch={} old_stream={} error={}",
                                self.sid, epoch, stream, e
                            );
                        }
                        continue;
                    }
                    if std::env::var_os("DBBRIDGE_TRACE").is_some() {
                        eprintln!("ingress ACK failed session={} error={e}", self.sid);
                    }
                    self.record_ingress_fault("control", &e);
                    // A transient control failure is not fatal on its own: the
                    // peer's watchdog decides. Back off a little.
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }
    }
}

fn carrier_failure(e: &Error) -> bool {
    e.code == wire::ERR_BACKEND_LOST
        || e.code == wire::ERR_WS_HANDSHAKE_FAILED
        || (e.is_local() && (e.message.contains("carrier") || e.message.starts_with("i/o: ")))
}

impl crate::metrics::IngressGauge for Relay {
    fn shutdown(&self) {
        self.fail(Error::local("ingress shutdown"));
        if let Some(local) = self.local_conn.lock().unwrap().take() {
            let _ = local.shutdown(std::net::Shutdown::Both);
        }
    }

    fn ingress_gauge(&self) -> crate::metrics::IngressGaugeValue {
        let g = self.state.lock().unwrap();
        let active = !g.closed && !g.carrier_lost && self.attached.load(Ordering::Acquire);
        crate::metrics::IngressGaugeValue {
            bound: active.then(|| {
                (
                    self.peer.id.clone(),
                    self.endpoint_id(),
                    g.mode.as_str().to_string(),
                    self.recovery_enabled,
                )
            }),
            recovering: !g.closed && g.carrier_lost && g.recovery_deadline.is_some(),
            up_pending_bytes: g.up_next.saturating_sub(g.up_acked),
            retained_frames: g.up_frames.len() as u64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reset carrier (ECONNRESET / EPIPE, surfaced as a local i/o error)
    /// is recovered like a closed one; protocol violations are not.
    #[test]
    fn carrier_reset_is_a_recoverable_carrier_failure() {
        let reset: Error = std::io::Error::from(std::io::ErrorKind::ConnectionReset).into();
        assert!(carrier_failure(&reset));
        let pipe: Error = std::io::Error::from(std::io::ErrorKind::BrokenPipe).into();
        assert!(carrier_failure(&pipe));
        assert!(carrier_failure(&Error::new(wire::ERR_BACKEND_LOST, "x")));
        assert!(!carrier_failure(&Error::new(
            wire::ERR_BAD_FRAME,
            "bad frame"
        )));
        assert!(!carrier_failure(&Error::local("protocol violation")));
    }

    #[test]
    fn normal_close_needs_both_fins_confirmed_by_the_peer() {
        // B4: releasing the carrier before the peer confirmed both FINs made
        // the egress treat a normal end as a carrier loss and park the
        // session for recovery.
        let mut g = RelayState::initial(1, "s".into(), wire::Mode::Ws);
        assert!(!g.normal_close_confirmed());
        g.up_fin = true;
        g.down_fin = true;
        assert!(!g.normal_close_confirmed(), "FINs sent but not confirmed");
        g.up_fin_applied = true;
        assert!(!g.normal_close_confirmed(), "down FIN ACK not confirmed");
        g.down_fin_acked = true;
        assert!(g.normal_close_confirmed());
        g.up_fin = false;
        assert!(!g.normal_close_confirmed(), "upstream EOF not reached");
    }

    #[test]
    fn recovery_deadline_is_stable_until_success() {
        let now = Instant::now();
        let first = recovery_deadline(None, now, Duration::from_secs(5));
        let second = recovery_deadline(
            Some(first),
            now + Duration::from_secs(1),
            Duration::from_secs(5),
        );
        assert_eq!(first, second);
    }

    #[test]
    fn successful_barrier_clears_deadline_for_next_fault_cycle() {
        assert_eq!(committed_recovery_deadline(), None);
    }

    #[test]
    fn carrier_send_failure_is_recovery_signal_not_protocol_failure() {
        let carrier = Error::new(wire::ERR_BACKEND_LOST, "carrier write failed");
        let protocol = Error::new(wire::ERR_BAD_ACK, "bad acknowledgement");
        assert!(carrier.code == wire::ERR_BACKEND_LOST);
        assert!(!protocol.code.eq(wire::ERR_BACKEND_LOST));
    }

    #[test]
    fn stale_ack_response_does_not_match_recovered_generation() {
        assert!(ack_response_matches_generation(
            2,
            "stream-new",
            false,
            false,
            2,
            "stream-new"
        ));
        assert!(!ack_response_matches_generation(
            2,
            "stream-new",
            false,
            false,
            1,
            "stream-old"
        ));
        assert!(!ack_response_matches_generation(
            2,
            "stream-new",
            true,
            false,
            2,
            "stream-new"
        ));
        assert!(!ack_response_matches_generation(
            2,
            "stream-new",
            false,
            true,
            2,
            "stream-new"
        ));
    }

    #[test]
    fn replay_too_old_is_the_confirmed_duplicate_frame_signal() {
        let replayed = Error::new(wire::ERR_REPLAY_TOO_OLD, "confirmed frame receipt expired");
        let conflict = Error::new(wire::ERR_FRAME_CONFLICT, "frame bytes differ");
        assert!(is_confirmed_duplicate_frame(&replayed));
        assert!(!is_confirmed_duplicate_frame(&conflict));
    }
}

#[cfg(test)]
#[path = "spec_relay_missing_tests.rs"]
mod spec_relay_missing_tests;
