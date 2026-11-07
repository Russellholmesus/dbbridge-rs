//! Accepting connections and turning one into a session: pick a peer, create
//! the session, attach a carrier.

use std::collections::HashMap;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::{self, Config, Peer};
use crate::error::{Error, Result};
use crate::net::http1::Client;
use crate::transport;
use crate::transport::control::ControlClient;
use crate::wire::{self, CreateRequest, Mode};

use super::errors::{fatal_error, pause, reason_category, safe_retry};
use super::{EndpointTable, Health, Ingress};

#[path = "cleanup.rs"]
pub(super) mod cleanup;

struct IngressConnectionGuard(Arc<crate::metrics::Metrics>);

impl IngressConnectionGuard {
    fn new(metrics: Arc<crate::metrics::Metrics>) -> Self {
        metrics.ingress_connection_opened();
        Self(metrics)
    }
}

impl Drop for IngressConnectionGuard {
    fn drop(&mut self) {
        self.0.ingress_connection_closed();
    }
}

fn recovery_request_fields(
    global_enabled: bool,
    grace: Duration,
    peer_enabled: Option<bool>,
) -> (bool, u64) {
    let enabled = global_enabled && peer_enabled.unwrap_or(true);
    let grace_ms = if enabled { grace.as_millis() as u64 } else { 0 };
    (enabled, grace_ms)
}

const ACCEPT_BACKOFF_MIN: Duration = Duration::from_millis(5);
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);
pub(super) const ACCEPT_FATAL_AFTER: u32 = 20;

/// A callback for unrecoverable background failures of the ingress.
pub type FatalHandler = Arc<dyn Fn(Error) + Send + Sync>;

pub(super) trait AcceptSource {
    fn accept_conn(&self) -> std::io::Result<(TcpStream, std::net::SocketAddr)>;
}

impl AcceptSource for TcpListener {
    fn accept_conn(&self) -> std::io::Result<(TcpStream, std::net::SocketAddr)> {
        self.accept()
    }
}

pub(super) fn accept_transient(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    if matches!(
        e.kind(),
        ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::Interrupted
            | ErrorKind::WouldBlock
            | ErrorKind::TimedOut
            | ErrorKind::OutOfMemory
    ) {
        return true;
    }
    // EMFILE, ENFILE, ENOBUFS, ENOMEM, EINTR, EAGAIN, ECONNABORTED,
    // ECONNRESET (Linux numbering).
    #[cfg(target_os = "linux")]
    if matches!(
        e.raw_os_error(),
        Some(24 | 23 | 105 | 12 | 4 | 11 | 103 | 104)
    ) {
        return true;
    }
    false
}

pub(super) fn warn_non_loopback(listener: &config::Listener, addr: std::net::SocketAddr) {
    if addr.ip().is_loopback() {
        return;
    }
    crate::slog::warn(
        "ingress listener is bound to a non-loopback address; any host that can reach it can use this peer's credentials",
        &[
            ("listener", listener.id.as_str().into()),
            ("listen", listener.listen.as_str().into()),
        ],
    );
}

impl Ingress {
    pub fn new(cfg: Arc<Config>) -> Self {
        let client = Arc::new(Client::new(
            cfg.transport.peer_dial_timeout,
            cfg.transport.control_request_timeout,
        ));
        let mut peer_clients = HashMap::new();
        for peer in cfg.peers.iter().filter(|p| !p.reverse) {
            if !peer.tls.verify {
                for ep in peer.endpoints.iter().filter(|e| e.url.is_tls()) {
                    crate::slog::warn(
                        "TLS certificate verification is DISABLED for peer (tls.verify=false); peer credentials and all traffic are exposed to man-in-the-middle attacks. Do not use in production.",
                        &[("peer_url", format!("https://{}", ep.url.authority()).into())],
                    );
                }
            }
            peer_clients.insert(
                peer.id.clone(),
                Arc::new(Client::new_with_tls_and_h2(
                    cfg.transport.peer_dial_timeout,
                    cfg.transport.control_request_timeout,
                    peer.tls.clone(),
                    cfg.transport.h2_pool_size,
                    cfg.transport.heartbeat,
                )),
            );
        }
        let hub = if cfg.has_reverse_peers() {
            Some(Arc::new(crate::tunnel::Hub::new(&cfg)))
        } else {
            None
        };
        let mut reverse_clients = HashMap::new();
        if let Some(h) = &hub {
            for peer in cfg.peers.iter().filter(|p| p.reverse) {
                let c = Arc::new(
                    Client::new(
                        cfg.transport.peer_dial_timeout,
                        cfg.transport.control_request_timeout,
                    )
                    .with_h2_pool_size(cfg.transport.h2_pool_size),
                );
                c.set_dialer(Arc::new(crate::tunnel::TunnelDialer::new(
                    h.clone(),
                    &peer.id,
                )));
                reverse_clients.insert(peer.id.clone(), c);
            }
        }
        Ingress {
            cfg,
            client,
            metrics: Arc::new(crate::metrics::Metrics::new()),
            auth: None,
            endpoints: Arc::new(EndpointTable::default()),
            hub,
            reverse_clients,
            peer_clients,
            prechecks: Arc::new(Mutex::new(HashMap::new())),
            accept_addrs: Arc::new(Mutex::new(Vec::new())),
            drain: Arc::new(super::DrainState::default()),
            fatal: Arc::new(Mutex::new(None)),
            cleanups: Arc::default(),
        }
    }

    pub fn with_auth(mut self, auth: Arc<crate::auth::Authenticator>) -> Self {
        if let Some(hub) = self.hub.as_ref() {
            hub.set_auth(auth.clone());
        }
        self.auth = Some(auth);
        self
    }
    pub fn token_provider(&self, peer: &str) -> Option<crate::transport::control::TokenProvider> {
        self.auth.as_ref().map(|a| {
            let a = a.clone();
            let id = peer.to_string();
            Arc::new(move || {
                a.outbound_token(&id).ok_or_else(|| {
                    Error::new(
                        crate::config::CODE_CREDENTIAL,
                        format!("missing outbound credential for peer {id}"),
                    )
                })
            }) as crate::transport::control::TokenProvider
        })
    }
    pub fn with_metrics(mut self, metrics: Arc<crate::metrics::Metrics>) -> Self {
        metrics.configure_resources(&self.cfg);
        if let Some(resources) = metrics.resource_manager() {
            self.client.set_resource_manager(resources.clone());
            for client in self
                .peer_clients
                .values()
                .chain(self.reverse_clients.values())
            {
                client.set_resource_manager(resources.clone());
            }
        }
        if let Some(hub) = &self.hub {
            metrics.set_reverse_hub(hub);
            if let Some(resources) = metrics.resource_manager() {
                hub.set_resources(resources);
            }
        }
        self.metrics = metrics;
        self
    }

    pub fn request_shutdown(&self) {
        self.drain.draining.store(true, Ordering::SeqCst);
        self.metrics.shutdown_ingress_sessions();
        self.drain.close_all();
        self.wake_listeners();
    }

    /// Wakes every blocking local listener so its worker can observe
    /// shutdown or drain.
    pub(super) fn wake_listeners(&self) {
        let addrs = self
            .accept_addrs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        for addr in addrs {
            let _ = crate::net::wake_tcp_listener(addr);
        }
    }

    /// Waits (bounded) until every local client connection has finished,
    /// including its remote cleanup. Returns whether the ingress is idle.
    #[cfg(test)]
    pub fn wait_idle(&self, timeout: Duration) -> bool {
        let until = std::time::Instant::now() + timeout;
        while self.metrics.ingress_connection_count() > 0 {
            if std::time::Instant::now() >= until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Self::wait_cleanups(&self.cleanups, until)
    }

    /// The client that carries this peer's requests.
    pub(super) fn client_for(&self, peer: &str) -> Arc<Client> {
        self.reverse_clients
            .get(peer)
            .cloned()
            .or_else(|| self.peer_clients.get(peer).cloned())
            .unwrap_or_else(|| self.client.clone())
    }

    /// The endpoints a peer offers. A reverse peer has no configured
    /// endpoints: its tunnel is the transport, so one virtual endpoint
    /// stands in and its host is never resolved.
    pub(super) fn peer_endpoints(peer: &Peer) -> Vec<config::Endpoint> {
        if peer.reverse {
            vec![config::Endpoint {
                id: crate::tunnel::REVERSE_ENDPOINT_ID.to_string(),
                url: crate::net::Url::parse(crate::tunnel::REVERSE_ENDPOINT_URL)
                    .expect("the virtual endpoint is a constant"),
                priority: 1,
            }]
        } else {
            peer.endpoints.clone()
        }
    }

    /// Starts one accept loop per configured listener.
    pub fn start(&self, shutdown: Arc<AtomicBool>) -> Result<Vec<std::thread::JoinHandle<()>>> {
        if !self
            .accept_addrs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
        {
            return Err(Error::local("ingress already started"));
        }
        let mut handles = Vec::new();
        for listener in self.cfg.listeners.clone() {
            let bind = listener.listen.clone();
            let (host, port) =
                config::parse_hostport(&bind).map_err(|e| Error::new(config::CODE_LISTEN, e))?;
            let bind = if host.is_empty() {
                format!("0.0.0.0:{port}")
            } else {
                bind
            };
            let ln = TcpListener::bind(&bind).map_err(|e| {
                Error::new(
                    config::CODE_LISTEN,
                    format!("listener {}: {bind}: {e}", listener.id),
                )
            })?;
            let addr = ln
                .local_addr()
                .map_err(|e| Error::local(format!("listener {} local_addr: {e}", listener.id)))?;
            self.accept_addrs
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(addr);
            crate::slog::debug(
                &format!(
                    "listener {} accepting on {bind} -> peer {} target {}",
                    listener.id, listener.peer, listener.target
                ),
                &[],
            );
            warn_non_loopback(&listener, addr);
            let me = Arc::new(Ingress {
                cfg: self.cfg.clone(),
                client: self.client.clone(),
                metrics: self.metrics.clone(),
                endpoints: self.endpoints.clone(),
                auth: self.auth.clone(),
                hub: self.hub.clone(),
                reverse_clients: self.reverse_clients.clone(),
                peer_clients: self.peer_clients.clone(),
                prechecks: self.prechecks.clone(),
                accept_addrs: self.accept_addrs.clone(),
                drain: self.drain.clone(),
                fatal: self.fatal.clone(),
                cleanups: self.cleanups.clone(),
            });
            let sd = shutdown.clone();
            handles.push(std::thread::spawn(move || {
                let stopped = || sd.load(Ordering::Relaxed) || me.drain.draining();
                me.accept_loop(&ln, &listener, &stopped, ACCEPT_BACKOFF_MAX);
            }));
        }
        Ok(handles)
    }

    pub(super) fn accept_loop(
        self: &Arc<Self>,
        ln: &dyn AcceptSource,
        listener: &config::Listener,
        stopped: &dyn Fn() -> bool,
        backoff_max: Duration,
    ) {
        let mut backoff = Duration::ZERO;
        let mut permanent = 0u32;
        let mut last_reject: Option<Instant> = None;
        loop {
            if stopped() {
                break;
            }
            match ln.accept_conn() {
                Ok((stream, peer_addr)) => {
                    if stopped() {
                        drop(stream);
                        break;
                    }
                    backoff = Duration::ZERO;
                    permanent = 0;
                    let leases = match self.admit_local(listener, &mut last_reject) {
                        Some(leases) => leases,
                        None => {
                            drop(stream);
                            continue;
                        }
                    };
                    let _ = crate::net::set_nodelay(&stream);
                    let _ = stream.set_nonblocking(false);
                    let me = self.clone();
                    let l = listener.clone();
                    let _ = crate::util::spawn_connection(move || {
                        let _leases = leases;
                        if let Err(e) = me.handle_client(&l, stream) {
                            crate::slog::debug(
                                "ingress session error",
                                &[
                                    ("listener", l.id.as_str().into()),
                                    ("client", peer_addr.to_string().into()),
                                    ("err", crate::slog::err(&e)),
                                ],
                            );
                        }
                    });
                }
                Err(e) => {
                    if stopped() {
                        break;
                    }
                    let transient = accept_transient(&e);
                    if transient {
                        permanent = 0;
                    } else {
                        permanent += 1;
                    }
                    backoff = (backoff * 2).max(ACCEPT_BACKOFF_MIN).min(backoff_max);
                    crate::slog::warn(
                        "ingress accept error; retrying",
                        &[
                            ("listener", listener.id.as_str().into()),
                            ("err", crate::slog::err(&e)),
                            ("backoff", backoff.into()),
                            ("transient", (permanent == 0).into()),
                        ],
                    );
                    if permanent >= ACCEPT_FATAL_AFTER
                        && self.report_fatal(Error::local(format!(
                            "ingress listener {}: accept keeps failing: {e}",
                            listener.id
                        )))
                    {
                        return;
                    }
                    std::thread::sleep(backoff);
                }
            }
        }
    }

    pub fn set_fatal_handler(&self, handler: FatalHandler) {
        *self
            .fatal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(handler);
    }

    fn report_fatal(&self, error: Error) -> bool {
        let handler = self
            .fatal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        match handler {
            Some(h) => {
                h(error);
                true
            }
            None => false,
        }
    }

    fn admit_local(
        &self,
        listener: &config::Listener,
        last_reject: &mut Option<Instant>,
    ) -> Option<(
        Option<crate::resource::budget::BudgetLease>,
        Option<crate::resource::budget::BudgetLease>,
    )> {
        let Some(resources) = self.metrics.resource_manager() else {
            return Some((None, None));
        };
        resources.mark_instrumented("sessions");
        resources.mark_instrumented("metadata");
        let refused = |budget: &str, last_reject: &mut Option<Instant>| {
            let total = self.metrics.ingress_accept_rejected();
            if last_reject.is_some_and(|t| t.elapsed() < Duration::from_secs(1)) {
                return;
            }
            crate::slog::warn(
                "ingress connection rejected: local budget exhausted",
                &[
                    ("listener", listener.id.as_str().into()),
                    ("budget", budget.to_string().into()),
                    ("rejected_total", total.into()),
                ],
            );
            *last_reject = Some(Instant::now());
        };
        let Some(session) = resources.sessions.try_acquire(1) else {
            refused("sessions", last_reject);
            return None;
        };
        let cost = (16i64 << 10) + i64::from(self.cfg.transport.up_max_inflight_frames) * 192;
        let Some(metadata) = resources.metadata.try_acquire(cost) else {
            drop(session);
            refused("metadata", last_reject);
            return None;
        };
        Some((Some(session), Some(metadata)))
    }

    fn handle_client(&self, listener: &config::Listener, stream: TcpStream) -> Result<()> {
        super::termination::reset();
        let _active = self.drain.track(stream.try_clone().ok());
        let _connection = IngressConnectionGuard::new(self.metrics.clone());
        let peer = self
            .cfg
            .peer(&listener.peer)
            .ok_or_else(|| Error::local("listener references an unknown peer"))?
            .clone();
        let local = stream.try_clone().ok();
        let attach_by = Instant::now() + self.cfg.transport.create_retry_timeout;
        let (endpoint, control, mode, created) =
            match self.create_with_retries(&peer, &listener.target) {
                Ok(v) => v,
                Err(e) => {
                    self.log_early_termination(&peer, None, &e, local);
                    return Err(e);
                }
            };

        let result = match mode {
            Mode::Ws => self.relay_ws(&peer, &endpoint, &control, &created, stream, attach_by),
            Mode::HttpSse => self.relay_sse(&peer, &endpoint, &control, &created, stream),
        };
        if mode == Mode::Ws {
            if let Err(e) = &result {
                // The precheck said this path carries WebSocket and it did
                // not: drop the cached answer so the next connection tries SSE
                // instead of repeating the failure for the rest of the TTL.
                if e.code == wire::ERR_WS_HANDSHAKE_FAILED
                    || e.code == wire::ERR_WS_PROTOCOL_ERROR
                    || e.code == wire::ERR_TRANSPORT_UNSUPPORTED
                {
                    self.forget_precheck(&peer.id, &endpoint.id, &created.instance_id);
                    self.endpoints.record_transport_failure(
                        &peer.id,
                        &endpoint.id,
                        Mode::Ws,
                        peer.failover.cooldown,
                    );
                }
            }
        }
        if let Err(e) = &result {
            if !super::termination::logged() {
                self.log_early_termination(&peer, Some(&created), e, local);
            }
        }
        result
    }

    /// The termination record of a session that ended before its relay ran.
    fn log_early_termination(
        &self,
        peer: &Peer,
        created: Option<&wire::CreateResponse>,
        e: &Error,
        local: Option<TcpStream>,
    ) {
        let terminal = std::time::SystemTime::now();
        if let Some(local) = local {
            let _ = local.shutdown(std::net::Shutdown::Both);
        }
        let local_closed = std::time::SystemTime::now();
        let (recovery_enabled, _) = recovery_request_fields(
            self.cfg.transport.recovery_enabled,
            self.cfg.transport.recovery_grace,
            peer.recovery_enabled,
        );
        let record = super::termination::Termination {
            session: created.map(|c| c.session_id.clone()).unwrap_or_default(),
            peer: peer.id.clone(),
            endpoint: String::new(),
            owner: created.map(|c| c.instance_id.clone()).unwrap_or_default(),
            epoch: created.map_or(0, |c| c.epoch),
            transport: created.map_or("", |c| c.mode.as_str()),
            recovery_enabled,
            attempts: 0,
            deadline: None,
            outcome_unknown: false,
            reason: reason_category(e),
            fault_source: String::new(),
            fault_reason: "",
            fault_time: None,
            terminal,
            local_closed,
        }
        .settle(false);
        let close = record
            .local_closed
            .duration_since(record.terminal)
            .unwrap_or_default();
        self.metrics.client_closed(close.as_millis() as i64);
        self.metrics
            .observe_operation("ingress", "local_close", close);
        self.metrics.record_session_event(
            "ingress",
            "terminate",
            record.reason,
            record.transport,
            "none",
        );
        super::termination::count_termination(
            &self.metrics,
            record.reason,
            recovery_enabled,
            false,
        );
        record.log();
    }

    /// Creates one remote session within one deadline.  The request id is
    /// deliberately allocated outside the loop: a retry must hit the egress
    /// idempotency record rather than create a second session.
    fn create_with_retries(
        &self,
        peer: &Peer,
        target: &str,
    ) -> Result<(config::Endpoint, ControlClient, Mode, wire::CreateResponse)> {
        let deadline = Instant::now() + self.cfg.transport.create_retry_timeout;
        let request_id = crate::util::random_id(24).map_err(crate::util::random_error)?;
        let peer_client = self.client_for(&peer.id);
        let (recovery_enabled, recovery_grace_ms) = recovery_request_fields(
            self.cfg.transport.recovery_enabled,
            self.cfg.transport.recovery_grace,
            peer.recovery_enabled,
        );
        let mut last = Error::local("create deadline exceeded");
        let mut current: Option<(config::Endpoint, Health, Mode)> = None;
        let mut same_endpoint_retries = 0u32;
        let mut select_attempts = 0u32;
        let mut create_submitted = false;

        loop {
            if Instant::now() >= deadline {
                return Err(last);
            }
            let (endpoint, health, mode) = match current.take() {
                Some(v) => v,
                None => {
                    let (ep, h) = match self.select_endpoint_for(peer, !create_submitted) {
                        Ok(v) => v,
                        Err(e) => {
                            if fatal_error(&e) {
                                return Err(e);
                            }
                            let endpoints = Self::peer_endpoints(peer);
                            let wait = match self.endpoints.cooldown_end(&peer.id, &endpoints) {
                                Some(until) => {
                                    let d = until.saturating_duration_since(Instant::now());
                                    d + pause(0, &e)?.min(Duration::from_millis(100)) / 4
                                }
                                None => pause(select_attempts, &e)?,
                            };
                            select_attempts = select_attempts.saturating_add(1);
                            let remaining = deadline.saturating_duration_since(Instant::now());
                            if wait >= remaining {
                                return Err(e);
                            }
                            std::thread::sleep(wait);
                            last = e;
                            continue;
                        }
                    };
                    let m = match self.select_mode(peer, &ep, &h, &peer_client) {
                        Ok(mode) => mode,
                        Err(e) => {
                            if matches!(
                                e.code.as_str(),
                                wire::ERR_WS_PROTOCOL_ERROR
                                    | wire::ERR_PROTOCOL_MISMATCH
                                    | wire::ERR_INSTANCE_MISMATCH
                                    | wire::ERR_NODE_MISMATCH
                                    | wire::ERR_TRANSPORT_MISMATCH
                                    | wire::ERR_TLS_FAILED
                            ) {
                                self.endpoints
                                    .penalize(&peer.id, &ep.id, peer.failover.cooldown);
                            }
                            let now = Instant::now();
                            let modes: &[Mode] = match peer.protocol {
                                config::Protocol::Ws => &[Mode::Ws],
                                config::Protocol::Auto => &[Mode::Ws, Mode::HttpSse],
                                _ => &[Mode::HttpSse],
                            };
                            let wait = self
                                .endpoints
                                .next_eligible(&peer.id, &ep.id, modes, now)
                                .map_or(Duration::from_millis(10), |at| {
                                    at.saturating_duration_since(now)
                                })
                                .min(deadline.saturating_duration_since(now));
                            std::thread::sleep(wait.max(Duration::from_millis(1)));
                            last = e;
                            continue;
                        }
                    };
                    same_endpoint_retries = 0;
                    (ep, h, m)
                }
            };
            let create = CreateRequest {
                target_id: target.to_string(),
                create_request_id: request_id.clone(),
                ingress_instance_id: self.cfg.node.instance_id.clone(),
                mode,
                recovery_enabled,
                recovery_grace_ms,
                limits: transport::requested_limits(&self.cfg.transport),
            };
            let mut control = ControlClient::new(
                peer_client.clone(),
                endpoint.url.clone(),
                peer.token.clone(),
                health.instance_id.clone(),
                peer.tls.clone(),
            );
            if let Some(provider) = self.token_provider(&peer.id) {
                control = control.with_token_provider(provider);
            }
            match control.create(&create) {
                Ok(created) => {
                    if peer.protocol == config::Protocol::Auto
                        && mode == Mode::HttpSse
                        && health.transports.contains(&Mode::Ws)
                    {
                        self.metrics.record_session_event(
                            "ingress",
                            "fallback",
                            "transport",
                            "ws",
                            "http-sse",
                        );
                    }
                    return Ok((endpoint, control, mode, created));
                }
                Err(e) => {
                    if e.is_local() && e.remote_status.is_none() {
                        create_submitted = true;
                    }
                    last = e.clone();
                    crate::egress::log_debug(&format!(
                        "ingress create on peer {} endpoint {} failed: {} ({})",
                        peer.id,
                        endpoint.id,
                        e,
                        reason_category(&e)
                    ));
                    // A restart invalidates only the probe used for this
                    // attempt.  It is not endpoint failure and must be
                    // reprobed immediately, without entering cooldown.
                    if e.code == wire::ERR_INSTANCE_MISMATCH {
                        self.endpoints.invalidate(&peer.id, &endpoint.id);
                        self.metrics.clear_endpoint_state(&peer.id, &endpoint.id);
                        peer_client.drop_idle(&endpoint.url.authority());
                        continue;
                    }
                    // Every rejected create invalidates the cached probe.  A
                    // safe retry may stay on this endpoint, but only while the
                    // overall create deadline remains and before failover.
                    self.endpoints.invalidate(&peer.id, &endpoint.id);
                    self.metrics.clear_endpoint_state(&peer.id, &endpoint.id);
                    if fatal_error(&e) {
                        return Err(e);
                    }
                    if safe_retry(&e) && same_endpoint_retries == 0 {
                        same_endpoint_retries += 1;
                        let delay = pause(same_endpoint_retries - 1, &e)?;
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        if delay < remaining {
                            std::thread::sleep(delay);
                            current = Some((endpoint, health, mode));
                            continue;
                        }
                        return Err(e);
                    }
                    let endpoints = Self::peer_endpoints(peer);
                    if !e.is_local()
                        && self.endpoints.other_endpoint_available(
                            &peer.id,
                            &endpoint.id,
                            &endpoints,
                        )
                    {
                        self.endpoints
                            .penalize(&peer.id, &endpoint.id, peer.failover.cooldown);
                    } else if !e.is_local() {
                        // The pooled connection the create rode may belong to
                        // a path that is gone (e.g. a stream of a tunnel that
                        // was replaced): never reuse it for the retry.
                        peer_client.drop_idle(&endpoint.url.authority());
                        let delay = pause(same_endpoint_retries, &e)?;
                        same_endpoint_retries = same_endpoint_retries.saturating_add(1);
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        if delay < remaining {
                            std::thread::sleep(delay);
                            continue;
                        }
                        return Err(e);
                    }
                    if e.is_local() {
                        let delay = pause(0, &e)?;
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        if delay < remaining {
                            std::thread::sleep(delay);
                            continue;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
pub(in crate::ingress) mod tests {
    use super::*;
    use crate::wire::CreateResponse;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Copy)]
    enum Behavior {
        InstanceMismatchThenSuccess,
        Always503,
        Success,
        /// The first create's connection is closed without an answer (the
        /// path died under it, like a stream of a replaced reverse tunnel).
        DropFirstCreate,
    }

    struct Stats {
        probes: AtomicUsize,
        creates: AtomicUsize,
        request_ids: Mutex<Vec<String>>,
        recovery_requests: Mutex<Vec<(bool, u64)>>,
    }

    struct FakePeer {
        addr: SocketAddr,
        stats: Arc<Stats>,
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl FakePeer {
        fn start(behavior: Behavior, instance: &'static str) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let addr = listener.local_addr().unwrap();
            let stats = Arc::new(Stats {
                probes: AtomicUsize::new(0),
                creates: AtomicUsize::new(0),
                request_ids: Mutex::new(Vec::new()),
                recovery_requests: Mutex::new(Vec::new()),
            });
            let thread_stats = stats.clone();
            let stop = Arc::new(AtomicBool::new(false));
            let thread_stop = stop.clone();
            let thread = std::thread::spawn(move || {
                while !thread_stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                            if let Some((path, body)) = read_request(&mut stream) {
                                respond(
                                    &mut stream,
                                    behavior,
                                    instance,
                                    &thread_stats,
                                    &path,
                                    &body,
                                );
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(_) => break,
                    }
                }
            });
            Self {
                addr,
                stats,
                stop,
                thread: Some(thread),
            }
        }
    }

    impl Drop for FakePeer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    fn read_request(stream: &mut TcpStream) -> Option<(String, Vec<u8>)> {
        let mut reader = BufReader::new(stream);
        let mut first = String::new();
        reader.read_line(&mut first).ok()?;
        let path = first.split_whitespace().nth(1)?.to_string();
        let mut content_length = 0usize;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).ok()?;
            if line == "\r\n" || line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = value.trim().parse().ok()?;
                }
            }
        }
        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body).ok()?;
        Some((path, body))
    }

    fn respond(
        stream: &mut TcpStream,
        behavior: Behavior,
        base_instance: &str,
        stats: &Stats,
        path: &str,
        body: &[u8],
    ) {
        let parsed = crate::util::json::parse_bytes(body).unwrap();
        if path == wire::PATH_PROBE {
            let nonce = parsed
                .get("nonce")
                .and_then(crate::util::json::Json::as_str)
                .unwrap()
                .to_string();
            let count = stats.probes.fetch_add(1, Ordering::SeqCst) + 1;
            let instance_id = match behavior {
                Behavior::InstanceMismatchThenSuccess if count == 1 => "instance-old",
                Behavior::InstanceMismatchThenSuccess => "instance-new",
                _ => base_instance,
            };
            let response = crate::util::json::obj(vec![
                (
                    "protocol_version",
                    crate::util::json::Json::from(wire::PROTOCOL_VERSION),
                ),
                ("node_id", crate::util::json::Json::from("egress-b")),
                ("instance_id", crate::util::json::Json::from(instance_id)),
                ("nonce", crate::util::json::Json::from(nonce)),
                ("recovery_available", crate::util::json::Json::Bool(true)),
                (
                    "accepting_new_sessions",
                    crate::util::json::Json::Bool(true),
                ),
                (
                    "transports",
                    crate::util::json::Json::Arr(vec![crate::util::json::Json::from("http-sse")]),
                ),
            ]);
            write_response(stream, 200, instance_id, &response.to_string());
            return;
        }
        assert_eq!(path, wire::PATH_SESSIONS);
        let request = crate::wire::CreateRequest::from_json(&parsed).unwrap();
        stats
            .request_ids
            .lock()
            .unwrap()
            .push(request.create_request_id.clone());
        stats
            .recovery_requests
            .lock()
            .unwrap()
            .push((request.recovery_enabled, request.recovery_grace_ms));
        let count = stats.creates.fetch_add(1, Ordering::SeqCst) + 1;
        if matches!(behavior, Behavior::DropFirstCreate) && count == 1 {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return;
        }
        if matches!(behavior, Behavior::Always503) {
            write_error(
                stream,
                503,
                base_instance,
                wire::ERR_CREATE_PENDING,
                "creation is pending",
            );
            return;
        }
        if matches!(behavior, Behavior::InstanceMismatchThenSuccess) && count == 1 {
            write_error(
                stream,
                409,
                "instance-old",
                wire::ERR_INSTANCE_MISMATCH,
                "egress instance changed",
            );
            return;
        }
        let instance_id = if matches!(behavior, Behavior::InstanceMismatchThenSuccess) {
            "instance-new"
        } else {
            base_instance
        };
        let response = CreateResponse {
            node_id: "egress-b".to_string(),
            instance_id: instance_id.to_string(),
            session_id: format!("session-{count}"),
            session_token: "session-token".to_string(),
            epoch: 1,
            mode: request.mode,
            recovery_enabled: request.recovery_enabled,
            recovery_grace_ms: request.recovery_grace_ms,
            limits: {
                let mut limits = request.limits;
                limits.up_receipt_limit = limits
                    .up_max_inflight_frames
                    .saturating_mul(2)
                    .saturating_add(8)
                    .max(64);
                limits.down_max_frames = 512;
                limits
            },
            unattached_timeout_ms: 30_000,
        };
        write_response(stream, 201, instance_id, &response.to_json().to_string());
    }

    fn write_error(stream: &mut TcpStream, status: u16, instance: &str, code: &str, message: &str) {
        let body = format!(
            "{{\"code\":\"{code}\",\"message\":\"{message}\",\"retryable\":true,\"session_closed\":false}}"
        );
        write_response(stream, status, instance, &body);
    }

    fn write_response(stream: &mut TcpStream, status: u16, instance: &str, body: &str) {
        let response = format!(
            "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{}: {}\r\n\r\n{}",
            body.len(),
            wire::H_INSTANCE_ID,
            instance,
            body
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
    }

    struct Fixture {
        ingress: Ingress,
        peer: crate::config::Peer,
        dir: std::path::PathBuf,
    }

    impl Fixture {
        fn new(endpoints: &[(&str, SocketAddr, i32)]) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "dbbingress-{}",
                crate::util::random_hex(6).unwrap()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("peer-token"), "peer-token").unwrap();
            let path = dir.join("config.yaml");
            let endpoint_yaml = endpoints
                .iter()
                .map(|(id, addr, priority)| {
                    format!(
                        "      - id: {id}\n        url: \"http://{addr}\"\n        priority: {priority}\n"
                    )
                })
                .collect::<String>();
            let config = format!(
                "node:\n  id: ingress-a\nlisteners:\n  - id: local\n    listen: \"127.0.0.1:13306\"\n    peer: peer-b\n    target: db\npeers:\n  - id: peer-b\n    expected_node_id: egress-b\n    credential_ref: peer-b\n    token_file: peer-token\n    transport:\n      protocol: http-sse\n    failover:\n      cooldown: 5s\n    endpoints:\n{endpoint_yaml}transport:\n  create_retry_timeout: 3s\n"
            );
            std::fs::write(&path, config).unwrap();
            let cfg = Arc::new(crate::config::load(&path).unwrap());
            let peer = cfg.peer("peer-b").unwrap().clone();
            let ingress = Ingress::new(cfg);
            Self { ingress, peer, dir }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    pub(in crate::ingress) fn instance_mismatch_reprobes_without_cooldown() {
        let server = FakePeer::start(Behavior::InstanceMismatchThenSuccess, "unused");
        let fixture = Fixture::new(&[("primary", server.addr, 1)]);
        let (endpoint, _control, _mode, created) = fixture
            .ingress
            .create_with_retries(&fixture.peer, "db")
            .unwrap();
        assert_eq!(endpoint.id, "primary");
        assert_eq!(created.instance_id, "instance-new");
        assert_eq!(server.stats.probes.load(Ordering::SeqCst), 2);
        assert_eq!(server.stats.creates.load(Ordering::SeqCst), 2);
        let ids = server.stats.request_ids.lock().unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[0], ids[1], "retry must reuse create_request_id");
        assert_eq!(
            *server.stats.recovery_requests.lock().unwrap(),
            vec![(true, 30_000), (true, 30_000)]
        );
        assert!(
            !fixture
                .ingress
                .endpoints
                .in_cooldown(&fixture.peer.id, "primary"),
            "instance mismatch must not cool down the endpoint"
        );
    }

    /// KB-I4: a failed create on the only endpoint (a reverse peer's tunnel
    /// after a database-side restart) is retried after a backoff, without a
    /// cooldown and without a placeholder "not accepting" health entry that
    /// kept new sessions away for ~10 s.
    #[test]
    fn failed_create_on_the_only_endpoint_retries_without_cooldown() {
        let server = FakePeer::start(Behavior::DropFirstCreate, "instance-x");
        let fixture = Fixture::new(&[("primary", server.addr, 1)]);
        let started = Instant::now();
        let (endpoint, _control, _mode, created) = fixture
            .ingress
            .create_with_retries(&fixture.peer, "db")
            .unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(endpoint.id, "primary");
        assert_eq!(created.instance_id, "instance-x");
        assert_eq!(server.stats.creates.load(Ordering::SeqCst), 2);
        assert!(!fixture
            .ingress
            .endpoints
            .in_cooldown(&fixture.peer.id, "primary"));
    }

    /// A penalized endpoint is reprobed when its cooldown ends instead of
    /// being served from a placeholder entry that looks freshly probed.
    #[test]
    fn penalized_endpoint_is_reprobed_after_the_cooldown() {
        let table = EndpointTable::default();
        table.penalize("p", "e", Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(5));
        let h = table.get("p", "e").unwrap();
        assert!(!table.in_cooldown("p", "e"));
        assert!(h.accepting_new_sessions);
        assert!(h.probed_at.elapsed() >= Duration::from_secs(15));
    }

    #[test]
    fn probe_failure_below_threshold_does_not_cool_down() {
        let table = EndpointTable::default();
        table.record_probe_failure("p", "e", Duration::from_secs(5), 2, false);
        assert!(!table.in_cooldown("p", "e"));
        table.record_probe_failure("p", "e", Duration::from_secs(5), 2, false);
        assert!(table.in_cooldown("p", "e"));
        let other = EndpointTable::default();
        other.record_probe_failure("p", "e", Duration::from_secs(5), 2, true);
        assert!(other.in_cooldown("p", "e"));
    }

    pub(in crate::ingress) fn create_fails_over_to_second_endpoint_on_503() {
        let first = FakePeer::start(Behavior::Always503, "instance-first");
        let second = FakePeer::start(Behavior::Success, "instance-second");
        let fixture = Fixture::new(&[("primary", first.addr, 1), ("secondary", second.addr, 2)]);
        let (endpoint, _control, _mode, created) = fixture
            .ingress
            .create_with_retries(&fixture.peer, "db")
            .unwrap();
        assert_eq!(endpoint.id, "secondary");
        assert_eq!(created.instance_id, "instance-second");
        assert_eq!(first.stats.probes.load(Ordering::SeqCst), 1);
        assert_eq!(first.stats.creates.load(Ordering::SeqCst), 2);
        assert_eq!(second.stats.probes.load(Ordering::SeqCst), 1);
        assert_eq!(second.stats.creates.load(Ordering::SeqCst), 1);
        let first_ids = first.stats.request_ids.lock().unwrap();
        assert_eq!(first_ids.len(), 2);
        assert_eq!(first_ids[0], first_ids[1]);
        assert!(fixture
            .ingress
            .endpoints
            .in_cooldown(&fixture.peer.id, "primary"));
        assert!(!fixture
            .ingress
            .endpoints
            .in_cooldown(&fixture.peer.id, "secondary"));
    }

    #[test]
    fn recovery_request_uses_spec_defaults_and_peer_override() {
        assert_eq!(
            recovery_request_fields(true, Duration::from_secs(30), None),
            (true, 30_000)
        );
        assert_eq!(
            recovery_request_fields(true, Duration::from_secs(30), Some(false)),
            (false, 0)
        );
        assert_eq!(
            recovery_request_fields(false, Duration::from_secs(30), Some(true)),
            (false, 0)
        );
    }

    #[test]
    fn blocking_local_accept_wakes_on_shutdown() {
        let server = FakePeer::start(Behavior::Success, "unused");
        let mut fixture = Fixture::new(&[("primary", server.addr, 1)]);
        Arc::get_mut(&mut fixture.ingress.cfg).unwrap().listeners[0].listen =
            "127.0.0.1:0".to_string();
        let shutdown = Arc::new(AtomicBool::new(false));
        let workers = fixture.ingress.start(shutdown.clone()).unwrap();
        std::thread::sleep(Duration::from_millis(25));
        shutdown.store(true, Ordering::Relaxed);
        fixture.ingress.request_shutdown();
        for worker in workers {
            worker.join().unwrap();
        }
    }

    #[test]
    fn with_auth_is_safe_after_reverse_hub_is_shared() {
        let dir = std::env::temp_dir().join(format!(
            "dbb-ingress-reverse-auth-{}",
            crate::util::random_hex(6).unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("peer-token"), "0123456789abcdef0123456789abcdef").unwrap();
        let path = dir.join("config.yaml");
        std::fs::write(
            &path,
            "node:\n  id: ingress-a\nhttp:\n  enabled: true\n  listen: '127.0.0.1:0'\npeers:\n  - id: peer-b\n    mode: reverse\n    expected_node_id: egress-b\n    credential_ref: peer-b\n    token_file: peer-token\nlisteners:\n  - id: local\n    listen: '127.0.0.1:0'\n    peer: peer-b\n    target: db\n",
        )
        .unwrap();
        let cfg = Arc::new(crate::config::load(&path).unwrap());
        let auth = Arc::new(crate::auth::Authenticator::new(cfg.clone()));

        let ingress = Ingress::new(cfg).with_auth(auth);
        assert!(ingress.hub.is_some());

        let _ = std::fs::remove_dir_all(dir);
    }
}

#[cfg(test)]
mod spec_listener_warn_tests {
    use super::warn_non_loopback;

    #[test]
    fn spec_non_loopback_listener_warns() {
        let id = format!("open-{}", crate::util::random_hex(4).unwrap());
        let l = crate::config::Listener {
            id: id.clone(),
            listen: "0.0.0.0:3306".into(),
            peer: "p".into(),
            target: "t".into(),
        };
        let mine = || -> Vec<String> {
            crate::slog::test_captured()
                .into_iter()
                .filter(|line| line.contains(&id))
                .collect()
        };
        warn_non_loopback(&l, "127.0.0.1:1".parse().unwrap());
        assert!(mine().is_empty(), "loopback listener warned: {:?}", mine());
        warn_non_loopback(&l, "0.0.0.0:3306".parse().unwrap());
        assert!(
            mine().iter().any(|line| line.contains("non-loopback")),
            "missing warning for a non-loopback listener: {:?}",
            mine()
        );
    }
}
