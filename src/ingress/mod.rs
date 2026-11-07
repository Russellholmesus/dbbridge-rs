//! The ingress role: accepts local database connections and forwards each one
//! to a peer.
//!
//! Per connection it picks an endpoint (by priority, skipping endpoints in
//! cooldown), probes it, creates a session, attaches a carrier and then relays
//! bytes. The relay has three moving parts — upstream, downstream and the
//! control ticker — that share one piece of offset state.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::error::Error;
use crate::net::http1::Client;
use crate::transport::control::ControlClient;
use crate::wire::{self, Mode};

struct PrecheckEntry {
    expires: Instant,
    stale_until: Instant,
    answer: Option<String>,
    last_used: Instant,
    refreshing: bool,
}

type PrecheckCache = HashMap<String, PrecheckEntry>;

/// What a probe told us about one endpoint, cached until it goes stale.
#[derive(Clone)]
struct Health {
    instance_id: String,
    transports: Vec<Mode>,
    /// Whether the peer said it is taking new sessions. An endpoint that is
    /// draining must not be handed a new one.
    accepting_new_sessions: bool,
    probed_at: Instant,
    cooldown_until: Option<Instant>,
    failures: u32,
    probe_failures: u32,
    successes: u32,
    state: &'static str,
}

/// An instant old enough that any cached answer stamped with it is stale.
fn stale_instant() -> Instant {
    let now = Instant::now();
    now.checked_sub(Duration::from_secs(3600))
        .or_else(|| now.checked_sub(Duration::from_secs(60)))
        .unwrap_or(now)
}

#[derive(Default)]
struct EndpointTable {
    inner: Mutex<HashMap<(String, String), Health>>,
    carriers: Mutex<HashMap<(String, String, Mode), Instant>>,
}

impl EndpointTable {
    fn record_transport_failure(&self, peer: &str, ep: &str, mode: Mode, cooldown: Duration) {
        let until = Instant::now() + cooldown;
        let mut g = self.carriers.lock().unwrap();
        let entry = g
            .entry((peer.to_string(), ep.to_string(), mode))
            .or_insert(until);
        if until > *entry {
            *entry = until;
        }
    }

    fn transport_available(&self, peer: &str, ep: &str, mode: Mode, now: Instant) -> bool {
        self.carriers
            .lock()
            .unwrap()
            .get(&(peer.to_string(), ep.to_string(), mode))
            .map_or(true, |until| now >= *until)
    }

    fn next_eligible(&self, peer: &str, ep: &str, modes: &[Mode], now: Instant) -> Option<Instant> {
        let carriers = self.carriers.lock().unwrap();
        let carrier = modes
            .iter()
            .map(|m| {
                carriers
                    .get(&(peer.to_string(), ep.to_string(), *m))
                    .copied()
                    .unwrap_or(now)
            })
            .min()
            .unwrap_or(now);
        drop(carriers);
        let address = self
            .get(peer, ep)
            .and_then(|h| h.cooldown_until)
            .unwrap_or(now);
        let next = address.max(carrier);
        (next > now).then_some(next)
    }

    fn get(&self, peer: &str, ep: &str) -> Option<Health> {
        self.inner
            .lock()
            .unwrap()
            .get(&(peer.to_string(), ep.to_string()))
            .cloned()
    }

    fn put(&self, peer: &str, ep: &str, mut h: Health, healthy_threshold: u32) -> &'static str {
        let mut inner = self.inner.lock().unwrap();
        let key = (peer.to_string(), ep.to_string());
        if let Some(previous) = inner.get(&key) {
            let now = Instant::now();
            h.cooldown_until = previous
                .cooldown_until
                .filter(|t| *t > now)
                .or(h.cooldown_until);
            h.successes = previous.successes.saturating_add(1);
            h.state = if h.successes >= healthy_threshold.max(1) {
                "HEALTHY"
            } else {
                previous.state
            };
        } else {
            h.successes = 1;
            h.state = if healthy_threshold <= 1 {
                "HEALTHY"
            } else {
                "UNKNOWN"
            };
        }
        h.failures = 0;
        h.probe_failures = 0;
        let state = h.state;
        inner.insert(key, h);
        state
    }

    fn invalidate(&self, peer: &str, ep: &str) {
        self.inner
            .lock()
            .unwrap()
            .remove(&(peer.to_string(), ep.to_string()));
    }

    /// Marks an endpoint unusable for `cooldown`, so the next connection moves
    /// to the next priority instead of paying the same timeout again.
    fn penalize(&self, peer: &str, ep: &str, cooldown: Duration) {
        let mut g = self.inner.lock().unwrap();
        let key = (peer.to_string(), ep.to_string());
        let entry = g.entry(key).or_insert(Health {
            instance_id: String::new(),
            transports: Vec::new(),
            accepting_new_sessions: false,
            probed_at: Instant::now(),
            cooldown_until: None,
            failures: 0,
            probe_failures: 0,
            successes: 0,
            state: "UNKNOWN",
        });
        entry.failures = entry.failures.saturating_add(1);
        entry.cooldown_until = Some(Instant::now() + cooldown);
        entry.accepting_new_sessions = true;
        entry.probed_at = stale_instant();
    }

    fn other_endpoint_available(
        &self,
        peer: &str,
        ep: &str,
        endpoints: &[crate::config::Endpoint],
    ) -> bool {
        let now = Instant::now();
        let g = self.inner.lock().unwrap();
        endpoints.iter().any(|e| {
            e.id != ep
                && match g.get(&(peer.to_string(), e.id.clone())) {
                    None => true,
                    Some(h) => {
                        !matches!(h.cooldown_until, Some(t) if now < t)
                            && h.state != "UNHEALTHY"
                            && h.state != "MISMATCHED"
                            && h.accepting_new_sessions
                    }
                }
        })
    }

    /// Earliest end of a running cooldown over `endpoints` of `peer`, or
    /// `None` when some endpoint is not cooling down.
    fn cooldown_end(&self, peer: &str, endpoints: &[crate::config::Endpoint]) -> Option<Instant> {
        let now = Instant::now();
        let g = self.inner.lock().unwrap();
        let mut first: Option<Instant> = None;
        for e in endpoints {
            let until = g
                .get(&(peer.to_string(), e.id.clone()))
                .and_then(|h| h.cooldown_until)
                .filter(|t| *t > now)?;
            first = Some(first.map_or(until, |f| f.min(until)));
        }
        first
    }

    fn record_probe_failure(
        &self,
        peer: &str,
        ep: &str,
        cooldown: Duration,
        unhealthy_threshold: u32,
        mismatched: bool,
    ) -> &'static str {
        let mut g = self.inner.lock().unwrap();
        let key = (peer.to_string(), ep.to_string());
        let entry = g.entry(key).or_insert(Health {
            instance_id: String::new(),
            transports: Vec::new(),
            accepting_new_sessions: false,
            probed_at: Instant::now(),
            cooldown_until: None,
            failures: 0,
            probe_failures: 0,
            successes: 0,
            state: "UNKNOWN",
        });
        entry.failures = entry.failures.saturating_add(1);
        entry.probe_failures = entry.probe_failures.saturating_add(1);
        entry.successes = 0;
        if mismatched || entry.probe_failures >= unhealthy_threshold.max(1) {
            entry.cooldown_until = Some(Instant::now() + cooldown);
        }
        entry.probed_at = stale_instant();
        if mismatched {
            entry.state = "MISMATCHED";
        } else if entry.probe_failures >= unhealthy_threshold.max(1) {
            entry.state = "UNHEALTHY";
        }
        entry.state
    }

    fn in_cooldown(&self, peer: &str, ep: &str) -> bool {
        match self.get(peer, ep) {
            Some(h) => h
                .cooldown_until
                .map(|t| Instant::now() < t)
                .unwrap_or(false),
            None => false,
        }
    }
}

pub struct Ingress {
    pub cfg: Arc<Config>,
    pub client: Arc<Client>,
    pub metrics: Arc<crate::metrics::Metrics>,
    pub auth: Option<Arc<crate::auth::Authenticator>>,
    endpoints: Arc<EndpointTable>,
    /// The public side of reverse mode, shared with the egress server that
    /// accepts the tunnels.
    pub hub: Option<Arc<crate::tunnel::Hub>>,
    /// Per-peer clients for reverse peers: each opens its connections as
    /// streams on that peer's tunnel instead of dialing a socket.
    reverse_clients: HashMap<String, Arc<Client>>,
    /// Forward clients are per-peer so pooled connections cannot mix TLS
    /// policies between peers that happen to share an authority.
    peer_clients: HashMap<String, Arc<Client>>,
    /// Whether WebSocket works on an endpoint, keyed by peer, endpoint and
    /// egress instance.
    ///
    /// Without this the ingress dials a WebSocket precheck for *every* client
    /// connection. A peer that rate-limits prechecks answers 429 after a few,
    /// and the ingress then falls back to SSE for a path that is fine — the
    /// fallback is correct, but asking every time is not. A definitive answer
    /// is reused for `PRECHECK_TTL`; a transient one is never cached.
    prechecks: Arc<Mutex<PrecheckCache>>,
    /// Bound addresses are used to wake the blocking acceptors during drain.
    accept_addrs: Arc<Mutex<Vec<std::net::SocketAddr>>>,
    drain: Arc<DrainState>,
    fatal: Arc<Mutex<Option<serve::FatalHandler>>>,
    cleanups: Arc<serve::cleanup::CleanupTracker>,
}

#[derive(Default)]
pub(super) struct DrainState {
    draining: AtomicBool,
    next_id: std::sync::atomic::AtomicU64,
    active: Mutex<HashMap<u64, Option<std::net::TcpStream>>>,
}

impl DrainState {
    pub(super) fn draining(&self) -> bool {
        self.draining.load(Ordering::SeqCst)
    }

    /// Registers one accepted local connection until the guard drops.
    pub(super) fn track(self: &Arc<Self>, local: Option<std::net::TcpStream>) -> ActiveConn {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id, local);
        ActiveConn {
            state: self.clone(),
            id,
        }
    }

    fn count(&self) -> usize {
        self.active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    fn close_all(&self) {
        let active = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for local in active.values().flatten() {
            let _ = local.shutdown(std::net::Shutdown::Both);
        }
    }
}

/// One entry of `DrainState::active`, removed on drop.
pub(super) struct ActiveConn {
    state: Arc<DrainState>,
    id: u64,
}

impl Drop for ActiveConn {
    fn drop(&mut self) {
        self.state
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.id);
    }
}

impl Ingress {
    pub fn drain(&self) {
        if !self.drain.draining.swap(true, Ordering::SeqCst) {
            self.wake_listeners();
        }
    }

    pub fn count(&self) -> usize {
        self.drain.count()
    }

    pub fn close_until(&self, deadline: Instant) {
        self.drain();
        self.drain.close_all();
        while self.drain.count() > 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        Self::wait_cleanups(&self.cleanups, deadline);
    }

    pub(in crate::ingress) fn wait_cleanups(
        cleanups: &serve::cleanup::CleanupTracker,
        deadline: Instant,
    ) -> bool {
        cleanups
            .idle()
            .wait_timeout(deadline.saturating_duration_since(Instant::now()))
    }
}

const PRECHECK_TTL: Duration = Duration::from_secs(30);
const PRECHECK_STALE_MAX: Duration = Duration::from_secs(5 * 60);
const PRECHECK_KEEP_WARM: Duration = Duration::from_secs(2 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PrecheckVerdict {
    WsUnavailable,
    SessionFailed,
    Mismatched,
    Temporary,
}

/// Classify from structured metadata only; human-readable messages are never
/// used to decide whether an endpoint may carry another session.
pub(super) fn classify_precheck(e: &Error) -> PrecheckVerdict {
    if matches!(
        e.code.as_str(),
        wire::ERR_WS_PROTOCOL_ERROR
            | wire::ERR_PROTOCOL_MISMATCH
            | wire::ERR_INSTANCE_MISMATCH
            | wire::ERR_NODE_MISMATCH
            | wire::ERR_TRANSPORT_MISMATCH
            | wire::ERR_TLS_FAILED
    ) {
        return PrecheckVerdict::Mismatched;
    }
    if e.code == wire::ERR_UNAUTHORIZED
        || (e.code == wire::ERR_TARGET_FORBIDDEN && e.trusted)
        || (e.remote_status == Some(403) && e.trusted)
        || e.remote_status == Some(401)
    {
        return PrecheckVerdict::SessionFailed;
    }
    if e.code == wire::ERR_TRANSPORT_UNSUPPORTED && e.trusted {
        return PrecheckVerdict::WsUnavailable;
    }
    if e.retryable
        || (e.trusted && matches!(e.remote_status, Some(408 | 425 | 429)))
        || matches!(e.remote_status, Some(status) if status >= 500 && e.trusted)
    {
        return PrecheckVerdict::Temporary;
    }
    if e.remote_status.is_some() || e.code == wire::ERR_WS_HANDSHAKE_FAILED {
        return PrecheckVerdict::WsUnavailable;
    }
    PrecheckVerdict::WsUnavailable
}

/// Cache only definitive endpoint answers; 408/425/429 and all 5xx are
/// transient and must never pin an endpoint for the TTL.
pub(super) fn precheck_cacheable(e: &Error) -> bool {
    !e.retryable
        && !matches!(e.remote_status, Some(408 | 425 | 429))
        && !matches!(e.remote_status, Some(status) if status >= 500)
}

#[allow(dead_code)]
mod errors;
mod link;
mod relay;
mod select;
mod serve;
mod termination;

pub use relay::Relay;

fn control_client_clone(c: &ControlClient) -> ControlClient {
    ControlClient {
        client: c.client.clone(),
        url: c.url.clone(),
        token: c.token.clone(),
        token_provider: c.token_provider.clone(),
        expected_instance: c.expected_instance.clone(),
        tls: c.tls.clone(),
    }
}

#[cfg(test)]
mod drain_tests {
    use super::*;

    #[test]
    fn drain_state_counts_and_closes_local_connections() {
        use std::io::Read;
        let ln = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = std::net::TcpStream::connect(ln.local_addr().unwrap()).unwrap();
        let (server, _) = ln.accept().unwrap();
        let state = Arc::new(DrainState::default());
        assert!(!state.draining());
        let guard = state.track(server.try_clone().ok());
        assert_eq!(state.count(), 1);
        state.close_all();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut buf = [0u8; 1];
        assert_eq!(client.read(&mut buf).unwrap(), 0);
        drop(guard);
        assert_eq!(state.count(), 0);
    }
}

#[cfg(test)]
#[path = "spec_link_tests.rs"]
mod spec_link_tests;

#[cfg(test)]
#[path = "spec_unit_tests.rs"]
mod spec_unit_tests;

#[cfg(test)]
mod tests {
    use super::errors::{fatal_error, pause_delay, reason_category, safe_retry};
    use super::{classify_precheck, precheck_cacheable, EndpointTable, Health, PrecheckVerdict};
    use crate::config::Protocol;
    use crate::error::Error;
    use crate::wire;
    use std::time::Duration;

    fn remote(code: &str, status: u16, trusted: bool, retryable: bool, closed: bool) -> Error {
        Error::new(code, "test")
            .remote_status(status)
            .trusted(trusted)
            .retryable(retryable)
            .closed(closed)
    }

    #[test]
    fn fatal_error_table() {
        assert!(fatal_error(&remote(
            wire::ERR_BAD_FRAME,
            400,
            true,
            false,
            false
        )));
        assert!(fatal_error(&remote(
            wire::ERR_SESSION_CLOSED,
            410,
            true,
            false,
            true
        )));
        assert!(!fatal_error(&remote(
            wire::ERR_BAD_FRAME,
            400,
            false,
            false,
            false
        )));
    }

    #[test]
    fn safe_retry_table() {
        assert!(safe_retry(&remote(
            wire::ERR_QUOTA_EXCEEDED,
            429,
            true,
            true,
            false
        )));
        assert!(safe_retry(&remote(
            wire::ERR_WINDOW_EXCEEDED,
            409,
            true,
            true,
            false
        )));
        assert!(!safe_retry(&remote(
            wire::ERR_QUOTA_EXCEEDED,
            429,
            false,
            true,
            false
        )));
    }

    #[test]
    fn retry_after_capped_2s() {
        let e = remote(wire::ERR_QUOTA_EXCEEDED, 429, true, true, false)
            .retry_after(Duration::from_secs(99));
        assert_eq!(pause_delay(0, &e, 0), Duration::from_secs(2));
    }

    #[test]
    fn reason_category_table() {
        assert_eq!(
            reason_category(&Error::new(wire::ERR_BACKEND_LOST, "x")),
            "backend_lost"
        );
        assert_eq!(
            reason_category(&Error::new(wire::ERR_BAD_ACK, "x")),
            "offset"
        );
        assert_eq!(
            reason_category(&Error::local("connection reset")),
            "network"
        );
    }

    #[test]
    fn endpoint_health_state_obeys_configured_thresholds() {
        let endpoints = EndpointTable::default();
        let healthy = || Health {
            instance_id: "instance".into(),
            transports: vec![crate::wire::Mode::Ws],
            accepting_new_sessions: true,
            probed_at: std::time::Instant::now(),
            cooldown_until: None,
            failures: 0,
            probe_failures: 0,
            successes: 0,
            state: "UNKNOWN",
        };

        assert_eq!(endpoints.put("peer", "endpoint", healthy(), 2), "UNKNOWN");
        assert_eq!(endpoints.put("peer", "endpoint", healthy(), 2), "HEALTHY");
        assert_eq!(
            endpoints.record_probe_failure("peer", "endpoint", Duration::from_secs(1), 2, false,),
            "HEALTHY"
        );
        assert_eq!(
            endpoints.record_probe_failure("peer", "endpoint", Duration::from_secs(1), 2, false,),
            "UNHEALTHY"
        );
        assert_eq!(
            endpoints.record_probe_failure("peer", "endpoint", Duration::from_secs(1), 3, true,),
            "MISMATCHED"
        );
    }

    #[test]
    fn instance_mismatch_reprobes_without_cooldown() {
        super::serve::tests::instance_mismatch_reprobes_without_cooldown();
    }

    #[test]
    fn create_fails_over_to_second_endpoint_on_503() {
        super::serve::tests::create_fails_over_to_second_endpoint_on_503();
    }

    #[test]
    fn classify_precheck_matches_spec_trusted_and_raw_status_matrix() {
        let cases = [
            (
                "hello protocol mismatch",
                Error::new(wire::ERR_WS_PROTOCOL_ERROR, "node ID mismatch"),
                PrecheckVerdict::Mismatched,
            ),
            (
                "trusted instance mismatch",
                remote(wire::ERR_INSTANCE_MISMATCH, 409, true, false, false),
                PrecheckVerdict::Mismatched,
            ),
            (
                "trusted 401",
                remote(wire::ERR_UNAUTHORIZED, 401, true, false, false),
                PrecheckVerdict::SessionFailed,
            ),
            (
                "trusted 403",
                remote(wire::ERR_UNAUTHORIZED, 403, true, false, false),
                PrecheckVerdict::SessionFailed,
            ),
            (
                "raw 401",
                remote(wire::ERR_INTERNAL_ERROR, 401, false, false, false),
                PrecheckVerdict::SessionFailed,
            ),
            (
                "raw 403",
                remote(wire::ERR_INTERNAL_ERROR, 403, false, false, false),
                PrecheckVerdict::WsUnavailable,
            ),
            (
                "raw redirect",
                remote(wire::ERR_INTERNAL_ERROR, 302, false, false, false),
                PrecheckVerdict::WsUnavailable,
            ),
            (
                "raw proxy authentication",
                remote(wire::ERR_INTERNAL_ERROR, 407, false, false, false),
                PrecheckVerdict::WsUnavailable,
            ),
            (
                "raw server error",
                remote(wire::ERR_INTERNAL_ERROR, 500, false, false, false),
                PrecheckVerdict::WsUnavailable,
            ),
            (
                "trusted transport unsupported",
                remote(wire::ERR_TRANSPORT_UNSUPPORTED, 400, true, false, false),
                PrecheckVerdict::WsUnavailable,
            ),
            (
                "trusted server error",
                remote(wire::ERR_INTERNAL_ERROR, 500, true, false, false),
                PrecheckVerdict::Temporary,
            ),
            (
                "trusted retryable quota",
                remote(wire::ERR_QUOTA_EXCEEDED, 429, true, true, false),
                PrecheckVerdict::Temporary,
            ),
            (
                "upgrade refusal",
                Error::new(wire::ERR_WS_HANDSHAKE_FAILED, "status 426"),
                PrecheckVerdict::WsUnavailable,
            ),
            (
                "connection reset",
                Error::local("connection reset by peer"),
                PrecheckVerdict::WsUnavailable,
            ),
        ];

        for (name, error, expected) in cases {
            assert_eq!(classify_precheck(&error), expected, "{name}");
        }
    }

    #[test]
    fn ws_precheck_read_timeout_is_temporary_and_not_cached() {
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            thread::sleep(Duration::from_millis(160));
        });

        let url = crate::net::Url::parse(&format!("http://127.0.0.1:{}", address.port())).unwrap();
        let client = crate::net::http1::Client::new(Duration::from_secs(1), Duration::from_secs(1));
        let dialer = client.dialer();
        let error = crate::transport::ws_carrier::precheck_via(
            &*dialer,
            &url,
            &[],
            Duration::from_millis(60),
        )
        .unwrap_err();
        server.join().unwrap();

        assert!(error.is_local(), "expected a local timeout, got {error:?}");
        assert!(
            error.retryable,
            "precheck timeout must be retryable: {error:?}"
        );
        assert_eq!(classify_precheck(&error), PrecheckVerdict::Temporary);
        assert!(!precheck_cacheable(&error), "a timeout must not be cached");
    }

    #[test]
    fn precheck_classification_table() {
        let cases = [
            (
                Error::new(wire::ERR_UNAUTHORIZED, "x"),
                PrecheckVerdict::SessionFailed,
            ),
            (
                Error::new(wire::ERR_TARGET_FORBIDDEN, "x").trusted(true),
                PrecheckVerdict::SessionFailed,
            ),
            (
                Error::new(wire::ERR_TARGET_FORBIDDEN, "x"),
                PrecheckVerdict::WsUnavailable,
            ),
            (
                Error::new(wire::ERR_TRANSPORT_UNSUPPORTED, "x").trusted(true),
                PrecheckVerdict::WsUnavailable,
            ),
            (
                Error::new(wire::ERR_WS_PROTOCOL_ERROR, "x"),
                PrecheckVerdict::Mismatched,
            ),
            (
                Error::new(wire::ERR_WS_HANDSHAKE_FAILED, "x"),
                PrecheckVerdict::WsUnavailable,
            ),
            (
                Error::new(wire::ERR_INTERNAL_ERROR, "x")
                    .remote_status(503)
                    .trusted(true),
                PrecheckVerdict::Temporary,
            ),
            (
                Error::new(wire::ERR_INTERNAL_ERROR, "gateway").remote_status(503),
                PrecheckVerdict::WsUnavailable,
            ),
        ];
        for (error, expected) in cases {
            assert_eq!(classify_precheck(&error), expected);
        }
    }

    #[test]
    fn forced_ws_never_uses_sse() {
        assert_eq!(
            super::select::mode_without_ws(Protocol::Ws, false, true),
            Err(wire::ERR_TRANSPORT_UNSUPPORTED)
        );
    }

    #[test]
    fn precheck_transient_statuses_are_never_cached() {
        for status in [408, 425, 429, 500, 501, 502, 503, 504, 599] {
            let e = Error::new(wire::ERR_INTERNAL_ERROR, "ignored")
                .remote_status(status)
                .trusted(true);
            assert!(!precheck_cacheable(&e), "status {status}");
        }
        assert!(precheck_cacheable(
            &Error::new(wire::ERR_TRANSPORT_UNSUPPORTED, "ignored").trusted(true)
        ));
        assert!(!precheck_cacheable(
            &Error::new(wire::ERR_TRANSPORT_UNSUPPORTED, "ignored").retryable(true)
        ));
    }

    #[test]
    fn precheck_auth_and_mismatch_classification_does_not_use_message() {
        assert_eq!(
            classify_precheck(
                &Error::new(wire::ERR_INTERNAL_ERROR, "401 is only text")
                    .trusted(false)
                    .remote_status(401)
            ),
            PrecheckVerdict::SessionFailed
        );
        assert_eq!(
            classify_precheck(
                &Error::new(wire::ERR_INTERNAL_ERROR, "403 is only text")
                    .trusted(true)
                    .remote_status(403)
            ),
            PrecheckVerdict::SessionFailed
        );
        assert_eq!(
            classify_precheck(
                &Error::new(wire::ERR_PROTOCOL_MISMATCH, "arbitrary message").remote_status(409)
            ),
            PrecheckVerdict::Mismatched
        );
    }
}

#[cfg(test)]
#[path = "spec_e2e_harness.rs"]
mod spec_e2e_harness;

#[cfg(test)]
#[path = "spec_e2e_tests.rs"]
mod spec_e2e_tests;

#[cfg(test)]
#[path = "spec_precheck_tests.rs"]
mod spec_precheck_tests;

#[cfg(test)]
#[path = "spec_e2e2_tests.rs"]
mod spec_e2e2_tests;

#[cfg(test)]
#[path = "spec_select3_tests.rs"]
mod spec_select3_tests;

#[cfg(test)]
#[path = "spec_e2e3_tests.rs"]
mod spec_e2e3_tests;

#[cfg(test)]
#[path = "spec_recovery3_tests.rs"]
mod spec_recovery3_tests;

#[cfg(test)]
#[path = "spec_shutdown_tests.rs"]
mod spec_shutdown_tests;

#[cfg(test)]
#[path = "spec_blackhole_tests.rs"]
pub(super) mod spec_blackhole_tests;

#[cfg(test)]
#[path = "spec_probe3_tests.rs"]
mod spec_probe3_tests;

#[cfg(test)]
#[path = "spec_e2e4_tests.rs"]
mod spec_e2e4_tests;

#[cfg(test)]
#[path = "spec_flow3_tests.rs"]
mod spec_flow3_tests;

#[cfg(test)]
#[path = "spec_sse_comment3_tests.rs"]
mod spec_sse_comment3_tests;

#[cfg(test)]
#[path = "spec_liveness3_tests.rs"]
mod spec_liveness3_tests;

#[cfg(test)]
#[path = "spec_boundary3_tests.rs"]
mod spec_boundary3_tests;

#[cfg(test)]
#[path = "spec_metrics3_tests.rs"]
mod spec_metrics3_tests;

#[cfg(test)]
#[path = "spec_lifecycle3_tests.rs"]
mod spec_lifecycle3_tests;

#[cfg(test)]
#[path = "halfclose_stress_tests.rs"]
mod halfclose_stress_tests;

#[cfg(test)]
#[path = "spec_missing_tests.rs"]
mod spec_missing_tests;
