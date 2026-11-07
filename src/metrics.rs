use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

const RESOURCES: [&str; 16] = [
    "payload",
    "codec",
    "metadata",
    "control_metadata",
    "probe_metadata",
    "sessions",
    "probes",
    "recovery",
    "cleanup",
    "creates",
    "inbound_connections",
    "conn_metadata",
    "data_connections",
    "control_connections",
    "data_requests",
    "control_requests",
];
const OPERATION_BUCKETS: [f64; 10] = [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 30.0, 60.0];
const OPERATION_BUCKET_TEXT: [&str; 10] = [
    "0.001", "0.005", "0.01", "0.05", "0.1", "0.5", "1", "5", "30", "60",
];

#[derive(Clone, Copy, Default)]
struct DurationStats {
    count: u64,
    sum: f64,
    buckets: [u64; 10],
}

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct SessionEventLabels {
    role: String,
    event: String,
    reason: String,
    from: String,
    to: String,
}

#[derive(Clone, Debug, Default)]
pub struct IngressGaugeValue {
    /// (peer, endpoint, transport, recovery) while an active carrier is bound.
    pub bound: Option<(String, String, String, bool)>,
    /// Inside a recovery window without an active carrier.
    pub recovering: bool,
    pub up_pending_bytes: u64,
    pub retained_frames: u64,
}

pub trait IngressGauge: Send + Sync {
    fn ingress_gauge(&self) -> IngressGaugeValue;
    fn shutdown(&self) {}
}

fn one_of<'a>(value: &'a str, allowed: &[&str]) -> &'a str {
    if allowed.contains(&value) {
        value
    } else {
        "other"
    }
}

const EVENT_REASONS: &[&str] = &[
    "normal",
    "network",
    "timeout",
    "protocol",
    "unauthorized",
    "forbidden",
    "instance",
    "offset",
    "quota",
    "backend_lost",
    "barrier",
    "buffer",
    "success",
    "failed",
    "unknown",
    "authentication",
    "transport",
    "shutdown",
    "local_socket",
    "dial_failed",
    "draining",
    "not_needed",
    "skipped",
];
const FAULT_REASONS: &[&str] = &[
    "normal",
    "network",
    "timeout",
    "protocol",
    "unauthorized",
    "forbidden",
    "instance",
    "offset",
    "quota",
    "backend_lost",
    "barrier",
    "buffer",
    "failed",
    "unknown",
    "transport",
    "shutdown",
    "local_socket",
    "dial_failed",
    "draining",
];

/// Live values collected from the egress registry for one Prometheus scrape.
#[derive(Clone, Default)]
pub struct EgressMetricsSnapshot {
    pub live_sessions: u64,
    pub active_sessions: u64,
    pub suspended_sessions: u64,
    pub carrier_sessions: BTreeMap<String, u64>,
    pub states: BTreeMap<String, u64>,
    pub up_pending_frames: u64,
    pub down_retained_frames: u64,
    pub digest_receipts: u64,
    pub down_unconfirmed_bytes: u64,
    pub resource_in_use: BTreeMap<String, u64>,
    pub resource_limits: BTreeMap<String, u64>,
    pub buffer_memory_bytes: u64,
    pub payload_limit: u64,
    pub suspended_mem_bytes: u64,
    pub recovery_retained_bytes: u64,
    pub recovery_retained_limit: u64,
    pub resource_waits: BTreeMap<String, (u64, f64)>,
}

pub struct Metrics {
    sessions_created: AtomicU64,
    sessions_active: AtomicU64,
    suspended_sessions: AtomicU64,
    upstream_frames: AtomicU64,
    upstream_bytes: AtomicU64,
    downstream_frames: AtomicU64,
    downstream_bytes: AtomicU64,
    post_count: AtomicU64,
    piggyback_ack: AtomicU64,
    explicit_ack: AtomicU64,
    up_fin_applied: AtomicU64,
    down_fin_acked: AtomicU64,
    dial_total: AtomicU64,
    dial_failures: AtomicU64,
    ingress_accept_rejected: AtomicU64,
    terminated_direct: AtomicU64,
    terminated_after_resume_fail: AtomicU64,
    client_close_count: AtomicU64,
    client_close_duration_sum_ms: AtomicU64,
    backpressure: AtomicU64,
    admission_rejected: AtomicU64,
    ingress_connections: AtomicU64,
    suspended_mem_bytes: AtomicU64,
    remote_cleanup_failed: AtomicU64,
    remote_cleanup_unknown: AtomicU64,
    auth_reload_success: AtomicU64,
    auth_reload_failed: AtomicU64,
    auth_credentials_stale: AtomicU64,
    auth_reload_last_success_unix: AtomicU64,
    resume_success: AtomicU64,
    resume_failed: AtomicU64,
    reverse_tunnel_established: AtomicU64,
    reverse_tunnel_lost: AtomicU64,
    reverse_tunnel_dial_failures: AtomicU64,
    carrier_sessions: Mutex<BTreeMap<String, u64>>,
    egress_states: Mutex<BTreeMap<String, u64>>,
    ingress_bound_sessions: Mutex<BTreeMap<(String, String, String, String), u64>>,
    session_events: Mutex<BTreeMap<SessionEventLabels, u64>>,
    endpoint_states: Mutex<BTreeMap<(String, String), String>>,
    ingress_faults: Mutex<BTreeMap<(String, String), u64>>,
    operation_durations: Mutex<BTreeMap<(String, String), DurationStats>>,
    phase_durations: Mutex<BTreeMap<(String, String, String, bool), DurationStats>>,
    resource_manager: Mutex<Option<Arc<crate::resource::manager::ResourceManager>>>,
    egress_registry: Mutex<Option<Weak<crate::egress::Registry>>>,
    reverse_hub: Mutex<Option<Weak<crate::tunnel::Hub>>>,
    reverse_hub_rejected: Mutex<BTreeMap<String, u64>>,
    reverse_tunnels: Mutex<BTreeMap<(String, String), u64>>,
    reverse_tunnel_fallback: Mutex<BTreeMap<(String, String), u64>>,
    ingress_live: Mutex<BTreeMap<u64, Weak<dyn IngressGauge>>>,
    ingress_live_next: AtomicU64,
}

impl Metrics {
    pub fn new() -> Self {
        Metrics {
            sessions_created: AtomicU64::new(0),
            sessions_active: AtomicU64::new(0),
            suspended_sessions: AtomicU64::new(0),
            upstream_frames: AtomicU64::new(0),
            upstream_bytes: AtomicU64::new(0),
            downstream_frames: AtomicU64::new(0),
            downstream_bytes: AtomicU64::new(0),
            post_count: AtomicU64::new(0),
            piggyback_ack: AtomicU64::new(0),
            explicit_ack: AtomicU64::new(0),
            up_fin_applied: AtomicU64::new(0),
            down_fin_acked: AtomicU64::new(0),
            dial_total: AtomicU64::new(0),
            dial_failures: AtomicU64::new(0),
            ingress_accept_rejected: AtomicU64::new(0),
            terminated_direct: AtomicU64::new(0),
            terminated_after_resume_fail: AtomicU64::new(0),
            client_close_count: AtomicU64::new(0),
            client_close_duration_sum_ms: AtomicU64::new(0),
            backpressure: AtomicU64::new(0),
            admission_rejected: AtomicU64::new(0),
            ingress_connections: AtomicU64::new(0),
            suspended_mem_bytes: AtomicU64::new(0),
            remote_cleanup_failed: AtomicU64::new(0),
            remote_cleanup_unknown: AtomicU64::new(0),
            auth_reload_success: AtomicU64::new(0),
            auth_reload_failed: AtomicU64::new(0),
            auth_credentials_stale: AtomicU64::new(0),
            auth_reload_last_success_unix: AtomicU64::new(0),
            resume_success: AtomicU64::new(0),
            resume_failed: AtomicU64::new(0),
            reverse_tunnel_established: AtomicU64::new(0),
            reverse_tunnel_lost: AtomicU64::new(0),
            reverse_tunnel_dial_failures: AtomicU64::new(0),
            carrier_sessions: Mutex::new(BTreeMap::new()),
            egress_states: Mutex::new(BTreeMap::new()),
            ingress_bound_sessions: Mutex::new(BTreeMap::new()),
            session_events: Mutex::new(BTreeMap::new()),
            endpoint_states: Mutex::new(BTreeMap::new()),
            ingress_faults: Mutex::new(BTreeMap::new()),
            operation_durations: Mutex::new(BTreeMap::new()),
            phase_durations: Mutex::new(BTreeMap::new()),
            resource_manager: Mutex::new(None),
            egress_registry: Mutex::new(None),
            reverse_hub: Mutex::new(None),
            reverse_hub_rejected: Mutex::new(BTreeMap::new()),
            reverse_tunnels: Mutex::new(BTreeMap::new()),
            reverse_tunnel_fallback: Mutex::new(BTreeMap::new()),
            ingress_live: Mutex::new(BTreeMap::new()),
            ingress_live_next: AtomicU64::new(1),
        }
    }

    /// Registers a live ingress session for the ingress gauges; the returned
    /// id unregisters it.
    pub fn register_ingress(&self, session: Weak<dyn IngressGauge>) -> u64 {
        let id = self.ingress_live_next.fetch_add(1, Ordering::Relaxed);
        self.ingress_live.lock().unwrap().insert(id, session);
        id
    }

    pub fn unregister_ingress(&self, id: u64) {
        self.ingress_live.lock().unwrap().remove(&id);
    }

    pub fn shutdown_ingress_sessions(&self) {
        let live: Vec<_> = self
            .ingress_live
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        for session in live.iter().filter_map(Weak::upgrade) {
            session.shutdown();
        }
    }

    /// Open ingress client connections (sessions still running or cleaning up).
    pub fn ingress_connection_count(&self) -> u64 {
        self.ingress_connections.load(Ordering::Relaxed)
    }

    pub(crate) fn ingress_gauges(&self) -> Vec<IngressGaugeValue> {
        let live: Vec<_> = self
            .ingress_live
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect();
        live.iter()
            .filter_map(Weak::upgrade)
            .map(|s| s.ingress_gauge())
            .collect()
    }

    pub fn client_closed(&self, local_close_ms: i64) {
        self.client_close_count.fetch_add(1, Ordering::Relaxed);
        self.client_close_duration_sum_ms
            .fetch_add(local_close_ms.max(0) as u64, Ordering::Relaxed);
    }

    pub fn reverse_hub_rejected(&self, code: &str) {
        *self
            .reverse_hub_rejected
            .lock()
            .unwrap()
            .entry(code.to_string())
            .or_insert(0) += 1;
    }

    /// A connection or request refused by admission control.
    pub fn admission_rejected(&self) {
        self.admission_rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn observe_ingress_phase(
        &self,
        peer: &str,
        endpoint: &str,
        phase: &str,
        success: bool,
        elapsed: Duration,
    ) {
        self.observe_operation("ingress", phase, elapsed);
        self.observe_phase(peer, endpoint, phase, success, elapsed);
    }

    pub fn configure_resources(&self, cfg: &crate::config::Config) {
        let mut manager = self
            .resource_manager
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if manager.is_none() {
            *manager = Some(crate::resource::manager::ResourceManager::new(cfg));
        }
    }

    pub fn resource_manager(&self) -> Option<Arc<crate::resource::manager::ResourceManager>> {
        self.resource_manager
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// One egress session started.
    pub fn session_opened(&self) {
        self.sessions_created.fetch_add(1, Ordering::Relaxed);
        self.sessions_active.fetch_add(1, Ordering::Relaxed);
    }

    /// One session ended. Saturating, so a stray close cannot wrap the gauge.
    pub fn session_closed(&self) {
        let mut cur = self.sessions_active.load(Ordering::Relaxed);
        loop {
            if cur == 0 {
                return;
            }
            match self.sessions_active.compare_exchange_weak(
                cur,
                cur - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(now) => cur = now,
            }
        }
    }

    pub fn upstream(&self, bytes: usize) {
        self.upstream_frames.fetch_add(1, Ordering::Relaxed);
        self.upstream_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Counts bytes only after they have been written to a local client.
    pub fn downstream(&self, bytes: usize) {
        self.downstream_frames.fetch_add(1, Ordering::Relaxed);
        self.downstream_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn post_received(&self) {
        self.post_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn piggyback_acknowledged(&self) {
        self.piggyback_ack.fetch_add(1, Ordering::Relaxed);
    }

    pub fn explicit_ack_received(&self) {
        self.explicit_ack.fetch_add(1, Ordering::Relaxed);
    }

    pub fn upstream_fin_applied(&self) {
        self.up_fin_applied.fetch_add(1, Ordering::Relaxed);
    }

    pub fn downstream_fin_acked(&self) {
        self.down_fin_acked.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_egress_registry(&self, registry: Weak<crate::egress::Registry>) {
        *self.egress_registry.lock().unwrap() = Some(registry);
    }

    pub fn dial_attempted(&self) {
        self.dial_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn ingress_accept_rejected(&self) -> u64 {
        self.ingress_accept_rejected.fetch_add(1, Ordering::Relaxed) + 1
    }

    pub fn ingress_connection_opened(&self) {
        self.ingress_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn ingress_connection_closed(&self) {
        let mut current = self.ingress_connections.load(Ordering::Relaxed);
        loop {
            if current == 0 {
                return;
            }
            match self.ingress_connections.compare_exchange_weak(
                current,
                current - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(now) => current = now,
            }
        }
    }

    pub fn dial_failed(&self) {
        self.dial_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn remote_cleanup_failed(&self) {
        self.remote_cleanup_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn remote_cleanup_unknown(&self) {
        self.remote_cleanup_unknown.fetch_add(1, Ordering::Relaxed);
    }

    pub fn resume_succeeded(&self) {
        self.resume_success.fetch_add(1, Ordering::Relaxed);
    }

    pub fn resume_failed(&self) {
        self.resume_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn session_terminated(&self, recovery_enabled: bool, reason: &str) {
        if matches!(reason, "normal" | "shutdown") {
            return;
        }
        let counter = if recovery_enabled {
            &self.terminated_after_resume_fail
        } else {
            &self.terminated_direct
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn reverse_tunnel_fallback(&self, from: &str, to: &str) {
        let mut counters = self.reverse_tunnel_fallback.lock().unwrap();
        *counters
            .entry((from.to_string(), to.to_string()))
            .or_insert(0) += 1;
    }

    pub fn reverse_tunnel_opened(&self, endpoint: &str, transport: &str) {
        let mut live = self.reverse_tunnels.lock().unwrap();
        *live
            .entry((endpoint.to_string(), transport.to_string()))
            .or_insert(0) += 1;
        self.reverse_tunnel_established
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn reverse_tunnel_closed(&self, endpoint: &str, transport: &str, lost: bool) {
        let mut live = self.reverse_tunnels.lock().unwrap();
        if let Some(count) = live.get_mut(&(endpoint.to_string(), transport.to_string())) {
            *count = count.saturating_sub(1);
        }
        if lost {
            self.reverse_tunnel_lost.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn reverse_tunnel_dial_failed(&self) {
        self.reverse_tunnel_dial_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_reverse_hub(&self, hub: &std::sync::Arc<crate::tunnel::Hub>) {
        *self.reverse_hub.lock().unwrap() = Some(std::sync::Arc::downgrade(hub));
    }

    pub fn auth_reload_failed(&self) {
        self.auth_reload_failed.fetch_add(1, Ordering::Relaxed);
        self.auth_credentials_stale.store(1, Ordering::Relaxed);
    }

    pub fn auth_reload_succeeded(&self, changed: bool) {
        if changed {
            self.auth_reload_success.fetch_add(1, Ordering::Relaxed);
        }
        self.auth_credentials_stale.store(0, Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.auth_reload_last_success_unix
            .store(now, Ordering::Relaxed);
    }

    pub fn record_session_event(
        &self,
        role: &str,
        event: &str,
        reason: &str,
        from: &str,
        to: &str,
    ) {
        let role = one_of(role, &["ingress", "egress"]);
        let event = one_of(
            event,
            &[
                "fault",
                "terminate",
                "resume",
                "fallback",
                "cleanup",
                "cache_hit",
                "cache_miss",
                "cache_invalidate",
                "precheck",
                "attach",
            ],
        );
        let reason = one_of(reason, EVENT_REASONS);
        let from = one_of(from, &["ws", "http-sse", "none"]);
        let to = one_of(to, &["ws", "http-sse", "none"]);
        let mut values = self.session_events.lock().unwrap();
        *values
            .entry(SessionEventLabels {
                role: role.into(),
                event: event.into(),
                reason: reason.into(),
                from: from.into(),
                to: to.into(),
            })
            .or_insert(0) += 1;
    }

    /// Test helper: the summed `dbb_session_events_total` for one
    /// role/event/reason across transports.
    #[cfg(test)]
    pub(crate) fn session_event_total(&self, role: &str, event: &str, reason: &str) -> u64 {
        self.session_events
            .lock()
            .unwrap()
            .iter()
            .filter(|(k, _)| k.role == role && k.event == event && k.reason == reason)
            .map(|(_, v)| *v)
            .sum()
    }

    pub fn record_ingress_fault(&self, source: &str, reason: &str) {
        let source = one_of(source, &["data", "upstream", "control", "liveness"]);
        let reason = one_of(reason, FAULT_REASONS);
        let mut values = self.ingress_faults.lock().unwrap();
        *values.entry((source.into(), reason.into())).or_insert(0) += 1;
    }

    pub fn observe_operation(&self, role: &str, phase: &str, elapsed: Duration) {
        let role = one_of(role, &["ingress", "egress"]);
        let phase = one_of(
            phase,
            &[
                "barrier",
                "local_close",
                "recovery",
                "cleanup",
                "probe",
                "precheck",
                "attach",
                "control",
            ],
        );
        let mut values = self.operation_durations.lock().unwrap();
        observe_duration(
            values.entry((role.into(), phase.into())).or_default(),
            elapsed,
        );
    }

    pub fn operation_timer(&self, role: &'static str, phase: &'static str) -> OperationTimer<'_> {
        OperationTimer {
            metrics: self,
            role,
            phase,
            started: std::time::Instant::now(),
        }
    }

    pub fn backpressure_waited(&self) {
        self.backpressure.fetch_add(1, Ordering::Relaxed);
    }

    #[allow(dead_code)]
    pub fn observe_phase(
        &self,
        peer: &str,
        endpoint: &str,
        phase: &str,
        success: bool,
        elapsed: Duration,
    ) {
        let mut values = self.phase_durations.lock().unwrap();
        observe_duration(
            values
                .entry((peer.into(), endpoint.into(), phase.into(), success))
                .or_default(),
            elapsed,
        );
    }

    #[allow(dead_code)]
    pub fn set_ingress_bound_sessions(
        &self,
        peer: &str,
        endpoint: &str,
        transport: &str,
        recovery: bool,
        value: u64,
    ) {
        self.ingress_bound_sessions.lock().unwrap().insert(
            (
                peer.into(),
                endpoint.into(),
                transport.into(),
                recovery.to_string(),
            ),
            value,
        );
    }

    #[allow(dead_code)]
    pub fn set_egress_state(&self, state: &str, value: u64) {
        self.egress_states
            .lock()
            .unwrap()
            .insert(state.into(), value);
    }

    pub fn set_endpoint_state(&self, peer: &str, endpoint: &str, state: &str) {
        self.endpoint_states
            .lock()
            .unwrap()
            .insert((peer.into(), endpoint.into()), state.into());
    }

    pub fn clear_endpoint_state(&self, peer: &str, endpoint: &str) {
        self.endpoint_states
            .lock()
            .unwrap()
            .remove(&(peer.into(), endpoint.into()));
    }
}

fn observe_duration(stats: &mut DurationStats, elapsed: Duration) {
    let seconds = elapsed.as_secs_f64();
    stats.count += 1;
    stats.sum += seconds;
    for (index, bound) in OPERATION_BUCKETS.iter().enumerate() {
        if seconds <= *bound {
            stats.buckets[index] += 1;
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

pub struct OperationTimer<'a> {
    metrics: &'a Metrics,
    role: &'static str,
    phase: &'static str,
    started: std::time::Instant,
}

impl Drop for OperationTimer<'_> {
    fn drop(&mut self) {
        self.metrics
            .observe_operation(self.role, self.phase, self.started.elapsed());
    }
}

mod render;
mod render_helpers;

#[cfg(test)]
mod spec_metrics3_tests;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod spec_metrics_tests;
