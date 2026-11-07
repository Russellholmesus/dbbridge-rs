//! The egress role: terminates peer traffic and talks to the database.
//!
//! It serves one small HTTP API — probe, create, ack, up, fin, delete, the SSE
//! event stream and the WebSocket upgrade — authenticates every request with a
//! peer token, checks the target ACL, dials the target once per session, and
//! then relays bytes without looking at them.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::error::Error;
use crate::net::http1::Client;
use crate::resource::budget::{Budget, BudgetLease};
use crate::resource::retention::Retention;
use crate::session::{Session, Tombstone};
use crate::wire;

type SessionMap = Arc<Mutex<HashMap<String, Arc<Session>>>>;
type TombstoneMap = Arc<Mutex<HashMap<String, (Tombstone, Instant)>>>;
type CreateMap = Arc<Mutex<HashMap<String, CreateRecord>>>;

pub struct Registry {
    sessions: SessionMap,
    tombstones: TombstoneMap,
    creates: CreateMap,
    sweeper_running: Arc<AtomicBool>,
    metrics: Arc<crate::metrics::Metrics>,
    tombstone_ttl: Duration,
    payload_budget: Arc<Budget>,
    backpressure_timeout: Duration,
    suspended_retention: Arc<Retention>,
    accepting: AtomicBool,
}

struct CreateRecord {
    peer: String,
    params: String,
    state: CreateState,
    status: u16,
    body: String,
    session_id: Option<String>,
    at: Instant,
    create_lease: Option<BudgetLease>,
    session_lease: Option<BudgetLease>,
    session_metadata_lease: Option<BudgetLease>,
    _record_metadata_lease: Option<BudgetLease>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CreateState {
    Pending,
    Done,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordLimits {
    /// Every retained record of the peer: its share of the record budget.
    pub total: usize,
    /// In-flight and failed records of the peer.
    pub pending: usize,
}

impl RecordLimits {
    pub fn peer_pending(max_sessions: u32) -> usize {
        64usize.max((max_sessions as usize).saturating_mul(4))
    }

    /// Bounds when no resource manager sizes the record budget.
    pub fn without_budget(max_sessions: u32) -> Self {
        RecordLimits {
            total: 4096,
            pending: Self::peer_pending(max_sessions),
        }
    }

    pub fn from_budget(
        metadata_limit: i64,
        session_slots: i64,
        session_metadata_cost: i64,
        enabled_peers: usize,
        max_sessions: u32,
    ) -> Self {
        const RECORD_COST: i64 = 2 << 10;
        let egress = metadata_limit.max(0);
        let need = session_slots
            .max(0)
            .saturating_mul(session_metadata_cost.max(0));
        let budget = if need > egress { 0 } else { egress - need };
        let budget = budget.max(egress / 8).min(egress);
        let capacity = budget / RECORD_COST;
        let share = crate::auth::peer_share(capacity, enabled_peers).max(1);
        RecordLimits {
            total: usize::try_from(share).unwrap_or(usize::MAX),
            pending: Self::peer_pending(max_sessions),
        }
    }
}

pub enum CreateLookup {
    Reserved,
    Pending,
    Replay {
        status: u16,
        body: String,
        session_id: Option<String>,
    },
    Conflict,
    Quota(&'static str),
    Draining,
}

pub enum SessionLookup {
    Live(Arc<Session>),
    Tombstone(Box<Tombstone>),
}

impl Registry {
    #[cfg(test)]
    pub fn new(metrics: Arc<crate::metrics::Metrics>) -> Self {
        Self::new_with_ttl(metrics, Duration::from_secs(10 * 60))
    }

    #[cfg(test)]
    pub fn new_with_ttl(metrics: Arc<crate::metrics::Metrics>, tombstone_ttl: Duration) -> Self {
        Self::new_with_ttl_and_suspended_limit(metrics, tombstone_ttl, 64 * 1024 * 1024)
    }

    #[cfg(test)]
    pub fn new_with_ttl_and_suspended_limit(
        metrics: Arc<crate::metrics::Metrics>,
        tombstone_ttl: Duration,
        suspended_buffer_limit: u64,
    ) -> Self {
        Self::new_with_limits(
            metrics,
            tombstone_ttl,
            suspended_buffer_limit,
            256 * 1024 * 1024,
        )
    }

    #[cfg(test)]
    pub fn new_with_limits(
        metrics: Arc<crate::metrics::Metrics>,
        tombstone_ttl: Duration,
        suspended_buffer_limit: u64,
        global_buffer_limit: u64,
    ) -> Self {
        Self::new_with_resource_limits(
            metrics,
            tombstone_ttl,
            suspended_buffer_limit,
            global_buffer_limit,
            Duration::from_secs(120),
        )
    }

    pub fn new_with_resource_limits(
        metrics: Arc<crate::metrics::Metrics>,
        tombstone_ttl: Duration,
        suspended_buffer_limit: u64,
        global_buffer_limit: u64,
        backpressure_timeout: Duration,
    ) -> Self {
        let resources = metrics.resource_manager();
        let payload_budget = resources
            .as_ref()
            .map(|manager| {
                manager.mark_instrumented("payload");
                manager.payload.clone()
            })
            .unwrap_or_else(|| Budget::new(i64::try_from(global_buffer_limit).unwrap_or(i64::MAX)));
        let suspended_retention = resources
            .as_ref()
            .map(|manager| manager.suspended.clone())
            .unwrap_or_else(|| {
                Arc::new(Retention::new(
                    i64::try_from(suspended_buffer_limit).unwrap_or(i64::MAX),
                ))
            });
        Registry {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            tombstones: Arc::new(Mutex::new(HashMap::new())),
            creates: Arc::new(Mutex::new(HashMap::new())),
            sweeper_running: Arc::new(AtomicBool::new(false)),
            metrics,
            tombstone_ttl,
            payload_budget,
            backpressure_timeout,
            suspended_retention,
            accepting: AtomicBool::new(true),
        }
    }

    #[cfg(test)]
    pub fn insert(&self, s: Arc<Session>) {
        let mut leases = Vec::new();
        if let Some(resources) = self.metrics.resource_manager() {
            resources.mark_instrumented("sessions");
            resources.mark_instrumented("metadata");
            leases.push(
                resources
                    .sessions
                    .try_acquire(1)
                    .expect("direct session insert must fit the session budget"),
            );
            leases.push(
                resources
                    .metadata
                    .try_acquire(resources.session_metadata_cost())
                    .expect("direct session insert must fit the metadata budget"),
            );
        }
        self.insert_inner(s, leases);
    }

    pub fn insert_created(&self, s: Arc<Session>, key: &str) -> Result<(), &'static str> {
        let (session_lease, session_metadata_lease) = {
            let mut creates = self.creates.lock().unwrap();
            let record = creates.get_mut(key).ok_or("missing create reservation")?;
            (
                record.session_lease.take(),
                record.session_metadata_lease.take(),
            )
        };
        let mut leases = Vec::new();
        if let Some(resources) = self.metrics.resource_manager() {
            resources.mark_instrumented("sessions");
            resources.mark_instrumented("metadata");
            leases.push(session_lease.ok_or("missing session budget lease")?);
            leases.push(session_metadata_lease.ok_or("missing session metadata lease")?);
        } else {
            leases.extend(session_lease);
            leases.extend(session_metadata_lease);
        }
        self.insert_inner(s, leases);
        Ok(())
    }

    fn insert_inner(&self, s: Arc<Session>, leases: Vec<BudgetLease>) {
        s.set_suspended_retention(self.suspended_retention.clone());
        s.set_global_payload_budget(self.payload_budget.clone(), self.backpressure_timeout)
            .expect("new sessions must join the payload budget before buffering");
        for lease in leases {
            s.hold_resource_lease(lease);
        }
        self.metrics.session_opened();
        self.sessions.lock().unwrap().insert(s.id.clone(), s);
    }
    pub fn get(&self, id: &str) -> Option<Arc<Session>> {
        self.sessions.lock().unwrap().get(id).cloned()
    }
    pub fn all_sessions(&self) -> Vec<Arc<Session>> {
        self.sessions.lock().unwrap().values().cloned().collect()
    }
    pub fn metrics_snapshot(&self) -> crate::metrics::EgressMetricsSnapshot {
        let accepting = self.accepting();
        let sessions = self.all_sessions();
        let mut snapshot = crate::metrics::EgressMetricsSnapshot::default();
        for session in sessions {
            let session = session.metrics_snapshot(!accepting);
            if session.state == "CLOSED" {
                continue;
            }
            snapshot.live_sessions += 1;
            if matches!(session.state, "SUSPENDED" | "RESUMING") {
                snapshot.suspended_sessions += 1;
            } else {
                snapshot.active_sessions += 1;
            }
            *snapshot.states.entry(session.state.into()).or_insert(0) += 1;
            *snapshot
                .carrier_sessions
                .entry(session.carrier.into())
                .or_insert(0) += 1;
            snapshot.up_pending_frames += session.up_pending_frames;
            snapshot.down_retained_frames += session.down_retained_frames;
            snapshot.digest_receipts += session.digest_receipts;
            snapshot.down_unconfirmed_bytes += session.down_unconfirmed_bytes;
        }
        let creating = {
            let creates = self.creates.lock().unwrap();
            creates
                .values()
                .filter(|record| record.state == CreateState::Pending)
                .count() as u64
        };
        let payload_used = self.payload_budget.used().max(0) as u64;
        let payload_limit = self.payload_budget.limit().max(0) as u64;
        let (payload_wait_count, payload_wait_duration) = self.payload_budget.wait_stats();
        let recovery_used = self.suspended_retention.used().max(0) as u64;
        snapshot.buffer_memory_bytes = payload_used;
        snapshot.payload_limit = payload_limit;
        snapshot.suspended_mem_bytes = recovery_used;
        snapshot.recovery_retained_bytes = recovery_used;
        snapshot.recovery_retained_limit = self.suspended_retention.limit().max(0) as u64;
        snapshot.resource_waits.insert(
            "payload".into(),
            (payload_wait_count, payload_wait_duration.as_secs_f64()),
        );
        if creating > 0 {
            snapshot.states.insert("CREATING".into(), creating);
        }
        let mut resource_in_use = BTreeMap::new();
        resource_in_use.insert("payload".into(), payload_used);
        resource_in_use.insert("sessions".into(), snapshot.live_sessions);
        resource_in_use.insert("creates".into(), creating);
        if let Some(resources) = self.metrics.resource_manager() {
            resource_in_use.clear();
            snapshot.resource_limits.clear();
            snapshot.resource_waits.clear();
            for (resource, (used, limit, waits, seconds)) in resources.resource_snapshot() {
                resource_in_use.insert(resource.clone(), used);
                snapshot.resource_limits.insert(resource.clone(), limit);
                snapshot.resource_waits.insert(resource, (waits, seconds));
            }
        } else {
            snapshot
                .resource_limits
                .insert("payload".into(), payload_limit);
        }
        snapshot.resource_in_use = resource_in_use;
        snapshot
    }
    pub fn get_any(&self, id: &str) -> Option<SessionLookup> {
        if let Some(s) = self.get(id) {
            return Some(SessionLookup::Live(s));
        }
        let mut tombstones = self.tombstones.lock().unwrap();
        let now = Instant::now();
        tombstones.retain(|_, (_, at)| now.duration_since(*at) < self.tombstone_ttl);
        tombstones
            .get(id)
            .map(|(t, _)| SessionLookup::Tombstone(Box::new(t.clone())))
    }
    pub fn accepting(&self) -> bool {
        self.accepting.load(Ordering::Acquire)
    }
    pub fn set_draining(&self) {
        self.accepting.store(false, Ordering::Release);
    }
    pub fn session_count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }
    /// Test helper: records `tombstone` as if its session had just been
    /// removed.
    #[cfg(test)]
    pub fn insert_tombstone(&self, tombstone: crate::session::Tombstone) {
        self.tombstones
            .lock()
            .unwrap()
            .insert(tombstone.id.clone(), (tombstone, Instant::now()));
    }

    pub fn remove(&self, id: &str) {
        unattached::cancel(id);
        let removed = {
            let mut creates = self.creates.lock().unwrap();
            let removed = self.sessions.lock().unwrap().remove(id);
            if removed.is_some() {
                let now = Instant::now();
                for record in creates.values_mut() {
                    if record.session_id.as_deref() == Some(id) {
                        record.at = now;
                    }
                }
            }
            removed
        };
        if let Some(s) = removed {
            if !s.is_closed() {
                s.close(Error::new(wire::ERR_SESSION_CLOSED, "session removed").closed(true));
            }
            self.metrics.session_closed();
            let tombstone = s.compact_tombstone();
            let now = Instant::now();
            let mut tombstones = self.tombstones.lock().unwrap();
            tombstones.retain(|_, (_, at)| now.duration_since(*at) < self.tombstone_ttl);
            tombstones.insert(id.to_string(), (tombstone, now));
            drop(tombstones);
            self.schedule_expiry();
        }
    }
    fn count_owned_by_locked(&self, peer: &str) -> usize {
        self.sessions
            .lock()
            .unwrap()
            .values()
            .filter(|s| s.owner_peer == peer && !s.is_closed())
            .count()
    }

    /// Atomically checks live and in-flight session quotas and claims an idempotency key.
    #[cfg(test)]
    pub fn reserve_create(
        &self,
        key: &str,
        peer: &str,
        params: String,
        peer_limit: u32,
        total_limit: u32,
    ) -> CreateLookup {
        self.reserve_create_with_records(
            key,
            peer,
            params,
            peer_limit,
            total_limit,
            RecordLimits::without_budget(peer_limit),
        )
    }

    fn expire_create_records_locked(&self, creates: &mut HashMap<String, CreateRecord>) {
        let now = Instant::now();
        let live: std::collections::HashSet<String> = self
            .sessions
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, s)| !s.is_closed())
            .map(|(id, _)| id.clone())
            .collect();
        creates.retain(|_, r| {
            r.state == CreateState::Pending
                || now.duration_since(r.at) < self.tombstone_ttl
                || r.session_id.as_ref().is_some_and(|id| live.contains(id))
        });
    }

    pub fn lookup_create(&self, key: &str, params: &str) -> Option<CreateLookup> {
        let mut creates = self.creates.lock().unwrap();
        self.expire_create_records_locked(&mut creates);
        let r = creates.get(key)?;
        if r.params != params {
            return Some(CreateLookup::Conflict);
        }
        Some(match r.state {
            CreateState::Pending => CreateLookup::Pending,
            CreateState::Done | CreateState::Failed => CreateLookup::Replay {
                status: r.status,
                body: r.body.clone(),
                session_id: r.session_id.clone(),
            },
        })
    }

    pub fn reserve_create_with_records(
        &self,
        key: &str,
        peer: &str,
        params: String,
        peer_limit: u32,
        total_limit: u32,
        records: RecordLimits,
    ) -> CreateLookup {
        let mut creates = self.creates.lock().unwrap();
        self.expire_create_records_locked(&mut creates);
        let now = Instant::now();
        if let Some(r) = creates.get(key) {
            if r.params != params {
                return CreateLookup::Conflict;
            }
            return match r.state {
                CreateState::Pending => CreateLookup::Pending,
                CreateState::Done | CreateState::Failed => CreateLookup::Replay {
                    status: r.status,
                    body: r.body.clone(),
                    session_id: r.session_id.clone(),
                },
            };
        }
        let live_total = self
            .sessions
            .lock()
            .unwrap()
            .values()
            .filter(|s| !s.is_closed())
            .count();
        let live_peer = self.count_owned_by_locked(peer);
        let pending_peer = creates
            .values()
            .filter(|r| r.peer == peer && r.state == CreateState::Pending)
            .count();
        let pending_total = creates
            .values()
            .filter(|r| r.state == CreateState::Pending)
            .count();
        if peer_limit > 0 && live_peer + pending_peer >= peer_limit as usize {
            return CreateLookup::Quota("peer session quota");
        }
        if total_limit > 0 && live_total + pending_total >= total_limit as usize {
            return CreateLookup::Quota("session quota");
        }
        if !self.accepting() {
            return CreateLookup::Draining;
        }
        let (peer_records, peer_unsettled) = creates.values().filter(|r| r.peer == peer).fold(
            (0usize, 0usize),
            |(all, unsettled), r| {
                let open = matches!(r.state, CreateState::Pending | CreateState::Failed);
                (all + 1, unsettled + usize::from(open))
            },
        );
        if peer_records >= records.total.max(1) || peer_unsettled >= records.pending.max(1) {
            return CreateLookup::Quota("peer idempotency quota");
        }
        let (create_lease, session_lease, session_metadata_lease, record_metadata_lease) =
            if let Some(resources) = self.metrics.resource_manager() {
                resources.mark_instrumented("creates");
                resources.mark_instrumented("sessions");
                resources.mark_instrumented("metadata");
                let Some(create_lease) = resources.creates.try_acquire(1) else {
                    return CreateLookup::Quota("creation concurrency");
                };
                let Some(session_lease) = resources.try_egress_session() else {
                    return CreateLookup::Quota("session quota");
                };
                let Some(session_metadata_lease) =
                    resources.try_egress_metadata(resources.session_metadata_cost())
                else {
                    return CreateLookup::Quota("session metadata budget");
                };
                let record_cost = (1536 + key.len() + params.len()).max(2 << 10);
                let record_cost = i64::try_from(record_cost).unwrap_or(i64::MAX);
                let Some(record_metadata_lease) = resources.metadata.try_acquire(record_cost)
                else {
                    return CreateLookup::Quota("peer idempotency quota");
                };
                (
                    Some(create_lease),
                    Some(session_lease),
                    Some(session_metadata_lease),
                    Some(record_metadata_lease),
                )
            } else {
                (None, None, None, None)
            };
        creates.insert(
            key.to_string(),
            CreateRecord {
                peer: peer.to_string(),
                params,
                state: CreateState::Pending,
                status: 202,
                body: String::new(),
                session_id: None,
                at: now,
                create_lease,
                session_lease,
                session_metadata_lease,
                _record_metadata_lease: record_metadata_lease,
            },
        );
        CreateLookup::Reserved
    }

    pub fn complete_create(&self, key: &str, session_id: String, body: String) {
        if let Some(r) = self.creates.lock().unwrap().get_mut(key) {
            r.state = CreateState::Done;
            r.status = 201;
            r.body = body;
            r.session_id = Some(session_id);
            r.at = Instant::now();
            drop(r.create_lease.take());
            drop(r.session_lease.take());
            drop(r.session_metadata_lease.take());
        }
        self.schedule_expiry();
    }
    pub fn fail_create(&self, key: &str, status: u16, body: String) {
        if let Some(r) = self.creates.lock().unwrap().get_mut(key) {
            r.state = CreateState::Failed;
            r.status = status;
            r.body = body;
            r.at = Instant::now();
            drop(r.create_lease.take());
            drop(r.session_lease.take());
            drop(r.session_metadata_lease.take());
        }
        self.schedule_expiry();
    }
    pub fn close_all(&self) {
        self.accepting.store(false, Ordering::Release);
        let mut sessions = self.sessions.lock().unwrap();
        let all = sessions.values().cloned().collect::<Vec<_>>();
        let now = Instant::now();
        let mut tombstones = self.tombstones.lock().unwrap();
        tombstones.retain(|_, (_, at)| now.duration_since(*at) < self.tombstone_ttl);
        for s in &all {
            unattached::cancel(&s.id);
            s.close(Error::new(wire::ERR_DRAINING, "node shutting down"));
            tombstones.insert(s.id.clone(), (s.compact_tombstone(), now));
            self.metrics.session_closed();
        }
        sessions.clear();
        drop(tombstones);
        drop(sessions);
        self.creates
            .lock()
            .unwrap()
            .retain(|_, r| r.state == CreateState::Pending);
        self.schedule_expiry();
    }

    fn schedule_expiry(&self) {
        if self.sweeper_running.swap(true, Ordering::AcqRel) {
            return;
        }
        let sessions = Arc::downgrade(&self.sessions);
        let tombstones = Arc::downgrade(&self.tombstones);
        let creates = Arc::downgrade(&self.creates);
        let running = self.sweeper_running.clone();
        let ttl = self.tombstone_ttl;
        let spawned = std::thread::Builder::new()
            .name("egress-expiry".into())
            .spawn(move || loop {
                let (Some(sessions), Some(tombstones), Some(creates)) =
                    (sessions.upgrade(), tombstones.upgrade(), creates.upgrade())
                else {
                    running.store(false, Ordering::Release);
                    return;
                };
                let mut next = sweep_expired(&sessions, &tombstones, &creates, ttl);
                if next.is_none() {
                    running.store(false, Ordering::Release);
                    // A record settled between the sweep and the store above
                    // saw `running == true` and did not spawn: sweep once
                    // more and keep going only if no other sweeper took over.
                    next = sweep_expired(&sessions, &tombstones, &creates, ttl);
                    if next.is_none() || running.swap(true, Ordering::AcqRel) {
                        return;
                    }
                }
                drop((sessions, tombstones, creates));
                if let Some(at) = next {
                    std::thread::sleep(at.saturating_duration_since(Instant::now()));
                }
            });
        if spawned.is_err() {
            self.sweeper_running.store(false, Ordering::Release);
        }
    }

    /// Settled create records currently retained (test hook).
    #[cfg(test)]
    pub(crate) fn create_record_count(&self) -> usize {
        self.creates.lock().unwrap().len()
    }

    /// Tombstones currently retained (test hook).
    #[cfg(test)]
    pub(crate) fn tombstone_count(&self) -> usize {
        self.tombstones.lock().unwrap().len()
    }
}

fn sweep_expired(
    sessions: &Mutex<HashMap<String, Arc<Session>>>,
    tombstones: &Mutex<HashMap<String, (Tombstone, Instant)>>,
    creates: &Mutex<HashMap<String, CreateRecord>>,
    ttl: Duration,
) -> Option<Instant> {
    let now = Instant::now();
    let mut next: Option<Instant> = None;
    let mut note = |at: Instant| {
        let deadline = at + ttl;
        next = Some(next.map_or(deadline, |n| n.min(deadline)));
    };
    {
        let mut tombstones = tombstones.lock().unwrap();
        tombstones.retain(|_, (_, at)| now.duration_since(*at) < ttl);
        for (_, at) in tombstones.values() {
            note(*at);
        }
    }
    let mut creates = creates.lock().unwrap();
    let live: std::collections::HashSet<String> =
        sessions.lock().unwrap().keys().cloned().collect();
    creates.retain(|_, r| {
        r.state == CreateState::Pending
            || now.duration_since(r.at) < ttl
            || r.session_id.as_ref().is_some_and(|id| live.contains(id))
    });
    for r in creates.values() {
        let held = r.state == CreateState::Pending
            || r.session_id.as_ref().is_some_and(|id| live.contains(id));
        if !held {
            note(r.at);
        }
    }
    next
}

pub struct SessionLease {
    registry: Arc<Registry>,
    id: String,
    epoch: u64,
}
impl SessionLease {
    pub fn new(registry: Arc<Registry>, id: impl Into<String>) -> Self {
        let id = id.into();
        let epoch = registry.get(&id).map(|s| s.epoch()).unwrap_or(0);
        SessionLease {
            registry,
            id,
            epoch,
        }
    }
}
impl Drop for SessionLease {
    fn drop(&mut self) {
        // A carrier disappearing is recoverable only while the session is still
        // live and recovery has a positive grace.  Terminal paths (FIN,
        // explicit DELETE, backend errors) close first, so suspend_current
        // returns false and the normal registry/tombstone cleanup applies.
        if let Some(session) = self.registry.get(&self.id) {
            if self.epoch != 0 {
                // A stale carrier can finish after a replacement has already
                // resumed the same session. Its lease must not remove the new
                // epoch from the registry.
                if session.epoch() != self.epoch {
                    return;
                }
                if session.suspend(self.epoch) {
                    unattached::schedule_recovery(&self.registry, &session);
                    return;
                }
            }
        }
        self.registry.remove(&self.id);
    }
}

#[derive(Default)]
struct ConnectionCounts {
    total: usize,
    unauthenticated: usize,
    unauthenticated_by_ip: HashMap<IpAddr, usize>,
}
pub struct ConnectionBudget {
    max_total: usize,
    max_unauthenticated: usize,
    max_unauthenticated_per_ip: usize,
    counts: Mutex<ConnectionCounts>,
    inbound_budget: Option<Arc<Budget>>,
    metadata_budget: Option<Arc<Budget>>,
}
impl ConnectionBudget {
    pub fn new(max_sessions: u32) -> Self {
        Self::new_with_budgets(max_sessions, None, None)
    }

    pub fn new_with_budgets(
        max_sessions: u32,
        inbound_budget: Option<Arc<Budget>>,
        metadata_budget: Option<Arc<Budget>>,
    ) -> Self {
        let max_total = 4 * max_sessions.min(8192) as usize + 64;
        let max_unauthenticated = max_total / 2;
        ConnectionBudget {
            max_total,
            max_unauthenticated,
            max_unauthenticated_per_ip: 8.max(max_unauthenticated / 4),
            counts: Mutex::new(ConnectionCounts::default()),
            inbound_budget,
            metadata_budget,
        }
    }
    pub fn acquire(self: &Arc<Self>, ip: IpAddr) -> Option<ConnectionPermit> {
        let mut c = self.counts.lock().unwrap();
        let n = c.unauthenticated_by_ip.get(&ip).copied().unwrap_or(0);
        if c.total >= self.max_total
            || c.unauthenticated >= self.max_unauthenticated
            || n >= self.max_unauthenticated_per_ip
        {
            return None;
        }
        let inbound_lease = match &self.inbound_budget {
            Some(budget) => Some(budget.try_acquire(1)?),
            None => None,
        };
        let metadata_lease = match &self.metadata_budget {
            Some(budget) => Some(budget.try_acquire(16 << 10)?),
            None => None,
        };
        c.total += 1;
        c.unauthenticated += 1;
        *c.unauthenticated_by_ip.entry(ip).or_default() += 1;
        Some(ConnectionPermit {
            budget: self.clone(),
            ip,
            authenticated: false,
            accepted_at: Instant::now(),
            _inbound_lease: inbound_lease,
            _metadata_lease: metadata_lease,
        })
    }
    fn mark_authenticated(&self, ip: IpAddr) {
        let mut c = self.counts.lock().unwrap();
        c.unauthenticated = c.unauthenticated.saturating_sub(1);
        if let Some(n) = c.unauthenticated_by_ip.get_mut(&ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                c.unauthenticated_by_ip.remove(&ip);
            }
        }
    }
    fn release(&self, ip: IpAddr, authenticated: bool) {
        let mut c = self.counts.lock().unwrap();
        c.total = c.total.saturating_sub(1);
        if !authenticated {
            c.unauthenticated = c.unauthenticated.saturating_sub(1);
            if let Some(n) = c.unauthenticated_by_ip.get_mut(&ip) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    c.unauthenticated_by_ip.remove(&ip);
                }
            }
        }
    }
}
pub struct ConnectionPermit {
    budget: Arc<ConnectionBudget>,
    ip: IpAddr,
    authenticated: bool,
    accepted_at: Instant,
    _inbound_lease: Option<BudgetLease>,
    _metadata_lease: Option<BudgetLease>,
}
impl ConnectionPermit {
    pub fn mark_authenticated(&mut self) {
        if !self.authenticated {
            self.budget.mark_authenticated(self.ip);
            self.authenticated = true;
        }
    }
    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }
    pub fn auth_deadline(&self) -> Instant {
        self.accepted_at + Duration::from_secs(5)
    }
}
impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.budget.release(self.ip, self.authenticated);
    }
}

pub struct Server {
    pub cfg: Arc<Config>,
    pub auth: Arc<crate::auth::Authenticator>,
    pub registry: Arc<Registry>,
    pub client: Arc<Client>,
    pub started: Instant,
    pub hub: Option<Arc<crate::tunnel::Hub>>,
    pub tunnels: Option<Arc<crate::tunnel::client::TunnelListener>>,
    pub metrics: Arc<crate::metrics::Metrics>,
    pub connection_budget: Arc<ConnectionBudget>,
    pub(crate) authz_lock: Arc<Mutex<()>>,
    pub(crate) probe_budget: Arc<ProbeBudget>,
    pub(crate) accept_addr: Arc<Mutex<Option<SocketAddr>>>,
}

pub struct ProbeBudget {
    resource_budget: Arc<Budget>,
    per_peer: Mutex<HashMap<String, usize>>,
    precheck_active: Mutex<HashMap<String, usize>>,
    precheck_times: Mutex<HashMap<String, (f64, Instant)>>,
}
impl ProbeBudget {
    pub fn new() -> Self {
        Self::new_with_budget(Budget::new(16))
    }

    pub fn new_with_budget(resource_budget: Arc<Budget>) -> Self {
        Self {
            resource_budget,
            per_peer: Mutex::new(HashMap::new()),
            precheck_active: Mutex::new(HashMap::new()),
            precheck_times: Mutex::new(HashMap::new()),
        }
    }
    pub fn try_acquire_precheck_with_reason(
        &self,
        peer: &str,
        peers: usize,
    ) -> std::result::Result<ProbePermit<'_>, &'static str> {
        self.try_acquire_precheck_at(peer, peers, Instant::now())
    }

    pub(crate) fn try_acquire_precheck_at(
        &self,
        peer: &str,
        peers: usize,
        now: Instant,
    ) -> std::result::Result<ProbePermit<'_>, &'static str> {
        const PRECHECK_CONCURRENCY: usize = 2;
        const PRECHECK_BURST: f64 = 4.0;
        const PRECHECKS_PER_SECOND: f64 = 4.0;
        let mut permit = self.try_acquire_probe_with_reason(peer, peers)?;
        let mut active = self.precheck_active.lock().unwrap();
        let active_count = active.get(peer).copied().unwrap_or(0);
        let mut buckets = self.precheck_times.lock().unwrap();
        let (tokens, updated) = buckets
            .entry(peer.to_string())
            .or_insert((PRECHECK_BURST, now));
        if now > *updated {
            let elapsed = now.duration_since(*updated).as_secs_f64();
            *tokens = PRECHECK_BURST.min(*tokens + elapsed * PRECHECKS_PER_SECOND);
            *updated = now;
        }
        if active_count >= PRECHECK_CONCURRENCY || *tokens < 1.0 {
            return Err("peer precheck budget");
        }
        *tokens -= 1.0;
        *active.entry(peer.to_string()).or_default() += 1;
        permit.precheck_peer = Some(peer.to_string());
        Ok(permit)
    }
    pub fn try_acquire_probe_with_reason(
        &self,
        peer: &str,
        peers: usize,
    ) -> std::result::Result<ProbePermit<'_>, &'static str> {
        self.acquire_with_reasons(peer, peers, "peer probe budget", "probe budget")
    }
    fn acquire_with_reasons(
        &self,
        peer: &str,
        peers: usize,
        peer_reason: &'static str,
        global_reason: &'static str,
    ) -> std::result::Result<ProbePermit<'_>, &'static str> {
        let fair = usize::try_from(
            crate::auth::peer_share(self.resource_budget.limit(), peers.max(1)).max(1),
        )
        .unwrap_or(1);
        let mut p = self.per_peer.lock().unwrap();
        let n = p.get(peer).copied().unwrap_or(0);
        if n >= fair {
            return Err(peer_reason);
        }
        let lease = self.resource_budget.try_acquire(1).ok_or(global_reason)?;
        *p.entry(peer.to_string()).or_default() += 1;
        Ok(ProbePermit {
            budget: self,
            peer: peer.to_string(),
            precheck_peer: None,
            _lease: lease,
        })
    }
}
pub struct ProbePermit<'a> {
    budget: &'a ProbeBudget,
    peer: String,
    precheck_peer: Option<String>,
    _lease: BudgetLease,
}
impl Drop for ProbePermit<'_> {
    fn drop(&mut self) {
        let mut p = self.budget.per_peer.lock().unwrap();
        if let Some(n) = p.get_mut(&self.peer) {
            *n -= 1;
            if *n == 0 {
                p.remove(&self.peer);
            }
        }
        drop(p);
        if let Some(peer) = &self.precheck_peer {
            let mut active = self.budget.precheck_active.lock().unwrap();
            if let Some(n) = active.get_mut(peer) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    active.remove(peer);
                }
            }
        }
    }
}
mod accept;
mod api;
mod carrier;
#[cfg(feature = "h2")]
mod h2;
mod pump;
mod unattached;
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = u8::from(a.len() != b.len());
    for i in 0..a.len().max(b.len()) {
        diff |= a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0);
    }
    diff == 0
}
pub fn log_info(msg: &str) {
    crate::slog::info(msg, &[]);
}
pub fn log_debug(msg: &str) {
    crate::slog::debug(msg, &[]);
}

#[cfg(test)]
mod tests {
    use super::{
        constant_time_eq, ConnectionBudget, CreateLookup, ProbeBudget, Registry, Server,
        SessionLookup,
    };
    use crate::error::Error;
    use crate::net::http1::{Client, Request};
    use crate::session::recovery::{ResumeFin, ResumeRequest};
    use crate::session::Session;
    use crate::wire::{self, CreateRequest, Limits as WireLimits, Mode};
    use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    struct Fixture {
        server: Arc<Server>,
        dir: std::path::PathBuf,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn fixture(target_addr: &str, max_sessions: u32) -> Fixture {
        let dir =
            std::env::temp_dir().join(format!("dbbcreate-{}", crate::util::random_hex(6).unwrap()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("peer-token"), "abc").unwrap();
        let path = dir.join("config.yaml");
        let text = format!(
            "node:\n  id: peer-b\nhttp:\n  enabled: true\n  listen: \"127.0.0.1:18080\"\ntargets:\n  db:\n    network: tcp\n    address: \"{target_addr}\"\nauth:\n  inbound_peers:\n    - id: peer-a\n      token_files: [peer-token]\n      allowed_targets: [db]\n      max_sessions: {max_sessions}\nlimits:\n  max_sessions: {max_sessions}\ntransport:\n  unattached_timeout: 5s\n"
        );
        std::fs::write(&path, text).unwrap();
        let cfg = Arc::new(crate::config::load(&path).unwrap());
        let metrics = Arc::new(crate::metrics::Metrics::new());
        let registry = Arc::new(Registry::new(metrics.clone()));
        let client = Arc::new(Client::new(
            cfg.transport.dial_timeout,
            cfg.transport.control_request_timeout,
        ));
        let server = Arc::new(Server {
            cfg: cfg.clone(),
            auth: Arc::new(crate::auth::Authenticator::new(cfg.clone())),
            registry,
            client,
            started: Instant::now(),
            hub: None,
            tunnels: None,
            metrics: metrics.clone(),
            connection_budget: Arc::new(ConnectionBudget::new(max_sessions)),
            authz_lock: Arc::new(std::sync::Mutex::new(())),
            probe_budget: Arc::new(ProbeBudget::new()),
            accept_addr: Arc::new(std::sync::Mutex::new(None)),
        });
        Fixture { server, dir }
    }

    #[test]
    fn registry_shares_payload_budget_across_session_windows() {
        let metrics = Arc::new(crate::metrics::Metrics::new());
        let registry = Registry::new_with_limits(metrics.clone(), Duration::from_secs(600), 4, 4);
        let limits = crate::transport::requested_limits(&crate::config::Transport::default());
        let mut clients = Vec::new();
        let mut make_session = |id: &str| {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (backend, _) = listener.accept().unwrap();
            clients.push(client);
            Session::new(
                id.to_string(),
                "token".to_string(),
                "inst".to_string(),
                "peer".to_string(),
                "db".to_string(),
                Mode::Ws,
                limits,
                64,
                backend,
                metrics.clone(),
            )
        };
        let first = make_session("payload-one");
        let second = make_session("payload-two");
        registry.insert(first.clone());
        registry.insert(second.clone());

        first.mark_down_produced(b"four").unwrap();
        assert_eq!(registry.payload_budget.used(), 4);
        let error = second.mark_down_produced(b"x").unwrap_err();
        assert_eq!(error.code, wire::ERR_BUFFER_EXHAUSTED);

        first.apply_down_ack(4, false).unwrap();
        assert_eq!(registry.payload_budget.used(), 0);
        assert_eq!(second.mark_down_produced(b"x").unwrap(), 0);
        assert_eq!(registry.payload_budget.used(), 1);
    }

    fn create_request(server: &Server, id: &str, max_frame_size: Option<usize>) -> Request {
        let mut limits = crate::transport::requested_limits(&server.cfg.transport);
        if let Some(size) = max_frame_size {
            limits.max_frame_size = size;
        }
        let body = CreateRequest {
            target_id: "db".to_string(),
            create_request_id: id.to_string(),
            ingress_instance_id: "ingress-test".to_string(),
            mode: Mode::Ws,
            recovery_enabled: false,
            recovery_grace_ms: 0,
            limits,
        }
        .to_json()
        .to_string()
        .into_bytes();
        Request {
            method: "POST".to_string(),
            path: wire::PATH_SESSIONS.to_string(),
            query: Vec::new(),
            version: "HTTP/1.1".to_string(),
            headers: vec![
                (wire::H_PEER_AUTH.to_string(), "Bearer abc".to_string()),
                (
                    wire::H_INSTANCE_ID.to_string(),
                    server.cfg.node.instance_id.clone(),
                ),
            ],
            body,
        }
    }

    fn response_session_id(body: &str) -> String {
        let value = crate::util::json::parse(body).unwrap();
        wire::CreateResponse::from_json(&value).unwrap().session_id
    }

    fn ws_check_request(server: &Server, nonce: Option<&str>) -> Request {
        let mut headers = vec![
            (wire::H_PEER_AUTH.to_string(), "Bearer abc".to_string()),
            (
                wire::H_INSTANCE_ID.to_string(),
                server.cfg.node.instance_id.clone(),
            ),
            ("Connection".to_string(), "Upgrade".to_string()),
            ("Upgrade".to_string(), "websocket".to_string()),
            ("Sec-WebSocket-Version".to_string(), "13".to_string()),
            (
                "Sec-WebSocket-Key".to_string(),
                "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
            ),
            (
                "Sec-WebSocket-Protocol".to_string(),
                wire::WS_SUBPROTOCOL.to_string(),
            ),
            (wire::H_WS_PURPOSE.to_string(), "check".to_string()),
        ];
        if let Some(nonce) = nonce {
            headers.push((wire::H_WS_NONCE.to_string(), nonce.to_string()));
        }
        Request {
            method: "GET".to_string(),
            path: wire::PATH_WS.to_string(),
            query: Vec::new(),
            version: "HTTP/1.1".to_string(),
            headers,
            body: Vec::new(),
        }
    }

    fn close_session(server: &Server, id: &str) {
        if let Some(session) = server.registry.get(id) {
            session.close(
                crate::error::Error::new(wire::ERR_SESSION_CLOSED, "test cleanup").closed(true),
            );
        }
        server.registry.remove(id);
    }
    #[test]
    fn accepted_socket_has_nodelay() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let c = std::net::TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (s, _) = l.accept().unwrap();
        crate::net::set_nodelay(&s).unwrap();
        assert!(s.nodelay().unwrap());
        drop(c);
    }
    #[test]
    fn token_plus_256_nul_does_not_match() {
        let t = b"T";
        let mut e = t.to_vec();
        e.extend(std::iter::repeat(0).take(256));
        assert!(!constant_time_eq(t, &e));
    }
    #[test]
    fn per_ip_unauthenticated_cap() {
        let b = Arc::new(ConnectionBudget::new(0));
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let mut p: Vec<_> = (0..8).map(|_| b.acquire(ip).unwrap()).collect();
        assert!(b.acquire(ip).is_none());
        p[0].mark_authenticated();
        assert!(b.acquire(ip).is_some());
        assert!(b.acquire(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))).is_some());
    }

    #[test]
    fn per_ip_unauthenticated_permit_releases_once_and_reuses_capacity() {
        let budget = Arc::new(ConnectionBudget::new(0));
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let per_ip_limit = budget.max_unauthenticated_per_ip;
        let mut permits: Vec<_> = (0..per_ip_limit)
            .map(|_| {
                budget
                    .acquire(ip)
                    .expect("within per-IP unauthenticated limit")
            })
            .collect();

        assert!(budget.acquire(ip).is_none());

        let mut authenticated = permits.pop().unwrap();
        authenticated.mark_authenticated();
        authenticated.mark_authenticated();
        let replacement = budget
            .acquire(ip)
            .expect("marking authenticated releases one unauthenticated slot");
        assert!(budget.acquire(ip).is_none());

        drop(replacement);
        assert!(budget.acquire(ip).is_some());
    }

    #[test]
    fn p1_06_probe_budget_table() {
        for (peers, expected_share) in [(1, 16usize), (2, 12), (3, 7), (4, 4), (32, 1)] {
            let budget = ProbeBudget::new();
            let mut permits = Vec::new();
            for _ in 0..expected_share {
                permits.push(
                    budget
                        .try_acquire_probe_with_reason("peer-a", peers)
                        .expect("fair share"),
                );
            }
            assert!(budget
                .try_acquire_probe_with_reason("peer-a", peers)
                .is_err());
            drop(permits);
            assert!(budget
                .try_acquire_probe_with_reason("peer-a", peers)
                .is_ok());
        }
    }

    #[test]
    fn p1_06_probe_budget_distinguishes_peer_and_global_limits() {
        let budget = ProbeBudget::new();
        let mut permits = Vec::new();
        for peer in 0..16 {
            permits.push(
                budget
                    .try_acquire_probe_with_reason(&format!("peer-{peer}"), 1)
                    .expect("global slot"),
            );
        }
        assert!(matches!(
            budget.try_acquire_probe_with_reason("peer-overflow", 1),
            Err("probe budget")
        ));
        drop(permits);

        let first = budget
            .try_acquire_probe_with_reason("peer-a", 16)
            .expect("peer fair slot");
        assert!(matches!(
            budget.try_acquire_probe_with_reason("peer-a", 16),
            Err("peer probe budget")
        ));
        drop(first);
    }

    #[test]
    fn p1_06_probe_budget_third_peer_keeps_floor() {
        let budget = ProbeBudget::new();
        let mut occupied = Vec::new();
        for peer in ["peer-a", "peer-b"] {
            for _ in 0..7 {
                occupied.push(
                    budget
                        .try_acquire_probe_with_reason(peer, 3)
                        .expect("each peer gets PeerShare(16, 3) = 7 fair slots"),
                );
            }
        }

        assert!(matches!(
            budget.try_acquire_probe_with_reason("peer-a", 3),
            Err("peer probe budget")
        ));
        assert!(matches!(
            budget.try_acquire_probe_with_reason("peer-b", 3),
            Err("peer probe budget")
        ));
        assert!(budget.try_acquire_probe_with_reason("peer-c", 3).is_ok());
    }

    #[test]
    fn p1_06_probe_rejects_non_string_expected_node_id() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        let fixture = fixture(&target.local_addr().unwrap().to_string(), 4);
        let request = Request {
            method: "POST".to_string(),
            path: wire::PATH_PROBE.to_string(),
            query: Vec::new(),
            version: "HTTP/1.1".to_string(),
            headers: vec![(wire::H_PEER_AUTH.to_string(), "Bearer abc".to_string())],
            body: br#"{"protocol_version":"1.5","expected_node_id":7,"nonce":"n"}"#.to_vec(),
        };
        let error = match fixture.server.handle_probe(&request) {
            Err(error) => error,
            Ok(_) => panic!("non-string expected_node_id must be rejected"),
        };
        assert_eq!(error.code, wire::ERR_BAD_FRAME);
        assert_eq!(error.message, "expected_node_id");
    }

    #[test]
    fn p1_07_precheck_limits_two_active_and_four_per_second() {
        let budget = ProbeBudget::new();
        let first = budget
            .try_acquire_precheck_with_reason("peer-a", 4)
            .expect("first active precheck");
        let second = budget
            .try_acquire_precheck_with_reason("peer-a", 4)
            .expect("second active precheck");
        assert!(matches!(
            budget.try_acquire_precheck_with_reason("peer-a", 4),
            Err("peer precheck budget")
        ));
        drop(first);
        drop(second);

        for _ in 0..2 {
            drop(
                budget
                    .try_acquire_precheck_with_reason("peer-a", 4)
                    .expect("within precheck rate"),
            );
        }
        assert!(matches!(
            budget.try_acquire_precheck_with_reason("peer-a", 4),
            Err("peer precheck budget")
        ));

        let budget = ProbeBudget::new();
        let regular: Vec<_> = (0..5)
            .map(|_| {
                budget
                    .try_acquire_probe_with_reason("peer-b", 1)
                    .expect("regular probe")
            })
            .collect();
        let first = budget
            .try_acquire_precheck_with_reason("peer-b", 1)
            .expect("precheck independent of regular probe count");
        let second = budget
            .try_acquire_precheck_with_reason("peer-b", 1)
            .expect("second concurrent precheck");
        assert!(matches!(
            budget.try_acquire_precheck_with_reason("peer-b", 1),
            Err("peer precheck budget")
        ));
        drop(first);
        drop(second);
        drop(regular);
    }

    #[test]
    fn p1_07_precheck_active_quota_isolated_by_peer_identity() {
        let budget = ProbeBudget::new();
        let first = budget
            .try_acquire_precheck_with_reason("peer-a", 3)
            .expect("first active precheck for peer-a");
        let second = budget
            .try_acquire_precheck_with_reason("peer-a", 3)
            .expect("second active precheck for peer-a");

        assert!(matches!(
            budget.try_acquire_precheck_with_reason("peer-a", 3),
            Err("peer precheck budget")
        ));
        assert!(budget.try_acquire_precheck_with_reason("peer-b", 3).is_ok());

        drop(first);
        drop(second);
    }

    #[test]
    fn p1_07_ws_check_preflight_budget_nonce_handshake_order() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        let fixture = fixture(&target.local_addr().unwrap().to_string(), 4);
        let server = &fixture.server;
        let mut request = ws_check_request(server, None);
        request
            .headers
            .retain(|(name, _)| !name.eq_ignore_ascii_case("sec-websocket-key"));

        let mut occupied = Vec::new();
        for index in 0..16 {
            occupied.push(
                server
                    .probe_budget
                    .try_acquire_probe_with_reason(&format!("load-{index}"), 1)
                    .expect("global probe slot"),
            );
        }
        let error = match server.ws_preflight(&request) {
            Err(error) => error,
            Ok(_) => panic!("full global probe budget must reject WS check"),
        };
        assert_eq!(error.code, wire::ERR_QUOTA_EXCEEDED);
        assert_eq!(error.message, "probe budget");
        drop(occupied);

        let error = match server.ws_preflight(&request) {
            Err(error) => error,
            Ok(_) => panic!("missing nonce must be rejected"),
        };
        assert_eq!(error.code, wire::ERR_BAD_FRAME);
        assert_eq!(error.message, "nonce");

        request
            .headers
            .push((wire::H_WS_NONCE.to_string(), "nonce".to_string()));
        let error = match server.ws_preflight(&request) {
            Err(error) => error,
            Ok(_) => panic!("missing WebSocket key must be rejected"),
        };
        assert_eq!(error.code, wire::ERR_WS_HANDSHAKE_FAILED);

        request.headers.push((
            "Sec-WebSocket-Key".to_string(),
            "dGhlIHNhbXBsZSBub25jZQ==".to_string(),
        ));
        let (session, _, is_check, permit) = server.ws_preflight(&request).unwrap();
        assert!(session.is_none());
        assert!(is_check);
        drop(permit);
    }

    #[test]
    fn resume_on_non_recovery_session_409() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        let fixture = fixture(&target.local_addr().unwrap().to_string(), 4);
        let create = create_request(&fixture.server, "resume-disabled", None);
        let (_, body) = fixture.server.handle_create(&create).unwrap();
        let session_id = response_session_id(&body);
        let session = fixture.server.registry.get(&session_id).unwrap();
        let mut req = create;
        req.path = format!("{}/{session_id}/resume", wire::PATH_SESSIONS);
        req.query.clear();
        req.body = br#"{"resume_request_id":"resume-1","expected_epoch":"1","ingress_instance_id":"ingress-instance","transport":{"mode":"ws"},"known_up_ack_offset":"0","up_next_offset":"0","down_delivered_offset":"0","up_fin":{"seen":false,"final_offset":null,"applied":false,"acked":false},"down_fin":{"seen":false,"final_offset":null,"applied":false,"acked":false}}"#.to_vec();
        req.headers
            .push((wire::H_SESSION_TOKEN.to_string(), session.token.clone()));

        let error = fixture.server.handle_session_post(&req).unwrap_err();
        assert_eq!(error.code, wire::ERR_RECOVERY_DISABLED);
        close_session(&fixture.server, &session_id);
    }

    #[test]
    fn metrics_scrape_uses_live_registry_session_snapshot() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        let fixture = fixture(&target.local_addr().unwrap().to_string(), 4);
        let registry = fixture.server.registry.clone();
        let metrics = fixture.server.metrics.clone();
        metrics.set_egress_registry(Arc::downgrade(&registry));
        metrics.configure_resources(&fixture.server.cfg);

        let create = create_request(&fixture.server, "metrics-live-session", None);
        let (_, body) = fixture.server.handle_create(&create).unwrap();
        let session_id = response_session_id(&body);
        let snapshot = registry.metrics_snapshot();
        assert_eq!(snapshot.live_sessions, 1);
        assert_eq!(snapshot.active_sessions, 1);
        assert_eq!(snapshot.suspended_sessions, 0);
        assert_eq!(snapshot.states.get("ATTACHING"), Some(&1));
        assert_eq!(snapshot.carrier_sessions.get("ws"), Some(&1));
        assert_eq!(snapshot.resource_in_use.get("sessions"), Some(&1));

        let rendered = metrics.render(&fixture.server.cfg, Instant::now(), true);
        for sample in [
            "dbb_active_sessions 1\n",
            "dbb_egress_state_ATTACHING 1\n",
            "dbb_egress_carrier_sessions{transport=\"ws\"} 1\n",
            "dbb_egress_down_unconfirmed_bytes 0\n",
            "dbb_resource_in_use{resource=\"sessions\"} 1\n",
        ] {
            assert!(rendered.contains(sample), "missing sample {sample}");
        }
        close_session(&fixture.server, &session_id);
    }

    #[test]
    fn delete_wrong_epoch_409() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        let fixture = fixture(&target.local_addr().unwrap().to_string(), 4);
        let create = create_request(&fixture.server, "delete-stale", None);
        let (_, body) = fixture.server.handle_create(&create).unwrap();
        let session_id = response_session_id(&body);
        let session = fixture.server.registry.get(&session_id).unwrap();
        let mut req = create;
        req.method = "DELETE".to_string();
        req.path = format!("{}/{session_id}", wire::PATH_SESSIONS);
        req.query = vec![("epoch".to_string(), "2".to_string())];
        req.body.clear();
        req.headers
            .push((wire::H_SESSION_TOKEN.to_string(), session.token.clone()));

        let error = fixture.server.handle_delete(&req).unwrap_err();
        assert_eq!(error.code, wire::ERR_STALE_EPOCH);
        assert!(!session.is_closed());
        close_session(&fixture.server, &session_id);
    }

    #[test]
    fn compact_tombstone_preserves_terminal_and_epoch_order() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        let fixture = fixture(&target.local_addr().unwrap().to_string(), 4);
        let create = create_request(&fixture.server, "compact-tombstone", None);
        let (_, body) = fixture.server.handle_create(&create).unwrap();
        let session_id = response_session_id(&body);
        let session = fixture.server.registry.get(&session_id).unwrap();
        let token = session.token.clone();
        session.close(Error::new(wire::ERR_BACKEND_LOST, "test backend lost").closed(true));
        fixture.server.registry.remove(&session_id);
        assert!(fixture.server.registry.get(&session_id).is_none());
        let tombstone = match fixture.server.registry.get_any(&session_id) {
            Some(SessionLookup::Tombstone(tombstone)) => tombstone,
            _ => panic!("closed session must be represented by a compact tombstone"),
        };
        assert_eq!(tombstone.owner_peer, "peer-a");
        assert_eq!(tombstone.terminal_code, wire::ERR_BACKEND_LOST);
        assert_eq!(tombstone.epoch, 1);

        let mut req = create;
        req.path = format!("{}/{session_id}/up", wire::PATH_SESSIONS);
        req.body = b"not json".to_vec();
        req.headers
            .push((wire::H_SESSION_TOKEN.to_string(), token.clone()));
        req.query = vec![("epoch".to_string(), "2".to_string())];
        let error = fixture.server.handle_session_post(&req).unwrap_err();
        assert_eq!(error.code, wire::ERR_STALE_EPOCH);

        req.query = vec![("epoch".to_string(), "1".to_string())];
        let error = fixture.server.handle_session_post(&req).unwrap_err();
        assert_eq!(error.code, wire::ERR_BACKEND_LOST);

        req.path = format!("{}/{session_id}/resume", wire::PATH_SESSIONS);
        req.query.clear();
        let error = fixture.server.handle_session_post(&req).unwrap_err();
        assert_eq!(error.code, wire::ERR_BACKEND_LOST);

        req.method = "DELETE".to_string();
        req.path = format!("{}/{session_id}", wire::PATH_SESSIONS);
        req.query = vec![("epoch".to_string(), "2".to_string())];
        let error = fixture.server.handle_delete(&req).unwrap_err();
        assert_eq!(error.code, wire::ERR_STALE_EPOCH);
        req.query = vec![("epoch".to_string(), "1".to_string())];
        let body = fixture.server.handle_delete(&req).unwrap();
        assert!(body.contains("\"closed\":true"), "{body}");
    }

    #[test]
    fn create_idempotent_replay_200() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        let fixture = fixture(&target.local_addr().unwrap().to_string(), 4);
        let req = create_request(&fixture.server, "replay", None);
        let (status, body) = fixture.server.handle_create(&req).unwrap();
        assert_eq!(status, 201);
        let session_id = response_session_id(&body);
        let (status, replay) = fixture.server.handle_create(&req).unwrap();
        assert_eq!(status, 200);
        assert_eq!(replay, body);
        close_session(&fixture.server, &session_id);
    }

    #[test]
    fn create_concurrent_same_key_single_dial() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = target.local_addr().unwrap();
        target.set_nonblocking(true).unwrap();
        let fixture = fixture(&addr.to_string(), 4);
        let req1 = create_request(&fixture.server, "concurrent", None);
        let req2 = req1.clone();
        let server1 = fixture.server.clone();
        let server2 = fixture.server.clone();
        let t1 = std::thread::spawn(move || server1.handle_create(&req1));
        let t2 = std::thread::spawn(move || server2.handle_create(&req2));
        let r1 = t1.join().unwrap();
        let r2 = t2.join().unwrap();
        let success = [&r1, &r2]
            .into_iter()
            .find_map(|result| result.as_ref().ok().map(|(_, body)| body.clone()))
            .expect("one request creates the session");
        assert!([&r1, &r2].into_iter().any(|result| {
            matches!(result, Err(e) if e.code == wire::ERR_CREATE_PENDING)
                || matches!(result, Ok((200, _)))
        }));
        let session_id = response_session_id(&success);
        let mut accepted = Vec::new();
        loop {
            match target.accept() {
                Ok((stream, _)) => accepted.push(stream),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => panic!("accept target connection: {e}"),
            }
        }
        assert_eq!(accepted.len(), 1, "same-key requests must dial once");
        close_session(&fixture.server, &session_id);
    }

    #[test]
    fn create_param_conflict_409() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        let fixture = fixture(&target.local_addr().unwrap().to_string(), 4);
        let req = create_request(&fixture.server, "conflict", None);
        let (_, body) = fixture.server.handle_create(&req).unwrap();
        let session_id = response_session_id(&body);
        let changed = create_request(&fixture.server, "conflict", Some(128 * 1024));
        let err = fixture.server.handle_create(&changed).unwrap_err();
        assert_eq!(err.code, wire::ERR_IDEMPOTENCY_CONFLICT);
        assert_eq!(err.status(), 409);
        close_session(&fixture.server, &session_id);
    }

    #[test]
    fn create_failed_dial_cached_502() {
        let closed = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = closed.local_addr().unwrap().to_string();
        drop(closed);
        let fixture = fixture(&addr, 4);
        let req = create_request(&fixture.server, "failed-dial", None);
        let err = fixture.server.handle_create(&req).unwrap_err();
        assert_eq!(err.code, wire::ERR_DIAL_FAILED);
        assert_eq!(err.status(), 502);
        let (status, body) = fixture.server.handle_create(&req).unwrap();
        assert_eq!(status, 502);
        assert!(body.contains(wire::ERR_DIAL_FAILED));
    }

    #[test]
    fn create_quota_429_not_cached() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        let fixture = fixture(&target.local_addr().unwrap().to_string(), 1);
        let first = create_request(&fixture.server, "quota-first", None);
        let (_, body) = fixture.server.handle_create(&first).unwrap();
        let first_id = response_session_id(&body);
        let second = create_request(&fixture.server, "quota-second", None);
        let err = fixture.server.handle_create(&second).unwrap_err();
        assert_eq!(err.code, wire::ERR_QUOTA_EXCEEDED);
        assert_eq!(err.status(), 429);
        close_session(&fixture.server, &first_id);
        let (status, body) = fixture.server.handle_create(&second).unwrap();
        assert_eq!(status, 201, "a quota rejection must not reserve the key");
        close_session(&fixture.server, &response_session_id(&body));
    }

    #[test]
    fn create_after_session_closed_410() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        let fixture = fixture(&target.local_addr().unwrap().to_string(), 4);
        let req = create_request(&fixture.server, "closed-replay", None);
        let (_, body) = fixture.server.handle_create(&req).unwrap();
        let session_id = response_session_id(&body);
        close_session(&fixture.server, &session_id);
        let err = fixture.server.handle_create(&req).unwrap_err();
        assert_eq!(err.code, wire::ERR_SESSION_CLOSED);
        assert_eq!(err.status(), 410);
        assert!(err.session_closed);
    }

    #[test]
    fn create_record_budget_rejects_only_new_keys_and_replays_old() {
        let metrics = Arc::new(crate::metrics::Metrics::new());
        let registry = Registry::new_with_ttl(metrics, Duration::from_secs(60));
        let records = super::RecordLimits {
            total: 2,
            pending: 64,
        };
        let reserve = |key: &str| {
            registry.reserve_create_with_records(key, "peer", "p".into(), 0, 0, records)
        };
        assert!(matches!(reserve("a"), CreateLookup::Reserved));
        registry.complete_create("a", "s-a".into(), "body-a".into());
        assert!(matches!(reserve("b"), CreateLookup::Reserved));
        registry.complete_create("b", "s-b".into(), "body-b".into());
        assert!(matches!(
            reserve("c"),
            CreateLookup::Quota("peer idempotency quota")
        ));
        assert!(matches!(reserve("a"), CreateLookup::Replay { .. }));
        // Records are per peer: another peer is not refused by this one.
        assert!(matches!(
            registry.reserve_create_with_records("x", "other", "p".into(), 0, 0, records),
            CreateLookup::Reserved
        ));
    }

    #[test]
    fn draining_registry_refuses_new_creates_and_replays_known_keys() {
        let metrics = Arc::new(crate::metrics::Metrics::new());
        let registry = Registry::new_with_ttl(metrics, Duration::from_secs(60));
        let records = super::RecordLimits::without_budget(0);
        let reserve = |key: &str| {
            registry.reserve_create_with_records(key, "peer", "p".into(), 0, 0, records)
        };
        assert!(matches!(reserve("a"), CreateLookup::Reserved));
        registry.complete_create("a", "s-a".into(), "body-a".into());
        assert!(registry.accepting());
        registry.set_draining();
        assert!(!registry.accepting());
        assert!(matches!(reserve("b"), CreateLookup::Draining));
        assert!(matches!(reserve("a"), CreateLookup::Replay { .. }));
        assert_eq!(registry.session_count(), 0);
    }

    #[test]
    fn create_records_are_not_capped_at_twice_max_sessions() {
        // B4: with max_sessions 200 the old fixed cap (2 x 200 records kept
        // for the tombstone TTL) refused every create after 400 sessions.
        let metrics = Arc::new(crate::metrics::Metrics::new());
        let registry = Registry::new_with_ttl(metrics, Duration::from_secs(60));
        let cost = 100 << 10;
        let records = super::RecordLimits::from_budget(32 << 20, 200, cost, 1, 200);
        assert_eq!(records.pending, 800);
        assert!(records.total >= 2048, "{records:?}");
        for i in 0..1100 {
            let key = format!("k{i}");
            assert!(
                matches!(
                    registry.reserve_create_with_records(
                        &key,
                        "peer",
                        "p".into(),
                        200,
                        200,
                        records
                    ),
                    CreateLookup::Reserved
                ),
                "create {i} refused"
            );
            registry.complete_create(&key, format!("s{i}"), "body".into());
        }
        let tight = super::RecordLimits {
            total: 4096,
            pending: 2,
        };
        let registry = Registry::new_with_ttl(
            Arc::new(crate::metrics::Metrics::new()),
            Duration::from_secs(60),
        );
        for key in ["p1", "p2"] {
            assert!(matches!(
                registry.reserve_create_with_records(key, "peer", "p".into(), 0, 0, tight),
                CreateLookup::Reserved
            ));
        }
        assert!(matches!(
            registry.reserve_create_with_records("p3", "peer", "p".into(), 0, 0, tight),
            CreateLookup::Quota("peer idempotency quota")
        ));
        assert_eq!(
            super::RecordLimits::from_budget(32 << 20, 200, cost, 2, 1).pending,
            64
        );
    }

    #[test]
    fn failed_create_record_expires_after_ttl() {
        let metrics = Arc::new(crate::metrics::Metrics::new());
        let registry = Registry::new_with_ttl(metrics, Duration::from_millis(1));
        assert!(matches!(
            registry.reserve_create("failed", "peer", "p".into(), 0, 1),
            CreateLookup::Reserved
        ));
        registry.fail_create("failed", 502, "failed".into());
        std::thread::sleep(Duration::from_millis(3));
        assert!(matches!(
            registry.reserve_create("new", "peer", "p".into(), 0, 1),
            CreateLookup::Reserved
        ));
    }

    #[test]
    fn stale_carrier_lease_does_not_remove_resumed_epoch() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (backend, _) = listener.accept().unwrap();
        let metrics = Arc::new(crate::metrics::Metrics::new());
        let registry = Arc::new(Registry::new(metrics.clone()));
        let session = Session::new(
            "s_test".to_string(),
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
            metrics,
        );
        session.enable_recovery(Duration::from_secs(5));
        session.attach("old-stream").unwrap();
        registry.insert(session.clone());
        let stale_lease = super::SessionLease::new(registry.clone(), session.id.clone());
        assert!(session.suspend(1));

        let request = ResumeRequest {
            resume_request_id: "resume-1".to_string(),
            expected_epoch: 1,
            ingress_instance_id: session.instance_id.clone(),
            transport: Mode::Ws,
            known_up_ack_offset: 0,
            up_next_offset: 0,
            down_delivered_offset: 0,
            up_fin: ResumeFin::default(),
            down_fin: ResumeFin::default(),
        };
        assert_eq!(
            session
                .resume(&request, Duration::from_secs(1))
                .unwrap()
                .epoch,
            2
        );

        drop(stale_lease);
        assert!(registry.get(&session.id).is_some());
        assert_eq!(session.epoch(), 2);
        registry.remove(&session.id);
        drop(peer);
    }

    #[test]
    fn auth_reload_sweep_closes_session_removed_from_target_acl() {
        let target = TcpListener::bind("127.0.0.1:0").unwrap();
        let fixture = fixture(&target.local_addr().unwrap().to_string(), 4);
        let request = create_request(&fixture.server, "acl-sweep", None);
        let (_, body) = fixture.server.handle_create(&request).unwrap();
        let session_id = response_session_id(&body);
        let session = fixture.server.registry.get(&session_id).unwrap();
        let (_backend, _) = target.accept().unwrap();

        let mut candidate = fixture.server.auth.snapshot();
        candidate
            .inbound
            .iter_mut()
            .find(|peer| peer.id == "peer-a")
            .unwrap()
            .allowed_targets
            .clear();
        fixture.server.on_auth_reload(&candidate);

        assert!(session.is_closed());
        assert_eq!(
            session.terminal_error().unwrap().code,
            wire::ERR_TARGET_FORBIDDEN
        );
        assert!(fixture.server.registry.get(&session_id).is_none());
    }

    #[test]
    fn inbound_connection_permit_holds_and_releases_connection_metadata_budgets() {
        let connections = crate::resource::budget::Budget::new(2);
        let metadata = crate::resource::budget::Budget::new(32 << 10);
        let budget = Arc::new(ConnectionBudget::new_with_budgets(
            1,
            Some(connections.clone()),
            Some(metadata.clone()),
        ));
        let ip = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let mut permit = budget.acquire(ip).expect("budgeted inbound connection");
        assert_eq!(connections.used(), 1);
        assert_eq!(metadata.used(), 16 << 10);
        permit.mark_authenticated();
        drop(permit);
        assert_eq!(connections.used(), 0);
        assert_eq!(metadata.used(), 0);
    }

    #[test]
    fn probe_permit_holds_and_releases_shared_probe_budget() {
        let shared = crate::resource::budget::Budget::new(1);
        let budget = ProbeBudget::new_with_budget(shared.clone());
        let permit = budget
            .try_acquire_probe_with_reason("peer-a", 1)
            .expect("one shared probe slot");
        assert_eq!(shared.used(), 1);
        assert!(matches!(
            budget.try_acquire_probe_with_reason("peer-b", 1),
            Err("probe budget")
        ));
        drop(permit);
        assert_eq!(shared.used(), 0);
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod migration_tests;

#[cfg(test)]
#[path = "spec_precheck_tests.rs"]
mod spec_precheck_tests;

#[cfg(test)]
#[path = "spec_server_tests.rs"]
mod spec_server_tests;

#[cfg(test)]
#[path = "spec_api_tests.rs"]
mod spec_api_tests;

#[cfg(test)]
#[path = "spec_registry_tests.rs"]
mod spec_registry_tests;

#[cfg(test)]
#[path = "spec_registry2_tests.rs"]
mod spec_registry2_tests;

#[cfg(test)]
#[path = "spec_budget_tests.rs"]
mod spec_budget_tests;

#[cfg(test)]
#[path = "spec_ws3_tests.rs"]
mod spec_ws3_tests;

#[cfg(test)]
#[path = "spec_ws4_tests.rs"]
mod spec_ws4_tests;

#[cfg(test)]
mod spec_adapt_tests;
#[cfg(test)]
#[path = "spec_ws5_tests.rs"]
mod spec_ws5_tests;
