use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use crate::config::Config;

use super::budget::Budget;
use super::retention::Retention;

pub const RESOURCE_NAMES: [&str; 16] = [
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

pub struct ResourceManager {
    pub payload: Arc<Budget>,
    pub codec: Arc<Budget>,
    pub metadata: Arc<Budget>,
    pub control_metadata: Arc<Budget>,
    pub probe_metadata: Arc<Budget>,
    pub sessions: Arc<Budget>,
    pub probes: Arc<Budget>,
    pub recovery: Arc<Budget>,
    pub cleanup: Arc<Budget>,
    pub creates: Arc<Budget>,
    pub inbound_connections: Arc<Budget>,
    pub conn_metadata: Arc<Budget>,
    pub data_connections: Arc<Budget>,
    pub control_connections: Arc<Budget>,
    pub data_requests: Arc<Budget>,
    pub control_requests: Arc<Budget>,
    pub suspended: Arc<Retention>,
    pub chunk_size: u64,
    pub buffer_per_direction: u64,
    pub up_max_inflight_frames: u32,
    pub receipt_limit_per_session: u32,
    instrumented: Mutex<BTreeSet<String>>,
    ingress_session_floor: AtomicI64,
    ingress_metadata_floor: AtomicI64,
    ingress_codec_floor: Arc<AtomicI64>,
    peer_codec: Mutex<BTreeMap<String, Arc<Budget>>>,
    max_codec_charge: i64,
}

const WS_BINARY_HEADER_LEN: i64 = 56;
const WS_TEXT_COST: i64 = 16 << 10;

fn configured_max_frame(cfg: &Config) -> i64 {
    let n = if cfg.transport.max_frame_size > 0 {
        cfg.transport.max_frame_size
    } else {
        256 << 10
    };
    i64::try_from(n).unwrap_or(i64::MAX)
}

fn ws_down_cost(size: i64) -> i64 {
    size.saturating_mul(2).saturating_add(WS_BINARY_HEADER_LEN)
}

fn sse_down_cost(size: i64) -> i64 {
    size.saturating_mul(6).saturating_add(16384)
}

fn max_codec_charge(cfg: &Config) -> i64 {
    let n = configured_max_frame(cfg);
    let mut charge = ws_down_cost(n).max(WS_TEXT_COST);
    let modes = cfg.transports();
    if modes.is_empty() || modes.contains(&crate::wire::Mode::HttpSse) {
        charge = charge.max(sse_down_cost(n));
    }
    charge
}

fn ingress_codec_charge(cfg: &Config) -> i64 {
    let n = configured_max_frame(cfg);
    let ws = crate::config::Protocol::Ws;
    let sse = cfg.transport.protocol != ws || cfg.peers.iter().any(|p| p.protocol != ws);
    if sse {
        sse_down_cost(n)
    } else {
        n.saturating_add(WS_BINARY_HEADER_LEN)
    }
}

impl ResourceManager {
    pub fn new(cfg: &Config) -> Arc<Self> {
        let physical = u64::from(cfg.limits.max_sessions.clamp(1, 8192));
        let reserve = (cfg.transport.metadata_limit / 4).min(1 << 20);
        let inbound_connections = 4u64.saturating_mul(physical).saturating_add(64);
        let data_slots = 2u64.saturating_mul(physical).saturating_add(32);
        let control_slots = physical.saturating_add(32).min(256);
        let as_i64 = |value: u64| i64::try_from(value).unwrap_or(i64::MAX);
        let max_sessions = cfg.limits.max_sessions;

        let manager = Arc::new(Self {
            payload: Budget::new(as_i64(cfg.transport.global_buffer_limit)),
            codec: Budget::new(as_i64(cfg.transport.codec_buffer_limit)),
            metadata: Budget::new(as_i64(
                cfg.transport.metadata_limit.saturating_sub(2 * reserve),
            )),
            control_metadata: Budget::new(as_i64(reserve)),
            probe_metadata: Budget::new(as_i64(reserve)),
            sessions: Budget::new(i64::from(max_sessions)),
            probes: Budget::new(16),
            recovery: Budget::new(16),
            cleanup: Budget::new(16),
            creates: Budget::new(16),
            inbound_connections: Budget::new(as_i64(inbound_connections)),
            conn_metadata: Budget::new(as_i64(inbound_connections.saturating_mul(16 << 10))),
            data_connections: Budget::new(as_i64(data_slots)),
            control_connections: Budget::new(as_i64(control_slots)),
            data_requests: Budget::new(as_i64(data_slots)),
            control_requests: Budget::new(as_i64(control_slots)),
            suspended: Arc::new(Retention::new(as_i64(cfg.transport.suspended_buffer_limit))),
            chunk_size: cfg.transport.chunk_size.max(1) as u64,
            buffer_per_direction: cfg.transport.buffer_per_direction,
            up_max_inflight_frames: cfg.transport.up_max_inflight_frames,
            receipt_limit_per_session: cfg.transport.receipt_limit_per_session,
            instrumented: Mutex::new(BTreeSet::new()),
            ingress_session_floor: AtomicI64::new(0),
            ingress_metadata_floor: AtomicI64::new(0),
            ingress_codec_floor: Arc::new(AtomicI64::new(0)),
            peer_codec: Mutex::new(BTreeMap::new()),
            max_codec_charge: max_codec_charge(cfg),
        });
        if cfg.egress_role() {
            manager.apply_ingress_reserve(cfg);
            manager.apply_ingress_codec_reserve(cfg);
        }
        manager
    }

    fn apply_ingress_reserve(&self, cfg: &Config) {
        if cfg.listeners.is_empty() {
            return;
        }
        let limit = self.sessions.limit();
        let sessions = if limit > 1 { (limit / 4).max(1) } else { 0 };
        self.ingress_session_floor
            .store(sessions.min(limit).max(0), Ordering::Release);
        let metadata = self.metadata.limit() / 8;
        self.ingress_metadata_floor.store(
            metadata.min(self.metadata.limit()).max(0),
            Ordering::Release,
        );
    }

    fn apply_ingress_codec_reserve(&self, cfg: &Config) {
        if cfg.listeners.is_empty() {
            return;
        }
        let limit = self.codec.limit();
        let floor = (limit / 8)
            .max(ingress_codec_charge(cfg))
            .min(limit - max_codec_charge(cfg));
        if floor > 0 {
            self.ingress_codec_floor
                .store(floor.min(limit), Ordering::Release);
        }
    }

    #[cfg(test)]
    pub fn ingress_reserve(&self) -> (i64, i64) {
        (
            self.ingress_session_floor.load(Ordering::Acquire),
            self.ingress_metadata_floor.load(Ordering::Acquire),
        )
    }

    #[cfg(test)]
    pub fn ingress_codec_reserve(&self) -> i64 {
        self.ingress_codec_floor.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub fn set_ingress_codec_reserve(&self, n: i64) {
        self.ingress_codec_floor
            .store(n.clamp(0, self.codec.limit()), Ordering::Release);
    }

    pub fn try_egress_session(&self) -> Option<super::budget::BudgetLease> {
        self.sessions
            .try_acquire_keep(1, self.ingress_session_floor.load(Ordering::Acquire))
    }

    pub fn egress_metadata_limit(&self) -> i64 {
        (self.metadata.limit() - self.ingress_metadata_floor.load(Ordering::Acquire)).max(0)
    }

    pub fn egress_session_slots(&self) -> i64 {
        (self.sessions.limit() - self.ingress_session_floor.load(Ordering::Acquire)).max(0)
    }

    pub fn try_egress_metadata(&self, n: i64) -> Option<super::budget::BudgetLease> {
        self.metadata
            .try_acquire_keep(n, self.ingress_metadata_floor.load(Ordering::Acquire))
    }

    pub fn try_codec_keep(&self, n: i64) -> Option<super::budget::BudgetLease> {
        self.codec
            .try_acquire_keep(n, self.ingress_codec_floor.load(Ordering::Acquire))
    }

    pub fn egress_codec_limit(&self) -> i64 {
        (self.codec.limit() - self.ingress_codec_floor.load(Ordering::Acquire)).max(0)
    }

    pub fn peer_codec_limit(&self, known: bool, enabled_peers: usize) -> i64 {
        let egress = self.egress_codec_limit();
        let share = if known {
            crate::auth::peer_share(egress, enabled_peers)
        } else {
            0
        };
        share.max(self.max_codec_charge).min(egress)
    }

    pub fn egress_codec_for(&self, peer: &str, limit: impl FnOnce() -> i64) -> Arc<Budget> {
        self.mark_instrumented("codec");
        let mut shares = self
            .peer_codec
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(share) = shares.get(peer) {
            return share.clone();
        }
        let floor = self.ingress_codec_floor.clone();
        let share = Budget::new_share(self.codec.clone(), limit(), move || {
            floor.load(Ordering::Acquire)
        });
        shares.insert(peer.to_string(), share.clone());
        share
    }

    pub fn resize_peer_codec(&self, limit: impl Fn(&str) -> i64) {
        let shares = self
            .peer_codec
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (peer, share) in shares.iter() {
            share.set_limit(limit(peer));
        }
    }

    pub fn budget(&self, resource: &str) -> Option<&Arc<Budget>> {
        match resource {
            "payload" => Some(&self.payload),
            "codec" => Some(&self.codec),
            "metadata" => Some(&self.metadata),
            "control_metadata" => Some(&self.control_metadata),
            "probe_metadata" => Some(&self.probe_metadata),
            "sessions" => Some(&self.sessions),
            "probes" => Some(&self.probes),
            "recovery" => Some(&self.recovery),
            "cleanup" => Some(&self.cleanup),
            "creates" => Some(&self.creates),
            "inbound_connections" => Some(&self.inbound_connections),
            "conn_metadata" => Some(&self.conn_metadata),
            "data_connections" => Some(&self.data_connections),
            "control_connections" => Some(&self.control_connections),
            "data_requests" => Some(&self.data_requests),
            "control_requests" => Some(&self.control_requests),
            _ => None,
        }
    }

    pub fn mark_instrumented(&self, resource: &str) {
        if RESOURCE_NAMES.contains(&resource) {
            self.instrumented
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(resource.to_string());
        }
    }

    pub fn session_metadata_cost(&self) -> i64 {
        let buffer_size = self.buffer_per_direction.max(1);
        let cost = (64u64 << 10)
            .saturating_add(u64::from(self.receipt_limit_per_session).saturating_mul(160))
            .saturating_add(u64::from(self.up_max_inflight_frames).saturating_mul(192))
            .saturating_add(
                (buffer_size / self.chunk_size)
                    .saturating_add(513)
                    .saturating_mul(32),
            );
        i64::try_from(cost).unwrap_or(i64::MAX)
    }

    pub fn resource_snapshot(&self) -> BTreeMap<String, (u64, u64, u64, f64)> {
        let instrumented = self
            .instrumented
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        RESOURCE_NAMES
            .iter()
            .filter(|name| instrumented.contains(**name))
            .filter_map(|name| {
                let budget = self.budget(name)?;
                let (waits, duration) = budget.wait_stats();
                Some((
                    (*name).to_string(),
                    (
                        budget.used().max(0) as u64,
                        budget.limit().max(0) as u64,
                        waits,
                        duration.as_secs_f64(),
                    ),
                ))
            })
            .collect()
    }
}

#[cfg(test)]
#[path = "spec_codec3_tests.rs"]
mod spec_codec3_tests;

#[cfg(test)]
mod tests {
    use super::*;

    fn config(yaml_extra: &str, listeners: bool) -> Config {
        let dir = std::env::temp_dir().join(format!(
            "dbb-rm-{}",
            crate::util::random_hex(6).expect("OS random for test fixture")
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("tok"), "abcdefghijklmnop").unwrap();
        let listeners = if listeners {
            "listeners:\n  - id: local\n    listen: \"127.0.0.1:13306\"\n    peer: peer-b\n    target: db\npeers:\n  - id: peer-b\n    expected_node_id: peer-b\n    credential_ref: peer-b\n    token_file: tok\n    endpoints:\n      - {id: p, url: \"http://127.0.0.1:18081\", priority: 1}\n"
        } else {
            ""
        };
        let yaml = format!(
            "node:\n  id: peer-a\nhttp:\n  enabled: true\n  listen: \"127.0.0.1:18080\"\n{listeners}targets:\n  db:\n    network: tcp\n    address: \"127.0.0.1:3306\"\nauth:\n  inbound_peers:\n    - id: peer-c\n      token_files: [tok]\n      allowed_targets: [db]\n{yaml_extra}"
        );
        let path = dir.join("config.yaml");
        std::fs::write(&path, yaml).unwrap();
        let cfg = crate::config::load(&path).unwrap();
        std::fs::remove_dir_all(dir).unwrap();
        cfg
    }

    #[test]
    fn ingress_reserve_keeps_local_sessions_free_from_egress_admission() {
        let cfg = config("limits:\n  max_sessions: 8\n", true);
        let r = ResourceManager::new(&cfg);
        assert_eq!(r.ingress_reserve(), (2, r.metadata.limit() / 8));
        assert!(r.ingress_codec_reserve() > 0);
        let egress: Vec<_> = std::iter::from_fn(|| r.try_egress_session())
            .take(10)
            .collect();
        assert_eq!(egress.len(), 6);
        let local: Vec<_> = std::iter::from_fn(|| r.sessions.try_acquire(1))
            .take(10)
            .collect();
        assert_eq!(local.len(), 2);

        let cfg = config("limits:\n  max_sessions: 8\n", false);
        let r = ResourceManager::new(&cfg);
        assert_eq!(r.ingress_reserve(), (0, 0));
        assert_eq!(r.ingress_codec_reserve(), 0);
        let egress: Vec<_> = std::iter::from_fn(|| r.try_egress_session())
            .take(10)
            .collect();
        assert_eq!(egress.len(), 8);
    }

    #[test]
    fn egress_codec_share_per_peer_keeps_ingress_reserve() {
        let cfg = config("", true);
        let r = ResourceManager::new(&cfg);
        let floor = r.ingress_codec_reserve();
        assert!(floor > 0);
        let egress = r.codec.limit() - floor;
        assert_eq!(r.egress_codec_limit(), egress);
        assert_eq!(r.peer_codec_limit(true, 1), egress);
        let two = crate::auth::peer_share(egress, 2).max(r.max_codec_charge);
        assert_eq!(r.peer_codec_limit(true, 2), two.min(egress));
        // Unknown or disabled peers still get one maximal charge.
        assert_eq!(r.peer_codec_limit(false, 2), r.max_codec_charge.min(egress));

        let a = r.egress_codec_for("peer-c", || egress);
        assert!(Arc::ptr_eq(&a, &r.egress_codec_for("peer-c", || 1)));
        // The share can take the egress part but never the ingress floor.
        let all = a.try_acquire(egress).unwrap();
        assert_eq!(r.codec.used(), egress);
        assert!(a.try_acquire(1).is_none());
        let b = r.egress_codec_for("peer-d", || egress);
        assert!(b.try_acquire(1).is_none());
        // The local ingress still has its reserve.
        let local = r.codec.try_acquire(floor).unwrap();
        drop(local);
        drop(all);
        assert_eq!(r.codec.used(), 0);

        r.resize_peer_codec(|peer| if peer == "peer-c" { 1000 } else { 2000 });
        assert_eq!(a.limit(), 1000);
        assert_eq!(b.limit(), 2000);
        assert!(a.try_acquire(1001).is_none());
        assert!(a.try_acquire(1000).is_some());
    }
}
