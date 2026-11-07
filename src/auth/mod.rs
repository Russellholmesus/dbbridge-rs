use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use crate::config::{Config, InboundPeer};
use crate::error::{Error, Result};

#[derive(Clone, Debug)]
pub struct Snapshot {
    pub inbound: Vec<InboundPeer>,
    pub outbound: HashMap<String, String>,
    pub reverse: HashMap<String, String>,
}

impl Snapshot {
    pub fn from_config(cfg: &Config) -> Self {
        let outbound = cfg
            .peers
            .iter()
            .map(|p| (p.id.clone(), p.token.clone()))
            .collect();
        let mut reverse = HashMap::new();
        if cfg.reverse.enabled {
            reverse.insert(cfg.reverse.peer_node_id.clone(), cfg.reverse.token.clone());
        }
        Snapshot {
            inbound: cfg.inbound.clone(),
            outbound,
            reverse,
        }
    }

    fn compatible_with(&self, cfg: &Config, candidate: &Snapshot) -> Result<()> {
        let old_ids: Vec<_> = self.outbound.keys().collect();
        let new_ids: Vec<_> = candidate.outbound.keys().collect();
        if old_ids.len() != new_ids.len()
            || old_ids
                .iter()
                .any(|id| !candidate.outbound.contains_key(*id))
        {
            return Err(Error::new(
                crate::config::CODE_CREDENTIAL,
                "adding or removing peers requires a restart",
            ));
        }
        if cfg
            .peers
            .iter()
            .any(|p| !candidate.outbound.contains_key(&p.id))
        {
            return Err(Error::new(
                crate::config::CODE_CREDENTIAL,
                "adding or removing peers requires a restart",
            ));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct Authenticator {
    current: Arc<RwLock<Snapshot>>,
    cfg: Arc<Config>,
    metrics: Arc<crate::metrics::Metrics>,
    fair_usage: Arc<Mutex<HashMap<(String, String), i64>>>,
    reload_state: Arc<Mutex<ReloadState>>,
    on_reload: Arc<RwLock<Option<ReloadCallback>>>,
}

/// A per-peer share reservation. Its amount is returned when the protected
/// request finishes, including early-return and error paths.
pub struct FairLease {
    usage: Arc<Mutex<HashMap<(String, String), i64>>>,
    key: (String, String),
    amount: i64,
}

impl Drop for FairLease {
    fn drop(&mut self) {
        let mut usage = self
            .usage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(held) = usage.get_mut(&self.key) {
            *held = held.saturating_sub(self.amount);
            if *held <= 0 {
                usage.remove(&self.key);
            }
        }
    }
}

fn credential_warnings(cfg: &Config) -> impl Iterator<Item = &String> {
    cfg.warnings.iter().filter(|w| {
        w.contains("shorter than 16 bytes")
            || (w.starts_with("inbound peer ") && w.contains("exceeds limits.max_sessions"))
            || w.starts_with("inbound peers may hold all ")
    })
}

pub fn peer_share(global: i64, peers: usize) -> i64 {
    let global = global.max(0);
    if peers <= 1 || global <= 1 {
        return global;
    }
    let n = peers as i64;
    let floor = (global / (2 * n)).max(1);
    ((global - floor) / (n - 1)).max(1)
}

#[derive(Default)]
struct ReloadState {
    last_error: Option<String>,
    last_logged: Option<Instant>,
    revision: u64,
}

pub type ReloadCallback = Arc<dyn Fn(&Snapshot) + Send + Sync>;

impl Authenticator {
    pub fn new(cfg: Arc<Config>) -> Self {
        Self::with_metrics(cfg, Arc::new(crate::metrics::Metrics::new()))
    }

    pub fn with_metrics(cfg: Arc<Config>, metrics: Arc<crate::metrics::Metrics>) -> Self {
        metrics.auth_reload_succeeded(false);
        Self {
            current: Arc::new(RwLock::new(Snapshot::from_config(&cfg))),
            cfg,
            metrics,
            fair_usage: Arc::new(Mutex::new(HashMap::new())),
            reload_state: Arc::new(Mutex::new(ReloadState {
                last_error: None,
                last_logged: None,
                revision: 1,
            })),
            on_reload: Arc::new(RwLock::new(None)),
        }
    }

    pub fn set_reload_callback(&self, callback: ReloadCallback) {
        *self
            .on_reload
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(callback);
    }

    pub fn snapshot(&self) -> Snapshot {
        self.current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Reserves one peer's portion of a divisible process budget. The caller
    /// must also acquire the global budget; this per-peer guard only prevents
    /// one identity from consuming the other enabled identities' floor.
    pub fn reserve_fair_n(
        &self,
        peer: &str,
        kind: &str,
        global: i64,
        amount: i64,
    ) -> Option<FairLease> {
        let snapshot = self
            .current
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let enabled = snapshot.inbound.iter().filter(|p| p.enabled).count();
        if !snapshot.inbound.iter().any(|p| p.id == peer && p.enabled) || amount < 0 {
            return None;
        }
        let limit = peer_share(global, enabled);
        if amount > limit {
            return None;
        }
        let key = (peer.to_string(), kind.to_string());
        let mut usage = self
            .fair_usage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let held = usage.get(&key).copied().unwrap_or(0);
        if held.saturating_add(amount) > limit {
            return None;
        }
        usage.insert(key.clone(), held.saturating_add(amount));
        Some(FairLease {
            usage: self.fair_usage.clone(),
            key,
            amount,
        })
    }

    #[allow(dead_code)]
    pub fn authenticate(&self, token: &str) -> Option<String> {
        let snapshot = self.snapshot();
        let mut found = None;
        for peer in snapshot.inbound.iter().filter(|p| p.enabled) {
            let mut matched = false;
            for candidate in &peer.tokens {
                matched |= crate::egress::constant_time_eq(candidate.as_bytes(), token.as_bytes());
            }
            if matched {
                found = Some(peer.id.clone());
            }
        }
        found
    }

    pub fn inbound(&self, id: &str) -> Option<InboundPeer> {
        self.snapshot().inbound.into_iter().find(|p| p.id == id)
    }

    #[allow(dead_code)]
    pub fn outbound_token(&self, id: &str) -> Option<String> {
        self.snapshot().outbound.get(id).cloned()
    }

    pub fn reverse_token(&self, peer_node_id: &str) -> Option<String> {
        self.snapshot().reverse.get(peer_node_id).cloned()
    }

    #[cfg(test)]
    pub fn revision(&self) -> u64 {
        self.reload_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .revision
    }

    pub fn reload(&self, trigger: &str) -> Result<bool> {
        let mut state = self
            .reload_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let candidate_cfg = match crate::config::load(&self.cfg.path) {
            Ok(cfg) => cfg,
            Err(error) => return Err(self.reject_reload(&mut state, trigger, error)),
        };
        let candidate = Snapshot::from_config(&candidate_cfg);
        let old = self.snapshot();
        if let Err(error) = old.compatible_with(&self.cfg, &candidate) {
            return Err(self.reject_reload(&mut state, trigger, error));
        }
        let changed = old.inbound.len() != candidate.inbound.len()
            || old.inbound.iter().zip(&candidate.inbound).any(|(a, b)| {
                a.id != b.id
                    || a.enabled != b.enabled
                    || a.tokens != b.tokens
                    || a.allowed_targets != b.allowed_targets
                    || a.max_sessions != b.max_sessions
            })
            || old.outbound != candidate.outbound
            || old.reverse != candidate.reverse;
        self.metrics.auth_reload_succeeded(changed);
        if state.last_error.take().is_some() {
            crate::slog::info(
                "credential reload succeeded; the earlier reload error is resolved",
                &[("trigger", trigger.into())],
            );
            state.last_logged = None;
        }
        if changed {
            state.revision += 1;
            *self
                .current
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = candidate;
            crate::slog::info(
                "credentials reloaded",
                &[
                    ("trigger", trigger.into()),
                    ("revision", state.revision.into()),
                ],
            );
            for warning in credential_warnings(&candidate_cfg) {
                crate::slog::warn(
                    "credentials reload warning",
                    &[("warning", warning.as_str().into())],
                );
            }
            let callback = self
                .on_reload
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            if let Some(callback) = callback {
                callback(&self.snapshot());
            }
        } else if trigger == "request" {
            crate::slog::info(
                "credentials re-read; no change",
                &[("trigger", trigger.into())],
            );
        }
        Ok(changed)
    }

    fn reject_reload(&self, state: &mut ReloadState, trigger: &str, error: Error) -> Error {
        self.metrics.auth_reload_failed();
        let now = Instant::now();
        let reason = error.message.clone();
        let should_log = trigger == "request"
            || state.last_error.as_deref() != Some(reason.as_str())
            || state.last_logged.map_or(true, |at| {
                now.duration_since(at) >= Duration::from_secs(5 * 60)
            });
        if should_log {
            crate::slog::error(
                "credential reload rejected; the previous credentials stay in effect, including identities the candidate disables or removes",
                &[
                    ("code", "DBB-CFG-020".into()),
                    ("cause_code", error.code.as_str().into()),
                    ("trigger", trigger.into()),
                    ("err", error.message.as_str().into()),
                ],
            );
            state.last_logged = Some(now);
        }
        state.last_error = Some(reason);
        Error::new("DBB-CFG-020", error.message)
    }

    pub fn start(
        &self,
        stop: Arc<std::sync::atomic::AtomicBool>,
        hup: fn() -> bool,
    ) -> thread::JoinHandle<()> {
        let auth = self.clone();
        let interval = self.cfg.auth_reload_interval;
        thread::spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let deadline = std::time::Instant::now() + interval;
                while std::time::Instant::now() < deadline
                    && !stop.load(std::sync::atomic::Ordering::Relaxed)
                {
                    if hup() {
                        let _ = auth.reload("request");
                    }
                    thread::sleep(Duration::from_millis(50));
                }
                if !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let _ = auth.reload("interval");
                }
            }
        })
    }
}

#[cfg(test)]
#[path = "spec_auth_tests.rs"]
mod spec_auth_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn token_rotation_publishes_new_snapshot_without_identity_change() {
        let path = std::env::temp_dir().join(format!(
            "dbb-auth-{}-{}.yaml",
            std::process::id(),
            crate::util::random_hex(4).unwrap()
        ));
        fs::write(&path, "node:\n  id: n\ntargets:\n  db:\n    network: tcp\n    address: 127.0.0.1:3306\nauth:\n  inbound_peers:\n    - id: a\n      token_files: [dbb-auth-token]\n      allowed_targets: [db]\n").unwrap();
        let token_path = std::env::temp_dir().join("dbb-auth-token");
        fs::write(&token_path, "old-token\n").unwrap();
        let mut c = crate::config::load(&path).unwrap();
        c.path = path.clone();
        let a = Authenticator::new(Arc::new(c));
        let initial_metrics = a.metrics.render(&a.cfg, std::time::Instant::now(), true);
        assert!(!initial_metrics.contains("dbb_auth_reload_last_success_timestamp_seconds 0\n"));
        let callbacks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let callback_count = callbacks.clone();
        a.set_reload_callback(Arc::new(move |_| {
            callback_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }));
        assert_eq!(a.authenticate("old-token"), Some("a".into()));
        assert!(a.authenticate("invalid-token").is_none());
        fs::write(&token_path, "new-token\n").unwrap();
        assert!(a.reload("request").unwrap());
        assert!(a.authenticate("old-token").is_none());
        assert_eq!(a.authenticate("new-token"), Some("a".into()));
        assert_eq!(callbacks.load(std::sync::atomic::Ordering::Relaxed), 1);
        let metrics = a.metrics.render(&a.cfg, std::time::Instant::now(), true);
        assert!(metrics.contains("dbb_auth_reload_success_total 1"));
        assert!(metrics.contains("dbb_auth_credentials_stale 0"));
        fs::remove_file(&path).ok();
        fs::remove_file(&token_path).ok();
    }

    #[test]
    fn failed_reload_keeps_live_snapshot_and_session_identity() {
        let path = std::env::temp_dir().join(format!("dbb-auth-fail-{}.yaml", std::process::id()));
        fs::write(&path, "node:\n  id: n\ntargets:\n  db:\n    network: tcp\n    address: 127.0.0.1:3306\nauth:\n  inbound_peers:\n    - id: a\n      token_files: [dbb-auth-fail-token]\n      allowed_targets: [db]\n").unwrap();
        let token_path = std::env::temp_dir().join("dbb-auth-fail-token");
        fs::write(&token_path, "stable-token\n").unwrap();
        let mut c = crate::config::load(&path).unwrap();
        c.path = path.clone();
        let a = Authenticator::new(Arc::new(c));
        assert!(a.reload("request").is_ok());
        fs::write(&path, "node: [broken\n").unwrap();
        assert!(a.reload("interval").is_err());
        assert_eq!(a.authenticate("stable-token"), Some("a".into()));
        let metrics = a.metrics.render(&a.cfg, std::time::Instant::now(), true);
        assert!(metrics.contains("dbb_auth_reload_failed_total 1"));
        assert!(metrics.contains("dbb_auth_credentials_stale 1"));
        fs::remove_file(&path).ok();
        fs::remove_file(&token_path).ok();
    }

    #[test]
    fn reload_keeps_identity_quota_partition_and_rotates_one_token() {
        let dir = std::env::temp_dir().join(format!(
            "dbb-auth-partition-{}-{}",
            std::process::id(),
            crate::util::random_hex(4).unwrap()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.yaml");
        let credentials = dir.join("credentials.yaml");
        fs::write(
            &path,
            "node:\n  id: n\ntargets:\n  db:\n    network: tcp\n    address: 127.0.0.1:3306\nlimits:\n  max_sessions: 10\nauth:\n  credentials_file: credentials.yaml\n",
        )
        .unwrap();
        let write_credentials = |a_quota: u32, b_quota: u32, a_token: &str| {
            fs::write(
                &credentials,
                format!(
                    "version: 1\ninbound_peers:\n  - id: A\n    token_files: [a-token]\n    allowed_targets: [db]\n    max_sessions: {a_quota}\n  - id: B\n    token_files: [b-token]\n    allowed_targets: [db]\n    max_sessions: {b_quota}\n"
                ),
            )
            .unwrap();
            fs::write(dir.join("a-token"), format!("{a_token}\n")).unwrap();
            fs::write(dir.join("b-token"), "identity-b-stable-token\n").unwrap();
        };
        write_credentials(5, 5, "identity-a-old-token");

        let mut cfg = crate::config::load(&path).unwrap();
        cfg.path = path.clone();
        let auth = Authenticator::new(Arc::new(cfg));
        assert_eq!(peer_share(16, 1), 16);
        assert_eq!(peer_share(16, 2), 12);
        assert_eq!(peer_share(16, 3), 7);
        assert_eq!(peer_share(4, 3), 1);
        let held = auth
            .reserve_fair_n("A", "data-requests", 16, 12)
            .expect("enabled peer receives its share");
        assert!(auth.reserve_fair_n("A", "data-requests", 16, 1).is_none());
        assert!(auth.reserve_fair_n("B", "data-requests", 16, 12).is_some());
        drop(held);
        assert!(auth.reserve_fair_n("A", "data-requests", 16, 1).is_some());
        assert_eq!(auth.authenticate("identity-a-old-token"), Some("A".into()));
        assert_eq!(
            auth.authenticate("identity-b-stable-token"),
            Some("B".into())
        );
        assert_eq!(auth.inbound("A").unwrap().max_sessions, 5);
        assert_eq!(auth.inbound("B").unwrap().max_sessions, 5);

        write_credentials(6, 4, "identity-a-new-token");
        assert!(auth.reload("request").unwrap());
        assert_eq!(auth.inbound("A").unwrap().max_sessions, 6);
        assert_eq!(auth.inbound("B").unwrap().max_sessions, 4);
        assert_eq!(auth.authenticate("identity-a-new-token"), Some("A".into()));
        assert!(auth.authenticate("identity-a-old-token").is_none());
        assert_eq!(
            auth.authenticate("identity-b-stable-token"),
            Some("B".into())
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reload_rejects_zero_quota_and_keeps_previous_snapshot() {
        let dir = std::env::temp_dir().join(format!(
            "dbb-auth-zero-quota-{}-{}",
            std::process::id(),
            crate::util::random_hex(4).unwrap()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.yaml");
        let credentials = dir.join("credentials.yaml");
        fs::write(
            &path,
            "node:\n  id: n\ntargets:\n  db:\n    network: tcp\n    address: 127.0.0.1:3306\nauth:\n  credentials_file: credentials.yaml\n",
        )
        .unwrap();
        fs::write(
            &credentials,
            "version: 1\ninbound_peers:\n  - id: A\n    token_files: [a-token]\n    allowed_targets: [db]\n    max_sessions: 2\n",
        )
        .unwrap();
        fs::write(dir.join("a-token"), "identity-a-stable-token\n").unwrap();

        let mut cfg = crate::config::load(&path).unwrap();
        cfg.path = path.clone();
        let auth = Authenticator::new(Arc::new(cfg));
        assert_eq!(
            auth.authenticate("identity-a-stable-token"),
            Some("A".into())
        );
        assert_eq!(auth.inbound("A").unwrap().max_sessions, 2);

        fs::write(
            &credentials,
            "version: 1\ninbound_peers:\n  - id: A\n    token_files: [a-token]\n    allowed_targets: [db]\n    max_sessions: 0\n",
        )
        .unwrap();
        assert!(auth.reload("request").is_err());
        assert_eq!(
            auth.authenticate("identity-a-stable-token"),
            Some("A".into())
        );
        assert_eq!(auth.inbound("A").unwrap().max_sessions, 2);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn disabled_identity_token_is_never_authenticated() {
        let path = std::env::temp_dir().join(format!(
            "dbb-auth-disabled-{}-{}.yaml",
            std::process::id(),
            crate::util::random_hex(4).unwrap()
        ));
        fs::write(
            &path,
            "node:\n  id: n\ntargets:\n  db:\n    network: tcp\n    address: 127.0.0.1:3306\nauth:\n  inbound_peers:\n    - id: dormant\n      enabled: false\n      token_files: [unused-token]\n      allowed_targets: [db]\n",
        )
        .unwrap();
        let mut cfg = crate::config::load(&path).unwrap();
        cfg.inbound[0].enabled = false;
        // A stale token can exist in a caller-provided snapshot even though
        // config loading correctly skips credential resolution for disabled peers.
        cfg.inbound[0].tokens = vec!["disabled-token".into()];
        let auth = Authenticator::new(Arc::new(cfg));
        assert!(auth.authenticate("disabled-token").is_none());
        assert!(auth.authenticate("invalid-token").is_none());
        fs::remove_file(&path).ok();
    }

    #[test]
    fn hot_reload_removal_revokes_only_removed_inbound_peer() {
        let dir = std::env::temp_dir().join(format!(
            "dbb-auth-remove-{}-{}",
            std::process::id(),
            crate::util::random_hex(4).unwrap()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.yaml");
        let credentials = dir.join("credentials.yaml");
        fs::write(
            &path,
            "node:\n  id: n\ntargets:\n  db:\n    network: tcp\n    address: 127.0.0.1:3306\nauth:\n  credentials_file: credentials.yaml\n",
        )
        .unwrap();
        fs::write(
            &credentials,
            "version: 1\ninbound_peers:\n  - id: peer-1\n    token_files: [peer-1.token]\n    allowed_targets: [db]\n    max_sessions: 100\n  - id: peer-2\n    token_files: [peer-2.token]\n    allowed_targets: [db]\n    max_sessions: 100\n",
        )
        .unwrap();
        fs::write(dir.join("peer-1.token"), "peer-one-token-012345\n").unwrap();
        fs::write(dir.join("peer-2.token"), "peer-two-token-012345\n").unwrap();

        let mut cfg = crate::config::load(&path).unwrap();
        cfg.path = path.clone();
        let auth = Authenticator::new(Arc::new(cfg));
        assert_eq!(
            auth.authenticate("peer-one-token-012345"),
            Some("peer-1".into())
        );
        assert_eq!(
            auth.authenticate("peer-two-token-012345"),
            Some("peer-2".into())
        );

        fs::write(
            &credentials,
            "version: 1\ninbound_peers:\n  - id: peer-1\n    token_files: [peer-1.token]\n    allowed_targets: [db]\n",
        )
        .unwrap();
        assert!(auth.reload("request").unwrap());
        assert_eq!(
            auth.authenticate("peer-one-token-012345"),
            Some("peer-1".into())
        );
        assert!(auth.authenticate("peer-two-token-012345").is_none());

        fs::remove_dir_all(&dir).ok();
    }
}

#[cfg(test)]
#[path = "spec_reload4_tests.rs"]
mod spec_reload4_tests;
