pub mod yaml;

use std::path::PathBuf;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::net::Url;
use crate::wire::Mode;
use yaml::Yaml;

pub const CODE_CONFIG_READ: &str = "DBB-CFG-001";
pub const CODE_CONFIG_INVALID: &str = "DBB-CFG-002";
pub const CODE_CONFIG_SECURITY: &str = "DBB-CFG-005";
pub const CODE_AUTH_CONFLICT: &str = "DBB-CFG-003";
pub const CODE_TLS: &str = "DBB-CFG-004";
pub const CODE_PEER_MODE: &str = "DBB-CFG-007";
pub const CODE_REVERSE: &str = "DBB-CFG-008";
pub const CODE_CREDENTIAL: &str = "DBB-CFG-003";
pub const CODE_ENVIRONMENT: &str = "DBB-CFG-006";
pub const CODE_LISTEN: &str = "DBB-CFG-005";
pub const CODE_START_FAILED: &str = "DBB-CFG-010";
pub const CODE_SERVICE_INSTALL: &str = "DBB-CFG-030";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Auto,
    Ws,
    HttpSse,
    LongPoll,
}

impl Protocol {
    pub fn parse(s: &str) -> Option<Protocol> {
        match s {
            "auto" => Some(Protocol::Auto),
            "ws" => Some(Protocol::Ws),
            "http-sse" => Some(Protocol::HttpSse),
            "long-poll" => Some(Protocol::LongPoll),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Node {
    pub id: String,
    pub instance_id: String,
}

#[derive(Debug, Clone)]
pub struct Http {
    pub enabled: bool,
    pub listen: String,
    pub allowed_transports: Vec<Mode>,
    #[allow(dead_code)]
    pub tls: HttpTls,
}

#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct HttpTls {
    pub enabled: bool,
    pub cert_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct Admin {
    pub enabled: bool,
    pub listen: String,
}

#[derive(Debug, Clone)]
pub struct Endpoint {
    pub id: String,
    pub url: Url,
    pub priority: i32,
}

#[derive(Debug, Clone)]
pub struct Failover {
    pub enabled: bool,
    #[allow(dead_code)]
    pub strategy: String,
    #[allow(dead_code)]
    pub failback: String,
    pub healthy_threshold: u32,
    pub unhealthy_threshold: u32,
    pub healthcheck_interval: Duration,
    pub healthcheck_timeout: Duration,
    pub cooldown: Duration,
}

impl Default for Failover {
    fn default() -> Self {
        Failover {
            enabled: true,
            strategy: "priority".into(),
            failback: "new_sessions".into(),
            healthy_threshold: 2,
            unhealthy_threshold: 2,
            healthcheck_interval: Duration::from_secs(10),
            healthcheck_timeout: Duration::from_secs(3),
            cooldown: Duration::from_secs(5),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Peer {
    pub id: String,
    pub expected_node_id: String,
    pub token: String,
    pub endpoints: Vec<Endpoint>,
    pub failover: Failover,
    pub protocol: Protocol,
    pub recovery_enabled: Option<bool>,
    /// The peer dials this node and carries every session to it over that
    /// tunnel, so it has no endpoints: the one virtual endpoint
    /// `reverse.tunnel.invalid` stands in for them.
    pub reverse: bool,
    #[allow(dead_code)]
    pub tls: ClientTls,
}

#[derive(Debug, Clone, Default)]
pub struct ClientTls {
    pub verify: bool,
    pub ca_file: Option<PathBuf>,
    #[allow(dead_code)]
    pub allow_insecure_skip_verify: bool,
}

/// The database side of reverse mode: this node dials the public side and
/// serves its egress role over the tunnels it keeps open.
#[derive(Debug, Clone)]
pub struct Reverse {
    pub enabled: bool,
    pub peer_node_id: String,
    pub token: String,
    pub transport: Protocol,
    pub tunnels_per_endpoint: u32,
    pub endpoints: Vec<Endpoint>,
    pub min_backoff: Duration,
    pub max_backoff: Duration,
    pub tls: ClientTls,
}

impl Default for Reverse {
    fn default() -> Self {
        Reverse {
            enabled: false,
            peer_node_id: String::new(),
            token: String::new(),
            transport: Protocol::Auto,
            tunnels_per_endpoint: 2,
            endpoints: Vec::new(),
            min_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(30),
            tls: ClientTls {
                verify: true,
                ..ClientTls::default()
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct Listener {
    pub id: String,
    pub listen: String,
    pub peer: String,
    pub target: String,
}

#[derive(Debug, Clone)]
pub struct Target {
    pub id: String,
    pub network: String,
    pub address: String,
    pub allowed_cidrs: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct InboundPeer {
    pub id: String,
    pub enabled: bool,
    /// Each configured token source is an alternative credential for this identity.
    pub tokens: Vec<String>,
    pub allowed_targets: Vec<String>,
    pub max_sessions: u32,
}

#[derive(Debug, Clone)]
pub struct Transport {
    pub protocol: Protocol,
    pub h2_pool_size: u32,
    pub frame_size: usize,
    pub max_frame_size: usize,
    pub chunk_size: usize,
    pub buffer_per_direction: u64,
    pub global_buffer_limit: u64,
    pub suspended_buffer_limit: u64,
    pub up_window_bytes: u64,
    pub up_max_inflight_frames: u32,
    pub receipt_limit_per_session: u32,
    pub heartbeat: Duration,
    pub failure_detect_timeout: Duration,
    pub ack_batch_bytes: u64,
    pub ack_max_delay: Duration,
    pub up_ack_max_delay: Duration,
    pub control_request_timeout: Duration,
    pub create_retry_timeout: Duration,
    pub dial_timeout: Duration,
    pub peer_dial_timeout: Duration,
    pub unattached_timeout: Duration,
    pub backpressure_timeout: Duration,
    pub sse_write_idle_timeout: Duration,
    pub ws_handshake_timeout: Duration,
    pub shutdown_timeout: Duration,
    pub recovery_enabled: bool,
    pub recovery_grace: Duration,
    pub recovery_barrier_timeout: Duration,
    pub idempotency_tombstone_ttl: Duration,
    pub codec_buffer_limit: u64,
    pub metadata_limit: u64,
    #[allow(dead_code)]
    pub ws_write_idle_timeout: Duration,
    #[allow(dead_code)]
    pub up_request_timeout: Duration,
    #[allow(dead_code)]
    pub socket_write_timeout: Duration,
    #[allow(dead_code)]
    pub use_environment_proxy: bool,
    #[allow(dead_code)]
    pub user_agent: String,
}

pub const DEFAULT_USER_AGENT: &str = "DBBridge/1.5";

impl Transport {
    pub fn tunnel_stream_window(&self) -> u64 {
        let lo = 256 << 10;
        let hi = self.buffer_per_direction.min(1 << 20).max(lo);
        (self.codec_buffer_limit / 128).max(lo).min(hi)
    }
}

impl Default for Transport {
    fn default() -> Self {
        Transport {
            protocol: Protocol::Auto,
            h2_pool_size: 4,
            frame_size: 32 * 1024,
            max_frame_size: 256 * 1024,
            chunk_size: 32 * 1024,
            buffer_per_direction: 4 * 1024 * 1024,
            global_buffer_limit: 256 * 1024 * 1024,
            suspended_buffer_limit: 64 * 1024 * 1024,
            up_window_bytes: 2 * 1024 * 1024,
            up_max_inflight_frames: 8,
            receipt_limit_per_session: 64,
            heartbeat: Duration::from_secs(15),
            failure_detect_timeout: Duration::from_secs(45),
            ack_batch_bytes: 1024 * 1024,
            ack_max_delay: Duration::from_millis(200),
            up_ack_max_delay: Duration::from_millis(10),
            control_request_timeout: Duration::from_secs(10),
            create_retry_timeout: Duration::from_secs(30),
            dial_timeout: Duration::from_secs(5),
            peer_dial_timeout: Duration::from_secs(5),
            unattached_timeout: Duration::from_secs(30),
            backpressure_timeout: Duration::from_secs(120),
            sse_write_idle_timeout: Duration::from_secs(60),
            ws_handshake_timeout: Duration::from_secs(5),
            shutdown_timeout: Duration::from_secs(30),
            recovery_enabled: true,
            recovery_grace: Duration::from_secs(30),
            recovery_barrier_timeout: Duration::from_secs(5),
            idempotency_tombstone_ttl: Duration::from_secs(600),
            codec_buffer_limit: 32 * 1024 * 1024,
            metadata_limit: 32 * 1024 * 1024,
            ws_write_idle_timeout: Duration::from_secs(60),
            up_request_timeout: Duration::from_secs(30),
            socket_write_timeout: Duration::from_secs(60),
            use_environment_proxy: false,
            user_agent: DEFAULT_USER_AGENT.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Limits {
    pub max_sessions: u32,
    pub max_endpoints_per_peer: u32,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub path: PathBuf,
    pub node: Node,
    pub http: Http,
    pub admin: Admin,
    pub peers: Vec<Peer>,
    pub listeners: Vec<Listener>,
    pub targets: Vec<Target>,
    pub inbound: Vec<InboundPeer>,
    pub warnings: Vec<String>,
    /// Parsed interval reserved for the still-pending P3 credential reload loop.
    #[allow(dead_code)]
    pub auth_reload_interval: Duration,
    pub transport: Transport,
    pub limits: Limits,
    pub reverse: Reverse,
}

pub const SHUTDOWN_TEARDOWN_BUDGET: Duration = Duration::from_secs(15);

impl Config {
    pub fn max_shutdown_duration(&self) -> Duration {
        self.transport.shutdown_timeout + SHUTDOWN_TEARDOWN_BUDGET
    }

    pub fn ingress_role(&self) -> bool {
        !self.listeners.is_empty()
    }

    pub fn egress_role(&self) -> bool {
        // A reverse node serves its egress role over the tunnel instead of a
        // listening socket, so it is an egress even with http.enabled false.
        self.http.enabled || self.reverse.enabled
    }

    pub fn has_reverse_peers(&self) -> bool {
        self.peers.iter().any(|p| p.reverse)
    }

    pub fn peer(&self, id: &str) -> Option<&Peer> {
        self.peers.iter().find(|p| p.id == id)
    }

    pub fn target(&self, id: &str) -> Option<&Target> {
        self.targets.iter().find(|t| t.id == id)
    }

    /// The transports this node accepts as an egress.
    pub fn transports(&self) -> &[Mode] {
        &self.http.allowed_transports
    }
}

pub(crate) fn validate_metadata_budget(
    transport: &Transport,
    limits: &Limits,
    http: &Http,
    listeners: &[Listener],
    peers: &[Peer],
    reverse: &Reverse,
) -> Result<()> {
    let metadata = transport.metadata_limit;
    if metadata < 512 * 1024 {
        return Err(invalid("codec/metadata budget too small".into()));
    }
    let frame = transport.max_frame_size as u64;
    let mut codec = (2 * frame + 56).max(16 * 1024);
    if !listeners.is_empty()
        || !peers.is_empty()
        || !http.enabled
        || http.allowed_transports.contains(&Mode::HttpSse)
    {
        codec = codec.max(6 * frame + 16 * 1024);
    }
    if http.enabled && !listeners.is_empty() {
        let mut egress = (2 * frame + 56).max(16 * 1024);
        if http.allowed_transports.contains(&Mode::HttpSse) {
            egress = egress.max(6 * frame + 16 * 1024);
        }
        codec = codec.max(egress + frame + 56);
    }
    if transport.codec_buffer_limit < codec {
        return Err(invalid("codec/metadata budget too small".into()));
    }
    if reverse.enabled {
        let mut need = codec
            .checked_add(2 * transport.tunnel_stream_window())
            .ok_or_else(|| invalid("codec budget overflows".into()))?;
        if reverse.transport != Protocol::Ws {
            need = need
                .checked_add(1 << 20)
                .ok_or_else(|| invalid("codec budget overflows".into()))?;
        }
        if need > transport.codec_buffer_limit {
            return Err(invalid(format!(
                "transport.codec_buffer_limit ({} KiB) is too small for reverse tunnels: one session needs a control and a data stream window (2 x {} KiB) plus an HTTP carrier's buffers beside the {} KiB the data plane needs; raise it to at least {} KiB",
                transport.codec_buffer_limit >> 10,
                transport.tunnel_stream_window() >> 10,
                codec >> 10,
                need.div_ceil(1024)
            )));
        }
    }
    let usable = metadata.saturating_sub(2 * (metadata / 4).min(1 << 20));
    let per_session = (64 * 1024u64)
        .checked_add(
            160u64
                .checked_mul(transport.receipt_limit_per_session as u64)
                .ok_or_else(|| invalid("per-session metadata budget overflows".into()))?,
        )
        .and_then(|n| {
            192u64
                .checked_mul(transport.up_max_inflight_frames as u64)
                .and_then(|x| n.checked_add(x))
        })
        .and_then(|n| {
            transport
                .buffer_per_direction
                .checked_div(transport.chunk_size as u64)
                .and_then(|chunks| chunks.checked_add(513))
                .and_then(|chunks| chunks.checked_mul(32))
                .and_then(|x| n.checked_add(x))
        })
        .and_then(|n| n.checked_add(8 * 1024))
        .ok_or_else(|| invalid("per-session metadata budget overflows".into()))?;
    if limits.max_sessions as u64 > usable / per_session {
        let need = (limits.max_sessions as u64)
            .checked_mul(per_session)
            .and_then(|n| n.checked_add(metadata - usable))
            .ok_or_else(|| invalid("total metadata budget overflows".into()))?;
        return Err(invalid(format!(
            "limits.max_sessions ({}) x per-session metadata (~{} KiB) exceeds the process metadata budget ({} KiB of transport.metadata_limit); raise transport.metadata_limit to at least {} MiB or lower limits.max_sessions to {}",
            limits.max_sessions,
            per_session / 1024,
            usable / 1024,
            need.div_ceil(1 << 20),
            usable / per_session
        )));
    }
    Ok(())
}

mod build;
mod describe;
mod endpoints;
mod peers;
mod reverse;
mod scalars;
mod sections;

#[cfg(test)]
mod spec_budget_tests;
#[cfg(test)]
mod spec_contracts3_tests;
#[cfg(test)]
mod spec_recovery_tests;
#[cfg(test)]
mod spec_tests;
#[cfg(test)]
mod tests;

pub use build::{load, load_with_options};
pub use describe::describe;
pub use scalars::{cidr_contains, parse_hostport};

/// Parses the `reverse` section: the database side of reverse mode.
fn invalid(msg: String) -> Error {
    Error::new(CODE_CONFIG_INVALID, msg)
}

fn check_keys(doc: &Yaml, section: &str, known: &[&str], unsupported: &[&str]) -> Result<()> {
    let fields = match doc {
        Yaml::Map(fields) => fields,
        Yaml::Null => return Ok(()),
        _ => {
            return Err(Error::new(
                CODE_CONFIG_READ,
                format!("{section} must be an object"),
            ))
        }
    };
    for (key, _) in fields {
        if known.contains(&key.as_str()) {
            continue;
        }
        if unsupported.contains(&key.as_str()) {
            return Err(Error::new(
                CODE_CONFIG_READ,
                format!("{section}.{key}: not supported by this build"),
            ));
        }
        let path = if section == "config" || section.starts_with("config.") {
            section.to_string()
        } else {
            format!("config.{section}")
        };
        return Err(Error::new(
            CODE_CONFIG_READ,
            format!("field {key:?} not found in {path}"),
        ));
    }
    Ok(())
}
