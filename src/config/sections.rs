//! One function per top-level section. Each reads its own keys, applies its
//! own defaults and refuses its own nonsense, so `build` reads as a table of
//! contents instead of a five-hundred-line scroll.

use std::time::Duration;

use crate::error::{Error, Result};
use crate::wire::Mode;

use super::scalars::{dur_field, parse_cidr, parse_hostport, size_field};
use super::yaml::Yaml;
use super::{
    check_keys, invalid, Admin, Http, HttpTls, Limits, Protocol, Target, Transport,
    CODE_CONFIG_READ,
};

fn optional_string(doc: &Yaml, key: &str, path: &str) -> Result<Option<String>> {
    match doc.get(key) {
        None => Ok(None),
        Some(Yaml::Str(value)) if !super::yaml::is_float_scalar(value) => Ok(Some(value.clone())),
        Some(_) => Err(Error::new(
            CODE_CONFIG_READ,
            format!("{path} must be a string"),
        )),
    }
}

fn optional_bool(doc: &Yaml, key: &str, path: &str) -> Result<Option<bool>> {
    match doc.get(key) {
        None => Ok(None),
        Some(Yaml::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(Error::new(
            CODE_CONFIG_READ,
            format!("{path} must be a boolean"),
        )),
    }
}

pub(super) fn node(doc: &Yaml) -> Result<String> {
    let node_doc = doc.get("node").unwrap_or(&Yaml::Null);
    check_keys(node_doc, "node", &["id"], &["instance_id"])?;
    let node_id = optional_string(node_doc, "id", "node.id")?
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid("node.id is required".into()))?;
    if node_id.len() > 128 {
        return Err(invalid("node.id is longer than 128 bytes".into()));
    }
    Ok(node_id)
}

pub(super) fn http(doc: &Yaml) -> Result<Http> {
    let http_doc = doc.get("http").unwrap_or(&Yaml::Null);
    check_keys(
        http_doc,
        "http",
        &[
            "enabled",
            "listen",
            "allowed_transports",
            "tls",
            "allow_insecure_listen",
        ],
        &[],
    )?;
    let http_enabled = optional_bool(http_doc, "enabled", "http.enabled")?.unwrap_or(false);
    let http_listen = optional_string(http_doc, "listen", "http.listen")?
        .unwrap_or_else(|| "127.0.0.1:18080".to_string());
    let mut allowed = Vec::new();
    match http_doc.get("allowed_transports") {
        None => allowed = vec![Mode::Ws, Mode::HttpSse],
        Some(Yaml::Seq(list)) if list.is_empty() => {
            return Err(invalid("http.allowed_transports cannot be empty".into()))
        }
        Some(Yaml::Seq(list)) => {
            for item in list {
                let s = item
                    .as_str()
                    .filter(|value| !super::yaml::is_float_scalar(value))
                    .ok_or_else(|| {
                        Error::new(CODE_CONFIG_READ, "http.allowed_transports must be strings")
                    })?;
                let m = Mode::parse(s).ok_or_else(|| {
                    invalid(format!("http.allowed_transports: unknown mode {s:?}"))
                })?;
                if allowed.contains(&m) {
                    return Err(invalid(format!("http.allowed_transports: duplicate {s:?}")));
                }
                allowed.push(m);
            }
        }
        Some(_) => {
            return Err(Error::new(
                CODE_CONFIG_READ,
                "http.allowed_transports must be an array",
            ))
        }
    }
    let tls_doc = http_doc.get("tls").unwrap_or(&Yaml::Null);
    check_keys(
        tls_doc,
        "http.tls",
        &["enabled", "cert_file", "key_file"],
        &[],
    )?;
    let tls_enabled = optional_bool(tls_doc, "enabled", "http.tls.enabled")?.unwrap_or(false);
    let cert_file = optional_string(tls_doc, "cert_file", "http.tls.cert_file")?
        .filter(|path| !path.is_empty())
        .map(std::path::PathBuf::from);
    let key_file = optional_string(tls_doc, "key_file", "http.tls.key_file")?
        .filter(|path| !path.is_empty())
        .map(std::path::PathBuf::from);
    if tls_enabled && (cert_file.is_none() || key_file.is_none()) {
        return Err(Error::new(
            super::CODE_TLS,
            "http.tls.enabled requires cert_file and key_file",
        ));
    }
    if tls_enabled && !cfg!(feature = "tls") {
        return Err(Error::new(super::CODE_TLS, "TLS support not compiled in"));
    }
    Ok(Http {
        enabled: http_enabled,
        listen: http_listen,
        allowed_transports: allowed,
        tls: HttpTls {
            enabled: tls_enabled,
            cert_file,
            key_file,
        },
    })
}

pub(super) fn admin(doc: &Yaml) -> Result<Admin> {
    let admin_doc = doc.get("admin").unwrap_or(&Yaml::Null);
    check_keys(
        admin_doc,
        "admin",
        &["enabled", "listen", "allow_remote"],
        &[],
    )?;
    let admin = Admin {
        enabled: optional_bool(admin_doc, "enabled", "admin.enabled")?.unwrap_or(false),
        listen: optional_string(admin_doc, "listen", "admin.listen")?
            .unwrap_or_else(|| "127.0.0.1:18090".to_string()),
    };
    Ok(admin)
}

pub(super) fn auth_reload_interval(doc: &Yaml) -> Result<Duration> {
    let auth_doc = doc.get("auth").unwrap_or(&Yaml::Null);
    let interval = dur_field(auth_doc, "reload_interval", Duration::from_secs(5))
        .map_err(|e| Error::new(&e.code, format!("auth.reload_interval: {}", e.message)))?;
    let interval = if interval.is_zero() {
        Duration::from_secs(5)
    } else {
        interval
    };
    if interval < Duration::from_secs(1) {
        return Err(invalid(format!(
            "auth.reload_interval ({interval:?}) must be >= 1s"
        )));
    }
    Ok(interval)
}

pub(super) fn transport(doc: &Yaml) -> Result<Transport> {
    let t_doc = doc.get("transport").unwrap_or(&Yaml::Null);
    check_keys(
        t_doc,
        "transport",
        &[
            "protocol",
            "protocol_version",
            "h2_pool_size",
            "frame_size",
            "max_frame_size",
            "chunk_size",
            "buffer_per_direction",
            "global_buffer_limit",
            "suspended_buffer_limit",
            "up_window_bytes",
            "up_max_inflight_frames",
            "receipt_limit_per_session",
            "heartbeat",
            "failure_detect_timeout",
            "ack_batch_bytes",
            "ack_max_delay",
            "up_ack_max_delay",
            "control_request_timeout",
            "create_retry_timeout",
            "dial_timeout",
            "peer_dial_timeout",
            "unattached_timeout",
            "backpressure_timeout",
            "sse_write_idle_timeout",
            "shutdown_timeout",
            "ws",
            "recovery",
            "idempotency_tombstone_ttl",
            "codec_buffer_limit",
            "metadata_limit",
            "sql_replay",
            "user_agent",
            "use_environment_proxy",
            "up_request_timeout",
            "socket_write_timeout",
        ],
        &[],
    )?;
    let mut transport = Transport::default();
    if let Some(protocol_version) =
        optional_string(t_doc, "protocol_version", "transport.protocol_version")?
    {
        if protocol_version != crate::wire::PROTOCOL_VERSION {
            return Err(invalid(format!(
                "protocol_version must be {:?}, got {:?}",
                crate::wire::PROTOCOL_VERSION,
                protocol_version
            )));
        }
    }
    if let Some(p) = optional_string(t_doc, "protocol", "transport.protocol")? {
        transport.protocol = Protocol::parse(&p)
            .filter(|parsed| *parsed != Protocol::LongPoll)
            .ok_or_else(|| {
                invalid(format!(
                    "invalid transport.protocol: {p:?} (must be auto, ws, or http-sse)"
                ))
            })?;
    }
    if let Some(value) = t_doc.get("h2_pool_size") {
        if !value.is_null() {
            let size = match value {
                Yaml::Int(value) => *value,
                other => {
                    return Err(Error::new(
                        CODE_CONFIG_READ,
                        format!("transport.h2_pool_size: expected an integer, got {other}"),
                    ))
                }
            };
            if !(1..=64).contains(&size) {
                return Err(invalid(
                    "transport.h2_pool_size must be between 1 and 64".into(),
                ));
            }
            transport.h2_pool_size = size as u32;
        }
    }
    transport.frame_size = size_field(t_doc, "frame_size", transport.frame_size as u64)? as usize;
    transport.max_frame_size =
        size_field(t_doc, "max_frame_size", transport.max_frame_size as u64)? as usize;
    transport.chunk_size = size_field(t_doc, "chunk_size", transport.chunk_size as u64)? as usize;
    transport.buffer_per_direction = size_field(
        t_doc,
        "buffer_per_direction",
        transport.buffer_per_direction,
    )?;
    transport.global_buffer_limit =
        size_field(t_doc, "global_buffer_limit", transport.global_buffer_limit)?;
    transport.suspended_buffer_limit = size_field(
        t_doc,
        "suspended_buffer_limit",
        transport.suspended_buffer_limit,
    )?;
    transport.up_window_bytes = size_field(t_doc, "up_window_bytes", transport.up_window_bytes)?;
    transport.up_max_inflight_frames = t_doc
        .i64_of("up_max_inflight_frames")
        .map(|v| v as u32)
        .unwrap_or(transport.up_max_inflight_frames);
    transport.receipt_limit_per_session = t_doc
        .i64_of("receipt_limit_per_session")
        .map(|v| v as u32)
        .unwrap_or(0);
    transport.heartbeat = dur_field(t_doc, "heartbeat", transport.heartbeat)?;
    transport.failure_detect_timeout = dur_field(
        t_doc,
        "failure_detect_timeout",
        transport.failure_detect_timeout,
    )?;
    if t_doc.get("failure_detect_timeout").is_none() {
        if let Some(minimum) = transport.heartbeat.checked_mul(3) {
            transport.failure_detect_timeout = transport.failure_detect_timeout.max(minimum);
        }
    }
    transport.ack_batch_bytes = size_field(t_doc, "ack_batch_bytes", transport.ack_batch_bytes)?;
    transport.ack_max_delay = dur_field(t_doc, "ack_max_delay", transport.ack_max_delay)?;
    transport.up_ack_max_delay = dur_field(t_doc, "up_ack_max_delay", transport.up_ack_max_delay)?;
    transport.control_request_timeout = dur_field(
        t_doc,
        "control_request_timeout",
        transport.control_request_timeout,
    )?;
    transport.create_retry_timeout = dur_field(
        t_doc,
        "create_retry_timeout",
        transport.create_retry_timeout,
    )?;
    transport.dial_timeout = dur_field(t_doc, "dial_timeout", transport.dial_timeout)?;
    transport.peer_dial_timeout = dur_field(t_doc, "peer_dial_timeout", transport.dial_timeout)?;
    transport.unattached_timeout =
        dur_field(t_doc, "unattached_timeout", transport.unattached_timeout)?;
    transport.backpressure_timeout = dur_field(
        t_doc,
        "backpressure_timeout",
        transport.backpressure_timeout,
    )?;
    transport.sse_write_idle_timeout = dur_field(
        t_doc,
        "sse_write_idle_timeout",
        transport.sse_write_idle_timeout,
    )?;
    transport.shutdown_timeout = dur_field(t_doc, "shutdown_timeout", transport.shutdown_timeout)?;
    let ws_doc = t_doc.get("ws").unwrap_or(&Yaml::Null);
    check_keys(
        ws_doc,
        "transport.ws",
        &["handshake_timeout", "write_idle_timeout"],
        &[],
    )?;
    transport.ws_handshake_timeout =
        dur_field(ws_doc, "handshake_timeout", transport.ws_handshake_timeout)?;
    transport.ws_write_idle_timeout = dur_field(
        ws_doc,
        "write_idle_timeout",
        transport.ws_write_idle_timeout,
    )?;
    if transport.ws_write_idle_timeout.is_zero() {
        return Err(invalid(format!(
            "transport.ws.write_idle_timeout ({}) must be > 0",
            super::scalars::spec_duration(transport.ws_write_idle_timeout)
        )));
    }
    transport.up_request_timeout =
        dur_field(t_doc, "up_request_timeout", transport.up_request_timeout)?;
    if transport.up_request_timeout.is_zero() {
        return Err(invalid(format!(
            "transport.up_request_timeout ({}) must be > 0",
            super::scalars::spec_duration(transport.up_request_timeout)
        )));
    }
    transport.socket_write_timeout = dur_field(
        t_doc,
        "socket_write_timeout",
        transport.socket_write_timeout,
    )?;
    if transport.socket_write_timeout.is_zero() {
        return Err(invalid(format!(
            "transport.socket_write_timeout ({}) must be > 0",
            super::scalars::spec_duration(transport.socket_write_timeout)
        )));
    }
    match t_doc.get("use_environment_proxy") {
        None => {}
        Some(Yaml::Bool(v)) => transport.use_environment_proxy = *v,
        Some(_) => {
            return Err(Error::new(
                CODE_CONFIG_READ,
                "config.transport.use_environment_proxy must be a boolean",
            ))
        }
    }
    if let Some(ua) = optional_string(t_doc, "user_agent", "transport.user_agent")? {
        if !ua.is_empty() {
            valid_user_agent(&ua).map_err(invalid)?;
            transport.user_agent = ua;
        }
    }

    let rec_doc = t_doc.get("recovery").unwrap_or(&Yaml::Null);
    check_keys(
        rec_doc,
        "transport.recovery",
        &["enabled", "grace", "barrier_timeout"],
        &[],
    )?;
    let recovery_requested = match rec_doc.get("enabled") {
        None => transport.recovery_enabled,
        Some(Yaml::Bool(v)) => *v,
        Some(_) => return Err(invalid("transport.recovery.enabled must be boolean".into())),
    };
    transport.recovery_enabled = recovery_requested;
    transport.recovery_grace = dur_field(rec_doc, "grace", transport.recovery_grace)?;
    transport.recovery_barrier_timeout = dur_field(
        rec_doc,
        "barrier_timeout",
        transport.recovery_barrier_timeout,
    )?;
    if rec_doc.get("barrier_timeout").is_none() && !transport.recovery_grace.is_zero() {
        transport.recovery_barrier_timeout = Duration::from_millis(1).max(
            transport
                .recovery_barrier_timeout
                .min(transport.recovery_grace / 2),
        );
    }
    if transport.recovery_enabled {
        let dur = super::scalars::spec_duration;
        if transport.recovery_grace.is_zero() {
            return Err(invalid(format!(
                "transport.recovery.grace ({}) must be > 0",
                dur(transport.recovery_grace)
            )));
        }
        if transport.recovery_barrier_timeout.is_zero() {
            return Err(invalid(format!(
                "transport.recovery.barrier_timeout ({}) must be > 0",
                dur(transport.recovery_barrier_timeout)
            )));
        }
        if transport.recovery_barrier_timeout >= transport.recovery_grace {
            let note = |key: &str, d: Duration| spec_value_note(rec_doc, key, dur(d));
            return Err(invalid(format!(
                "recovery.barrier_timeout ({}) must be < recovery.grace ({})",
                note("barrier_timeout", transport.recovery_barrier_timeout),
                note("grace", transport.recovery_grace)
            )));
        }
    }
    transport.idempotency_tombstone_ttl = dur_field(
        t_doc,
        "idempotency_tombstone_ttl",
        transport.idempotency_tombstone_ttl,
    )?;
    transport.codec_buffer_limit =
        size_field(t_doc, "codec_buffer_limit", transport.codec_buffer_limit)?;
    transport.metadata_limit = size_field(t_doc, "metadata_limit", transport.metadata_limit)?;
    if optional_bool(t_doc, "sql_replay", "transport.sql_replay")?.unwrap_or(false) {
        return Err(invalid(
            "sql_replay is not supported and must be false".into(),
        ));
    }
    if t_doc.get("up_window_bytes").is_none() {
        transport.up_window_bytes = transport
            .up_window_bytes
            .min(transport.buffer_per_direction);
    }
    if t_doc.get("ack_batch_bytes").is_none() {
        transport.ack_batch_bytes = transport
            .ack_batch_bytes
            .min(transport.buffer_per_direction / 4)
            .max(1);
    }
    if t_doc.get("max_frame_size").is_none() {
        transport.max_frame_size = transport
            .max_frame_size
            .min(transport.up_window_bytes.min(usize::MAX as u64) as usize)
            .max(1);
    }
    if t_doc.get("frame_size").is_none() {
        transport.frame_size = transport.frame_size.min(transport.max_frame_size);
    }
    if t_doc.get("suspended_buffer_limit").is_none() {
        transport.suspended_buffer_limit =
            (transport.global_buffer_limit / 4).clamp(1, 64 * 1024 * 1024);
    }
    if transport.idempotency_tombstone_ttl < std::time::Duration::from_secs(600) {
        return Err(invalid(
            "transport.idempotency_tombstone_ttl must be >= 10m".into(),
        ));
    }

    let dur = super::scalars::spec_duration;
    let size_note = |key: &str, v: u64| spec_value_note(t_doc, key, v.to_string());
    let dur_note = |key: &str, d: Duration| spec_value_note(t_doc, key, dur(d));
    if transport.frame_size == 0 {
        return Err(invalid(format!(
            "transport.frame_size ({}) must be > 0",
            transport.frame_size
        )));
    }
    if transport.max_frame_size == 0 {
        return Err(invalid(format!(
            "transport.max_frame_size ({}) must be > 0",
            transport.max_frame_size
        )));
    }
    if transport.heartbeat.is_zero() {
        return Err(invalid(format!(
            "transport.heartbeat ({}) must be > 0",
            dur(transport.heartbeat)
        )));
    }
    if transport.frame_size > transport.max_frame_size {
        return Err(invalid(format!(
            "frame_size ({}) must be <= max_frame_size ({})",
            size_note("frame_size", transport.frame_size as u64),
            size_note("max_frame_size", transport.max_frame_size as u64)
        )));
    }
    if transport.max_frame_size > 1024 * 1024 {
        return Err(invalid(format!(
            "max_frame_size ({}) must be <= 1 MiB",
            transport.max_frame_size
        )));
    }
    if transport.max_frame_size as u64 > transport.up_window_bytes {
        return Err(invalid(format!(
            "max_frame_size ({}) must be <= up_window_bytes ({})",
            size_note("max_frame_size", transport.max_frame_size as u64),
            size_note("up_window_bytes", transport.up_window_bytes)
        )));
    }
    if transport.up_window_bytes > transport.buffer_per_direction {
        return Err(invalid(format!(
            "up_window_bytes ({}) must be <= buffer_per_direction ({})",
            size_note("up_window_bytes", transport.up_window_bytes),
            size_note("buffer_per_direction", transport.buffer_per_direction)
        )));
    }
    if transport.ack_batch_bytes >= transport.buffer_per_direction {
        return Err(invalid(format!(
            "ack_batch_bytes ({}) must be < buffer_per_direction ({})",
            size_note("ack_batch_bytes", transport.ack_batch_bytes),
            size_note("buffer_per_direction", transport.buffer_per_direction)
        )));
    }
    if transport.suspended_buffer_limit >= transport.global_buffer_limit {
        return Err(invalid(format!(
            "suspended_buffer_limit ({}) must be < global_buffer_limit ({})",
            size_note("suspended_buffer_limit", transport.suspended_buffer_limit),
            size_note("global_buffer_limit", transport.global_buffer_limit)
        )));
    }
    let failure_ok = transport
        .heartbeat
        .checked_mul(3)
        .is_some_and(|minimum| transport.failure_detect_timeout >= minimum);
    if !failure_ok {
        return Err(invalid(format!(
            "failure_detect_timeout ({}) must be >= 3 * heartbeat ({})",
            dur_note("failure_detect_timeout", transport.failure_detect_timeout),
            dur_note("heartbeat", transport.heartbeat)
        )));
    }
    if transport.dial_timeout.is_zero() {
        return Err(invalid("transport.dial_timeout must be > 0".into()));
    }
    if transport.peer_dial_timeout.is_zero() {
        return Err(invalid("transport.peer_dial_timeout must be > 0".into()));
    }
    if transport.frame_size > transport.max_frame_size {
        return Err(invalid(
            "transport.frame_size must not exceed transport.max_frame_size".into(),
        ));
    }
    if transport.max_frame_size > crate::wire::MAX_FRAME_PAYLOAD {
        return Err(invalid(format!(
            "transport.max_frame_size must not exceed {} bytes",
            crate::wire::MAX_FRAME_PAYLOAD
        )));
    }
    if transport.up_max_inflight_frames == 0 {
        transport.up_max_inflight_frames = 8;
    }
    let min_receipts = 2 * transport.up_max_inflight_frames + 8;
    if transport.receipt_limit_per_session == 0 {
        transport.receipt_limit_per_session = 64.max(min_receipts);
    } else if transport.receipt_limit_per_session < min_receipts {
        return Err(invalid(
            "transport.receipt_limit_per_session must be >= 2 * up_max_inflight_frames + 8".into(),
        ));
    }
    if transport.max_frame_size as u64 > transport.up_window_bytes {
        return Err(invalid(
            "transport.max_frame_size must not exceed transport.up_window_bytes".into(),
        ));
    }
    if transport.max_frame_size as u64 > transport.buffer_per_direction {
        return Err(invalid(
            "transport.max_frame_size must not exceed transport.buffer_per_direction".into(),
        ));
    }
    if transport.up_window_bytes > transport.buffer_per_direction {
        return Err(invalid(
            "transport.up_window_bytes must not exceed transport.buffer_per_direction".into(),
        ));
    }
    if transport.ack_batch_bytes == 0 || transport.ack_batch_bytes >= transport.buffer_per_direction
    {
        return Err(invalid(
            "transport.ack_batch_bytes must be > 0 and < transport.buffer_per_direction".into(),
        ));
    }
    if transport.global_buffer_limit == 0 || transport.suspended_buffer_limit == 0 {
        return Err(invalid("transport buffer limits must be > 0".into()));
    }
    if transport.suspended_buffer_limit >= transport.global_buffer_limit {
        return Err(invalid(
            "transport.suspended_buffer_limit must be < transport.global_buffer_limit".into(),
        ));
    }
    Ok(transport)
}

pub(super) fn targets(doc: &Yaml) -> Result<Vec<Target>> {
    let mut targets = Vec::new();
    let fields = match doc.get("targets") {
        None => return Ok(targets),
        Some(Yaml::Map(fields)) => fields,
        Some(_) => return Err(Error::new(CODE_CONFIG_READ, "targets must be an object")),
    };
    for (id, body) in fields {
        if id.is_empty() {
            return Err(invalid("targets: target name cannot be empty".into()));
        }
        check_keys(
            body,
            &format!("targets.{id}"),
            &["network", "address", "allowed_cidrs"],
            &[],
        )?;
        let address = optional_string(body, "address", &format!("targets.{id}.address"))?
            .filter(|s| !s.is_empty())
            .ok_or_else(|| invalid(format!("targets.{id}.address is required")))?;
        super::scalars::validate_socket_address(&address, false)
            .map_err(|e| invalid(format!("target[{id}]: {e}")))?;
        let (host, port) =
            parse_hostport(&address).map_err(|e| invalid(format!("target[{id}]: {e}")))?;
        if !address.starts_with('[') && host.contains(':') {
            return Err(invalid(format!(
                "targets.{id}: IPv6 target addresses must be bracketed"
            )));
        }
        if port == 0 {
            return Err(invalid(format!(
                "targets.{id}: TCP port must be numeric and in range"
            )));
        }
        if host.is_empty() {
            return Err(invalid(format!("targets.{id}: target host is required")));
        }
        if address.trim() != address
            || host.trim() != host
            || host.chars().any(|c| "/\\?#@ \t\r\n".contains(c))
        {
            return Err(invalid(format!("targets.{id}: invalid TCP host")));
        }
        let mut allowed_cidrs = Vec::new();
        match body.get("allowed_cidrs") {
            None => {}
            Some(Yaml::Seq(list)) => {
                for item in list {
                    let s = item
                        .as_str()
                        .filter(|value| !super::yaml::is_float_scalar(value))
                        .ok_or_else(|| {
                            Error::new(
                                CODE_CONFIG_READ,
                                format!("targets.{id}.allowed_cidrs must contain strings"),
                            )
                        })?;
                    let (network, prefix) = parse_cidr(s.trim()).map_err(|_| {
                        invalid(format!(
                            "invalid CIDR in targets[{id}].allowed_cidrs {s:?}: invalid CIDR address: {}",
                            s.trim()
                        ))
                    })?;
                    allowed_cidrs.push(format!("{network}/{prefix}"));
                }
            }
            Some(_) => {
                return Err(Error::new(
                    CODE_CONFIG_READ,
                    format!("targets.{id}.allowed_cidrs must be an array"),
                ))
            }
        }
        let network =
            optional_string(body, "network", &format!("targets.{id}.network"))?.unwrap_or_default();
        if !matches!(network.as_str(), "" | "tcp" | "tcp4" | "tcp6") {
            return Err(invalid(format!(
                "targets.{id}.network must be tcp, tcp4 or tcp6"
            )));
        }
        targets.push(Target {
            id: id.clone(),
            network: if network.is_empty() {
                "tcp".to_string()
            } else {
                network
            },
            address,
            allowed_cidrs,
        });
    }
    Ok(targets)
}

pub(super) fn limits(doc: &Yaml) -> Result<Limits> {
    let limits_doc = doc.get("limits").unwrap_or(&Yaml::Null);
    check_keys(
        limits_doc,
        "limits",
        &["max_sessions", "max_endpoints_per_peer"],
        &[],
    )?;
    let positive = |key: &str, default: u32| -> Result<u32> {
        let Some(_) = limits_doc.get(key) else {
            return Ok(default);
        };
        let value = limits_doc.i64_of(key).ok_or_else(|| {
            Error::new(
                CODE_CONFIG_READ,
                format!("config.limits.{key} must be an integer"),
            )
        })?;
        if value <= 0 || value > u32::MAX as i64 {
            return Err(Error::new(
                CODE_CONFIG_READ,
                format!("config.limits.{key} must be a positive integer"),
            ));
        }
        Ok(value as u32)
    };
    Ok(Limits {
        max_sessions: positive("max_sessions", 200)?,
        max_endpoints_per_peer: positive("max_endpoints_per_peer", 16)?,
    })
}

pub(super) fn valid_user_agent(ua: &str) -> std::result::Result<(), String> {
    if ua.len() > 256 {
        return Err("transport.user_agent is longer than 256 bytes".into());
    }
    for (i, c) in ua.bytes().enumerate() {
        if !(0x20..=0x7e).contains(&c) {
            return Err(format!(
                "transport.user_agent may contain only printable ASCII characters (byte {i} is 0x{c:02x})"
            ));
        }
    }
    if ua.starts_with(' ') || ua.ends_with(' ') {
        return Err("transport.user_agent must not start or end with a space".into());
    }
    Ok(())
}

fn spec_value_note(doc: &Yaml, key: &str, value: String) -> String {
    let unset = match doc.get(key) {
        None | Some(Yaml::Null) => true,
        Some(Yaml::Str(text)) => text.trim().is_empty(),
        Some(_) => false,
    };
    if unset {
        format!("{value}, default")
    } else {
        value
    }
}
