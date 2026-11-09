//! Loading a configuration file and assembling the node from its sections.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

use super::scalars::{parse_hostport, read_text_limited};
use super::yaml::{self, Yaml};
use super::{
    check_keys, peers, reverse, sections, Config, Node, Peer, Protocol, CODE_AUTH_CONFLICT,
    CODE_CONFIG_INVALID, CODE_CONFIG_READ, CODE_CONFIG_SECURITY, CODE_CREDENTIAL, CODE_LISTEN,
};

/// Reads and validates a configuration file.
pub fn load(path: &Path) -> Result<Config> {
    load_with_options(path, false)
}

pub fn load_with_options(path: &Path, offline: bool) -> Result<Config> {
    let path = absolute_path(path)?;
    let text = read_text_limited(&path, 4 << 20, CODE_CONFIG_READ).map_err(|e| {
        let cause = if e.message.contains("exceeds maximum size") {
            "config too large".to_string()
        } else {
            e.message
        };
        Error::new(
            CODE_CONFIG_READ,
            format!("failed to read config file {}: {cause}", path.display()),
        )
    })?;
    let doc = yaml::parse(&text).map_err(|e| Error::new(CODE_CONFIG_READ, e))?;
    yaml::reject_explicit_null(&doc).map_err(|e| Error::new(CODE_CONFIG_READ, e))?;
    if !matches!(doc, Yaml::Map(_)) {
        return Err(Error::new(
            CODE_CONFIG_READ,
            "configuration root is not a mapping",
        ));
    }
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    build(&doc, &path, dir, offline)
}

fn build(doc: &Yaml, path: &Path, dir: &Path, offline: bool) -> Result<Config> {
    let mut warnings = Vec::new();
    check_keys(
        doc,
        "config",
        &[
            "node",
            "http",
            "admin",
            "auth",
            "peers",
            "listeners",
            "targets",
            "limits",
            "transport",
            "reverse",
        ],
        &[],
    )?;

    let node_id = sections::node(doc)?;
    let mut http = sections::http(doc)?;
    for file in [&mut http.tls.cert_file, &mut http.tls.key_file] {
        if let Some(path) = file.take() {
            *file = Some(resolved_path(dir, &path.to_string_lossy()));
        }
    }
    let admin = sections::admin(doc)?;
    let transport = sections::transport(doc)?;
    let limits = sections::limits(doc)?;
    let auth_reload_interval = sections::auth_reload_interval(doc)?;
    let targets = sections::targets(doc)?;

    // Credentials first: a peer names its token either inline or by
    // reference into this table, so the table has to exist before peers
    // are read.
    let (inbound, outbound) = peers::credentials(doc, dir, offline)?;
    let acl_targets_checked = doc.get("targets").is_some();
    for identity in inbound.iter().filter(|_| acl_targets_checked) {
        for target in &identity.allowed_targets {
            if !targets
                .iter()
                .any(|configured| configured.id.as_str() == target.as_str())
            {
                return Err(Error::new(
                    CODE_CREDENTIAL,
                    format!("unknown ACL target {target:?}"),
                ));
            }
        }
    }
    let credentials_file_set = doc
        .get("auth")
        .and_then(|auth| auth.str_of("credentials_file"))
        .is_some_and(|path| !path.is_empty());
    if credentials_file_set
        && doc.seq_of("peers").is_some_and(|peers| {
            peers.iter().any(|peer| {
                ["token", "token_env", "token_file"]
                    .iter()
                    .any(|key| peer.get(key).is_some())
            })
        })
    {
        return Err(Error::new(
            CODE_AUTH_CONFLICT,
            "credentials_file cannot be mixed with direct outbound credentials",
        ));
    }
    for (i, a) in inbound.iter().enumerate() {
        if !a.enabled {
            continue;
        }
        for b in inbound.iter().skip(i + 1).filter(|b| b.enabled) {
            if a.tokens.iter().any(|token| b.tokens.contains(token)) {
                return Err(Error::new(
                    CODE_AUTH_CONFLICT,
                    format!(
                        "inbound peers {} and {} use the same token; every inbound identity needs its own token",
                        a.id, b.id
                    ),
                ));
            }
        }
    }
    let inbound_quota = inbound
        .iter()
        .filter(|identity| identity.enabled)
        .try_fold(0u64, |total, identity| {
            total.checked_add(identity.max_sessions as u64)
        })
        .ok_or_else(|| Error::new(CODE_CREDENTIAL, "inbound quota sum overflows"))?;
    let enabled_inbound = inbound.iter().filter(|identity| identity.enabled).count();
    if limits.max_sessions > 0 && enabled_inbound > 1 && inbound_quota > limits.max_sessions as u64
    {
        return Err(super::invalid(format!(
            "sum of inbound peer max_sessions ({inbound_quota}, an omitted quota counts as 200) exceeds limits.max_sessions ({}); set explicit per-peer quotas or raise the global limit",
            limits.max_sessions
        )));
    }
    let peers = peers::peers(
        doc,
        &node_id,
        &outbound,
        transport.protocol,
        limits.max_endpoints_per_peer,
        dir,
        offline,
    )?;
    if !transport.recovery_enabled {
        if let Some(peer) = peers
            .iter()
            .find(|peer| peer.recovery_enabled == Some(true))
        {
            return Err(Error::new(
                CODE_CONFIG_INVALID,
                format!(
                    "peer[{}].recovery.enabled cannot be true when transport.recovery.enabled is false",
                    peer.id
                ),
            ));
        }
    }
    let listeners = peers::listeners(doc, &peers)?;

    let mut credential_files = Vec::new();
    let mut token_files = Vec::new();
    collect_credential_paths(doc, dir, &mut credential_files, &mut token_files);

    if let Some(peer_docs) = doc.seq_of("peers") {
        for peer_doc in peer_docs {
            if peer_doc.str_of("mode").as_deref() == Some("reverse") {
                let reverse_tls_configured = peer_doc.get("tls").is_some_and(|tls| {
                    tls.get("verify").is_some()
                        || tls.str_of("ca_file").is_some_and(|path| !path.is_empty())
                        || tls.bool_of("allow_insecure_skip_verify").unwrap_or(false)
                });
                if reverse_tls_configured
                    || peer_doc.bool_of("allow_insecure_http").unwrap_or(false)
                {
                    let id = peer_doc.str_of("id").unwrap_or_default();
                    warnings.push(format!(
                        "peers[{id}]: tls and allow_insecure_http are ignored for a reverse peer; the tunnel's TLS is http.tls on this node and reverse.tls on the database side"
                    ));
                }
            }
            if let Some(endpoints) = peer_doc.seq_of("endpoints") {
                for endpoint in endpoints {
                    if let Some(id) = endpoint.str_of("id") {
                        warn_id(&mut warnings, "endpoint", &id);
                    }
                }
            }
        }
    }
    if let Some(endpoints) = doc
        .get("reverse")
        .and_then(|reverse| reverse.seq_of("endpoints"))
    {
        for endpoint in endpoints {
            if let Some(id) = endpoint.str_of("id") {
                warn_id(&mut warnings, "endpoint", &id);
            }
        }
    }
    for identity in &inbound {
        warn_id(&mut warnings, "inbound peer", &identity.id);
    }

    for identity in inbound.iter().filter(|identity| identity.enabled) {
        if identity.max_sessions > limits.max_sessions {
            warnings.push(format!(
                "inbound peer {} max_sessions ({}) exceeds limits.max_sessions ({}); the global limit applies",
                identity.id, identity.max_sessions, limits.max_sessions
            ));
        }
    }
    if !listeners.is_empty()
        && inbound.iter().any(|identity| identity.enabled)
        && inbound_quota >= limits.max_sessions as u64
    {
        warnings.push(format!(
            "inbound peers may hold all {} sessions (quota sum {}) that local listeners share on this bidirectional node; set inbound max_sessions below limits.max_sessions to keep room for local clients",
            limits.max_sessions, inbound_quota
        ));
    }
    for identity in &inbound {
        for token in &identity.tokens {
            if token.len() < 16 {
                warnings.push(format!(
                    "inbound peer {} uses a bearer token shorter than 16 bytes; use gen-config or 32 random bytes",
                    identity.id
                ));
            }
        }
    }
    for (id, token) in &outbound {
        if token.len() < 16 {
            warnings.push(format!(
                "outbound credential {id} uses a bearer token shorter than 16 bytes; use gen-config or 32 random bytes"
            ));
        }
    }
    for peer in &peers {
        if peer.token.len() < 16 {
            warnings.push(format!(
                "peer {} uses a bearer token shorter than 16 bytes; use gen-config or 32 random bytes",
                peer.id
            ));
        }
    }
    if transport.recovery_enabled {
        let grace = transport.recovery_grace;
        for peer in &peers {
            if peer.recovery_enabled == Some(false) || !single_recovery_carrier(peer) {
                continue;
            }
            let need = peer.failover.cooldown + transport.recovery_barrier_timeout;
            if grace <= need {
                warnings.push(format!(
                    "peers[{}]: transport.recovery.grace ({}) does not exceed failover.cooldown ({}) plus recovery.barrier_timeout ({}); with a forced transport and a single endpoint the carrier that failed stays cooled down until the recovery deadline, so recovery cannot succeed; raise recovery.grace, lower failover.cooldown, use protocol auto or add an endpoint",
                    peer.id,
                    super::scalars::spec_duration(grace),
                    super::scalars::spec_duration(peer.failover.cooldown),
                    super::scalars::spec_duration(transport.recovery_barrier_timeout),
                ));
            }
        }
    }
    for target in &targets {
        if target.allowed_cidrs.is_empty() {
            if let Ok((host, _)) = parse_hostport(&target.address) {
                if host.parse::<std::net::IpAddr>().is_err() {
                    warnings.push(format!(
                        "target {} uses hostname {:?} without allowed_cidrs; any address it resolves to will be dialed (DNS rebinding/SSRF risk); list the expected networks in allowed_cidrs",
                        target.id, host
                    ));
                }
            }
        }
    }
    let mut seen: Vec<(String, String)> = Vec::new();
    let mut check_listen = |addr: &str| -> std::result::Result<(), String> {
        super::scalars::validate_socket_address(addr, true)?;
        let (host, port) = super::scalars::spec_split_host_port(addr)?;
        let key = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        if port != "0" {
            for (existing, existing_host) in &seen {
                let existing_port = existing.rsplit(':').next().unwrap_or("");
                if existing_port == port && listen_hosts_overlap(&host, existing_host) {
                    return Err(format!(
                        "conflicting listen address {key} overlaps {existing}"
                    ));
                }
            }
        }
        seen.push((key, host));
        Ok(())
    };
    if http.enabled {
        check_listen(&http.listen).map_err(|e| Error::new(CODE_LISTEN, e))?;
        let (host, _) = parse_hostport(&http.listen).map_err(|e| Error::new(CODE_LISTEN, e))?;
        let tls_enabled = doc
            .get("http")
            .and_then(|h| h.get("tls"))
            .and_then(|t| t.bool_of("enabled"))
            .unwrap_or(false);
        if !tls_enabled && !is_loopback_host(&host) {
            let opted_in = doc
                .get("http")
                .and_then(|h| h.bool_of("allow_insecure_listen"))
                .unwrap_or(false);
            if !opted_in {
                return Err(Error::new(
                    CODE_CONFIG_SECURITY,
                    "non-loopback HTTP needs TLS or explicit insecure opt-in (http.allow_insecure_listen: true)",
                ));
            }
            warnings.push(format!(
                "http.listen {} accepts plaintext HTTP on a non-loopback address; bearer tokens and database traffic are not encrypted",
                http.listen
            ));
        }
    }
    if admin.enabled {
        check_listen(&admin.listen).map_err(|e| {
            Error::new(CODE_LISTEN, format!("admin.listen {:?}: {e}", admin.listen))
        })?;
        let (host, _) = parse_hostport(&admin.listen).map_err(|e| Error::new(CODE_LISTEN, e))?;
        let allow_remote = doc
            .get("admin")
            .and_then(|a| a.bool_of("allow_remote"))
            .unwrap_or(false);
        if !is_loopback_host(&host) {
            if !allow_remote {
                return Err(Error::new(
                    CODE_CONFIG_SECURITY,
                    "admin.listen must be a loopback address (the admin endpoint has no TLS or authentication); set admin.allow_remote: true to override",
                ));
            }
            warnings.push(format!(
                "admin.listen {} exposes /metrics and /readyz without TLS or authentication; restrict it with a firewall",
                admin.listen
            ));
        }
    }
    for listener in &listeners {
        check_listen(&listener.listen).map_err(|e| Error::new(CODE_LISTEN, e))?;
        if let Ok((host, _)) = parse_hostport(&listener.listen) {
            if !is_loopback_host(&host) {
                warnings.push(format!(
                    "listeners[{}].listen {} is not a loopback address: every host that can reach it gets a connection to peer {} target {} without authentication; bind 127.0.0.1 or firewall the port",
                    listener.id, listener.listen, listener.peer, listener.target
                ));
            }
        }
    }

    // reverse
    let reverse = reverse::parse_reverse(
        doc.get("reverse").unwrap_or(&Yaml::Null),
        dir,
        &node_id,
        limits.max_endpoints_per_peer,
        offline,
    )?;
    if !http.enabled && !reverse.enabled {
        let credentials_file_configured = doc
            .get("auth")
            .and_then(|auth| auth.str_of("credentials_file"))
            .is_some_and(|value| !value.is_empty());
        if !inbound.is_empty() || (credentials_file_configured && peers.is_empty()) {
            warnings.push(
                "auth inbound peers are configured but http.enabled is false; this node never accepts inbound sessions"
                    .into(),
            );
        }
        if !targets.is_empty() {
            warnings.push(
                "targets are configured but http.enabled is false; they are only used by the inbound HTTP server"
                    .into(),
            );
        }
        let tls_configured = doc
            .get("http")
            .and_then(|http| http.get("tls"))
            .is_some_and(|tls| {
                ["enabled", "cert_file", "key_file"]
                    .iter()
                    .any(|key| tls.get(key).is_some())
            });
        if tls_configured {
            warnings.push(
                "http.tls is configured but http.enabled is false; the TLS settings are ignored"
                    .into(),
            );
        }
    }
    if !reverse.enabled
        && doc.get("reverse").is_some_and(|section| {
            [
                "peer_node_id",
                "token_file",
                "token_env",
                "transport",
                "tunnels_per_endpoint",
                "endpoints",
                "reconnect",
            ]
            .iter()
            .any(|key| section.get(key).is_some())
        })
    {
        warnings.push(
            "reverse is configured but reverse.enabled is false; the settings are ignored".into(),
        );
    }
    if reverse.enabled && targets.is_empty() {
        warnings.push(
            "reverse.enabled is true but no targets are configured; sessions arriving over the tunnel have nothing to connect to".into(),
        );
    }
    if reverse.enabled && reverse.endpoints.is_empty() {
        return Err(Error::new(
            super::CODE_REVERSE,
            "reverse.endpoints cannot be empty when reverse.enabled is true",
        ));
    }
    // A reverse peer dials this node, so the tunnel has to arrive somewhere.
    if let Some(peer) = peers.iter().find(|p| p.reverse).filter(|_| !http.enabled) {
        return Err(Error::new(
            super::CODE_PEER_MODE,
            format!(
                "peers[{}]: a reverse peer needs http.enabled: true; its tunnel arrives on http.listen (/v1/reverse)",
                peer.id
            ),
        ));
    }
    // Checked after `reverse` is known: a node that only serves tunnels is a
    // perfectly valid egress even with no listener and no HTTP front door.
    if !http.enabled && listeners.is_empty() && peers.is_empty() && !reverse.enabled {
        warnings.push(
            "neither http.enabled nor any peers or listeners are configured; the node has nothing to do"
                .into(),
        );
    }

    warn_filesystem_sources(
        dir,
        &credential_files,
        &token_files,
        http.tls
            .enabled
            .then_some(http.tls.key_file.as_deref())
            .flatten(),
        offline,
        &mut warnings,
    );

    super::validate_metadata_budget(&transport, &limits, &http, &listeners, &peers, &reverse)?;
    check_server_certificate(&http, offline)?;

    warn_id(&mut warnings, "node", &node_id);
    for peer in &peers {
        warn_id(&mut warnings, "peer", &peer.id);
    }
    for listener in &listeners {
        warn_id(&mut warnings, "listener", &listener.id);
    }
    for target in &targets {
        warn_id(&mut warnings, "target", &target.id);
    }
    if reverse.enabled {
        warn_id(&mut warnings, "reverse peer node", &reverse.peer_node_id);
        if transport.recovery_enabled {
            let dur = super::scalars::spec_duration;
            let dial = std::time::Duration::from_millis(
                (transport.peer_dial_timeout.as_nanos() as f64 / 1e6).round() as u64,
            );
            let need = transport.peer_dial_timeout
                + reverse.min_backoff
                + transport.recovery_barrier_timeout;
            if transport.recovery_grace <= need {
                warnings.push(format!(
                    "reverse: transport.recovery.grace ({}) does not exceed peer_dial_timeout ({}) plus reverse.reconnect.min_backoff ({}) plus recovery.barrier_timeout ({}); a tunnel that fails its first reconnect cannot come back before sessions expire; raise recovery.grace or lower min_backoff",
                    dur(transport.recovery_grace),
                    dur(dial),
                    dur(reverse.min_backoff),
                    dur(transport.recovery_barrier_timeout)
                ));
            }
        }
    }

    Ok(Config {
        path: path.to_path_buf(),
        node: Node {
            id: node_id,
            instance_id: crate::util::random_hex(8).map_err(crate::util::random_error)?,
        },
        http,
        admin,
        peers,
        listeners,
        targets,
        inbound,
        warnings,
        auth_reload_interval,
        transport,
        limits,
        reverse,
    })
}

fn check_server_certificate(http: &super::Http, offline: bool) -> Result<()> {
    if offline || !http.enabled || !http.tls.enabled {
        return Ok(());
    }
    #[cfg(feature = "tls")]
    if let (Some(cert), Some(key)) = (&http.tls.cert_file, &http.tls.key_file) {
        let config = crate::net::tls::server_config(cert, key)
            .map_err(|e| Error::new(super::CODE_TLS, format!("http.tls certificate/key: {e}")))?;
        if !key_matches_certificate(std::sync::Arc::new(config)) {
            return Err(Error::new(
                super::CODE_TLS,
                "http.tls certificate/key: tls: private key does not match public key",
            ));
        }
    }
    Ok(())
}

#[cfg(feature = "tls")]
fn key_matches_certificate(server: std::sync::Arc<rustls::ServerConfig>) -> bool {
    use std::sync::Arc;
    // Accepts any chain: only the handshake signature check matters here,
    // and that verifies it against the end-entity certificate.
    let provider = crate::net::tls::crypto_provider();
    let verifier = Arc::new(crate::net::tls::AnyServerCert::new(provider.clone()));
    let Ok(builder) =
        rustls::ClientConfig::builder_with_provider(provider).with_safe_default_protocol_versions()
    else {
        return false;
    };
    let client_config = builder
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let Ok(name) = rustls::pki_types::ServerName::try_from("localhost") else {
        return false;
    };
    let Ok(mut client) = rustls::ClientConnection::new(Arc::new(client_config), name) else {
        return false;
    };
    let Ok(mut server) = rustls::ServerConnection::new(server) else {
        return false;
    };
    fn pump(from: &mut dyn FnMut(&mut Vec<u8>) -> bool, to: &mut dyn FnMut(&[u8]) -> bool) -> bool {
        let mut buf = Vec::new();
        if !from(&mut buf) {
            return false;
        }
        buf.is_empty() || to(&buf)
    }
    for _ in 0..32 {
        let ok = pump(
            &mut |buf| !client.wants_write() || client.write_tls(buf).is_ok(),
            &mut |mut data| {
                while !data.is_empty() {
                    if server.read_tls(&mut data).is_err() {
                        return false;
                    }
                }
                server.process_new_packets().is_ok()
            },
        ) && pump(
            &mut |buf| !server.wants_write() || server.write_tls(buf).is_ok(),
            &mut |mut data| {
                while !data.is_empty() {
                    if client.read_tls(&mut data).is_err() {
                        return false;
                    }
                }
                client.process_new_packets().is_ok()
            },
        );
        if !ok {
            return false;
        }
        if !client.is_handshaking() && !server.is_handshaking() {
            return true;
        }
    }
    false
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    std::env::current_dir()
        .map(|dir| dir.join(path))
        .map_err(|e| Error::new(CODE_CONFIG_READ, format!("cannot resolve config path: {e}")))
}

fn resolved_path(dir: &Path, value: &str) -> PathBuf {
    let path = Path::new(value);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        dir.join(path)
    }
}

fn collect_credential_paths(
    doc: &Yaml,
    dir: &Path,
    credential_files: &mut Vec<PathBuf>,
    token_files: &mut Vec<PathBuf>,
) {
    let add = |value: Option<String>, out: &mut Vec<PathBuf>| {
        if let Some(value) = value.filter(|value| !value.is_empty()) {
            out.push(resolved_path(dir, &value));
        }
    };
    if let Some(auth) = doc.get("auth") {
        add(auth.str_of("credentials_file"), credential_files);
        if let Some(credential_path) = auth
            .str_of("credentials_file")
            .filter(|value| !value.is_empty())
            .map(|value| resolved_path(dir, &value))
        {
            if let Ok(text) = read_text_limited(&credential_path, 1 << 20, CODE_CREDENTIAL) {
                if let Ok(credentials) = yaml::parse(&text) {
                    let credential_dir = credential_path.parent().unwrap_or(dir);
                    if let Some(inbound) = credentials.seq_of("inbound_peers") {
                        for item in inbound {
                            if item.bool_of("enabled") == Some(false) {
                                continue;
                            }
                            if let Some(files) = item.seq_of("token_files") {
                                for file in files {
                                    if let Some(file) = file.as_str().filter(|v| !v.is_empty()) {
                                        token_files.push(resolved_path(credential_dir, file));
                                    }
                                }
                            }
                        }
                    }
                    if let Some(outbound) = credentials.seq_of("outbound_peers") {
                        for item in outbound {
                            if let Some(file) = item.str_of("token_file") {
                                if !file.is_empty() {
                                    token_files.push(resolved_path(credential_dir, &file));
                                }
                            }
                        }
                    }
                }
            }
        }
        if let Some(inbound) = auth.seq_of("inbound_peers") {
            for item in inbound {
                if item.bool_of("enabled") == Some(false) {
                    continue;
                }
                if let Some(files) = item.seq_of("token_files") {
                    for file in files {
                        add(file.as_str().map(str::to_owned), token_files);
                    }
                }
            }
        }
    }
    if let Some(peers) = doc.seq_of("peers") {
        for peer in peers {
            add(peer.str_of("token_file"), token_files);
        }
    }
    if let Some(reverse) = doc.get("reverse") {
        if reverse.bool_of("enabled").unwrap_or(false) {
            add(reverse.str_of("token_file"), token_files);
        }
    }
}

pub(super) fn warn_filesystem_sources(
    config_dir: &Path,
    credential_files: &[PathBuf],
    token_files: &[PathBuf],
    tls_key: Option<&Path>,
    offline: bool,
    warnings: &mut Vec<String>,
) {
    let mut sandbox_files = credential_files.to_vec();
    sandbox_files.extend(token_files.iter().cloned());
    let config_dir_string = format!("{}/", config_dir.display());
    for path in sandbox_files {
        let path = path.to_string_lossy();
        for prefix in ["/home/", "/root/", "/run/user/", "/tmp/", "/var/tmp/"] {
            if path.starts_with(prefix) && !config_dir_string.starts_with(prefix) {
                let tree = prefix.trim_end_matches('/');
                warnings.push(format!(
                    "credential file {path} is under {tree} but the configuration is not; a service installed with 'dbbridge install' sees {tree} only when a file there is referenced at install time, so keep credential files next to the configuration"
                ));
                break;
            }
        }
    }
    if offline {
        return;
    }
    let mut protected = token_files.to_vec();
    if let Some(key) = tls_key {
        protected.push(if key.is_absolute() {
            key.to_path_buf()
        } else {
            config_dir.join(key)
        });
    }
    for path in protected {
        warn_insecure_permissions(&path, warnings);
    }
}

#[cfg(unix)]
pub(super) fn warn_insecure_permissions(path: &Path, warnings: &mut Vec<String>) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(info) = std::fs::metadata(path) else {
        return;
    };
    if !info.file_type().is_file() {
        return;
    }
    let mode = info.permissions().mode() & 0o777;
    if mode & 0o027 != 0 {
        warnings.push(format!(
            "secret file {} has mode {:04o}: other users can access it or its group can write it; use chmod 600 (or 640 with a service group)",
            path.display(), mode
        ));
    }
}

#[cfg(not(unix))]
pub(super) fn warn_insecure_permissions(_path: &Path, _warnings: &mut Vec<String>) {}

fn is_loopback_host(host: &str) -> bool {
    super::endpoints::is_loopback_host(host)
}

fn warn_id(warnings: &mut Vec<String>, kind: &str, id: &str) {
    let mut chars = id.chars();
    let valid = chars
        .next()
        .is_some_and(|first| first.is_ascii_alphanumeric())
        && id.len() <= 64
        && chars.all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'));
    if !valid {
        warnings.push(format!(
            "{kind} id {id:?} should match ^[A-Za-z0-9][A-Za-z0-9_.-]{{0,63}}$ (letters, digits, '.', '_', '-', at most 64 characters)"
        ));
    }
}

enum ListenHost {
    All,
    V4Any,
    Ips(Vec<std::net::IpAddr>),
    Name(String),
}

fn parse_listen_host(h: &str) -> ListenHost {
    let h = h.trim_matches(|c| c == '[' || c == ']');
    let h = h.strip_suffix('.').unwrap_or(h).to_ascii_lowercase();
    match h.as_str() {
        "" | "::" => return ListenHost::All,
        "localhost" => {
            return ListenHost::Ips(vec![
                std::net::Ipv4Addr::LOCALHOST.into(),
                std::net::Ipv6Addr::LOCALHOST.into(),
            ])
        }
        _ => {}
    }
    match h.parse::<std::net::IpAddr>() {
        Err(_) => ListenHost::Name(h),
        Ok(ip) => {
            let ip = match ip {
                std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, std::net::IpAddr::V4),
                v4 => v4,
            };
            if ip.is_unspecified() {
                if ip.is_ipv4() {
                    ListenHost::V4Any
                } else {
                    ListenHost::All
                }
            } else {
                ListenHost::Ips(vec![ip])
            }
        }
    }
}

pub(super) fn listen_hosts_overlap(a: &str, b: &str) -> bool {
    let (x, y) = (parse_listen_host(a), parse_listen_host(b));
    if matches!(x, ListenHost::All) || matches!(y, ListenHost::All) {
        return true;
    }
    let has_v4 = |l: &ListenHost| match l {
        ListenHost::V4Any | ListenHost::Name(_) => true,
        ListenHost::Ips(ips) => ips.iter().any(|ip| ip.is_ipv4()),
        ListenHost::All => true,
    };
    if (matches!(x, ListenHost::V4Any) && has_v4(&y))
        || (matches!(y, ListenHost::V4Any) && has_v4(&x))
    {
        return true;
    }
    match (&x, &y) {
        (ListenHost::Name(n), ListenHost::Name(m)) => n == m,
        (ListenHost::Name(_), _) | (_, ListenHost::Name(_)) => false,
        (ListenHost::Ips(i), ListenHost::Ips(j)) => i.iter().any(|ip| j.contains(ip)),
        _ => false,
    }
}

pub(crate) fn single_recovery_carrier(peer: &Peer) -> bool {
    matches!(peer.protocol, Protocol::Ws | Protocol::HttpSse)
        && (peer.endpoints.len() <= 1 || !peer.failover.enabled)
}
