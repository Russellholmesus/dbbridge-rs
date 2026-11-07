//! Reverse mode's own section, plus the two helpers it shares with the peer
//! sections: inbound identities and token resolution.

use std::path::Path;
use std::time::Duration;

use crate::error::{Error, Result};

use super::scalars::{dur_field, read_text_limited};
use super::yaml::Yaml;
use super::{
    check_keys, invalid, ClientTls, InboundPeer, Protocol, Reverse, CODE_CONFIG_INVALID,
    CODE_CREDENTIAL, CODE_REVERSE,
};

pub(super) fn parse_reverse(
    doc: &Yaml,
    dir: &Path,
    node_id: &str,
    max_endpoints_per_peer: u32,
    offline: bool,
) -> Result<Reverse> {
    check_keys(
        doc,
        "reverse",
        &[
            "enabled",
            "peer_node_id",
            "token_file",
            "token_env",
            "transport",
            "tunnels_per_endpoint",
            "endpoints",
            "reconnect",
            "tls",
            "allow_insecure_http",
        ],
        &[],
    )?;
    let mut r = Reverse {
        enabled: doc.bool_of("enabled").unwrap_or(false),
        ..Reverse::default()
    };
    if !r.enabled {
        return Ok(r);
    }
    let fail = |m: String| Error::new(CODE_REVERSE, m);
    r.peer_node_id = doc.str_of("peer_node_id").unwrap_or_default();
    if r.peer_node_id.is_empty() {
        return Err(fail(
            "reverse.peer_node_id is required when reverse.enabled is true".into(),
        ));
    }
    if r.peer_node_id == node_id {
        return Err(fail(
            "reverse.peer_node_id must differ from this node's node.id".into(),
        ));
    }

    r.transport = match doc.str_of("transport").unwrap_or_default().as_str() {
        "" | "auto" => Protocol::Auto,
        "ws" => Protocol::Ws,
        "http-sse" => Protocol::HttpSse,
        "long-poll" => Protocol::LongPoll,
        other => {
            return Err(fail(format!(
                "invalid reverse.transport: {other:?} (must be auto, ws, http-sse or long-poll)"
            )))
        }
    };

    let tunnels_per_endpoint = match doc.get("tunnels_per_endpoint") {
        None | Some(Yaml::Null) => 2,
        Some(Yaml::Int(n)) if *n > 0 => *n,
        Some(_) => {
            return Err(Error::new(
                super::CODE_CONFIG_READ,
                "config.reverse.tunnels_per_endpoint must be a positive integer",
            ))
        }
    };
    if !(1..=16).contains(&tunnels_per_endpoint) {
        return Err(fail(format!(
            "reverse.tunnels_per_endpoint must be 1-16, got {tunnels_per_endpoint}"
        )));
    }
    r.tunnels_per_endpoint = tunnels_per_endpoint as u32;

    let declared = doc.seq_of("endpoints").unwrap_or(&[]);
    if declared.is_empty() {
        return Err(fail(
            "reverse.endpoints cannot be empty when reverse.enabled is true".into(),
        ));
    }
    if declared.len() > max_endpoints_per_peer as usize {
        return Err(fail(format!(
            "reverse.endpoints length ({}) exceeds max_endpoints_per_peer ({max_endpoints_per_peer})",
            declared.len()
        )));
    }
    r.endpoints = super::endpoints::normalize_endpoints(
        declared,
        &super::endpoints::Owner {
            prefix: "reverse",
            name: "reverse",
            insecure_hint: "set reverse.allow_insecure_http: true",
            code: CODE_REVERSE,
        },
        doc.bool_of("allow_insecure_http").unwrap_or(false),
    )?;
    r.endpoints.sort_by_key(|e| e.priority);

    let tls_doc = doc.get("tls").unwrap_or(&Yaml::Null);
    check_keys(
        tls_doc,
        "reverse.tls",
        &["verify", "ca_file", "allow_insecure_skip_verify"],
        &[],
    )?;
    r.tls = ClientTls {
        verify: tls_doc.bool_of("verify").unwrap_or(true),
        ca_file: tls_doc.str_of("ca_file").map(|p| dir.join(p)),
        allow_insecure_skip_verify: tls_doc
            .bool_of("allow_insecure_skip_verify")
            .unwrap_or(false),
    };
    validate_client_tls(&r.tls, &r.endpoints, "reverse", offline).map_err(|e| {
        if e.code == CODE_CONFIG_INVALID {
            fail(e.message)
        } else {
            e
        }
    })?;

    let rc = doc.get("reconnect").unwrap_or(&Yaml::Null);
    check_keys(
        rc,
        "reverse.reconnect",
        &["min_backoff", "max_backoff"],
        &[],
    )?;
    let spec_duration_error = |key: &str, e: Error| {
        if e.code == super::CODE_CONFIG_READ {
            return e;
        }
        let detail = e
            .message
            .strip_prefix(&format!("{key}: "))
            .unwrap_or(&e.message)
            .to_string();
        let detail = if detail.starts_with("invalid duration")
            || detail.starts_with("missing unit")
            || detail.starts_with("unknown unit")
        {
            format!("time: {detail}")
        } else {
            detail
        };
        fail(format!("invalid reverse.reconnect.{key}: {detail}"))
    };
    r.min_backoff = dur_field(rc, "min_backoff", r.min_backoff)
        .map_err(|e| spec_duration_error("min_backoff", e))?;
    let max_backoff_is_unset = match rc.get("max_backoff") {
        None | Some(Yaml::Null) => true,
        Some(value) => value.as_str().is_some_and(|text| text.trim().is_empty()),
    };
    if max_backoff_is_unset {
        // An unset max_backoff never falls below an explicit min_backoff.
        r.max_backoff = r.min_backoff.max(Duration::from_secs(30));
    } else {
        r.max_backoff = dur_field(rc, "max_backoff", r.max_backoff)
            .map_err(|e| spec_duration_error("max_backoff", e))?;
    }
    if r.min_backoff.is_zero() {
        return Err(fail("reverse.reconnect.min_backoff must be > 0".into()));
    }
    let dur = super::scalars::spec_duration;
    if r.max_backoff < r.min_backoff {
        return Err(fail(format!(
            "reverse.reconnect.max_backoff ({}) must be >= min_backoff ({})",
            dur(r.max_backoff),
            dur(r.min_backoff)
        )));
    }
    let max_reverse_backoff = Duration::from_secs(10 * 60);
    if r.max_backoff > max_reverse_backoff {
        return Err(fail(format!(
            "reverse.reconnect.max_backoff ({}) must be <= {}",
            dur(r.max_backoff),
            dur(max_reverse_backoff)
        )));
    }

    let token_env = doc.str_of("token_env").unwrap_or_default();
    let token_file = doc.str_of("token_file").unwrap_or_default();
    if token_env.is_empty() && token_file.is_empty() {
        return Err(fail(
            "reverse needs a token: set reverse.token_file or reverse.token_env".into(),
        ));
    }
    if !token_env.is_empty() && !token_file.is_empty() {
        return Err(fail(format!(
            "reverse: ambiguous credential source: both token_file {token_file} and token_env {token_env} are set"
        )));
    }
    r.token = read_token(doc, dir, CODE_CREDENTIAL, offline).map_err(|e| {
        Error::new(
            CODE_CREDENTIAL,
            format!("reverse credential: {}", e.message),
        )
    })?;
    Ok(r)
}

pub(super) fn parse_inbound(item: &Yaml, dir: &Path, offline: bool) -> Result<InboundPeer> {
    check_keys(
        item,
        "auth.inbound_peers[]",
        &[
            "id",
            "enabled",
            "token_files",
            "token_envs",
            "allowed_targets",
            "max_sessions",
        ],
        &[],
    )?;
    let id = item
        .str_of("id")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::new(CODE_CREDENTIAL, "auth.inbound_peers[].id is required"))?;
    let enabled = item.bool_of("enabled").unwrap_or(true);
    let (token_files, token_envs) = inbound_token_sources(item, &id)?;
    let mut allowed_targets = Vec::new();
    let target_list = item.seq_of("allowed_targets").ok_or_else(|| {
        Error::new(
            CODE_CREDENTIAL,
            format!("auth.inbound_peers[{id}].allowed_targets must be a list"),
        )
    })?;
    for t in target_list {
        let target = t.as_str().ok_or_else(|| {
            Error::new(
                CODE_CREDENTIAL,
                format!("auth.inbound_peers[{id}].allowed_targets entries must be strings"),
            )
        })?;
        if allowed_targets.iter().any(|existing| existing == target) {
            return Err(Error::new(
                CODE_CREDENTIAL,
                format!(
                    "auth.inbound_peers[{id}].allowed_targets contains duplicate target {target:?}"
                ),
            ));
        }
        allowed_targets.push(target.to_string());
    }
    if allowed_targets.is_empty() {
        return Err(Error::new(
            CODE_CREDENTIAL,
            format!("auth.inbound_peers[{id}].allowed_targets is required"),
        ));
    }
    // Disabled identities retain their ACL for validation/documentation, but
    // credential sources are deliberately not opened or resolved.
    let tokens = if enabled && !offline {
        read_inbound_tokens(&token_files, &token_envs, dir, &id)?
    } else {
        Vec::new()
    };
    if enabled && token_files.is_empty() && token_envs.is_empty() {
        return Err(Error::new(
            CODE_CREDENTIAL,
            format!("auth.inbound_peers[{id}] needs token_files or token_envs"),
        ));
    }
    let max_sessions = item.i64_of("max_sessions").unwrap_or(200);
    if max_sessions <= 0 || max_sessions > u32::MAX as i64 {
        return Err(Error::new(
            CODE_CREDENTIAL,
            format!("auth.inbound_peers[{id}].max_sessions must be a positive integer"),
        ));
    }
    Ok(InboundPeer {
        id,
        enabled,
        tokens,
        allowed_targets,
        max_sessions: max_sessions as u32,
    })
}

/// Reads canonical inbound token source lists and rejects malformed list
/// shapes before disabled identities skip opening the source values.
fn inbound_token_sources(item: &Yaml, id: &str) -> Result<(Vec<String>, Vec<String>)> {
    fn names(item: &Yaml, key: &str, id: &str) -> Result<Vec<String>> {
        match item.get(key) {
            None => Ok(Vec::new()),
            Some(Yaml::Seq(values)) => values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .filter(|name| !name.is_empty())
                        .map(str::to_string)
                        .ok_or_else(|| {
                            Error::new(
                                CODE_CREDENTIAL,
                                format!("auth.inbound_peers[{id}].{key} entries must be non-empty strings"),
                            )
                        })
                })
                .collect(),
            Some(_) => Err(Error::new(
                CODE_CREDENTIAL,
                format!("auth.inbound_peers[{id}].{key} must be a list"),
            )),
        }
    }
    let files = names(item, "token_files", id)?;
    let envs = names(item, "token_envs", id)?;
    if !files.is_empty() && !envs.is_empty() {
        return Err(Error::new(
            CODE_CREDENTIAL,
            format!("auth.inbound_peers[{id}]: mixed inbound token sources"),
        ));
    }
    Ok((files, envs))
}

/// Resolves each inbound credential source as an alternative token.
fn read_inbound_tokens(
    files: &[String],
    envs: &[String],
    dir: &Path,
    id: &str,
) -> Result<Vec<String>> {
    let mut tokens = Vec::new();
    if !envs.is_empty() {
        for name in envs {
            let value = std::env::var(name).map_err(|_| {
                Error::new(
                    CODE_CREDENTIAL,
                    format!("auth.inbound_peers[{id}]: environment variable {name} is not set"),
                )
            })?;
            tokens.push(validate_inbound_token(value, id)?);
        }
    } else {
        for file in files {
            let path = dir.join(file);
            let value = read_text_limited(&path, 8195, CODE_CREDENTIAL).map_err(|error| {
                Error::new(
                    CODE_CREDENTIAL,
                    format!("auth.inbound_peers[{id}]: {}", error.message),
                )
            })?;
            tokens.push(validate_inbound_token(value, id)?);
        }
    }
    let mut unique = Vec::new();
    for token in tokens {
        if !unique.contains(&token) {
            unique.push(token);
        }
    }
    Ok(unique)
}

fn validate_inbound_token(mut token: String, id: &str) -> Result<String> {
    if token.ends_with('\n') {
        token.pop();
        if token.ends_with('\r') {
            token.pop();
        }
    }
    if token.is_empty()
        || token.len() > 8192
        || token.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(Error::new(
            CODE_CREDENTIAL,
            format!("auth.inbound_peers[{id}] token must be 1..=8192 bytes with no whitespace or control characters"),
        ));
    }
    Ok(token)
}

pub(super) fn read_token(item: &Yaml, dir: &Path, code: &str, offline: bool) -> Result<String> {
    const MAX_TOKEN_BYTES: usize = 8 << 10;
    const MALFORMED: &str = "missing, empty, oversized or malformed token";
    let env = item.str_of("token_env").filter(|value| !value.is_empty());
    let file = item.str_of("token_file").filter(|value| !value.is_empty());
    let malformed = |token: &str| {
        token.is_empty()
            || token.len() > MAX_TOKEN_BYTES
            || token
                .chars()
                .any(|character| character.is_whitespace() || character.is_control())
    };
    match (env, file) {
        (Some(env), Some(file)) => Err(Error::new(
            code,
            format!(
                "ambiguous credential source: both token_file {file} and token_env {env} are set"
            ),
        )),
        (None, None) => Err(Error::new(code, "no token_file or token_env configured")),
        _ if offline => Ok("offline-credential-placeholder".to_string()),
        (Some(name), None) => {
            let token = std::env::var_os(&name)
                .map(|v| v.to_string_lossy().into_owned())
                .unwrap_or_default();
            if token.is_empty() {
                return Err(Error::new(
                    code,
                    format!("token_env {name} is unset or empty"),
                ));
            }
            if malformed(&token) {
                return Err(Error::new(code, format!("token_env {name}: {MALFORMED}")));
            }
            Ok(token)
        }
        (None, Some(file)) => {
            use std::io::Read;
            let path = dir.join(file);
            let shown = path.display();
            let handle = std::fs::File::open(&path).map_err(|e| {
                Error::new(
                    code,
                    format!(
                        "token_file: open {shown}: {}",
                        crate::util::spec_errno_text(&e)
                    ),
                )
            })?;
            let mut raw = Vec::new();
            handle
                .take(MAX_TOKEN_BYTES as u64 + 3)
                .read_to_end(&mut raw)
                .map_err(|e| {
                    Error::new(
                        code,
                        format!(
                            "token_file {shown}: read {shown}: {}",
                            crate::util::spec_errno_text(&e)
                        ),
                    )
                })?;
            let mut token = String::from_utf8_lossy(&raw).into_owned();
            if token.ends_with('\n') {
                token.pop();
            }
            if token.ends_with('\r') {
                token.pop();
            }
            if malformed(&token) {
                return Err(Error::new(code, format!("token_file {shown}: {MALFORMED}")));
            }
            Ok(token)
        }
    }
}

pub(super) fn validate_client_tls(
    tls: &ClientTls,
    endpoints: &[super::Endpoint],
    prefix: &str,
    offline: bool,
) -> Result<()> {
    if !tls.verify {
        if tls.ca_file.is_some() {
            return Err(invalid(format!(
                "{prefix}.tls.ca_file cannot be combined with tls.verify: false"
            )));
        }
        if !tls.allow_insecure_skip_verify {
            for ep in endpoints {
                if ep.url.is_tls() && !super::endpoints::is_loopback_host(&ep.url.host) {
                    return Err(invalid(format!(
                        "{prefix}.tls.verify: false for non-loopback endpoint {} requires tls.allow_insecure_skip_verify: true",
                        ep.id
                    )));
                }
            }
        }
    }
    let Some(path) = tls.ca_file.as_ref() else {
        return Ok(());
    };
    if offline {
        return Ok(());
    }
    let tls_err = |m: String| Error::new(super::CODE_TLS, m);
    let data = read_file_limited(path, 1 << 20, "tls.ca_file too large")
        .map_err(|m| tls_err(format!("{prefix}.tls.ca_file: {m}")))?;
    if !pem_has_certificate(&data) {
        return Err(tls_err(format!(
            "{prefix}.tls.ca_file contains no PEM certificates"
        )));
    }
    Ok(())
}

pub(super) fn read_file_limited(
    path: &Path,
    limit: u64,
    too_large: &str,
) -> std::result::Result<Vec<u8>, String> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|e| {
        format!(
            "open {}: {}",
            path.display(),
            crate::util::spec_errno_text(&e)
        )
    })?;
    if file.metadata().map(|m| m.len() > limit).unwrap_or(false) {
        return Err(too_large.to_string());
    }
    let mut data = Vec::new();
    file.take(limit + 1).read_to_end(&mut data).map_err(|e| {
        format!(
            "read {}: {}",
            path.display(),
            crate::util::spec_errno_text(&e)
        )
    })?;
    if data.len() as u64 > limit {
        return Err(too_large.to_string());
    }
    Ok(data)
}

fn pem_has_certificate(data: &[u8]) -> bool {
    #[cfg(feature = "tls")]
    {
        let mut reader = std::io::BufReader::new(data);
        rustls_pemfile::certs(&mut reader)
            .map(|certs| !certs.is_empty())
            .unwrap_or(false)
    }
    #[cfg(not(feature = "tls"))]
    {
        let text = String::from_utf8_lossy(data);
        text.contains("-----BEGIN CERTIFICATE-----") && text.contains("-----END CERTIFICATE-----")
    }
}
