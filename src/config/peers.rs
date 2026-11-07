//! The peer-facing sections: inbound credentials, outbound peers, and the
//! local listeners that point at them.

use std::{
    collections::{HashMap, HashSet},
    path::Path,
};

use crate::error::{Error, Result};

use super::reverse::{parse_inbound, read_token};
use super::scalars::{dur_field, parse_hostport, read_text_limited};
use super::yaml::{self, Yaml};
use super::{
    check_keys, invalid, ClientTls, Failover, InboundPeer, Listener, Peer, Protocol,
    CODE_CONFIG_INVALID, CODE_CONFIG_READ, CODE_CREDENTIAL, CODE_LISTEN,
};

type Credentials = (Vec<InboundPeer>, Vec<(String, String)>);

/// Reads `auth`: inbound identities this node accepts, plus the outbound
/// credential table that `peers[].credential_ref` points into.
pub(super) fn credentials(doc: &Yaml, dir: &Path, offline: bool) -> Result<Credentials> {
    let auth_doc = doc.get("auth").unwrap_or(&Yaml::Null);
    check_keys(
        auth_doc,
        "auth",
        &["credentials_file", "inbound_peers", "reload_interval"],
        &[],
    )?;
    let mut inbound = Vec::new();
    let mut outbound: Vec<(String, String)> = Vec::new();
    let mut cred_doc_owned = Yaml::Null;
    let mut credential_dir = dir.to_path_buf();
    if let Some(rel) = auth_doc
        .str_of("credentials_file")
        .filter(|value| !value.is_empty())
    {
        let cred_path = dir.join(&rel);
        let text = read_text_limited(&cred_path, 1 << 20, CODE_CREDENTIAL)?;
        cred_doc_owned = yaml::parse(&text).map_err(|e| Error::new(CODE_CREDENTIAL, e))?;
        yaml::reject_explicit_null(&cred_doc_owned).map_err(|e| Error::new(CODE_CREDENTIAL, e))?;
        check_keys(
            &cred_doc_owned,
            "credentials",
            &["version", "inbound_peers", "outbound_peers"],
            &[],
        )?;
        if cred_doc_owned.i64_of("version") != Some(1) {
            return Err(Error::new(
                CODE_CREDENTIAL,
                "credentials file version must be 1",
            ));
        }
        if auth_doc
            .seq_of("inbound_peers")
            .is_some_and(|items| !items.is_empty())
        {
            return Err(Error::new(
                super::CODE_AUTH_CONFLICT,
                "credentials_file cannot be mixed with inline inbound credentials",
            ));
        }
        credential_dir = cred_path.parent().unwrap_or(dir).to_path_buf();
    }
    let cred_source = if cred_doc_owned.is_null() {
        auth_doc
    } else {
        &cred_doc_owned
    };
    if let Some(list) = cred_source.seq_of("inbound_peers") {
        let mut ids = HashSet::new();
        for item in list {
            let identity = parse_inbound(item, &credential_dir, offline)?;
            if !ids.insert(identity.id.clone()) {
                return Err(Error::new(
                    CODE_CREDENTIAL,
                    format!("invalid or duplicate inbound identity {:?}", identity.id),
                ));
            }
            inbound.push(identity);
        }
    }
    if let Some(list) = cred_source.seq_of("outbound_peers") {
        let mut ids = HashSet::new();
        for item in list {
            check_keys(
                item,
                "auth.outbound_peers[]",
                &["id", "token_file", "token_env"],
                &[],
            )?;
            let id = item
                .str_of("id")
                .filter(|value| !value.is_empty())
                .ok_or_else(|| Error::new(CODE_CREDENTIAL, "outbound_peers[].id is required"))?;
            if !ids.insert(id.clone()) {
                return Err(Error::new(
                    CODE_CREDENTIAL,
                    format!("invalid or duplicate outbound credential id {id:?}"),
                ));
            }
            let token =
                read_token(item, &credential_dir, CODE_CREDENTIAL, offline).map_err(|e| {
                    Error::new(
                        CODE_CREDENTIAL,
                        format!("outbound_peers[{id}]: {}", e.message),
                    )
                })?;
            outbound.push((id, token));
        }
    }
    Ok((inbound, outbound))
}

pub(super) fn peers(
    doc: &Yaml,
    node_id: &str,
    outbound: &[(String, String)],
    default_protocol: Protocol,
    max_endpoints_per_peer: u32,
    dir: &Path,
    offline: bool,
) -> Result<Vec<Peer>> {
    let mut peers = Vec::new();
    let mut reverse_nodes = HashMap::<String, String>::new();
    let credentials_file_set = doc
        .get("auth")
        .and_then(|auth| auth.str_of("credentials_file"))
        .is_some_and(|path| !path.is_empty());
    let peer_entries = match doc.get("peers") {
        None => None,
        Some(Yaml::Seq(list)) => Some(list),
        Some(_) => return Err(Error::new(CODE_CONFIG_READ, "peers must be an array")),
    };
    if let Some(list) = peer_entries {
        for (index, item) in list.iter().enumerate() {
            let id = item
                .str_of("id")
                .filter(|s| !s.is_empty())
                .ok_or_else(|| invalid("peers[].id is required".into()))?;
            if peers.iter().any(|p: &Peer| p.id == id) {
                return Err(invalid(format!("duplicate peer id {id:?}")));
            }
            let mode = match item.get("mode") {
                None => String::new(),
                Some(Yaml::Str(text)) if !yaml::is_float_scalar(text) => text.clone(),
                Some(Yaml::Null) => {
                    return Err(Error::new(
                        CODE_CONFIG_READ,
                        format!("config.peers[{index}].mode: explicit null is not allowed; omit optional fields"),
                    ))
                }
                Some(_) => {
                    return Err(Error::new(
                        CODE_CONFIG_READ,
                        format!("config.peers[{index}].mode must be a string"),
                    ))
                }
            };
            let reverse = match mode.as_str() {
                "" | "forward" => false,
                "reverse" => true,
                other => {
                    return Err(Error::new(
                        super::CODE_PEER_MODE,
                        format!("invalid peers[{id}].mode: {other:?} (must be forward or reverse)"),
                    ))
                }
            };
            let mut supported_keys = vec![
                "id",
                "expected_node_id",
                "token_env",
                "token_file",
                "credential_ref",
                "endpoints",
                "failover",
                "transport",
                "recovery",
                "mode",
                "tls",
            ];
            supported_keys.push("allow_insecure_http");
            let unsupported_keys = &["min_backoff", "max_backoff"][..];
            check_keys(
                item,
                &format!("peers[{id}]"),
                &supported_keys,
                // The TLS fields would change how the peer is reached;
                // ignoring them would connect in the clear.
                unsupported_keys,
            )?;
            let fo_doc = item.get("failover").unwrap_or(&Yaml::Null);
            check_keys(
                fo_doc,
                "peers[].failover",
                &[
                    "enabled",
                    "strategy",
                    "failback",
                    "healthy_threshold",
                    "unhealthy_threshold",
                    "healthcheck_interval",
                    "healthcheck_timeout",
                    "cooldown",
                ],
                &["max_concurrent_probes"],
            )?;
            if item.get("allow_insecure_http").is_some()
                && item.bool_of("allow_insecure_http").is_none()
            {
                return Err(invalid(format!(
                    "peers[{id}].allow_insecure_http must be a boolean"
                )));
            }
            let expected_node_id = item
                .str_of("expected_node_id")
                .filter(|value| !value.is_empty())
                .ok_or_else(|| invalid(format!("peers[{id}].expected_node_id is required")))?;
            if expected_node_id == node_id {
                return Err(invalid(format!(
                    "peers[{id}].expected_node_id must differ from this node's node.id"
                )));
            }
            if reverse {
                if let Some(other) = reverse_nodes.insert(expected_node_id.clone(), id.clone()) {
                    return Err(invalid(format!(
                        "peers[{other}] and peers[{id}]: reverse peers must have distinct expected_node_id ({expected_node_id:?})"
                    )));
                }
            }
            let credential_ref = item
                .str_of("credential_ref")
                .filter(|value| !value.is_empty())
                .ok_or_else(|| invalid(format!("peers[{id}].credential_ref is required")))?;
            let tls_doc = item.get("tls").unwrap_or(&Yaml::Null);
            check_keys(
                tls_doc,
                &format!("peers[{id}].tls"),
                &["verify", "ca_file", "allow_insecure_skip_verify"],
                &[],
            )?;
            let tls = ClientTls {
                verify: tls_doc.bool_of("verify").unwrap_or(true),
                ca_file: tls_doc.str_of("ca_file").map(|p| dir.join(p)),
                allow_insecure_skip_verify: tls_doc
                    .bool_of("allow_insecure_skip_verify")
                    .unwrap_or(false),
            };
            let has_token_env = item.get("token_env").is_some();
            let has_token_file = item.get("token_file").is_some();
            if offline && has_token_env && has_token_file {
                return Err(invalid(format!(
                    "peer[{id}] credential: ambiguous credential source"
                )));
            }
            if credentials_file_set && (has_token_env || has_token_file) {
                return Err(Error::new(
                    super::CODE_AUTH_CONFLICT,
                    "credentials_file cannot be mixed with direct outbound credentials",
                ));
            }
            let token = if credentials_file_set {
                outbound
                    .iter()
                    .find(|(pid, _)| *pid == credential_ref)
                    .map(|(_, t)| t.clone())
                    .ok_or_else(|| {
                        Error::new(
                            CODE_CREDENTIAL,
                            format!("peers[{id}].credential_ref {credential_ref:?} is not defined"),
                        )
                    })?
            } else if has_token_env || has_token_file {
                read_token(item, dir, CODE_CREDENTIAL, offline).map_err(|e| {
                    Error::new(
                        CODE_CREDENTIAL,
                        format!("peer[{id}] credential: {}", e.message),
                    )
                })?
            } else {
                return Err(Error::new(
                    CODE_CREDENTIAL,
                    format!("peers[{id}] has no outbound credential: set token_env or token_file, or use auth.credentials_file"),
                ));
            };
            if token.is_empty() {
                return Err(Error::new(
                    CODE_CREDENTIAL,
                    format!("peers[{id}] resolved an empty token"),
                ));
            }
            let prefix = format!("peers[{id}]");
            let name = format!("peer {id}");
            let declared = item.seq_of("endpoints").unwrap_or(&[]);
            if !reverse && declared.is_empty() {
                return Err(invalid(format!("peers[{id}].endpoints cannot be empty")));
            }
            if !reverse && declared.len() > max_endpoints_per_peer as usize {
                return Err(invalid(format!(
                    "peers[{id}].endpoints length ({}) exceeds max_endpoints_per_peer ({max_endpoints_per_peer})",
                    declared.len()
                )));
            }
            let mut endpoints = if reverse {
                Vec::new()
            } else {
                super::endpoints::normalize_endpoints(
                    item.seq_of("endpoints").unwrap_or(&[]),
                    &super::endpoints::Owner {
                        prefix: &prefix,
                        name: &name,
                        insecure_hint: "set peers[].allow_insecure_http: true for this peer",
                        code: CODE_CONFIG_INVALID,
                    },
                    item.bool_of("allow_insecure_http").unwrap_or(false),
                )?
            };
            if reverse {
                if !declared.is_empty() {
                    return Err(Error::new(
                        super::CODE_PEER_MODE,
                        format!("peers[{id}]: a reverse peer dials in over its tunnel and cannot have endpoints; remove endpoints or set mode: forward"),
                    ));
                }
            } else if endpoints.is_empty() {
                return Err(invalid(format!("peers[{id}] has no endpoints")));
            } else if endpoints.len() > max_endpoints_per_peer as usize {
                return Err(invalid(format!(
                    "peers[{id}].endpoints length ({}) exceeds max_endpoints_per_peer ({max_endpoints_per_peer})",
                    endpoints.len()
                )));
            }
            endpoints.sort_by_key(|e| e.priority);
            if !reverse {
                super::reverse::validate_client_tls(&tls, &endpoints, &prefix, offline)?;
            }

            let defaults = Failover::default();
            let strategy = fo_doc
                .str_of("strategy")
                .unwrap_or_else(|| "priority".to_string());
            if strategy != "priority" {
                return Err(invalid(format!(
                    "peers[{id}].failover.strategy must be \"priority\""
                )));
            }
            let failback = fo_doc
                .str_of("failback")
                .unwrap_or_else(|| "new_sessions".to_string());
            if failback != "new_sessions" {
                return Err(invalid(format!(
                    "peers[{id}].failover.failback must be \"new_sessions\""
                )));
            }
            let mut failover = Failover {
                enabled: fo_doc.bool_of("enabled").unwrap_or(endpoints.len() > 1),
                strategy,
                failback,
                healthy_threshold: fo_doc
                    .i64_of("healthy_threshold")
                    .map(|v| v.max(1) as u32)
                    .unwrap_or(defaults.healthy_threshold),
                unhealthy_threshold: fo_doc
                    .i64_of("unhealthy_threshold")
                    .map(|v| v.max(1) as u32)
                    .unwrap_or(defaults.unhealthy_threshold),
                healthcheck_interval: dur_field(
                    fo_doc,
                    "healthcheck_interval",
                    defaults.healthcheck_interval,
                )?,
                healthcheck_timeout: dur_field(
                    fo_doc,
                    "healthcheck_timeout",
                    defaults.healthcheck_timeout,
                )?,
                cooldown: dur_field(fo_doc, "cooldown", defaults.cooldown)?,
            };
            let timeout_unset = match fo_doc.get("healthcheck_timeout") {
                None => true,
                Some(Yaml::Str(value)) => value.trim().is_empty(),
                Some(_) => false,
            };
            if timeout_unset {
                failover.healthcheck_timeout = std::time::Duration::from_millis(1)
                    .max(std::time::Duration::from_secs(3).min(failover.healthcheck_interval / 2));
            }
            if failover.healthcheck_interval.is_zero()
                || failover.healthcheck_timeout.is_zero()
                || failover.healthcheck_timeout >= failover.healthcheck_interval
            {
                return Err(invalid(format!(
                    "peers[{id}].failover.healthcheck_timeout ({:?}) must be < healthcheck_interval ({:?})",
                    failover.healthcheck_timeout, failover.healthcheck_interval
                )));
            }

            if let Some(t) = item.get("transport") {
                check_keys(t, "peers[].transport", &["protocol"], &[])?;
            }
            if let Some(r) = item.get("recovery") {
                check_keys(r, "peers[].recovery", &["enabled", "grace"], &[])?;
            }
            let recovery_enabled = match item.get("recovery") {
                Some(recovery) => match recovery.get("enabled") {
                    None => None,
                    Some(_) => Some(recovery.bool_of("enabled").ok_or_else(|| {
                        invalid(format!("peers[{id}].recovery.enabled must be boolean"))
                    })?),
                },
                None => None,
            };
            let protocol = match item
                .get("transport")
                .and_then(|t| t.str_of("protocol"))
                .filter(|p| !p.is_empty())
            {
                Some(p) => Protocol::parse(&p)
                    .filter(|v| *v != Protocol::LongPoll)
                    .ok_or_else(|| {
                    invalid(format!(
                        "invalid peers[{id}].transport.protocol: {p:?} (must be auto, ws, or http-sse)"
                    ))
                })?,
                None => default_protocol,
            };
            peers.push(Peer {
                id,
                expected_node_id,
                token,
                endpoints,
                failover,
                protocol,
                recovery_enabled,
                reverse,
                tls,
            });
        }
    }
    Ok(peers)
}

pub(super) fn listeners(doc: &Yaml, peers: &[Peer]) -> Result<Vec<Listener>> {
    let mut listeners = Vec::new();
    let listener_entries = match doc.get("listeners") {
        None => None,
        Some(Yaml::Seq(list)) => Some(list),
        Some(_) => return Err(Error::new(CODE_CONFIG_READ, "listeners must be an array")),
    };
    if let Some(list) = listener_entries {
        for (index, item) in list.iter().enumerate() {
            let id = item
                .str_of("id")
                .filter(|s| !s.is_empty())
                .ok_or_else(|| invalid(format!("listeners[{index}].id cannot be empty")))?;
            if listeners.iter().any(|l: &Listener| l.id == id) {
                return Err(invalid(format!("duplicate listener id: {id}")));
            }
            check_keys(
                item,
                &format!("listeners[{id}]"),
                &["id", "listen", "peer", "target"],
                &[],
            )?;
            let listen = item
                .str_of("listen")
                .filter(|s| !s.is_empty())
                .ok_or_else(|| invalid(format!("listeners[{id}].listen cannot be empty")))?;
            super::scalars::validate_socket_address(&listen, true)
                .map_err(|e| Error::new(CODE_LISTEN, e))?;
            parse_hostport(&listen).map_err(|e| Error::new(CODE_LISTEN, e))?;
            let peer = item
                .str_of("peer")
                .filter(|s| !s.is_empty())
                .ok_or_else(|| invalid(format!("listeners[{id}].peer cannot be empty")))?;
            if !peers.iter().any(|p| p.id == peer) {
                return Err(invalid(format!(
                    "listeners[{id}] references non-existent peer: {peer}"
                )));
            }
            let target = item
                .str_of("target")
                .filter(|s| !s.is_empty())
                .ok_or_else(|| invalid(format!("listeners[{id}].target cannot be empty")))?;
            listeners.push(Listener {
                id,
                listen,
                peer,
                target,
            });
        }
    }
    Ok(listeners)
}
