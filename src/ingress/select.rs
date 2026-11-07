//! Choosing where to send a connection: endpoint by priority and health, then
//! carrier by what the endpoint says it speaks.

use std::time::{Duration, Instant};

use crate::config::{self, Peer, Protocol};
use crate::error::{Error, Result};
use crate::net::http1::Client;
use crate::transport::control::ControlClient;
use crate::transport::ws_carrier;
use crate::wire::{self, Mode};

use super::{
    classify_precheck, precheck_cacheable, Health, Ingress, PrecheckVerdict, PRECHECK_TTL,
};

pub(super) fn mode_without_ws(
    protocol: Protocol,
    ws_offered: bool,
    sse_offered: bool,
) -> std::result::Result<Mode, &'static str> {
    if ws_offered {
        return Ok(Mode::Ws);
    }
    if protocol == Protocol::Auto && sse_offered {
        return Ok(Mode::HttpSse);
    }
    Err(wire::ERR_TRANSPORT_UNSUPPORTED)
}

pub(super) fn excluded_state(state: &str) -> bool {
    state == "UNHEALTHY" || state == "MISMATCHED"
}

impl Ingress {
    /// Tries endpoints in priority order, probing any whose cached result is
    /// stale, and skipping the ones in cooldown.
    #[cfg(test)]
    pub(super) fn select_endpoint(&self, peer: &Peer) -> Result<(config::Endpoint, Health)> {
        self.select_endpoint_for(peer, true)
    }

    pub(super) fn select_endpoint_for(
        &self,
        peer: &Peer,
        for_new: bool,
    ) -> Result<(config::Endpoint, Health)> {
        let mut last_err = Error::local("no usable endpoint");
        let interval = peer.failover.healthcheck_interval;
        let mut ordered = Self::peer_endpoints(peer);
        ordered.sort_by_key(|e| e.priority);
        if !peer.failover.enabled {
            ordered.truncate(1);
        }
        if ordered.len() > 1 {
            ordered.sort_by_key(|e| {
                self.endpoints
                    .get(&peer.id, &e.id)
                    .is_some_and(|h| h.failures > 0)
            });
        }
        for ep in ordered {
            if self.endpoints.in_cooldown(&peer.id, &ep.id) {
                last_err = Error::local(format!("endpoint {} is cooling down", ep.id));
                continue;
            }
            if let Some(h) = self.endpoints.get(&peer.id, &ep.id) {
                if h.probed_at.elapsed() < interval.min(Duration::from_secs(15))
                    && !excluded_state(h.state)
                {
                    if for_new && !h.accepting_new_sessions {
                        last_err = Error::local(format!(
                            "endpoint {} is not accepting new sessions",
                            ep.id
                        ));
                        continue;
                    }
                    return Ok((ep, h));
                }
            }
            let mut ctl = ControlClient::new(
                self.client_for(&peer.id),
                ep.url.clone(),
                peer.token.clone(),
                String::new(),
                peer.tls.clone(),
            );
            if let Some(provider) = self.token_provider(&peer.id) {
                ctl = ctl.with_token_provider(provider);
            }
            let probe_started = Instant::now();
            let probed = ctl.probe_within(
                &peer.expected_node_id,
                Some(peer.failover.healthcheck_timeout),
            );
            if !matches!(&probed, Err(e) if e.is_local() && e.message.contains("budget")) {
                self.metrics.observe_ingress_phase(
                    &peer.id,
                    &ep.id,
                    "probe",
                    probed.is_ok(),
                    probe_started.elapsed(),
                );
            }
            crate::egress::log_debug(&format!(
                "ingress probe of peer {} endpoint {}: {} after {:?}",
                peer.id,
                ep.id,
                match &probed {
                    Ok(p) => format!(
                        "instance {} accepting {}",
                        p.instance_id, p.accepting_new_sessions
                    ),
                    Err(e) => e.to_string(),
                },
                probe_started.elapsed()
            ));
            match probed {
                Ok(p) => {
                    let transports: Vec<Mode> =
                        p.transports.iter().filter_map(|t| Mode::parse(t)).collect();
                    let h = Health {
                        instance_id: p.instance_id,
                        transports,
                        accepting_new_sessions: p.accepting_new_sessions,
                        probed_at: Instant::now(),
                        cooldown_until: None,
                        failures: 0,
                        probe_failures: 0,
                        successes: 0,
                        state: "UNKNOWN",
                    };
                    let state = self.endpoints.put(
                        &peer.id,
                        &ep.id,
                        h.clone(),
                        peer.failover.healthy_threshold,
                    );
                    self.metrics.set_endpoint_state(&peer.id, &ep.id, state);
                    if excluded_state(state) {
                        last_err = Error::local(format!("endpoint {} is {state}", ep.id));
                        continue;
                    }
                    if for_new && !h.accepting_new_sessions {
                        last_err = Error::local(format!(
                            "endpoint {} is not accepting new sessions",
                            ep.id
                        ));
                        continue;
                    }
                    return Ok((ep, h));
                }
                Err(e) => {
                    let mismatched = classify_precheck(&e) == PrecheckVerdict::Mismatched;
                    let state = self.endpoints.record_probe_failure(
                        &peer.id,
                        &ep.id,
                        peer.failover.cooldown,
                        peer.failover.unhealthy_threshold,
                        mismatched,
                    );
                    self.metrics.set_endpoint_state(&peer.id, &ep.id, state);
                    last_err = e;
                }
            }
        }
        Err(last_err)
    }

    pub(super) fn select_mode(
        &self,
        peer: &Peer,
        ep: &config::Endpoint,
        h: &Health,
        client: &Client,
    ) -> Result<Mode> {
        let prefer_ws = match peer.protocol {
            Protocol::Ws => true,
            Protocol::HttpSse => false,
            Protocol::LongPoll => false,
            Protocol::Auto => true,
        };
        let now = Instant::now();
        let ws_offered = h.transports.contains(&Mode::Ws)
            && self
                .endpoints
                .transport_available(&peer.id, &ep.id, Mode::Ws, now);
        let sse_offered = h.transports.contains(&Mode::HttpSse)
            && self
                .endpoints
                .transport_available(&peer.id, &ep.id, Mode::HttpSse, now);
        if !prefer_ws {
            return if sse_offered {
                Ok(Mode::HttpSse)
            } else {
                Err(Error::new(
                    wire::ERR_TRANSPORT_UNSUPPORTED,
                    "peer does not accept http-sse",
                ))
            };
        }
        if !ws_offered {
            return mode_without_ws(peer.protocol, ws_offered, sse_offered)
                .map_err(|code| Error::new(code, "peer does not accept ws"));
        }
        // Precheck the upgrade path: a proxy that refuses `Upgrade` shows up
        // here as a plain HTTP answer, and only then is SSE the right choice.
        let key = format!("{}|{}|{}", peer.id, ep.id, h.instance_id);
        if let Some((cached, refresh)) = self.cached_precheck(&key) {
            self.metrics
                .record_session_event("ingress", "cache_hit", "success", "ws", "ws");
            if refresh {
                self.refresh_precheck(&key, peer, ep, h, client);
            }
            return match cached {
                None => Ok(Mode::Ws),
                Some(_msg) if sse_offered => Ok(Mode::HttpSse),
                Some(msg) => Err(Error::new(wire::ERR_TRANSPORT_UNSUPPORTED, msg)),
            };
        }
        let nonce = crate::util::random_hex(16).map_err(crate::util::random_error)?;
        let token = self
            .token_provider(&peer.id)
            .map(|p| p())
            .transpose()?
            .unwrap_or_else(|| peer.token.clone());
        let headers = vec![
            (wire::H_PEER_AUTH.to_string(), format!("Bearer {token}")),
            (wire::H_INSTANCE_ID.to_string(), h.instance_id.clone()),
            (wire::H_WS_PURPOSE.to_string(), "check".to_string()),
            (wire::H_WS_NONCE.to_string(), nonce),
        ];
        let timeout = self.cfg.transport.ws_handshake_timeout;
        self.metrics
            .record_session_event("ingress", "cache_miss", "success", "ws", "ws");
        let resource_leases = client.acquire_data_connection_leases(timeout)?;
        let precheck_started = Instant::now();
        let precheck = ws_carrier::precheck_via_node(
            &*client.dialer(),
            &ep.url,
            &headers,
            timeout,
            resource_leases,
            &peer.expected_node_id,
        );
        self.metrics.observe_ingress_phase(
            &peer.id,
            &ep.id,
            "precheck",
            precheck.is_ok(),
            precheck_started.elapsed(),
        );
        match precheck {
            Ok(()) => {
                let outcome = Ok(Mode::Ws);
                self.remember_precheck(&key, &outcome);
                outcome
            }
            Err(e) => {
                let verdict = classify_precheck(&e);
                if verdict == PrecheckVerdict::WsUnavailable {
                    self.endpoints.record_transport_failure(
                        &peer.id,
                        &ep.id,
                        Mode::Ws,
                        peer.failover.cooldown,
                    );
                }
                // Cache the original WS answer, not the selected fallback
                // mode. Otherwise auto would perform the same precheck for
                // every new session after falling back to SSE.
                self.remember_precheck(&key, &Err(e.clone()));
                match (verdict, sse_offered) {
                    (PrecheckVerdict::WsUnavailable, true) => match self.probe_endpoint(peer, ep) {
                        Ok(again)
                            if again.instance_id == h.instance_id
                                && again.transports.iter().any(|t| t == "http-sse") =>
                        {
                            Ok(Mode::HttpSse)
                        }
                        Ok(_) => Err(Error::local(format!(
                            "endpoint {} changed after the WS precheck refusal",
                            ep.id
                        ))),
                        Err(pe) => Err(pe),
                    },
                    _ => Err(e),
                }
            }
        }
    }

    /// One authenticated probe of `ep` (no health bookkeeping).
    fn probe_endpoint(
        &self,
        peer: &Peer,
        ep: &config::Endpoint,
    ) -> Result<crate::wire::ProbeResponse> {
        let mut ctl = ControlClient::new(
            self.client_for(&peer.id),
            ep.url.clone(),
            peer.token.clone(),
            String::new(),
            peer.tls.clone(),
        );
        if let Some(provider) = self.token_provider(&peer.id) {
            ctl = ctl.with_token_provider(provider);
        }
        ctl.probe(&peer.expected_node_id)
    }

    /// A cached precheck answer: `None` inside means WebSocket works.
    /// The boolean requests a detached refresh; it is set under the mutex so
    /// concurrent callers can never start two network checks for one key.
    fn cached_precheck(&self, key: &str) -> Option<(Option<String>, bool)> {
        use super::PRECHECK_KEEP_WARM;
        use super::PRECHECK_STALE_MAX;
        let mut g = self.prechecks.lock().unwrap();
        let now = Instant::now();
        let entry = g.get_mut(key)?;
        if now < entry.expires {
            let recently_used = now.duration_since(entry.last_used) <= PRECHECK_KEEP_WARM;
            entry.last_used = now;
            let refresh = entry.answer.is_none()
                && !entry.refreshing
                && entry.expires.saturating_duration_since(now) <= Duration::from_secs(5)
                && recently_used;
            if refresh {
                entry.refreshing = true;
            }
            return Some((entry.answer.clone(), refresh));
        }
        if entry.answer.is_none() && now < entry.expires + PRECHECK_STALE_MAX {
            entry.last_used = now;
            let refresh = !entry.refreshing;
            entry.refreshing = true;
            return Some((None, refresh));
        }
        g.remove(key);
        None
    }

    fn refresh_precheck(
        &self,
        key: &str,
        peer: &Peer,
        ep: &config::Endpoint,
        h: &Health,
        client: &Client,
    ) {
        let nonce = match crate::util::random_hex(16) {
            Ok(nonce) => nonce,
            Err(_) => {
                if let Ok(mut g) = self.prechecks.lock() {
                    if let Some(entry) = g.get_mut(key) {
                        entry.refreshing = false;
                    }
                }
                return;
            }
        };
        let token = match self.token_provider(&peer.id) {
            Some(provider) => match provider() {
                Ok(t) => t,
                Err(_) => {
                    if let Ok(mut g) = self.prechecks.lock() {
                        if let Some(entry) = g.get_mut(key) {
                            entry.refreshing = false;
                        }
                    }
                    return;
                }
            },
            None => peer.token.clone(),
        };
        let headers = vec![
            (wire::H_PEER_AUTH.to_string(), format!("Bearer {token}")),
            (wire::H_INSTANCE_ID.to_string(), h.instance_id.clone()),
            (wire::H_WS_PURPOSE.to_string(), "check".to_string()),
            (wire::H_WS_NONCE.to_string(), nonce),
        ];
        let key = key.to_string();
        let dialer = client.dialer();
        let resources = client.resource_manager_handle();
        let url = ep.url.clone();
        let timeout = self.cfg.transport.ws_handshake_timeout;
        let cache = self.prechecks.clone();
        let metrics = self.metrics.clone();
        let (peer_id, ep_id) = (peer.id.clone(), ep.id.clone());
        let expected_node = peer.expected_node_id.clone();
        std::thread::spawn(move || {
            let started = Instant::now();
            let outcome = match resources {
                Some(resources) => Client::acquire_data_connection_leases_from(&resources, timeout)
                    .and_then(|leases| {
                        ws_carrier::precheck_via_node(
                            &*dialer,
                            &url,
                            &headers,
                            timeout,
                            leases,
                            &expected_node,
                        )
                        .map(|_| Mode::Ws)
                    }),
                None => ws_carrier::precheck_via_node(
                    &*dialer,
                    &url,
                    &headers,
                    timeout,
                    Vec::new(),
                    &expected_node,
                )
                .map(|_| Mode::Ws),
            };
            metrics.observe_ingress_phase(
                &peer_id,
                &ep_id,
                "precheck",
                outcome.is_ok(),
                started.elapsed(),
            );
            // Reuse the normal cache policy, but never hold the cache mutex
            // while the detached network operation is in progress.
            let now = Instant::now();
            let mut g = cache.lock().unwrap();
            if let Ok(Mode::Ws) = outcome {
                g.insert(
                    key,
                    super::PrecheckEntry {
                        expires: now + super::PRECHECK_TTL,
                        stale_until: now + super::PRECHECK_TTL + super::PRECHECK_STALE_MAX,
                        answer: None,
                        last_used: now,
                        refreshing: false,
                    },
                );
            } else if let Some(entry) = g.get_mut(&key) {
                entry.refreshing = false;
            }
        });
    }

    /// Drops a cached answer after a WebSocket session failed on it.
    pub(super) fn forget_precheck(&self, peer: &str, ep: &str, instance: &str) {
        let key = format!("{peer}|{ep}|{instance}");
        if self.prechecks.lock().unwrap().remove(&key).is_some() {
            self.metrics.record_session_event(
                "ingress",
                "cache_invalidate",
                "transport",
                "ws",
                "ws",
            );
        }
    }

    /// Caches a definitive answer, and only a definitive one: a quota answer
    /// or a timeout must be retried on the next connection, not remembered.
    fn remember_precheck(&self, key: &str, outcome: &Result<Mode>) {
        let answer = match outcome {
            Ok(Mode::Ws) => None,
            Ok(_) => return,
            Err(e) => {
                if !precheck_cacheable(e) {
                    return;
                }
                if classify_precheck(e) != PrecheckVerdict::WsUnavailable {
                    return;
                }
                Some(e.message.clone())
            }
        };
        let now = Instant::now();
        let mut g = self.prechecks.lock().unwrap();
        g.retain(|_, entry| now < entry.stale_until);
        g.insert(
            key.to_string(),
            super::PrecheckEntry {
                expires: now + PRECHECK_TTL,
                stale_until: now + PRECHECK_TTL + super::PRECHECK_STALE_MAX,
                answer,
                last_used: now,
                refreshing: false,
            },
        );
    }
}
