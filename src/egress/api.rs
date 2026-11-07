//! The control API: probe, create, ack, up, fin, delete — plus the target
//! dial that `create` performs.

use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use crate::config::{self, Target};
use crate::error::{Error, Result};
use crate::net::http1::Request;
use crate::session::Session;
use crate::transport;
use crate::util::json::{self, Json};
use crate::wire::{
    self, AckRequest, AckResponse, CreateRequest, FinResponse, Mode, ResumeRequestWire,
};

use super::{constant_time_eq, CreateLookup, Server};

fn optional_header_offset(req: &Request, name: &str) -> Result<u64> {
    match req.header(name) {
        None | Some("") => Ok(0),
        Some(value) => json::canonical_offset(value).ok_or_else(|| {
            Error::new(
                wire::ERR_BAD_ACK,
                format!("non-canonical {name} acknowledgement offset"),
            )
        }),
    }
}

impl Server {
    pub(super) fn bind_cred(&self, peer: &str, token: &str) -> bool {
        self.auth
            .inbound(peer)
            .filter(|p| p.enabled)
            .is_some_and(|p| {
                p.tokens
                    .iter()
                    .any(|candidate| constant_time_eq(candidate.as_bytes(), token.as_bytes()))
            })
    }

    pub(super) fn handle_probe(&self, req: &Request) -> Result<String> {
        let peer = self.authenticate(req)?;
        let _probe = self
            .probe_budget
            .try_acquire_probe_with_reason(
                &peer.id,
                self.cfg.inbound.iter().filter(|p| p.enabled).count(),
            )
            .map_err(|reason| Error::new(wire::ERR_QUOTA_EXCEEDED, reason).retryable(true))?;
        let v = json::parse_bytes(&req.body)
            .map_err(|_| Error::new(wire::ERR_BAD_FRAME, "invalid control body"))?;
        v.reject_unknown_fields(&["protocol_version", "expected_node_id", "nonce"])
            .map_err(|e| Error::new(wire::ERR_BAD_FRAME, e))?;
        if v.str_field("protocol_version")? != wire::PROTOCOL_VERSION {
            return Err(Error::new(wire::ERR_PROTOCOL_MISMATCH, "protocol"));
        }
        let expected = match v.get("expected_node_id") {
            Some(value) => value
                .as_str()
                .ok_or_else(|| Error::new(wire::ERR_BAD_FRAME, "expected_node_id"))?,
            None => "",
        };
        if !expected.is_empty() && expected != self.cfg.node.id {
            return Err(Error::new(wire::ERR_NODE_MISMATCH, "node"));
        }
        let nonce = v.str_field("nonce")?;
        if nonce.is_empty() || nonce.len() > 128 {
            return Err(Error::new(wire::ERR_BAD_FRAME, "nonce"));
        }
        Ok(json::obj(vec![
            ("protocol_version", Json::from(wire::PROTOCOL_VERSION)),
            ("node_id", Json::from(self.cfg.node.id.as_str())),
            (
                "instance_id",
                Json::from(self.cfg.node.instance_id.as_str()),
            ),
            ("nonce", Json::from(nonce)),
            (
                "recovery_available",
                Json::Bool(self.cfg.transport.recovery_enabled),
            ),
            (
                "accepting_new_sessions",
                Json::Bool(self.registry.accepting()),
            ),
            (
                "transports",
                Json::Arr(
                    self.cfg
                        .transports()
                        .iter()
                        .map(|m| Json::from(m.as_str()))
                        .collect(),
                ),
            ),
        ])
        .to_string())
    }

    fn answer_create_lookup(&self, found: CreateLookup) -> Result<(u16, String)> {
        match found {
            CreateLookup::Pending | CreateLookup::Reserved => {
                Err(Error::new(wire::ERR_CREATE_PENDING, "pending").retryable(true))
            }
            CreateLookup::Conflict => Err(Error::new(
                wire::ERR_IDEMPOTENCY_CONFLICT,
                "parameters differ",
            )),
            CreateLookup::Quota(message) => {
                Err(Error::new(wire::ERR_QUOTA_EXCEEDED, message).retryable(true))
            }
            CreateLookup::Draining => {
                Err(Error::new(wire::ERR_DRAINING, "new sessions unavailable").retryable(true))
            }
            CreateLookup::Replay {
                status,
                body,
                session_id,
            } => {
                if let Some(id) = session_id {
                    if self.registry.get(&id).is_none() {
                        return Err(Error::new(wire::ERR_SESSION_CLOSED, "creation is terminal")
                            .closed(true));
                    }
                }
                let replay_status = if status == 201 { 200 } else { status };
                Ok((replay_status, body))
            }
        }
    }

    pub(super) fn handle_create(&self, req: &Request) -> Result<(u16, String)> {
        let peer = self.authenticate(req)?;
        self.check_instance(req)?;
        let v = json::parse_bytes(&req.body)
            .map_err(|_| Error::new(wire::ERR_BAD_FRAME, "invalid control body"))?;
        let creq = CreateRequest::from_json(&v)?;

        if creq.target_id.is_empty()
            || creq.create_request_id.is_empty()
            || creq.create_request_id.len() > 128
            || creq.ingress_instance_id.is_empty()
            || creq.ingress_instance_id.len() > 128
        {
            return Err(Error::new(wire::ERR_BAD_FRAME, "missing/invalid identity"));
        }
        if !self.cfg.transports().contains(&creq.mode) {
            return Err(Error::new(
                wire::ERR_TRANSPORT_UNSUPPORTED,
                format!("transport {} is not allowed", creq.mode.as_str()),
            ));
        }
        if creq.recovery_enabled && !self.cfg.transport.recovery_enabled {
            return Err(Error::new(
                wire::ERR_RECOVERY_UNSUPPORTED,
                "recovery unsupported",
            ));
        }
        if (!creq.recovery_enabled && creq.recovery_grace_ms != 0)
            || (creq.recovery_enabled && creq.recovery_grace_ms == 0)
        {
            return Err(Error::new(wire::ERR_BAD_FRAME, "recovery grace"));
        }
        if creq.limits.max_frame_size == 0
            || creq.limits.max_frame_size as u64 > wire::MAX_FRAME_PAYLOAD as u64
            || creq.limits.up_max_inflight_frames == 0
            || creq.limits.up_window_bytes == 0
            || creq.limits.down_buffer_bytes == 0
            || creq.limits.max_frame_size as u64 > creq.limits.up_window_bytes
            || creq.limits.up_window_bytes > creq.limits.down_buffer_bytes
        {
            return Err(Error::new(wire::ERR_BAD_FRAME, "invalid limits"));
        }
        let idem_key = Json::Arr(vec![
            Json::from(peer.id.as_str()),
            Json::from(creq.ingress_instance_id.as_str()),
            Json::from(creq.create_request_id.as_str()),
        ])
        .to_string();
        let params = creq.to_json().to_string();
        if let Some(found) = self.registry.lookup_create(&idem_key, &params) {
            return self.answer_create_lookup(found);
        }
        let target = self
            .cfg
            .target(creq.target_id.as_str())
            .ok_or_else(|| Error::new(wire::ERR_TARGET_FORBIDDEN, "creation refused"))?;
        if !peer.allowed_targets.iter().any(|t| t == &creq.target_id) {
            return Err(Error::new(wire::ERR_TARGET_FORBIDDEN, "creation refused"));
        }
        let limits = transport::negotiate_limits(&self.cfg.transport, &creq.limits)?;
        let records = self.create_record_limits(peer.max_sessions);
        let _create_fair = match self.metrics.resource_manager() {
            Some(resources) => Some(
                self.auth
                    .reserve_fair_n(&peer.id, "create", resources.creates.limit(), 1)
                    .ok_or_else(|| {
                        Error::new(wire::ERR_QUOTA_EXCEEDED, "creation concurrency").retryable(true)
                    })?,
            ),
            None => None,
        };
        match self.registry.reserve_create_with_records(
            &idem_key,
            &peer.id,
            params,
            peer.max_sessions,
            self.cfg.limits.max_sessions,
            records,
        ) {
            CreateLookup::Reserved => {}
            found => return self.answer_create_lookup(found),
        }
        self.metrics.dial_attempted();
        let backend = match dial_target(target, self.cfg.transport.dial_timeout) {
            Ok(s) => s,
            Err(e) => {
                self.metrics.dial_failed();
                let e = if self.registry.accepting() {
                    e
                } else {
                    Error::new(wire::ERR_DRAINING, "stopped").retryable(true)
                };
                self.registry.fail_create(
                    &idem_key,
                    e.status(),
                    wire::ErrorBody::from_error(&e).to_json().to_string(),
                );
                return Err(e);
            }
        };

        // The target ACL and bearer token may be reloaded while a slow DNS/TCP
        // dial is in progress. Never publish a session based on stale auth.
        let _authz_gate = self
            .authz_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let current_token = req
            .header(wire::H_PEER_AUTH)
            .and_then(|v| v.split_once(' '))
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("Bearer"))
            .map(|(_, token)| token)
            .unwrap_or("");
        if !self.registry.accepting() {
            let _ = backend.shutdown(std::net::Shutdown::Both);
            let e = Error::new(wire::ERR_DRAINING, "stopped").retryable(true);
            self.registry.fail_create(
                &idem_key,
                e.status(),
                wire::ErrorBody::from_error(&e).to_json().to_string(),
            );
            return Err(e);
        }
        let current_peer = self.auth.inbound(&peer.id).filter(|p| p.enabled);
        let Some(current_peer) = current_peer else {
            let _ = backend.shutdown(std::net::Shutdown::Both);
            let e = Error::new(wire::ERR_UNAUTHORIZED, "invalid credentials");
            self.registry.fail_create(
                &idem_key,
                e.status(),
                wire::ErrorBody::from_error(&e).to_json().to_string(),
            );
            return Err(e);
        };
        if !self.bind_cred(&current_peer.id, current_token) {
            let _ = backend.shutdown(std::net::Shutdown::Both);
            let e = Error::new(wire::ERR_UNAUTHORIZED, "invalid credentials");
            self.registry.fail_create(
                &idem_key,
                e.status(),
                wire::ErrorBody::from_error(&e).to_json().to_string(),
            );
            return Err(e);
        }
        if !current_peer
            .allowed_targets
            .iter()
            .any(|t| t == &creq.target_id)
        {
            let _ = backend.shutdown(std::net::Shutdown::Both);
            let e = Error::new(wire::ERR_TARGET_FORBIDDEN, "creation refused");
            self.registry.fail_create(
                &idem_key,
                e.status(),
                wire::ErrorBody::from_error(&e).to_json().to_string(),
            );
            return Err(e);
        }

        let session_id = match crate::util::random_id(24) {
            Ok(id) => id,
            Err(error) => {
                let error = crate::util::random_error(error);
                self.registry.fail_create(
                    &idem_key,
                    error.status(),
                    wire::ErrorBody::from_error(&error).to_json().to_string(),
                );
                return Err(error);
            }
        };
        let session_token = match crate::util::random_id(32) {
            Ok(token) => token,
            Err(error) => {
                let error = crate::util::random_error(error);
                self.registry.fail_create(
                    &idem_key,
                    error.status(),
                    wire::ErrorBody::from_error(&error).to_json().to_string(),
                );
                return Err(error);
            }
        };
        let session = Session::new_with_ingress_instance_id(
            session_id,
            session_token,
            self.cfg.node.instance_id.clone(),
            creq.ingress_instance_id.clone(),
            current_peer.id.clone(),
            creq.target_id.clone(),
            creq.mode,
            limits,
            self.cfg.transport.receipt_limit_per_session,
            backend,
            self.metrics.clone(),
        );
        let grace = if creq.recovery_enabled {
            self.cfg
                .transport
                .recovery_grace
                .min(Duration::from_millis(creq.recovery_grace_ms))
        } else {
            Duration::ZERO
        };
        session.enable_recovery(grace);
        if let Err(reason) = self.registry.insert_created(session.clone(), &idem_key) {
            let error = Error::new(wire::ERR_QUOTA_EXCEEDED, reason).retryable(true);
            self.registry.fail_create(
                &idem_key,
                error.status(),
                wire::ErrorBody::from_error(&error).to_json().to_string(),
            );
            return Err(error);
        }
        self.watch_unattached(session.clone());

        let resp = wire::CreateResponse {
            node_id: self.cfg.node.id.clone(),
            instance_id: self.cfg.node.instance_id.clone(),
            session_id: session.id.clone(),
            session_token: session.token.clone(),
            epoch: session.epoch(),
            mode: creq.mode,
            recovery_enabled: creq.recovery_enabled,
            recovery_grace_ms: grace.as_millis() as u64,
            limits,
            unattached_timeout_ms: self.cfg.transport.unattached_timeout.as_millis() as u64,
        };
        let out = resp.to_json().to_string();
        self.registry
            .complete_create(&idem_key, session.id.clone(), out.clone());
        Ok((201, out))
    }

    /// Drops a session whose carrier never arrived, so a failed create does
    /// not pin a database connection.
    pub(super) fn watch_unattached(&self, session: Arc<Session>) {
        super::unattached::schedule(
            &self.registry,
            &session,
            self.cfg.transport.unattached_timeout,
        );
    }

    pub(super) fn session_from_path(&self, req: &Request) -> Result<(Arc<Session>, String)> {
        let (lookup, action) = self.lookup_from_path(req)?;
        match lookup {
            super::SessionLookup::Live(session) => Ok((session, action)),
            super::SessionLookup::Tombstone(tombstone) => {
                Err(Self::tombstone_refusal(req, &tombstone, &action))
            }
        }
    }

    fn tombstone_refusal(
        req: &Request,
        tombstone: &crate::session::Tombstone,
        action: &str,
    ) -> Error {
        if action != "resume" {
            match Self::epoch_from_query(req) {
                Ok(epoch) if epoch == tombstone.epoch => {}
                Ok(_) => return Error::new(wire::ERR_STALE_EPOCH, "epoch"),
                Err(e) => return e,
            }
        }
        tombstone.terminal_error()
    }

    pub(super) fn lookup_from_path(&self, req: &Request) -> Result<(super::SessionLookup, String)> {
        let rest = req
            .path
            .strip_prefix(wire::PATH_SESSIONS)
            .unwrap_or("")
            .trim_start_matches('/');
        let mut parts = rest.split('/');
        let sid = parts.next().unwrap_or("");
        let action = parts.next().unwrap_or("").to_string();
        if !wire::valid_session_id(sid) {
            return Err(Error::new(wire::ERR_SESSION_NOT_FOUND, "not found").closed(true));
        }
        let peer = self.authenticate(req)?;
        let lookup = self
            .registry
            .get_any(sid)
            .ok_or_else(|| Error::new(wire::ERR_SESSION_NOT_FOUND, "not found").closed(true))?;
        let (owner_peer, token, target_id) = match &lookup {
            super::SessionLookup::Live(session) => (
                session.owner_peer.as_str(),
                session.token.as_str(),
                session.target_id.as_str(),
            ),
            super::SessionLookup::Tombstone(tombstone) => (
                tombstone.owner_peer.as_str(),
                tombstone.token.as_str(),
                tombstone.target_id.as_str(),
            ),
        };
        if owner_peer != peer.id {
            return Err(Error::new(wire::ERR_SESSION_NOT_FOUND, "not found").closed(true));
        }
        let supplied_token = req.header(wire::H_SESSION_TOKEN).unwrap_or("");
        if !constant_time_eq(token.as_bytes(), supplied_token.as_bytes()) {
            return Err(Error::new(
                wire::ERR_UNAUTHORIZED,
                "invalid session credentials",
            ));
        }
        if !peer.allowed_targets.iter().any(|t| t == target_id) {
            if let super::SessionLookup::Live(session) = &lookup {
                session.close(
                    Error::new(wire::ERR_TARGET_FORBIDDEN, "authorization revoked").closed(true),
                );
            }
            return Err(
                Error::new(wire::ERR_TARGET_FORBIDDEN, "authorization revoked").closed(true),
            );
        }
        Ok((lookup, action))
    }

    fn tombstone_request(
        &self,
        req: &Request,
        tombstone: &crate::session::Tombstone,
        action: &str,
    ) -> Result<String> {
        if action == "resume" || (action != "ack" && !action.is_empty()) {
            return Err(Self::tombstone_refusal(req, tombstone, action));
        }
        let epoch = Self::epoch_from_query(req)?;
        if epoch != tombstone.epoch {
            return Err(Error::new(wire::ERR_STALE_EPOCH, "epoch"));
        }
        if action.is_empty() {
            return Ok(Self::delete_body(
                &tombstone.id,
                &tombstone.instance_id,
                epoch,
            ));
        }
        self.metrics.explicit_ack_received();
        let stream = req.header(wire::H_STREAM_ID).unwrap_or("");
        if !tombstone.closed_normally_for(epoch, stream) {
            return Err(tombstone.terminal_error());
        }
        let v = json::parse_bytes(&req.body)
            .map_err(|_| Error::new(wire::ERR_BAD_FRAME, "invalid control body"))?;
        let q = AckRequest::from_json(&v)?;
        if let Some(s) = v.get("stream_id").and_then(Json::as_str) {
            if !s.is_empty() && s != stream {
                return Err(Error::new(wire::ERR_BAD_FRAME, "stream mismatch"));
            }
        }
        Ok(AckResponse {
            session_id: tombstone.id.clone(),
            instance_id: tombstone.instance_id.clone(),
            epoch,
            stream_id: tombstone.stream_id.clone(),
            mode: tombstone.mode,
            ack_up_offset: tombstone.ack_up,
            up_fin_applied: tombstone.up_fin,
            down_ack_offset: tombstone.down_ack,
            down_fin_acked: tombstone.down_fin_acked,
            probe_id: q.probe_id,
            data_tx_blocked: false,
            data_rx_blocked: false,
            backpressure_reason: "none".to_string(),
        }
        .to_json()
        .to_string())
    }

    fn delete_body(id: &str, instance_id: &str, epoch: u64) -> String {
        json::obj(vec![
            ("session_id", Json::from(id)),
            ("instance_id", Json::from(instance_id)),
            ("epoch", Json::from(epoch.to_string())),
            ("closed", Json::Bool(true)),
        ])
        .to_string()
    }

    pub(super) fn epoch_from_query(req: &Request) -> Result<u64> {
        let raw = req
            .query("epoch")
            .ok_or_else(|| Error::new(wire::ERR_STALE_EPOCH, "epoch"))?;
        json::canonical_offset(raw).ok_or_else(|| Error::new(wire::ERR_STALE_EPOCH, "epoch"))
    }

    pub(super) fn handle_session_post(&self, req: &Request) -> Result<String> {
        let (session, action) = match self.lookup_from_path(req)? {
            (super::SessionLookup::Live(session), action) => (session, action),
            (super::SessionLookup::Tombstone(tombstone), action) => {
                return self.tombstone_request(req, &tombstone, &action);
            }
        };
        if action == "resume" {
            if session.is_closed() {
                return Err(session
                    .terminal_error()
                    .unwrap_or_else(|| Error::new(wire::ERR_SESSION_CLOSED, "session closed"))
                    .closed(true));
            }
            let v = json::parse_bytes(&req.body)
                .map_err(|_| Error::new(wire::ERR_BAD_FRAME, "invalid control body"))?;
            let q = ResumeRequestWire::from_json(&v)?.inner;
            if !self.cfg.transports().contains(&q.transport) {
                return Err(Error::new(wire::ERR_TRANSPORT_UNSUPPORTED, "transport"));
            }
            let response = session.resume(&q, self.cfg.transport.recovery_barrier_timeout)?;
            self.metrics.resume_succeeded();
            return Ok(response.to_json().to_string());
        }
        let epoch = Self::epoch_from_query(req)?;
        if epoch != session.epoch() {
            return Err(Error::new(wire::ERR_STALE_EPOCH, "epoch"));
        }
        match action.as_str() {
            "ack" => self.handle_ack(&session, epoch, req),
            "up" => self.handle_up(&session, epoch, req),
            "fin" => self.handle_fin(&session, epoch, req),
            other => Err(Error::new(
                wire::ERR_BAD_FRAME,
                format!("unknown session action {other:?}"),
            )),
        }
    }

    pub(super) fn handle_ack(
        &self,
        session: &Arc<Session>,
        epoch: u64,
        req: &Request,
    ) -> Result<String> {
        self.metrics.explicit_ack_received();
        let stream = req.header(wire::H_STREAM_ID).unwrap_or("");
        let mode = session.current_mode();
        let closed_normally = session.closed_normally_for(epoch, stream);
        if !closed_normally {
            session.check_stream(epoch, stream)?;
        }
        let v = json::parse_bytes(&req.body)
            .map_err(|_| Error::new(wire::ERR_BAD_FRAME, "invalid control body"))?;
        let q = AckRequest::from_json(&v)?;
        if let Some(s) = v.get("stream_id").and_then(Json::as_str) {
            if !s.is_empty() && s != stream {
                return Err(Error::new(wire::ERR_BAD_FRAME, "stream mismatch"));
            }
        }
        if !closed_normally {
            session.apply_up_confirmation(q.up_confirmed_offset)?;
            session.apply_down_ack(q.down_delivered_offset, q.down_fin_applied)?;
            session.note_ack_control(&q.heartbeat_nonce, &q.probe_id, q.ready_received);
        }
        let snap = session.snapshot();
        let (data_tx_blocked, backpressure_reason, data_rx_blocked) = session.flow_control_state();
        Ok(AckResponse {
            session_id: snap.session_id,
            instance_id: snap.instance_id,
            epoch,
            // Carrier suspend/resume may race this response. Echo the binding
            // validated at request entry instead of mutable snapshot fields.
            stream_id: stream.to_string(),
            mode,
            ack_up_offset: snap.ack_up_offset,
            up_fin_applied: snap.up_fin_applied,
            down_ack_offset: snap.down_ack_offset,
            down_fin_acked: snap.down_fin_acked,
            probe_id: q.probe_id,
            data_tx_blocked,
            data_rx_blocked,
            backpressure_reason,
        }
        .to_json()
        .to_string())
    }

    pub(super) fn handle_up(
        &self,
        session: &Arc<Session>,
        epoch: u64,
        req: &Request,
    ) -> Result<String> {
        self.metrics.post_received();
        let _inflight = session.try_acquire_up().ok_or_else(|| {
            Error::new(
                wire::ERR_WINDOW_EXCEEDED,
                "upstream in-flight window exceeded",
            )
            .retryable(true)
        })?;
        let stream = req.header(wire::H_STREAM_ID).unwrap_or("");
        let mode = session.current_mode();
        session.check_stream(epoch, stream)?;
        if mode != Mode::HttpSse {
            return Err(Error::new(wire::ERR_TRANSPORT_MISMATCH, "mode"));
        }
        let offset = req
            .header(wire::H_OFFSET)
            .and_then(json::canonical_offset)
            .ok_or_else(|| Error::new(wire::ERR_BAD_FRAME, "frame headers"))?;
        let length: usize = req
            .header(wire::H_LENGTH)
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| Error::new(wire::ERR_BAD_FRAME, "frame headers"))?;
        if length == 0 || length > session.limits.max_frame_size {
            return Err(Error::new(wire::ERR_FRAME_TOO_LARGE, "frame too large"));
        }
        if req.body.len() != length {
            return Err(Error::new(wire::ERR_BAD_FRAME, "frame headers"));
        }
        let _codec = match self.codec_for(&session.owner_peer) {
            Some(codec) => Some(
                codec
                    .try_acquire(i64::try_from(length).unwrap_or(i64::MAX))
                    .ok_or_else(|| {
                        Error::new(wire::ERR_BUFFER_EXHAUSTED, "codec budget").retryable(true)
                    })?,
            ),
            None => None,
        };
        if req.header("content-encoding").is_some() {
            return Err(Error::new(
                wire::ERR_BAD_FRAME,
                "content encoding is not allowed",
            ));
        }
        if req
            .header("content-length")
            .and_then(|v| v.parse::<usize>().ok())
            != Some(length)
        {
            return Err(Error::new(wire::ERR_BAD_FRAME, "content length"));
        }
        if req.header("content-type") != Some("application/octet-stream") {
            return Err(Error::new(wire::ERR_BAD_FRAME, "frame headers"));
        }
        let digest = crate::util::hex(&crate::util::sha256::digest(&req.body));
        if req.header(wire::H_SHA256) != Some(digest.as_str()) {
            return Err(Error::new(wire::ERR_BAD_DIGEST, "digest"));
        }
        // Piggybacked downstream acknowledgement, so the SSE carrier needs no
        // extra round trip to report progress.
        let down = optional_header_offset(req, wire::H_ACK_DOWN_OFFSET)?;
        let up = optional_header_offset(req, wire::H_CONFIRM_UP_OFFSET)?;
        // Apply both piggyback acknowledgements; malformed, out-of-range, and
        // non-boundary confirmations are protocol errors, never ignored.
        session.apply_up_confirmation(up)?;
        session.apply_down_ack(down, false)?;
        self.metrics.piggyback_acknowledged();
        if let Err(error) = session.ingest_up(epoch, offset, &req.body) {
            if error.code == wire::ERR_FRAME_CONFLICT {
                let terminal = Error::new(&error.code, error.message.clone()).closed(true);
                session.close(terminal.clone());
                return Err(terminal.remote_status(409));
            }
            return Err(error);
        }
        session.note_control("");
        let snap = session.snapshot();
        Ok(json::obj(vec![
            ("session_id", Json::from(snap.session_id)),
            ("instance_id", Json::from(snap.instance_id)),
            ("epoch", Json::from(epoch.to_string())),
            ("frame_accepted", Json::Bool(true)),
            ("ack_up_offset", Json::from(snap.ack_up_offset.to_string())),
            (
                "down_ack_offset",
                Json::from(snap.down_ack_offset.to_string()),
            ),
            (
                "up_receive_limit",
                Json::from(session.up_receive_limit(snap.ack_up_offset).to_string()),
            ),
            ("up_fin_applied", Json::Bool(snap.up_fin_applied)),
            ("stream_id", Json::from(stream)),
            (
                "transport",
                json::obj(vec![("mode", Json::from(mode.as_str()))]),
            ),
        ])
        .to_string())
    }

    pub(super) fn handle_fin(
        &self,
        session: &Arc<Session>,
        epoch: u64,
        req: &Request,
    ) -> Result<String> {
        let stream = req.header(wire::H_STREAM_ID).unwrap_or("");
        let mode = session.current_mode();
        session.check_stream(epoch, stream)?;
        let v = json::parse_bytes(&req.body)
            .map_err(|_| Error::new(wire::ERR_BAD_FRAME, "invalid control body"))?;
        v.reject_unknown_fields(&["direction", "final_offset"])
            .map_err(|e| Error::new(wire::ERR_BAD_FRAME, e))?;
        if v.str_field("direction")? != "up" {
            return Err(Error::new(wire::ERR_BAD_FRAME, "FIN"));
        }
        let offset = v.offset("final_offset")?;
        if let Err(error) = session.ingest_up_fin(epoch, offset) {
            if error.code == wire::ERR_FRAME_CONFLICT {
                let terminal = Error::new(&error.code, error.message.clone()).closed(true);
                session.close(terminal.clone());
                return Err(terminal.remote_status(409));
            }
            return Err(error);
        }
        session.note_control("");
        let snap = session.snapshot();
        Ok(FinResponse {
            session_id: snap.session_id,
            instance_id: snap.instance_id,
            epoch,
            stream_id: stream.to_string(),
            mode,
            up_fin_applied: snap.up_fin_applied,
        }
        .to_json()
        .to_string())
    }

    pub(super) fn handle_delete(&self, req: &Request) -> Result<String> {
        let (session, action) = match self.lookup_from_path(req)? {
            (super::SessionLookup::Live(session), action) => (session, action),
            (super::SessionLookup::Tombstone(tombstone), action) => {
                if !action.is_empty() {
                    return Err(Error::new(wire::ERR_BAD_FRAME, "action"));
                }
                return self.tombstone_request(req, &tombstone, &action);
            }
        };
        if !action.is_empty() {
            return Err(Error::new(wire::ERR_BAD_FRAME, "action"));
        }
        let epoch = Self::epoch_from_query(req)?;
        if epoch != session.epoch() {
            return Err(Error::new(wire::ERR_STALE_EPOCH, "epoch"));
        }
        if !session.is_closed() {
            session.close(Error::local("deleted by the ingress"));
        }
        self.registry.remove(&session.id);
        Ok(Self::delete_body(&session.id, &session.instance_id, epoch))
    }
}

pub(super) fn resolve_target(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<Vec<std::net::SocketAddr>> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(vec![std::net::SocketAddr::new(ip, port)]);
    }
    let (tx, rx) = std::sync::mpsc::channel();
    let name = host.to_string();
    std::thread::Builder::new()
        .name("egress-resolve".into())
        .spawn(move || {
            let result = (name.as_str(), port)
                .to_socket_addrs()
                .map(|addrs| addrs.collect::<Vec<_>>());
            let _ = tx.send(result);
        })
        .map_err(|e| Error::new(wire::ERR_DIAL_FAILED, format!("resolve {host}: {e}")))?;
    match rx.recv_timeout(timeout) {
        Ok(Ok(addrs)) => Ok(addrs),
        Ok(Err(e)) => Err(Error::new(
            wire::ERR_DIAL_FAILED,
            format!("resolve {host}: {e}"),
        )),
        Err(_) => Err(Error::new(
            wire::ERR_DIAL_FAILED,
            format!("resolve {host}: timed out"),
        )),
    }
}

fn dial_target(target: &Target, timeout: Duration) -> Result<TcpStream> {
    let ipv6_only = match target.network.as_str() {
        "" | "tcp" => None,
        "tcp4" => Some(false),
        "tcp6" => Some(true),
        _ => {
            return Err(Error::new(
                wire::ERR_TARGET_FORBIDDEN,
                format!("target network {:?} is not supported", target.network),
            ))
        }
    };
    let (host, port) = config::parse_hostport(&target.address)
        .map_err(|e| Error::new(wire::ERR_TARGET_FORBIDDEN, e))?;
    let addrs = resolve_target(&host, port, timeout)?;
    if addrs.is_empty() {
        return Err(Error::new(
            wire::ERR_DIAL_FAILED,
            "target resolved to no address",
        ));
    }
    let mut family_matches = Vec::new();
    for a in addrs {
        if ipv6_only.is_some_and(|ipv6| a.is_ipv6() != ipv6) {
            continue;
        }
        family_matches.push(a);
    }
    if family_matches.is_empty() {
        return Err(Error::new(
            wire::ERR_DIAL_FAILED,
            format!("target resolved to no {} address", target.network),
        ));
    }
    let mut allowed = Vec::new();
    for a in family_matches {
        if target.allowed_cidrs.is_empty()
            || target
                .allowed_cidrs
                .iter()
                .any(|c| config::cidr_contains(c, a.ip()))
        {
            allowed.push(a);
        }
    }
    if allowed.is_empty() {
        return Err(Error::new(
            wire::ERR_TARGET_FORBIDDEN,
            "target resolved outside allowed_cidrs",
        ));
    }
    let mut last = None;
    for a in allowed {
        match TcpStream::connect_timeout(&a, timeout) {
            Ok(s) => {
                let _ = crate::net::set_nodelay(&s);
                return Ok(s);
            }
            Err(e) => last = Some(e),
        }
    }
    Err(Error::new(
        wire::ERR_DIAL_FAILED,
        format!("dial {}: {}", target.address, last.unwrap()),
    ))
}

impl Server {
    pub(super) fn create_record_limits(&self, max_sessions: u32) -> super::RecordLimits {
        match self.metrics.resource_manager() {
            Some(resources) => super::RecordLimits::from_budget(
                resources.egress_metadata_limit(),
                resources.egress_session_slots(),
                resources.session_metadata_cost(),
                self.cfg.inbound.iter().filter(|p| p.enabled).count(),
                max_sessions,
            ),
            None => super::RecordLimits::without_budget(max_sessions),
        }
    }
}
