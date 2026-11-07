//! The three carriers: the reverse tunnel handshake, the SSE event stream
//! and the WebSocket upgrade. Each ends by handing its session to the relay.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::net::http1::{self, Request};
use crate::net::BufferedConn;
use crate::session::Session;
use crate::transport::{ws_carrier, CarrierReader, CarrierWriter, Incoming, SharedWriter};
use crate::util::json::{self, Json};
use crate::wire::{self, ControlKind, Mode};

use super::accept::error_response;
use super::pump::{ready_control, run_downstream};
use super::{constant_time_eq, Server, SessionLease};

fn validate_ws_handshake(req: &Request) -> Result<()> {
    if !req.is_websocket_upgrade() {
        return Err(Error::new(
            wire::ERR_WS_HANDSHAKE_FAILED,
            "not a WebSocket upgrade",
        ));
    }
    if req.header("sec-websocket-version") != Some("13") {
        return Err(Error::new(
            wire::ERR_WS_HANDSHAKE_FAILED,
            "unsupported WebSocket version",
        ));
    }
    let key = req
        .header("sec-websocket-key")
        .ok_or_else(|| Error::new(wire::ERR_WS_HANDSHAKE_FAILED, "missing key"))?;
    if crate::util::base64::decode(key.trim())
        .map(|value| value.len() != 16)
        .unwrap_or(true)
    {
        return Err(Error::new(
            wire::ERR_WS_HANDSHAKE_FAILED,
            "malformed WebSocket key",
        ));
    }
    Ok(())
}

impl Server {
    /// Accepts a reverse tunnel: verify, upgrade, then hand the connection to
    /// the multiplexer. After this returns, the tunnel lives in the hub.
    pub(super) fn handle_reverse(
        &self,
        conn: BufferedConn,
        req: Request,
        permit: Option<super::ConnectionPermit>,
    ) -> Result<()> {
        if req.path.starts_with("/v1/reverse/") {
            return self.handle_reverse_http(conn, req);
        }
        let Some(hub) = &self.hub else {
            let mut conn = conn;
            let (status, body, extra) =
                error_response(&Error::new(wire::ERR_SESSION_NOT_FOUND, "not found"));
            let _ = http1::write_response(&mut conn, status, &extra, &body, false);
            return Ok(());
        };
        let reserved = match hub.reserve(&req, &self.cfg) {
            Ok(r) => r,
            Err(e) => {
                self.metrics.reverse_hub_rejected(&e.code);
                let status = e.status();
                let attrs = [
                    ("remote", crate::slog::V::from(conn.describe())),
                    ("code", e.code.as_str().into()),
                    ("reason", e.message.as_str().into()),
                ];
                if status == 401 || status == 403 || e.code == wire::ERR_TUNNEL_CONFLICT {
                    crate::slog::warn("reverse tunnel rejected", &attrs);
                } else {
                    crate::slog::debug("reverse tunnel rejected", &attrs);
                }
                let (status, body, extra) = error_response(&e);
                let mut conn = conn;
                let _ = http1::write_response(&mut conn, status, &extra, &body, false);
                return Ok(());
            }
        };
        let mut conn = conn;
        Self::write_reverse_tunnel_upgrade(&mut conn, &reserved.headers)?;
        let guard = permit.map(|p| Box::new(p) as Box<dyn std::any::Any + Send + Sync>);
        hub.register(reserved, conn, &self.cfg, guard)
    }

    /// The reverse peer has authenticated in `hub.reserve`; its socket is now
    /// a long-lived tunnel, so the pre-authentication deadline must not leak
    /// past the HTTP upgrade.
    fn write_reverse_tunnel_upgrade(
        conn: &mut BufferedConn,
        headers: &[(String, String)],
    ) -> std::io::Result<()> {
        conn.set_read_deadline(None);
        http1::write_upgrade(conn, headers)
    }

    fn admit_reverse_request(
        &self,
        conn: &mut BufferedConn,
        hub: &crate::tunnel::Hub,
        req: &Request,
        id: &str,
        control: bool,
    ) -> std::result::Result<Option<crate::tunnel::ReverseAdmission>, ()> {
        let Ok(peer) = hub.http_peer(req, id, &self.cfg) else {
            return Ok(None);
        };
        match hub.admit_request(req, &peer, control) {
            Ok(admission) => Ok(admission),
            Err((e, slot)) => {
                if slot {
                    self.metrics.admission_rejected();
                }
                let (st, b, h) = error_response(&e);
                let _ = http1::write_response(conn, st, &h, &b, false);
                Err(())
            }
        }
    }

    fn handle_reverse_http(&self, mut conn: BufferedConn, mut req: Request) -> Result<()> {
        let path = req.path.clone();
        let rest = path.strip_prefix("/v1/reverse/").unwrap_or("");
        let mut parts = rest.split('/');
        let id = parts.next().unwrap_or("").to_string();
        let action = parts.next().unwrap_or("").to_string();
        if id.is_empty() || parts.next().is_some() {
            let e = Error::new(wire::ERR_BAD_FRAME, "not found");
            let (st, b, h) = error_response(&e);
            let _ = http1::write_response(&mut conn, st, &h, &b, false);
            return Ok(());
        }
        let Some(hub) = &self.hub else {
            let e = Error::new(wire::ERR_TUNNEL_NOT_FOUND, "tunnel not found");
            let (st, b, h) = error_response(&e);
            let _ = http1::write_response(&mut conn, st, &h, &b, false);
            return Ok(());
        };
        if action == "open" {
            if req.method != "POST" {
                let e = Error::new(wire::ERR_BAD_FRAME, "method");
                let (_, b, mut h) = error_response(&e);
                h.push(("Allow".into(), "POST".into()));
                let _ = http1::write_response(&mut conn, 405, &h, &b, false);
                return Ok(());
            }
            let transport = req
                .header("x-dbb-tunnel-transport")
                .unwrap_or("")
                .to_string();
            match hub.open_http(&req, &self.cfg, &id, &transport) {
                Ok(mut h) => {
                    h.push(("Content-Length".into(), "0".into()));
                    http1::write_response(&mut conn, 200, &h, b"", false)
                        .map_err(|e| Error::local(e.to_string()))?;
                }
                Err(e) => {
                    let (st, b, h) = error_response(&e);
                    let _ = http1::write_response(&mut conn, st, &h, &b, false);
                }
            }
            return Ok(());
        }
        if action == "up" {
            if req.method != "POST" {
                let e = Error::new(wire::ERR_BAD_FRAME, "method");
                let (_, b, mut h) = error_response(&e);
                h.push(("Allow".into(), "POST".into()));
                let _ = http1::write_response(&mut conn, 405, &h, &b, false);
                return Ok(());
            }
            let Ok(_admission) = self.admit_reverse_request(&mut conn, hub, &req, &id, false)
            else {
                return Ok(());
            };
            if let Err(e) = http1::read_request_body(&mut conn, &mut req, 128 * 1024) {
                let e = Error::new(wire::ERR_FRAME_TOO_LARGE, e.to_string());
                let (st, b, h) = error_response(&e);
                let _ = http1::write_response(&mut conn, st, &h, &b, false);
                return Ok(());
            }
            let result = hub.http_up(&req, &id, &self.cfg);
            let off = match &result {
                Ok(n) => *n,
                Err(_) => hub
                    .http_confirm_up_offset(&req, &id, &self.cfg)
                    .unwrap_or(0),
            };
            let mut h = vec![
                (wire::H_CONFIRM_UP_OFFSET.to_string(), off.to_string()),
                ("Cache-Control".into(), "no-store".into()),
            ];
            match result {
                Ok(_) => {
                    h.push(("Content-Length".into(), "0".into()));
                    http1::write_response(&mut conn, 200, &h, b"", false).ok();
                }
                Err(e) => {
                    let (st, b, mut eh) = error_response(&e);
                    eh.extend(h);
                    let _ = http1::write_response(&mut conn, st, &eh, &b, false);
                }
            }
            return Ok(());
        }
        match action.as_str() {
            "events" if req.method == "GET" => {
                let generation = match hub.http_reader_start(&req, &id, &self.cfg) {
                    Ok(g) => g,
                    Err(e) => {
                        let (mut st, b, h) = error_response(&e);
                        if e.code == wire::ERR_BAD_ACK {
                            st = 409;
                        }
                        let _ = http1::write_response(&mut conn, st, &h, &b, false);
                        return Ok(());
                    }
                };
                let start = req
                    .header(wire::H_ACK_DOWN_OFFSET)
                    .unwrap_or("0")
                    .parse::<i64>()
                    .unwrap_or(0);
                let h = vec![
                    (
                        "Content-Type".into(),
                        "text/event-stream; charset=utf-8".into(),
                    ),
                    ("Cache-Control".into(), "no-store, no-transform".into()),
                    ("X-Accel-Buffering".into(), "no".into()),
                ];
                http1::write_stream_head(&mut conn, 200, &h)
                    .map_err(|e| Error::local(e.to_string()))?;
                conn.write_all(format!("event: ready\ndata: {start}\n\n").as_bytes())
                    .map_err(|e| Error::local(e.to_string()))?;
                conn.flush().ok();
                let deadline = std::time::Instant::now() + Duration::from_secs(300);
                let mut at = start;
                while std::time::Instant::now() < deadline {
                    if !hub.http_reader_current(&req, &id, &self.cfg, generation) {
                        break;
                    }
                    match hub.http_down(&req, &id, &self.cfg, at, Duration::from_millis(500)) {
                        Ok(Some((o, d))) => {
                            let n = d.len().min(32 * 1024);
                            let x = format!(
                                "id: {o}\ndata: {}\n\n",
                                crate::util::base64::encode(&d[..n])
                            );
                            conn.write_all(x.as_bytes())
                                .map_err(|e| Error::local(e.to_string()))?;
                            conn.flush().map_err(|e| Error::local(e.to_string()))?;
                            at = o + n as i64;
                        }
                        Ok(None) => break,
                        Err(_) => break,
                    }
                }
                return Ok(());
            }
            "poll" if req.method == "GET" => {
                let generation = match hub.http_reader_start(&req, &id, &self.cfg) {
                    Ok(g) => g,
                    Err(e) => {
                        let (mut st, b, h) = error_response(&e);
                        if e.code == wire::ERR_BAD_ACK {
                            st = 409;
                        }
                        let _ = http1::write_response(&mut conn, st, &h, &b, false);
                        return Ok(());
                    }
                };
                let start = req
                    .header(wire::H_ACK_DOWN_OFFSET)
                    .unwrap_or("0")
                    .parse::<i64>()
                    .unwrap_or(0);
                let deadline = std::time::Instant::now() + Duration::from_secs(25);
                let response = if !hub.http_reader_current(&req, &id, &self.cfg, generation) {
                    None
                } else {
                    let left = deadline.saturating_duration_since(std::time::Instant::now());
                    if left.is_zero() {
                        Some(Ok(None))
                    } else {
                        match hub.http_down(
                            &req,
                            &id,
                            &self.cfg,
                            start,
                            left.min(Duration::from_millis(500)),
                        ) {
                            Ok(Some(v)) => Some(Ok(Some(v))),
                            Ok(None) => Some(Ok(None)),
                            Err(e) => Some(Err(e)),
                        }
                    }
                };
                match response {
                    None => {}
                    Some(Ok(Some(_)))
                        if !hub.http_reader_current(&req, &id, &self.cfg, generation) => {}
                    Some(Ok(Some((o, d)))) => {
                        let h = vec![
                            ("Content-Type".into(), "application/octet-stream".into()),
                            ("X-DBB-Offset".into(), o.to_string()),
                            ("Cache-Control".into(), "no-store".into()),
                        ];
                        http1::write_response(&mut conn, 200, &h, &d, false).ok();
                    }
                    Some(Ok(None)) => {
                        let h = vec![
                            ("X-DBB-Offset".into(), start.to_string()),
                            ("Cache-Control".into(), "no-store".into()),
                        ];
                        http1::write_response(&mut conn, 204, &h, b"", false).ok();
                    }
                    Some(Err(e)) => {
                        let (mut st, b, h) = error_response(&e);
                        if e.code == wire::ERR_BAD_ACK {
                            st = 409;
                        }
                        http1::write_response(&mut conn, st, &h, &b, false).ok();
                    }
                }
                return Ok(());
            }
            "" if req.method == "DELETE" => {
                let Ok(_admission) = self.admit_reverse_request(&mut conn, hub, &req, &id, true)
                else {
                    return Ok(());
                };
                match hub.http_delete(&req, &id, &self.cfg) {
                    Ok(()) => {
                        http1::write_response(
                            &mut conn,
                            204,
                            &[("Cache-Control".into(), "no-store".into())],
                            b"",
                            false,
                        )
                        .ok();
                    }
                    Err(e) => {
                        let (mut st, b, h) = error_response(&e);
                        if e.code == wire::ERR_BAD_ACK {
                            st = 409;
                        }
                        http1::write_response(&mut conn, st, &h, &b, false).ok();
                    }
                }
                return Ok(());
            }
            _ => {}
        }
        if action != "open"
            && action != "up"
            && action != "events"
            && action != "poll"
            && !action.is_empty()
        {
            let e = Error::new(wire::ERR_BAD_FRAME, "not found");
            let (_, b, h) = error_response(&e);
            let _ = http1::write_response(&mut conn, 404, &h, &b, false);
            return Ok(());
        }
        let e = Error::new(wire::ERR_BAD_FRAME, "method");
        let (_, b, mut h) = error_response(&e);
        h.push((
            "Allow".into(),
            if action == "events" || action == "poll" {
                "GET"
            } else {
                "POST"
            }
            .into(),
        ));
        let _ = http1::write_response(&mut conn, 405, &h, &b, false);
        Ok(())
    }

    pub(super) fn handle_events(
        &self,
        conn: BufferedConn,
        req: Request,
        request_leases: super::accept::RequestResourceLeases,
    ) -> Result<()> {
        let prepared = self.session_from_path(&req).and_then(|(session, action)| {
            if action != "events" {
                return Err(Error::new(wire::ERR_BAD_FRAME, "action"));
            }
            let epoch = Self::epoch_from_query(&req)?;
            if epoch != session.epoch() {
                return Err(Error::new(wire::ERR_STALE_EPOCH, "epoch"));
            }
            if session.current_mode() != Mode::HttpSse {
                return Err(Error::new(wire::ERR_TRANSPORT_MISMATCH, "mode"));
            }
            Ok(session)
        });
        let session = match prepared {
            Ok(s) => s,
            Err(e) => {
                let (status, body, mut extra) = error_response(&e);
                extra.push((
                    wire::H_INSTANCE_ID.to_string(),
                    self.cfg.node.instance_id.clone(),
                ));
                let mut conn = conn;
                let _ = http1::write_response(&mut conn, status, &extra, &body, false);
                return Ok(());
            }
        };
        let stream_id = crate::util::random_id(16).map_err(crate::util::random_error)?;
        session.attach(&stream_id)?;
        drop(request_leases);
        let carrier_epoch = session.epoch();
        // From here on the session is this handler's to clean up, however it
        // ends. A `?` below must not be able to leave it in the registry.
        let _lease = SessionLease::new(self.registry.clone(), session.id.clone());
        // A second handle on the socket: after a normal close the handler
        // watches it for the ingress closing the stream (see
        // linger_sse_normal_close).
        let peer_watch = conn.try_clone().ok();
        let mut sink = crate::transport::sse_carrier::SseEventSink::new(
            conn,
            self.cfg.transport.sse_write_idle_timeout,
        );
        sink.write_head(&self.cfg.node.instance_id)?;
        let ready = ready_control(&session, &stream_id, Mode::HttpSse);
        sink.send_control(&ready)?;
        let linger_session = session.clone();
        let writer = SharedWriter::new(Box::new(SseLingerSink {
            inner: sink,
            linger: Box::new(move || linger_session.is_closed() && linger_session.finished()),
            watch: peer_watch,
            limit: NORMAL_CLOSE_LINGER,
        }));
        let codec = self.codec_for(&session.owner_peer);
        run_downstream(&self.cfg, session.clone(), writer, codec)?;
        if session.epoch() != carrier_epoch
            || session.recovery_state() == crate::session::recovery::RecoveryState::Suspended
        {
            return Ok(());
        }
        // The upstream half arrives as POSTs; hold the session open until it
        // closes so the database connection is not dropped mid-stream.
        session.wait_until_closed(self.cfg.transport.shutdown_timeout);
        Ok(())
    }

    pub(super) fn handle_ws(
        &self,
        conn: BufferedConn,
        req: Request,
        request_leases: super::accept::RequestResourceLeases,
    ) -> Result<()> {
        let prepared = self.ws_preflight(&req);
        let (session, stream_id, is_check, _precheck_permit) = match prepared {
            Ok(v) => v,
            Err(e) => {
                let (status, body, mut extra) = error_response(&e);
                if is_check_request(&req) && e.code == wire::ERR_QUOTA_EXCEEDED {
                    extra.push(("Retry-After".to_string(), "1".to_string()));
                }
                extra.push((
                    wire::H_INSTANCE_ID.to_string(),
                    self.cfg.node.instance_id.clone(),
                ));
                let mut conn = conn;
                let _ = http1::write_response(&mut conn, status, &extra, &body, false);
                return Ok(());
            }
        };
        let mut headers = vec![
            ("Upgrade".to_string(), "websocket".to_string()),
            ("Connection".to_string(), "Upgrade".to_string()),
            (
                "Sec-WebSocket-Accept".to_string(),
                crate::net::ws::accept_key(req.header("sec-websocket-key").unwrap_or_default()),
            ),
            (
                "Sec-WebSocket-Protocol".to_string(),
                wire::WS_SUBPROTOCOL.to_string(),
            ),
            ("Cache-Control".to_string(), "no-store".to_string()),
            (
                wire::H_INSTANCE_ID.to_string(),
                self.cfg.node.instance_id.clone(),
            ),
        ];
        if is_check {
            conn.set_write_timeout(Some(Duration::from_secs(5)))?;
            let (mut reader, mut writer) = ws_carrier::accept(conn, &headers)?;
            reader.set_message_limit(16 * 1024);
            writer.set_write_timeout(Some(Duration::from_secs(1)))?;
            let hello = json::obj(vec![
                ("type", Json::from("hello")),
                ("protocol_version", Json::from(wire::PROTOCOL_VERSION)),
                ("node_id", Json::from(self.cfg.node.id.as_str())),
                (
                    "instance_id",
                    Json::from(self.cfg.node.instance_id.as_str()),
                ),
                (
                    "nonce",
                    Json::from(req.header(wire::H_WS_NONCE).unwrap_or("")),
                ),
                ("transport", Json::from("ws")),
            ]);
            writer.send_text(&hello.to_string())?;
            drop(request_leases);
            // The precheck ends here; a read for a moment gives the peer time
            // to take the hello before the socket closes.
            reader.set_read_deadline(Some(Instant::now() + Duration::from_secs(1)));
            let _ = reader.recv();
            reader.set_read_deadline(None);
            writer.set_write_timeout(None)?;
            writer.shutdown();
            return Ok(());
        }
        headers.push((wire::H_IMPLICIT_READY.to_string(), "1".to_string()));
        let Some(session) = session else {
            return Err(Error::new(wire::ERR_BAD_FRAME, "missing session"));
        };
        let _lease = SessionLease::new(self.registry.clone(), session.id.clone());
        conn.set_write_timeout(Some(Duration::from_secs(5)))?;
        let (mut reader, writer) = ws_carrier::accept(conn, &headers)?;
        reader.set_message_limit(
            session
                .limits
                .max_frame_size
                .saturating_add(56)
                .max(16 * 1024),
        );
        reader.set_message_timeout(Some(up_body_timeout(
            &self.cfg,
            session
                .limits
                .max_frame_size
                .saturating_add(wire::WS_HEADER_LEN),
        )));
        let mut writer = writer;
        writer.set_write_timeout(Some(Duration::from_secs(60)))?;
        writer.send_control(&ready_control(&session, &stream_id, Mode::Ws))?;
        drop(request_leases);
        self.run_ws_session(session.clone(), &mut reader, writer);
        Ok(())
    }

    /// Validates a WebSocket request and reserves the stream. Returns
    /// `(session, stream_id, is_check)`; `session` is `None` for a precheck.
    #[allow(clippy::type_complexity)]
    pub(super) fn ws_preflight<'a>(
        &'a self,
        req: &Request,
    ) -> Result<(
        Option<Arc<Session>>,
        String,
        bool,
        Option<super::ProbePermit<'a>>,
    )> {
        if req.method != "GET" {
            return Err(Error::new(wire::ERR_BAD_FRAME, "method"));
        }
        let peer = self.authenticate(req)?;
        self.check_instance(req)?;
        if !req.query.is_empty() {
            return Err(Error::new(wire::ERR_BAD_FRAME, "query not allowed"));
        }
        let offered = req
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("sec-websocket-protocol"))
            .any(|(_, value)| {
                value
                    .split(',')
                    .any(|protocol| protocol.trim() == wire::WS_SUBPROTOCOL)
            });
        if !offered {
            return Err(Error::new(
                wire::ERR_TRANSPORT_UNSUPPORTED,
                "subprotocol not offered",
            ));
        }
        if !self.cfg.transports().contains(&Mode::Ws) {
            return Err(Error::new(
                wire::ERR_TRANSPORT_UNSUPPORTED,
                "ws not allowed",
            ));
        }
        match req.header(wire::H_WS_PURPOSE).unwrap_or("") {
            "check" => {
                let permit = self
                    .probe_budget
                    .try_acquire_precheck_with_reason(
                        &peer.id,
                        self.cfg.inbound.iter().filter(|p| p.enabled).count(),
                    )
                    .map_err(|reason| {
                        Error::new(wire::ERR_QUOTA_EXCEEDED, reason).retryable(true)
                    })?;
                let nonce = req.header(wire::H_WS_NONCE).unwrap_or("");
                if nonce.is_empty() || nonce.len() > 128 {
                    return Err(Error::new(wire::ERR_BAD_FRAME, "nonce"));
                }
                validate_ws_handshake(req)?;
                Ok((None, String::new(), true, Some(permit)))
            }
            "session" => {
                let sid = req.header(wire::H_WS_SESSION_ID).unwrap_or("");
                let lookup = self.registry.get_any(sid).ok_or_else(|| {
                    Error::new(wire::ERR_SESSION_NOT_FOUND, "not found").closed(true)
                })?;
                let (owner, token, target) = match &lookup {
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
                if owner != peer.id {
                    return Err(Error::new(wire::ERR_SESSION_NOT_FOUND, "not found").closed(true));
                }
                let supplied_token = req.header(wire::H_SESSION_TOKEN).unwrap_or("");
                if !constant_time_eq(token.as_bytes(), supplied_token.as_bytes()) {
                    return Err(Error::new(wire::ERR_UNAUTHORIZED, "session"));
                }
                if !peer.allowed_targets.iter().any(|allowed| allowed == target) {
                    if let super::SessionLookup::Live(session) = &lookup {
                        session.close(
                            Error::new(wire::ERR_TARGET_FORBIDDEN, "authorization revoked")
                                .closed(true),
                        );
                    }
                    return Err(
                        Error::new(wire::ERR_TARGET_FORBIDDEN, "authorization revoked")
                            .closed(true),
                    );
                }
                let session = match lookup {
                    super::SessionLookup::Live(session) => session,
                    super::SessionLookup::Tombstone(tombstone) => {
                        return Err(tombstone.terminal_error());
                    }
                };
                if session.is_closed() {
                    return Err(session
                        .terminal_error()
                        .unwrap_or_else(|| Error::new(wire::ERR_SESSION_CLOSED, "session closed"))
                        .closed(true));
                }
                validate_ws_handshake(req)
                    .map_err(|e| Error::new(wire::ERR_BAD_FRAME, e.message))?;
                let epoch = req
                    .header(wire::H_WS_EPOCH)
                    .and_then(json::canonical_offset)
                    .ok_or_else(|| Error::new(wire::ERR_TRANSPORT_MISMATCH, "mode"))?;
                if session.current_mode() != Mode::Ws {
                    return Err(Error::new(wire::ERR_TRANSPORT_MISMATCH, "mode"));
                }
                if epoch != session.epoch() {
                    return Err(Error::new(wire::ERR_STALE_EPOCH, "epoch"));
                }
                let stream_id = crate::util::random_id(16).map_err(crate::util::random_error)?;
                session.attach(&stream_id)?;
                Ok((Some(session), stream_id, false, None))
            }
            _ => Err(Error::new(wire::ERR_BAD_FRAME, "purpose")),
        }
    }

    pub(super) fn run_ws_session(
        &self,
        session: Arc<Session>,
        reader: &mut dyn crate::transport::CarrierReader,
        writer: ws_carrier::WsCarrierWriter,
    ) {
        let epoch = session.epoch();
        let detect = self.cfg.transport.failure_detect_timeout;
        let cfg = self.cfg.clone();
        // Downstream runs on its own thread: it blocks on the backend socket
        // and on the carrier, and neither should stall upstream reads.
        let down_session = session.clone();
        let codec = self.codec_for(&session.owner_peer);
        let down_codec = codec.clone();
        let reader_done = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let linger_session = session.clone();
        let down_writer = LingerWriter {
            inner: writer.clone(),
            linger: Box::new(move || linger_session.is_closed() && linger_session.finished()),
            reader_done: reader_done.clone(),
            limit: NORMAL_CLOSE_LINGER,
        };
        let down = std::thread::Builder::new()
            .stack_size(crate::util::CONNECTION_STACK)
            .spawn(move || {
                let w = SharedWriter::new(Box::new(down_writer));
                let _ = run_downstream(&cfg, down_session, w, down_codec);
            })
            .ok();
        if down.is_none() {
            // Same reasoning as the ingress relay: no downstream pump means no
            // bytes, so end the session instead of waiting for a timeout.
            session.close(Error::local("cannot start the downstream pump"));
        }

        let mut closed_normally_at: Option<Instant> = None;
        loop {
            if session.is_closed() {
                // A normally finished session keeps reading until the peer
                // closes the carrier (bounded): see LingerWriter.
                if !session.finished() {
                    break;
                }
                let at = *closed_normally_at.get_or_insert_with(Instant::now);
                if at.elapsed() >= NORMAL_CLOSE_LINGER {
                    break;
                }
            }
            if session.epoch() != epoch {
                break;
            }
            if !session.is_closed() && session.control_expired(detect) {
                session.close(Error::new(wire::ERR_SESSION_CLOSED, "control timeout"));
                break;
            }
            match reader.recv() {
                Ok(Incoming::Data {
                    epoch: e,
                    offset,
                    payload,
                }) => {
                    if e != epoch {
                        if session.epoch() == epoch {
                            session.close(Error::new(wire::ERR_STALE_EPOCH, "epoch"));
                        }
                        break;
                    }
                    if session.epoch() != epoch {
                        break;
                    }
                    let _codec = match &codec {
                        Some(codec) => match take_ws_codec(
                            codec,
                            wire::WS_HEADER_LEN.saturating_add(payload.len()),
                            self.cfg.transport.backpressure_timeout,
                        ) {
                            Ok(lease) => Some(lease),
                            Err(err) => {
                                if session.epoch() == epoch {
                                    session.close(err);
                                }
                                break;
                            }
                        },
                        None => None,
                    };
                    let ingested = ingest_up_with_backpressure(
                        &session,
                        epoch,
                        offset,
                        &payload,
                        self.cfg.transport.backpressure_timeout,
                    );
                    if let Err(err) = ingested {
                        if std::env::var("DBBRIDGE_TRACE").is_ok() {
                            eprintln!("egress ingest_up({offset},{}) failed: {err}", payload.len());
                        }
                        if session.epoch() == epoch {
                            session.close(err);
                        }
                        break;
                    }
                    if std::env::var("DBBRIDGE_TRACE").is_ok() {
                        eprintln!("egress up offset={offset} len={}", payload.len());
                    }
                }
                Ok(Incoming::Control(c)) => {
                    let _codec = match &codec {
                        Some(codec) => match take_ws_codec(
                            codec,
                            WS_TEXT_COST,
                            self.cfg.transport.backpressure_timeout,
                        ) {
                            Ok(lease) => Some(lease),
                            Err(err) => {
                                if session.epoch() == epoch {
                                    session.close(err);
                                }
                                break;
                            }
                        },
                        None => None,
                    };
                    if c.kind == ControlKind::Error {
                        if session.epoch() == epoch {
                            session.close(Error {
                                code: c.code.unwrap_or_default(),
                                message: "peer ended the session".to_string(),
                                retryable: c.retryable,
                                session_closed: true,
                                remote_status: None,
                                trusted: false,
                                retry_after: Duration::ZERO,
                            });
                        }
                        break;
                    }
                }
                Ok(Incoming::Idle) => {}
                Ok(Incoming::Closed(_)) => {
                    if session.epoch() == epoch
                        && !session.is_closed()
                        && !session.suspend(epoch)
                        && !session.down_fin()
                    {
                        session.close(Error::new(wire::ERR_SESSION_CLOSED, "carrier closed"));
                    }
                    break;
                }
                Err(e) => {
                    let violation = matches!(
                        e.code.as_str(),
                        wire::ERR_BAD_FRAME
                            | wire::ERR_FRAME_TOO_LARGE
                            | wire::ERR_PROTOCOL_MISMATCH
                            | wire::ERR_WS_PROTOCOL_ERROR
                    );
                    if session.epoch() == epoch && !session.is_closed() {
                        if violation {
                            session.close(e.closed(true));
                            break;
                        }
                        if !session.suspend(epoch) {
                            session.close(e);
                        }
                    }
                    break;
                }
            }
        }
        if session.epoch() == epoch && !session.is_closed() && !session.suspend(epoch) {
            session.close(Error::local("carrier finished"));
        }
        {
            let (done, cv) = &*reader_done;
            *done.lock().unwrap() = true;
            cv.notify_all();
        }
        if let Some(d) = down {
            let _ = d.join();
        }
    }
}

pub(super) fn up_body_timeout(cfg: &crate::config::Config, length: usize) -> Duration {
    let limit = if cfg.transport.up_request_timeout.is_zero() {
        Duration::from_secs(30)
    } else {
        cfg.transport.up_request_timeout
    };
    limit.min(Duration::from_secs(5) + Duration::from_secs_f64(length as f64 / (16 << 10) as f64))
}

const WS_TEXT_COST: usize = 16 << 10;

fn take_ws_codec(
    codec: &Arc<crate::resource::budget::Budget>,
    cost: usize,
    stall: Duration,
) -> Result<crate::resource::budget::BudgetLease> {
    let cost = i64::try_from(cost).unwrap_or(i64::MAX);
    if let Some(lease) = codec.try_acquire(cost) {
        return Ok(lease);
    }
    let stall = if stall.is_zero() {
        Duration::from_secs(120)
    } else {
        stall
    };
    codec
        .acquire_timeout(cost, Some(stall))
        .map_err(|_| Error::new(wire::ERR_BUFFER_EXHAUSTED, "codec budget").closed(true))
}

/// How long the egress keeps the carrier (WebSocket or SSE stream) of a
/// normally finished session open for the ingress to close it first.
const NORMAL_CLOSE_LINGER: Duration = Duration::from_secs(1);

/// The SSE event sink of the downstream pump; see [`linger_sse_normal_close`].
struct SseLingerSink<W: crate::transport::CarrierWriter> {
    inner: W,
    /// Whether the session finished normally: only then does the end of
    /// the stream wait for the ingress.
    linger: Box<dyn Fn() -> bool + Send>,
    /// Read handle on the stream's socket (None when it could not be
    /// cloned: then the stream ends at once, as before).
    watch: Option<Box<dyn crate::net::Conn>>,
    limit: Duration,
}

impl<W: crate::transport::CarrierWriter> crate::transport::CarrierWriter for SseLingerSink<W> {
    fn send_data(&mut self, epoch: u64, offset: u64, payload: &[u8]) -> Result<Option<u64>> {
        self.inner.send_data(epoch, offset, payload)
    }
    fn send_control(&mut self, c: &crate::wire::Control) -> Result<()> {
        self.inner.send_control(c)
    }
    fn send_text(&mut self, text: &str) -> Result<()> {
        self.inner.send_text(text)
    }
    fn send_close(&mut self, code: u16, reason: &str) -> Result<()> {
        self.inner.send_close(code, reason)
    }
    fn shutdown(&mut self) {
        if (self.linger)() {
            if let Some(watch) = self.watch.take() {
                linger_sse_normal_close(watch, self.limit);
            }
        }
        self.inner.shutdown();
    }
}

fn linger_sse_normal_close(mut watch: Box<dyn crate::net::Conn>, limit: Duration) {
    let deadline = Instant::now() + limit;
    let mut buf = [0u8; 512];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || watch.set_read_timeout(Some(left)).is_err() {
            return;
        }
        match std::io::Read::read(&mut watch, &mut buf) {
            Ok(0) => return,
            Ok(_) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return,
        }
    }
}

struct LingerWriter<W: crate::transport::CarrierWriter> {
    inner: W,
    /// Whether the session finished normally (closed after both FINs were
    /// confirmed): only then does the close wait for the reader.
    linger: Box<dyn Fn() -> bool + Send>,
    reader_done: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    limit: Duration,
}

impl<W: crate::transport::CarrierWriter> crate::transport::CarrierWriter for LingerWriter<W> {
    fn send_data(&mut self, epoch: u64, offset: u64, payload: &[u8]) -> Result<Option<u64>> {
        self.inner.send_data(epoch, offset, payload)
    }
    fn send_control(&mut self, c: &crate::wire::Control) -> Result<()> {
        self.inner.send_control(c)
    }
    fn send_text(&mut self, text: &str) -> Result<()> {
        self.inner.send_text(text)
    }
    fn send_close(&mut self, code: u16, reason: &str) -> Result<()> {
        self.inner.send_close(code, reason)
    }
    fn shutdown(&mut self) {
        if (self.linger)() {
            let (done, cv) = &*self.reader_done;
            let deadline = Instant::now() + self.limit;
            let mut g = done.lock().unwrap();
            while !*g {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    break;
                }
                g = cv.wait_timeout(g, left).unwrap().0;
            }
        }
        self.inner.shutdown();
    }
}

fn is_check_request(req: &Request) -> bool {
    req.header(wire::H_WS_PURPOSE) == Some("check")
}

fn ingest_up_with_backpressure(
    session: &Session,
    epoch: u64,
    offset: u64,
    payload: &[u8],
    stall: Duration,
) -> crate::error::Result<()> {
    let stall_until = Instant::now() + stall;
    let mut rx_blocked = false;
    let result = loop {
        let generation = session.change_generation();
        let result = session.ingest_up(epoch, offset, payload);
        match &result {
            Err(err)
                if err.code == wire::ERR_WINDOW_EXCEEDED
                    && Instant::now() < stall_until
                    && session.epoch() == epoch
                    && !session.is_closed() =>
            {
                session.wait_for_change_since(generation, Duration::from_millis(5));
            }
            Err(err)
                if err.code == wire::ERR_BUFFER_EXHAUSTED
                    && Instant::now() < stall_until
                    && session.epoch() == epoch
                    && !session.is_closed() =>
            {
                if !rx_blocked {
                    rx_blocked = true;
                    session.set_transport_rx_blocked(epoch, true);
                }
                session.wait_for_change_since(generation, Duration::from_millis(5));
            }
            _ => break result,
        }
    };
    if rx_blocked {
        session.set_transport_rx_blocked(epoch, false);
    }
    result
}

#[cfg(test)]
mod reverse_upgrade_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::time::{Duration, Instant};

    #[test]
    fn clears_expired_auth_deadline_before_sending_101() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();

        let mut conn = BufferedConn::new(server);
        conn.set_read_deadline(Some(Instant::now() - Duration::from_secs(1)));
        let headers = [
            ("Upgrade".to_string(), "websocket".to_string()),
            ("Connection".to_string(), "Upgrade".to_string()),
        ];

        Server::write_reverse_tunnel_upgrade(&mut conn, &headers).unwrap();

        let mut response = Vec::new();
        let mut chunk = [0u8; 128];
        while !response.windows(4).any(|window| window == b"\r\n\r\n") {
            let n = peer.read(&mut chunk).unwrap();
            assert_ne!(n, 0, "server closed before complete 101 response");
            response.extend_from_slice(&chunk[..n]);
        }
        assert!(response.starts_with(b"HTTP/1.1 101 Switching Protocols\r\n"));

        let payload = b"payload-after-upgrade";
        peer.write_all(payload).unwrap();
        assert_eq!(conn.fill().unwrap(), payload.len());
        assert_eq!(conn.buffered(), payload);
    }
}

#[cfg(test)]
mod backpressure_tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    fn session_with_receipts(limit: u32) -> (Arc<Session>, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (backend, _) = listener.accept().unwrap();
        let session = Session::new(
            "s_test".to_string(),
            "token".to_string(),
            "instance".to_string(),
            "peer".to_string(),
            "target".to_string(),
            Mode::Ws,
            wire::Limits {
                max_frame_size: 1024,
                up_max_inflight_frames: 1,
                up_window_bytes: 1024,
                down_buffer_bytes: 1024,
                up_receipt_limit: limit,
                down_max_frames: 1,
            },
            limit,
            backend,
            Arc::new(crate::metrics::Metrics::new()),
        );
        session.attach("stream").unwrap();
        (session, client)
    }

    #[test]
    fn full_receipt_window_waits_for_the_peer_confirmation() {
        let (session, _client) = session_with_receipts(2);
        // Fill the receipt window with unconfirmed 1-byte frames.
        let mut next = 0u64;
        let refused = loop {
            assert!(next < 1024, "receipt window never filled");
            match session.ingest_up(1, next, b"x") {
                Ok(()) => next += 1,
                Err(err) => break err,
            }
        };
        assert_eq!(refused.code, wire::ERR_WINDOW_EXCEEDED);
        let full = next;
        let confirming = session.clone();
        let confirm = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(40));
            confirming.apply_up_confirmation(full).unwrap();
        });
        let started = Instant::now();
        ingest_up_with_backpressure(&session, 1, full, b"x", Duration::from_secs(5)).unwrap();
        assert!(started.elapsed() >= Duration::from_millis(30));
        confirm.join().unwrap();
        next = full + 1;
        while session.ingest_up(1, next, b"x").is_ok() {
            next += 1;
        }

        // Without a confirmation the frame is refused once the stall passes.
        let started = Instant::now();
        let err = ingest_up_with_backpressure(&session, 1, next, b"x", Duration::from_millis(60))
            .unwrap_err();
        assert_eq!(err.code, wire::ERR_WINDOW_EXCEEDED);
        assert!(started.elapsed() >= Duration::from_millis(60));
        assert!(!session.is_closed());
    }
}

#[cfg(test)]
mod linger_tests {
    /// An SSE stream of a normally finished session ends only once the
    /// ingress closed it (or after the bound), so the ACK response that
    /// finished the session reaches the ingress before the stream's EOF.
    #[test]
    fn sse_normal_close_waits_for_the_ingress_close_bounded() {
        use std::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let ingress = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (egress, _) = listener.accept().unwrap();

        // Ingress keeps the stream open: the wait is bounded by the limit.
        let started = Instant::now();
        super::linger_sse_normal_close(
            Box::new(egress.try_clone().unwrap()),
            Duration::from_millis(300),
        );
        let waited = started.elapsed();
        assert!(
            waited >= Duration::from_millis(250),
            "returned after {waited:?}"
        );
        assert!(waited < Duration::from_secs(2), "returned after {waited:?}");

        // Ingress closes: the wait ends at once.
        let closer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            drop(ingress);
        });
        let started = Instant::now();
        super::linger_sse_normal_close(Box::new(egress), Duration::from_secs(5));
        let waited = started.elapsed();
        closer.join().unwrap();
        assert!(waited < Duration::from_secs(2), "returned after {waited:?}");
    }

    use super::*;
    use crate::transport::CarrierWriter;
    use std::sync::Mutex;

    /// Records when the carrier was shut down.
    struct Probe(Arc<Mutex<Option<Instant>>>);

    impl CarrierWriter for Probe {
        fn send_data(&mut self, _: u64, _: u64, _: &[u8]) -> Result<Option<u64>> {
            Ok(None)
        }
        fn send_control(&mut self, _: &crate::wire::Control) -> Result<()> {
            Ok(())
        }
        fn shutdown(&mut self) {
            *self.0.lock().unwrap() = Some(Instant::now());
        }
    }

    type Done = Arc<(Mutex<bool>, std::sync::Condvar)>;

    fn writer(
        normal: bool,
        limit: Duration,
    ) -> (LingerWriter<Probe>, Arc<Mutex<Option<Instant>>>, Done) {
        let at = Arc::new(Mutex::new(None));
        let done: Done = Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let w = LingerWriter {
            inner: Probe(at.clone()),
            linger: Box::new(move || normal),
            reader_done: done.clone(),
            limit,
        };
        (w, at, done)
    }

    #[test]
    fn normal_close_waits_until_the_peer_closed_the_carrier() {
        let (mut w, at, done) = writer(true, Duration::from_secs(5));
        let started = Instant::now();
        let closer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            let (d, cv) = &*done;
            *d.lock().unwrap() = true;
            cv.notify_all();
        });
        w.shutdown();
        closer.join().unwrap();
        let shut = at.lock().unwrap().expect("carrier shut down");
        let waited = shut - started;
        assert!(
            waited >= Duration::from_millis(140),
            "closed after {waited:?}, before the peer"
        );
        assert!(waited < Duration::from_secs(2), "waited {waited:?}");
    }

    #[test]
    fn normal_close_is_bounded_when_the_peer_never_closes() {
        let (mut w, at, _done) = writer(true, Duration::from_millis(200));
        let started = Instant::now();
        w.shutdown();
        let waited = at.lock().unwrap().unwrap() - started;
        assert!(waited >= Duration::from_millis(190), "{waited:?}");
        assert!(waited < Duration::from_secs(1), "{waited:?}");
    }

    #[test]
    fn any_other_end_closes_at_once() {
        let (mut w, at, _done) = writer(false, Duration::from_secs(5));
        let started = Instant::now();
        w.shutdown();
        let waited = at.lock().unwrap().unwrap() - started;
        assert!(waited < Duration::from_millis(100), "{waited:?}");
    }
}
