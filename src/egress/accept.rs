//! Accepting a connection and routing one request on it.

use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::{self, Config};
use crate::error::{Error, Result};
use crate::net::http1::{self, Client, Request};
use crate::net::BufferedConn;
use crate::resource::budget::BudgetLease;
use crate::wire;

use super::{constant_time_eq, log_debug, log_info, Registry, Server};

pub(super) struct RequestResourceLeases {
    _budgets: Vec<BudgetLease>,
    _fair: Vec<crate::auth::FairLease>,
}

fn peer_codec_limit(
    resources: &crate::resource::manager::ResourceManager,
    snapshot: &crate::auth::Snapshot,
    peer: &str,
) -> i64 {
    let enabled = snapshot.inbound.iter().filter(|p| p.enabled).count();
    let known = snapshot.inbound.iter().any(|p| p.id == peer && p.enabled);
    resources.peer_codec_limit(known, enabled)
}

impl Server {
    pub(super) fn codec_for(&self, peer: &str) -> Option<Arc<crate::resource::budget::Budget>> {
        let resources = self.metrics.resource_manager()?;
        let snapshot = self.auth.snapshot();
        Some(resources.egress_codec_for(peer, || peer_codec_limit(&resources, &snapshot, peer)))
    }

    pub fn new(cfg: Arc<Config>, metrics: Arc<crate::metrics::Metrics>) -> Self {
        let t = &cfg.transport;
        let registry = Arc::new(Registry::new_with_resource_limits(
            metrics.clone(),
            cfg.transport.idempotency_tombstone_ttl,
            cfg.transport.suspended_buffer_limit,
            cfg.transport.global_buffer_limit,
            cfg.transport.backpressure_timeout,
        ));
        metrics.set_egress_registry(Arc::downgrade(&registry));
        let resources = metrics.resource_manager();
        let connection_budget = resources.as_ref().map_or_else(
            || Arc::new(super::ConnectionBudget::new(cfg.limits.max_sessions)),
            |manager| {
                manager.mark_instrumented("inbound_connections");
                manager.mark_instrumented("conn_metadata");
                Arc::new(super::ConnectionBudget::new_with_budgets(
                    cfg.limits.max_sessions,
                    Some(manager.inbound_connections.clone()),
                    Some(manager.conn_metadata.clone()),
                ))
            },
        );
        let probe_budget = resources.as_ref().map_or_else(
            || Arc::new(super::ProbeBudget::new()),
            |manager| {
                manager.mark_instrumented("probes");
                Arc::new(super::ProbeBudget::new_with_budget(manager.probes.clone()))
            },
        );
        Server {
            registry,
            client: Arc::new(Client::new(t.dial_timeout, t.control_request_timeout)),
            started: Instant::now(),
            hub: None,
            tunnels: None,
            metrics,
            connection_budget,
            authz_lock: Arc::new(std::sync::Mutex::new(())),
            probe_budget,
            accept_addr: Arc::new(std::sync::Mutex::new(None)),
            auth: Arc::new(crate::auth::Authenticator::new(cfg.clone())),
            cfg,
        }
    }

    pub fn drain(&self) {
        self.registry.set_draining();
    }

    pub fn session_count(&self) -> usize {
        self.registry.session_count()
    }

    /// Stops admission before the accept thread exits, then wakes its blocking
    /// `accept` call with a loopback connection.
    pub fn request_shutdown(&self) {
        self.registry.close_all();
        if let Some(tunnels) = &self.tunnels {
            tunnels.close();
        }
        let addr = *self
            .accept_addr
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(addr) = addr {
            let _ = crate::net::wake_tcp_listener(addr);
        }
    }

    pub fn on_auth_reload(&self, candidate: &crate::auth::Snapshot) {
        let _gate = self
            .authz_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(resources) = self.metrics.resource_manager() {
            resources.resize_peer_codec(|peer| peer_codec_limit(&resources, candidate, peer));
        }
        for session in self.registry.all_sessions() {
            let authorized = candidate.inbound.iter().any(|peer| {
                peer.id == session.owner_peer
                    && peer.enabled
                    && peer
                        .allowed_targets
                        .iter()
                        .any(|target| target == &session.target_id)
            });
            if !authorized {
                session.close(
                    Error::new(wire::ERR_TARGET_FORBIDDEN, "authorization revoked").closed(true),
                );
                self.registry.remove(&session.id);
            }
        }
    }

    pub fn listen(&self, shutdown: Arc<AtomicBool>) -> Result<()> {
        let me = Arc::new(Server {
            cfg: self.cfg.clone(),
            auth: self.auth.clone(),
            registry: self.registry.clone(),
            client: self.client.clone(),
            started: self.started,
            hub: self.hub.clone(),
            tunnels: self.tunnels.clone(),
            metrics: self.metrics.clone(),
            connection_budget: self.connection_budget.clone(),
            authz_lock: self.authz_lock.clone(),
            probe_budget: self.probe_budget.clone(),
            accept_addr: self.accept_addr.clone(),
        });

        #[cfg(feature = "tls")]
        let tls_config = if self.cfg.http.tls.enabled {
            let cert = self
                .cfg
                .http
                .tls
                .cert_file
                .as_ref()
                .ok_or_else(|| Error::local("TLS certificate path missing"))?;
            let key = self
                .cfg
                .http
                .tls
                .key_file
                .as_ref()
                .ok_or_else(|| Error::local("TLS private key path missing"))?;
            Some(Arc::new(
                crate::net::tls::server_config(cert, key)
                    .map_err(|e| Error::local(format!("TLS certificate/key: {e}")))?,
            ))
        } else {
            None
        };

        // A reverse node serves its egress role over tunnel streams and needs
        // no listening socket at all.
        let mut tcp = None;
        if self.cfg.http.enabled {
            let (host, port) = config::parse_hostport(&self.cfg.http.listen)
                .map_err(|e| Error::new(config::CODE_LISTEN, e))?;
            let bind = if host.is_empty() {
                format!("0.0.0.0:{port}")
            } else {
                self.cfg.http.listen.clone()
            };
            let listener = TcpListener::bind(&bind)
                .map_err(|e| Error::new(config::CODE_LISTEN, format!("http.listen {bind}: {e}")))?;
            log_info(&format!("egress listening on {bind}"));
            tcp = Some(listener);
        }

        // Tunnel streams run on their own accept loop: they are already
        // connections, they just have no socket.
        let tunnel_thread = match (&me.tunnels, me.cfg.reverse.enabled) {
            (Some(ln), true) => {
                let me = me.clone();
                let sd = shutdown.clone();
                let ln = ln.clone();
                log_info("egress serving reverse tunnel streams");
                Some(std::thread::spawn(move || {
                    while !sd.load(Ordering::Relaxed) {
                        let Some(conn) = ln.accept_next() else {
                            break;
                        };
                        let desc = conn.describe();
                        let me = me.clone();
                        let sd = sd.clone();
                        let _ = crate::util::spawn_connection(move || {
                            if let Err(e) = me.handle_conn(conn, sd, None) {
                                log_debug(&format!("{desc}: {e}"));
                            }
                        });
                    }
                }))
            }
            _ => None,
        };

        let Some(listener) = tcp else {
            // Keep admission open while reverse tunnels are serving requests.
            // `request_shutdown` drains the registry and closes this listener.
            if let Some(t) = tunnel_thread {
                let _ = t.join();
            }
            return Ok(());
        };
        let accept_addr = listener
            .local_addr()
            .map_err(|e| Error::local(format!("http listener local_addr: {e}")))?;
        *self
            .accept_addr
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(accept_addr);

        loop {
            if shutdown.load(Ordering::Relaxed) {
                break;
            }
            match listener.accept() {
                Ok((stream, peer)) => {
                    if shutdown.load(Ordering::Relaxed) {
                        drop(stream);
                        break;
                    }
                    let _ = crate::net::set_nodelay(&stream);
                    let Some(permit) = self.connection_budget.acquire(peer.ip()) else {
                        self.metrics.admission_rejected();
                        drop(stream);
                        continue;
                    };
                    // Keep the handler's connection blocking on every platform.
                    let _ = stream.set_nonblocking(false);
                    #[cfg(feature = "tls")]
                    let stream: Box<dyn crate::net::Conn> = if let Some(config) = tls_config.clone()
                    {
                        match crate::net::tls::TlsConn::accept_with_config(
                            stream,
                            config,
                            Duration::from_secs(5),
                        ) {
                            Ok(s) => {
                                #[cfg(feature = "h2")]
                                if s.alpn_protocol().as_deref() == Some(b"h2".as_slice()) {
                                    let me = me.clone();
                                    let _ = crate::util::spawn_connection(move || {
                                        if let Err(e) = super::h2::serve(me, s, Some(permit)) {
                                            log_debug(&format!(
                                                "HTTP/2 connection from {peer}: {e}"
                                            ));
                                        }
                                    });
                                    continue;
                                }
                                if s.alpn_protocol().as_deref() != Some(b"http/1.1".as_slice()) {
                                    log_debug(&format!(
                                        "rejecting TLS connection from {peer}: unsupported ALPN"
                                    ));
                                    continue;
                                }
                                Box::new(s)
                            }
                            Err(e) => {
                                log_debug(&format!("TLS handshake from {peer}: {e}"));
                                continue;
                            }
                        }
                    } else {
                        Box::new(stream)
                    };
                    #[cfg(not(feature = "tls"))]
                    let stream: Box<dyn crate::net::Conn> = Box::new(stream);
                    let me = me.clone();
                    let sd = shutdown.clone();
                    let _ = crate::util::spawn_connection(move || {
                        if let Err(e) = me.handle_conn(Box::new(stream), sd, Some(permit)) {
                            log_debug(&format!("connection from {peer}: {e}"));
                        }
                    });
                }
                Err(e) => {
                    // A transient accept error must not end the listener.
                    log_debug(&format!("accept: {e}"));
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
        self.registry.close_all();
        if let Some(t) = tunnel_thread {
            let _ = t.join();
        }
        Ok(())
    }

    pub(super) fn handle_conn(
        &self,
        stream: Box<dyn crate::net::Conn>,
        shutdown: Arc<AtomicBool>,
        mut permit: Option<super::ConnectionPermit>,
    ) -> Result<()> {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
        let mut conn = BufferedConn::from_boxed(stream);
        if let Some(permit) = permit.as_ref().filter(|p| !p.is_authenticated()) {
            conn.set_read_deadline(Some(permit.auth_deadline()));
        }
        let max_body = self.cfg.transport.max_frame_size.max(32 * 1024);
        loop {
            let mut req = match http1::read_request_head(&mut conn) {
                Ok(Some(r)) => r,
                Ok(None) => return Ok(()),
                Err(e) => {
                    if let Some(reject) = http1::reject_of(&e) {
                        http1::write_reject(&mut conn, reject);
                    }
                    return Err(Error::local(format!(
                        "read request on {}: {e}",
                        conn.describe()
                    )));
                }
            };
            if req.method == "OPTIONS" && req.path == "*" {
                if http1::read_request_body(&mut conn, &mut req, max_body).is_err() {
                    return Ok(());
                }
                let keep_alive = wants_keep_alive(&req);
                http1::write_response(&mut conn, 200, &[], b"", keep_alive)
                    .map_err(|e| Error::local(format!("write response: {e}")))?;
                if !keep_alive {
                    return Ok(());
                }
                continue;
            }
            if shutdown.load(Ordering::Relaxed) {
                let e = Error::new(wire::ERR_DRAINING, "stopped").retryable(true);
                let (status, body, headers) =
                    response_for(&e, Some(&req), true, &self.cfg.node.instance_id);
                let _ = http1::write_response(&mut conn, status, &headers, &body, false);
                return Ok(());
            }
            if (req.method == "GET" || req.method == "HEAD") && request_has_body(&req) {
                let e = Error::new(wire::ERR_BAD_FRAME, "request body not allowed");
                let (status, body, headers) =
                    response_for(&e, Some(&req), true, &self.cfg.node.instance_id);
                let _ = http1::write_response(&mut conn, status, &headers, &body, false);
                return Ok(());
            }
            if let Some(e) = invalid_binding_headers(&req) {
                let (status, body, headers) =
                    response_for(&e, Some(&req), true, &self.cfg.node.instance_id);
                let _ = http1::write_response(&mut conn, status, &headers, &body, false);
                return Ok(());
            }
            if is_reverse_path(&req.path) && self.hub.is_some() {
                return self.handle_reverse(conn, req, permit.take());
            }
            let Some(expected) = expected_method(&req.path) else {
                let e = Error::new(wire::ERR_BAD_FRAME, "not found");
                let (_, body, headers) =
                    response_for(&e, Some(&req), true, &self.cfg.node.instance_id);
                let _ = http1::write_response(&mut conn, 404, &headers, &body, false);
                return Ok(());
            };
            if req.method != expected {
                let e = Error::new(wire::ERR_BAD_FRAME, "method");
                let (status, body, mut headers) =
                    response_for(&e, Some(&req), true, &self.cfg.node.instance_id);
                headers.push(("Allow".to_string(), expected.to_string()));
                let _ = http1::write_response(&mut conn, status, &headers, &body, false);
                return Ok(());
            }
            let authenticated_peer = match self.authenticate(&req) {
                Ok(peer) => {
                    if let Some(permit) = permit.as_mut() {
                        permit.mark_authenticated();
                    }
                    conn.set_read_deadline(None);
                    peer.id
                }
                Err(_) => {
                    let e = Error::new(wire::ERR_UNAUTHORIZED, "invalid credentials");
                    let (status, body, mut headers) =
                        response_for(&e, Some(&req), true, &self.cfg.node.instance_id);
                    headers.push((
                        "WWW-Authenticate".to_string(),
                        "Bearer realm=\"dbbridge\"".to_string(),
                    ));
                    let _ = http1::write_response(&mut conn, status, &headers, &body, false);
                    return Err(Error::local("unauthenticated request closed"));
                }
            };
            if requires_instance_binding(&req.path) {
                if let Err(e) = self.check_instance(&req) {
                    let (status, body, mut headers) = error_response(&e);
                    headers.push((
                        wire::H_INSTANCE_ID.to_string(),
                        self.cfg.node.instance_id.clone(),
                    ));
                    headers.push(("Connection".to_string(), "close".to_string()));
                    let _ = http1::write_response(&mut conn, status, &headers, &body, false);
                    return Ok(());
                }
            }
            let request_leases = match self.request_resource_leases(&req, &authenticated_peer) {
                Ok(leases) => leases,
                Err(error) => {
                    let (status, body, headers) =
                        response_for(&error, Some(&req), true, &self.cfg.node.instance_id);
                    let _ = http1::write_response(&mut conn, status, &headers, &body, false);
                    return Ok(());
                }
            };
            let _ = conn.set_read_timeout(Some(self.cfg.transport.control_request_timeout));
            conn.set_read_deadline(Some(
                Instant::now() + self.cfg.transport.control_request_timeout,
            ));
            if let Err(e) = http1::read_request_body(&mut conn, &mut req, max_body) {
                let pe = Error::new(wire::ERR_BAD_FRAME, format!("malformed request body: {e}"));
                let (status, body, mut headers) =
                    response_for(&pe, Some(&req), true, &self.cfg.node.instance_id);
                if !headers
                    .iter()
                    .any(|(name, _)| name.eq_ignore_ascii_case(wire::H_INSTANCE_ID))
                {
                    headers.push((
                        wire::H_INSTANCE_ID.to_string(),
                        self.cfg.node.instance_id.clone(),
                    ));
                }
                let _ = http1::write_response(&mut conn, status, &headers, &body, false);
                return Err(Error::local("malformed request body"));
            }
            conn.set_read_deadline(None);
            let keep_alive = wants_keep_alive(&req);
            if req.path == wire::PATH_WS {
                return self.handle_ws(conn, req, request_leases);
            }
            if req.path.starts_with(wire::PATH_SESSIONS) && req.path.ends_with("/events") {
                return self.handle_events(conn, req, request_leases);
            }
            let (status, body, mut extra) = self.route(&req);
            if !extra
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("cache-control"))
            {
                extra.push(("Cache-Control".to_string(), "no-store".to_string()));
            }
            extra.push((
                wire::H_INSTANCE_ID.to_string(),
                self.cfg.node.instance_id.clone(),
            ));
            http1::write_response(&mut conn, status, &extra, &body, keep_alive)
                .map_err(|e| Error::local(format!("write response: {e}")))?;
            if !keep_alive {
                return Ok(());
            }
            let _ = conn.set_read_timeout(Some(Duration::from_secs(90)));
        }
    }

    pub(super) fn request_resource_leases(
        &self,
        req: &Request,
        peer: &str,
    ) -> Result<RequestResourceLeases> {
        let Some(resources) = self.metrics.resource_manager() else {
            return Ok(RequestResourceLeases {
                _budgets: Vec::new(),
                _fair: Vec::new(),
            });
        };
        let control_cost = || {
            let body = if req.header("transfer-encoding").is_some() {
                16 << 10
            } else {
                req.header("content-length")
                    .and_then(|value| value.parse::<usize>().ok())
                    .unwrap_or(0)
                    .min(16 << 10)
            };
            (4 << 10) + body
        };
        let (request_name, metadata_name, metadata_kind, metadata_cost) =
            if req.path == wire::PATH_PROBE {
                (
                    "control_requests",
                    "probe_metadata",
                    "probe-meta",
                    control_cost(),
                )
            } else if req.path == wire::PATH_SESSIONS && req.method == "POST" {
                ("data_requests", "metadata", "meta", 64 << 10)
            } else if req.path == wire::PATH_WS
                || (req.path.starts_with(wire::PATH_SESSIONS) && req.path.ends_with("/events"))
            {
                ("data_requests", "metadata", "meta", 16 << 10)
            } else if req.path.starts_with(wire::PATH_SESSIONS) && req.path.ends_with("/up") {
                ("data_requests", "metadata", "meta", 64 << 10)
            } else if req.method == "DELETE" {
                (
                    "control_requests",
                    "control_metadata",
                    "control-meta",
                    4 << 10,
                )
            } else {
                (
                    "control_requests",
                    "control_metadata",
                    "control-meta",
                    control_cost(),
                )
            };
        resources.mark_instrumented(request_name);
        resources.mark_instrumented(metadata_name);
        let request_kind = if request_name == "data_requests" {
            "data-requests"
        } else {
            "control-requests"
        };
        let request_budget = resources
            .budget(request_name)
            .expect("known request resource");
        let request_fair = self
            .auth
            .reserve_fair_n(peer, request_kind, request_budget.limit(), 1)
            .ok_or_else(|| {
                self.metrics.admission_rejected();
                Error::new(wire::ERR_QUOTA_EXCEEDED, "request concurrency").retryable(true)
            })?;
        let request_lease = resources
            .budget(request_name)
            .and_then(|budget| budget.try_acquire(1))
            .ok_or_else(|| {
                self.metrics.admission_rejected();
                Error::new(wire::ERR_QUOTA_EXCEEDED, "request concurrency").retryable(true)
            })?;
        let metadata_budget = resources
            .budget(metadata_name)
            .expect("known request metadata resource");
        let data_metadata = metadata_name == "metadata";
        let metadata_limit = if data_metadata {
            resources.egress_metadata_limit()
        } else {
            metadata_budget.limit()
        };
        let metadata_fair = self
            .auth
            .reserve_fair_n(peer, metadata_kind, metadata_limit, metadata_cost as i64)
            .ok_or_else(|| {
                Error::new(wire::ERR_QUOTA_EXCEEDED, "request metadata").retryable(true)
            })?;
        let metadata_cost = i64::try_from(metadata_cost).unwrap_or(i64::MAX);
        let metadata_lease = if data_metadata {
            resources.try_egress_metadata(metadata_cost)
        } else {
            metadata_budget.try_acquire(metadata_cost)
        }
        .ok_or_else(|| Error::new(wire::ERR_QUOTA_EXCEEDED, "request metadata").retryable(true))?;
        Ok(RequestResourceLeases {
            _budgets: vec![request_lease, metadata_lease],
            _fair: vec![request_fair, metadata_fair],
        })
    }

    pub(super) fn route(&self, req: &Request) -> (u16, Vec<u8>, Vec<(String, String)>) {
        let result: Result<(u16, String)> = match (req.method.as_str(), req.path.as_str()) {
            ("POST", wire::PATH_PROBE) => self.handle_probe(req).map(|b| (200, b)),
            ("POST", wire::PATH_SESSIONS) => self.handle_create(req),
            ("POST", _) if req.path.starts_with(wire::PATH_SESSIONS) => {
                self.handle_session_post(req).map(|b| (200, b))
            }
            ("DELETE", _) if req.path.starts_with(wire::PATH_SESSIONS) => {
                self.handle_delete(req).map(|b| (200, b))
            }
            _ => Err(Error::new(wire::ERR_SESSION_NOT_FOUND, "not found")),
        };
        match result {
            Ok((status, body)) => (
                status,
                json_line(body),
                vec![("Content-Type".to_string(), "application/json".to_string())],
            ),
            Err(e) => {
                // A refusal is worth seeing at debug level: it is the first
                // symptom when a peer's view of the protocol drifts.
                log_debug(&format!(
                    "{} {} refused: {} {}",
                    req.method, req.path, e.code, e.message
                ));
                error_response(&e)
            }
        }
    }

    // -- authentication ---------------------------------------------------

    pub(super) fn authenticate(&self, req: &Request) -> Result<config::InboundPeer> {
        let auth = req
            .header(wire::H_PEER_AUTH)
            .ok_or_else(|| Error::new(wire::ERR_UNAUTHORIZED, "missing credentials"))?;
        let (_, token) = auth
            .split_once(' ')
            .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("Bearer"))
            .ok_or_else(|| {
                Error::new(wire::ERR_UNAUTHORIZED, "credentials are not a bearer token")
            })?;
        if token.is_empty() || token.trim() != token {
            return Err(Error::new(wire::ERR_UNAUTHORIZED, "invalid credentials"));
        }
        let mut found: Option<String> = None;
        for peer in self.auth.snapshot().inbound.iter() {
            // Compare every alternative for every enabled identity, even after
            // a match, so neither token position nor identity leaks via an
            // early return.
            let mut peer_matched = false;
            if peer.enabled {
                for candidate in &peer.tokens {
                    peer_matched |= constant_time_eq(candidate.as_bytes(), token.as_bytes());
                }
            }
            if peer_matched {
                found = Some(peer.id.clone());
            }
        }
        found
            .and_then(|id| self.auth.inbound(&id))
            .ok_or_else(|| Error::new(wire::ERR_UNAUTHORIZED, "unknown credentials"))
    }

    pub(super) fn check_instance(&self, req: &Request) -> Result<()> {
        let inst = req
            .header(wire::H_INSTANCE_ID)
            .ok_or_else(|| Error::new(wire::ERR_INSTANCE_MISMATCH, "missing instance binding"))?;
        if inst != self.cfg.node.instance_id {
            return Err(Error::new(
                wire::ERR_INSTANCE_MISMATCH,
                "the peer expected a different instance",
            ));
        }
        Ok(())
    }
}

pub(super) fn requires_instance_binding(path: &str) -> bool {
    path == wire::PATH_SESSIONS || path == wire::PATH_WS || path.starts_with("/v1/sessions/")
}

pub(super) fn wants_keep_alive(req: &Request) -> bool {
    let tokens = |want: &str| {
        req.headers.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("connection")
                && v.split(',').any(|t| t.trim().eq_ignore_ascii_case(want))
        })
    };
    if req.version == "HTTP/1.0" {
        tokens("keep-alive") && !tokens("close")
    } else {
        !tokens("close")
    }
}

pub(super) fn json_line(mut body: String) -> Vec<u8> {
    if !body.is_empty() && !body.ends_with('\n') {
        body.push('\n');
    }
    body.into_bytes()
}

pub(super) fn error_response(e: &Error) -> (u16, Vec<u8>, Vec<(String, String)>) {
    let e = if e.code.is_empty() {
        Error::new(wire::ERR_INTERNAL_ERROR, e.message.clone()).retryable(true)
    } else {
        e.clone()
    };
    let body = wire::ErrorBody::from_error(&e).to_json().to_string();
    let body = json_line(body);
    let mut headers = vec![
        ("Content-Type".to_string(), "application/json".to_string()),
        ("Cache-Control".to_string(), "no-store".to_string()),
    ];
    if e.code == wire::ERR_CREATE_PENDING || e.code == wire::ERR_RESUME_PENDING {
        headers.push(("Retry-After".to_string(), "1".to_string()));
    }
    (e.status(), body, headers)
}

pub(super) fn request_has_body(req: &Request) -> bool {
    req.header("transfer-encoding").is_some()
        || req
            .header("content-length")
            .map(|v| v.trim() != "0")
            .unwrap_or(false)
}

pub(super) fn invalid_binding_headers(req: &Request) -> Option<Error> {
    let count = req.headers.len();
    let size: usize = req.headers.iter().map(|(k, v)| k.len() + v.len() + 4).sum();
    let mut seen = std::collections::HashSet::new();
    for (name, _) in &req.headers {
        if (name.eq_ignore_ascii_case(wire::H_PEER_AUTH)
            || name.to_ascii_lowercase().starts_with("x-dbb-"))
            && !seen.insert(name.to_ascii_lowercase())
        {
            return Some(Error::new(wire::ERR_BAD_FRAME, "duplicate binding header"));
        }
    }
    if count > 64 || size > 16 * 1024 || req.header("origin").is_some() {
        return Some(Error::new(wire::ERR_BAD_FRAME, "invalid headers"));
    }
    None
}

fn is_reverse_path(path: &str) -> bool {
    path == crate::tunnel::PATH_REVERSE || path.starts_with("/v1/reverse/")
}

pub(super) fn expected_method(path: &str) -> Option<&'static str> {
    match path {
        wire::PATH_PROBE | wire::PATH_SESSIONS => return Some("POST"),
        wire::PATH_WS => return Some("GET"),
        _ => {}
    }
    let rest = path.strip_prefix("/v1/sessions/")?;
    let mut parts = rest.split('/');
    if parts.next().unwrap_or("").is_empty() || parts.clone().count() > 1 {
        return None;
    }
    Some(match parts.next().unwrap_or("") {
        "" => "DELETE",
        "events" => "GET",
        _ => "POST",
    })
}

pub(super) fn response_for(
    e: &Error,
    req: Option<&Request>,
    close: bool,
    instance: &str,
) -> (u16, Vec<u8>, Vec<(String, String)>) {
    let (status, body, mut headers) = error_response(e);
    if close {
        headers.push(("Connection".to_string(), "close".to_string()));
    }
    if req.and_then(|r| r.header(wire::H_INSTANCE_ID)) == Some(instance) {
        headers.push((wire::H_INSTANCE_ID.to_string(), instance.to_string()));
    }
    (status, body, headers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn middleware_matrix() {
        let req = Request {
            method: "GET".into(),
            path: "/v1/peer/probe".into(),
            query: vec![],
            version: "HTTP/1.1".into(),
            headers: vec![("Content-Length".into(), "1".into())],
            body: vec![],
        };
        assert!(request_has_body(&req));
        let dup = Request {
            headers: vec![
                (wire::H_PEER_AUTH.into(), "a".into()),
                (wire::H_PEER_AUTH.into(), "b".into()),
            ],
            ..req.clone()
        };
        assert_eq!(
            invalid_binding_headers(&dup).unwrap().message,
            "duplicate binding header"
        );
        assert_eq!(expected_method("/unknown"), None);
        assert_eq!(expected_method(wire::PATH_PROBE), Some("POST"));
        assert!(is_reverse_path("/v1/reverse/t1"));
        assert!(requires_instance_binding(wire::PATH_SESSIONS));
        assert!(requires_instance_binding("/v1/sessions/s1/events"));
        assert!(!requires_instance_binding(wire::PATH_PROBE));

        let mut too_many = req.clone();
        too_many.headers = (0..65)
            .map(|n| (format!("X-Test-{n}"), "v".to_string()))
            .collect();
        assert_eq!(
            invalid_binding_headers(&too_many).unwrap().message,
            "invalid headers"
        );
        let too_large = Request {
            headers: vec![("X-Test".into(), "x".repeat(17 * 1024))],
            ..req.clone()
        };
        assert_eq!(
            invalid_binding_headers(&too_large).unwrap().message,
            "invalid headers"
        );
        let origin = Request {
            headers: vec![("Origin".into(), "https://example.test".into())],
            ..req.clone()
        };
        assert_eq!(
            invalid_binding_headers(&origin).unwrap().message,
            "invalid headers"
        );

        let draining = Error::new(wire::ERR_DRAINING, "stopped").retryable(true);
        let (status, body, headers) = error_response(&draining);
        assert_eq!(status, 503);
        assert!(String::from_utf8_lossy(&body).contains("\"retryable\":true"));
        assert!(headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("Cache-Control") && value == "no-store"
        }));
        let echoed_req = Request {
            headers: vec![(wire::H_INSTANCE_ID.into(), "inst".into())],
            ..req.clone()
        };
        let (_, _, headers) = response_for(&draining, Some(&echoed_req), true, "inst");
        assert!(headers
            .iter()
            .any(|(name, value)| name == wire::H_INSTANCE_ID && value == "inst"));
        let (_, _, headers) = response_for(&draining, Some(&echoed_req), true, "other");
        assert!(!headers.iter().any(|(name, _)| name == wire::H_INSTANCE_ID));
    }

    #[test]
    fn disabled_identity_cannot_authenticate() {
        let dir =
            std::env::temp_dir().join(format!("dbb-auth-{}", crate::util::random_hex(6).unwrap()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("active-token"), "active-secret").unwrap();
        let path = dir.join("cfg.yaml");
        std::fs::write(
            &path,
            "\
node:\n  id: egress\n\
http:\n  enabled: true\n  listen: \"127.0.0.1:18080\"\n\
targets:\n  db:\n    network: tcp\n    address: \"127.0.0.1:3306\"\n\
auth:\n  inbound_peers:\n    - id: active\n      token_files: [active-token]\n      allowed_targets: [db]\n    - id: disabled\n      enabled: false\n      token_files: [missing-token]\n      allowed_targets: [db]\n",
        )
        .unwrap();
        let cfg = Arc::new(config::load(&path).unwrap());
        let server = Server::new(cfg, Arc::new(crate::metrics::Metrics::new()));
        let req = Request {
            method: "POST".to_string(),
            path: wire::PATH_PROBE.to_string(),
            query: Vec::new(),
            version: "HTTP/1.1".to_string(),
            headers: vec![(
                wire::H_PEER_AUTH.to_string(),
                "Bearer disabled-secret".to_string(),
            )],
            body: Vec::new(),
        };
        let error = server.authenticate(&req).unwrap_err();
        assert_eq!(error.code, wire::ERR_UNAUTHORIZED);
        assert_eq!(error.status(), 401);
    }

    #[test]
    fn unauthenticated_socket_closed_after_5s() {
        let dir = std::env::temp_dir().join(format!(
            "dbb-timeout-{}",
            crate::util::random_hex(6).unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("active-token"), "active-secret").unwrap();
        let path = dir.join("cfg.yaml");
        std::fs::write(
            &path,
            "node:\n  id: egress\nhttp:\n  enabled: true\n  listen: \"127.0.0.1:0\"\ntargets:\n  db:\n    network: tcp\n    address: \"127.0.0.1:3306\"\nauth:\n  inbound_peers:\n    - id: active\n      token_files: [active-token]\n      allowed_targets: [db]\n",
        )
        .unwrap();
        let cfg = Arc::new(config::load(&path).unwrap());
        let server = Arc::new(Server::new(cfg, Arc::new(crate::metrics::Metrics::new())));

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server_stream, _) = listener.accept().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(7)))
            .unwrap();
        let permit = server
            .connection_budget
            .acquire(server_stream.peer_addr().unwrap().ip())
            .unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let server_thread = server.clone();
        let started = Instant::now();
        let thread = std::thread::spawn(move || {
            server_thread.handle_conn(Box::new(server_stream), shutdown, Some(permit))
        });

        let mut response = Vec::new();
        client
            .try_clone()
            .unwrap()
            .read_to_end(&mut response)
            .unwrap();
        assert!(started.elapsed() >= Duration::from_secs(4));
        assert!(
            response.is_empty(),
            "{}",
            String::from_utf8_lossy(&response)
        );
        assert!(thread.join().unwrap().is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn loopback_wakeup_unblocks_wildcard_listener_accept() {
        let listener = TcpListener::bind("0.0.0.0:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_thread = std::thread::spawn(move || listener.accept().map(|_| ()));
        crate::net::wake_tcp_listener(addr).unwrap();
        accept_thread.join().unwrap().unwrap();
    }

    #[test]
    fn reverse_only_server_remains_accepting_until_shutdown() {
        let dir = std::env::temp_dir().join(format!(
            "dbb-reverse-only-{}",
            crate::util::random_hex(6).unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("peer-token"), "test-token").unwrap();
        let path = dir.join("cfg.yaml");
        std::fs::write(
            &path,
            "node:\n  id: egress\nhttp:\n  enabled: true\n  listen: \"127.0.0.1:0\"\ntargets:\n  db:\n    network: tcp\n    address: \"127.0.0.1:3306\"\nauth:\n  inbound_peers:\n    - id: ingress\n      token_files: [peer-token]\n      allowed_targets: [db]\n",
        )
        .unwrap();
        let mut cfg = config::load(&path).unwrap();
        cfg.http.enabled = false;
        cfg.reverse.enabled = true;
        let mut server = Server::new(Arc::new(cfg), Arc::new(crate::metrics::Metrics::new()));
        let tunnels = Arc::new(crate::tunnel::client::TunnelListener::new());
        server.tunnels = Some(tunnels);
        let server = Arc::new(server);

        let listen_server = server.clone();
        let shutdown = Arc::new(AtomicBool::new(false));
        let listen_thread = std::thread::spawn(move || listen_server.listen(shutdown));
        std::thread::sleep(Duration::from_millis(50));
        assert!(server.registry.accepting());

        server.request_shutdown();
        assert!(listen_thread.join().unwrap().is_ok());
        assert!(!server.registry.accepting());
        let _ = std::fs::remove_dir_all(dir);
    }
}
