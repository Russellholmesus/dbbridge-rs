//! Public side of reverse mode: accepting tunnels and handing out streams.
//!
//! The hub is the only mutable state reverse mode has. A tunnel is registered
//! once, then read concurrently by every ingress thread that needs a stream on
//! it, so the map is behind one mutex and nothing is held across a syscall.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::mux::{Opener, Session};
use crate::net::{header, Conn};
use crate::wire;

use super::ws::split_tunnel_guarded;
use super::{
    mux_config, valid_tunnel_id, H_EXPECTED_NODE_ID, H_NODE_ID, H_TUNNEL_ID, H_TUNNEL_PRIORITY,
    MAX_STREAMS_PER_TUNNEL, MAX_TUNNELS_PER_PEER, REVERSE_SUBPROTOCOL, REVERSE_SUBPROTOCOL_PREFIX,
};

struct RegisteredTunnel {
    id: String,
    peer: String,
    transport: String,
    instance: String,
    priority: i32,
    session: Arc<Session>,
    http: Option<HttpTunnel>,
    credential: String,
}

#[derive(Clone)]
struct HttpTunnel {
    pipe: crate::tunnel::pipe::Pipe,
    token: String,
    reader_generation: Arc<AtomicU64>,
}

struct PeerTunnels {
    tunnels: HashMap<String, Arc<RegisteredTunnel>>,
}

/// The public side of reverse mode: accepts tunnels, verifies who dialed
/// them, and hands out streams on them to the ingress role.
pub struct Hub {
    node_id: String,
    instance_id: String,
    peers: Mutex<HashMap<String, PeerTunnels>>,
    closed: AtomicBool,
    accepted: AtomicU64,
    rejected: AtomicU64,
    auth: RwLock<Option<Arc<crate::auth::Authenticator>>>,
    resources: RwLock<Option<Arc<crate::resource::manager::ResourceManager>>>,
    stream_window: i64,
    reverse_shares: Arc<Mutex<HashMap<String, i64>>>,
    reverse_peers: usize,
}

pub struct ReverseAdmission {
    _leases: Vec<crate::resource::budget::BudgetLease>,
    shares: Vec<(String, i64)>,
    map: Arc<Mutex<HashMap<String, i64>>>,
}

impl Drop for ReverseAdmission {
    fn drop(&mut self) {
        let mut map = self.map.lock().unwrap_or_else(|p| p.into_inner());
        for (key, n) in self.shares.drain(..).rev() {
            if let Some(v) = map.get_mut(&key) {
                *v -= n;
                if *v <= 0 {
                    map.remove(&key);
                }
            }
        }
    }
}

fn request_metadata(req: &crate::net::http1::Request) -> i64 {
    let mut uri = req.path.len();
    if !req.query.is_empty() {
        uri += 1 + req
            .query
            .iter()
            .map(|(k, v)| k.len() + v.len() + 1)
            .sum::<usize>()
            .saturating_sub(1);
    }
    let headers: usize = req.headers.iter().map(|(k, v)| k.len() + v.len() + 4).sum();
    i64::try_from(req.method.len() + uri + 16 + headers).unwrap_or(i64::MAX)
}

impl Hub {
    pub fn set_resources(&self, resources: Arc<crate::resource::manager::ResourceManager>) {
        *self
            .resources
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(resources);
    }

    fn stream_codec_lease(&self) -> Result<Option<crate::resource::budget::BudgetLease>> {
        let resources = self
            .resources
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let Some(resources) = resources else {
            return Ok(None);
        };
        resources.mark_instrumented("codec");
        resources
            .codec
            .try_acquire(self.stream_window)
            .map(Some)
            .ok_or_else(|| {
                Error::local("local connection budget: codec budget for a tunnel stream")
            })
    }

    fn http_tunnel_codec_lease(&self) -> Result<Option<crate::resource::budget::BudgetLease>> {
        let resources = self
            .resources
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let Some(resources) = resources else {
            return Ok(None);
        };
        resources.mark_instrumented("codec");
        resources
            .try_codec_keep(crate::tunnel::http_tunnel_budget())
            .map(Some)
            .ok_or_else(|| Error::new(wire::ERR_BUFFER_EXHAUSTED, "codec budget").retryable(true))
    }

    pub fn new(cfg: &crate::config::Config) -> Hub {
        let mut peers = HashMap::new();
        for p in &cfg.peers {
            if p.reverse {
                peers.insert(
                    p.id.clone(),
                    PeerTunnels {
                        tunnels: HashMap::new(),
                    },
                );
            }
        }
        Hub {
            node_id: cfg.node.id.clone(),
            instance_id: cfg.node.instance_id.clone(),
            peers: Mutex::new(peers),
            closed: AtomicBool::new(false),
            accepted: AtomicU64::new(0),
            rejected: AtomicU64::new(0),
            auth: RwLock::new(None),
            resources: RwLock::new(None),
            stream_window: i64::try_from(cfg.transport.tunnel_stream_window()).unwrap_or(i64::MAX),
            reverse_shares: Arc::new(Mutex::new(HashMap::new())),
            reverse_peers: cfg.peers.iter().filter(|p| p.reverse).count(),
        }
    }

    pub fn admit_request(
        &self,
        req: &crate::net::http1::Request,
        peer: &str,
        control: bool,
    ) -> std::result::Result<Option<ReverseAdmission>, (Error, bool)> {
        let resources = self
            .resources
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let Some(res) = resources else {
            return Ok(None);
        };
        let refused =
            || Error::new(wire::ERR_QUOTA_EXCEEDED, "request concurrency").retryable(true);
        let mut admission = ReverseAdmission {
            _leases: Vec::new(),
            shares: Vec::new(),
            map: self.reverse_shares.clone(),
        };
        let (requests, kind) = if control {
            (&res.control_requests, "control")
        } else {
            (&res.data_requests, "data")
        };
        let mut take = |key: &str,
                        limit: i64,
                        n: i64,
                        try_take: &dyn Fn(i64) -> Option<crate::resource::budget::BudgetLease>|
         -> bool {
            let key = format!("{peer}|{key}");
            let share = crate::auth::peer_share(limit, self.reverse_peers);
            {
                let mut map = self
                    .reverse_shares
                    .lock()
                    .unwrap_or_else(|p| p.into_inner());
                let active = map.get(&key).copied().unwrap_or(0);
                if active + n > share {
                    return false;
                }
                map.insert(key.clone(), active + n);
            }
            admission.shares.push((key, n));
            match try_take(n) {
                Some(lease) => {
                    admission._leases.push(lease);
                    true
                }
                None => false,
            }
        };
        if !take(kind, requests.limit(), 1, &|n| requests.try_acquire(n)) {
            return Err((refused(), true));
        }
        let meta = request_metadata(req).max(1);
        if !take("metadata", res.egress_metadata_limit(), meta, &|n| {
            res.try_egress_metadata(n)
        }) {
            return Err((refused(), false));
        }
        Ok(Some(admission))
    }

    pub fn http_peer(
        &self,
        req: &crate::net::http1::Request,
        id: &str,
        cfg: &crate::config::Config,
    ) -> Result<String> {
        self.http_find(req, id, cfg).map(|t| t.peer.clone())
    }

    pub fn set_auth(&self, auth: Arc<crate::auth::Authenticator>) {
        *self
            .auth
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(auth);
    }
    /// Verifies a tunnel handshake without changing any state, and builds the
    /// upgrade response. The caller writes it, then calls `register`.
    pub fn reserve(
        &self,
        req: &crate::net::http1::Request,
        cfg: &crate::config::Config,
    ) -> Result<Reserved> {
        let reserved = self.reserve_inner(req, cfg);
        if reserved.is_err() {
            self.rejected.fetch_add(1, Ordering::Relaxed);
        }
        reserved
    }

    #[cfg(test)]
    pub fn rejected(&self) -> u64 {
        self.rejected.load(Ordering::Relaxed)
    }

    fn reserve_inner(
        &self,
        req: &crate::net::http1::Request,
        cfg: &crate::config::Config,
    ) -> Result<Reserved> {
        let offer = self.verify(req, cfg)?;
        if self.closed.load(Ordering::Relaxed) {
            return Err(Error::new(wire::ERR_DRAINING, "node shutting down").retryable(true));
        }
        let key = header(&req.headers, "sec-websocket-key")
            .ok_or_else(|| Error::new(wire::ERR_WS_HANDSHAKE_FAILED, "missing key"))?;
        let headers = vec![
            ("Upgrade".to_string(), "websocket".to_string()),
            ("Connection".to_string(), "Upgrade".to_string()),
            (
                "Sec-WebSocket-Accept".to_string(),
                crate::net::ws::accept_key(key),
            ),
            (
                "Sec-WebSocket-Protocol".to_string(),
                REVERSE_SUBPROTOCOL.to_string(),
            ),
            (H_NODE_ID.to_string(), self.node_id.clone()),
            (wire::H_INSTANCE_ID.to_string(), self.instance_id.clone()),
            ("Cache-Control".to_string(), "no-store".to_string()),
        ];
        Ok(Reserved { offer, headers })
    }

    /// Starts the multiplexer on an upgraded connection and registers it.
    pub fn register(
        &self,
        reserved: Reserved,
        conn: crate::net::BufferedConn,
        cfg: &crate::config::Config,
        guard: Option<Box<dyn std::any::Any + Send + Sync>>,
    ) -> Result<()> {
        let offer = reserved.offer;
        let auth = self
            .auth
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        // Re-check the credential while holding the hub lock. A reservation
        // can outlive a credential reload between HTTP verification and the
        // actual mux registration.
        {
            let peers = self.peers.lock().unwrap();
            let p = peers
                .get(&offer.peer)
                .ok_or_else(|| Error::new(wire::ERR_UNAUTHORIZED, "unauthorized"))?;
            let current = cfg
                .peer(&offer.peer)
                .ok_or_else(|| Error::new(wire::ERR_UNAUTHORIZED, "unauthorized"))?;
            let expected = match &auth {
                Some(auth) => auth.outbound_token(&offer.peer).ok_or_else(|| {
                    Error::new(
                        crate::config::CODE_CREDENTIAL,
                        "missing outbound credential",
                    )
                })?,
                None => current.token.clone(),
            };
            if !crate::egress::constant_time_eq(expected.as_bytes(), offer.token.as_bytes()) {
                return Err(Error::new(wire::ERR_UNAUTHORIZED, "credentials changed"));
            }
            if p.tunnels.contains_key(&offer.id) {
                return Err(Error::new(
                    wire::ERR_TUNNEL_CONFLICT,
                    "tunnel id already registered",
                ));
            }
        }
        let remote = conn.describe();
        let session =
            split_tunnel_guarded(conn, false, mux_config(&cfg.transport), Opener::Odd, guard)?;
        let tunnel = Arc::new(RegisteredTunnel {
            id: offer.id.clone(),
            peer: offer.peer.clone(),
            transport: "ws".to_string(),
            instance: offer.instance.clone(),
            priority: offer.priority,
            session: session.clone(),
            http: None,
            credential: crate::util::hex(&crate::util::sha256::digest(offer.token.as_bytes())),
        });
        {
            let mut peers = self.peers.lock().unwrap();
            let Some(p) = peers.get_mut(&offer.peer) else {
                tunnel.session.close();
                return Err(Error::new(wire::ERR_UNAUTHORIZED, "unauthorized"));
            };
            let Some(current) = cfg.peer(&offer.peer) else {
                tunnel.session.close();
                return Err(Error::new(wire::ERR_UNAUTHORIZED, "unauthorized"));
            };
            let expected = match &auth {
                Some(auth) => match auth.outbound_token(&offer.peer) {
                    Some(token) => token,
                    None => {
                        tunnel.session.close();
                        return Err(Error::new(
                            crate::config::CODE_CREDENTIAL,
                            "missing outbound credential",
                        ));
                    }
                },
                None => current.token.clone(),
            };
            if !crate::egress::constant_time_eq(expected.as_bytes(), offer.token.as_bytes()) {
                tunnel.session.close();
                return Err(Error::new(wire::ERR_UNAUTHORIZED, "credentials changed"));
            }
            p.tunnels
                .retain(|_, registered| !registered.session.is_closed());
            // `reserve` rejected a duplicate id, but two handshakes can pass
            // it concurrently. The second registration must fail rather than
            // replacing the live tunnel.
            if p.tunnels.contains_key(&offer.id) {
                tunnel.session.close();
                return Err(Error::new(
                    wire::ERR_TUNNEL_CONFLICT,
                    "tunnel id already registered",
                ));
            }
            if p.tunnels
                .values()
                .any(|registered| registered.instance != offer.instance)
            {
                tunnel.session.close();
                return Err(Error::new(
                    wire::ERR_TUNNEL_CONFLICT,
                    "another instance of this peer holds live tunnels",
                )
                .retryable(true));
            }
            if p.tunnels.len() >= MAX_TUNNELS_PER_PEER {
                tunnel.session.close();
                return Err(
                    Error::new(wire::ERR_QUOTA_EXCEEDED, "tunnels per peer").retryable(true)
                );
            }
            p.tunnels.insert(offer.id.clone(), tunnel);
        }
        self.accepted.fetch_add(1, Ordering::Relaxed);
        crate::slog::info(
            "reverse tunnel registered",
            &[
                ("peer", offer.peer.as_str().into()),
                ("tunnel", offer.id.as_str().into()),
                ("transport", "ws".into()),
                ("instance", offer.instance.as_str().into()),
                ("priority", offer.priority.into()),
                ("remote", remote.as_str().into()),
            ],
        );
        Ok(())
    }

    pub fn open_http(
        &self,
        req: &crate::net::http1::Request,
        cfg: &crate::config::Config,
        id: &str,
        transport: &str,
    ) -> Result<Vec<(String, String)>> {
        let peer = self.verify_http(req, cfg, id, transport)?;
        let instance = header(&req.headers, wire::H_INSTANCE_ID)
            .unwrap_or("")
            .to_string();
        let priority: i32 = header(&req.headers, H_TUNNEL_PRIORITY)
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let token = header(&req.headers, wire::H_PEER_AUTH)
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|v| crate::util::hex(&crate::util::sha256::digest(v.as_bytes())))
            .unwrap_or_default();
        let pipe = crate::tunnel::pipe::Pipe::new(format!("reverse:{id}"), peer.clone());
        let session =
            crate::tunnel::split_pipe(pipe.clone(), mux_config(&cfg.transport), Opener::Odd);
        let mut peers = self.peers.lock().unwrap();
        let p = peers
            .get_mut(&peer)
            .ok_or_else(|| Error::new(wire::ERR_UNAUTHORIZED, "unauthorized"))?;
        p.tunnels.retain(|_, t| !t.session.is_closed());
        if p.tunnels.contains_key(id) {
            session.close();
            return Err(Error::new(
                wire::ERR_TUNNEL_CONFLICT,
                "tunnel id already registered",
            ));
        }
        if p.tunnels.values().any(|t| t.instance != instance) {
            session.close();
            return Err(Error::new(
                wire::ERR_TUNNEL_CONFLICT,
                "another instance of this peer holds live tunnels",
            )
            .retryable(true));
        }
        if p.tunnels.len() >= MAX_TUNNELS_PER_PEER {
            session.close();
            return Err(Error::new(wire::ERR_QUOTA_EXCEEDED, "tunnels per peer").retryable(true));
        }
        match self.http_tunnel_codec_lease() {
            Ok(Some(lease)) => session.hold_until_closed(Box::new(lease)),
            Ok(None) => {}
            Err(error) => {
                session.close();
                return Err(error);
            }
        }
        p.tunnels.insert(
            id.to_string(),
            Arc::new(RegisteredTunnel {
                id: id.to_string(),
                peer: peer.clone(),
                transport: transport.to_string(),
                instance,
                priority,
                session,
                http: Some(HttpTunnel {
                    pipe,
                    token: token.clone(),
                    reader_generation: Arc::new(AtomicU64::new(0)),
                }),
                credential: token,
            }),
        );
        self.accepted.fetch_add(1, Ordering::Relaxed);
        Ok(vec![
            (H_NODE_ID.to_string(), self.node_id.clone()),
            (wire::H_INSTANCE_ID.to_string(), self.instance_id.clone()),
            (
                "X-DBB-Reverse-Protocol".to_string(),
                REVERSE_SUBPROTOCOL.to_string(),
            ),
            ("Cache-Control".to_string(), "no-store".to_string()),
        ])
    }

    fn verify_http(
        &self,
        req: &crate::net::http1::Request,
        cfg: &crate::config::Config,
        id: &str,
        transport: &str,
    ) -> Result<String> {
        if req.method != "POST" {
            return Err(Error::new(wire::ERR_BAD_FRAME, "method"));
        }
        if !valid_tunnel_id(id) || header(&req.headers, H_TUNNEL_ID) != Some(id) {
            return Err(Error::new(wire::ERR_BAD_FRAME, "tunnel identity"));
        }
        let peer = authenticate(
            &self.auth.read().unwrap_or_else(|p| p.into_inner()).clone(),
            req,
            cfg,
        )?;
        let pc = cfg
            .peer(&peer)
            .ok_or_else(|| Error::new(wire::ERR_UNAUTHORIZED, "unauthorized"))?;
        if header(&req.headers, H_NODE_ID).unwrap_or("") != pc.expected_node_id {
            return Err(Error::new(wire::ERR_NODE_MISMATCH, "node identity"));
        }
        if header(&req.headers, H_EXPECTED_NODE_ID).unwrap_or("") != self.node_id {
            return Err(Error::new(wire::ERR_NODE_MISMATCH, "expected node"));
        }
        let inst = header(&req.headers, wire::H_INSTANCE_ID).unwrap_or("");
        if inst.is_empty() || inst.len() > 128 {
            return Err(Error::new(wire::ERR_BAD_FRAME, "tunnel identity"));
        }
        let proto = header(&req.headers, "x-dbb-reverse-protocol").unwrap_or("");
        if proto != REVERSE_SUBPROTOCOL {
            return Err(if proto.starts_with(REVERSE_SUBPROTOCOL_PREFIX) {
                Error::new(wire::ERR_PROTOCOL_MISMATCH, "protocol")
            } else {
                Error::new(wire::ERR_TRANSPORT_UNSUPPORTED, "protocol")
            });
        }
        if transport != "http-sse" && transport != "long-poll" {
            return Err(Error::new(wire::ERR_BAD_FRAME, "transport"));
        }
        let pri = header(&req.headers, H_TUNNEL_PRIORITY)
            .and_then(|v| v.parse::<i32>().ok())
            .ok_or_else(|| Error::new(wire::ERR_BAD_FRAME, "tunnel priority"))?;
        if pri < 0 {
            return Err(Error::new(wire::ERR_BAD_FRAME, "tunnel priority"));
        }
        Ok(peer)
    }

    fn http_find(
        &self,
        req: &crate::net::http1::Request,
        id: &str,
        cfg: &crate::config::Config,
    ) -> Result<Arc<RegisteredTunnel>> {
        if !valid_tunnel_id(id) {
            return Err(Error::new(wire::ERR_BAD_FRAME, "not found"));
        }
        let peer = authenticate(
            &self.auth.read().unwrap_or_else(|p| p.into_inner()).clone(),
            req,
            cfg,
        )?;
        let t = self
            .peers
            .lock()
            .unwrap()
            .get(&peer)
            .and_then(|p| p.tunnels.get(id))
            .cloned()
            .ok_or_else(|| Error::new(wire::ERR_TUNNEL_NOT_FOUND, "tunnel not found"))?;
        let tok = header(&req.headers, wire::H_PEER_AUTH)
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|v| crate::util::hex(&crate::util::sha256::digest(v.as_bytes())))
            .unwrap_or_default();
        let inst = header(&req.headers, wire::H_INSTANCE_ID).unwrap_or("");
        if t.http.is_none()
            || t.http.as_ref().unwrap().token != tok
            || t.instance != inst
            || t.session.is_closed()
        {
            return Err(Error::new(wire::ERR_TUNNEL_NOT_FOUND, "tunnel not found"));
        }
        Ok(t)
    }
    fn http_ack(&self, t: &Arc<RegisteredTunnel>, req: &crate::net::http1::Request) -> Result<()> {
        let Some(raw) = header(&req.headers, wire::H_ACK_DOWN_OFFSET) else {
            return Ok(());
        };
        let result = raw
            .parse::<i64>()
            .ok()
            .filter(|n| *n >= 0)
            .ok_or_else(|| Error::new(wire::ERR_BAD_ACK, "ack offset"))
            .and_then(|n| {
                if t.http.as_ref().unwrap().pipe.ack(n).is_ok() {
                    Ok(())
                } else {
                    Err(Error::new(wire::ERR_BAD_ACK, "ack offset"))
                }
            });
        if let Err(e) = result {
            t.session.close();
            self.drop_tunnel(&t.peer, &t.id);
            return Err(e);
        }
        Ok(())
    }
    fn http_find_ack(
        &self,
        req: &crate::net::http1::Request,
        id: &str,
        cfg: &crate::config::Config,
    ) -> Result<Arc<RegisteredTunnel>> {
        let t = self.http_find(req, id, cfg)?;
        self.http_ack(&t, req)?;
        Ok(t)
    }
    pub fn http_reader_start(
        &self,
        req: &crate::net::http1::Request,
        id: &str,
        cfg: &crate::config::Config,
    ) -> Result<u64> {
        let t = self.http_find_ack(req, id, cfg)?;
        Ok(t.http
            .as_ref()
            .unwrap()
            .reader_generation
            .fetch_add(1, Ordering::SeqCst)
            + 1)
    }
    pub fn http_reader_current(
        &self,
        req: &crate::net::http1::Request,
        id: &str,
        cfg: &crate::config::Config,
        generation: u64,
    ) -> bool {
        self.http_find(req, id, cfg)
            .ok()
            .and_then(|t| {
                t.http
                    .as_ref()
                    .map(|h| h.reader_generation.load(Ordering::SeqCst) == generation)
            })
            .unwrap_or(false)
    }
    pub fn http_up(
        &self,
        req: &crate::net::http1::Request,
        id: &str,
        cfg: &crate::config::Config,
    ) -> Result<i64> {
        let t = self.http_find_ack(req, id, cfg)?;
        let h = t.http.as_ref().unwrap();
        let off = header(&req.headers, wire::H_OFFSET)
            .ok_or_else(|| Error::new(wire::ERR_BAD_FRAME, "offset"))?
            .parse::<i64>()
            .map_err(|_| Error::new(wire::ERR_BAD_FRAME, "offset"))?;
        if off < 0 {
            return Err(Error::new(wire::ERR_BAD_FRAME, "offset"));
        }
        let d = header(&req.headers, wire::H_SHA256)
            .ok_or_else(|| Error::new(wire::ERR_BAD_FRAME, "digest"))?;
        if d.len() != 64
            || !d
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(Error::new(wire::ERR_BAD_FRAME, "digest"));
        }
        if crate::util::hex(&crate::util::sha256::digest(&req.body)) != d {
            return Err(Error::new(wire::ERR_BAD_DIGEST, "digest").retryable(true));
        }
        match h.pipe.receive(off, &req.body, Duration::from_secs(10)) {
            Ok(n) => Ok(n),
            Err(crate::tunnel::pipe::ReceiveError::Gap(n)) => {
                h.pipe.close_with(Some(io::ErrorKind::InvalidData));
                Err(Error::new(wire::ERR_OFFSET_GAP, format!("expected {n}")))
            }
            Err(crate::tunnel::pipe::ReceiveError::Full) => {
                Err(Error::new(wire::ERR_BUFFER_EXHAUSTED, "receive buffer full").retryable(true))
            }
            Err(_) => Err(Error::new(wire::ERR_TUNNEL_NOT_FOUND, "tunnel not found")),
        }
    }
    pub fn http_down(
        &self,
        req: &crate::net::http1::Request,
        id: &str,
        cfg: &crate::config::Config,
        from: i64,
        wait: Duration,
    ) -> Result<Option<(i64, Vec<u8>)>> {
        let t = self.http_find(req, id, cfg)?;
        Ok(t.http
            .as_ref()
            .unwrap()
            .pipe
            .wait_for_data(from, wait)
            .map(|(o, d)| (o, d[..d.len().min(crate::tunnel::http::MAX_POLL)].to_vec())))
    }
    pub fn http_confirm_up_offset(
        &self,
        req: &crate::net::http1::Request,
        id: &str,
        cfg: &crate::config::Config,
    ) -> Result<i64> {
        let t = self.http_find(req, id, cfg)?;
        Ok(t.http.as_ref().unwrap().pipe.received())
    }
    pub fn http_delete(
        &self,
        req: &crate::net::http1::Request,
        id: &str,
        cfg: &crate::config::Config,
    ) -> Result<()> {
        let t = self.http_find_ack(req, id, cfg)?;
        t.session.close();
        self.drop_tunnel(&t.peer, id);
        Ok(())
    }

    /// Opens a stream on the best live tunnel of `peer`.
    ///
    /// "Best" is the lowest priority value, then the fewest open streams,
    /// then the lowest id, so a burst spreads over the tunnels that are up
    /// instead of piling onto one.
    pub fn open_stream(&self, peer: &str) -> Result<crate::mux::Stream> {
        let mut last =
            Error::new(wire::ERR_TUNNEL_NOT_FOUND, "reverse tunnel unavailable").retryable(true);
        for _ in 0..4 {
            let picked = {
                let peers = self.peers.lock().unwrap();
                let Some(p) = peers.get(peer) else {
                    return Err(last);
                };
                let mut best: Option<Arc<RegisteredTunnel>> = None;
                for t in p.tunnels.values() {
                    if t.session.is_closed() {
                        continue;
                    }
                    if t.session.num_streams() >= MAX_STREAMS_PER_TUNNEL {
                        continue;
                    }
                    best = Some(match best {
                        None => t.clone(),
                        Some(b) => {
                            let (tn, bn) = (t.session.num_streams(), b.session.num_streams());
                            let better = t.priority < b.priority
                                || (t.priority == b.priority
                                    && (tn < bn || (tn == bn && t.id < b.id)));
                            if better {
                                t.clone()
                            } else {
                                b
                            }
                        }
                    });
                }
                best
            };
            let Some(tunnel) = picked else {
                return Err(last);
            };
            match tunnel.session.open() {
                Ok(s) => return Ok(s),
                Err(e) => {
                    // The tunnel is failing; drop it and let the next attempt
                    // pick another.
                    last = Error::new(
                        wire::ERR_TUNNEL_NOT_FOUND,
                        format!("open stream on {}: {e}", tunnel.id),
                    )
                    .retryable(true);
                    tunnel.session.close();
                    self.drop_tunnel(&tunnel.peer, &tunnel.id);
                }
            }
        }
        Err(last)
    }

    fn drop_tunnel(&self, peer: &str, id: &str) {
        let mut peers = self.peers.lock().unwrap();
        if let Some(p) = peers.get_mut(peer) {
            p.tunnels.remove(id);
        }
    }

    pub fn revalidate(&self, outbound: &HashMap<String, String>) {
        let mut peers = self.peers.lock().unwrap();
        for (peer, p) in peers.iter_mut() {
            let expected = outbound
                .get(peer)
                .map(|t| crate::util::hex(&crate::util::sha256::digest(t.as_bytes())));
            for t in p.tunnels.values() {
                let current = expected.as_deref().is_some_and(|e| {
                    crate::egress::constant_time_eq(e.as_bytes(), t.credential.as_bytes())
                });
                if !current {
                    crate::slog::info(
                        "reverse tunnel closed: credential rotated",
                        &[
                            ("peer", peer.as_str().into()),
                            ("tunnel", t.id.as_str().into()),
                        ],
                    );
                    t.session.close();
                }
            }
            p.tunnels.retain(|_, t| !t.session.is_closed());
        }
    }

    pub fn missing_peers(&self) -> Vec<String> {
        let peers = self.peers.lock().unwrap();
        let mut missing: Vec<String> = peers
            .iter()
            .filter(|(_, p)| !p.tunnels.values().any(|t| !t.session.is_closed()))
            .map(|(id, _)| id.clone())
            .collect();
        missing.sort();
        missing
    }

    #[allow(dead_code)]
    pub fn live_tunnels(&self, peer: &str) -> usize {
        self.peers
            .lock()
            .unwrap()
            .get(peer)
            .map(|p| {
                p.tunnels
                    .values()
                    .filter(|t| !t.session.is_closed())
                    .count()
            })
            .unwrap_or(0)
    }

    pub(crate) fn metrics_snapshot(&self) -> (BTreeMap<(String, String), u64>, u64) {
        let peers = self.peers.lock().unwrap();
        let mut live = BTreeMap::new();
        for (peer, tunnels) in peers.iter() {
            for tunnel in tunnels.tunnels.values() {
                if !tunnel.session.is_closed() {
                    *live
                        .entry((peer.clone(), tunnel.transport.clone()))
                        .or_insert(0) += 1;
                }
            }
        }
        (live, self.accepted.load(Ordering::Relaxed))
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        let peers = self.peers.lock().unwrap();
        for p in peers.values() {
            for t in p.tunnels.values() {
                t.session.close();
            }
        }
    }

    fn verify(
        &self,
        req: &crate::net::http1::Request,
        cfg: &crate::config::Config,
    ) -> Result<Offer> {
        if req.method != "GET" {
            return Err(Error::new(wire::ERR_BAD_FRAME, "method"));
        }
        let auth = self
            .auth
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let peer = authenticate(&auth, req, cfg)?;
        let peer_cfg = cfg
            .peer(&peer)
            .ok_or_else(|| Error::new(wire::ERR_UNAUTHORIZED, "unauthorized"))?;

        let node_seen = header(&req.headers, H_NODE_ID).unwrap_or("");
        if node_seen != peer_cfg.expected_node_id {
            return Err(Error::new(wire::ERR_NODE_MISMATCH, "node identity"));
        }
        if header(&req.headers, H_EXPECTED_NODE_ID).unwrap_or("") != self.node_id {
            return Err(Error::new(wire::ERR_NODE_MISMATCH, "expected node"));
        }
        let id = header(&req.headers, H_TUNNEL_ID).unwrap_or("");
        if !valid_tunnel_id(id) {
            return Err(Error::new(wire::ERR_BAD_FRAME, "tunnel identity"));
        }
        let instance = header(&req.headers, wire::H_INSTANCE_ID).unwrap_or("");
        if instance.is_empty() || instance.len() > 128 {
            return Err(Error::new(wire::ERR_BAD_FRAME, "tunnel identity"));
        }
        let priority: i32 = header(&req.headers, H_TUNNEL_PRIORITY)
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| Error::new(wire::ERR_BAD_FRAME, "tunnel priority"))?;
        if priority < 0 {
            return Err(Error::new(wire::ERR_BAD_FRAME, "tunnel priority"));
        }

        // The subprotocol says which protocol revision the database side
        // speaks. A different one is a mismatch, not an unsupported transport.
        let offered = header(&req.headers, "sec-websocket-protocol").unwrap_or("");
        let mut exact = false;
        let mut other = false;
        for p in offered.split(',') {
            let p = p.trim();
            if p == REVERSE_SUBPROTOCOL {
                exact = true;
            } else if p.starts_with(REVERSE_SUBPROTOCOL_PREFIX) {
                other = true;
            }
        }
        if !exact {
            return if other {
                Err(Error::new(wire::ERR_PROTOCOL_MISMATCH, "protocol"))
            } else {
                Err(Error::new(wire::ERR_TRANSPORT_UNSUPPORTED, "subprotocol"))
            };
        }
        if !req.is_websocket_upgrade() {
            return Err(Error::new(
                wire::ERR_TRANSPORT_UNSUPPORTED,
                "not a WebSocket upgrade",
            ));
        }
        if req.header("sec-websocket-version") != Some("13") {
            return Err(Error::new(wire::ERR_BAD_FRAME, "invalid WebSocket version"));
        }
        let key = req
            .header("sec-websocket-key")
            .ok_or_else(|| Error::new(wire::ERR_BAD_FRAME, "missing WebSocket key"))?;
        if crate::util::base64::decode(key.trim())
            .map(|decoded| decoded.len() != 16)
            .unwrap_or(true)
        {
            return Err(Error::new(wire::ERR_BAD_FRAME, "invalid WebSocket key"));
        }

        // Conflicts: a duplicate id, another live instance of the same peer,
        // or the per-peer tunnel cap.
        let mut peers = self.peers.lock().unwrap();
        let Some(p) = peers.get_mut(&peer) else {
            return Err(Error::new(wire::ERR_UNAUTHORIZED, "unauthorized"));
        };
        // Drop tunnels whose multiplexer already ended before counting: a
        // reconnect must not be refused because dead entries fill the cap.
        p.tunnels.retain(|_, t| !t.session.is_closed());
        if p.tunnels.contains_key(id) {
            return Err(Error::new(
                wire::ERR_TUNNEL_CONFLICT,
                "tunnel id already registered",
            ));
        }
        if p.tunnels
            .values()
            .any(|t| t.instance != instance && !t.session.is_closed())
        {
            return Err(Error::new(
                wire::ERR_TUNNEL_CONFLICT,
                "another instance of this peer holds live tunnels",
            )
            .retryable(true));
        }
        if p.tunnels.len() >= MAX_TUNNELS_PER_PEER {
            return Err(Error::new(wire::ERR_QUOTA_EXCEEDED, "tunnels per peer").retryable(true));
        }
        Ok(Offer {
            peer,
            id: id.to_string(),
            instance: instance.to_string(),
            priority,
            token: header(&req.headers, wire::H_PEER_AUTH)
                .and_then(|v| v.strip_prefix("Bearer "))
                .unwrap_or("")
                .to_string(),
        })
    }
}

struct Offer {
    peer: String,
    id: String,
    instance: String,
    priority: i32,
    token: String,
}

/// Maps the bearer token to a reverse peer, comparing every candidate so the
/// work does not depend on which one matched.
fn authenticate(
    provider: &Option<Arc<crate::auth::Authenticator>>,
    req: &crate::net::http1::Request,
    cfg: &crate::config::Config,
) -> Result<String> {
    let auth_header = header(&req.headers, wire::H_PEER_AUTH)
        .ok_or_else(|| Error::new(wire::ERR_UNAUTHORIZED, "unauthorized"))?;
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| Error::new(wire::ERR_UNAUTHORIZED, "unauthorized"))?;
    if token.is_empty() || token.trim() != token {
        return Err(Error::new(wire::ERR_UNAUTHORIZED, "unauthorized"));
    }
    let node_seen = header(&req.headers, H_NODE_ID).unwrap_or("");
    let mut matched: Option<String> = None;
    let mut by_node: Option<String> = None;
    for p in &cfg.peers {
        if !p.reverse {
            continue;
        }
        let expected = match provider {
            Some(auth) => match auth.outbound_token(&p.id) {
                Some(token) => token,
                None => continue,
            },
            None => p.token.clone(),
        };
        if !expected.is_empty()
            && crate::egress::constant_time_eq(expected.as_bytes(), token.as_bytes())
        {
            if matched.is_none() {
                matched = Some(p.id.clone());
            }
            if by_node.is_none() && p.expected_node_id == node_seen {
                by_node = Some(p.id.clone());
            }
        }
    }
    // Several reverse peers may share a token; the one whose expected node id
    // the handshake names wins.
    by_node
        .or(matched)
        .ok_or_else(|| Error::new(wire::ERR_UNAUTHORIZED, "unauthorized"))
}

/// The reverse-mode dialer for a peer client: every connection is a stream on
/// a live tunnel instead of a TCP connect.
pub struct TunnelDialer {
    hub: Arc<Hub>,
    peer: String,
}

impl TunnelDialer {
    pub fn new(hub: Arc<Hub>, peer: &str) -> TunnelDialer {
        TunnelDialer {
            hub,
            peer: peer.to_string(),
        }
    }
}

impl crate::net::http1::Dialer for TunnelDialer {
    /// Opening a stream is local work on a socket that is already open, so
    /// there is nothing to time out on: a tunnel that is gone fails here at
    /// once with `DBB_TUNNEL_NOT_FOUND` instead of after a connect timeout.
    fn dial(&self, _url: &crate::net::Url, _timeout: Duration) -> Result<Box<dyn Conn>> {
        let lease = self.hub.stream_codec_lease()?;
        let stream = self.hub.open_stream(&self.peer)?;
        Ok(match lease {
            Some(lease) => Box::new(crate::net::LeasedConn::new(Box::new(stream), lease)),
            None => Box::new(stream),
        })
    }
}

/// What a verified handshake is waiting on: the upgrade response to send and
/// the identity to register once the multiplexer starts.
pub struct Reserved {
    offer: Offer,
    pub headers: Vec<(String, String)>,
}
