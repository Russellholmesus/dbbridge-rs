//! Opening the carrier for a session and handing it to the relay.

use std::net::TcpStream;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::{self, Peer};
use crate::error::{Error, Result};
use crate::transport::control::ControlClient;
use crate::transport::sse_carrier::{SseEventReader, SseUpPoster};
use crate::transport::{ws_carrier, CarrierReader, CarrierWriter, Incoming};
use crate::wire::{self, ControlKind};

use super::relay::RelayInit;
use super::{control_client_clone, Ingress, Relay};

impl Ingress {
    pub(super) fn relay_ws(
        &self,
        peer: &Peer,
        ep: &config::Endpoint,
        control: &ControlClient,
        created: &wire::CreateResponse,
        client_conn: TcpStream,
        attach_by: Instant,
    ) -> Result<()> {
        let headers = vec![
            (
                wire::H_PEER_AUTH.to_string(),
                format!("Bearer {}", control.current_token()?),
            ),
            (
                wire::H_SESSION_TOKEN.to_string(),
                created.session_token.clone(),
            ),
            (wire::H_INSTANCE_ID.to_string(), created.instance_id.clone()),
            (wire::H_WS_PURPOSE.to_string(), "session".to_string()),
            (
                wire::H_WS_SESSION_ID.to_string(),
                created.session_id.clone(),
            ),
            (wire::H_WS_EPOCH.to_string(), created.epoch.to_string()),
        ];
        let peer_client = self.client_for(&peer.id);
        let reap_by = (created.unattached_timeout_ms > 0)
            .then(|| Instant::now() + Duration::from_millis(created.unattached_timeout_ms));
        let attach_by = reap_by.map_or(attach_by, |r| r.min(attach_by));
        let timeout = attach_by
            .saturating_duration_since(Instant::now())
            .min(
                self.cfg
                    .transport
                    .ws_handshake_timeout
                    .max(Duration::from_secs(10)),
            )
            .max(Duration::from_millis(1));
        let resource_leases = peer_client.acquire_data_connection_leases(timeout)?;
        let attach_started = Instant::now();
        let attach = ws_carrier::dial_session_via_with_leases(
            &*peer_client.dialer(),
            &ep.url,
            &headers,
            timeout,
            resource_leases,
        );
        self.metrics.observe_ingress_phase(
            &peer.id,
            &ep.id,
            "attach",
            attach.is_ok(),
            attach_started.elapsed(),
        );
        let attach = match attach {
            Ok(attach) => attach,
            Err(e) => {
                let e = if Instant::now() >= attach_by {
                    Error::local(format!("first attach deadline: {}", e.message))
                } else {
                    e
                };
                return self.first_ws_attach_failed(peer, ep, control, created, client_conn, e);
            }
        };
        let ready = &attach.ready;
        if ready.session_id != created.session_id
            || ready.instance_id != created.instance_id
            || ready.epoch != created.epoch
            || ready.stream_id.is_empty()
            || ready.transport.as_deref() != Some("ws")
        {
            return Err(Error::new(
                wire::ERR_WS_PROTOCOL_ERROR,
                "unexpected WS ready binding",
            ));
        }
        let stream_id = ready.stream_id.clone();
        self.run_relay(
            control,
            peer,
            ep,
            created,
            &stream_id,
            client_conn,
            attach.reader,
            attach.writer,
            attach.implicit_ready,
        )
    }

    fn first_ws_attach_failed(
        &self,
        peer: &Peer,
        ep: &config::Endpoint,
        control: &ControlClient,
        created: &wire::CreateResponse,
        client_conn: TcpStream,
        e: Error,
    ) -> Result<()> {
        let sse_offered = self
            .endpoints
            .get(&peer.id, &ep.id)
            .is_some_and(|h| h.transports.contains(&wire::Mode::HttpSse));
        if !created.recovery_enabled
            || peer.protocol != config::Protocol::Auto
            || !sse_offered
            || !first_attach_carrier_failure(&e)
        {
            return Err(e);
        }
        self.forget_precheck(&peer.id, &ep.id, &created.instance_id);
        self.endpoints.record_transport_failure(
            &peer.id,
            &ep.id,
            wire::Mode::Ws,
            peer.failover.cooldown,
        );
        crate::egress::log_debug(&format!(
            "ingress first WS attach of session {} failed ({e}); resuming onto http-sse",
            created.session_id
        ));
        Relay::new(RelayInit {
            cfg: self.cfg.clone(),
            control: control_client_clone(control),
            peer: peer.clone(),
            endpoint: ep.clone(),
            metrics: self.metrics.clone(),
            created,
            stream: "",
            implicit_ready: false,
        })
        .with_endpoints(self.endpoints.clone(), self.prechecks.clone())
        .with_cleanups(self.cleanups.clone())
        .with_failed_first_attach(wire::Mode::HttpSse)
        .run(
            client_conn,
            Box::new(FailedAttachReader(Some(e))),
            Box::new(FailedAttachWriter),
        )
    }

    pub(super) fn relay_sse(
        &self,
        peer: &Peer,
        ep: &config::Endpoint,
        control: &ControlClient,
        created: &wire::CreateResponse,
        client_conn: TcpStream,
    ) -> Result<()> {
        let path = format!(
            "{}/{}/events?epoch={}",
            wire::PATH_SESSIONS,
            created.session_id,
            created.epoch
        );
        let headers = vec![
            (
                wire::H_PEER_AUTH.to_string(),
                format!("Bearer {}", control.current_token()?),
            ),
            (
                wire::H_SESSION_TOKEN.to_string(),
                created.session_token.clone(),
            ),
            (wire::H_INSTANCE_ID.to_string(), created.instance_id.clone()),
            ("Accept".to_string(), "text/event-stream".to_string()),
        ];
        let attach_started = Instant::now();
        let attached = (|| -> Result<_> {
            let peer_client = self.client_for(&peer.id);
            let (conn, resp) = peer_client.stream(
                &ep.url,
                "GET",
                &path,
                &headers,
                self.cfg.transport.failure_detect_timeout,
            )?;
            if resp.status != 200 {
                if let Some(e) = wire::ErrorBody::parse(&String::from_utf8_lossy(&resp.body)) {
                    return Err(e.to_error());
                }
                return Err(Error::local(format!(
                    "event stream answered {}",
                    resp.status
                )));
            }
            // A peer that omits the header needs its ready ACK accepted before the
            // data plane opens, so the upstream pump has to wait for it.
            let implicit_ready = resp
                .header(wire::H_IMPLICIT_READY)
                .map(|v| v.trim() == "1")
                .unwrap_or(false);
            let mut reader =
                SseEventReader::new(conn, created.limits.max_frame_size, created.epoch);
            // The stream starts with the ready event.
            let stream_id = loop {
                match reader.recv()? {
                    Incoming::Control(c) if c.kind == ControlKind::Ready => {
                        if c.session_id != created.session_id
                            || c.instance_id != created.instance_id
                            || c.epoch != created.epoch
                            || c.stream_id.is_empty()
                            || c.transport.as_deref() != Some("http-sse")
                        {
                            return Err(Error::new(
                                wire::ERR_PROTOCOL_MISMATCH,
                                "unexpected SSE ready binding",
                            ));
                        }
                        break c.stream_id;
                    }
                    Incoming::Control(_) => continue,
                    Incoming::Idle => continue,
                    Incoming::Data { .. } => {
                        return Err(Error::new(wire::ERR_PROTOCOL_MISMATCH, "data before ready"))
                    }
                    Incoming::Closed(_) => {
                        return Err(Error::new(
                            wire::ERR_TRANSPORT_UNSUPPORTED,
                            "event stream closed before ready",
                        ))
                    }
                }
            };
            Ok((reader, stream_id, implicit_ready))
        })();
        self.metrics.observe_ingress_phase(
            &peer.id,
            &ep.id,
            "attach",
            attached.is_ok(),
            attach_started.elapsed(),
        );
        let (reader, stream_id, implicit_ready) = attached?;
        let down_ack = Arc::new(AtomicU64::new(0));
        let up_confirm = Arc::new(AtomicU64::new(0));
        let writer = SseUpPoster::new(
            self.client_for(&peer.id),
            ep.url.clone(),
            created.session_id.clone(),
            control.token_provider.clone(),
            created.session_token.clone(),
            created.instance_id.clone(),
            created.epoch,
            stream_id.clone(),
            down_ack.clone(),
            up_confirm.clone(),
        );
        self.run_relay_sse(
            control,
            peer,
            ep,
            created,
            &stream_id,
            client_conn,
            reader,
            writer,
            down_ack,
            up_confirm,
            implicit_ready,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn run_relay(
        &self,
        control: &ControlClient,
        peer: &Peer,
        ep: &config::Endpoint,
        created: &wire::CreateResponse,
        stream_id: &str,
        client_conn: TcpStream,
        reader: impl CarrierReader + 'static,
        writer: impl CarrierWriter + 'static,
        implicit_ready: bool,
    ) -> Result<()> {
        Relay::new(RelayInit {
            cfg: self.cfg.clone(),
            control: control_client_clone(control),
            peer: peer.clone(),
            endpoint: ep.clone(),
            metrics: self.metrics.clone(),
            created,
            stream: stream_id,
            implicit_ready,
        })
        .with_endpoints(self.endpoints.clone(), self.prechecks.clone())
        .with_cleanups(self.cleanups.clone())
        .run(client_conn, Box::new(reader), Box::new(writer))
    }

    #[allow(clippy::too_many_arguments)]
    fn run_relay_sse(
        &self,
        control: &ControlClient,
        peer: &Peer,
        ep: &config::Endpoint,
        created: &wire::CreateResponse,
        stream_id: &str,
        client_conn: TcpStream,
        reader: SseEventReader,
        writer: SseUpPoster,
        down_ack: Arc<AtomicU64>,
        up_confirm: Arc<AtomicU64>,
        implicit_ready: bool,
    ) -> Result<()> {
        let relay = Relay::new(RelayInit {
            cfg: self.cfg.clone(),
            control: control_client_clone(control),
            peer: peer.clone(),
            endpoint: ep.clone(),
            metrics: self.metrics.clone(),
            created,
            stream: stream_id,
            implicit_ready,
        })
        .with_endpoints(self.endpoints.clone(), self.prechecks.clone())
        .with_cleanups(self.cleanups.clone())
        .with_sse(down_ack, up_confirm);
        relay.run(client_conn, Box::new(reader), Box::new(writer))
    }
}

pub(super) fn first_attach_carrier_failure(e: &Error) -> bool {
    if e.code == wire::ERR_WS_HANDSHAKE_FAILED || e.code == wire::ERR_BACKEND_LOST {
        return !e.message.contains("budget");
    }
    if !e.is_local() {
        return false;
    }
    let m = e.message.to_ascii_lowercase();
    !(m.contains("budget")
        || m.contains("local client socket")
        || m.contains("timed out")
        || m.contains("deadline")
        || m.contains("would block")
        || m.contains("temporarily unavailable"))
}

/// The carrier of a first attach that never came up: the relay's first read
/// reports the attach failure as a carrier loss, so recovery starts at once.
struct FailedAttachReader(Option<Error>);

impl CarrierReader for FailedAttachReader {
    fn recv(&mut self) -> Result<Incoming> {
        match self.0.take() {
            Some(e) => Ok(Incoming::Closed(Some(e))),
            None => Ok(Incoming::Closed(Some(Error::new(
                wire::ERR_BACKEND_LOST,
                "carrier closed",
            )))),
        }
    }
}

struct FailedAttachWriter;

impl CarrierWriter for FailedAttachWriter {
    fn send_data(&mut self, _: u64, _: u64, _: &[u8]) -> Result<Option<u64>> {
        Err(Error::new(wire::ERR_BACKEND_LOST, "no carrier").closed(true))
    }
    fn send_control(&mut self, _: &wire::Control) -> Result<()> {
        Err(Error::new(wire::ERR_BACKEND_LOST, "no carrier").closed(true))
    }
    fn shutdown(&mut self) {}
}
