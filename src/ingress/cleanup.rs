//! Remote session cleanup for abnormal ingress termination.
//!
//! The cleanup request is deliberately conservative: it only uses the last
//! observed epoch, never invents a newer epoch, and probes a failover endpoint
//! before sending a DELETE there.  A trusted stale-epoch response means the
//! remote outcome is unknown (the peer may have advanced the epoch), not that
//! another DELETE with a guessed epoch is safe.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::config::Peer;
use crate::error::Error;
use crate::net::http1::Client;
use crate::transport::control::ControlClient;
use crate::wire;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::ingress) enum CleanupResult {
    Confirmed,
    Failed,
    Unknown,
}

#[allow(clippy::too_many_arguments)]
pub(in crate::ingress) fn cleanup_with_failover(
    peer: &Peer,
    client: Arc<Client>,
    primary: &ControlClient,
    sid: &str,
    session_token: &str,
    owner: &str,
    epoch: u64,
    recovering: bool,
    timeout: Duration,
) -> CleanupResult {
    if sid.is_empty() || owner.is_empty() || epoch == 0 {
        return CleanupResult::Failed;
    }

    let mut endpoints = super::Ingress::peer_endpoints(peer);
    endpoints.sort_by_key(|ep| ep.priority);
    let failover = peer.failover.enabled && endpoints.len() > 1;
    let primary_url = primary.url.clone();
    let mut backups = Vec::new();
    for ep in endpoints {
        if ep.url != primary_url {
            backups.push(ep);
        }
    }

    let mut order = Vec::new();
    if !recovering {
        order.push(false);
    }
    if failover {
        order.extend(std::iter::repeat_n(true, backups.len()));
    }
    if recovering {
        order.push(false);
    }
    if order.is_empty() {
        order.push(false);
    }

    let deadline = Instant::now() + timeout;
    let attempt_count = order.len();
    let mut backup_index = 0usize;
    for (index, is_backup) in order.into_iter().enumerate() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let slots = attempt_count.saturating_sub(index).max(1);
        let attempt_timeout = remaining / slots as u32;
        let attempt_timeout = attempt_timeout.max(Duration::from_millis(1));
        let attempt_deadline = Instant::now() + attempt_timeout;

        let ctl = if is_backup {
            let Some(ep) = backups.get(backup_index) else {
                continue;
            };
            backup_index += 1;
            let probe = ControlClient::new(
                client.clone(),
                ep.url.clone(),
                primary.token.clone(),
                String::new(),
                peer.tls.clone(),
            )
            .with_optional_token_provider(primary.token_provider.clone());
            match probe.probe(&peer.expected_node_id) {
                Ok(response) if response.instance_id == owner => ControlClient::new(
                    client.clone(),
                    ep.url.clone(),
                    primary.token.clone(),
                    owner.to_string(),
                    peer.tls.clone(),
                )
                .with_optional_token_provider(primary.token_provider.clone()),
                _ => continue,
            }
        } else {
            ControlClient::new(
                primary.client.clone(),
                primary.url.clone(),
                primary.token.clone(),
                primary.expected_instance.clone(),
                primary.tls.clone(),
            )
        };

        let result = ctl.delete(sid, session_token, epoch);
        match result {
            Ok(()) => return CleanupResult::Confirmed,
            Err(error) if is_trusted_stale_epoch(&error) => {
                return CleanupResult::Unknown;
            }
            Err(_) => {
                // Continue to the next endpoint, but never alter `epoch`.
                if Instant::now() >= attempt_deadline {
                    continue;
                }
            }
        }
    }
    CleanupResult::Failed
}

fn is_trusted_stale_epoch(error: &Error) -> bool {
    error.trusted && error.code == wire::ERR_STALE_EPOCH
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ClientTls, Endpoint, Failover, Protocol};
    use crate::net::Url;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    #[test]
    fn stale_epoch_is_unknown_not_retryable_with_a_guessed_epoch() {
        let error = Error::new(wire::ERR_STALE_EPOCH, "stale")
            .trusted(true)
            .remote_status(409);
        assert!(is_trusted_stale_epoch(&error));
        assert!(!is_trusted_stale_epoch(&Error::new(
            wire::ERR_STALE_EPOCH,
            "untrusted"
        )));
    }

    #[test]
    fn cleanup_result_is_explicit() {
        assert_ne!(CleanupResult::Confirmed, CleanupResult::Unknown);
        assert_ne!(CleanupResult::Failed, CleanupResult::Unknown);
    }

    #[test]
    fn cleanup_uses_backup_endpoint() {
        let backup_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let backup_addr = backup_listener.local_addr().unwrap();
        let primary_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let primary_addr = primary_listener.local_addr().unwrap();
        drop(primary_listener);

        let server = thread::spawn(move || {
            let mut paths = Vec::new();
            for _ in 0..2 {
                let (mut stream, _) = backup_listener.accept().unwrap();
                let (path, body) = read_http_request(&mut stream);
                paths.push(path.clone());
                let response = if path == wire::PATH_PROBE {
                    let request = crate::util::json::parse_bytes(&body).unwrap();
                    let nonce = request
                        .get("nonce")
                        .and_then(crate::util::json::Json::as_str)
                        .unwrap();
                    crate::util::json::obj(vec![
                        (
                            "protocol_version",
                            crate::util::json::Json::from(wire::PROTOCOL_VERSION),
                        ),
                        ("node_id", crate::util::json::Json::from("remote-node")),
                        (
                            "instance_id",
                            crate::util::json::Json::from("owner-instance"),
                        ),
                        ("nonce", crate::util::json::Json::from(nonce)),
                        ("recovery_available", crate::util::json::Json::Bool(false)),
                        (
                            "accepting_new_sessions",
                            crate::util::json::Json::Bool(true),
                        ),
                        (
                            "transports",
                            crate::util::json::Json::Arr(vec![crate::util::json::Json::from(
                                "http-sse",
                            )]),
                        ),
                    ])
                    .to_string()
                } else {
                    assert!(path.starts_with("/v1/sessions/session-1?epoch=1"));
                    crate::util::json::obj(vec![
                        ("session_id", crate::util::json::Json::from("session-1")),
                        (
                            "instance_id",
                            crate::util::json::Json::from("owner-instance"),
                        ),
                        ("epoch", crate::util::json::Json::from("1")),
                        ("closed", crate::util::json::Json::Bool(true)),
                    ])
                    .to_string()
                };
                write_http_response(&mut stream, &response);
            }
            paths
        });

        let primary_url = Url::parse(&format!("http://{primary_addr}")).unwrap();
        let backup_url = Url::parse(&format!("http://{backup_addr}")).unwrap();
        let peer = Peer {
            id: "peer".to_string(),
            expected_node_id: "remote-node".to_string(),
            token: "peer-token".to_string(),
            endpoints: vec![
                Endpoint {
                    id: "primary".to_string(),
                    url: primary_url.clone(),
                    priority: 0,
                },
                Endpoint {
                    id: "backup".to_string(),
                    url: backup_url,
                    priority: 1,
                },
            ],
            failover: Failover {
                enabled: true,
                ..Failover::default()
            },
            protocol: Protocol::Auto,
            recovery_enabled: None,
            reverse: false,
            tls: ClientTls {
                verify: true,
                ..ClientTls::default()
            },
        };
        let client = Arc::new(Client::new(Duration::from_secs(1), Duration::from_secs(1)));
        let primary = ControlClient::new(
            client.clone(),
            primary_url,
            peer.token.clone(),
            "owner-instance".to_string(),
            peer.tls.clone(),
        );
        let result = cleanup_with_failover(
            &peer,
            client,
            &primary,
            "session-1",
            "session-token",
            "owner-instance",
            1,
            false,
            Duration::from_secs(4),
        );
        assert_eq!(result, CleanupResult::Confirmed);
        let paths = server.join().unwrap();
        assert_eq!(
            paths,
            vec![wire::PATH_PROBE, "/v1/sessions/session-1?epoch=1"]
        );
    }

    fn read_http_request(stream: &mut TcpStream) -> (String, Vec<u8>) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 2048];
        let header_end = loop {
            let n = stream.read(&mut chunk).unwrap();
            assert_ne!(n, 0, "request closed before headers");
            bytes.extend_from_slice(&chunk[..n]);
            if let Some(pos) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
        };
        let headers = String::from_utf8_lossy(&bytes[..header_end]).into_owned();
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.split_once(':')
                    .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                    .and_then(|(_, value)| value.trim().parse::<usize>().ok())
            })
            .unwrap_or(0);
        while bytes.len() < header_end + content_length {
            let n = stream.read(&mut chunk).unwrap();
            assert_ne!(n, 0, "request closed before body");
            bytes.extend_from_slice(&chunk[..n]);
        }
        let path = headers
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .to_string();
        (
            path,
            bytes[header_end..header_end + content_length].to_vec(),
        )
    }

    fn write_http_response(stream: &mut TcpStream, body: &str) {
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{}: owner-instance\r\n\r\n{}",
            body.len(),
            wire::H_INSTANCE_ID,
            body
        )
        .unwrap();
        stream.flush().unwrap();
    }
}

#[derive(Default)]
pub(in crate::ingress) struct CleanupTracker {
    state: std::sync::Mutex<TrackerState>,
    cv: std::sync::Condvar,
}

#[derive(Default)]
struct TrackerState {
    running: usize,
    /// Bumped every time the count drops to zero.
    idle_epoch: u64,
}

pub(in crate::ingress) struct CleanupIdle<'a> {
    tracker: &'a CleanupTracker,
    after: Option<u64>,
}

impl CleanupTracker {
    pub(in crate::ingress) fn add(&self) {
        self.state.lock().unwrap().running += 1;
    }

    pub(in crate::ingress) fn done(&self) {
        let mut g = self.state.lock().unwrap();
        g.running = g.running.saturating_sub(1);
        if g.running == 0 {
            g.idle_epoch = g.idle_epoch.wrapping_add(1);
            self.cv.notify_all();
        }
    }

    /// Counts one cleanup until the guard drops.
    pub(in crate::ingress) fn track(&self) -> CleanupGuard<'_> {
        self.add();
        CleanupGuard(self)
    }

    pub(in crate::ingress) fn idle(&self) -> CleanupIdle<'_> {
        let g = self.state.lock().unwrap();
        CleanupIdle {
            tracker: self,
            after: (g.running > 0).then_some(g.idle_epoch),
        }
    }
}

pub(in crate::ingress) struct CleanupGuard<'a>(&'a CleanupTracker);

impl Drop for CleanupGuard<'_> {
    fn drop(&mut self) {
        self.0.done();
    }
}

impl CleanupIdle<'_> {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(in crate::ingress) fn is_ready(&self) -> bool {
        match self.after {
            None => true,
            Some(epoch) => self.tracker.state.lock().unwrap().idle_epoch != epoch,
        }
    }

    /// Waits until ready or `timeout`; returns whether it became ready.
    pub(in crate::ingress) fn wait_timeout(&self, timeout: Duration) -> bool {
        let Some(epoch) = self.after else {
            return true;
        };
        let g = self.tracker.state.lock().unwrap();
        let (g, _) = self
            .tracker
            .cv
            .wait_timeout_while(g, timeout, |s| s.idle_epoch == epoch)
            .unwrap();
        g.idle_epoch != epoch
    }
}
