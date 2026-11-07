//! Reverse mode: the database side dials a long-lived tunnel to the public
//! side, and every DBBridge connection runs as a multiplexed stream inside it.
//!
//! Forward mode has the ingress dial the egress, so the egress must be
//! reachable. Reverse mode inverts only that: the side with the database is
//! often behind NAT or a firewall and can only make outbound connections, so
//! *it* dials out and holds the tunnel open. Everything above the tunnel is
//! unchanged — the public side's ingress still sends HTTP requests, and the
//! database side still answers them from its egress HTTP server. The requests
//! just travel inside a stream instead of over a TCP connection.
//!
//! ```text
//!   local client ──TCP──▶ ingress ─┐
//!                                  │ HTTP over a mux stream
//!                                  ▼
//!                             tunnel (WS, dialed by the database side)
//!                                  │
//!                                  ▼
//!                            egress HTTP server ──TCP──▶ database
//! ```
//!
//! A peer's virtual endpoint is `http://reverse.tunnel.invalid`: the host is
//! never resolved, it only names the origin so the HTTP client builds a
//! `Host` header. `TunnelDialer` replaces the TCP connect that would follow.

pub mod client;

mod client_http;
mod http;
mod hub;
pub mod pipe;

#[cfg(test)]
#[path = "spec_listener_tests.rs"]
mod spec_listener_tests;

#[cfg(test)]
#[path = "spec_hub2_tests.rs"]
mod spec_hub2_tests;
#[cfg(test)]
#[path = "spec_hub3_tests.rs"]
mod spec_hub3_tests;
#[cfg(test)]
mod spec_pipe3_tests;
mod ws;

#[cfg(test)]
mod tests;

pub use hub::{Hub, ReverseAdmission, TunnelDialer};
// `Reserved` never appears in a signature the rest of the crate writes out —
// `reserve()` hands it straight back to `register()` — but it is part of the
// hub's contract, so it is re-exported rather than left unreachable.
#[allow(unused_imports)]
pub use hub::Reserved;
pub use ws::{split_pipe, split_tunnel};

use std::time::Duration;

use crate::mux::MuxConfig;

/// Where a database side dials its tunnel.
pub const PATH_REVERSE: &str = "/v1/reverse";
/// The subprotocol a tunnel negotiates. The version is part of the token, so
/// a peer on a different protocol revision is refused with
/// `DBB_PROTOCOL_MISMATCH` rather than failing later.
pub const REVERSE_SUBPROTOCOL: &str = "dbbridge.reverse.v1.5";
/// The prefix every reverse subprotocol shares, so a peer speaking a different
/// revision is told `DBB_PROTOCOL_MISMATCH` rather than "unsupported".
const REVERSE_SUBPROTOCOL_PREFIX: &str = "dbbridge.reverse.";

pub const H_TUNNEL_ID: &str = "X-DBB-Tunnel-ID";
pub const H_TUNNEL_PRIORITY: &str = "X-DBB-Tunnel-Priority";
pub const H_NODE_ID: &str = "X-DBB-Node-ID";
pub const H_EXPECTED_NODE_ID: &str = "X-DBB-Expected-Node-ID";

/// The origin of the one virtual endpoint a reverse peer has. Never resolved.
pub const REVERSE_ENDPOINT_URL: &str = "http://reverse.tunnel.invalid";
/// The endpoint id a reverse peer reports in health checks.
pub const REVERSE_ENDPOINT_ID: &str = "tunnel";

/// Live tunnels one public-side node keeps for a single reverse peer.
pub const MAX_TUNNELS_PER_PEER: usize = 64;
/// Streams open at once on one tunnel.
pub const MAX_STREAMS_PER_TUNNEL: usize = 1024;

pub fn http_tunnel_budget() -> i64 {
    2 * pipe::PIPE_CAPACITY as i64
}

pub fn new_tunnel_id() -> crate::error::Result<String> {
    let id = crate::util::random_hex(16).map_err(crate::util::random_error)?;
    Ok(format!("tn_{id}"))
}

pub fn valid_tunnel_id(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("tn_") else {
        return false;
    };
    rest.len() == 32
        && rest
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

pub fn mux_config(t: &crate::config::Transport) -> MuxConfig {
    MuxConfig {
        max_frame_size: 32 * 1024,
        stream_window: t.tunnel_stream_window() as u32,
        max_streams: MAX_STREAMS_PER_TUNNEL,
        max_receive_buffer: t
            .tunnel_stream_window()
            .saturating_mul(MAX_STREAMS_PER_TUNNEL as u64)
            .min(i32::MAX as u64) as usize,
        keepalive: t.heartbeat.max(Duration::from_secs(1)),
        detect: t.failure_detect_timeout.max(Duration::from_secs(3)),
    }
}
