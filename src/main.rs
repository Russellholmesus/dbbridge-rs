//! DBBridge — a peer-to-peer database proxy over plain HTTPS.
//!
//! One binary, three roles: an *ingress* node listens on a local TCP port and
//! forwards each accepted connection to a peer, an *egress* node terminates
//! that traffic and dials the real database, and a node can be both. This is
//! the forward-mode implementation of protocol 1.5.
//!
//! No third-party crates: hashing, Base64, JSON, YAML, HTTP/1.1 and WebSocket
//! are implemented here, which keeps the binary self-contained and the
//! supply chain empty.

mod admin;
mod auth;
mod cli;
mod config;
mod egress;
mod error;
mod ingress;
mod metrics;
mod mux;
mod net;
mod node_log;
mod resource;
mod service;
mod session;
mod slog;
mod stream;
mod transport;
mod tunnel;
mod util;
mod wire;

#[cfg(test)]
mod spec_node_tests;

static USER_AGENT: std::sync::RwLock<String> = std::sync::RwLock::new(String::new());

/// The User-Agent for peer requests and handshakes.
pub fn user_agent() -> String {
    let ua = USER_AGENT
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if ua.is_empty() {
        config::DEFAULT_USER_AGENT.to_string()
    } else {
        ua.clone()
    }
}

/// Applies the configured `transport.user_agent` (empty: the default).
pub fn set_user_agent(ua: &str) {
    *USER_AGENT
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = ua.to_string();
}
/// Version reported by `dbbridge version`.
pub const VERSION: &str = match option_env!("DBBRIDGE_VERSION") {
    Some(version) => version,
    None => "1.5-dev",
};
pub const COMMIT: &str = match option_env!("DBBRIDGE_COMMIT") {
    Some(commit) => commit,
    None => "unknown",
};
pub const BUILD_DATE: &str = match option_env!("DBBRIDGE_BUILD_DATE") {
    Some(date) => date,
    None => "unknown",
};
pub const RUSTC_VERSION: &str = env!("DBBRIDGE_RUSTC_VERSION");

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(cli::run(&args));
}
