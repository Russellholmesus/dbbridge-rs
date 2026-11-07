use crate::error::Error;
use crate::slog::{self, V};
use std::time::Duration;

fn code_of<'a>(e: &'a Error, fallback: &'a str) -> &'a str {
    if e.code.is_empty() {
        fallback
    } else {
        e.code.as_str()
    }
}

pub fn environment_failed(e: &Error) {
    slog::error(
        "failed to load service credential environment",
        &[
            ("code", code_of(e, "DBB-CFG-006").into()),
            ("err", e.message.as_str().into()),
        ],
    );
}

pub fn config_failed(e: &Error) {
    slog::error(
        "failed to load configuration",
        &[
            ("code", code_of(e, "DBB-CFG-001").into()),
            ("err", e.message.as_str().into()),
        ],
    );
}

pub fn config_warning(warning: &str) {
    slog::warn("configuration warning", &[("warning", warning.into())]);
}

pub fn start_failed(err: &str) {
    slog::error(
        "failed to start node",
        &[("code", "DBB-CFG-010".into()), ("err", err.into())],
    );
}

pub fn starting(node_id: &str) {
    slog::info(
        "starting dbbridge peer node",
        &[("node_id", node_id.into())],
    );
}

pub fn admin_started(listen: &str) {
    slog::info("admin server started", &[("listen", listen.into())]);
}

pub fn reverse_starting(peer_node_id: &str, endpoints: usize, tunnels_per_endpoint: usize) {
    slog::info(
        "reverse tunnels starting",
        &[
            ("peer_node_id", peer_node_id.into()),
            ("endpoints", endpoints.into()),
            ("tunnels_per_endpoint", tunnels_per_endpoint.into()),
        ],
    );
}

pub fn termination_requested() {
    slog::info(
        "received termination request, initiating graceful shutdown (send the signal again to force exit)",
        &[],
    );
}

pub fn fatal(err: &str) {
    slog::error(
        "fatal background failure; stopping the node",
        &[("code", "DBB-CFG-011".into()), ("err", err.into())],
    );
}

pub fn shutting_down(node_id: &str) {
    slog::info(
        "shutting down dbbridge peer node",
        &[("node_id", node_id.into())],
    );
}

pub fn teardown_exceeded(budget: Duration) {
    slog::error(
        "shutdown teardown exceeded its budget; abandoning remaining cleanup",
        &[("budget", V::Dur(budget))],
    );
}

pub fn stopped() {
    slog::info("dbbridge peer node stopped", &[]);
}

pub fn exited_cleanly() {
    slog::info("node exited cleanly", &[]);
}

pub fn workers_panicked(panics: usize) {
    slog::error(
        "worker threads panicked during shutdown",
        &[("panics", panics.into())],
    );
}

pub fn notify_failed(state: &str, e: &std::io::Error) {
    slog::warn(
        "systemd notification failed",
        &[("state", state.into()), ("err", slog::err(e))],
    );
}
