use super::render_helpers::{spec_float, write_family, write_sample, write_scalar};
use super::Metrics;
use crate::config::Config;
use std::sync::atomic::Ordering;

impl Metrics {
    pub fn render(&self, cfg: &Config, _started: std::time::Instant, _ready: bool) -> String {
        let registry = self
            .egress_registry
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|registry| registry.upgrade());
        let egress = registry
            .as_ref()
            .map(|registry| registry.metrics_snapshot());
        let resources = self.resource_manager();
        let mut s = String::new();

        // observability.WriteEventMetrics
        self.write_session_events(&mut s);
        self.write_ingress_faults(&mut s);
        self.write_operation_durations(&mut s);

        // node.writeMetrics
        let payload_used = resources.as_ref().map(|r| r.payload.used().max(0) as u64);
        if let Some(r) = &resources {
            let retained = egress
                .as_ref()
                .map(|e| e.recovery_retained_bytes)
                .unwrap_or_else(|| r.suspended.used().max(0) as u64);
            write_family(
                &mut s,
                "dbb_recovery_retained_bytes",
                "gauge",
                "Bytes retained for session recovery",
            );
            write_sample(&mut s, "dbb_recovery_retained_bytes", &[], retained);
            write_family(
                &mut s,
                "dbb_recovery_retained_limit",
                "gauge",
                "Limit on bytes retained for session recovery",
            );
            write_sample(
                &mut s,
                "dbb_recovery_retained_limit",
                &[],
                r.suspended.limit(),
            );
            let mut names: Vec<&str> = super::RESOURCES.to_vec();
            names.sort_unstable();
            let in_use = |name: &str| -> i64 {
                egress
                    .as_ref()
                    .and_then(|e| e.resource_in_use.get(name).copied())
                    .map(|v| v as i64)
                    .or_else(|| r.budget(name).map(|b| b.used()))
                    .unwrap_or(0)
            };
            write_family(
                &mut s,
                "dbb_resource_in_use",
                "gauge",
                "Resource budget units in use",
            );
            for name in &names {
                write_sample(
                    &mut s,
                    "dbb_resource_in_use",
                    &[("resource", (*name).to_string())],
                    in_use(name),
                );
            }
            write_family(
                &mut s,
                "dbb_resource_limit",
                "gauge",
                "Resource budget limit",
            );
            for name in &names {
                write_sample(
                    &mut s,
                    "dbb_resource_limit",
                    &[("resource", (*name).to_string())],
                    r.budget(name).map_or(0, |b| b.limit()),
                );
            }
            write_family(
                &mut s,
                "dbb_resource_wait_seconds",
                "summary",
                "Time spent waiting for resource budgets",
            );
            for name in &names {
                let (count, wait) = r.budget(name).map(|b| b.wait_stats()).unwrap_or_default();
                let labels = [("resource", (*name).to_string())];
                write_sample(&mut s, "dbb_resource_wait_seconds_count", &labels, count);
                write_sample(
                    &mut s,
                    "dbb_resource_wait_seconds_sum",
                    &labels,
                    spec_float(wait.as_secs_f64()),
                );
            }
        }
        if let Some(snapshot) = egress.as_ref().filter(|e| e.live_sessions > 0) {
            let mut gauges: Vec<(String, u64)> = vec![
                ("digest_receipts".into(), snapshot.digest_receipts),
                ("down_retained_frames".into(), snapshot.down_retained_frames),
                (
                    "down_unconfirmed_bytes".into(),
                    snapshot.down_unconfirmed_bytes,
                ),
                ("up_pending_frames".into(), snapshot.up_pending_frames),
            ];
            for (state, value) in &snapshot.states {
                if *value > 0 {
                    gauges.push((format!("state_{state}"), *value));
                }
            }
            gauges.sort();
            for (key, value) in gauges {
                write_scalar(
                    &mut s,
                    &format!("dbb_egress_{key}"),
                    "gauge",
                    &format!("Sum of {key} over egress sessions"),
                    value,
                );
            }
        }
        write_family(
            &mut s,
            "dbb_egress_carrier_sessions",
            "gauge",
            "Egress sessions by carrier transport",
        );
        for transport in ["ws", "http-sse"] {
            let value = match &egress {
                Some(snapshot) => snapshot
                    .carrier_sessions
                    .get(transport)
                    .copied()
                    .unwrap_or(0),
                None => self
                    .carrier_sessions
                    .lock()
                    .unwrap()
                    .get(transport)
                    .copied()
                    .unwrap_or(0),
            };
            write_sample(
                &mut s,
                "dbb_egress_carrier_sessions",
                &[("transport", transport.to_string())],
                value,
            );
        }
        if cfg.has_reverse_peers() {
            self.write_reverse_hub_metrics(&mut s, cfg);
        }
        if cfg.reverse.enabled {
            self.write_reverse_client_metrics(&mut s, cfg);
        }
        if cfg.ingress_role() {
            self.write_endpoint_states(&mut s, cfg);
            self.write_phase_durations(&mut s);
            self.write_ingress_sessions(&mut s);
            let connections = self.ingress_connections.load(Ordering::Relaxed);
            let codec = resources
                .as_ref()
                .map_or(0, |r| r.codec.used().max(0) as u64);
            let mut snapshot: Vec<(&str, &str, u64)> = vec![
                (
                    "accept_rejected_total",
                    "counter",
                    self.ingress_accept_rejected.load(Ordering::Relaxed),
                ),
                ("codec_bytes", "gauge", codec),
                ("payload_bytes", "gauge", payload_used.unwrap_or(0)),
            ];
            if connections > 0 {
                snapshot.push(("connections", "gauge", connections));
            }
            snapshot.sort();
            for (name, kind, value) in snapshot {
                write_scalar(
                    &mut s,
                    &format!("dbb_ingress_{name}"),
                    kind,
                    &format!("Ingress {name}"),
                    value,
                );
            }
        }

        // AdminServer.renderMetrics
        let active_sessions = egress
            .as_ref()
            .map(|snapshot| snapshot.active_sessions)
            .unwrap_or_else(|| {
                self.sessions_active
                    .load(Ordering::Relaxed)
                    .saturating_sub(self.suspended_sessions.load(Ordering::Relaxed))
            });
        let suspended_sessions = egress
            .as_ref()
            .map(|snapshot| snapshot.suspended_sessions)
            .unwrap_or_else(|| self.suspended_sessions.load(Ordering::Relaxed));
        let buffer_memory = payload_used
            .or_else(|| egress.as_ref().map(|e| e.buffer_memory_bytes))
            .unwrap_or(0);
        let suspended_mem = egress
            .as_ref()
            .map(|e| e.suspended_mem_bytes)
            .unwrap_or_else(|| self.suspended_mem_bytes.load(Ordering::Relaxed));
        let load = |v: &std::sync::atomic::AtomicU64| v.load(Ordering::Relaxed);
        let scalars: [(&str, &str, &str, u64); 21] = [
            (
                "dbb_active_sessions",
                "gauge",
                "Number of currently active sessions",
                active_sessions,
            ),
            (
                "dbb_suspended_sessions",
                "gauge",
                "Number of currently suspended sessions",
                suspended_sessions,
            ),
            (
                "dbb_unbalanced_release_total",
                "counter",
                "Budget releases that exceeded the held amount (accounting bug indicator)",
                crate::resource::budget::unbalanced_releases(),
            ),
            (
                "dbb_up_bytes_total",
                "counter",
                "Total bytes sent upstream",
                load(&self.upstream_bytes),
            ),
            (
                "dbb_down_bytes_total",
                "counter",
                "Total bytes received downstream",
                load(&self.downstream_bytes),
            ),
            (
                "dbb_post_count_total",
                "counter",
                "Total HTTP POST requests",
                load(&self.post_count),
            ),
            (
                "dbb_piggyback_ack_total",
                "counter",
                "Total piggyback ACK counts",
                load(&self.piggyback_ack),
            ),
            (
                "dbb_explicit_ack_total",
                "counter",
                "Total explicit /ack counts",
                load(&self.explicit_ack),
            ),
            (
                "dbb_resume_success_total",
                "counter",
                "Total successful resumes",
                load(&self.resume_success),
            ),
            (
                "dbb_resume_failed_total",
                "counter",
                "Total failed resumes",
                load(&self.resume_failed),
            ),
            (
                "dbb_buffer_memory_bytes",
                "gauge",
                "Total buffered memory bytes in use",
                buffer_memory,
            ),
            (
                "dbb_suspended_mem_bytes",
                "gauge",
                "Memory bytes occupied by suspended sessions",
                suspended_mem,
            ),
            (
                "dbb_terminated_direct_total",
                "counter",
                "Total sessions terminated directly on failure without resume",
                load(&self.terminated_direct),
            ),
            (
                "dbb_terminated_after_resume_fail_total",
                "counter",
                "Total sessions terminated after recovery failed",
                load(&self.terminated_after_resume_fail),
            ),
            (
                "dbb_remote_cleanup_failed_total",
                "counter",
                "Total remote cleanup delete attempts failed",
                load(&self.remote_cleanup_failed),
            ),
            (
                "dbb_remote_cleanup_unknown_total",
                "counter",
                "Total remote cleanup delete attempts with unknown/stale epoch",
                load(&self.remote_cleanup_unknown),
            ),
            (
                "dbb_client_close_duration_sum_ms",
                "counter",
                "Total client close duration in milliseconds",
                load(&self.client_close_duration_sum_ms),
            ),
            (
                "dbb_client_close_count_total",
                "counter",
                "Total client connections actively closed",
                load(&self.client_close_count),
            ),
            (
                "dbb_dial_total",
                "counter",
                "Backend dial attempts made by the egress role",
                load(&self.dial_total),
            ),
            (
                "dbb_dial_failed_total",
                "counter",
                "Backend dial attempts that failed",
                load(&self.dial_failures),
            ),
            (
                "dbb_auth_reload_success_total",
                "counter",
                "Credential reloads that installed a changed snapshot",
                load(&self.auth_reload_success),
            ),
        ];
        for (name, kind, help, value) in scalars {
            write_scalar(&mut s, name, kind, help, value);
        }
        for (name, kind, help, value) in [
            (
                "dbb_auth_reload_failed_total",
                "counter",
                "Credential load or reload attempts that were rejected",
                load(&self.auth_reload_failed),
            ),
            (
                "dbb_up_fin_applied_total",
                "counter",
                "Upstream FIN frames applied to the backend connection",
                load(&self.up_fin_applied),
            ),
            (
                "dbb_down_fin_acked_total",
                "counter",
                "Downstream FIN frames acknowledged by the peer",
                load(&self.down_fin_acked),
            ),
            ("dbb_backpressure_total", "counter", "Times a session waited for buffer space", load(&self.backpressure)),
            (
                "dbb_admission_rejected_total",
                "counter",
                "Connections and requests rejected by admission control",
                load(&self.admission_rejected),
            ),
            (
                "dbb_auth_credentials_stale",
                "gauge",
                "1 while the last credential reload was rejected and the previous credentials are still in effect",
                load(&self.auth_credentials_stale),
            ),
            (
                "dbb_auth_reload_last_success_timestamp_seconds",
                "gauge",
                "Unix time of the last accepted credential load",
                load(&self.auth_reload_last_success_unix),
            ),
        ] {
            write_scalar(&mut s, name, kind, help, value);
        }
        s
    }
}
