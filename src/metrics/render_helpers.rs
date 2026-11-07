use super::{Metrics, OPERATION_BUCKET_TEXT};
use crate::config::Config;
use std::fmt::Display;
use std::sync::atomic::Ordering;

impl Metrics {
    pub(super) fn write_session_events(&self, out: &mut String) {
        write_family(
            out,
            "dbb_session_events_total",
            "counter",
            "Session lifecycle events by role, event, reason and carrier transition",
        );
        for (labels, value) in self.session_events.lock().unwrap().iter() {
            write_sample(
                out,
                "dbb_session_events_total",
                &[
                    ("role", labels.role.clone()),
                    ("event", labels.event.clone()),
                    ("reason", labels.reason.clone()),
                    ("from", labels.from.clone()),
                    ("to", labels.to.clone()),
                ],
                value,
            );
        }
    }

    pub(super) fn write_ingress_faults(&self, out: &mut String) {
        write_family(
            out,
            "dbb_ingress_faults_total",
            "counter",
            "Carrier faults detected by the ingress, by source and reason",
        );
        for ((source, reason), value) in self.ingress_faults.lock().unwrap().iter() {
            write_sample(
                out,
                "dbb_ingress_faults_total",
                &[("source", source.clone()), ("reason", reason.clone())],
                value,
            );
        }
    }

    pub(super) fn write_operation_durations(&self, out: &mut String) {
        write_family(
            out,
            "dbb_operation_duration_seconds",
            "histogram",
            "Duration of session operations by role and phase",
        );
        for ((role, phase), stats) in self.operation_durations.lock().unwrap().iter() {
            for (index, bound) in OPERATION_BUCKET_TEXT.iter().enumerate() {
                write_sample(
                    out,
                    "dbb_operation_duration_seconds_bucket",
                    &[
                        ("role", role.clone()),
                        ("phase", phase.clone()),
                        ("le", (*bound).to_string()),
                    ],
                    stats.buckets[index],
                );
            }
            write_sample(
                out,
                "dbb_operation_duration_seconds_bucket",
                &[
                    ("role", role.clone()),
                    ("phase", phase.clone()),
                    ("le", "+Inf".to_string()),
                ],
                stats.count,
            );
            write_sample(
                out,
                "dbb_operation_duration_seconds_count",
                &[("role", role.clone()), ("phase", phase.clone())],
                stats.count,
            );
            write_sample(
                out,
                "dbb_operation_duration_seconds_sum",
                &[("role", role.clone()), ("phase", phase.clone())],
                spec_float(stats.sum),
            );
        }
    }

    pub(super) fn write_endpoint_states(&self, out: &mut String, cfg: &Config) {
        write_family(
            out,
            "dbb_endpoint_state",
            "gauge",
            "Endpoint health state (1 for the current state)",
        );
        if !cfg.ingress_role() {
            return;
        }
        let mut endpoints = Vec::new();
        for peer in &cfg.peers {
            if peer.reverse {
                endpoints.push((
                    peer.id.clone(),
                    crate::tunnel::REVERSE_ENDPOINT_ID.to_string(),
                ));
            } else {
                endpoints.extend(
                    peer.endpoints
                        .iter()
                        .map(|endpoint| (peer.id.clone(), endpoint.id.clone())),
                );
            }
        }
        endpoints.sort_by(|a, b| a.0.cmp(&b.0));
        let states = self.endpoint_states.lock().unwrap();
        for (peer, endpoint) in endpoints {
            let current = states
                .get(&(peer.clone(), endpoint.clone()))
                .map(String::as_str)
                .unwrap_or("UNKNOWN");
            for state in ["UNKNOWN", "HEALTHY", "UNHEALTHY", "MISMATCHED"] {
                write_sample(
                    out,
                    "dbb_endpoint_state",
                    &[
                        ("peer", peer.clone()),
                        ("endpoint", endpoint.clone()),
                        ("state", state.to_string()),
                    ],
                    u8::from(state == current),
                );
            }
        }
    }

    pub(super) fn write_phase_durations(&self, out: &mut String) {
        write_family(
            out,
            "dbb_phase_duration_seconds",
            "summary",
            "Duration of ingress phases per endpoint",
        );
        for ((peer, endpoint, phase, success), stats) in self.phase_durations.lock().unwrap().iter()
        {
            let labels = [
                ("peer", peer.clone()),
                ("endpoint", endpoint.clone()),
                ("phase", phase.clone()),
                ("success", success.to_string()),
            ];
            write_sample(
                out,
                "dbb_phase_duration_seconds_sum",
                &labels,
                spec_float(stats.sum),
            );
            write_sample(
                out,
                "dbb_phase_duration_seconds_count",
                &labels,
                stats.count,
            );
        }
    }

    pub(super) fn write_reverse_hub_metrics(&self, out: &mut String, cfg: &Config) {
        write_family(
            out,
            "dbb_reverse_hub_tunnels",
            "gauge",
            "Live reverse tunnels accepted from each reverse peer, by transport",
        );
        let (live, accepted) = self
            .reverse_hub
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|hub| hub.upgrade())
            .map(|hub| hub.metrics_snapshot())
            .unwrap_or_default();
        let mut peers = cfg
            .peers
            .iter()
            .filter(|peer| peer.reverse)
            .map(|peer| peer.id.clone())
            .collect::<Vec<_>>();
        peers.sort();
        for peer in peers {
            for transport in ["ws", "http-sse", "long-poll"] {
                write_sample(
                    out,
                    "dbb_reverse_hub_tunnels",
                    &[("peer", peer.clone()), ("transport", transport.to_string())],
                    live.get(&(peer.clone(), transport.to_string()))
                        .copied()
                        .unwrap_or(0),
                );
            }
        }
        drop(live);
        write_scalar(
            out,
            "dbb_reverse_hub_accepted_total",
            "counter",
            "Reverse tunnels accepted and registered",
            accepted,
        );
        write_family(
            out,
            "dbb_reverse_hub_rejected_total",
            "counter",
            "Reverse tunnel handshakes refused, by DBBridge error code",
        );
        for (code, value) in self.reverse_hub_rejected.lock().unwrap().iter() {
            write_sample(
                out,
                "dbb_reverse_hub_rejected_total",
                &[("code", code.clone())],
                value,
            );
        }
    }

    pub(super) fn write_reverse_client_metrics(&self, out: &mut String, cfg: &Config) {
        write_family(
            out,
            "dbb_reverse_tunnels",
            "gauge",
            "Live reverse tunnels dialed by this node, by endpoint and transport",
        );
        let live = self.reverse_tunnels.lock().unwrap();
        let mut endpoints = cfg
            .reverse
            .endpoints
            .iter()
            .map(|endpoint| endpoint.id.clone())
            .collect::<Vec<_>>();
        endpoints.sort();
        for endpoint in endpoints {
            for transport in ["ws", "http-sse", "long-poll"] {
                write_sample(
                    out,
                    "dbb_reverse_tunnels",
                    &[
                        ("endpoint", endpoint.clone()),
                        ("transport", transport.to_string()),
                    ],
                    live.get(&(endpoint.clone(), transport.to_string()))
                        .copied()
                        .unwrap_or(0),
                );
            }
        }
        drop(live);
        write_scalar(
            out,
            "dbb_reverse_tunnel_established_total",
            "counter",
            "Reverse tunnels established",
            self.reverse_tunnel_established.load(Ordering::Relaxed),
        );
        write_scalar(
            out,
            "dbb_reverse_tunnel_lost_total",
            "counter",
            "Established reverse tunnels that ended while the node was running",
            self.reverse_tunnel_lost.load(Ordering::Relaxed),
        );
        write_scalar(
            out,
            "dbb_reverse_tunnel_dial_failures_total",
            "counter",
            "Failed reverse tunnel dials (after any transport fallback)",
            self.reverse_tunnel_dial_failures.load(Ordering::Relaxed),
        );
        write_family(
            out,
            "dbb_reverse_tunnel_fallback_total",
            "counter",
            "Transport fallbacks of reverse.transport auto",
        );
        for ((from, to), value) in self.reverse_tunnel_fallback.lock().unwrap().iter() {
            write_sample(
                out,
                "dbb_reverse_tunnel_fallback_total",
                &[("from", from.clone()), ("to", to.clone())],
                value,
            );
        }
    }
}

impl Metrics {
    pub(super) fn write_ingress_sessions(&self, out: &mut String) {
        let mut bound: std::collections::BTreeMap<(String, String, String, bool), u64> =
            std::collections::BTreeMap::new();
        let (mut recovering, mut up_pending, mut retained) = (0u64, 0u64, 0u64);
        for g in self.ingress_gauges() {
            if let Some(key) = g.bound {
                *bound.entry(key).or_insert(0) += 1;
            } else if g.recovering {
                recovering += 1;
            }
            up_pending += g.up_pending_bytes;
            retained += g.retained_frames;
        }
        write_family(
            out,
            "dbb_ingress_bound_sessions",
            "gauge",
            "Ingress sessions by bound endpoint and carrier",
        );
        for ((peer, endpoint, transport, recovery), value) in bound {
            write_sample(
                out,
                "dbb_ingress_bound_sessions",
                &[
                    ("peer", peer),
                    ("endpoint", endpoint),
                    ("transport", transport),
                    ("recovery", recovery.to_string()),
                ],
                value,
            );
        }
        write_scalar(
            out,
            "dbb_ingress_recovering_sessions",
            "gauge",
            "Ingress sessions inside a recovery window without an active carrier",
            recovering,
        );
        write_scalar(
            out,
            "dbb_ingress_up_pending_bytes",
            "gauge",
            "Upstream bytes sent but not yet acknowledged",
            up_pending,
        );
        write_scalar(
            out,
            "dbb_ingress_retained_frames",
            "gauge",
            "Upstream frames retained for replay",
            retained,
        );
    }
}

pub(super) struct SpecFloat(pub f64);

pub(super) fn spec_float(v: f64) -> SpecFloat {
    SpecFloat(v)
}

impl Display for SpecFloat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let v = self.0;
        if v == 0.0 {
            return f.write_str("0");
        }
        if !v.is_finite() {
            return f.write_str(if v.is_nan() {
                "NaN"
            } else if v > 0.0 {
                "+Inf"
            } else {
                "-Inf"
            });
        }
        let e = format!("{v:e}"); // shortest digits, e.g. "-1.2345e-5"
        let (mantissa, exp) = e.split_once('e').unwrap_or((&e, "0"));
        let exp: i32 = exp.parse().unwrap_or(0);
        if !(-4..6).contains(&exp) {
            let esign = if exp < 0 { '-' } else { '+' };
            return write!(f, "{mantissa}e{esign}{:02}", exp.abs());
        }
        write!(f, "{v}")
    }
}

pub(super) fn write_family(out: &mut String, name: &str, kind: &str, help: &str) {
    out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} {kind}\n"));
}

pub(super) fn write_scalar<T: Display>(
    out: &mut String,
    name: &str,
    kind: &str,
    help: &str,
    value: T,
) {
    write_family(out, name, kind, help);
    write_sample(out, name, &[], value);
}

pub(super) fn write_sample<T: Display>(
    out: &mut String,
    name: &str,
    labels: &[(&str, String)],
    value: T,
) {
    if labels.is_empty() {
        out.push_str(&format!("{name} {value}\n"));
        return;
    }
    let labels = labels
        .iter()
        .map(|(key, value)| format!("{key}=\"{}\"", escape_label(value)))
        .collect::<Vec<_>>()
        .join(",");
    out.push_str(&format!("{name}{{{labels}}} {value}\n"));
}

fn escape_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}
