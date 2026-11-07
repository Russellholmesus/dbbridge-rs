//! The human-readable summary `check-config` prints.

use crate::wire::PROTOCOL_VERSION;

use super::Config;

/// network. `check-config --offline` uses this.
pub fn describe(cfg: &Config) -> Vec<String> {
    let mut out = Vec::new();
    out.push(format!("config             {}", cfg.path.display()));
    out.push(format!("node.id            {}", cfg.node.id));
    out.push(format!(
        "roles              {}{}",
        if cfg.ingress_role() { "ingress" } else { "" },
        if cfg.egress_role() && cfg.ingress_role() {
            " + egress"
        } else if cfg.egress_role() {
            "egress"
        } else {
            ""
        }
    ));
    out.push(format!("protocol version   {}", PROTOCOL_VERSION));
    if cfg.egress_role() {
        out.push(format!("http.listen        {}", cfg.http.listen));
        out.push(format!(
            "transports         {}",
            cfg.transports()
                .iter()
                .map(|m| m.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
        out.push(format!("targets            {}", cfg.targets.len()));
        out.push(format!("inbound peers      {}", cfg.inbound.len()));
    }
    if cfg.ingress_role() {
        out.push(format!("listeners          {}", cfg.listeners.len()));
        out.push(format!("peers              {}", cfg.peers.len()));
    }
    out
}
