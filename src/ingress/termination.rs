use crate::slog::{self, V};
use std::cell::Cell;
use std::time::{Instant, SystemTime};

thread_local! {
    /// Set once the relay of the connection served by this thread logged its
    /// termination, so the connection handler does not log a second one.
    static LOGGED: Cell<bool> = const { Cell::new(false) };
}

/// Called when the connection handler starts on its thread.
pub(super) fn reset() {
    LOGGED.with(|l| l.set(false));
}

pub(super) fn logged() -> bool {
    LOGGED.with(Cell::get)
}

pub(super) fn count_termination(
    metrics: &crate::metrics::Metrics,
    reason: &str,
    recovery_enabled: bool,
    recovering: bool,
) {
    if matches!(reason, "normal" | "shutdown") {
        return;
    }
    metrics.session_terminated(recovery_enabled, reason);
    if recovery_enabled && recovering {
        metrics.resume_failed();
    }
}

pub(super) fn short_id(id: &str) -> &str {
    match id.char_indices().nth(12) {
        Some((i, _)) => &id[..i],
        None => id,
    }
}

/// The wall-clock time of a monotonic instant.
pub(super) fn wall(at: Instant) -> SystemTime {
    let now_i = Instant::now();
    let now_s = SystemTime::now();
    if at <= now_i {
        now_s - (now_i - at)
    } else {
        now_s + (at - now_i)
    }
}

#[derive(Debug, Clone)]
pub(super) struct Termination {
    pub session: String,
    pub peer: String,
    pub endpoint: String,
    pub owner: String,
    pub epoch: u64,
    pub transport: &'static str,
    pub recovery_enabled: bool,
    pub attempts: u32,
    pub deadline: Option<SystemTime>,
    pub outcome_unknown: bool,
    pub reason: &'static str,
    pub fault_source: String,
    pub fault_reason: &'static str,
    pub fault_time: Option<SystemTime>,
    pub terminal: SystemTime,
    pub local_closed: SystemTime,
}

impl Termination {
    pub(super) fn settle(mut self, recovering: bool) -> Self {
        if self.fault_time.is_none() && self.reason != "normal" {
            self.fault_time = Some(self.terminal);
        }
        if let Some(deadline) = self.deadline {
            if self.terminal > deadline {
                self.terminal = deadline;
            }
        }
        if !self.recovery_enabled && !recovering {
            if let Some(fault) = self.fault_time {
                if fault < self.terminal {
                    self.terminal = fault;
                }
            }
        }
        self
    }

    pub(super) fn attrs(&self) -> Vec<(&'static str, V<'_>)> {
        let local_close_ms = match self.local_closed.duration_since(self.terminal) {
            Ok(d) => d.as_millis() as i64,
            Err(e) => -(e.duration().as_millis() as i64),
        };
        vec![
            ("session", short_id(&self.session).into()),
            ("role", "ingress".into()),
            ("peer", self.peer.as_str().into()),
            ("endpoint", self.endpoint.as_str().into()),
            ("owner", short_id(&self.owner).into()),
            ("epoch", self.epoch.into()),
            ("transport", self.transport.into()),
            ("recovery_enabled", self.recovery_enabled.into()),
            ("attempts", self.attempts.into()),
            (
                "deadline",
                match self.deadline {
                    Some(t) => V::Time(Some(t)),
                    None => "".into(),
                },
            ),
            ("outcome_unknown", self.outcome_unknown.into()),
            ("reason", self.reason.into()),
            ("fault_source", self.fault_source.as_str().into()),
            ("fault_reason", self.fault_reason.into()),
            ("local_close_ms", local_close_ms.into()),
            ("fault_time", V::Time(self.fault_time)),
            ("terminal_time", V::Time(Some(self.terminal))),
            ("local_closed_time", V::Time(Some(self.local_closed))),
        ]
    }

    pub(super) fn log(&self) {
        LOGGED.with(|l| l.set(true));
        slog::info("session terminated", &self.attrs());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn base() -> Termination {
        let t = UNIX_EPOCH + Duration::from_secs(1_793_341_140);
        Termination {
            session: "0123456789abcdef".into(),
            peer: "peer-b".into(),
            endpoint: "".into(),
            owner: "".into(),
            epoch: 0,
            transport: "",
            recovery_enabled: true,
            attempts: 0,
            deadline: None,
            outcome_unknown: false,
            reason: "dial_failed",
            fault_source: "".into(),
            fault_reason: "",
            fault_time: None,
            terminal: t,
            local_closed: t + Duration::from_millis(3),
        }
    }

    #[test]
    fn record_has_spec_fields_in_spec_order() {
        let r = base().settle(false);
        let keys: Vec<&str> = r.attrs().iter().map(|(k, _)| *k).collect();
        assert_eq!(
            keys,
            [
                "session",
                "role",
                "peer",
                "endpoint",
                "owner",
                "epoch",
                "transport",
                "recovery_enabled",
                "attempts",
                "deadline",
                "outcome_unknown",
                "reason",
                "fault_source",
                "fault_reason",
                "local_close_ms",
                "fault_time",
                "terminal_time",
                "local_closed_time"
            ]
        );
        let line = crate::slog::render(
            crate::slog::Format::Text,
            UNIX_EPOCH,
            crate::slog::Level::Info,
            "session terminated",
            &r.attrs(),
        );
        assert!(line.contains(" session=0123456789ab role=ingress peer=peer-b endpoint=\"\" owner=\"\" epoch=0 transport=\"\" recovery_enabled=true attempts=0 deadline=\"\" outcome_unknown=false reason=dial_failed fault_source=\"\" fault_reason=\"\" local_close_ms=3 fault_time="), "{line}");
    }

    #[test]
    fn non_normal_end_without_fault_uses_terminal_as_fault_time() {
        let r = base().settle(false);
        assert_eq!(r.fault_time, Some(r.terminal));
        let mut n = base();
        n.reason = "normal";
        let n = n.settle(false);
        assert_eq!(n.fault_time, None);
    }

    #[test]
    fn terminal_is_capped_by_deadline_and_fault_when_recovery_is_off() {
        let mut r = base();
        r.deadline = Some(r.terminal - Duration::from_secs(1));
        let want = r.deadline;
        assert_eq!(r.settle(true).terminal, want.unwrap());
        let mut r = base();
        r.recovery_enabled = false;
        r.fault_time = Some(r.terminal - Duration::from_millis(500));
        let fault = r.fault_time.unwrap();
        let r = r.settle(false);
        assert_eq!(r.terminal, fault);
        assert_eq!(r.attrs()[14].0, "local_close_ms");
    }

    #[test]
    fn short_id_is_twelve_chars() {
        assert_eq!(short_id("0123456789abcdef"), "0123456789ab");
        assert_eq!(short_id("abc"), "abc");
    }
}
