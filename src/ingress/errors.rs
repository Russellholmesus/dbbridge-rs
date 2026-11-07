use std::time::Duration;

use crate::error::{Error, Result};
use crate::wire;

const MAX_RETRY_AFTER: Duration = Duration::from_secs(2);

fn status(e: &Error) -> u16 {
    e.remote_status.unwrap_or_else(|| e.status())
}

pub(crate) fn fatal_error(e: &Error) -> bool {
    if e.is_local() {
        return e.message.contains("protocol")
            || e.message.contains("backpressure")
            || e.message.contains("no progress");
    }
    e.trusted
        && (e.session_closed
            || status(e) == 401
            || status(e) == 403
            || matches!(
                e.code.as_str(),
                wire::ERR_BAD_ACK
                    | wire::ERR_BAD_FRAME
                    | wire::ERR_FRAME_CONFLICT
                    | wire::ERR_FRAME_TOO_LARGE
                    | wire::ERR_IDEMPOTENCY_CONFLICT
                    | wire::ERR_RECOVERY_DISABLED
                    | wire::ERR_RECOVERY_UNSUPPORTED
                    | wire::ERR_REPLAY_TOO_OLD
                    | wire::ERR_PROTOCOL_MISMATCH
                    | wire::ERR_NODE_MISMATCH
                    | wire::ERR_TRANSPORT_MISMATCH
                    | wire::ERR_TRANSPORT_UNSUPPORTED
            ))
}

pub(crate) fn safe_retry(e: &Error) -> bool {
    e.trusted
        && e.retryable
        && !e.session_closed
        && (status(e) == 429
            || status(e) == 503
            || matches!(
                e.code.as_str(),
                wire::ERR_WINDOW_EXCEEDED
                    | wire::ERR_CREATE_PENDING
                    | wire::ERR_RESUME_PENDING
                    | wire::ERR_RESUME_IN_PROGRESS
            ))
}

pub(crate) fn terminal_remote(e: &Error) -> bool {
    e.trusted && !e.retryable && (400..500).contains(&status(e)) && !safe_retry(e)
}

pub(crate) fn pause_delay(attempt: u32, e: &Error, random_byte: u8) -> Duration {
    let base_ms = 100u64 * (1u64 << attempt.min(4));
    let base = Duration::from_millis(base_ms.min(2000));
    let jitter = base / 2 + base * u32::from(random_byte) / 512;
    jitter.max(e.retry_after.min(MAX_RETRY_AFTER))
}

pub(crate) fn pause(attempt: u32, e: &Error) -> Result<Duration> {
    let random = crate::util::random_bytes(1).map_err(crate::util::random_error)?;
    let random_byte = random
        .first()
        .copied()
        .ok_or_else(|| Error::local("entropy source returned no jitter byte"))?;
    Ok(pause_delay(attempt, e, random_byte))
}

pub(crate) fn reason_category(e: &Error) -> &'static str {
    if e.code.is_empty() {
        if e.message == "closed_normal" {
            return "normal";
        }
        if e.message.contains("node stopped") || e.message.contains("shutdown") {
            return "shutdown";
        }
        if e.message.contains("local socket") || e.message.contains("local client socket error") {
            return "local_socket";
        }
        if e.message.contains("timeout") || e.message.contains("deadline") {
            return "timeout";
        }
        if e.message.contains("protocol") {
            return "protocol";
        }
        for (needle, category) in [
            ("barrier", "barrier"),
            ("quota", "quota"),
            ("buffer", "buffer"),
            ("backpressure", "timeout"),
        ] {
            if e.message.contains(needle) {
                return category;
            }
        }
        return "network";
    }
    match e.code.as_str() {
        wire::ERR_SESSION_CLOSED => "failed",
        wire::ERR_BACKEND_LOST => "backend_lost",
        wire::ERR_UNAUTHORIZED => "unauthorized",
        wire::ERR_TARGET_FORBIDDEN => "forbidden",
        wire::ERR_BAD_ACK | wire::ERR_REPLAY_TOO_OLD => "offset",
        wire::ERR_FRAME_CONFLICT
        | wire::ERR_BAD_FRAME
        | wire::ERR_BAD_DIGEST
        | wire::ERR_FRAME_TOO_LARGE
        | wire::ERR_IDEMPOTENCY_CONFLICT
        | wire::ERR_PROTOCOL_MISMATCH
        | wire::ERR_NODE_MISMATCH
        | wire::ERR_TRANSPORT_MISMATCH
        | wire::ERR_TRANSPORT_UNSUPPORTED
        | wire::ERR_RECOVERY_DISABLED
        | wire::ERR_RECOVERY_UNSUPPORTED => "protocol",
        wire::ERR_INSTANCE_MISMATCH => "instance",
        wire::ERR_QUOTA_EXCEEDED => "quota",
        wire::ERR_DIAL_FAILED => "dial_failed",
        wire::ERR_DRAINING => "draining",
        wire::ERR_BUFFER_EXHAUSTED => "buffer",
        wire::ERR_RESUME_EXPIRED => "timeout",
        _ => "network",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remote(code: &str, status: u16, trusted: bool, retryable: bool, closed: bool) -> Error {
        Error::new(code, "test")
            .remote_status(status)
            .trusted(trusted)
            .retryable(retryable)
            .closed(closed)
    }

    #[test]
    fn fatal_error_table() {
        assert!(fatal_error(&remote(
            wire::ERR_BAD_FRAME,
            400,
            true,
            false,
            false
        )));
        assert!(fatal_error(&remote(
            wire::ERR_SESSION_CLOSED,
            410,
            true,
            false,
            true
        )));
        assert!(!fatal_error(&remote(
            wire::ERR_BAD_FRAME,
            400,
            false,
            false,
            false
        )));
        assert!(!fatal_error(&remote(
            wire::ERR_QUOTA_EXCEEDED,
            429,
            true,
            true,
            false
        )));
    }

    #[test]
    fn safe_retry_table() {
        assert!(safe_retry(&remote(
            wire::ERR_QUOTA_EXCEEDED,
            429,
            true,
            true,
            false
        )));
        assert!(safe_retry(&remote(
            wire::ERR_WINDOW_EXCEEDED,
            409,
            true,
            true,
            false
        )));
        assert!(!safe_retry(&remote(
            wire::ERR_QUOTA_EXCEEDED,
            429,
            false,
            true,
            false
        )));
        assert!(!safe_retry(&remote(
            wire::ERR_QUOTA_EXCEEDED,
            429,
            true,
            true,
            true
        )));
    }

    #[test]
    fn retry_after_capped_2s() {
        let e = remote(wire::ERR_QUOTA_EXCEEDED, 429, true, true, false)
            .retry_after(Duration::from_secs(99));
        assert_eq!(e.retry_after, MAX_RETRY_AFTER);
        assert_eq!(pause_delay(0, &e, 0), MAX_RETRY_AFTER);
    }

    #[test]
    fn reason_category_names_all_egress_dial_and_drain_refusals() {
        let cases = [
            (wire::ERR_DIAL_FAILED, "dial_failed"),
            (wire::ERR_DRAINING, "draining"),
            (wire::ERR_BAD_ACK, "offset"),
            (wire::ERR_REPLAY_TOO_OLD, "offset"),
            (wire::ERR_BAD_FRAME, "protocol"),
            (wire::ERR_BAD_DIGEST, "protocol"),
            (wire::ERR_FRAME_TOO_LARGE, "protocol"),
            (wire::ERR_FRAME_CONFLICT, "protocol"),
            (wire::ERR_IDEMPOTENCY_CONFLICT, "protocol"),
            (wire::ERR_PROTOCOL_MISMATCH, "protocol"),
            (wire::ERR_NODE_MISMATCH, "protocol"),
            (wire::ERR_TRANSPORT_MISMATCH, "protocol"),
            (wire::ERR_TRANSPORT_UNSUPPORTED, "protocol"),
            (wire::ERR_RECOVERY_DISABLED, "protocol"),
            (wire::ERR_RECOVERY_UNSUPPORTED, "protocol"),
            (wire::ERR_INSTANCE_MISMATCH, "instance"),
        ];
        for (code, want) in cases {
            assert_eq!(reason_category(&Error::new(code, "test")), want, "{code}");
        }

        for code in [
            wire::ERR_FRAME_TOO_LARGE,
            wire::ERR_TRANSPORT_MISMATCH,
            wire::ERR_TRANSPORT_UNSUPPORTED,
            wire::ERR_PROTOCOL_MISMATCH,
            wire::ERR_NODE_MISMATCH,
        ] {
            assert!(
                fatal_error(&Error::new(code, "test").trusted(true)),
                "{code}"
            );
        }
    }

    #[test]
    fn reason_category_table() {
        let cases = [
            (wire::ERR_SESSION_CLOSED, "failed"),
            (wire::ERR_BACKEND_LOST, "backend_lost"),
            (wire::ERR_UNAUTHORIZED, "unauthorized"),
            (wire::ERR_TARGET_FORBIDDEN, "forbidden"),
            (wire::ERR_BAD_ACK, "offset"),
            (wire::ERR_BAD_FRAME, "protocol"),
            (wire::ERR_INSTANCE_MISMATCH, "instance"),
            (wire::ERR_QUOTA_EXCEEDED, "quota"),
            (wire::ERR_DIAL_FAILED, "dial_failed"),
            (wire::ERR_DRAINING, "draining"),
            (wire::ERR_BUFFER_EXHAUSTED, "buffer"),
            (wire::ERR_RESUME_EXPIRED, "timeout"),
        ];
        for (code, want) in cases {
            assert_eq!(reason_category(&Error::new(code, "test")), want, "{code}");
        }
    }
}
