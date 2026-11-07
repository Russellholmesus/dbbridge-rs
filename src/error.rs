//! Error type shared by every layer.
//!
//! A protocol error carries the stable `DBB_*` code the peer will see, so the
//! mapping from an internal failure to a wire response happens in one place.

use std::fmt;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Error {
    /// Stable protocol code (`DBB_*`), or an empty string for a purely local
    /// failure that never reaches the peer.
    pub code: String,
    pub message: String,
    pub retryable: bool,
    /// The failure ended the session, as opposed to one frame or one request.
    pub session_closed: bool,
    pub remote_status: Option<u16>,
    pub trusted: bool,
    pub retry_after: Duration,
}

impl Error {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Error {
            code: code.to_string(),
            message: message.into(),
            retryable: false,
            session_closed: false,
            remote_status: None,
            trusted: false,
            retry_after: Duration::ZERO,
        }
    }

    pub fn local(message: impl Into<String>) -> Self {
        Error {
            code: String::new(),
            message: message.into(),
            retryable: false,
            session_closed: false,
            remote_status: None,
            trusted: false,
            retry_after: Duration::ZERO,
        }
    }

    pub fn retryable(mut self, yes: bool) -> Self {
        self.retryable = yes;
        self
    }

    pub fn closed(mut self, yes: bool) -> Self {
        self.session_closed = yes;
        self
    }

    pub fn trusted(mut self, yes: bool) -> Self {
        self.trusted = yes;
        self
    }

    pub fn remote_status(mut self, status: u16) -> Self {
        self.remote_status = Some(status);
        self
    }

    pub fn retry_after(mut self, delay: Duration) -> Self {
        self.retry_after = delay.min(Duration::from_secs(2));
        self
    }

    pub fn is_local(&self) -> bool {
        self.code.is_empty()
    }

    /// The HTTP status a protocol code maps to when it is answered over HTTP.
    pub fn status(&self) -> u16 {
        // The first response to a frame conflict may both terminate the
        // session and still be a 409. The stored terminal error intentionally
        // has no override, so later tombstone requests remain 410.
        if self.session_closed
            && self.code == crate::wire::ERR_FRAME_CONFLICT
            && self.remote_status == Some(409)
        {
            return 409;
        }
        if self.session_closed
            && matches!(
                self.code.as_str(),
                crate::wire::ERR_FRAME_CONFLICT | crate::wire::ERR_BUFFER_EXHAUSTED
            )
        {
            return 410;
        }
        match self.code.as_str() {
            crate::wire::ERR_BAD_FRAME if self.message == "method" => 405,
            crate::wire::ERR_BAD_FRAME | crate::wire::ERR_BAD_DIGEST | crate::wire::ERR_BAD_ACK => {
                400
            }
            crate::wire::ERR_UNAUTHORIZED => 401,
            crate::wire::ERR_TARGET_FORBIDDEN => 403,
            // Reverse handshakes use the same stable code as probe, but the
            // identity failure is an authorization failure at the tunnel
            // boundary (the probe path remains 409).
            crate::wire::ERR_NODE_MISMATCH
                if self.message == "node identity" || self.message == "expected node" =>
            {
                403
            }
            crate::wire::ERR_SESSION_NOT_FOUND | crate::wire::ERR_TUNNEL_NOT_FOUND => 404,
            crate::wire::ERR_SESSION_CLOSED
            | crate::wire::ERR_BACKEND_LOST
            | crate::wire::ERR_RESUME_EXPIRED => 410,
            crate::wire::ERR_STALE_EPOCH
            | crate::wire::ERR_STREAM_EXISTS
            | crate::wire::ERR_IDEMPOTENCY_CONFLICT
            | crate::wire::ERR_RESUME_IN_PROGRESS
            | crate::wire::ERR_INSTANCE_MISMATCH
            | crate::wire::ERR_NODE_MISMATCH
            | crate::wire::ERR_PROTOCOL_MISMATCH
            | crate::wire::ERR_RECOVERY_DISABLED
            | crate::wire::ERR_RECOVERY_UNSUPPORTED
            | crate::wire::ERR_OFFSET_GAP
            | crate::wire::ERR_FRAME_CONFLICT
            | crate::wire::ERR_REPLAY_TOO_OLD
            | crate::wire::ERR_WINDOW_EXCEEDED
            | crate::wire::ERR_TRANSPORT_MISMATCH
            | crate::wire::ERR_TUNNEL_CONFLICT => 409,
            crate::wire::ERR_FRAME_TOO_LARGE => 413,
            // A reverse request with the right subprotocol but without an
            // actual WebSocket upgrade is specifically an HTTP 426.
            crate::wire::ERR_TRANSPORT_UNSUPPORTED if self.message == "not a WebSocket upgrade" => {
                426
            }
            crate::wire::ERR_TRANSPORT_UNSUPPORTED => 409,
            crate::wire::ERR_QUOTA_EXCEEDED => 429,
            crate::wire::ERR_DIAL_FAILED => 502,
            crate::wire::ERR_BUFFER_EXHAUSTED | crate::wire::ERR_DRAINING => 503,
            crate::wire::ERR_CREATE_PENDING | crate::wire::ERR_RESUME_PENDING => 202,
            _ => 500,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.code.is_empty() {
            f.write_str(&self.message)
        } else {
            write!(f, "[{}] {}", self.code, self.message)
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::local(format!("i/o: {e}"))
    }
}

impl From<std::fmt::Error> for Error {
    fn from(e: std::fmt::Error) -> Self {
        Error::local(format!("format: {e}"))
    }
}

impl From<String> for Error {
    fn from(e: String) -> Self {
        Error::local(e)
    }
}

impl From<&str> for Error {
    fn from(e: &str) -> Self {
        Error::local(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::Error;
    use crate::wire;

    #[test]
    fn error_table() {
        let cases = [
            (wire::ERR_BAD_FRAME, 400, false, false),
            (wire::ERR_BAD_DIGEST, 400, false, false),
            (wire::ERR_BAD_ACK, 400, false, false),
            (wire::ERR_UNAUTHORIZED, 401, false, false),
            (wire::ERR_TARGET_FORBIDDEN, 403, false, true),
            (wire::ERR_SESSION_NOT_FOUND, 404, false, true),
            (wire::ERR_TUNNEL_NOT_FOUND, 404, false, false),
            (wire::ERR_SESSION_CLOSED, 410, false, true),
            (wire::ERR_BACKEND_LOST, 410, false, true),
            (wire::ERR_RESUME_EXPIRED, 410, false, true),
            (wire::ERR_STALE_EPOCH, 409, false, false),
            (wire::ERR_STREAM_EXISTS, 409, false, false),
            (wire::ERR_IDEMPOTENCY_CONFLICT, 409, false, false),
            (wire::ERR_RESUME_IN_PROGRESS, 409, true, false),
            (wire::ERR_INSTANCE_MISMATCH, 409, false, false),
            (wire::ERR_NODE_MISMATCH, 409, false, false),
            (wire::ERR_PROTOCOL_MISMATCH, 409, false, false),
            (wire::ERR_RECOVERY_DISABLED, 409, false, false),
            (wire::ERR_RECOVERY_UNSUPPORTED, 409, false, false),
            (wire::ERR_OFFSET_GAP, 409, false, false),
            (wire::ERR_FRAME_CONFLICT, 409, false, false),
            (wire::ERR_REPLAY_TOO_OLD, 409, false, false),
            (wire::ERR_WINDOW_EXCEEDED, 409, true, false),
            (wire::ERR_TRANSPORT_UNSUPPORTED, 409, false, false),
            (wire::ERR_TRANSPORT_MISMATCH, 409, false, false),
            (wire::ERR_TUNNEL_CONFLICT, 409, false, false),
            (wire::ERR_FRAME_TOO_LARGE, 413, false, false),
            (wire::ERR_QUOTA_EXCEEDED, 429, true, false),
            (wire::ERR_DIAL_FAILED, 502, false, false),
            (wire::ERR_BUFFER_EXHAUSTED, 503, true, false),
            (wire::ERR_DRAINING, 503, true, false),
            (wire::ERR_CREATE_PENDING, 202, true, false),
            (wire::ERR_RESUME_PENDING, 202, true, false),
            (wire::ERR_INTERNAL_ERROR, 500, true, false),
        ];
        for (code, status, retryable, closed) in cases {
            let e = Error::new(code, "test").retryable(retryable).closed(closed);
            assert!(e.code.starts_with("DBB_"));
            assert_eq!(e.status(), status, "{code}");
            assert_eq!(e.retryable, retryable);
            assert_eq!(e.session_closed, closed);
        }
        let local = Error::local("internal");
        assert_eq!(local.code, "");
        assert_eq!(Error::new(wire::ERR_BAD_FRAME, "method").status(), 405);
        assert_eq!(
            Error::new(wire::ERR_NODE_MISMATCH, "node identity").status(),
            403
        );
        assert_eq!(
            Error::new(wire::ERR_TRANSPORT_UNSUPPORTED, "not a WebSocket upgrade").status(),
            426
        );
        assert_eq!(
            Error::new(wire::ERR_FRAME_CONFLICT, "closed conflict")
                .closed(true)
                .status(),
            410
        );
        assert_eq!(
            Error::new(wire::ERR_BUFFER_EXHAUSTED, "terminal budget")
                .closed(true)
                .status(),
            410
        );
    }
}
