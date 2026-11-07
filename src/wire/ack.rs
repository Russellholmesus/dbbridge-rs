//! The rest of the control API: ack, fin and the error body.

use crate::error::{Error, Result};
use crate::util::json::{self, canonical_offset, Json};

use super::{Mode, ERR_BAD_ACK, ERR_BAD_FRAME, ERR_PROTOCOL_MISMATCH};

#[derive(Debug, Clone, Default)]
pub struct AckRequest {
    pub down_delivered_offset: u64,
    pub up_confirmed_offset: u64,
    pub down_fin_applied: bool,
    pub ready_received: bool,
    pub heartbeat_nonce: String,
    pub probe_id: String,
    pub data_rx_blocked: bool,
    pub data_tx_blocked: bool,
    pub backpressure_reason: String,
}

impl AckRequest {
    pub fn to_json(&self) -> Json {
        let mut fields = vec![
            (
                "down_delivered_offset",
                Json::from(self.down_delivered_offset.to_string()),
            ),
            ("down_fin_applied", Json::Bool(self.down_fin_applied)),
            (
                "up_confirmed_offset",
                Json::from(self.up_confirmed_offset.to_string()),
            ),
            ("data_tx_blocked", Json::Bool(self.data_tx_blocked)),
            ("data_rx_blocked", Json::Bool(self.data_rx_blocked)),
            (
                "backpressure_reason",
                Json::from(self.backpressure_reason.as_str()),
            ),
        ];
        if self.ready_received {
            fields.push(("ready_received", Json::Bool(true)));
        }
        if !self.heartbeat_nonce.is_empty() {
            fields.push(("heartbeat_nonce", Json::from(self.heartbeat_nonce.as_str())));
        }
        if !self.probe_id.is_empty() {
            fields.push(("probe_id", Json::from(self.probe_id.as_str())));
        }
        json::obj(fields)
    }

    pub fn from_json(v: &Json) -> Result<Self> {
        v.reject_unknown_fields(&[
            "stream_id",
            "down_delivered_offset",
            "up_confirmed_offset",
            "down_fin_applied",
            "ready_received",
            "heartbeat_nonce",
            "probe_id",
            "data_tx_blocked",
            "data_rx_blocked",
            "backpressure_reason",
        ])
        .map_err(|e| Error::new(ERR_BAD_FRAME, e))?;
        let bad = |k: &str| Error::new(ERR_BAD_FRAME, format!("invalid control body field {k:?}"));
        let req_bool = |k: &str| match v.get(k) {
            Some(Json::Bool(b)) => Ok(*b),
            _ => Err(bad(k)),
        };
        let opt_bool = |k: &str| match v.get(k) {
            None => Ok(false),
            Some(Json::Bool(b)) => Ok(*b),
            _ => Err(bad(k)),
        };
        let req_str = |k: &str| match v.get(k) {
            Some(Json::Str(s)) => Ok(s.clone()),
            _ => Err(bad(k)),
        };
        let opt_str = |k: &str| match v.get(k) {
            None => Ok(String::new()),
            Some(Json::Str(s)) => Ok(s.clone()),
            _ => Err(bad(k)),
        };
        let down = req_str("down_delivered_offset")?;
        let up = req_str("up_confirmed_offset")?;
        let down_fin_applied = req_bool("down_fin_applied")?;
        let data_tx_blocked = req_bool("data_tx_blocked")?;
        let data_rx_blocked = req_bool("data_rx_blocked")?;
        let backpressure_reason = req_str("backpressure_reason")?;
        let ready_received = opt_bool("ready_received")?;
        let heartbeat_nonce = opt_str("heartbeat_nonce")?;
        let probe_id = opt_str("probe_id")?;
        opt_str("stream_id")?;
        let off = |s: &str| {
            canonical_offset(s).ok_or_else(|| Error::new(ERR_BAD_ACK, "non-canonical ack offset"))
        };
        Ok(AckRequest {
            down_delivered_offset: off(&down)?,
            up_confirmed_offset: off(&up)?,
            down_fin_applied,
            ready_received,
            heartbeat_nonce,
            probe_id,
            data_rx_blocked,
            data_tx_blocked,
            backpressure_reason,
        })
    }
}

#[derive(Debug, Clone)]
pub struct AckResponse {
    pub session_id: String,
    pub instance_id: String,
    pub epoch: u64,
    pub stream_id: String,
    pub mode: Mode,
    pub ack_up_offset: u64,
    pub up_fin_applied: bool,
    pub down_ack_offset: u64,
    pub down_fin_acked: bool,
    pub probe_id: String,
    pub data_tx_blocked: bool,
    pub data_rx_blocked: bool,
    pub backpressure_reason: String,
}

impl AckResponse {
    pub fn to_json(&self) -> Json {
        let mut fields = vec![
            ("session_id", Json::from(self.session_id.as_str())),
            ("instance_id", Json::from(self.instance_id.as_str())),
            ("epoch", Json::from(self.epoch.to_string())),
            ("ack_up_offset", Json::from(self.ack_up_offset.to_string())),
            ("up_fin_applied", Json::Bool(self.up_fin_applied)),
            (
                "down_ack_offset",
                Json::from(self.down_ack_offset.to_string()),
            ),
            ("down_fin_acked", Json::Bool(self.down_fin_acked)),
            ("stream_id", Json::from(self.stream_id.as_str())),
            (
                "transport",
                json::obj(vec![("mode", Json::from(self.mode.as_str()))]),
            ),
            ("data_tx_blocked", Json::Bool(self.data_tx_blocked)),
            ("data_rx_blocked", Json::Bool(self.data_rx_blocked)),
            (
                "backpressure_reason",
                Json::from(self.backpressure_reason.as_str()),
            ),
        ];
        if !self.probe_id.is_empty() {
            fields.push(("probe_id", Json::from(self.probe_id.as_str())));
        }
        json::obj(fields)
    }

    pub fn from_json(v: &Json) -> Result<Self> {
        let transport = v
            .get("transport")
            .ok_or_else(|| Error::new(ERR_PROTOCOL_MISMATCH, "ack response: transport"))?;
        v.reject_unknown_fields(&[
            "session_id",
            "instance_id",
            "epoch",
            "stream_id",
            "transport",
            "ack_up_offset",
            "up_fin_applied",
            "down_ack_offset",
            "down_fin_acked",
            "probe_id",
            "data_tx_blocked",
            "data_rx_blocked",
            "backpressure_reason",
        ])
        .map_err(|e| Error::new(ERR_PROTOCOL_MISMATCH, e))?;
        transport
            .reject_unknown_fields(&["mode"])
            .map_err(|e| Error::new(ERR_PROTOCOL_MISMATCH, e))?;
        let mode = Mode::parse(transport.str_field("mode")?)
            .ok_or_else(|| Error::new(ERR_PROTOCOL_MISMATCH, "ack response: mode"))?;
        let epoch = canonical_offset(v.str_field("epoch")?)
            .ok_or_else(|| Error::new(ERR_PROTOCOL_MISMATCH, "ack response: epoch"))?;
        Ok(AckResponse {
            session_id: v.str_field("session_id")?.to_string(),
            instance_id: v.str_field("instance_id")?.to_string(),
            epoch,
            stream_id: v.str_field("stream_id")?.to_string(),
            mode,
            ack_up_offset: v.offset("ack_up_offset")?,
            up_fin_applied: v.bool_field("up_fin_applied")?,
            down_ack_offset: v.offset("down_ack_offset")?,
            down_fin_acked: v.bool_field("down_fin_acked")?,
            probe_id: v
                .get("probe_id")
                .and_then(Json::as_str)
                .unwrap_or_default()
                .to_string(),
            data_tx_blocked: v
                .get("data_tx_blocked")
                .and_then(Json::as_bool)
                .unwrap_or(false),
            data_rx_blocked: v
                .get("data_rx_blocked")
                .and_then(Json::as_bool)
                .unwrap_or(false),
            backpressure_reason: v
                .get("backpressure_reason")
                .and_then(Json::as_str)
                .unwrap_or_default()
                .to_string(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct FinResponse {
    pub session_id: String,
    pub instance_id: String,
    pub epoch: u64,
    pub stream_id: String,
    pub mode: Mode,
    pub up_fin_applied: bool,
}

impl FinResponse {
    pub fn to_json(&self) -> Json {
        json::obj(vec![
            ("session_id", Json::from(self.session_id.as_str())),
            ("instance_id", Json::from(self.instance_id.as_str())),
            ("epoch", Json::from(self.epoch.to_string())),
            ("up_fin_applied", Json::Bool(self.up_fin_applied)),
            ("stream_id", Json::from(self.stream_id.as_str())),
            (
                "transport",
                json::obj(vec![("mode", Json::from(self.mode.as_str()))]),
            ),
        ])
    }

    pub fn from_json(v: &Json) -> Result<Self> {
        let transport = v
            .get("transport")
            .ok_or_else(|| Error::new(ERR_PROTOCOL_MISMATCH, "fin response: transport"))?;
        v.reject_unknown_fields(&[
            "session_id",
            "instance_id",
            "epoch",
            "stream_id",
            "transport",
            "up_fin_applied",
        ])
        .map_err(|e| Error::new(ERR_PROTOCOL_MISMATCH, e))?;
        transport
            .reject_unknown_fields(&["mode"])
            .map_err(|e| Error::new(ERR_PROTOCOL_MISMATCH, e))?;
        Ok(FinResponse {
            session_id: v.str_field("session_id")?.to_string(),
            instance_id: v.str_field("instance_id")?.to_string(),
            epoch: canonical_offset(v.str_field("epoch")?)
                .ok_or_else(|| Error::new(ERR_PROTOCOL_MISMATCH, "fin response: epoch"))?,
            stream_id: v.str_field("stream_id")?.to_string(),
            mode: Mode::parse(transport.str_field("mode")?)
                .ok_or_else(|| Error::new(ERR_PROTOCOL_MISMATCH, "fin response: mode"))?,
            up_fin_applied: v.bool_field("up_fin_applied")?,
        })
    }
}

/// The `error` body used by every HTTP refusal.
#[derive(Debug, Clone)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    pub session_closed: bool,
}

impl ErrorBody {
    pub fn from_error(e: &Error) -> Self {
        ErrorBody {
            code: e.code.clone(),
            message: e.message.clone(),
            retryable: e.retryable,
            session_closed: e.session_closed,
        }
    }

    pub fn to_json(&self) -> Json {
        json::obj(vec![
            ("code", Json::from(self.code.as_str())),
            ("message", Json::from(self.message.as_str())),
            ("retryable", Json::Bool(self.retryable)),
            ("session_closed", Json::Bool(self.session_closed)),
        ])
    }

    pub fn parse(body: &str) -> Option<ErrorBody> {
        let v = json::parse(body).ok()?;
        Some(ErrorBody {
            code: v.get("code")?.as_str()?.to_string(),
            message: v
                .get("message")
                .and_then(Json::as_str)
                .unwrap_or_default()
                .to_string(),
            retryable: v.get("retryable").and_then(Json::as_bool).unwrap_or(false),
            session_closed: v
                .get("session_closed")
                .and_then(Json::as_bool)
                .unwrap_or(false),
        })
    }

    pub fn to_error(&self) -> Error {
        Error {
            code: self.code.clone(),
            message: self.message.clone(),
            retryable: self.retryable,
            session_closed: self.session_closed,
            remote_status: None,
            trusted: false,
            retry_after: std::time::Duration::ZERO,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::json;
    use crate::wire::ERR_BAD_DIGEST;

    #[test]
    fn ack_request_rejects_null_and_case_alias_for_required_fields() {
        let null_bool = json::parse(
            r#"{"down_delivered_offset":"0","up_confirmed_offset":"0","down_fin_applied":null,"data_tx_blocked":false,"data_rx_blocked":false,"backpressure_reason":"none"}"#,
        )
        .unwrap();
        assert!(AckRequest::from_json(&null_bool).is_err());

        let wrong_case = json::parse(
            r#"{"down_delivered_offset":"0","up_confirmed_offset":"0","down_fin_applied":false,"data_tx_blocked":false,"data_rx_blocked":false,"backpressure_reason":"none","Down_fin_applied":false}"#,
        )
        .unwrap();
        let err = AckRequest::from_json(&wrong_case).unwrap_err();
        assert_eq!(err.code, ERR_BAD_FRAME);

        let valid = json::parse(
            r#"{"down_delivered_offset":"0","up_confirmed_offset":"0","down_fin_applied":false,"data_tx_blocked":false,"data_rx_blocked":false,"backpressure_reason":"none"}"#,
        )
        .unwrap();
        let json::Json::Obj(fields) = &valid else {
            panic!("ACK request fixture must be an object");
        };
        for required in [
            "down_fin_applied",
            "data_tx_blocked",
            "data_rx_blocked",
            "backpressure_reason",
        ] {
            let missing = json::Json::Obj(
                fields
                    .iter()
                    .filter(|(name, _)| name.as_str() != required)
                    .cloned()
                    .collect(),
            );
            assert!(
                AckRequest::from_json(&missing).is_err(),
                "accepted without {required}"
            );
        }

        for invalid in [
            r#"{"down_delivered_offset":"0","up_confirmed_offset":"0","down_fin_applied":false,"data_tx_blocked":"false","data_rx_blocked":false,"backpressure_reason":"none"}"#,
            r#"{"down_delivered_offset":"0","up_confirmed_offset":"0","down_fin_applied":false,"data_tx_blocked":false,"data_rx_blocked":false,"backpressure_reason":null}"#,
        ] {
            let value = json::parse(invalid).unwrap();
            assert!(AckRequest::from_json(&value).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn ack_response_keeps_transport_epoch_and_offsets_bound() {
        let wire = json::parse(
            r#"{"session_id":"s","instance_id":"i","epoch":"7","stream_id":"st","transport":{"mode":"http-sse"},"ack_up_offset":"11","up_fin_applied":true,"down_ack_offset":"13","down_fin_acked":false,"probe_id":"p","data_tx_blocked":true,"data_rx_blocked":false,"backpressure_reason":"window"}"#,
        )
        .unwrap();
        let parsed = AckResponse::from_json(&wire).unwrap();
        assert_eq!(parsed.session_id, "s");
        assert_eq!(parsed.instance_id, "i");
        assert_eq!(parsed.epoch, 7);
        assert_eq!(parsed.stream_id, "st");
        assert_eq!(parsed.mode, Mode::HttpSse);
        assert_eq!(parsed.ack_up_offset, 11);
        assert!(parsed.up_fin_applied);
        assert_eq!(parsed.down_ack_offset, 13);
        assert!(!parsed.down_fin_acked);
        assert_eq!(parsed.probe_id, "p");
        assert!(parsed.data_tx_blocked);
        assert!(!parsed.data_rx_blocked);
        assert_eq!(parsed.backpressure_reason, "window");

        let bad_mode = json::parse(
            r#"{"session_id":"s","instance_id":"i","epoch":"7","stream_id":"st","transport":{"mode":"tcp"},"ack_up_offset":"11","up_fin_applied":true,"down_ack_offset":"13","down_fin_acked":false,"data_tx_blocked":false,"data_rx_blocked":false,"backpressure_reason":"none"}"#,
        )
        .unwrap();
        assert_eq!(
            AckResponse::from_json(&bad_mode).unwrap_err().code,
            ERR_PROTOCOL_MISMATCH
        );
    }

    #[test]
    fn error_body_round_trips_stable_wire_flags() {
        let source = Error::new(ERR_BAD_DIGEST, "payload sha256 mismatch")
            .retryable(true)
            .closed(true);
        let body = ErrorBody::from_error(&source);
        let encoded = body.to_json().to_string();
        let parsed = ErrorBody::parse(&encoded).expect("valid error body");
        assert_eq!(parsed.code, ERR_BAD_DIGEST);
        assert_eq!(parsed.message, "payload sha256 mismatch");
        assert!(parsed.retryable);
        assert!(parsed.session_closed);

        let restored = parsed.to_error();
        assert_eq!(restored.code, source.code);
        assert_eq!(restored.message, source.message);
        assert_eq!(restored.retryable, source.retryable);
        assert_eq!(restored.session_closed, source.session_closed);
        assert!(!restored.trusted);
    }
}

#[cfg(test)]
mod strict_ack_tests {
    use super::*;

    fn parse(s: &str) -> Result<AckRequest> {
        AckRequest::from_json(&json::parse(s).unwrap())
    }

    const FULL: &str = r#"{"down_delivered_offset":"0","down_fin_applied":false,"up_confirmed_offset":"0","data_tx_blocked":false,"data_rx_blocked":false,"backpressure_reason":""}"#;

    #[test]
    fn ack_request_matches_spec_strict_decode() {
        assert!(parse(FULL).is_ok());
        // Every non-omitempty field is required (protocol.DecodeJSON).
        for k in [
            "down_delivered_offset",
            "down_fin_applied",
            "up_confirmed_offset",
            "data_tx_blocked",
            "data_rx_blocked",
            "backpressure_reason",
        ] {
            let mut v = json::parse(FULL).unwrap();
            if let Json::Obj(m) = &mut v {
                m.retain(|(n, _)| n != k);
            }
            let e = AckRequest::from_json(&v).unwrap_err();
            assert_eq!(e.code, ERR_BAD_FRAME, "missing {k}");
            let mut n = json::parse(FULL).unwrap();
            if let Json::Obj(m) = &mut n {
                for (name, val) in m.iter_mut() {
                    if name == k {
                        *val = Json::Null;
                    }
                }
            }
            assert_eq!(
                AckRequest::from_json(&n).unwrap_err().code,
                ERR_BAD_FRAME,
                "null {k}"
            );
        }
        assert_eq!(
            parse(&FULL.replace(r#""down_fin_applied":false"#, r#""down_fin_applied":null"#))
                .unwrap_err()
                .code,
            ERR_BAD_FRAME
        );
        assert_eq!(
            parse(&FULL.replace(r#""up_confirmed_offset":"0""#, r#""up_confirmed_offset":0"#))
                .unwrap_err()
                .code,
            ERR_BAD_FRAME
        );
        // A present but non-canonical offset is session.ErrBadAck.
        assert_eq!(
            parse(&FULL.replace(
                r#""down_delivered_offset":"0""#,
                r#""down_delivered_offset":"""#
            ))
            .unwrap_err()
            .code,
            ERR_BAD_ACK
        );
        assert_eq!(
            parse(&FULL.replace(
                r#""up_confirmed_offset":"0""#,
                r#""up_confirmed_offset":"01""#
            ))
            .unwrap_err()
            .code,
            ERR_BAD_ACK
        );
        assert_eq!(
            parse(&FULL.replace("{", r#"{"ready_received":"yes","#))
                .unwrap_err()
                .code,
            ERR_BAD_FRAME
        );
    }
}
