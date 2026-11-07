//! Control messages carried as WebSocket text frames or SSE events.

use crate::error::{Error, Result};
use crate::util::json::{self, canonical_offset, Json};

use super::ERR_WS_PROTOCOL_ERROR;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlKind {
    Ready,
    AckUp,
    Ping,
    Fin,
    Error,
}

impl ControlKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ControlKind::Ready => "ready",
            ControlKind::AckUp => "ack_up",
            ControlKind::Ping => "ping",
            ControlKind::Fin => "fin",
            ControlKind::Error => "error",
        }
    }

    pub fn parse(s: &str) -> Option<ControlKind> {
        match s {
            "ready" => Some(ControlKind::Ready),
            "ack_up" => Some(ControlKind::AckUp),
            "ping" => Some(ControlKind::Ping),
            "fin" => Some(ControlKind::Fin),
            "error" => Some(ControlKind::Error),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Control {
    pub kind: ControlKind,
    pub session_id: String,
    pub instance_id: String,
    pub epoch: u64,
    pub stream_id: String,
    pub protocol_version: Option<String>,
    pub transport: Option<String>,
    pub resume_request_id: Option<String>,
    pub ack_up_offset: Option<u64>,
    pub up_fin_applied: bool,
    pub nonce: Option<String>,
    pub final_offset: Option<u64>,
    pub code: Option<String>,
    pub retryable: bool,
    pub session_closed: bool,
    pub ack_requested: bool,
}

impl Control {
    pub fn base(
        kind: ControlKind,
        session_id: &str,
        instance_id: &str,
        epoch: u64,
        stream: &str,
    ) -> Self {
        Control {
            kind,
            session_id: session_id.to_string(),
            instance_id: instance_id.to_string(),
            epoch,
            stream_id: stream.to_string(),
            protocol_version: None,
            transport: None,
            resume_request_id: None,
            ack_up_offset: None,
            up_fin_applied: false,
            nonce: None,
            final_offset: None,
            code: None,
            retryable: false,
            session_closed: false,
            ack_requested: false,
        }
    }

    /// Encodes exactly the fields the peer's strict decoder expects for this
    /// message type: the common ones always, the union ones always present
    /// (even when zero) for the type that owns them.
    pub fn to_json(&self) -> Json {
        let mut fields: Vec<(&str, Json)> = vec![
            ("type", Json::from(self.kind.as_str())),
            ("session_id", Json::from(self.session_id.as_str())),
            ("instance_id", Json::from(self.instance_id.as_str())),
            ("epoch", Json::from(self.epoch.to_string())),
            ("stream_id", Json::from(self.stream_id.as_str())),
        ];
        match self.kind {
            ControlKind::Ready => {
                fields.push((
                    "protocol_version",
                    Json::from(self.protocol_version.clone().unwrap_or_default()),
                ));
                fields.push((
                    "transport",
                    Json::from(self.transport.clone().unwrap_or_default()),
                ));
                fields.push((
                    "resume_request_id",
                    Json::from(self.resume_request_id.clone()),
                ));
            }
            ControlKind::AckUp => {
                fields.push((
                    "ack_up_offset",
                    Json::from(self.ack_up_offset.unwrap_or(0).to_string()),
                ));
                fields.push(("up_fin_applied", Json::Bool(self.up_fin_applied)));
                if self.ack_requested {
                    fields.push(("ack_requested", Json::Bool(true)));
                }
            }
            ControlKind::Ping => {
                fields.push(("nonce", Json::from(self.nonce.clone().unwrap_or_default())));
            }
            ControlKind::Fin => {
                fields.push((
                    "final_offset",
                    Json::from(self.final_offset.unwrap_or(0).to_string()),
                ));
            }
            ControlKind::Error => {
                fields.push(("code", Json::from(self.code.clone().unwrap_or_default())));
                fields.push(("retryable", Json::Bool(self.retryable)));
                fields.push(("session_closed", Json::Bool(self.session_closed)));
            }
        }
        json::obj(fields)
    }

    pub fn parse(text: &str) -> Result<Control> {
        let v = json::parse(text).map_err(|e| Error::new(ERR_WS_PROTOCOL_ERROR, e))?;
        let kind_s = v
            .get("type")
            .and_then(Json::as_str)
            .ok_or_else(|| Error::new(ERR_WS_PROTOCOL_ERROR, "control message without type"))?;
        let kind = ControlKind::parse(kind_s)
            .ok_or_else(|| Error::new(ERR_WS_PROTOCOL_ERROR, "unknown control message type"))?;
        let mut allowed = vec!["type", "session_id", "instance_id", "epoch", "stream_id"];
        allowed.extend(match kind {
            ControlKind::Ready => &["protocol_version", "transport", "resume_request_id"][..],
            ControlKind::AckUp => &["ack_up_offset", "up_fin_applied", "ack_requested"][..],
            ControlKind::Ping => &["nonce"][..],
            ControlKind::Fin => &["final_offset"][..],
            ControlKind::Error => &["code", "retryable", "session_closed"][..],
        });
        v.reject_unknown_fields(&allowed)
            .map_err(|e| Error::new(ERR_WS_PROTOCOL_ERROR, e))?;
        let s = |k: &str| -> Result<String> {
            v.get(k)
                .and_then(Json::as_str)
                .map(str::to_string)
                .ok_or_else(|| Error::new(ERR_WS_PROTOCOL_ERROR, format!("missing field {k}")))
        };
        let epoch = canonical_offset(&s("epoch")?)
            .ok_or_else(|| Error::new(ERR_WS_PROTOCOL_ERROR, "invalid epoch"))?;
        let mut c = Control::base(
            kind,
            &s("session_id")?,
            &s("instance_id")?,
            epoch,
            &s("stream_id")?,
        );
        match kind {
            ControlKind::Ready => {
                c.protocol_version = Some(s("protocol_version")?);
                c.transport = Some(s("transport")?);
                c.resume_request_id = match v.get("resume_request_id") {
                    None | Some(Json::Null) => None,
                    Some(Json::Str(id)) => Some(id.clone()),
                    Some(_) => {
                        return Err(Error::new(
                            ERR_WS_PROTOCOL_ERROR,
                            "invalid resume_request_id",
                        ));
                    }
                };
            }
            ControlKind::AckUp => {
                c.ack_up_offset = Some(v.offset("ack_up_offset")?);
                c.up_fin_applied = v.bool_field("up_fin_applied")?;
                c.ack_requested = v
                    .get("ack_requested")
                    .and_then(Json::as_bool)
                    .unwrap_or(false);
            }
            ControlKind::Ping => c.nonce = Some(s("nonce")?),
            ControlKind::Fin => c.final_offset = Some(v.offset("final_offset")?),
            ControlKind::Error => {
                c.code = Some(s("code")?);
                c.retryable = v.bool_field("retryable")?;
                c.session_closed = v.bool_field("session_closed")?;
            }
        }
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::ERR_WS_PROTOCOL_ERROR;

    #[test]
    fn control_union_accepts_each_type_and_nullable_ready_resume_id() {
        let good = [
            r#"{"type":"ready","session_id":"s","instance_id":"i","epoch":"1","stream_id":"x","protocol_version":"1.5","transport":"ws","resume_request_id":null}"#,
            r#"{"type":"ack_up","session_id":"s","instance_id":"i","epoch":"1","stream_id":"x","ack_up_offset":"0","up_fin_applied":false}"#,
            r#"{"type":"ping","session_id":"s","instance_id":"i","epoch":"1","stream_id":"x","nonce":"n"}"#,
            r#"{"type":"fin","session_id":"s","instance_id":"i","epoch":"1","stream_id":"x","final_offset":"9"}"#,
            r#"{"type":"error","session_id":"s","instance_id":"i","epoch":"1","stream_id":"x","code":"DBB_X","retryable":false,"session_closed":true}"#,
        ];
        for (expected_kind, text) in [
            (ControlKind::Ready, good[0]),
            (ControlKind::AckUp, good[1]),
            (ControlKind::Ping, good[2]),
            (ControlKind::Fin, good[3]),
            (ControlKind::Error, good[4]),
        ] {
            let parsed = Control::parse(text).unwrap();
            assert_eq!(parsed.kind, expected_kind);
            let encoded = parsed.to_json().to_string();
            let round_trip = Control::parse(&encoded).unwrap();
            assert_eq!(round_trip.kind, expected_kind);
            if expected_kind == ControlKind::Ready {
                assert_eq!(round_trip.resume_request_id, None);
            }
            if expected_kind == ControlKind::AckUp {
                assert!(!round_trip.up_fin_applied);
            }
        }
    }

    #[test]
    fn control_union_rejects_missing_owner_fields_and_cross_type_fields() {
        let bad = [
            r#"{"type":"ready","session_id":"s","instance_id":"i","epoch":"1","stream_id":"x","transport":"ws","resume_request_id":null}"#,
            r#"{"type":"ack_up","session_id":"s","instance_id":"i","epoch":"1","stream_id":"x","ack_up_offset":"0"}"#,
            r#"{"type":"ping","session_id":"s","instance_id":"i","epoch":"1","stream_id":"x"}"#,
            r#"{"type":"fin","session_id":"s","instance_id":"i","epoch":"1","stream_id":"x"}"#,
            r#"{"type":"error","session_id":"s","instance_id":"i","epoch":"1","stream_id":"x","code":"DBB_X","retryable":false}"#,
            r#"{"type":"ping","session_id":"s","instance_id":"i","epoch":"1","stream_id":"x","nonce":"n","code":"DBB_X"}"#,
            r#"{"type":"ping","session_id":"s","instance_id":"i","epoch":"1","stream_id":"x","nonce":"n","ack_requested":true}"#,
            r#"{"type":"ack_up","session_id":"s","instance_id":"i","epoch":"1","stream_id":"x","ack_up_offset":"1","up_fin_applied":false,"nonce":"n"}"#,
            r#"{"type":"bogus","session_id":"s","instance_id":"i","epoch":"1","stream_id":"x"}"#,
        ];
        for text in &bad[..5] {
            assert!(Control::parse(text).is_err(), "accepted {text}");
        }
        for text in &bad[5..] {
            let err = Control::parse(text).unwrap_err();
            assert_eq!(err.code, ERR_WS_PROTOCOL_ERROR, "accepted {text}");
        }
    }

    #[test]
    fn control_union_rejects_each_missing_required_owner_field() {
        let cases: [(&str, &[&str]); 5] = [
            (
                r#"{"type":"ready","session_id":"s","instance_id":"i","epoch":"1","stream_id":"x","protocol_version":"1.5","transport":"ws","resume_request_id":null}"#,
                &["protocol_version", "transport"],
            ),
            (
                r#"{"type":"ack_up","session_id":"s","instance_id":"i","epoch":"1","stream_id":"x","ack_up_offset":"0","up_fin_applied":false}"#,
                &["ack_up_offset", "up_fin_applied"],
            ),
            (
                r#"{"type":"ping","session_id":"s","instance_id":"i","epoch":"1","stream_id":"x","nonce":"n"}"#,
                &["nonce"],
            ),
            (
                r#"{"type":"fin","session_id":"s","instance_id":"i","epoch":"1","stream_id":"x","final_offset":"0"}"#,
                &["final_offset"],
            ),
            (
                r#"{"type":"error","session_id":"s","instance_id":"i","epoch":"1","stream_id":"x","code":"DBB_X","retryable":false,"session_closed":false}"#,
                &["code", "retryable", "session_closed"],
            ),
        ];

        for (text, required_fields) in cases {
            let value = crate::util::json::parse(text).unwrap();
            let Json::Obj(fields) = &value else {
                panic!("control fixture must be an object");
            };
            assert!(
                Control::parse(text).is_ok(),
                "rejected valid fixture {text}"
            );
            for required in required_fields {
                let missing = Json::Obj(
                    fields
                        .iter()
                        .filter(|(name, _)| name.as_str() != *required)
                        .cloned()
                        .collect(),
                );
                assert!(
                    Control::parse(&missing.to_string()).is_err(),
                    "accepted {} without {required}",
                    text,
                );
            }
        }

        let wrong_resume_id = r#"{"type":"ready","session_id":"s","instance_id":"i","epoch":"1","stream_id":"x","protocol_version":"1.5","transport":"ws","resume_request_id":7}"#;
        assert_eq!(
            Control::parse(wrong_resume_id).unwrap_err().code,
            ERR_WS_PROTOCOL_ERROR
        );
        let string_resume_id = r#"{"type":"ready","session_id":"s","instance_id":"i","epoch":"1","stream_id":"x","protocol_version":"1.5","transport":"ws","resume_request_id":"r"}"#;
        assert_eq!(
            Control::parse(string_resume_id)
                .unwrap()
                .resume_request_id
                .as_deref(),
            Some("r")
        );
    }
}
