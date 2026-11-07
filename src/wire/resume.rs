use super::{Mode, ERR_BAD_FRAME};
use crate::error::{Error, Result};
use crate::util::json::{self, canonical_offset, Json};

fn fin_from(v: &Json, key: &str) -> Result<crate::session::recovery::ResumeFin> {
    let x = v
        .get(key)
        .ok_or_else(|| Error::new(ERR_BAD_FRAME, format!("resume: missing {key}")))?;
    x.reject_unknown_fields(&["seen", "final_offset", "applied", "acked"])
        .map_err(|e| Error::new(ERR_BAD_FRAME, e))?;
    let seen = x.bool_field("seen")?;
    let final_offset = match x.get("final_offset") {
        None | Some(Json::Null) => None,
        Some(v) => Some(
            canonical_offset(
                v.as_str()
                    .ok_or_else(|| Error::new(ERR_BAD_FRAME, "resume: final_offset"))?,
            )
            .ok_or_else(|| Error::new(ERR_BAD_FRAME, "resume: final_offset"))?,
        ),
    };
    if !seen && final_offset.is_some() {
        return Err(Error::new(ERR_BAD_FRAME, "resume: FIN shape"));
    }
    let optional_bool = |k: &str| -> Result<bool> {
        match x.get(k) {
            None => Ok(false),
            Some(v) => v
                .as_bool()
                .ok_or_else(|| Error::new(ERR_BAD_FRAME, format!("resume: {k}"))),
        }
    };
    Ok(crate::session::recovery::ResumeFin {
        seen,
        final_offset,
        applied: optional_bool("applied")?,
        acked: optional_bool("acked")?,
    })
}

#[derive(Debug, Clone)]
pub struct ResumeRequestWire {
    pub inner: crate::session::recovery::ResumeRequest,
}
impl ResumeRequestWire {
    pub fn from_json(v: &Json) -> Result<Self> {
        v.reject_unknown_fields(&[
            "resume_request_id",
            "expected_epoch",
            "ingress_instance_id",
            "transport",
            "known_up_ack_offset",
            "up_next_offset",
            "down_delivered_offset",
            "up_fin",
            "down_fin",
        ])
        .map_err(|e| Error::new(ERR_BAD_FRAME, e))?;
        let transport = v
            .get("transport")
            .ok_or_else(|| Error::new(ERR_BAD_FRAME, "resume: transport"))?;
        transport
            .reject_unknown_fields(&["mode"])
            .map_err(|e| Error::new(ERR_BAD_FRAME, e))?;
        let mode = Mode::parse(transport.str_field("mode")?)
            .ok_or_else(|| Error::new(super::ERR_TRANSPORT_UNSUPPORTED, "transport"))?;
        let off = |k: &str| {
            v.get(k)
                .and_then(Json::as_str)
                .and_then(canonical_offset)
                .ok_or_else(|| Error::new(ERR_BAD_FRAME, format!("resume: {k}")))
        };
        Ok(Self {
            inner: crate::session::recovery::ResumeRequest {
                resume_request_id: v.str_field("resume_request_id")?.to_string(),
                expected_epoch: off("expected_epoch")?,
                ingress_instance_id: v.str_field("ingress_instance_id")?.to_string(),
                transport: mode,
                known_up_ack_offset: off("known_up_ack_offset")?,
                up_next_offset: off("up_next_offset")?,
                down_delivered_offset: off("down_delivered_offset")?,
                up_fin: fin_from(v, "up_fin")?,
                down_fin: fin_from(v, "down_fin")?,
            },
        })
    }

    pub fn to_json(&self) -> Json {
        let r = &self.inner;
        json::obj(vec![
            (
                "resume_request_id",
                Json::from(r.resume_request_id.as_str()),
            ),
            ("expected_epoch", Json::from(r.expected_epoch.to_string())),
            (
                "ingress_instance_id",
                Json::from(r.ingress_instance_id.as_str()),
            ),
            (
                "transport",
                json::obj(vec![("mode", Json::from(r.transport.as_str()))]),
            ),
            (
                "known_up_ack_offset",
                Json::from(r.known_up_ack_offset.to_string()),
            ),
            ("up_next_offset", Json::from(r.up_next_offset.to_string())),
            (
                "down_delivered_offset",
                Json::from(r.down_delivered_offset.to_string()),
            ),
            ("up_fin", fin_json(&r.up_fin)),
            ("down_fin", fin_json(&r.down_fin)),
        ])
    }
}

fn fin_json(f: &crate::session::recovery::ResumeFin) -> Json {
    json::obj(vec![
        ("seen", Json::Bool(f.seen)),
        (
            "final_offset",
            f.final_offset
                .map(|n| Json::from(n.to_string()))
                .unwrap_or(Json::Null),
        ),
        ("applied", Json::Bool(f.applied)),
        ("acked", Json::Bool(f.acked)),
    ])
}

impl crate::session::recovery::ResumeResponse {
    pub fn from_json(v: &Json) -> Result<Self> {
        v.reject_unknown_fields(&[
            "session_id",
            "instance_id",
            "resume_request_id",
            "epoch",
            "transport",
            "up_written_offset",
            "ack_up_offset",
            "down_replay_from",
            "down_produced_offset",
            "down_retained_from",
            "up_fin",
            "down_fin",
            "resume_remaining_ms",
        ])
        .map_err(|e| Error::new(ERR_BAD_FRAME, e))?;
        let transport = v
            .get("transport")
            .ok_or_else(|| Error::new(ERR_BAD_FRAME, "resume response: transport"))?;
        transport
            .reject_unknown_fields(&["mode"])
            .map_err(|e| Error::new(ERR_BAD_FRAME, e))?;
        let mode = Mode::parse(transport.str_field("mode")?)
            .ok_or_else(|| Error::new(super::ERR_TRANSPORT_UNSUPPORTED, "transport"))?;
        let off = |key: &str| {
            v.get(key)
                .and_then(Json::as_str)
                .and_then(canonical_offset)
                .ok_or_else(|| Error::new(ERR_BAD_FRAME, format!("resume response: {key}")))
        };
        let parse_fin =
            |key: &str, fields: &[&str]| -> Result<crate::session::recovery::ResumeFin> {
                let x = v
                    .get(key)
                    .ok_or_else(|| Error::new(ERR_BAD_FRAME, format!("resume response: {key}")))?;
                x.reject_unknown_fields(fields)
                    .map_err(|e| Error::new(ERR_BAD_FRAME, e))?;
                let seen_key = if key == "up_fin" { "received" } else { "seen" };
                let seen = x.bool_field(seen_key)?;
                let final_offset = match x.get("final_offset") {
                    None | Some(Json::Null) => None,
                    Some(n) => Some(
                        canonical_offset(n.as_str().ok_or_else(|| {
                            Error::new(
                                ERR_BAD_FRAME,
                                format!("resume response: {key}.final_offset"),
                            )
                        })?)
                        .ok_or_else(|| {
                            Error::new(
                                ERR_BAD_FRAME,
                                format!("resume response: {key}.final_offset"),
                            )
                        })?,
                    ),
                };
                if !seen && final_offset.is_some() {
                    return Err(Error::new(ERR_BAD_FRAME, "resume response: FIN shape"));
                }
                let optional_bool = |name: &str| match x.get(name) {
                    None => Ok(false),
                    Some(value) => value.as_bool().ok_or_else(|| {
                        Error::new(ERR_BAD_FRAME, format!("resume response: {key}.{name}"))
                    }),
                };
                Ok(crate::session::recovery::ResumeFin {
                    seen,
                    final_offset,
                    applied: optional_bool("applied")?,
                    acked: optional_bool("acked")?,
                })
            };
        let remaining_ms = v
            .get("resume_remaining_ms")
            .and_then(Json::as_u64)
            .filter(|n| *n > 0 && *n <= (i64::MAX / 1_000_000) as u64)
            .ok_or_else(|| Error::new(ERR_BAD_FRAME, "resume response: remaining grace"))?;
        Ok(Self {
            session_id: v.str_field("session_id")?.to_string(),
            instance_id: v.str_field("instance_id")?.to_string(),
            resume_request_id: v.str_field("resume_request_id")?.to_string(),
            epoch: off("epoch")?,
            transport: mode,
            up_written_offset: off("up_written_offset")?,
            ack_up_offset: off("ack_up_offset")?,
            down_replay_from: off("down_replay_from")?,
            down_produced_offset: off("down_produced_offset")?,
            down_retained_from: off("down_retained_from")?,
            up_fin: parse_fin("up_fin", &["received", "final_offset", "applied"])?,
            down_fin: parse_fin("down_fin", &["seen", "final_offset", "applied", "acked"])?,
            resume_remaining: std::time::Duration::from_millis(remaining_ms),
        })
    }

    pub fn to_json(&self) -> Json {
        json::obj(vec![
            ("session_id", Json::from(self.session_id.as_str())),
            ("instance_id", Json::from(self.instance_id.as_str())),
            (
                "resume_request_id",
                Json::from(self.resume_request_id.as_str()),
            ),
            ("epoch", Json::from(self.epoch.to_string())),
            (
                "transport",
                json::obj(vec![("mode", Json::from(self.transport.as_str()))]),
            ),
            (
                "up_written_offset",
                Json::from(self.up_written_offset.to_string()),
            ),
            ("ack_up_offset", Json::from(self.ack_up_offset.to_string())),
            (
                "down_replay_from",
                Json::from(self.down_replay_from.to_string()),
            ),
            (
                "down_produced_offset",
                Json::from(self.down_produced_offset.to_string()),
            ),
            (
                "down_retained_from",
                Json::from(self.down_retained_from.to_string()),
            ),
            (
                "up_fin",
                json::obj(vec![
                    ("received", Json::Bool(self.up_fin.seen)),
                    (
                        "final_offset",
                        self.up_fin
                            .final_offset
                            .map(|n| Json::from(n.to_string()))
                            .unwrap_or(Json::Null),
                    ),
                    ("applied", Json::Bool(self.up_fin.applied)),
                ]),
            ),
            ("down_fin", fin_json(&self.down_fin)),
            (
                "resume_remaining_ms",
                Json::from(self.resume_remaining.as_millis() as u64),
            ),
        ])
    }
}

pub fn validate_response(
    req: &crate::session::recovery::ResumeRequest,
    out: &crate::session::recovery::ResumeResponse,
    session_id: &str,
    instance_id: &str,
) -> bool {
    let Some(epoch) = req.expected_epoch.checked_add(1) else {
        return false;
    };
    out.epoch == epoch
        && out.session_id == session_id
        && out.instance_id == instance_id
        && out.resume_request_id == req.resume_request_id
        && out.transport == req.transport
        && out.down_replay_from == req.down_delivered_offset
        && out.ack_up_offset >= req.known_up_ack_offset
        && out.ack_up_offset <= req.up_next_offset
        && out.up_written_offset == out.ack_up_offset
        && out.down_retained_from <= req.down_delivered_offset
        && req.down_delivered_offset <= out.down_produced_offset
        && out.resume_remaining > std::time::Duration::ZERO
        && (!req.up_fin.seen
            || (out.up_fin.seen && out.up_fin.final_offset == req.up_fin.final_offset))
        && (!req.up_fin.applied || out.up_fin.applied)
        && (!req.down_fin.applied || out.down_fin.acked)
        && (!out.down_fin.seen || out.down_fin.final_offset == Some(out.down_produced_offset))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn request() -> crate::session::recovery::ResumeRequest {
        crate::session::recovery::ResumeRequest {
            resume_request_id: "r".into(),
            expected_epoch: 7,
            ingress_instance_id: "i".into(),
            transport: Mode::Ws,
            known_up_ack_offset: 2,
            up_next_offset: 5,
            down_delivered_offset: 3,
            up_fin: Default::default(),
            down_fin: Default::default(),
        }
    }
    fn response() -> crate::session::recovery::ResumeResponse {
        crate::session::recovery::ResumeResponse {
            session_id: "s".into(),
            instance_id: "i".into(),
            resume_request_id: "r".into(),
            epoch: 8,
            transport: Mode::Ws,
            up_written_offset: 4,
            ack_up_offset: 4,
            down_replay_from: 3,
            down_produced_offset: 9,
            down_retained_from: 1,
            up_fin: Default::default(),
            down_fin: Default::default(),
            resume_remaining: Duration::from_millis(1),
        }
    }
    #[test]
    fn valid_response_and_request_wire_round_trip() {
        let req = request();
        let wire = ResumeRequestWire { inner: req.clone() };
        assert_eq!(
            ResumeRequestWire::from_json(&wire.to_json())
                .unwrap()
                .inner
                .fingerprint(),
            req.fingerprint()
        );
        assert!(validate_response(&req, &response(), "s", "i"));
    }
    #[test]
    fn response_round_trips_all_direction_fin_fields() {
        let mut out = response();
        out.up_fin = crate::session::recovery::ResumeFin {
            seen: true,
            final_offset: Some(8),
            applied: true,
            acked: false,
        };
        out.down_fin = crate::session::recovery::ResumeFin {
            seen: true,
            final_offset: Some(9),
            applied: true,
            acked: true,
        };
        let wire = out.to_json();
        let up_fin = wire.get("up_fin").unwrap();
        assert_eq!(up_fin.get("received").and_then(Json::as_bool), Some(true));
        assert!(up_fin.get("seen").is_none());
        let down_fin = wire.get("down_fin").unwrap();
        assert_eq!(down_fin.get("seen").and_then(Json::as_bool), Some(true));
        assert!(down_fin.get("received").is_none());
        let parsed = crate::session::recovery::ResumeResponse::from_json(&wire).unwrap();
        assert_eq!(parsed, out);
    }

    #[test]
    fn request_wire_allows_optional_fin_offset_but_rejects_bad_shapes() {
        let valid = json::parse(
            r#"{"resume_request_id":"r","expected_epoch":"7","ingress_instance_id":"i","transport":{"mode":"ws"},"known_up_ack_offset":"2","up_next_offset":"5","down_delivered_offset":"3","up_fin":{"seen":false},"down_fin":{"seen":false,"final_offset":null}}"#,
        )
        .unwrap();
        let parsed = ResumeRequestWire::from_json(&valid).unwrap();
        assert_eq!(parsed.inner.up_fin.final_offset, None);
        assert_eq!(parsed.inner.down_fin.final_offset, None);

        for text in [
            r#"{"resume_request_id":"r","expected_epoch":"07","ingress_instance_id":"i","transport":{"mode":"ws"},"known_up_ack_offset":"2","up_next_offset":"5","down_delivered_offset":"3","up_fin":{"seen":false},"down_fin":{"seen":false}}"#,
            r#"{"resume_request_id":"r","expected_epoch":"7","ingress_instance_id":"i","transport":{"mode":"ws"},"known_up_ack_offset":"2","up_next_offset":"5","down_delivered_offset":"3","up_fin":{"seen":false,"final_offset":"5"},"down_fin":{"seen":false}}"#,
            r#"{"resume_request_id":"r","expected_epoch":"7","ingress_instance_id":"i","transport":{"mode":"ws"},"known_up_ack_offset":"2","up_next_offset":"5","down_delivered_offset":"3","up_fin":{"seen":false,"applied":"yes"},"down_fin":{"seen":false}}"#,
        ] {
            assert_eq!(
                ResumeRequestWire::from_json(&json::parse(text).unwrap())
                    .unwrap_err()
                    .code,
                ERR_BAD_FRAME,
                "accepted {text}"
            );
        }
    }

    #[test]
    fn resume_validation_enforces_replay_and_ack_offset_relationships() {
        let req = request();

        let mut out = response();
        out.down_replay_from = 2;
        assert!(!validate_response(&req, &out, "s", "i"));

        let mut out = response();
        out.down_retained_from = 4;
        assert!(!validate_response(&req, &out, "s", "i"));

        let mut out = response();
        out.down_produced_offset = 2;
        assert!(!validate_response(&req, &out, "s", "i"));

        let mut out = response();
        out.ack_up_offset = 1;
        out.up_written_offset = 1;
        assert!(!validate_response(&req, &out, "s", "i"));

        let mut out = response();
        out.up_written_offset = 3;
        assert!(!validate_response(&req, &out, "s", "i"));

        let mut out = response();
        out.resume_remaining = Duration::ZERO;
        assert!(!validate_response(&req, &out, "s", "i"));
    }

    #[test]
    fn resume_validation_preserves_requested_fin_state() {
        let mut req = request();
        req.up_fin.seen = true;
        req.up_fin.final_offset = Some(5);

        let out = response();
        assert!(!validate_response(&req, &out, "s", "i"));

        let mut out = response();
        out.up_fin.seen = true;
        out.up_fin.final_offset = Some(4);
        assert!(!validate_response(&req, &out, "s", "i"));

        let mut out = response();
        out.up_fin.seen = true;
        out.up_fin.final_offset = Some(5);
        out.up_fin.applied = false;
        req.up_fin.applied = true;
        assert!(!validate_response(&req, &out, "s", "i"));

        let mut out = response();
        req.down_fin.applied = true;
        out.down_fin.acked = false;
        assert!(!validate_response(&req, &out, "s", "i"));
    }
    #[test]
    fn mismatches_and_bad_offsets_or_fin_are_rejected() {
        let req = request();
        let mut out = response();
        out.instance_id = "other".into();
        assert!(!validate_response(&req, &out, "s", "i"));
        let mut out = response();
        out.ack_up_offset = 6;
        out.up_written_offset = 6;
        assert!(!validate_response(&req, &out, "s", "i"));
        let mut out = response();
        out.down_fin.seen = true;
        out.down_fin.final_offset = Some(8);
        assert!(!validate_response(&req, &out, "s", "i"));
    }
    #[test]
    fn epoch_overflow_is_rejected() {
        let mut req = request();
        req.expected_epoch = u64::MAX;
        assert!(!validate_response(&req, &response(), "s", "i"));
    }
}
