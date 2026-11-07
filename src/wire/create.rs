//! Control API request and response shapes: probe, limits and session create.

use crate::error::{Error, Result};
use crate::util::json::{self, canonical_offset, Json};

use super::{
    Mode, ERR_BAD_FRAME, ERR_PROTOCOL_MISMATCH, ERR_TRANSPORT_UNSUPPORTED, PROTOCOL_VERSION,
};

const MAX_ADVERTISED_FRAMES: u64 = 1 << 20;

fn checked_usize(v: &Json, key: &str, code: &str) -> Result<usize> {
    let n = v.u64_field(key)?;
    usize::try_from(n).map_err(|_| Error::new(code, format!("create: {key} is out of range")))
}

fn checked_u32(v: &Json, key: &str, code: &str) -> Result<u32> {
    let n = v.u64_field(key)?;
    u32::try_from(n).map_err(|_| Error::new(code, format!("create: {key} is out of range")))
}

fn advertised_frames(v: &Json, key: &str) -> Result<u32> {
    let n = v.get(key).and_then(Json::as_u64).ok_or_else(|| {
        Error::new(
            ERR_PROTOCOL_MISMATCH,
            format!("create response: missing {key}"),
        )
    })?;
    u32::try_from(n.min(MAX_ADVERTISED_FRAMES))
        .map_err(|_| Error::new(ERR_PROTOCOL_MISMATCH, format!("create response: {key}")))
}

#[derive(Debug, Clone)]
pub struct ProbeRequest {
    pub expected_node_id: String,
    pub nonce: String,
}

impl ProbeRequest {
    pub fn to_json(&self) -> Json {
        json::obj(vec![
            ("protocol_version", Json::from(PROTOCOL_VERSION)),
            (
                "expected_node_id",
                Json::from(self.expected_node_id.as_str()),
            ),
            ("nonce", Json::from(self.nonce.as_str())),
        ])
    }
}

#[derive(Debug, Clone)]
pub struct ProbeResponse {
    pub protocol_version: String,
    pub node_id: String,
    pub instance_id: String,
    pub nonce: String,
    pub recovery_available: bool,
    pub accepting_new_sessions: bool,
    pub transports: Vec<String>,
}

impl ProbeResponse {
    pub fn from_json(v: &Json) -> Result<Self> {
        v.reject_unknown_fields(&[
            "protocol_version",
            "node_id",
            "instance_id",
            "nonce",
            "recovery_available",
            "accepting_new_sessions",
            "transports",
        ])
        .map_err(|e| Error::new(ERR_PROTOCOL_MISMATCH, format!("probe response: {e}")))?;
        let s = |k: &str| -> Result<String> {
            v.get(k)
                .and_then(Json::as_str)
                .map(str::to_string)
                .ok_or_else(|| {
                    Error::new(
                        ERR_PROTOCOL_MISMATCH,
                        format!("probe response: missing {k}"),
                    )
                })
        };
        let transports = v
            .get("transports")
            .and_then(Json::as_array)
            .ok_or_else(|| Error::new(ERR_PROTOCOL_MISMATCH, "probe response: transports"))?
            .iter()
            .filter_map(|t| t.as_str().map(str::to_string))
            .collect();
        // Required by the 1.5 shape, so a response without it is malformed even
        // though this build offers no session recovery and never uses the value.
        let recovery_available = v.bool_field("recovery_available")?;
        Ok(ProbeResponse {
            protocol_version: s("protocol_version")?,
            node_id: s("node_id")?,
            instance_id: s("instance_id")?,
            nonce: s("nonce")?,
            recovery_available,
            accepting_new_sessions: v.bool_field("accepting_new_sessions")?,
            transports,
        })
    }
}

/// Per-session negotiated limits.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_frame_size: usize,
    pub up_max_inflight_frames: u32,
    pub up_window_bytes: u64,
    pub down_buffer_bytes: u64,
    /// Advertised by the egress in a create response only.
    pub up_receipt_limit: u32,
    pub down_max_frames: u32,
}

#[derive(Debug, Clone)]
pub struct CreateRequest {
    pub target_id: String,
    pub create_request_id: String,
    pub ingress_instance_id: String,
    pub mode: Mode,
    pub recovery_enabled: bool,
    pub recovery_grace_ms: u64,
    pub limits: Limits,
}

impl CreateRequest {
    pub fn to_json(&self) -> Json {
        json::obj(vec![
            ("protocol_version", Json::from(PROTOCOL_VERSION)),
            (
                "transport",
                json::obj(vec![("mode", Json::from(self.mode.as_str()))]),
            ),
            (
                "recovery",
                json::obj(vec![
                    ("enabled", Json::Bool(self.recovery_enabled)),
                    ("grace_ms", Json::from(self.recovery_grace_ms)),
                ]),
            ),
            (
                "create_request_id",
                Json::from(self.create_request_id.as_str()),
            ),
            (
                "ingress_instance_id",
                Json::from(self.ingress_instance_id.as_str()),
            ),
            ("target_id", Json::from(self.target_id.as_str())),
            (
                "limits",
                json::obj(vec![
                    (
                        "max_frame_size",
                        Json::from(self.limits.max_frame_size as u64),
                    ),
                    (
                        "up_max_inflight_frames",
                        Json::from(self.limits.up_max_inflight_frames as u64),
                    ),
                    ("up_window_bytes", Json::from(self.limits.up_window_bytes)),
                    (
                        "down_buffer_bytes",
                        Json::from(self.limits.down_buffer_bytes),
                    ),
                ]),
            ),
        ])
    }

    pub fn from_json(v: &Json) -> Result<Self> {
        v.reject_unknown_fields(&[
            "protocol_version",
            "transport",
            "recovery",
            "create_request_id",
            "ingress_instance_id",
            "target_id",
            "limits",
        ])
        .map_err(|e| Error::new(ERR_BAD_FRAME, e))?;
        if v.str_field("protocol_version")? != PROTOCOL_VERSION {
            return Err(Error::new(
                ERR_PROTOCOL_MISMATCH,
                "create: protocol version",
            ));
        }
        let s = |k: &str| -> Result<String> {
            v.get(k)
                .and_then(Json::as_str)
                .map(str::to_string)
                .ok_or_else(|| Error::new(ERR_BAD_FRAME, format!("create: missing {k}")))
        };
        let transport = v
            .get("transport")
            .ok_or_else(|| Error::new(ERR_BAD_FRAME, "create: missing transport"))?;
        transport
            .reject_unknown_fields(&["mode"])
            .map_err(|e| Error::new(ERR_BAD_FRAME, e))?;
        let mode = Mode::parse(transport.str_field("mode")?).ok_or_else(|| {
            Error::new(ERR_TRANSPORT_UNSUPPORTED, "create: unknown transport mode")
        })?;
        let recovery = v
            .get("recovery")
            .ok_or_else(|| Error::new(ERR_BAD_FRAME, "create: missing recovery"))?;
        recovery
            .reject_unknown_fields(&["enabled", "grace_ms"])
            .map_err(|e| Error::new(ERR_BAD_FRAME, e))?;
        let limits = v
            .get("limits")
            .ok_or_else(|| Error::new(ERR_BAD_FRAME, "create: missing limits"))?;
        limits
            .reject_unknown_fields(&[
                "max_frame_size",
                "up_max_inflight_frames",
                "up_window_bytes",
                "down_buffer_bytes",
            ])
            .map_err(|e| Error::new(ERR_BAD_FRAME, e))?;
        Ok(CreateRequest {
            target_id: s("target_id")?,
            create_request_id: s("create_request_id")?,
            ingress_instance_id: s("ingress_instance_id")?,
            mode,
            recovery_enabled: recovery.bool_field("enabled")?,
            recovery_grace_ms: recovery.u64_field("grace_ms")?,
            limits: Limits {
                max_frame_size: checked_usize(limits, "max_frame_size", ERR_BAD_FRAME)?,
                up_max_inflight_frames: checked_u32(
                    limits,
                    "up_max_inflight_frames",
                    ERR_BAD_FRAME,
                )?,
                up_window_bytes: limits.u64_field("up_window_bytes")?,
                down_buffer_bytes: limits.u64_field("down_buffer_bytes")?,
                up_receipt_limit: 0,
                down_max_frames: 0,
            },
        })
    }
}

#[derive(Debug, Clone)]
pub struct CreateResponse {
    pub node_id: String,
    pub instance_id: String,
    pub session_id: String,
    pub session_token: String,
    pub epoch: u64,
    pub mode: Mode,
    pub recovery_enabled: bool,
    pub recovery_grace_ms: u64,
    pub limits: Limits,
    pub unattached_timeout_ms: u64,
}

impl CreateResponse {
    pub fn to_json(&self) -> Json {
        json::obj(vec![
            ("protocol_version", Json::from(PROTOCOL_VERSION)),
            ("node_id", Json::from(self.node_id.as_str())),
            ("instance_id", Json::from(self.instance_id.as_str())),
            ("session_id", Json::from(self.session_id.as_str())),
            ("session_token", Json::from(self.session_token.as_str())),
            ("epoch", Json::from(self.epoch.to_string())),
            (
                "transport",
                json::obj(vec![("mode", Json::from(self.mode.as_str()))]),
            ),
            (
                "recovery",
                json::obj(vec![
                    ("enabled", Json::Bool(self.recovery_enabled)),
                    ("grace_ms", Json::from(self.recovery_grace_ms)),
                ]),
            ),
            (
                "limits",
                json::obj(vec![
                    (
                        "max_frame_size",
                        Json::from(self.limits.max_frame_size as u64),
                    ),
                    (
                        "up_max_inflight_frames",
                        Json::from(self.limits.up_max_inflight_frames as u64),
                    ),
                    ("up_window_bytes", Json::from(self.limits.up_window_bytes)),
                    (
                        "down_buffer_bytes",
                        Json::from(self.limits.down_buffer_bytes),
                    ),
                    (
                        "up_receipt_limit",
                        Json::from(self.limits.up_receipt_limit as u64),
                    ),
                    (
                        "down_max_frames",
                        Json::from(self.limits.down_max_frames as u64),
                    ),
                ]),
            ),
            (
                "unattached_timeout_ms",
                Json::from(self.unattached_timeout_ms),
            ),
        ])
    }

    pub fn from_json(v: &Json) -> Result<Self> {
        v.reject_unknown_fields(&[
            "protocol_version",
            "node_id",
            "instance_id",
            "session_id",
            "session_token",
            "epoch",
            "transport",
            "recovery",
            "limits",
            "unattached_timeout_ms",
        ])
        .map_err(|e| Error::new(ERR_PROTOCOL_MISMATCH, format!("create response: {e}")))?;
        let s = |k: &str| -> Result<String> {
            v.get(k)
                .and_then(Json::as_str)
                .map(str::to_string)
                .ok_or_else(|| {
                    Error::new(
                        ERR_PROTOCOL_MISMATCH,
                        format!("create response: missing {k}"),
                    )
                })
        };
        let transport = v
            .get("transport")
            .ok_or_else(|| Error::new(ERR_PROTOCOL_MISMATCH, "create response: transport"))?;
        transport
            .reject_unknown_fields(&["mode"])
            .map_err(|e| Error::new(ERR_PROTOCOL_MISMATCH, e))?;
        let mode = Mode::parse(transport.str_field("mode")?)
            .ok_or_else(|| Error::new(ERR_PROTOCOL_MISMATCH, "create response: transport mode"))?;
        let recovery = v
            .get("recovery")
            .ok_or_else(|| Error::new(ERR_PROTOCOL_MISMATCH, "create response: recovery"))?;
        recovery
            .reject_unknown_fields(&["enabled", "grace_ms"])
            .map_err(|e| Error::new(ERR_PROTOCOL_MISMATCH, e))?;
        let limits = v
            .get("limits")
            .ok_or_else(|| Error::new(ERR_PROTOCOL_MISMATCH, "create response: limits"))?;
        limits
            .reject_unknown_fields(&[
                "max_frame_size",
                "up_max_inflight_frames",
                "up_window_bytes",
                "down_buffer_bytes",
                "up_receipt_limit",
                "down_max_frames",
            ])
            .map_err(|e| Error::new(ERR_PROTOCOL_MISMATCH, e))?;
        let epoch = canonical_offset(&s("epoch")?)
            .ok_or_else(|| Error::new(ERR_PROTOCOL_MISMATCH, "create response: epoch"))?;
        Ok(CreateResponse {
            node_id: s("node_id")?,
            instance_id: s("instance_id")?,
            session_id: s("session_id")?,
            session_token: s("session_token")?,
            epoch,
            mode,
            recovery_enabled: recovery.bool_field("enabled")?,
            recovery_grace_ms: recovery.u64_field("grace_ms")?,
            limits: Limits {
                max_frame_size: checked_usize(limits, "max_frame_size", ERR_PROTOCOL_MISMATCH)?,
                up_max_inflight_frames: checked_u32(
                    limits,
                    "up_max_inflight_frames",
                    ERR_PROTOCOL_MISMATCH,
                )?,
                up_window_bytes: limits.u64_field("up_window_bytes")?,
                down_buffer_bytes: limits.u64_field("down_buffer_bytes")?,
                up_receipt_limit: advertised_frames(limits, "up_receipt_limit")?,
                down_max_frames: advertised_frames(limits, "down_max_frames")?,
            },
            unattached_timeout_ms: v.u64_field("unattached_timeout_ms")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertised_frames_clamped() {
        let v = json::parse(
            r#"{
                "node_id":"n", "instance_id":"i", "session_id":"s",
                "session_token":"t", "epoch":"1",
                "transport":{"mode":"ws"},
                "recovery":{"enabled":false,"grace_ms":0},
                "limits":{
                    "max_frame_size":512, "up_max_inflight_frames":8,
                    "up_window_bytes":1048576, "down_buffer_bytes":1048576,
                    "up_receipt_limit":18446744073709551615,
                    "down_max_frames":16777216
                },
                "unattached_timeout_ms":1000
            }"#,
        )
        .unwrap();
        let response = CreateResponse::from_json(&v).unwrap();
        assert_eq!(response.limits.up_receipt_limit, 1 << 20);
        assert_eq!(response.limits.down_max_frames, 1 << 20);
    }

    #[test]
    fn advertised_frames_preserve_explicit_zero() {
        let v = json::parse(
            r#"{
                "node_id":"n", "instance_id":"i", "session_id":"s",
                "session_token":"t", "epoch":"1",
                "transport":{"mode":"ws"},
                "recovery":{"enabled":false,"grace_ms":0},
                "limits":{
                    "max_frame_size":512, "up_max_inflight_frames":8,
                    "up_window_bytes":1048576, "down_buffer_bytes":1048576,
                    "up_receipt_limit":0, "down_max_frames":0
                },
                "unattached_timeout_ms":1000
            }"#,
        )
        .unwrap();
        let response = CreateResponse::from_json(&v).unwrap();
        assert_eq!(response.limits.up_receipt_limit, 0);
        assert_eq!(response.limits.down_max_frames, 0);
    }

    #[test]
    fn create_request_rejects_response_only_limits() {
        let v = json::parse(
            r#"{"protocol_version":"1.5","transport":{"mode":"ws"},"recovery":{"enabled":false,"grace_ms":0},"create_request_id":"c","ingress_instance_id":"i","target_id":"t","limits":{"max_frame_size":512,"up_max_inflight_frames":8,"up_window_bytes":65536,"down_buffer_bytes":65536,"up_receipt_limit":10}}"#,
        )
        .unwrap();
        let err = CreateRequest::from_json(&v).unwrap_err();
        assert_eq!(err.code, ERR_BAD_FRAME);
    }

    #[test]
    fn create_request_rejects_wrong_protocol_version() {
        let v = json::parse(
            r#"{"protocol_version":"1.4","transport":{"mode":"ws"},"recovery":{"enabled":false,"grace_ms":0},"create_request_id":"c","ingress_instance_id":"i","target_id":"t","limits":{"max_frame_size":512,"up_max_inflight_frames":8,"up_window_bytes":65536,"down_buffer_bytes":65536}}"#,
        )
        .unwrap();
        let err = CreateRequest::from_json(&v).unwrap_err();
        assert_eq!(err.code, ERR_PROTOCOL_MISMATCH);
    }

    #[test]
    fn create_response_rejects_unknown_field() {
        let v = json::parse(r#"{"unexpected":true}"#).unwrap();
        let err = CreateResponse::from_json(&v).unwrap_err();
        assert_eq!(err.code, ERR_PROTOCOL_MISMATCH);
    }

    #[test]
    fn create_response_rejects_missing_flow_limits() {
        let v = json::parse(
            r#"{"node_id":"n","instance_id":"i","session_id":"s","session_token":"t","epoch":"1","transport":{"mode":"ws"},"recovery":{"enabled":false,"grace_ms":0},"limits":{"max_frame_size":512,"up_max_inflight_frames":8,"up_window_bytes":65536,"down_buffer_bytes":65536,"down_max_frames":8},"unattached_timeout_ms":1000}"#,
        )
        .unwrap();
        let err = CreateResponse::from_json(&v).unwrap_err();
        assert_eq!(err.code, ERR_PROTOCOL_MISMATCH);
    }

    #[test]
    fn create_request_rejects_each_missing_required_root_field() {
        let valid = json::parse(
            r#"{"protocol_version":"1.5","transport":{"mode":"ws"},"recovery":{"enabled":false,"grace_ms":0},"create_request_id":"c","ingress_instance_id":"i","target_id":"t","limits":{"max_frame_size":512,"up_max_inflight_frames":8,"up_window_bytes":65536,"down_buffer_bytes":65536}}"#,
        )
        .unwrap();
        let Json::Obj(fields) = &valid else {
            panic!("request fixture must be an object");
        };
        for key in [
            "protocol_version",
            "transport",
            "recovery",
            "create_request_id",
            "ingress_instance_id",
            "target_id",
            "limits",
        ] {
            let missing = Json::Obj(
                fields
                    .iter()
                    .filter(|(name, _)| name != key)
                    .cloned()
                    .collect(),
            );
            assert!(
                CreateRequest::from_json(&missing).is_err(),
                "accepted request without {key}"
            );
        }
    }

    #[test]
    fn create_request_requires_recovery_grace_ms() {
        let missing_grace = json::parse(
            r#"{"protocol_version":"1.5","transport":{"mode":"ws"},"recovery":{"enabled":false},"create_request_id":"c","ingress_instance_id":"i","target_id":"t","limits":{"max_frame_size":512,"up_max_inflight_frames":8,"up_window_bytes":65536,"down_buffer_bytes":65536}}"#,
        )
        .unwrap();
        assert!(CreateRequest::from_json(&missing_grace).is_err());
    }

    #[test]
    fn flow_limit_fields_bind_to_responses_not_create_requests() {
        let limits = Limits {
            max_frame_size: 512,
            up_max_inflight_frames: 8,
            up_window_bytes: 65_536,
            down_buffer_bytes: 65_536,
            up_receipt_limit: 64,
            down_max_frames: 512,
        };
        let request = CreateRequest {
            target_id: "t".into(),
            create_request_id: "c".into(),
            ingress_instance_id: "i".into(),
            mode: Mode::Ws,
            recovery_enabled: false,
            recovery_grace_ms: 0,
            limits,
        };
        let request_json = request.to_json();
        let request_limits = request_json.get("limits").unwrap();
        assert!(request_limits.get("up_receipt_limit").is_none());
        assert!(request_limits.get("down_max_frames").is_none());

        let response = CreateResponse {
            node_id: "n".into(),
            instance_id: "i".into(),
            session_id: "s".into(),
            session_token: "token".into(),
            epoch: 1,
            mode: Mode::Ws,
            recovery_enabled: false,
            recovery_grace_ms: 0,
            limits,
            unattached_timeout_ms: 1_000,
        };
        let decoded = CreateResponse::from_json(&response.to_json()).unwrap();
        assert_eq!(decoded.limits.up_receipt_limit, 64);
        assert_eq!(decoded.limits.down_max_frames, 512);
    }

    #[test]
    fn create_request_rejects_each_response_only_flow_limit() {
        for (field, value) in [("up_receipt_limit", 64), ("down_max_frames", 512)] {
            let text = format!(
                r#"{{"protocol_version":"1.5","transport":{{"mode":"ws"}},"recovery":{{"enabled":false,"grace_ms":0}},"create_request_id":"c","ingress_instance_id":"i","target_id":"t","limits":{{"max_frame_size":512,"up_max_inflight_frames":8,"up_window_bytes":65536,"down_buffer_bytes":65536,"{field}":{value}}}}}"#
            );
            let request = json::parse(&text).unwrap();
            let err = CreateRequest::from_json(&request).unwrap_err();
            assert_eq!(err.code, ERR_BAD_FRAME, "{field}");
        }
    }
}
