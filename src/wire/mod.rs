pub const PROTOCOL_VERSION: &str = "1.5";
pub const WS_SUBPROTOCOL: &str = "dbbridge.v1.5";

// Header names.
pub const H_PEER_AUTH: &str = "Authorization";
pub const H_SESSION_TOKEN: &str = "X-DBB-Session-Token";
pub const H_INSTANCE_ID: &str = "X-DBB-Instance-ID";
pub const H_OFFSET: &str = "X-DBB-Offset";
pub const H_LENGTH: &str = "X-DBB-Length";
pub const H_SHA256: &str = "X-DBB-SHA256";
pub const H_ACK_DOWN_OFFSET: &str = "X-DBB-Ack-Down-Offset";
pub const H_CONFIRM_UP_OFFSET: &str = "X-DBB-Confirm-Up-Offset";
pub const H_STREAM_ID: &str = "X-DBB-Stream-ID";
pub const H_WS_PURPOSE: &str = "X-DBB-WS-Purpose";
pub const H_WS_NONCE: &str = "X-DBB-Nonce";
pub const H_WS_SESSION_ID: &str = "X-DBB-Session-ID";
pub const H_WS_EPOCH: &str = "X-DBB-Epoch";
pub const H_IMPLICIT_READY: &str = "X-DBB-Implicit-Ready";

// Paths.
pub const PATH_PROBE: &str = "/v1/peer/probe";
pub const PATH_SESSIONS: &str = "/v1/sessions";
pub const PATH_WS: &str = "/v1/transport/ws";

// Error codes.
pub const ERR_BAD_FRAME: &str = "DBB_BAD_FRAME";
pub const ERR_BAD_DIGEST: &str = "DBB_BAD_DIGEST";
pub const ERR_BAD_ACK: &str = "DBB_BAD_ACK";
pub const ERR_UNAUTHORIZED: &str = "DBB_UNAUTHORIZED";
pub const ERR_TARGET_FORBIDDEN: &str = "DBB_TARGET_FORBIDDEN";
pub const ERR_SESSION_NOT_FOUND: &str = "DBB_SESSION_NOT_FOUND";
pub const ERR_STALE_EPOCH: &str = "DBB_STALE_EPOCH";
pub const ERR_STREAM_EXISTS: &str = "DBB_STREAM_EXISTS";
pub const ERR_IDEMPOTENCY_CONFLICT: &str = "DBB_IDEMPOTENCY_CONFLICT";
pub const ERR_RESUME_IN_PROGRESS: &str = "DBB_RESUME_IN_PROGRESS";
pub const ERR_INSTANCE_MISMATCH: &str = "DBB_INSTANCE_MISMATCH";
pub const ERR_NODE_MISMATCH: &str = "DBB_NODE_MISMATCH";
/// A reverse tunnel was refused: its id is taken, or another instance of the
/// peer still holds live tunnels.
pub const ERR_TUNNEL_CONFLICT: &str = "DBB_TUNNEL_CONFLICT";
/// A request names a reverse tunnel the public side no longer has.
pub const ERR_TUNNEL_NOT_FOUND: &str = "DBB_TUNNEL_NOT_FOUND";
pub const ERR_PROTOCOL_MISMATCH: &str = "DBB_PROTOCOL_MISMATCH";
pub const ERR_RECOVERY_DISABLED: &str = "DBB_RECOVERY_DISABLED";
pub const ERR_RECOVERY_UNSUPPORTED: &str = "DBB_RECOVERY_UNSUPPORTED";
pub const ERR_OFFSET_GAP: &str = "DBB_OFFSET_GAP";
pub const ERR_FRAME_CONFLICT: &str = "DBB_FRAME_CONFLICT";
pub const ERR_REPLAY_TOO_OLD: &str = "DBB_REPLAY_TOO_OLD";
pub const ERR_WINDOW_EXCEEDED: &str = "DBB_WINDOW_EXCEEDED";
pub const ERR_SESSION_CLOSED: &str = "DBB_SESSION_CLOSED";
pub const ERR_BACKEND_LOST: &str = "DBB_BACKEND_LOST";
pub const ERR_FRAME_TOO_LARGE: &str = "DBB_FRAME_TOO_LARGE";
pub const ERR_QUOTA_EXCEEDED: &str = "DBB_QUOTA_EXCEEDED";
pub const ERR_DIAL_FAILED: &str = "DBB_DIAL_FAILED";
pub const ERR_BUFFER_EXHAUSTED: &str = "DBB_BUFFER_EXHAUSTED";
pub const ERR_DRAINING: &str = "DBB_DRAINING";
pub const ERR_CREATE_PENDING: &str = "DBB_CREATE_PENDING";
pub const ERR_RESUME_PENDING: &str = "DBB_RESUME_PENDING";
pub const ERR_RESUME_EXPIRED: &str = "DBB_RESUME_EXPIRED";
pub const ERR_TRANSPORT_UNSUPPORTED: &str = "DBB_TRANSPORT_UNSUPPORTED";
pub const ERR_TRANSPORT_MISMATCH: &str = "DBB_TRANSPORT_MISMATCH";
pub const ERR_WS_HANDSHAKE_FAILED: &str = "DBB_WS_HANDSHAKE_FAILED";
pub const ERR_WS_PROTOCOL_ERROR: &str = "DBB_WS_PROTOCOL_ERROR";
pub const SESSION_CLOSED_NORMAL_MESSAGE: &str = "session terminated: normal";
pub const ERR_TLS_FAILED: &str = "DBB_TLS_FAILED";
pub const ERR_INTERNAL_ERROR: &str = "DBB_INTERNAL_ERROR";

/// 56-byte header of a WebSocket DATA frame:
/// `[0,1) type=0x01, [1,2) flags=0, [2,4) reserved=0, [4,12) epoch,
/// [12,20) offset, [20,24) length, [24,56) sha256(payload)`.
pub const WS_HEADER_LEN: usize = 56;
pub const WS_DATA_TYPE: u8 = 0x01;
/// Largest DATA payload a frame may carry.
pub const MAX_FRAME_PAYLOAD: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    Ws,
    HttpSse,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Ws => "ws",
            Mode::HttpSse => "http-sse",
        }
    }

    pub fn parse(s: &str) -> Option<Mode> {
        match s {
            "ws" => Some(Mode::Ws),
            "http-sse" => Some(Mode::HttpSse),
            _ => None,
        }
    }
}
mod ack;
mod control;
mod create;
mod frame;
mod resume;

pub use ack::{AckRequest, AckResponse, ErrorBody, FinResponse};
pub use control::{Control, ControlKind};
pub use create::{CreateRequest, CreateResponse, Limits, ProbeRequest, ProbeResponse};
pub use frame::{decode_ws_frame, encode_ws_frame, format_sse_data, parse_sse_data};
pub use resume::{validate_response as validate_resume_response, ResumeRequestWire};
// `Frame` is never named outside this module — callers let the decoder's return
// type do the work — but it is that return type, so it stays reachable.
#[allow(unused_imports)]
pub use frame::Frame;

/// Validates a peer-issued session ID: RFC 3986 unreserved characters only, so
/// it can never alter the request path.
pub fn valid_session_id(sid: &str) -> bool {
    if sid.is_empty() || sid.len() > 128 || sid == "." || sid == ".." {
        return false;
    }
    sid.bytes()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'~'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::json::Json;

    #[test]
    fn frame_round_trip() {
        let payload = b"hello world";
        let msg = encode_ws_frame(1, 42, payload).unwrap();
        let f = decode_ws_frame(&msg).unwrap();
        assert_eq!(f.epoch, 1);
        assert_eq!(f.offset, 42);
        assert_eq!(f.payload, payload);
    }

    #[test]
    fn frame_rejects_corruption() {
        let mut msg = encode_ws_frame(1, 0, b"abc").unwrap();
        msg[WS_HEADER_LEN] ^= 0xff;
        assert_eq!(decode_ws_frame(&msg).unwrap_err().code, ERR_BAD_DIGEST);
        assert!(encode_ws_frame(0, 0, b"abc").is_err());
        assert!(encode_ws_frame(1, 0, b"").is_err());
    }

    #[test]
    fn sse_round_trip() {
        let payload: Vec<u8> = (0..100u8).collect();
        let s = format_sse_data(1024, &payload).unwrap();
        let (off, data) = parse_sse_data(&s).unwrap();
        assert_eq!(off, 1024);
        assert_eq!(data, payload);
    }

    #[test]
    fn sse_rejects_bad_digest() {
        let s = format_sse_data(0, b"abc").unwrap();
        let mut parts: Vec<&str> = s.splitn(4, ':').collect();
        parts[2] = "0000000000000000000000000000000000000000000000000000000000000000";
        let tampered = parts.join(":");
        assert!(parse_sse_data(&tampered).is_err());
    }

    #[test]
    fn control_encoding_matches_spec_union_rules() {
        let mut c = Control::base(ControlKind::AckUp, "s1", "i1", 1, "st");
        c.ack_up_offset = Some(7);
        let text = c.to_json().to_string();
        assert!(text.contains("\"ack_up_offset\":\"7\""));
        assert!(text.contains("\"up_fin_applied\":false"));
        assert!(!text.contains("ack_requested"));

        let parsed = Control::parse(&text).unwrap();
        assert_eq!(parsed.kind, ControlKind::AckUp);
        assert_eq!(parsed.ack_up_offset, Some(7));
    }

    #[test]
    fn control_parse_rejects_unknown_type() {
        let bad =
            r#"{"type":"nope","session_id":"s","instance_id":"i","epoch":"1","stream_id":"x"}"#;
        assert!(Control::parse(bad).is_err());
    }

    #[test]
    fn ready_message_keeps_null_resume_id() {
        let mut c = Control::base(ControlKind::Ready, "s1", "i1", 1, "st");
        c.protocol_version = Some(PROTOCOL_VERSION.to_string());
        c.transport = Some("ws".to_string());
        let text = c.to_json().to_string();
        assert!(text.contains("\"resume_request_id\":null"));
    }

    #[test]
    fn control_marshal_field_sets() {
        let common = ["type", "session_id", "instance_id", "epoch", "stream_id"];
        let cases: [(ControlKind, &[&str]); 5] = [
            (
                ControlKind::Ready,
                &["protocol_version", "transport", "resume_request_id"],
            ),
            (
                ControlKind::AckUp,
                &["ack_up_offset", "up_fin_applied", "ack_requested"],
            ),
            (ControlKind::Ping, &["nonce"]),
            (ControlKind::Fin, &["final_offset"]),
            (ControlKind::Error, &["code", "retryable", "session_closed"]),
        ];
        for (kind, extra) in cases {
            let mut c = Control::base(kind, "s", "i", 1, "st");
            c.protocol_version = Some(PROTOCOL_VERSION.to_string());
            c.transport = Some("ws".to_string());
            c.ack_requested = true;
            let encoded = c.to_json();
            let Json::Obj(fields) = encoded else {
                panic!("control encoder did not produce an object");
            };
            let mut got: Vec<_> = fields.iter().map(|(key, _)| key.as_str()).collect();
            let mut expected: Vec<_> = common.into_iter().chain(extra.iter().copied()).collect();
            got.sort_unstable();
            expected.sort_unstable();
            assert_eq!(got, expected, "wrong fields for {}", kind.as_str());
        }
    }

    #[test]
    fn control_parse_rejects_unknown_type_specific_field() {
        let bad = r#"{"type":"ping","session_id":"s","instance_id":"i","epoch":"1","stream_id":"st","nonce":"n","code":"DBB_BAD_FRAME"}"#;
        let err = Control::parse(bad).unwrap_err();
        assert_eq!(err.code, ERR_WS_PROTOCOL_ERROR);
    }

    #[test]
    fn sse_parser_rejects_noncanonical_decimal_offsets_and_lengths() {
        let canonical = format_sse_data(5, b"x").unwrap();
        let parts: Vec<_> = canonical.splitn(4, ':').collect();
        let suffix = format!(":{}:{}", parts[2], parts[3]);
        for bad in [
            format!("0005:1{suffix}"),
            format!("+5:1{suffix}"),
            format!("5:+1{suffix}"),
            format!("5:01{suffix}"),
            format!(":1{suffix}"),
            format!("5:{suffix}"),
        ] {
            assert_eq!(
                parse_sse_data(&bad).unwrap_err().code,
                ERR_BAD_FRAME,
                "accepted {bad}"
            );
        }
        assert_eq!(parse_sse_data(&canonical).unwrap().0, 5);
    }

    #[test]
    fn sse_parser_rejects_malformed_base64_shapes_and_bad_digest() {
        let canonical = format_sse_data(0, b"A").unwrap();
        let parts: Vec<_> = canonical.splitn(4, ':').collect();
        let malformed_payloads = vec![
            "QQ".to_string(),
            "QQ==QQ==".to_string(),
            "A===".to_string(),
            "A".repeat(5_464),
        ];
        for bad_payload in malformed_payloads {
            let bad = format!("{}:{}:{}:{}", parts[0], parts[1], parts[2], bad_payload);
            assert_eq!(
                parse_sse_data(&bad).unwrap_err().code,
                ERR_BAD_FRAME,
                "accepted base64 payload of length {}",
                bad_payload.len(),
            );
        }

        let corrupted =
            "100:4:0000000000000000000000000000000000000000000000000000000000000000:dGVzdA==";
        assert_eq!(parse_sse_data(corrupted).unwrap_err().code, ERR_BAD_DIGEST);
    }

    #[test]
    fn sse_format_and_parse_enforce_payload_and_offset_boundaries() {
        assert_eq!(format_sse_data(0, b"").unwrap_err().code, ERR_BAD_FRAME);
        assert_eq!(
            format_sse_data(0, &vec![0; MAX_FRAME_PAYLOAD + 1])
                .unwrap_err()
                .code,
            ERR_BAD_FRAME
        );
        assert_eq!(
            format_sse_data(u64::MAX, b"x").unwrap_err().code,
            ERR_BAD_FRAME
        );

        let payload = vec![0xa5; MAX_FRAME_PAYLOAD];
        let line = format_sse_data(7, &payload).unwrap();
        let (offset, decoded) = parse_sse_data(&line).unwrap();
        assert_eq!(offset, 7);
        assert_eq!(decoded, payload);

        let overflow = format!(
            "{}:1:2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881:eA==",
            u64::MAX
        );
        assert_eq!(parse_sse_data(&overflow).unwrap_err().code, ERR_BAD_FRAME);
    }

    #[test]
    fn sse_parser_rejects_noncanonical_base64_and_payload_length_edges() {
        let canonical = format_sse_data(0, b"A").unwrap();
        let parts: Vec<_> = canonical.splitn(4, ':').collect();

        // `QR==` decodes to the same byte as `QQ==`, but has non-zero unused
        // trailing bits and is not the canonical padded wire representation.
        let noncanonical = format!("{}:{}:{}:QR==", parts[0], parts[1], parts[2]);
        assert_eq!(
            parse_sse_data(&noncanonical).unwrap_err().code,
            ERR_BAD_FRAME
        );

        let wrong_decoded_length = format!("0:2:{}:QQ==", parts[2]);
        assert_eq!(
            parse_sse_data(&wrong_decoded_length).unwrap_err().code,
            ERR_BAD_FRAME
        );

        let empty_digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(
            parse_sse_data(&format!("0:0:{empty_digest}:"))
                .unwrap_err()
                .code,
            ERR_BAD_FRAME
        );
        assert_eq!(
            parse_sse_data(&format!("0:{}:{}:A", MAX_FRAME_PAYLOAD + 1, parts[2]))
                .unwrap_err()
                .code,
            ERR_BAD_FRAME
        );
    }

    fn test_next(state: &mut u64) -> u64 {
        *state ^= *state << 13;
        *state ^= *state >> 7;
        *state ^= *state << 17;
        *state
    }

    #[test]
    fn fuzz_boundary_ws_decode_round_trips_seeded_inputs() {
        let mut state = 0x2e6b_71d4_9a03_c85fu64;
        for _ in 0..256 {
            let len = (test_next(&mut state) as usize % 4096) + 1;
            let mut payload = vec![0u8; len];
            for byte in &mut payload {
                *byte = test_next(&mut state) as u8;
            }
            let epoch = test_next(&mut state).max(1);
            let offset = test_next(&mut state) % (u64::MAX - len as u64);
            let encoded = encode_ws_frame(epoch, offset, &payload).unwrap();
            let decoded = decode_ws_frame(&encoded).unwrap();
            assert_eq!(
                (decoded.epoch, decoded.offset, decoded.payload),
                (epoch, offset, &payload[..])
            );
            assert_eq!(
                encode_ws_frame(decoded.epoch, decoded.offset, decoded.payload).unwrap(),
                encoded
            );

            // Arbitrary short byte strings must either be rejected or have a
            // unique canonical encoding when accepted.
            let raw_len = test_next(&mut state) as usize % 256;
            let raw: Vec<u8> = (0..raw_len).map(|_| test_next(&mut state) as u8).collect();
            if let Ok(frame) = decode_ws_frame(&raw) {
                assert_eq!(
                    encode_ws_frame(frame.epoch, frame.offset, frame.payload).unwrap(),
                    raw
                );
            }
        }
        let at_spec_fuzz_limit = vec![0u8; 2 << 20];
        assert!(decode_ws_frame(&at_spec_fuzz_limit).is_err());
    }

    #[test]
    fn fuzz_boundary_sse_decode_round_trips_seeded_inputs() {
        let mut state = 0x715a_38c2_d4e9_06bfu64;
        const ALPHABET: &[u8] = b"0123456789abcdefABCDEF:+/=_- xyz\n";
        for _ in 0..256 {
            let len = (test_next(&mut state) as usize % 4096) + 1;
            let mut payload = vec![0u8; len];
            for byte in &mut payload {
                *byte = test_next(&mut state) as u8;
            }
            let offset = test_next(&mut state) % (u64::MAX - len as u64);
            let line = format_sse_data(offset, &payload).unwrap();
            let (decoded_offset, decoded_payload) = parse_sse_data(&line).unwrap();
            assert_eq!(decoded_offset, offset);
            assert_eq!(decoded_payload, payload);
            let reformatted = format_sse_data(decoded_offset, &decoded_payload).unwrap();
            let (again_offset, again_payload) = parse_sse_data(&reformatted).unwrap();
            assert_eq!((again_offset, again_payload), (offset, payload));

            let random_len = test_next(&mut state) as usize % 256;
            let random_line: String = (0..random_len)
                .map(|_| ALPHABET[test_next(&mut state) as usize % ALPHABET.len()] as char)
                .collect();
            if let Ok((accepted_offset, accepted_payload)) = parse_sse_data(&random_line) {
                let canonical = format_sse_data(accepted_offset, &accepted_payload).unwrap();
                let (round_offset, round_payload) = parse_sse_data(&canonical).unwrap();
                assert_eq!(round_offset, accepted_offset);
                assert_eq!(round_payload, accepted_payload);
            }
        }
        let at_spec_fuzz_limit = "x".repeat(2 << 20);
        assert!(parse_sse_data(&at_spec_fuzz_limit).is_err());
    }
}

#[cfg(test)]
mod spec_wire_tests;
