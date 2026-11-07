use super::errors::{fatal_error, reason_category};
use crate::error::Error;
use crate::wire;

#[test]
fn spec_reason_category_names_egress_dial_and_drain_refusals() {
    for (code, want) in [
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
    ] {
        assert_eq!(reason_category(&Error::new(code, "")), want, "{code}");
    }
    for code in [
        wire::ERR_FRAME_TOO_LARGE,
        wire::ERR_TRANSPORT_MISMATCH,
        wire::ERR_TRANSPORT_UNSUPPORTED,
        wire::ERR_PROTOCOL_MISMATCH,
        wire::ERR_NODE_MISMATCH,
    ] {
        assert!(
            fatal_error(&Error::new(code, "").trusted(true)),
            "expected trusted {code} to be fatal"
        );
    }
}

#[test]
fn spec_reason_category_shutdown_and_local_socket() {
    assert_eq!(
        reason_category(&Error::local("ingress shutdown")),
        "shutdown",
        "node stop"
    );
    assert_eq!(
        reason_category(&Error::local(format!(
            "local client socket error: write: {}",
            std::io::Error::from(std::io::ErrorKind::BrokenPipe)
        ))),
        "local_socket",
        "client socket error"
    );
    assert_eq!(
        reason_category(&Error::local("read: connection reset by peer")),
        "network",
        "carrier error"
    );
}

#[test]
fn spec_log_time_leaves_zero_empty() {
    use crate::slog::V;
    let now = std::time::SystemTime::now();
    let record = |deadline| super::termination::Termination {
        session: "s".into(),
        peer: "p".into(),
        endpoint: String::new(),
        owner: String::new(),
        epoch: 0,
        transport: "",
        recovery_enabled: true,
        attempts: 0,
        deadline,
        outcome_unknown: false,
        reason: "normal",
        fault_source: String::new(),
        fault_reason: "",
        fault_time: None,
        terminal: now,
        local_closed: now,
    };
    let deadline_of = |r: &super::termination::Termination| {
        r.attrs()
            .into_iter()
            .find(|(k, _)| *k == "deadline")
            .map(|(_, v)| match v {
                V::Str(s) => format!("str:{s}"),
                V::Time(Some(t)) => format!("time:{:?}", t),
                _ => "other".to_string(),
            })
            .unwrap()
    };
    assert_eq!(deadline_of(&record(None)), "str:", "zero time logged");
    assert_eq!(
        deadline_of(&record(Some(now))),
        format!("time:{:?}", now),
        "non-zero time changed"
    );
}

#[test]
fn spec_flow_ack_thresholds() {
    use super::relay::{
        down_bytes_ack_threshold, down_frames_ack_threshold, up_frames_ack_threshold,
    };
    let mut adv = wire::Limits {
        max_frame_size: 0,
        up_max_inflight_frames: 8,
        up_window_bytes: 0,
        down_buffer_bytes: 4 << 20,
        up_receipt_limit: 64,
        down_max_frames: 512,
    };
    assert_eq!(up_frames_ack_threshold(&adv), 12, "advertised up threshold");
    assert_eq!(
        down_frames_ack_threshold(&adv),
        32,
        "advertised down threshold"
    );
    adv.up_receipt_limit = 10;
    adv.down_max_frames = 40;
    assert_eq!(
        up_frames_ack_threshold(&adv),
        5,
        "small receipt limit up threshold"
    );
    assert_eq!(
        down_frames_ack_threshold(&adv),
        10,
        "small frame cap down threshold"
    );
    adv.down_max_frames = 2;
    assert_eq!(
        down_frames_ack_threshold(&adv),
        1,
        "tiny frame cap down threshold"
    );
    assert_eq!(
        down_bytes_ack_threshold(1 << 20, &adv),
        1 << 20,
        "byte threshold"
    );
    let small = wire::Limits {
        max_frame_size: 0,
        up_max_inflight_frames: 0,
        up_window_bytes: 0,
        down_buffer_bytes: 512 << 10,
        up_receipt_limit: 0,
        down_max_frames: 0,
    };
    assert_eq!(
        down_bytes_ack_threshold(1 << 20, &small),
        256 << 10,
        "byte threshold under a small negotiated window"
    );
}
