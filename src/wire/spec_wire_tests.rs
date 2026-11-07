use super::*;
use crate::util::json::{self, Json};

const CTL_BASE: &str = r#""session_id":"s","instance_id":"i","epoch":"1","stream_id":"x""#;

#[test]
fn spec_control_union_strictness() {
    let bad = [
        format!(r#"{{"type":"ping",{CTL_BASE},"nonce":"n","code":"DBB_X","final_offset":"5"}}"#),
        format!(
            r#"{{"type":"ack_up",{CTL_BASE},"ack_up_offset":"1","up_fin_applied":false,"nonce":"n"}}"#
        ),
        format!(r#"{{"type":"bogus",{CTL_BASE}}}"#),
        format!(r#"{{"type":"",{CTL_BASE}}}"#),
    ];
    for c in &bad {
        assert!(Control::parse(c).is_err(), "accepted {c}");
    }
    let good = [
        format!(r#"{{"type":"ping",{CTL_BASE},"nonce":"n"}}"#),
        format!(r#"{{"type":"ack_up",{CTL_BASE},"ack_up_offset":"1","up_fin_applied":true}}"#),
        format!(r#"{{"type":"fin",{CTL_BASE},"final_offset":"9"}}"#),
        format!(
            r#"{{"type":"error",{CTL_BASE},"code":"DBB_X","retryable":false,"session_closed":true}}"#
        ),
    ];
    for c in &good {
        if let Err(e) = Control::parse(c) {
            panic!("rejected {c}: {e}");
        }
    }
}

#[test]
fn spec_sse_data_strict_base64() {
    let good = format_sse_data(0, b"A").unwrap();
    parse_sse_data(&good).unwrap();
    let parts: Vec<&str> = good.splitn(4, ':').collect();
    assert_eq!(parts[3], "QQ==", "fixture {good:?}");
    let big = crate::util::base64::encode(&[0u8; 4096]);
    for b64 in ["QR==", "QQ", "QQ==QQ==", big.as_str()] {
        let line = format!("{}:{b64}", parts[..3].join(":"));
        assert!(parse_sse_data(&line).is_err(), "accepted {b64:?}");
    }
    assert!(format_sse_data(0, b"").is_err(), "empty payload accepted");
    assert!(
        format_sse_data(0, &vec![0; MAX_FRAME_PAYLOAD + 1]).is_err(),
        "oversized payload accepted"
    );
    assert!(
        format_sse_data(u64::MAX, b"x").is_err(),
        "overflowing offset accepted"
    );
    let line = format_sse_data(7, b"x").unwrap();
    let (offset, payload) = parse_sse_data(&line).unwrap();
    assert_eq!((offset, payload.as_slice()), (7, &b"x"[..]));
    assert!(
        line.starts_with("7:1:") && line.ends_with(":eA=="),
        "{line}"
    );
}

fn without(text: &str, key: &str) -> String {
    let Json::Obj(fields) = json::parse(text).unwrap() else {
        panic!("not an object: {text}");
    };
    json::obj(
        fields
            .into_iter()
            .filter(|(k, _)| k != key)
            .map(|(k, v)| (Box::leak(k.into_boxed_str()) as &str, v))
            .collect(),
    )
    .to_string()
}

#[test]
fn spec_control_false_fields_and_ack_diagnostics() {
    let mut m = Control::base(ControlKind::AckUp, "s", "bi", 1, "st");
    m.ack_up_offset = Some(0);
    m.up_fin_applied = false;
    let text = m.to_json().to_string();
    Control::parse(&text).unwrap();
    assert!(
        Control::parse(&without(&text, "up_fin_applied")).is_err(),
        "missing ack_up false state accepted"
    );
    let ack = AckRequest {
        backpressure_reason: "none".into(),
        ..AckRequest::default()
    };
    let text = ack.to_json().to_string();
    AckRequest::from_json(&json::parse(&text).unwrap()).unwrap();
    for name in ["data_tx_blocked", "data_rx_blocked", "backpressure_reason"] {
        let missing = without(&text, name);
        assert!(
            AckRequest::from_json(&json::parse(&missing).unwrap()).is_err(),
            "missing {name} accepted"
        );
    }
}

fn create_response_with_frames(frames: &str) -> crate::error::Result<CreateResponse> {
    let text = format!(
        r#"{{"node_id":"n","instance_id":"i","session_id":"s","session_token":"t","epoch":"1",
        "transport":{{"mode":"ws"}},"recovery":{{"enabled":false,"grace_ms":0}},
        "limits":{{"max_frame_size":512,"up_max_inflight_frames":8,"up_window_bytes":1048576,
        "down_buffer_bytes":1048576,"up_receipt_limit":{frames},"down_max_frames":{frames}}},
        "unattached_timeout_ms":1000}}"#
    );
    CreateResponse::from_json(&json::parse(&text).unwrap())
}

#[test]
fn spec_clamp_advertised_frames() {
    const MAX: u32 = 1 << 20;
    for (input, want) in [
        ("0", 0),
        ("64", 64),
        ("1048576", MAX),
        ("1048577", MAX),
        ("1073741824", MAX),
    ] {
        let r = create_response_with_frames(input).unwrap();
        assert_eq!(r.limits.up_receipt_limit, want, "up_receipt_limit({input})");
        assert_eq!(r.limits.down_max_frames, want, "down_max_frames({input})");
    }
    assert!(create_response_with_frames("-1").is_err());
}

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

#[test]
fn spec_fuzz_boundary_ws_decode() {
    let mut corpus = vec![
        encode_ws_frame(1, 0, &[0, 255, 10, 13]).unwrap(),
        Vec::new(),
    ];
    let mut rng = Lcg(1);
    for i in 0..3000 {
        let n = (rng.next() % 300) as usize + 1;
        let (epoch, offset, payload) = (rng.next() % 5 + 1, rng.next(), rng.bytes(n));
        let frame = encode_ws_frame(epoch, offset, &payload).unwrap();
        match i % 4 {
            0 => corpus.push(frame),
            1 => {
                let mut m = frame;
                let at = (rng.next() as usize) % m.len();
                m[at] ^= 1 << (rng.next() % 8);
                corpus.push(m);
            }
            2 => {
                let mut m = frame;
                m.truncate((rng.next() as usize) % m.len());
                corpus.push(m);
            }
            _ => {
                let n = (rng.next() % 120) as usize;
                corpus.push(rng.bytes(n));
            }
        }
    }
    let mut accepted = 0;
    for b in corpus.iter().filter(|b| b.len() <= 2 << 20) {
        if let Ok(f) = decode_ws_frame(b) {
            accepted += 1;
            let again = encode_ws_frame(f.epoch, f.offset, f.payload).unwrap();
            assert_eq!(&again, b, "accepted non-roundtrippable frame");
        }
    }
    assert!(
        accepted >= 750,
        "too few valid frames exercised: {accepted}"
    );
}

#[test]
fn spec_fuzz_boundary_sse_decode() {
    let mut corpus = vec![
        format_sse_data(0, &[0, 255, 10, 13]).unwrap(),
        String::new(),
    ];
    let mut rng = Lcg(2);
    for i in 0..3000 {
        let n = (rng.next() % 300) as usize + 1;
        let (offset, payload) = (rng.next(), rng.bytes(n));
        let line = format_sse_data(offset, &payload).unwrap();
        match i % 4 {
            0 => corpus.push(line),
            1 => {
                let mut m = line.into_bytes();
                let at = (rng.next() as usize) % m.len();
                m[at] = b"0123456789abcdef:=+/ \nAZ"[(rng.next() % 24) as usize];
                corpus.push(String::from_utf8_lossy(&m).into_owned());
            }
            2 => {
                let cut = (rng.next() as usize) % line.len();
                corpus.push(line[..cut].to_string());
            }
            _ => {
                let n = (rng.next() % 120) as usize;
                corpus.push(String::from_utf8_lossy(&rng.bytes(n)).into_owned());
            }
        }
    }
    let mut accepted = 0;
    for s in corpus.iter().filter(|s| s.len() <= 2 << 20) {
        if let Ok((off, p)) = parse_sse_data(s) {
            accepted += 1;
            let (off2, p2) =
                parse_sse_data(&format_sse_data(off, &p).unwrap()).expect("frame roundtrip");
            assert_eq!((off, &p), (off2, &p2), "frame roundtrip");
        }
    }
    assert!(accepted >= 750, "too few valid lines exercised: {accepted}");
}
