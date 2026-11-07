use super::tests::{config, set_header, valid_request};
use super::{Hub, H_EXPECTED_NODE_ID, H_NODE_ID, H_TUNNEL_ID, H_TUNNEL_PRIORITY};
use crate::wire;

#[test]
fn spec_hub_rejects_bad_handshakes() {
    let cfg = config();
    let hub = Hub::new(&cfg);
    type Mutate = fn(&mut crate::net::http1::Request);
    let cases: [(&str, Mutate, u16, &str); 8] = [
        (
            "no token",
            |q| set_header(q, wire::H_PEER_AUTH, None),
            401,
            wire::ERR_UNAUTHORIZED,
        ),
        (
            "wrong token",
            |q| {
                set_header(
                    q,
                    wire::H_PEER_AUTH,
                    Some("Bearer wrong-token-0123456789abcdef"),
                )
            },
            401,
            wire::ERR_UNAUTHORIZED,
        ),
        (
            "impersonated node",
            |q| set_header(q, H_NODE_ID, Some("plant-x")),
            403,
            wire::ERR_NODE_MISMATCH,
        ),
        (
            "wrong public node",
            |q| set_header(q, H_EXPECTED_NODE_ID, Some("hq-z")),
            403,
            wire::ERR_NODE_MISMATCH,
        ),
        (
            "old protocol",
            |q| set_header(q, "Sec-WebSocket-Protocol", Some("dbbridge.reverse.v1.4")),
            409,
            wire::ERR_PROTOCOL_MISMATCH,
        ),
        (
            "no subprotocol",
            |q| set_header(q, "Sec-WebSocket-Protocol", None),
            409,
            wire::ERR_TRANSPORT_UNSUPPORTED,
        ),
        (
            "bad tunnel id",
            |q| set_header(q, H_TUNNEL_ID, Some("x")),
            400,
            wire::ERR_BAD_FRAME,
        ),
        (
            "bad priority",
            |q| set_header(q, H_TUNNEL_PRIORITY, Some("-1")),
            400,
            wire::ERR_BAD_FRAME,
        ),
    ];
    for (name, mutate, status, code) in cases {
        let mut q = valid_request();
        mutate(&mut q);
        let e = hub
            .reserve(&q, &cfg)
            .err()
            .unwrap_or_else(|| panic!("{name}: accepted"));
        assert_eq!((e.status(), e.code.as_str()), (status, code), "{name}: {e}");
    }
    assert!(
        hub.live_tunnels("peer-b") == 0 && hub.rejected() >= 8,
        "tunnels={} rejected={}",
        hub.live_tunnels("peer-b"),
        hub.rejected()
    );
}
