//! Wire helpers shared by the reverse HTTP carriers.
//! The actual smux byte stream remains in `pipe`; this module owns the small,
//! deterministic SSE/poll framing boundary.
pub const MAX_UPLOAD: usize = 128 * 1024;
pub const MAX_POLL: usize = 256 * 1024;
pub const SSE_CHUNK: usize = 32 * 1024;

/// Parses a long-poll response. 204 is an empty poll; 200 must carry a
/// non-negative offset and the raw body. The caller applies Pipe's overlap
/// deduplication and gap detection.
pub fn parse_poll_response<'a>(
    status: u16,
    offset: Option<&str>,
    body: &'a [u8],
) -> Option<(i64, &'a [u8])> {
    if status == 204 {
        return None;
    }
    if status != 200 {
        return None;
    }
    if body.len() > MAX_POLL {
        return None;
    }
    let off = offset?.parse::<i64>().ok()?;
    (off >= 0).then_some((off, body))
}

#[cfg(test)]
pub fn auto_mode_after(
    mode: &str,
    status: u16,
    code: Option<&str>,
    identity: bool,
    ready_buffered: bool,
) -> Option<&'static str> {
    match classify_fallback_identity(mode, status, code, identity, ready_buffered) {
        Fallback::ToSse => Some("http-sse"),
        Fallback::ToPoll => Some("long-poll"),
        Fallback::No => None,
    }
}

#[cfg(test)]
pub fn sse_ready(offset: i64) -> String {
    format!("event: ready\ndata: {offset}\n\n")
}
#[cfg(test)]
pub fn parse_sse_event(input: &str) -> Option<(Option<i64>, String, String)> {
    let mut id = None;
    let mut event = String::new();
    let mut data = String::new();
    for line in input.lines() {
        if let Some(v) = line.strip_prefix("id: ") {
            id = v.trim().parse().ok()
        } else if let Some(v) = line.strip_prefix("event: ") {
            event = v.trim().to_string()
        } else if let Some(v) = line.strip_prefix("data: ") {
            data.push_str(v.trim());
        }
    }
    if event.is_empty() {
        None
    } else {
        Some((id, event, data))
    }
}
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fallback {
    ToSse,
    ToPoll,
    No,
}
#[cfg(test)]
pub fn classify_fallback(
    mode: &str,
    status: u16,
    code: Option<&str>,
    ready_buffered: bool,
) -> Fallback {
    classify_fallback_identity(mode, status, code, false, ready_buffered)
}
/// A response carrying the verified peer identity is a DBBridge refusal, not
/// a plain intermediary answer. Only an explicit unsupported code may pass.
#[cfg(test)]
pub fn classify_fallback_identity(
    mode: &str,
    status: u16,
    code: Option<&str>,
    dbbridge_identity: bool,
    ready_buffered: bool,
) -> Fallback {
    if status == 401 {
        return Fallback::No;
    }
    // A plain intermediary response is fallback-safe only when it carries no
    // DBBridge identity and no protocol code.  An identified peer may only
    // opt us down explicitly with TRANSPORT_UNSUPPORTED.
    let plain = (!dbbridge_identity && code.is_none())
        || (dbbridge_identity && code == Some("DBB_TRANSPORT_UNSUPPORTED"));
    match (mode, plain || ready_buffered) {
        ("ws", true) => Fallback::ToSse,
        ("http-sse", true) => Fallback::ToPoll,
        _ => Fallback::No,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_ready() {
        assert_eq!(sse_ready(7), "event: ready\ndata: 7\n\n");
    }
    #[test]
    fn parse_data() {
        assert_eq!(
            parse_sse_event("id: 3\nevent: data\ndata: YQ==\n\n")
                .unwrap()
                .0,
            Some(3)
        );
    }
    #[test]
    fn fallback_is_strict() {
        assert_eq!(classify_fallback("ws", 404, None, false), Fallback::ToSse);
        assert_eq!(
            classify_fallback_identity("ws", 403, None, true, false),
            Fallback::No
        );
        assert_eq!(classify_fallback("ws", 401, None, false), Fallback::No);
        assert_eq!(
            classify_fallback("http-sse", 200, None, true),
            Fallback::ToPoll
        );
    }
    #[test]
    fn poll_body_parser_checks_status_and_offset() {
        let body = b"abc";
        assert_eq!(parse_poll_response(204, None, body), None);
        assert_eq!(parse_poll_response(200, Some("7"), body).unwrap().0, 7);
        assert_eq!(parse_poll_response(200, Some("-1"), body), None);
        assert_eq!(parse_poll_response(500, Some("7"), body), None);
        assert_eq!(
            parse_poll_response(200, Some("0"), &vec![0; MAX_POLL + 1]),
            None
        );
    }
    #[test]
    fn auto_selection_is_ordered_and_strict() {
        assert_eq!(
            auto_mode_after("ws", 404, None, false, false),
            Some("http-sse")
        );
        assert_eq!(
            auto_mode_after("http-sse", 200, None, false, true),
            Some("long-poll")
        );
        assert_eq!(auto_mode_after("ws", 403, None, true, false), None);
        assert_eq!(auto_mode_after("ws", 401, None, false, false), None);
        assert_eq!(
            auto_mode_after("ws", 409, Some("DBB_TRANSPORT_UNSUPPORTED"), true, false),
            Some("http-sse")
        );
        assert_eq!(auto_mode_after("ws", 503, None, true, false), None);
    }
}
