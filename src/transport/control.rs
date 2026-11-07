//! Client for the control API the ingress calls on the egress: probe, create,
//! ack, fin, delete.
//!
//! These always travel over plain HTTP requests, never over the data carrier,
//! so acknowledgements still arrive when the data channel is saturated.

use std::sync::Arc;
use std::time::Duration;

use crate::config::ClientTls;
use crate::error::{Error, Result};
use crate::net::http1::{self, Client};
use crate::net::Url;
use crate::util::json::Json;
use crate::wire::{
    self, AckRequest, AckResponse, CreateRequest, CreateResponse, ErrorBody, FinResponse,
    ProbeRequest, ProbeResponse,
};

pub type TokenProvider = Arc<dyn Fn() -> Result<String> + Send + Sync>;

pub struct ControlClient {
    pub client: Arc<Client>,
    pub url: Url,
    pub token: String,
    pub token_provider: Option<TokenProvider>,
    /// The egress instance this client expects, echoed on every request so a
    /// restarted peer is refused instead of silently served.
    pub expected_instance: String,
    pub tls: ClientTls,
}

impl ControlClient {
    pub fn new(
        client: Arc<Client>,
        url: Url,
        token: String,
        expected_instance: String,
        tls: ClientTls,
    ) -> Self {
        ControlClient {
            client,
            url,
            token,
            token_provider: None,
            expected_instance,
            tls,
        }
    }

    pub fn with_optional_token_provider(mut self, provider: Option<TokenProvider>) -> Self {
        if let Some(provider) = provider {
            self.token_provider = Some(provider);
        }
        self
    }
    pub fn with_token_provider(mut self, provider: TokenProvider) -> Self {
        self.token_provider = Some(provider);
        self
    }
    pub fn current_token(&self) -> Result<String> {
        match &self.token_provider {
            Some(p) => p(),
            None if !self.token.is_empty() => Ok(self.token.clone()),
            _ => Err(Error::new(
                crate::config::CODE_CREDENTIAL,
                "missing outbound credential",
            )),
        }
    }
    fn base_headers(&self) -> Result<Vec<(String, String)>> {
        let token = self.current_token()?;
        let mut h = vec![
            ("Authorization".to_string(), format!("Bearer {token}")),
            ("Accept".to_string(), "application/json".to_string()),
        ];
        if !self.expected_instance.is_empty() {
            h.push((
                wire::H_INSTANCE_ID.to_string(),
                self.expected_instance.clone(),
            ));
        }
        Ok(h)
    }

    fn send(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: Option<Vec<u8>>,
        accept: &[u16],
    ) -> Result<http1::Response> {
        self.send_within(method, path, headers, body, accept, None)
    }

    fn send_within(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: Option<Vec<u8>>,
        accept: &[u16],
        timeout: Option<std::time::Duration>,
    ) -> Result<http1::Response> {
        let resp = match timeout {
            Some(t) => {
                self.client
                    .request_within(&self.url, method, path, headers, body.as_deref(), t)?
            }
            None => self
                .client
                .request(&self.url, method, path, headers, body.as_deref())?,
        };
        if accept.contains(&resp.status) {
            return Ok(resp);
        }
        // A DBBridge refusal carries a stable code; anything else is the path
        // answering instead of the peer.
        if let Some(body) = ErrorBody::parse(&String::from_utf8_lossy(&resp.body)) {
            let trusted = !self.expected_instance.is_empty()
                && body.code.starts_with("DBB_")
                && resp.header(wire::H_INSTANCE_ID) == Some(self.expected_instance.as_str());
            return Err(body
                .to_error()
                .remote_status(resp.status)
                .trusted(trusted)
                .retry_after(parse_retry_after(resp.header("Retry-After"))));
        }
        Err(Error::local(format!(
            "{method} {path}: unexpected status {}",
            resp.status
        )))
    }

    pub fn probe(&self, expected_node_id: &str) -> Result<ProbeResponse> {
        self.probe_within(expected_node_id, None)
    }

    pub fn probe_within(
        &self,
        expected_node_id: &str,
        timeout: Option<std::time::Duration>,
    ) -> Result<ProbeResponse> {
        let nonce = crate::util::random_hex(16).map_err(crate::util::random_error)?;
        let req = ProbeRequest {
            expected_node_id: expected_node_id.to_string(),
            nonce: nonce.clone(),
        };
        let mut headers = self.base_headers()?;
        headers.push(("Content-Type".to_string(), "application/json".to_string()));
        let resp = self.send_within(
            "POST",
            wire::PATH_PROBE,
            &headers,
            Some(req.to_json().to_string().into_bytes()),
            &[200],
            timeout,
        )?;
        let text = String::from_utf8_lossy(&resp.body);
        let v = crate::util::json::parse(&text)
            .map_err(|e| Error::new(wire::ERR_PROTOCOL_MISMATCH, format!("probe response: {e}")))?;
        let out = ProbeResponse::from_json(&v)?;
        let _recovery_available = out.recovery_available;
        if out.protocol_version != wire::PROTOCOL_VERSION
            || out.node_id != expected_node_id
            || out.instance_id.is_empty()
            || out.nonce != nonce
            || out.transports.is_empty()
        {
            return Err(Error::new(
                wire::ERR_PROTOCOL_MISMATCH,
                "probe response identity or capability mismatch",
            ));
        }
        Ok(out)
    }

    pub fn create(&self, req: &CreateRequest) -> Result<CreateResponse> {
        let mut headers = self.base_headers()?;
        headers.push(("Content-Type".to_string(), "application/json".to_string()));
        let resp = self.send(
            "POST",
            wire::PATH_SESSIONS,
            &headers,
            Some(req.to_json().to_string().into_bytes()),
            &[200, 201],
        )?;
        let text = String::from_utf8_lossy(&resp.body);
        let v = crate::util::json::parse(&text).map_err(|e| {
            Error::new(wire::ERR_PROTOCOL_MISMATCH, format!("create response: {e}"))
        })?;
        let out = CreateResponse::from_json(&v)?;
        // Validate against the request: a peer that answers with something
        // other than what we asked for is not a peer we can trust.
        if out.instance_id != self.expected_instance
            || !wire::valid_session_id(&out.session_id)
            || out.session_token.is_empty()
            || out.epoch != 1
            || out.mode != req.mode
            || out.recovery_enabled != req.recovery_enabled
            || out.limits.max_frame_size == 0
            || out.limits.max_frame_size > req.limits.max_frame_size
            || out.limits.up_window_bytes == 0
            || out.limits.up_window_bytes > req.limits.up_window_bytes
            || out.limits.down_buffer_bytes == 0
            || out.limits.down_buffer_bytes > req.limits.down_buffer_bytes
            || out.limits.up_max_inflight_frames == 0
            || out.limits.up_max_inflight_frames > req.limits.up_max_inflight_frames
            || out.limits.up_receipt_limit <= out.limits.up_max_inflight_frames
            || out.limits.down_max_frames == 0
            || out.limits.max_frame_size as u64 > out.limits.up_window_bytes
            || out.limits.max_frame_size as u64 > out.limits.down_buffer_bytes
            || out.unattached_timeout_ms == 0
            || (!req.ingress_instance_id.is_empty() && out.node_id.is_empty())
        {
            return Err(Error::new(
                wire::ERR_PROTOCOL_MISMATCH,
                "create response binding mismatch",
            ));
        }
        Ok(out)
    }

    pub fn resume(
        &self,
        sid: &str,
        token: &str,
        req: &crate::session::recovery::ResumeRequest,
    ) -> Result<crate::session::recovery::ResumeResponse> {
        let mut headers = self.base_headers()?;
        headers.push(("Content-Type".to_string(), "application/json".to_string()));
        headers.push((wire::H_SESSION_TOKEN.to_string(), token.to_string()));
        let body = wire::ResumeRequestWire { inner: req.clone() };
        let path = format!(
            "{}/{}{}",
            wire::PATH_SESSIONS,
            escape_path_segment(sid),
            "/resume"
        );
        let resp = self.send(
            "POST",
            &path,
            &headers,
            Some(body.to_json().to_string().into_bytes()),
            &[200],
        )?;
        let text = String::from_utf8_lossy(&resp.body);
        let v = crate::util::json::parse(&text).map_err(|e| {
            Error::new(wire::ERR_PROTOCOL_MISMATCH, format!("resume response: {e}"))
        })?;
        let out = crate::session::recovery::ResumeResponse::from_json(&v).map_err(|e| {
            Error::new(
                wire::ERR_PROTOCOL_MISMATCH,
                format!("resume response: {}", e.message),
            )
        })?;
        if !wire::validate_resume_response(req, &out, sid, &self.expected_instance) {
            return Err(Error::new(
                wire::ERR_PROTOCOL_MISMATCH,
                "resume response binding or state mismatch",
            ));
        }
        Ok(out)
    }

    fn session_path(&self, sid: &str, suffix: &str, epoch: u64) -> String {
        format!(
            "{}/{}{}?epoch={}",
            wire::PATH_SESSIONS,
            escape_path_segment(sid),
            suffix,
            epoch
        )
    }

    pub fn ack(
        &self,
        sid: &str,
        token: &str,
        epoch: u64,
        stream: &str,
        req: &AckRequest,
    ) -> Result<AckResponse> {
        let mut headers = self.base_headers()?;
        headers.push(("Content-Type".to_string(), "application/json".to_string()));
        headers.push((wire::H_SESSION_TOKEN.to_string(), token.to_string()));
        headers.push((wire::H_STREAM_ID.to_string(), stream.to_string()));
        let resp = self.send(
            "POST",
            &self.session_path(sid, "/ack", epoch),
            &headers,
            Some(req.to_json().to_string().into_bytes()),
            &[200],
        )?;
        let text = String::from_utf8_lossy(&resp.body);
        let v = crate::util::json::parse(&text)
            .map_err(|e| Error::new(wire::ERR_PROTOCOL_MISMATCH, format!("ack response: {e}")))?;
        let out = AckResponse::from_json(&v)?;
        if out.session_id != sid
            || out.instance_id != self.expected_instance
            || out.epoch != epoch
            || out.stream_id != stream
            || out.probe_id != req.probe_id
        {
            return Err(Error::new(
                wire::ERR_PROTOCOL_MISMATCH,
                "ack response binding mismatch",
            ));
        }
        Ok(out)
    }

    pub fn fin(
        &self,
        sid: &str,
        token: &str,
        epoch: u64,
        stream: &str,
        final_offset: u64,
    ) -> Result<FinResponse> {
        let mut headers = self.base_headers()?;
        headers.push(("Content-Type".to_string(), "application/json".to_string()));
        headers.push((wire::H_SESSION_TOKEN.to_string(), token.to_string()));
        headers.push((wire::H_STREAM_ID.to_string(), stream.to_string()));
        let body = crate::util::json::obj(vec![
            ("direction", Json::from("up")),
            ("final_offset", Json::from(final_offset.to_string())),
        ]);
        let resp = self.send(
            "POST",
            &self.session_path(sid, "/fin", epoch),
            &headers,
            Some(body.to_string().into_bytes()),
            &[200],
        )?;
        let text = String::from_utf8_lossy(&resp.body);
        let v = crate::util::json::parse(&text)
            .map_err(|e| Error::new(wire::ERR_PROTOCOL_MISMATCH, format!("fin response: {e}")))?;
        let out = FinResponse::from_json(&v)?;
        if out.session_id != sid || out.instance_id != self.expected_instance || out.epoch != epoch
        {
            return Err(Error::new(
                wire::ERR_PROTOCOL_MISMATCH,
                "fin response binding mismatch",
            ));
        }
        Ok(out)
    }

    pub fn delete(&self, sid: &str, token: &str, epoch: u64) -> Result<()> {
        let mut headers = self.base_headers()?;
        headers.push((wire::H_SESSION_TOKEN.to_string(), token.to_string()));
        let resp = self.send(
            "DELETE",
            &self.session_path(sid, "", epoch),
            &headers,
            None,
            &[200],
        )?;
        let text = String::from_utf8_lossy(&resp.body);
        if let Ok(v) = crate::util::json::parse(&text) {
            let response_epoch = v.get("epoch").and_then(Json::as_str);
            if v.get("closed").and_then(Json::as_bool) == Some(true)
                && v.get("session_id").and_then(Json::as_str) == Some(sid)
                && v.get("instance_id").and_then(Json::as_str)
                    == Some(self.expected_instance.as_str())
                && response_epoch == Some(epoch.to_string().as_str())
            {
                return Ok(());
            }
        }
        Err(Error::new(
            wire::ERR_PROTOCOL_MISMATCH,
            "delete response binding mismatch",
        ))
    }
}

fn escape_path_segment(segment: &str) -> String {
    let mut escaped = String::with_capacity(segment.len());
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'_'
                    | b'.'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b':'
                    | b'='
                    | b'@'
            )
        {
            escaped.push(byte as char);
        } else {
            escaped.push('%');
            escaped.push(HEX[(byte >> 4) as usize] as char);
            escaped.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    escaped
}

fn parse_retry_after(value: Option<&str>) -> Duration {
    parse_retry_after_at(value.unwrap_or_default(), std::time::SystemTime::now())
}

fn parse_retry_after_at(value: &str, now: std::time::SystemTime) -> Duration {
    let value = value.trim();
    if let Ok(seconds) = value.parse::<u64>() {
        return Duration::from_secs(seconds.min(2));
    }
    let Some(target) = parse_http_date(value) else {
        return Duration::ZERO;
    };
    let now = now
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i128)
        .unwrap_or(0);
    if target <= now {
        Duration::ZERO
    } else {
        Duration::from_secs((target - now).min(2) as u64)
    }
}

/// Parses the IMF-fixdate form used by HTTP Retry-After (for example,
/// `Thu, 01 Jan 2026 00:00:01 GMT`) into Unix seconds.
fn parse_http_date(value: &str) -> Option<i128> {
    let fields: Vec<_> = value.split_whitespace().collect();
    if fields.len() != 6 || !fields[0].ends_with(',') || fields[5] != "GMT" {
        return None;
    }
    let day = fields[1].parse::<i64>().ok()?;
    let month = match fields[2] {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    let year = fields[3].parse::<i64>().ok()?;
    let mut time = fields[4].split(':');
    let hour = time.next()?.parse::<i64>().ok()?;
    let minute = time.next()?.parse::<i64>().ok()?;
    let second = time.next()?.parse::<i64>().ok()?;
    if time.next().is_some() || !(0..24).contains(&hour) || !(0..60).contains(&minute) {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if day < 1 || day > days_in_month || !(0..60).contains(&second) {
        return None;
    }

    // Gregorian civil date to days since 1970-01-01.
    let adjusted_year = year - i64::from(month <= 2);
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year - era * 400;
    let shifted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days_since_epoch = era * 146_097 + day_of_era - 719_468;
    Some(
        days_since_epoch as i128 * 86_400
            + hour as i128 * 3_600
            + minute as i128 * 60
            + second as i128,
    )
}

/// POSTs one upstream frame for the SSE carrier.
///
/// Two credentials travel here and they are not interchangeable: the peer
/// token identifies *who* is calling and the session token identifies *which*
/// session it is calling about. Sending the session token as the bearer is
/// what an egress answers with `DBB_UNAUTHORIZED`.
#[allow(clippy::too_many_arguments)]
pub fn post_up(
    client: &Client,
    url: &Url,
    sid: &str,
    peer_token: &str,
    session_token: &str,
    instance: &str,
    epoch: u64,
    stream: &str,
    offset: u64,
    payload: &[u8],
    down_ack: u64,
    up_confirm: u64,
) -> Result<(u16, Vec<u8>)> {
    let path = format!(
        "{}/{}/up?epoch={}",
        wire::PATH_SESSIONS,
        escape_path_segment(sid),
        epoch
    );
    let mut headers = vec![
        (
            wire::H_PEER_AUTH.to_string(),
            format!("Bearer {peer_token}"),
        ),
        (wire::H_SESSION_TOKEN.to_string(), session_token.to_string()),
        (wire::H_STREAM_ID.to_string(), stream.to_string()),
        (wire::H_OFFSET.to_string(), offset.to_string()),
        (wire::H_LENGTH.to_string(), payload.len().to_string()),
        (
            wire::H_SHA256.to_string(),
            crate::util::hex(&crate::util::sha256::digest(payload)),
        ),
        (
            "Content-Type".to_string(),
            "application/octet-stream".to_string(),
        ),
        (wire::H_ACK_DOWN_OFFSET.to_string(), down_ack.to_string()),
        (
            wire::H_CONFIRM_UP_OFFSET.to_string(),
            up_confirm.to_string(),
        ),
    ];
    if !instance.is_empty() {
        headers.push((wire::H_INSTANCE_ID.to_string(), instance.to_string()));
    }
    let resp = client.request(url, "POST", &path, &headers, Some(payload))?;
    Ok((resp.status, resp.body))
}

/// Parses the `up` response of the SSE carrier: how much upstream the egress
/// has applied.
pub fn parse_up_response(body: &[u8]) -> Result<u64> {
    let text = String::from_utf8_lossy(body);
    let v = crate::util::json::parse(&text)
        .map_err(|e| Error::new(wire::ERR_PROTOCOL_MISMATCH, format!("up response: {e}")))?;
    v.offset("ack_up_offset")
        .map_err(|e| Error::new(wire::ERR_PROTOCOL_MISMATCH, e))
}

pub fn check_up_binding(
    body: &[u8],
    sid: &str,
    instance: &str,
    epoch: u64,
    stream: &str,
) -> Result<()> {
    let text = String::from_utf8_lossy(body);
    let v = crate::util::json::parse(&text)
        .map_err(|e| Error::new(wire::ERR_PROTOCOL_MISMATCH, format!("up response: {e}")))?;
    let field = |name: &str| v.get(name).and_then(Json::as_str);
    let epoch_text = epoch.to_string();
    if field("session_id").is_some_and(|s| s != sid)
        || (!instance.is_empty() && field("instance_id").is_some_and(|s| s != instance))
        || field("epoch").is_some_and(|s| s != epoch_text)
        || field("stream_id").is_some_and(|s| s != stream)
    {
        return Err(Error::new(
            wire::ERR_PROTOCOL_MISMATCH,
            "up response binding mismatch",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor, Read, Write};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use crate::config::ClientTls;
    use crate::net::http1::{Client, Dialer};
    use crate::net::{Conn, Url};
    use crate::session::recovery::{ResumeFin, ResumeRequest};
    use crate::wire::{CreateRequest, Limits, Mode};

    use super::ControlClient;

    struct CapturedConn {
        response: Cursor<Vec<u8>>,
        request: Arc<Mutex<Vec<u8>>>,
    }

    impl Read for CapturedConn {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.response.read(buf)
        }
    }

    impl Write for CapturedConn {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.request.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Conn for CapturedConn {
        fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
            Ok(())
        }

        fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
            Ok(())
        }

        fn try_clone(&self) -> io::Result<Box<dyn Conn>> {
            Err(io::Error::other("test connection is not cloneable"))
        }

        fn shutdown_write(&self) -> io::Result<()> {
            Ok(())
        }

        fn shutdown_both(&self) -> io::Result<()> {
            Ok(())
        }

        fn describe(&self) -> String {
            "captured test connection".to_string()
        }
    }

    struct StaticDialer {
        response: Vec<u8>,
        request: Arc<Mutex<Vec<u8>>>,
    }

    impl Dialer for StaticDialer {
        fn dial(&self, _: &Url, _: Duration) -> crate::error::Result<Box<dyn Conn>> {
            Ok(Box::new(CapturedConn {
                response: Cursor::new(self.response.clone()),
                request: self.request.clone(),
            }))
        }
    }

    fn client_with_response(status: u16, body: &str) -> (ControlClient, Arc<Mutex<Vec<u8>>>) {
        let response = format!(
            "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let request = Arc::new(Mutex::new(Vec::new()));
        let client = Client::new(Duration::from_secs(1), Duration::from_secs(1));
        client.set_dialer(Arc::new(StaticDialer {
            response: response.into_bytes(),
            request: request.clone(),
        }));
        let api = ControlClient::new(
            Arc::new(client),
            Url::parse("http://peer.test").unwrap(),
            "peer-token".to_string(),
            "bi".to_string(),
            ClientTls::default(),
        );
        (api, request)
    }

    fn request_text(request: &Arc<Mutex<Vec<u8>>>) -> String {
        String::from_utf8(request.lock().unwrap().clone()).unwrap()
    }

    fn resume_request(expected_epoch: u64) -> ResumeRequest {
        ResumeRequest {
            resume_request_id: "request".to_string(),
            expected_epoch,
            ingress_instance_id: "ing".to_string(),
            transport: Mode::Ws,
            known_up_ack_offset: 0,
            up_next_offset: 0,
            down_delivered_offset: 0,
            up_fin: ResumeFin::default(),
            down_fin: ResumeFin::default(),
        }
    }

    #[test]
    fn spec_test_delete_rejects_unbound_gateway_success_page() {
        let (client, _) = client_with_response(200, "<html>gateway default success page</html>");
        let error = client
            .delete("original-session", "session-token", 7)
            .expect_err("an HTML gateway response cannot confirm session deletion");
        assert_eq!(error.code, crate::wire::ERR_PROTOCOL_MISMATCH);
    }

    #[test]
    fn spec_test_delete_response_requires_original_binding() {
        let cases = [
            (
                "valid",
                r#"{"session_id":"sid","instance_id":"bi","epoch":"7","closed":true}"#,
                true,
            ),
            (
                "session",
                r#"{"session_id":"another-session","instance_id":"bi","epoch":"7","closed":true}"#,
                false,
            ),
            (
                "instance",
                r#"{"session_id":"sid","instance_id":"other","epoch":"7","closed":true}"#,
                false,
            ),
            (
                "epoch",
                r#"{"session_id":"sid","instance_id":"bi","epoch":"6","closed":true}"#,
                false,
            ),
            (
                "not closed",
                r#"{"session_id":"sid","instance_id":"bi","epoch":"7","closed":false}"#,
                false,
            ),
            ("legacy", r#"{"closed":true}"#, false),
            ("no content", "", false),
        ];

        for (name, body, want_success) in cases {
            let status = if name == "no content" { 204 } else { 200 };
            let (client, _) = client_with_response(status, body);
            let result = client.delete("sid", "secret", 7);
            assert_eq!(result.is_ok(), want_success, "{name}: {result:?}");
        }
    }

    #[test]
    fn spec_test_session_id_is_escaped_as_one_path_segment() {
        let (client, request) = client_with_response(500, "");
        let _ = client.resume("../peer/probe?x=", "st", &resume_request(1));
        assert!(
            request_text(&request)
                .starts_with("POST /v1/sessions/..%2Fpeer%2Fprobe%3Fx=/resume HTTP/1.1\r\n"),
            "resume session id escaped incorrectly: {}",
            request_text(&request).lines().next().unwrap_or_default()
        );

        let (client, request) = client_with_response(500, "");
        let _ = client.delete("a/b", "st", 3);
        assert!(
            request_text(&request).starts_with("DELETE /v1/sessions/a%2Fb?epoch=3 HTTP/1.1\r\n")
        );

        let too_long = "a".repeat(129);
        for sid in ["", ".", "..", "a/b", "a?b", "a b", too_long.as_str()] {
            assert!(
                !crate::wire::valid_session_id(sid),
                "accepted invalid id {sid:?}"
            );
        }
        assert!(crate::wire::valid_session_id("0123abcdef-_.~XYZ"));
    }

    #[test]
    fn spec_test_resume_response_accepts_documented_up_fin_received_field() {
        let response = r#"{"session_id":"sid","instance_id":"bi","resume_request_id":"request","epoch":"2","transport":{"mode":"ws"},"up_written_offset":"0","ack_up_offset":"0","down_replay_from":"0","down_produced_offset":"0","down_retained_from":"0","up_fin":{"received":false,"final_offset":null,"applied":false},"down_fin":{"seen":false,"final_offset":null,"acked":false},"resume_remaining_ms":1000}"#;
        let (client, _) = client_with_response(200, response);
        let result = client.resume("sid", "session-token", &resume_request(1));
        assert!(
            result.is_ok(),
            "documented response schema rejected: {result:?}"
        );
    }

    #[test]
    fn spec_test_resume_epoch_wrap_is_rejected() {
        let response = r#"{"session_id":"sid","instance_id":"bi","resume_request_id":"request","epoch":"0","transport":{"mode":"ws"},"up_written_offset":"0","ack_up_offset":"0","down_replay_from":"0","down_produced_offset":"0","down_retained_from":"0","up_fin":{"received":false,"final_offset":null,"applied":false},"down_fin":{"seen":false,"final_offset":null,"applied":false,"acked":false},"resume_remaining_ms":1000}"#;
        let (client, _) = client_with_response(200, response);
        let result = client.resume("sid", "session-token", &resume_request(u64::MAX));
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("wrapped epoch must not be treated as the next epoch"),
        };
        assert_eq!(error.code, crate::wire::ERR_PROTOCOL_MISMATCH);
    }

    #[test]
    fn spec_test_retry_after_clamps_delta_seconds_and_http_dates() {
        use std::time::UNIX_EPOCH;

        let now = UNIX_EPOCH + Duration::from_secs(1_767_225_600);
        let cases = [
            ("", Duration::ZERO),
            ("0", Duration::ZERO),
            ("-1", Duration::ZERO),
            ("1", Duration::from_secs(1)),
            ("2", Duration::from_secs(2)),
            ("5", Duration::from_secs(2)),
            ("999999999999", Duration::from_secs(2)),
            ("x", Duration::ZERO),
            ("Thu, 01 Jan 2026 00:00:01 GMT", Duration::from_secs(1)),
            ("Thu, 01 Jan 2026 01:00:00 GMT", Duration::from_secs(2)),
            ("Wed, 31 Dec 2025 23:00:00 GMT", Duration::ZERO),
        ];
        for (value, expected) in cases {
            assert_eq!(
                super::parse_retry_after_at(value, now),
                expected,
                "Retry-After {value:?}"
            );
        }
    }

    fn create_response(receipt: &str, frames: &str) -> String {
        format!(
            r#"{{"protocol_version":"{}","node_id":"B","instance_id":"bi","session_id":"0123456789abcdef0123456789abcdef","session_token":"t","epoch":"1","transport":{{"mode":"ws"}},"recovery":{{"enabled":false,"grace_ms":0}},"limits":{{"max_frame_size":1024,"up_max_inflight_frames":8,"up_window_bytes":2048,"down_buffer_bytes":4096,"up_receipt_limit":{},"down_max_frames":{}}},"unattached_timeout_ms":1000}}"#,
            crate::wire::PROTOCOL_VERSION,
            receipt,
            frames
        )
    }

    fn create_request() -> CreateRequest {
        CreateRequest {
            target_id: "db".to_string(),
            create_request_id: "cr".to_string(),
            ingress_instance_id: "ing".to_string(),
            mode: Mode::Ws,
            recovery_enabled: false,
            recovery_grace_ms: 0,
            limits: Limits {
                max_frame_size: 1024,
                up_max_inflight_frames: 8,
                up_window_bytes: 2048,
                down_buffer_bytes: 4096,
                up_receipt_limit: 0,
                down_max_frames: 0,
            },
        }
    }

    #[test]
    fn spec_test_create_session_flow_limits_are_validated_and_clamped() {
        let cases = [
            ("missing receipt", "0", "0", false, 0),
            ("missing frames", "64", "0", false, 0),
            ("advertised", "64", "512", true, 64),
            ("receipt not above inflight", "8", "512", false, 0),
            ("negative receipt", "-1", "512", false, 0),
            ("negative frames", "64", "-1", false, 0),
            ("huge receipt clamped", "1048577", "512", true, 1 << 20),
            ("huge frames clamped", "64", "4194304", true, 64),
        ];

        for (name, receipt, frames, succeeds, expected_receipt) in cases {
            let (client, _) = client_with_response(201, &create_response(receipt, frames));
            let result = client.create(&create_request());
            assert_eq!(result.is_ok(), succeeds, "{name}: {result:?}");
            if let Ok(response) = result {
                assert_eq!(response.limits.up_receipt_limit, expected_receipt, "{name}");
                assert!(response.limits.down_max_frames <= 1 << 20, "{name}");
            }
        }
    }
}
