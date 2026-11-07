use super::{ConnectionBudget, ProbeBudget, Registry, Server};
use crate::net::http1::Request;
use crate::wire;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(super) struct Fixture {
    pub(super) server: Arc<Server>,
    dir: std::path::PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.registry.close_all();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// One egress node `peer-b` with target `db` and inbound peer `peer-a`
/// (token "abc"); `extra` is appended to the YAML.
pub(super) fn fixture(target_addr: &str, max_sessions: u32, extra: &str) -> Fixture {
    let dir = std::env::temp_dir().join(format!(
        "dbb-egress-spec-{}",
        crate::util::random_hex(6).unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("peer-token"), "abc").unwrap();
    let path = dir.join("config.yaml");
    let text = format!(
        "node:\n  id: peer-b\nhttp:\n  enabled: true\n  listen: \"127.0.0.1:0\"\ntargets:\n  db:\n    network: tcp\n    address: \"{target_addr}\"\nauth:\n  inbound_peers:\n    - id: peer-a\n      token_files: [peer-token]\n      allowed_targets: [db]\n      max_sessions: {max_sessions}\nlimits:\n  max_sessions: {max_sessions}\ntransport:\n  unattached_timeout: 5s\n{extra}"
    );
    std::fs::write(&path, text).unwrap();
    let cfg = Arc::new(crate::config::load(&path).unwrap());
    let metrics = Arc::new(crate::metrics::Metrics::new());
    let registry = Arc::new(Registry::new(metrics.clone()));
    let client = Arc::new(crate::net::http1::Client::new(
        cfg.transport.dial_timeout,
        cfg.transport.control_request_timeout,
    ));
    let server = Arc::new(Server {
        cfg: cfg.clone(),
        auth: Arc::new(crate::auth::Authenticator::new(cfg.clone())),
        registry,
        client,
        started: Instant::now(),
        hub: None,
        tunnels: None,
        metrics,
        connection_budget: Arc::new(ConnectionBudget::new(max_sessions)),
        authz_lock: Arc::new(std::sync::Mutex::new(())),
        probe_budget: Arc::new(ProbeBudget::new()),
        accept_addr: Arc::new(std::sync::Mutex::new(None)),
    });
    Fixture { server, dir }
}

pub(super) fn post(path: &str, token: &str, body: &str) -> Request {
    Request {
        method: "POST".to_string(),
        path: path.to_string(),
        query: Vec::new(),
        version: "HTTP/1.1".to_string(),
        headers: vec![(wire::H_PEER_AUTH.to_string(), format!("Bearer {token}"))],
        body: body.as_bytes().to_vec(),
    }
}

/// Serves exactly one connection with `request` written by the client and
/// returns everything the server wrote before closing.
pub(super) fn raw_exchange(server: Arc<Server>, request: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server_stream, _) = listener.accept().unwrap();
    let handler = std::thread::spawn(move || {
        let _ = server.handle_conn(
            Box::new(server_stream),
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
            None,
        );
    });
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    client.write_all(request.as_bytes()).unwrap();
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .expect("connection still open after the response");
    handler.join().expect("egress request handler thread");
    String::from_utf8(response).unwrap()
}

#[test]
fn spec_boundary_exact_schema() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let f = fixture(&target.local_addr().unwrap().to_string(), 4, "");
    for body in [
        r#"{"protocol_version":"bad","PROTOCOL_VERSION":"1.5","expected_node_id":"peer-b","nonce":"n"}"#,
        r#"{"protocol_version":"1.5","expected_node_id":"peer-b","nonce":"n","Nonce":"overridden"}"#,
    ] {
        let (status, resp, _) = f.server.route(&post(wire::PATH_PROBE, "abc", body));
        assert_ne!(
            status, 200,
            "non-schema alias silently overwrote canonical field: {body}"
        );
        let e = wire::ErrorBody::parse(std::str::from_utf8(&resp).unwrap()).unwrap();
        assert_eq!(e.code, wire::ERR_BAD_FRAME, "{body}");
    }
    let (status, _, _) = f.server.route(&post(
        wire::PATH_PROBE,
        "abc",
        r#"{"protocol_version":"1.5","expected_node_id":"peer-b","nonce":"n"}"#,
    ));
    assert_eq!(status, 200, "canonical probe refused");
    let ack = crate::util::json::parse(
        r#"{"down_delivered_offset":"0","up_confirmed_offset":"0","down_fin_applied":null}"#,
    )
    .unwrap();
    assert!(
        wire::AckRequest::from_json(&ack).is_err(),
        "null accepted as a boolean"
    );
}

#[test]
fn spec_unauthorized_closes_keep_alive_unknown_paths() {
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let f = fixture(&target.local_addr().unwrap().to_string(), 4, "");
    for path in ["/nope", "/v1/sessions"] {
        let response = raw_exchange(
            f.server.clone(),
            &format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n"),
        );
        let head = response.split("\r\n\r\n").next().unwrap();
        assert!(
            head.starts_with("HTTP/1.1 404 ") || head.starts_with("HTTP/1.1 405 "),
            "{path}: {head}"
        );
        assert!(
            head.to_ascii_lowercase().contains("\r\nconnection: close"),
            "{path}: close missing: {head}"
        );
    }
}
