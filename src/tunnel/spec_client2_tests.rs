use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::Arc;

use super::{Client, TunnelListener};

fn client_config(url: &str, peer: &str) -> Arc<crate::config::Config> {
    let dir = std::env::temp_dir().join(format!(
        "dbb-goclient2-{}",
        crate::util::random_hex(6).unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("tok"), "reverse-token-0123456789abcdef").unwrap();
    let path = dir.join("config.yaml");
    std::fs::write(
        &path,
        format!("node:\n  id: plant-a\nhttp:\n  enabled: false\nreverse:\n  enabled: true\n  peer_node_id: {peer}\n  token_file: tok\n  transport: ws\n  endpoints:\n    - id: e1\n      url: {url}\ntargets:\n  db:\n    network: tcp\n    address: '127.0.0.1:3306'\nauth:\n  inbound_peers:\n    - id: {peer}\n      token_files: [tok]\n      allowed_targets: [db]\n"),
    )
    .unwrap();
    let cfg = crate::config::load(&path).unwrap_or_else(|e| panic!("{}", e.message));
    std::fs::remove_dir_all(&dir).ok();
    Arc::new(cfg)
}

/// Serves one handshake: reads the request head and answers with `respond`
/// (given the Sec-WebSocket-Key).
fn one_shot(respond: impl FnOnce(&str) -> String + Send + 'static) -> String {
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", ln.local_addr().unwrap());
    std::thread::spawn(move || {
        let Ok((c, _)) = ln.accept() else { return };
        let mut r = BufReader::new(c.try_clone().unwrap());
        let mut key = String::new();
        loop {
            let mut line = String::new();
            if r.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("sec-websocket-key") {
                    key = value.trim().to_string();
                }
            }
        }
        let mut c = c;
        let _ = c.write_all(respond(&key).as_bytes());
        std::thread::sleep(std::time::Duration::from_millis(200));
    });
    url
}

#[test]
fn spec_client_rejects_wrong_public_node() {
    let url = one_shot(|_| {
        let body =
            r#"{"error":{"code":"DBB_NODE_MISMATCH","message":"expected node","retryable":false}}"#;
        format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
    });
    let cfg = client_config(&url, "hq-other");
    let cl = Client::new(cfg.clone(), Arc::new(TunnelListener::new()));
    let e = match cl.dial_ws(&cfg.reverse.endpoints[0]) {
        Ok(_) => panic!("refused handshake accepted"),
        Err(e) => e,
    };
    assert!(e.message.contains("403"), "err = {}", e.message);

    let liar = one_shot(|key| {
        format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: {}\r\n{}: hq-b\r\n{}: pi_x\r\n\r\n",
            crate::net::ws::accept_key(key),
            super::REVERSE_SUBPROTOCOL,
            super::H_NODE_ID,
            crate::wire::H_INSTANCE_ID
        )
    });
    let cfg2 = client_config(&liar, "hq-other");
    let cl2 = Client::new(cfg2.clone(), Arc::new(TunnelListener::new()));
    let e = match cl2.dial_ws(&cfg2.reverse.endpoints[0]) {
        Ok(_) => panic!("lying public node accepted"),
        Err(e) => e,
    };
    assert!(e.message.contains("node mismatch"), "err = {}", e.message);
}
