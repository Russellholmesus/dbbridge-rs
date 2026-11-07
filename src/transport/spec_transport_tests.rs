use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::config::ClientTls;
use crate::net::http1::Client;
use crate::net::Url;

use super::control::ControlClient;

/// A server that records every request's User-Agent and answers 503.
fn ua_server() -> (std::net::SocketAddr, Arc<Mutex<Vec<String>>>) {
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = ln.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s = seen.clone();
    std::thread::spawn(move || {
        for c in ln.incoming() {
            let Ok(mut c) = c else { return };
            let s = s.clone();
            std::thread::spawn(move || {
                let _ = c.set_read_timeout(Some(Duration::from_secs(2)));
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match c.read(&mut b) {
                        Ok(1) => head.push(b[0]),
                        _ => return,
                    }
                }
                let text = String::from_utf8_lossy(&head).to_string();
                let ua = text
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.trim()
                            .eq_ignore_ascii_case("user-agent")
                            .then(|| v.trim().to_string())
                    })
                    .unwrap_or_default();
                s.lock().unwrap().push(ua);
                let _ = c.write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            });
        }
    });
    (addr, seen)
}

#[test]
fn spec_user_agent_on_requests_and_handshakes() {
    for (configured, want) in [
        ("", crate::config::DEFAULT_USER_AGENT),
        (
            "Mozilla/5.0 (X11; Linux x86_64)",
            "Mozilla/5.0 (X11; Linux x86_64)",
        ),
    ] {
        let (addr, seen) = ua_server();
        crate::set_user_agent(configured);
        let url = Url::parse(&format!("http://{addr}")).unwrap();
        let client = Arc::new(Client::new(Duration::from_secs(1), Duration::from_secs(1)));
        let control = ControlClient::new(
            client.clone(),
            url.clone(),
            "tok".into(),
            String::new(),
            ClientTls::default(),
        );
        let _ = control.probe("B");
        let dialer = client.dialer();
        let _ = super::ws_carrier::precheck_via(&*dialer, &url, &[], Duration::from_secs(1));
        crate::set_user_agent("");
        let seen = seen.lock().unwrap().clone();
        assert!(
            seen.len() >= 2,
            "{configured:?}: server saw {} requests, want a probe and a WS precheck",
            seen.len()
        );
        for (i, ua) in seen.iter().enumerate() {
            assert_eq!(ua, want, "{configured:?}: request {i} User-Agent");
        }
    }
    assert_eq!(
        crate::config::DEFAULT_USER_AGENT,
        format!("DBBridge/{}", crate::wire::PROTOCOL_VERSION),
        "default User-Agent"
    );
}

/// A keep-alive HTTP/1.1 server: `respond` maps each request head to a
/// whole raw response (after an optional delay). Returns its address and the
/// heads it saw.
fn scripted_server(
    respond: impl Fn(&str) -> (Duration, String) + Send + Sync + 'static,
) -> (std::net::SocketAddr, Arc<Mutex<Vec<String>>>) {
    let ln = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = ln.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let s = seen.clone();
    let respond = Arc::new(respond);
    std::thread::spawn(move || {
        for c in ln.incoming() {
            let Ok(mut c) = c else { return };
            let (s, respond) = (s.clone(), respond.clone());
            std::thread::spawn(move || loop {
                let _ = c.set_read_timeout(Some(Duration::from_secs(5)));
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match c.read(&mut b) {
                        Ok(1) => head.push(b[0]),
                        _ => return,
                    }
                }
                let text = String::from_utf8_lossy(&head).to_string();
                let len: usize = text
                    .lines()
                    .find_map(|l| {
                        let (k, v) = l.split_once(':')?;
                        k.trim()
                            .eq_ignore_ascii_case("content-length")
                            .then(|| v.trim().parse().ok())?
                    })
                    .unwrap_or(0);
                let mut body = vec![0u8; len];
                if c.read_exact(&mut body).is_err() {
                    return;
                }
                s.lock().unwrap().push(text.clone());
                let (delay, resp) = respond(&text);
                std::thread::sleep(delay);
                if c.write_all(resp.as_bytes()).is_err() {
                    return;
                }
            });
        }
    });
    (addr, seen)
}

fn control(client: Arc<Client>, addr: std::net::SocketAddr) -> ControlClient {
    ControlClient::new(
        client,
        Url::parse(&format!("http://{addr}")).unwrap(),
        "tok".into(),
        String::new(),
        ClientTls::default(),
    )
}

const EMPTY_500: &str = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";

#[test]
fn spec_reject_redirect() {
    let (dst, dst_seen) = scripted_server(|_| (Duration::ZERO, EMPTY_500.to_string()));
    let location = format!("http://{dst}/v1/probe");
    let (src, _) = scripted_server(move |_| {
        (
            Duration::ZERO,
            format!(
                "HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\n\r\n"
            ),
        )
    });
    let client = Arc::new(Client::new(Duration::from_secs(1), Duration::from_secs(2)));
    let r = control(client, src).probe("p");
    std::thread::sleep(Duration::from_millis(50));
    let leaked = !dst_seen.lock().unwrap().is_empty();
    assert!(
        r.is_err() && !leaked,
        "followed 307 redirect to another origin; forwarded Authorization={leaked}"
    );
}

#[test]
fn spec_control_pool_not_capped_at_32() {
    use std::sync::atomic::{AtomicI64, Ordering};
    let cur = Arc::new(AtomicI64::new(0));
    let peak = Arc::new(AtomicI64::new(0));
    let (c2, p2) = (cur.clone(), peak.clone());
    let (addr, _) = scripted_server(move |_| {
        let n = c2.fetch_add(1, Ordering::SeqCst) + 1;
        p2.fetch_max(n, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(150));
        c2.fetch_sub(1, Ordering::SeqCst);
        (Duration::ZERO, EMPTY_500.to_string())
    });
    let client = Arc::new(Client::new(Duration::from_secs(2), Duration::from_secs(5)));
    let threads: Vec<_> = (0..60)
        .map(|_| {
            let c = control(client.clone(), addr);
            std::thread::spawn(move || {
                let _ = c.probe("B");
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    let peak = peak.load(Ordering::SeqCst);
    assert!(peak > 32, "peak concurrency {peak}, still capped at 32");
}

#[test]
fn spec_endpoint_pools() {
    let (one, one_seen) = scripted_server(|_| (Duration::ZERO, EMPTY_500.to_string()));
    let (two, two_seen) = scripted_server(|_| (Duration::ZERO, EMPTY_500.to_string()));
    let client = Arc::new(Client::new(Duration::from_secs(1), Duration::from_secs(2)));
    let _ = control(client.clone(), one).probe("p");
    let _ = control(client.clone(), two).probe("p");
    let _ = control(client.clone(), two).probe("p");
    assert_eq!(
        one_seen.lock().unwrap().len(),
        1,
        "endpoint one got another endpoint's request"
    );
    assert_eq!(
        two_seen.lock().unwrap().len(),
        2,
        "endpoint two requests went elsewhere"
    );
}
