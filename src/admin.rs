//! Loopback admin endpoint: `/healthz`, `/readyz` and Prometheus `/metrics`.
//!
//! Deliberately minimal and read-only — it exposes counters, never a way to
//! change the running configuration.

use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::metrics::Metrics;
use crate::net::http1;

pub type ReadyCheck = Arc<dyn Fn() -> (bool, String) + Send + Sync>;
/// Shared slot for the ready check, installed after the admin server starts.
pub type ReadyCheckSlot = Arc<std::sync::Mutex<Option<ReadyCheck>>>;

pub fn readiness(ready: bool, check: &ReadyCheckSlot) -> (bool, String) {
    if !ready {
        return (false, String::new());
    }
    let check = check
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    match check {
        Some(check) => check(),
        None => (true, String::new()),
    }
}

pub fn readyz_response(ok: bool, detail: &str) -> (u16, String) {
    let (status, mut body) = if ok {
        (200, "ready\n".to_string())
    } else {
        (503, "not ready\n".to_string())
    };
    if !detail.is_empty() {
        body.push_str(detail);
        body.push('\n');
    }
    (status, body)
}

pub fn reverse_readiness(
    http_enabled: bool,
    peer_node_id: &str,
    client_live: Option<usize>,
    hub_missing: &[String],
) -> (bool, String) {
    let mut ok = true;
    let mut details = Vec::new();
    if client_live == Some(0) {
        details.push(format!("reverse: no tunnel to {peer_node_id}"));
        if !http_enabled {
            ok = false;
        }
    }
    if !hub_missing.is_empty() {
        details.push(format!(
            "reverse peers without a tunnel: {}",
            hub_missing.join(",")
        ));
    }
    (ok, details.join("\n"))
}

pub struct Admin {
    pub cfg: Arc<Config>,
    pub metrics: Arc<Metrics>,
    pub started: Instant,
    pub ready_check: ReadyCheckSlot,
    rendered: std::sync::Mutex<Option<(Instant, String)>>,
}

const METRICS_TTL: std::time::Duration = std::time::Duration::from_secs(1);

fn try_acquire_connection(active: &AtomicUsize) -> bool {
    crate::util::increment_below(active, 16)
}

struct AdminConnectionPermit(Arc<AtomicUsize>);

impl Drop for AdminConnectionPermit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

fn wants_keep_alive(req: &http1::Request) -> bool {
    match crate::net::header(&req.headers, "connection") {
        Some(value) if value.eq_ignore_ascii_case("close") => false,
        Some(value) if req.version == "HTTP/1.0" => value.eq_ignore_ascii_case("keep-alive"),
        Some(_) => true,
        None => req.version != "HTTP/1.0",
    }
}

impl Admin {
    pub fn start_with_check(
        cfg: Arc<Config>,
        metrics: Arc<Metrics>,
        started: Instant,
        shutdown: Arc<AtomicBool>,
        ready: Arc<AtomicBool>,
        ready_check: ReadyCheckSlot,
    ) -> Result<(std::thread::JoinHandle<()>, SocketAddr)> {
        let (host, port) = crate::config::parse_hostport(&cfg.admin.listen)
            .map_err(|e| Error::new(crate::config::CODE_LISTEN, e))?;
        let bind = if host.is_empty() {
            format!("127.0.0.1:{port}")
        } else {
            cfg.admin.listen.clone()
        };
        let listener = TcpListener::bind(&bind).map_err(|e| {
            Error::new(
                crate::config::CODE_LISTEN,
                format!("admin.listen {bind}: {e}"),
            )
        })?;
        let addr = listener
            .local_addr()
            .map_err(|e| Error::local(format!("admin listener local_addr: {e}")))?;
        let me = Arc::new(Admin {
            cfg,
            metrics,
            started,
            ready_check,
            rendered: std::sync::Mutex::new(None),
        });
        let active = Arc::new(AtomicUsize::new(0));
        let handle = std::thread::spawn(move || loop {
            if shutdown.load(Ordering::Relaxed) {
                return;
            }
            match listener.accept() {
                Ok((stream, _)) => {
                    if shutdown.load(Ordering::Relaxed) {
                        drop(stream);
                        return;
                    }
                    let _ = crate::net::set_nodelay(&stream);
                    if !try_acquire_connection(&active) {
                        drop(stream);
                        continue;
                    }
                    let _ = stream.set_nonblocking(false);
                    let me = me.clone();
                    let ready = ready.clone();
                    let permit = AdminConnectionPermit(active.clone());
                    let _ = crate::util::spawn_connection(move || {
                        let _permit = permit;
                        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            let _ = me.serve(stream, ready.load(Ordering::Relaxed));
                        }));
                    });
                }
                Err(e) => {
                    crate::slog::debug("admin accept failed", &[("err", crate::slog::err(&e))]);
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
            }
        });
        Ok((handle, addr))
    }

    fn cached_metrics(&self, ready: bool) -> String {
        let mut cache = self
            .rendered
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((at, text)) = cache.as_ref() {
            if at.elapsed() < METRICS_TTL {
                return text.clone();
            }
        }
        let text = self.metrics.render(
            &self.cfg,
            self.started,
            readiness(ready, &self.ready_check).0,
        );
        *cache = Some((Instant::now(), text.clone()));
        text
    }

    fn serve(&self, stream: std::net::TcpStream, ready: bool) -> Result<()> {
        let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(10)));
        let mut conn = crate::net::BufferedConn::new(stream);
        let mut first = true;
        loop {
            let timeout = if first {
                std::time::Duration::from_secs(5)
            } else {
                std::time::Duration::from_secs(30)
            };
            let _ = conn.set_read_timeout(Some(timeout));
            let mut req = match http1::read_request_head_with_limit(&mut conn, 8 * 1024) {
                Ok(Some(r)) => r,
                Ok(None) => return Ok(()),
                Err(e) => {
                    if let Some(reject) = http1::reject_of(&e) {
                        http1::write_reject(&mut conn, reject);
                    }
                    return Ok(());
                }
            };
            let _ = conn.set_read_timeout(Some(std::time::Duration::from_secs(10)));
            if http1::read_request_body(&mut conn, &mut req, 8 * 1024).is_err() {
                return Ok(());
            }
            const TEXT: &str = "text/plain; charset=utf-8";
            let mut extra: Vec<(String, String)> = Vec::new();
            let (status, content_type, body) = if req.method == "OPTIONS" && req.path == "*" {
                // net/http globalOptionsHandler
                (200u16, "", String::new())
            } else if let Some(clean) = clean_path(&req.path).filter(|c| *c != req.path) {
                let mut location = clean.clone();
                if let Some(q) = raw_query(&req) {
                    location.push('?');
                    location.push_str(&q);
                }
                let body = if req.method == "GET" {
                    format!(
                        "<a href=\"{}\">Temporary Redirect</a>.\n\n",
                        html_escape(&location)
                    )
                } else {
                    String::new()
                };
                extra.push(("Location".to_string(), location));
                let ct = if req.method == "GET" || req.method == "HEAD" {
                    "text/html; charset=utf-8"
                } else {
                    ""
                };
                (307, ct, body)
            } else {
                match req.path.as_str() {
                    "/healthz" => (200u16, TEXT, "ok\n".to_string()),
                    "/readyz" => {
                        let (ok, detail) = readiness(ready, &self.ready_check);
                        let (status, body) = readyz_response(ok, &detail);
                        (status, TEXT, body)
                    }
                    "/metrics" => (200, "text/plain; version=0.0.4", self.cached_metrics(ready)),
                    _ => {
                        // http.NotFound
                        extra.push(("X-Content-Type-Options".to_string(), "nosniff".to_string()));
                        (404, TEXT, "404 page not found\n".to_string())
                    }
                }
            };
            let mut headers = Vec::new();
            if !content_type.is_empty() {
                headers.push(("Content-Type".to_string(), content_type.to_string()));
            }
            headers.extend(extra);
            let keep_alive = wants_keep_alive(&req);
            let keep_alive = keep_alive
                && !(req.version == "HTTP/1.0" && body.len() > http1::COMPAT_CHUNKING_THRESHOLD);
            http1::write_response_spec_framed(
                &mut conn,
                status,
                &headers,
                body.as_bytes(),
                keep_alive,
            )
            .map_err(|e| Error::local(format!("write: {e}")))?;
            if !keep_alive {
                return Ok(());
            }
            first = false;
        }
    }
}

fn clean_path(p: &str) -> Option<String> {
    if !p.starts_with('/') {
        return None;
    }
    let mut out: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    let mut c = format!("/{}", out.join("/"));
    if p.ends_with('/') && c != "/" {
        c.push('/');
    }
    Some(c)
}

fn raw_query(req: &http1::Request) -> Option<String> {
    if req.query.is_empty() {
        return None;
    }
    Some(
        req.query
            .iter()
            .map(|(k, v)| {
                if v.is_empty() {
                    k.clone()
                } else {
                    format!("{k}={v}")
                }
            })
            .collect::<Vec<_>>()
            .join("&"),
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&#34;")
        .replace('\'', "&#39;")
}

/// Convenience for the CLI: bind a probe listener to check `admin.listen`
/// without starting the server.
pub fn can_bind(addr: &str) -> bool {
    TcpListener::bind(addr).is_ok()
}

#[cfg(test)]
#[path = "admin_spec3_tests.rs"]
mod go3_tests;

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use super::{try_acquire_connection, Admin};

    #[test]
    fn admin_connection_cap_16() {
        let active = AtomicUsize::new(0);
        for _ in 0..16 {
            assert!(try_acquire_connection(&active));
        }
        assert!(!try_acquire_connection(&active));
        active.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        assert!(try_acquire_connection(&active));
    }

    #[test]
    fn blocking_admin_accept_wakes_during_shutdown() {
        let dir = std::env::temp_dir().join(format!(
            "dbbridge-admin-{}",
            crate::util::random_hex(6).unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("inbound-token"), "abc").unwrap();
        let path = dir.join("config.yaml");
        std::fs::write(
            &path,
            "node:\n  id: node-b\nhttp:\n  enabled: false\n  listen: '127.0.0.1:18080'\nadmin:\n  enabled: true\n  listen: '127.0.0.1:0'\ntargets:\n  db:\n    network: tcp\n    address: '127.0.0.1:3306'\nauth:\n  inbound_peers:\n    - id: peer-a\n      token_files: [inbound-token]\n      allowed_targets: [db]\n",
        )
        .unwrap();
        let cfg = Arc::new(crate::config::load(&path).unwrap());
        let shutdown = Arc::new(AtomicBool::new(false));
        let ready = Arc::new(AtomicBool::new(false));
        let (worker, addr) = Admin::start_with_check(
            cfg,
            Arc::new(crate::metrics::Metrics::new()),
            Instant::now(),
            shutdown.clone(),
            ready,
            Default::default(),
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(25));
        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        // The accepted wake socket is closed immediately, so connect may see a
        // reset even though the blocking accept was successfully released.
        let _ = crate::net::wake_tcp_listener(addr);
        worker.join().unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }
}
