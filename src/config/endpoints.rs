use crate::error::{Error, Result};
use crate::net::Url;

use super::yaml::Yaml;
use super::Endpoint;

/// Names the section that owns an endpoint list in error messages.
pub(super) struct Owner<'a> {
    /// `peers[B]` or `reverse`.
    pub prefix: &'a str,
    /// `peer B` or `reverse`.
    pub name: &'a str,
    /// How to permit plaintext http for this owner.
    pub insecure_hint: &'a str,
    /// Error code: DBB-CFG-002 for peers, DBB-CFG-008 for reverse.
    pub code: &'a str,
}

#[derive(Debug, Default, PartialEq)]
pub(super) struct SpecUrl {
    pub scheme: String,
    pub user: bool,
    pub host: String,
    pub path: String,
    pub opaque: String,
    pub raw_query: String,
    pub force_query: bool,
    pub fragment: String,
}

impl SpecUrl {
    /// `URL.Port()`.
    pub fn port(&self) -> &str {
        let h = &self.host;
        match h.rfind(':') {
            Some(i) if !h[i..].contains(']') && h[i + 1..].bytes().all(|b| b.is_ascii_digit()) => {
                &h[i + 1..]
            }
            _ => "",
        }
    }
    /// `URL.Hostname()`.
    pub fn hostname(&self) -> &str {
        let h = &self.host;
        let mut host = h.as_str();
        if let Some(i) = h.rfind(':') {
            if !h[i..].contains(']') && h[i + 1..].bytes().all(|b| b.is_ascii_digit()) {
                host = &h[..i];
            }
        }
        if let Some(inner) = host.strip_prefix('[') {
            if let Some(inner) = inner.strip_suffix(']') {
                return inner;
            }
        }
        host
    }
}

pub(super) fn spec_url_parse(raw: &str) -> std::result::Result<SpecUrl, ()> {
    if raw.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(());
    }
    let mut u = SpecUrl::default();
    let mut rest = raw;
    if let Some(i) = rest.find('#') {
        u.fragment = rest[i + 1..].to_string();
        rest = &rest[..i];
    }
    // getScheme
    let mut scheme_end = None;
    for (i, c) in rest.char_indices() {
        if c.is_ascii_alphabetic() {
            continue;
        }
        if (c.is_ascii_digit() || c == '+' || c == '-' || c == '.') && i > 0 {
            continue;
        }
        if c == ':' {
            if i == 0 {
                return Err(());
            }
            scheme_end = Some(i);
        }
        break;
    }
    if let Some(i) = scheme_end {
        u.scheme = rest[..i].to_ascii_lowercase();
        rest = &rest[i + 1..];
    }
    if let Some(i) = rest.find('?') {
        u.raw_query = rest[i + 1..].to_string();
        u.force_query = rest[i + 1..].is_empty();
        rest = &rest[..i];
    }
    if !rest.starts_with('/') && !u.scheme.is_empty() {
        u.opaque = rest.to_string();
        return Ok(u);
    }
    if let Some(after) = rest.strip_prefix("//") {
        let end = after.find('/').unwrap_or(after.len());
        let mut authority = &after[..end];
        u.path = after[end..].to_string();
        if let Some(i) = authority.rfind('@') {
            u.user = true;
            authority = &authority[i + 1..];
        }
        // parseHost
        if let Some(stripped) = authority.strip_prefix('[') {
            let close = stripped.find(']').ok_or(())?;
            let tail = &stripped[close + 1..];
            if !tail.is_empty() && !valid_optional_port(tail) {
                return Err(());
            }
        } else if let Some(i) = authority.rfind(':') {
            if !valid_optional_port(&authority[i..]) {
                return Err(());
            }
        }
        if authority.chars().any(|c| {
            c.is_whitespace() || matches!(c, '<' | '>' | '"' | '{' | '}' | '|' | '\\' | '^' | '`')
        }) {
            return Err(());
        }
        u.host = authority.to_string();
    } else {
        u.path = rest.to_string();
    }
    Ok(u)
}

fn valid_optional_port(port: &str) -> bool {
    if port.is_empty() {
        return true;
    }
    match port.strip_prefix(':') {
        Some(digits) => digits.bytes().all(|b| b.is_ascii_digit()),
        None => false,
    }
}

pub(super) fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_matches(|c| c == '[' || c == ']');
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => v4.is_loopback(),
        Ok(std::net::IpAddr::V6(v6)) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
        Err(_) => false,
    }
}

pub(super) fn normalize_endpoints(
    items: &[Yaml],
    owner: &Owner,
    allow_insecure: bool,
) -> Result<Vec<Endpoint>> {
    let fail = |m: String| Error::new(owner.code, m);
    let mut ids: Vec<String> = Vec::new();
    let mut urls: Vec<String> = Vec::new();
    let mut out = Vec::new();
    for (index, ep) in items.iter().enumerate() {
        let id = ep.str_of("id").unwrap_or_default();
        if id.is_empty() {
            return Err(fail(format!(
                "{}.endpoints[{index}].id cannot be empty",
                owner.prefix
            )));
        }
        if ids.contains(&id) {
            return Err(fail(format!(
                "duplicate endpoint id {id:?} in {}",
                owner.name
            )));
        }
        ids.push(id.clone());
        let raw = ep.str_of("url").unwrap_or_default();
        if raw.is_empty() {
            return Err(fail(format!(
                "{}.endpoints[{id}].url cannot be empty",
                owner.prefix
            )));
        }
        let parsed = spec_url_parse(&raw);
        let u = match parsed {
            Ok(u) if (u.scheme == "http" || u.scheme == "https") && !u.host.is_empty() => u,
            _ => {
                return Err(fail(format!(
                    "{}.endpoints[{id}].url {raw:?} is invalid (must be http/https origin)",
                    owner.prefix
                )))
            }
        };
        if u.user
            || !u.raw_query.is_empty()
            || u.force_query
            || !u.fragment.is_empty()
            || !u.path.is_empty()
            || !u.opaque.is_empty()
        {
            return Err(fail(format!(
                "{}.endpoints[{id}].url must be an origin without credentials, path, trailing slash, query or fragment",
                owner.prefix
            )));
        }
        let port = u.port().to_string();
        if !port.is_empty() || u.host.ends_with(':') {
            match port.parse::<u16>() {
                Ok(n) if n != 0 => {}
                _ => {
                    return Err(fail(format!(
                        "{}.endpoints[{id}].url port must be 1-65535",
                        owner.prefix
                    )))
                }
            }
        }
        let mut norm = format!("{}://{}", u.scheme, u.host.to_lowercase());
        if (port == "80" && u.scheme == "http") || (port == "443" && u.scheme == "https") {
            let mut host = u.hostname().to_lowercase();
            if host.contains(':') {
                host = format!("[{host}]");
            }
            norm = format!("{}://{host}", u.scheme);
        }
        let norm = norm.trim_end_matches('/').to_string();
        if urls.contains(&norm) {
            return Err(fail(format!(
                "duplicate normalized endpoint url {norm:?} in {}",
                owner.name
            )));
        }
        urls.push(norm.clone());
        if !allow_insecure && u.scheme == "http" && !is_loopback_host(u.hostname()) {
            return Err(fail(format!(
                "{}.endpoints[{id}].url {raw:?} uses plaintext http to a non-loopback address; use https or {}",
                owner.prefix, owner.insecure_hint
            )));
        }
        let priority = match ep.get("priority") {
            None => 0,
            Some(Yaml::Int(p)) => *p,
            Some(_) => {
                return Err(Error::new(
                    super::CODE_CONFIG_READ,
                    format!(
                        "config.{}.endpoints[{index}].priority must be an integer",
                        owner.prefix
                    ),
                ))
            }
        };
        if priority < 0 {
            return Err(fail(format!(
                "{}.endpoints[{id}].priority must be >= 0",
                owner.prefix
            )));
        }
        let url = Url::parse(&norm)
            .map_err(|e| fail(format!("{}.endpoints[{id}]: {e}", owner.prefix)))?;
        if url.is_tls() && !cfg!(feature = "tls") {
            return Err(Error::new(
                super::CODE_TLS,
                format!(
                    "{}.endpoints[{id}]: TLS support not compiled in",
                    owner.prefix
                ),
            ));
        }
        out.push(Endpoint {
            id,
            url,
            priority: priority.min(i32::MAX as i64) as i32,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eps(yaml: &str) -> Vec<Yaml> {
        let doc = super::super::yaml::parse(yaml).unwrap();
        doc.seq_of("endpoints").unwrap().to_vec()
    }

    fn owner() -> Owner<'static> {
        Owner {
            prefix: "peers[B]",
            name: "peer B",
            insecure_hint: "set peers[].allow_insecure_http: true for this peer",
            code: super::super::CODE_CONFIG_INVALID,
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn endpoint_url_rules_match_spec() {
        let cases: &[(&str, Option<&str>)] = &[
            ("http://127.0.0.1:18080", None),
            ("http://LOCALHOST:80", None),
            ("https://Example.COM:443", None),
            ("http://[::1]:8080", None),
            ("ftp://x", Some("is invalid (must be http/https origin)")),
            ("http://", Some("is invalid (must be http/https origin)")),
            ("http:x", Some("is invalid (must be http/https origin)")),
            ("http://h:abc", Some("is invalid (must be http/https origin)")),
            ("http://127.0.0.1:18080/", Some("must be an origin without credentials")),
            ("http://127.0.0.1:18080/x", Some("must be an origin without credentials")),
            ("http://u:p@127.0.0.1:1", Some("must be an origin without credentials")),
            ("http://127.0.0.1:1?", Some("must be an origin without credentials")),
            ("http://127.0.0.1:1#f", Some("must be an origin without credentials")),
            ("http://127.0.0.1:0", Some("port must be 1-65535")),
            ("http://127.0.0.1:", Some("port must be 1-65535")),
            ("http://127.0.0.1:70000", Some("port must be 1-65535")),
            ("http://10.0.0.1:80", Some("uses plaintext http to a non-loopback address; use https or set peers[].allow_insecure_http: true for this peer")),
        ];
        for (url, want) in cases {
            let list = eps(&format!("endpoints:\n  - {{id: e, url: \"{url}\"}}\n"));
            let got = normalize_endpoints(&list, &owner(), false);
            match want {
                None => assert!(got.is_ok(), "{url}: {:?}", got.err().map(|e| e.message)),
                Some(w) => assert!(
                    got.as_ref().err().is_some_and(|e| e.message.contains(w)),
                    "{url}: {:?}",
                    got.err().map(|e| e.message)
                ),
            }
        }
        let list = eps("endpoints:\n  - {id: e, url: \"http://10.0.0.1:80\"}\n");
        let ok = normalize_endpoints(&list, &owner(), true).unwrap();
        assert_eq!(ok[0].url.port, 80);
        assert_eq!(ok[0].priority, 0);
    }

    #[test]
    fn duplicates_after_normalisation_and_priority() {
        let list = eps("endpoints:\n  - {id: a, url: \"http://LOCALHOST:80\"}\n  - {id: b, url: \"http://localhost\"}\n");
        assert_eq!(
            normalize_endpoints(&list, &owner(), false)
                .unwrap_err()
                .message,
            "duplicate normalized endpoint url \"http://localhost\" in peer B"
        );
        let list = eps("endpoints:\n  - {id: a, url: \"http://127.0.0.1:1\"}\n  - {id: a, url: \"http://127.0.0.1:2\"}\n");
        assert_eq!(
            normalize_endpoints(&list, &owner(), false)
                .unwrap_err()
                .message,
            "duplicate endpoint id \"a\" in peer B"
        );
        let list = eps("endpoints:\n  - {id: a, url: \"http://127.0.0.1:1\", priority: -1}\n");
        assert_eq!(
            normalize_endpoints(&list, &owner(), false)
                .unwrap_err()
                .message,
            "peers[B].endpoints[a].priority must be >= 0"
        );
        let list = eps("endpoints:\n  - {url: \"http://127.0.0.1:1\"}\n");
        assert_eq!(
            normalize_endpoints(&list, &owner(), false)
                .unwrap_err()
                .message,
            "peers[B].endpoints[0].id cannot be empty"
        );
    }

    #[test]
    fn loopback_rule() {
        for h in [
            "localhost",
            "LOCALHOST.",
            "127.0.0.1",
            "127.9.9.9",
            "::1",
            "[::1]",
            "::ffff:127.0.0.1",
        ] {
            assert!(is_loopback_host(h), "{h}");
        }
        for h in ["10.0.0.1", "example.com", "0.0.0.0", "::"] {
            assert!(!is_loopback_host(h), "{h}");
        }
    }
}
