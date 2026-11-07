//! Scalar parsing: sizes, durations, host:port, CIDR.

use std::time::Duration;
use std::{io::Read, path::Path};

use crate::error::{Error, Result};

use super::yaml::{self, Yaml};
use super::{CODE_CONFIG_INVALID, CODE_CONFIG_READ};

pub(super) fn read_text_limited(path: &Path, max_bytes: usize, code: &str) -> Result<String> {
    let file = std::fs::File::open(path).map_err(|e| {
        Error::new(
            code,
            format!(
                "open {}: {}",
                path.display(),
                crate::util::spec_errno_text(&e)
            ),
        )
    })?;
    let mut text = String::new();
    file.take((max_bytes as u64).saturating_add(1))
        .read_to_string(&mut text)
        .map_err(|e| {
            Error::new(
                code,
                format!(
                    "read {}: {}",
                    path.display(),
                    crate::util::spec_errno_text(&e)
                ),
            )
        })?;
    if text.len() > max_bytes {
        return Err(Error::new(
            code,
            format!(
                "{}: file exceeds maximum size of {max_bytes} bytes",
                path.display()
            ),
        ));
    }
    Ok(text)
}

pub(super) fn size_field(doc: &Yaml, key: &str, default: u64) -> Result<u64> {
    match doc.get(key) {
        None | Some(Yaml::Null) => Ok(default),
        Some(Yaml::Int(i)) if *i >= 0 => Ok(*i as u64),
        Some(Yaml::Int(i)) => Err(Error::new(
            CODE_CONFIG_INVALID,
            format!("transport.{key}: byte size cannot be negative: {i}"),
        )),
        Some(Yaml::Str(s)) if s.trim().is_empty() => Ok(default),
        Some(Yaml::Str(s)) => parse_size(s)
            .map_err(|e| Error::new(CODE_CONFIG_INVALID, format!("transport.{key}: {e}"))),
        Some(other) => Err(Error::new(
            CODE_CONFIG_READ,
            format!("transport.{key}: expected a byte size, got {other}"),
        )),
    }
}

pub(super) fn dur_field(doc: &Yaml, key: &str, default: Duration) -> Result<Duration> {
    match doc.get(key) {
        None | Some(Yaml::Null) => Ok(default),
        Some(Yaml::Str(s)) if s.trim().is_empty() => Ok(default),
        Some(Yaml::Str(s)) if yaml::is_float_scalar(s) => parse_float_seconds(s)
            .map_err(|e| Error::new(CODE_CONFIG_INVALID, format!("{key}: {e}"))),
        Some(Yaml::Str(s)) => {
            parse_duration(s).map_err(|e| Error::new(CODE_CONFIG_INVALID, format!("{key}: {e}")))
        }
        Some(Yaml::Int(i)) if *i >= 0 => {
            seconds(*i as u128).map_err(|e| Error::new(CODE_CONFIG_INVALID, format!("{key}: {e}")))
        }
        Some(Yaml::Int(i)) => Err(Error::new(
            CODE_CONFIG_INVALID,
            format!("{key}: duration cannot be negative: {i}"),
        )),
        Some(other) => Err(Error::new(
            CODE_CONFIG_READ,
            format!("{key}: expected a duration, got {other}"),
        )),
    }
}

fn seconds(value: u128) -> std::result::Result<Duration, String> {
    let nanos = value
        .checked_mul(1_000_000_000)
        .ok_or_else(|| "duration overflow".to_string())?;
    if nanos > i64::MAX as u128 {
        return Err("duration overflow".into());
    }
    Ok(Duration::from_nanos(nanos as u64))
}

fn parse_float_seconds(s: &str) -> std::result::Result<Duration, String> {
    let raw = yaml::float_scalar_value(s).ok_or_else(|| "invalid duration number".to_string())?;
    let value: f64 = match raw.to_ascii_lowercase().as_str() {
        ".nan" => f64::NAN,
        ".inf" | "+.inf" => f64::INFINITY,
        "-.inf" => f64::NEG_INFINITY,
        _ => raw
            .parse()
            .map_err(|_| format!("invalid duration {raw:?}"))?,
    };
    if !value.is_finite() {
        return Err(format!("duration must be a finite number: {raw}"));
    }
    if value < 0.0 {
        return Err(format!("duration cannot be negative: {raw}"));
    }
    duration_from_f64(value, 1.0, raw)
}

pub fn parse_duration(input: &str) -> std::result::Result<Duration, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("empty duration".into());
    }
    if s == "0" {
        return Ok(Duration::ZERO);
    }
    if s.starts_with('-') {
        return Err(format!("duration cannot be negative: {s}"));
    }
    if s.starts_with('+') {
        return Err(format!("invalid duration {s:?}"));
    }

    let bytes = s.as_bytes();
    let mut i = 0;
    let mut total = 0.0f64;
    let mut components = 0;
    while i < bytes.len() {
        let start = i;
        let mut digits = 0;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            i += 1;
            digits += 1;
        }
        if i < bytes.len() && bytes[i] == b'.' {
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
                digits += 1;
            }
        }
        if digits == 0 {
            return Err(format!("invalid duration {s:?}"));
        }
        let number = &s[start..i];
        let unit_start = i;
        while i < bytes.len()
            && (bytes[i].is_ascii_alphabetic() || bytes.get(i..i + 2) == Some(&[0xce, 0xbc][..]))
        {
            // The µ in µs is a two-byte UTF-8 sequence.
            i += if bytes[i] == 0xce { 2 } else { 1 };
        }
        let unit = &s[unit_start..i];
        let multiplier = match unit {
            "ns" => 1e-9,
            "us" | "µs" => 1e-6,
            "ms" => 1e-3,
            "s" => 1.0,
            "m" => 60.0,
            "h" => 3600.0,
            _ => return Err(format!("unknown duration unit {unit:?}")),
        };
        let value: f64 = number
            .parse()
            .map_err(|_| format!("invalid duration {s:?}"))?;
        total += value * multiplier;
        if !total.is_finite() {
            return Err("duration overflow".into());
        }
        components += 1;
    }
    if components == 0 {
        return Err(format!("invalid duration {s:?}"));
    }
    duration_from_f64(total, 1.0, s)
}

fn duration_from_f64(
    value: f64,
    seconds_multiplier: f64,
    original: &str,
) -> std::result::Result<Duration, String> {
    let nanos = value * seconds_multiplier * 1e9;
    if !nanos.is_finite() || nanos >= (i64::MAX as f64) {
        return Err(format!("duration overflow: {original}"));
    }
    Ok(Duration::from_nanos(nanos as u64))
}

/// `32KiB`, `1MiB`, `256KiB`, or a plain byte count.
pub fn parse_size(input: &str) -> std::result::Result<u64, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("empty size".into());
    }
    let split = s.find(|c: char| !c.is_ascii_digit());
    let (num, unit) = split.map_or((s, ""), |i| (&s[..i], s[i..].trim()));
    if num.is_empty() || !num.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("invalid size {s:?}"));
    }
    let value: u64 = num
        .parse()
        .map_err(|_| format!("byte size overflow: {s}"))?;
    if value > i64::MAX as u64 {
        return Err(format!("byte size overflow: {s}"));
    }
    let multiplier: u64 = match unit.to_ascii_uppercase().as_str() {
        "" | "B" => 1,
        "K" | "KB" | "KIB" => 1024,
        "M" | "MB" | "MIB" => 1024 * 1024,
        "G" | "GB" | "GIB" => 1024 * 1024 * 1024,
        other => return Err(format!("unknown size unit {other:?}")),
    };
    value
        .checked_mul(multiplier)
        .ok_or_else(|| format!("byte size overflow: {s}"))
}

pub fn spec_split_host_port(hostport: &str) -> std::result::Result<(String, String), String> {
    let missing_port = || format!("address {hostport}: missing port in address");
    let too_many = || format!("address {hostport}: too many colons in address");
    let Some(i) = hostport.rfind(':') else {
        return Err(missing_port());
    };
    let (host, j, k);
    if hostport.starts_with('[') {
        let Some(end) = hostport.find(']') else {
            return Err(format!("address {hostport}: missing ']' in address"));
        };
        if end + 1 == hostport.len() {
            return Err(missing_port());
        }
        if end + 1 != i {
            if hostport.as_bytes()[end + 1] == b':' {
                return Err(too_many());
            }
            return Err(missing_port());
        }
        host = hostport[1..end].to_string();
        j = 1;
        k = end + 1;
    } else {
        host = hostport[..i].to_string();
        if host.contains(':') {
            return Err(too_many());
        }
        j = 0;
        k = 0;
    }
    if hostport[j..].contains('[') {
        return Err(format!("address {hostport}: unexpected '[' in address"));
    }
    if hostport[k..].contains(']') {
        return Err(format!("address {hostport}: unexpected ']' in address"));
    }
    Ok((host, hostport[i + 1..].to_string()))
}

pub fn validate_socket_address(address: &str, listener: bool) -> std::result::Result<(), String> {
    let (host, port) = spec_split_host_port(address)?;
    match port.parse::<u16>() {
        Ok(n) if listener || n != 0 => {}
        _ => return Err("TCP port must be numeric and in range".into()),
    }
    if !listener && host.is_empty() {
        return Err("target host is required".into());
    }
    if host.trim() != host || host.chars().any(|c| "/\\?#@ \t\r\n".contains(c)) {
        return Err("invalid TCP host".into());
    }
    Ok(())
}

/// Splits `host:port`, accepting `:port` and `0.0.0.0:port`.
pub fn parse_hostport(s: &str) -> std::result::Result<(String, u16), String> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| format!("malformed IPv6 address {s:?}"))?;
        let port = tail
            .strip_prefix(':')
            .ok_or_else(|| format!("missing port in {s:?}"))?
            .parse()
            .map_err(|_| format!("invalid port in {s:?}"))?;
        return Ok((host.to_string(), port));
    }
    let (host, port) = s
        .rsplit_once(':')
        .ok_or_else(|| format!("expected host:port, got {s:?}"))?;
    let port: u16 = port.parse().map_err(|_| format!("invalid port in {s:?}"))?;
    Ok((host.to_string(), port))
}

/// Parses an IPv4 or IPv6 CIDR into its masked network address and prefix.
pub fn parse_cidr(s: &str) -> std::result::Result<(std::net::IpAddr, u32), String> {
    let s = s.trim();
    let (addr, len) = s
        .split_once('/')
        .ok_or_else(|| format!("expected address/prefix, got {s:?}"))?;
    let addr: std::net::IpAddr = addr
        .parse()
        .map_err(|_| format!("invalid IP address {s:?}"))?;
    let prefix: u32 = len
        .parse()
        .map_err(|_| format!("invalid prefix length {s:?}"))?;
    let network = match addr {
        std::net::IpAddr::V4(addr) if prefix <= 32 => {
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(u32::from(addr) & mask))
        }
        std::net::IpAddr::V6(addr) if prefix <= 128 => {
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(u128::from(addr) & mask))
        }
        _ => return Err(format!("invalid prefix length {s:?}")),
    };
    Ok((network, prefix))
}

pub fn cidr_contains(cidr: &str, ip: std::net::IpAddr) -> bool {
    match parse_cidr(cidr) {
        Ok((std::net::IpAddr::V4(network), prefix)) => match ip {
            std::net::IpAddr::V4(address) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                (u32::from(address) & mask) == u32::from(network)
            }
            std::net::IpAddr::V6(_) => false,
        },
        Ok((std::net::IpAddr::V6(network), prefix)) => match ip {
            std::net::IpAddr::V6(address) => {
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                (u128::from(address) & mask) == u128::from(network)
            }
            std::net::IpAddr::V4(_) => false,
        },
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn p2_02_size_units_are_binary_and_integer_only() {
        assert_eq!(parse_size("1KB").unwrap(), 1024);
        assert_eq!(parse_size("1mib").unwrap(), 1024 * 1024);
        assert!(parse_size("1.5K").is_err());
        assert!(parse_size("1T").is_err());
        assert!(parse_size("18446744073709551615G").is_err());
    }
    #[test]
    fn p2_02_duration_matches_compound_units() {
        assert_eq!(parse_duration("1m30s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("1.5s").unwrap(), Duration::from_millis(1500));
        assert_eq!(parse_duration("0").unwrap(), Duration::ZERO);
        assert!(parse_duration("15").is_err());
        assert!(parse_duration("1d").is_err());
        assert!(parse_duration("-1s").is_err());
    }
}

pub fn spec_duration(d: Duration) -> String {
    let nanos = d.as_nanos();
    if nanos == 0 {
        return "0s".into();
    }
    fn frac(value: u128, unit: u128) -> String {
        let whole = value / unit;
        let rest = value % unit;
        if rest == 0 {
            return whole.to_string();
        }
        let digits = unit.to_string().len() - 1;
        let mut f = format!("{rest:0digits$}");
        while f.ends_with('0') {
            f.pop();
        }
        format!("{whole}.{f}")
    }
    if nanos < 1_000 {
        return format!("{nanos}ns");
    }
    if nanos < 1_000_000 {
        return format!("{}µs", frac(nanos, 1_000));
    }
    if nanos < 1_000_000_000 {
        return format!("{}ms", frac(nanos, 1_000_000));
    }
    let hours = nanos / 3_600_000_000_000;
    let rem = nanos % 3_600_000_000_000;
    let minutes = rem / 60_000_000_000;
    let secs = rem % 60_000_000_000;
    let s = format!("{}s", frac(secs, 1_000_000_000));
    if hours > 0 {
        format!("{hours}h{minutes}m{s}")
    } else if minutes > 0 {
        format!("{minutes}m{s}")
    } else {
        s
    }
}

#[cfg(test)]
mod spec_duration_tests {
    use super::*;

    #[test]
    fn spec_duration_strings() {
        for (d, want) in [
            (Duration::ZERO, "0s"),
            (Duration::from_millis(1500), "1.5s"),
            (Duration::from_millis(500), "500ms"),
            (Duration::from_secs(90), "1m30s"),
            (Duration::from_secs(3600), "1h0m0s"),
            (Duration::from_nanos(1500), "1.5µs"),
            (Duration::from_nanos(2), "2ns"),
            (Duration::from_millis(30_250), "30.25s"),
        ] {
            assert_eq!(spec_duration(d), want);
        }
    }
}
