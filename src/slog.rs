use std::borrow::Cow;
use std::io::Write;
use std::sync::atomic::{AtomicI8, AtomicU8, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Debug = -4,
    Info = 0,
    Warn = 4,
    Error = 8,
}

impl Level {
    fn name(self) -> &'static str {
        match self {
            Level::Debug => "DEBUG",
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Text,
    Json,
}

static LEVEL: AtomicI8 = AtomicI8::new(Level::Info as i8);
static FORMAT: AtomicU8 = AtomicU8::new(0);

pub fn init(level: &str, format: &str) {
    let level = match level {
        "debug" => Level::Debug,
        "warn" => Level::Warn,
        "error" => Level::Error,
        _ => Level::Info,
    };
    LEVEL.store(level as i8, Ordering::Relaxed);
    FORMAT.store(u8::from(format == "json"), Ordering::Relaxed);
}

pub fn enabled(level: Level) -> bool {
    level as i8 >= LEVEL.load(Ordering::Relaxed)
}

fn format() -> Format {
    if FORMAT.load(Ordering::Relaxed) == 1 {
        Format::Json
    } else {
        Format::Text
    }
}

/// One attribute value, with the kinds the node logs.
#[derive(Clone, Debug)]
pub enum V<'a> {
    Str(Cow<'a, str>),
    Int(i64),
    Uint(u64),
    Bool(bool),
    Dur(Duration),
    Time(Option<SystemTime>),
    List(Vec<String>),
}

impl<'a> From<&'a str> for V<'a> {
    fn from(v: &'a str) -> Self {
        V::Str(Cow::Borrowed(v))
    }
}
impl<'a> From<&'a String> for V<'a> {
    fn from(v: &'a String) -> Self {
        V::Str(Cow::Borrowed(v.as_str()))
    }
}
impl From<String> for V<'_> {
    fn from(v: String) -> Self {
        V::Str(Cow::Owned(v))
    }
}
impl From<bool> for V<'_> {
    fn from(v: bool) -> Self {
        V::Bool(v)
    }
}
impl From<Duration> for V<'_> {
    fn from(v: Duration) -> Self {
        V::Dur(v)
    }
}
impl From<SystemTime> for V<'_> {
    fn from(v: SystemTime) -> Self {
        V::Time(Some(v))
    }
}
impl From<Vec<String>> for V<'_> {
    fn from(v: Vec<String>) -> Self {
        V::List(v)
    }
}
macro_rules! from_int {
    ($($t:ty => $variant:ident),*) => {$(
        impl From<$t> for V<'_> {
            fn from(v: $t) -> Self {
                V::$variant(v as _)
            }
        }
    )*};
}
from_int!(i64 => Int, i32 => Int, isize => Int, u64 => Uint, u32 => Uint, u16 => Uint, usize => Uint);

pub fn err<E: std::fmt::Display>(e: E) -> V<'static> {
    V::Str(Cow::Owned(e.to_string()))
}

pub fn log(level: Level, msg: &str, attrs: &[(&str, V<'_>)]) {
    if !enabled(level) {
        return;
    }
    let mut line = render(format(), SystemTime::now(), level, msg, attrs);
    #[cfg(test)]
    TEST_CAPTURE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(line.clone());
    line.push('\n');
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let _ = out.write_all(line.as_bytes());
    let _ = out.flush();
}

#[cfg(test)]
static TEST_CAPTURE: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Every record logged so far by this test binary.
#[cfg(test)]
pub fn test_captured() -> Vec<String> {
    TEST_CAPTURE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

pub fn debug(msg: &str, attrs: &[(&str, V<'_>)]) {
    log(Level::Debug, msg, attrs);
}
pub fn info(msg: &str, attrs: &[(&str, V<'_>)]) {
    log(Level::Info, msg, attrs);
}
pub fn warn(msg: &str, attrs: &[(&str, V<'_>)]) {
    log(Level::Warn, msg, attrs);
}
pub fn error(msg: &str, attrs: &[(&str, V<'_>)]) {
    log(Level::Error, msg, attrs);
}

/// Renders one record without the trailing newline.
pub fn render(
    format: Format,
    now: SystemTime,
    level: Level,
    msg: &str,
    attrs: &[(&str, V<'_>)],
) -> String {
    render_with_offset(format, now, level, msg, attrs, &local_offset)
}

fn render_with_offset(
    format: Format,
    now: SystemTime,
    level: Level,
    msg: &str,
    attrs: &[(&str, V<'_>)],
    offset: &dyn Fn(i64) -> i32,
) -> String {
    let mut s = String::with_capacity(128);
    match format {
        Format::Text => {
            s.push_str("time=");
            s.push_str(&text_time(Some(now), offset));
            s.push_str(" level=");
            s.push_str(level.name());
            s.push_str(" msg=");
            text_string(&mut s, msg);
            for (k, v) in attrs {
                s.push(' ');
                text_string(&mut s, k);
                s.push('=');
                text_value(&mut s, v, offset);
            }
        }
        Format::Json => {
            s.push_str("{\"time\":\"");
            s.push_str(&json_time(Some(now), offset));
            s.push_str("\",\"level\":\"");
            s.push_str(level.name());
            s.push_str("\",\"msg\":");
            json_string(&mut s, msg);
            for (k, v) in attrs {
                s.push(',');
                json_string(&mut s, k);
                s.push(':');
                json_value(&mut s, v, offset);
            }
            s.push('}');
        }
    }
    s
}

fn text_value(s: &mut String, v: &V<'_>, offset: &dyn Fn(i64) -> i32) {
    match v {
        V::Str(x) => text_string(s, x),
        V::Int(x) => s.push_str(&x.to_string()),
        V::Uint(x) => s.push_str(&x.to_string()),
        V::Bool(x) => s.push_str(if *x { "true" } else { "false" }),
        V::Dur(d) => s.push_str(&spec_duration(*d)),
        V::Time(t) => s.push_str(&text_time(*t, offset)),
        // fmt "%+v" of a []string, then quoted when needed.
        V::List(l) => text_string(s, &format!("[{}]", l.join(" "))),
    }
}

fn json_value(s: &mut String, v: &V<'_>, offset: &dyn Fn(i64) -> i32) {
    match v {
        V::Str(x) => json_string(s, x),
        V::Int(x) => s.push_str(&x.to_string()),
        V::Uint(x) => s.push_str(&x.to_string()),
        V::Bool(x) => s.push_str(if *x { "true" } else { "false" }),
        V::Dur(d) => s.push_str(&d.as_nanos().min(i64::MAX as u128).to_string()),
        V::Time(t) => {
            s.push('"');
            s.push_str(&json_time(*t, offset));
            s.push('"');
        }
        V::List(l) => {
            s.push('[');
            for (i, x) in l.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                json_string(s, x);
            }
            s.push(']');
        }
    }
}

/// slog `needsQuoting`.
fn needs_quoting(v: &str) -> bool {
    if v.is_empty() {
        return true;
    }
    for c in v.chars() {
        if c.is_ascii() {
            let b = c as u8;
            if b != b'\\' && (b == b' ' || b == b'=' || b == b'"' || b < 0x20 || b == 0x7f) {
                return true;
            }
        } else if c.is_whitespace() || c.is_control() || c == '\u{fffd}' {
            return true;
        }
    }
    false
}

fn text_string(s: &mut String, v: &str) {
    if needs_quoting(v) {
        spec_quote(s, v);
    } else {
        s.push_str(v);
    }
}

/// strconv.Quote for valid UTF-8.
fn spec_quote(s: &mut String, v: &str) {
    s.push('"');
    for c in v.chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            '\u{7}' => s.push_str("\\a"),
            '\u{8}' => s.push_str("\\b"),
            '\u{c}' => s.push_str("\\f"),
            '\n' => s.push_str("\\n"),
            '\r' => s.push_str("\\r"),
            '\t' => s.push_str("\\t"),
            '\u{b}' => s.push_str("\\v"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                s.push_str(&format!("\\x{:02x}", c as u32));
            }
            c if c.is_control() => {
                let n = c as u32;
                if n <= 0xffff {
                    s.push_str(&format!("\\u{n:04x}"));
                } else {
                    s.push_str(&format!("\\U{n:08x}"));
                }
            }
            c => s.push(c),
        }
    }
    s.push('"');
}

/// slog appendEscapedJSONString (encoding/json without HTML escaping).
fn json_string(s: &mut String, v: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    s.push('"');
    for c in v.chars() {
        match c {
            '\\' => s.push_str("\\\\"),
            '"' => s.push_str("\\\""),
            '\n' => s.push_str("\\n"),
            '\r' => s.push_str("\\r"),
            '\t' => s.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let b = c as u32 as u8;
                s.push_str("\\u00");
                s.push(HEX[usize::from(b >> 4)] as char);
                s.push(HEX[usize::from(b & 0xf)] as char);
            }
            '\u{2028}' => s.push_str("\\u2028"),
            '\u{2029}' => s.push_str("\\u2029"),
            c => s.push(c),
        }
    }
    s.push('"');
}

pub fn spec_duration(d: Duration) -> String {
    let ns = d.as_nanos().min(i64::MAX as u128) as u64;
    if ns == 0 {
        return "0s".into();
    }
    if ns < 1_000_000_000 {
        let (unit, div, digits) = if ns < 1_000 {
            ("ns", 1u64, 0usize)
        } else if ns < 1_000_000 {
            ("µs", 1_000, 3)
        } else {
            ("ms", 1_000_000, 6)
        };
        return format!("{}{unit}", frac(ns / div, ns % div, digits));
    }
    let secs = ns / 1_000_000_000;
    let sub = ns % 1_000_000_000;
    let h = secs / 3600;
    let m = (secs / 60) % 60;
    let sec = secs % 60;
    let mut out = String::new();
    if h > 0 {
        out.push_str(&format!("{h}h"));
    }
    if h > 0 || m > 0 {
        out.push_str(&format!("{m}m"));
    }
    out.push_str(&frac(sec, sub, 9));
    out.push('s');
    out
}

/// `whole.fraction` with the fraction's trailing zeros (and a bare dot)
/// trimmed, the fraction having `digits` digits.
fn frac(whole: u64, fraction: u64, digits: usize) -> String {
    if digits == 0 || fraction == 0 {
        return whole.to_string();
    }
    let f = format!("{fraction:0digits$}");
    format!("{whole}.{}", f.trim_end_matches('0'))
}

fn split(t: SystemTime) -> (i64, u32) {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as i64, d.subsec_nanos()),
        Err(e) => {
            let d = e.duration();
            let mut secs = -(d.as_secs() as i64);
            let mut nanos = d.subsec_nanos();
            if nanos > 0 {
                secs -= 1;
                nanos = 1_000_000_000 - nanos;
            }
            (secs, nanos)
        }
    }
}

/// Civil date-time of `secs` (already shifted into the zone).
fn civil(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400) as u32;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d, rem / 3600, (rem / 60) % 60, rem % 60)
}

fn zone(offset: i32) -> String {
    if offset == 0 {
        return "Z".into();
    }
    let sign = if offset < 0 { '-' } else { '+' };
    let a = offset.unsigned_abs();
    format!("{sign}{:02}:{:02}", a / 3600, (a / 60) % 60)
}

const ZERO_TIME_SECS: i64 = -62_135_596_800;

fn stamp(t: Option<SystemTime>, offset: &dyn Fn(i64) -> i32) -> (i64, u32, i32) {
    match t {
        None => (ZERO_TIME_SECS, 0, 0),
        Some(t) => {
            let (secs, nanos) = split(t);
            (secs, nanos, offset(secs))
        }
    }
}

/// slog appendRFC3339Millis: "2006-01-02T15:04:05.000Z07:00".
fn text_time(t: Option<SystemTime>, offset: &dyn Fn(i64) -> i32) -> String {
    let (secs, nanos, off) = stamp(t, offset);
    let (y, mo, d, h, mi, s) = civil(secs + i64::from(off));
    format!(
        "{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{:03}{}",
        nanos / 1_000_000,
        zone(off)
    )
}

/// time.RFC3339Nano: "2006-01-02T15:04:05.999999999Z07:00".
fn json_time(t: Option<SystemTime>, offset: &dyn Fn(i64) -> i32) -> String {
    let (secs, nanos, off) = stamp(t, offset);
    let (y, mo, d, h, mi, s) = civil(secs + i64::from(off));
    let mut out = format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}");
    if nanos > 0 {
        let f = format!("{nanos:09}");
        out.push('.');
        out.push_str(f.trim_end_matches('0'));
    }
    out.push_str(&zone(off));
    out
}

#[cfg(unix)]
fn local_offset(secs: i64) -> i32 {
    #[repr(C)]
    struct Tm {
        tm_sec: i32,
        tm_min: i32,
        tm_hour: i32,
        tm_mday: i32,
        tm_mon: i32,
        tm_year: i32,
        tm_wday: i32,
        tm_yday: i32,
        tm_isdst: i32,
        tm_gmtoff: std::os::raw::c_long,
        tm_zone: *const std::os::raw::c_char,
    }
    extern "C" {
        fn localtime_r(t: *const i64, out: *mut Tm) -> *mut Tm;
        fn tzset();
    }
    static TZSET: std::sync::Once = std::sync::Once::new();
    // SAFETY: tzset has no arguments; localtime_r writes only into `tm`,
    // which is a correctly laid out `struct tm` on Linux (glibc and musl).
    unsafe {
        TZSET.call_once(|| tzset());
        let mut tm: Tm = std::mem::zeroed();
        if localtime_r(&secs, &mut tm).is_null() {
            return 0;
        }
        tm.tm_gmtoff as i32
    }
}

#[cfg(not(unix))]
fn local_offset(_secs: i64) -> i32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64, nanos: u32) -> SystemTime {
        UNIX_EPOCH + Duration::new(secs, nanos)
    }
    fn cst(_: i64) -> i32 {
        8 * 3600
    }
    fn utc(_: i64) -> i32 {
        0
    }

    #[test]
    fn text_record_matches_spec_text_handler() {
        // 2026-10-30T06:19:00.120Z
        let now = at(1_793_341_140, 120_456_789);
        let line = render_with_offset(
            Format::Text,
            now,
            Level::Info,
            "starting dbbridge peer node",
            &[("node_id", "a".into())],
            &cst,
        );
        assert_eq!(
            line,
            "time=2026-10-30T14:19:00.120+08:00 level=INFO msg=\"starting dbbridge peer node\" node_id=a"
        );
        let line = render_with_offset(
            Format::Text,
            at(1_793_341_140, 0),
            Level::Warn,
            "x",
            &[],
            &utc,
        );
        assert_eq!(line, "time=2026-10-30T06:19:00.000Z level=WARN msg=x");
    }

    #[test]
    fn json_record_matches_spec_json_handler() {
        let now = at(1_793_341_140, 120_450_000);
        let line = render_with_offset(
            Format::Json,
            now,
            Level::Error,
            "a \"b\"\n<c>&",
            &[
                ("n", 3i64.into()),
                ("ok", true.into()),
                ("d", Duration::from_millis(1500).into()),
                ("l", vec!["A".to_string(), "B".to_string()].into()),
                ("t", V::Time(None)),
            ],
            &cst,
        );
        assert_eq!(
            line,
            "{\"time\":\"2026-10-30T14:19:00.12045+08:00\",\"level\":\"ERROR\",\"msg\":\"a \\\"b\\\"\\n<c>&\",\"n\":3,\"ok\":true,\"d\":1500000000,\"l\":[\"A\",\"B\"],\"t\":\"0001-01-01T00:00:00Z\"}"
        );
        let whole = render_with_offset(
            Format::Json,
            at(1_793_341_140, 0),
            Level::Info,
            "m",
            &[],
            &utc,
        );
        assert_eq!(
            whole,
            "{\"time\":\"2026-10-30T06:19:00Z\",\"level\":\"INFO\",\"msg\":\"m\"}"
        );
    }

    #[test]
    fn text_values_quote_like_slog() {
        let line = render_with_offset(
            Format::Text,
            at(0, 0),
            Level::Debug,
            "m",
            &[
                ("empty", "".into()),
                ("eq", "a=b".into()),
                ("q", "say \"hi\"".into()),
                ("bs", "a\\b".into()),
                ("tab", "a\tb".into()),
                ("uni", "héllo".into()),
                ("d", Duration::from_secs(90).into()),
                ("zero", V::Time(None)),
                ("vars", vec!["A".to_string(), "B".to_string()].into()),
            ],
            &utc,
        );
        assert_eq!(
            line,
            "time=1970-01-01T00:00:00.000Z level=DEBUG msg=m empty=\"\" eq=\"a=b\" q=\"say \\\"hi\\\"\" bs=a\\b tab=\"a\\tb\" uni=héllo d=1m30s zero=0001-01-01T00:00:00.000Z vars=\"[A B]\""
        );
    }

    #[test]
    fn duration_string_matches_spec() {
        for (d, want) in [
            (Duration::ZERO, "0s"),
            (Duration::from_nanos(1), "1ns"),
            (Duration::from_nanos(1_500), "1.5µs"),
            (Duration::from_micros(100), "100µs"),
            (Duration::from_millis(100), "100ms"),
            (Duration::from_nanos(1_234_567), "1.234567ms"),
            (Duration::from_secs(1), "1s"),
            (Duration::from_millis(1500), "1.5s"),
            (Duration::from_secs(60), "1m0s"),
            (Duration::from_secs(3600), "1h0m0s"),
            (Duration::from_secs(3723), "1h2m3s"),
            (Duration::from_millis(30_250), "30.25s"),
        ] {
            assert_eq!(spec_duration(d), want, "{d:?}");
        }
    }

    #[test]
    fn level_filter_and_init() {
        init("warn", "json");
        assert!(!enabled(Level::Info));
        assert!(enabled(Level::Warn));
        assert_eq!(format(), Format::Json);
        init("bogus", "text");
        assert!(enabled(Level::Info));
        assert!(!enabled(Level::Debug));
        assert_eq!(format(), Format::Text);
    }

    #[test]
    fn civil_dates_around_epoch_and_leap_years() {
        assert_eq!(civil(0), (1970, 1, 1, 0, 0, 0));
        assert_eq!(civil(951_782_400), (2000, 2, 29, 0, 0, 0));
        assert_eq!(civil(ZERO_TIME_SECS), (1, 1, 1, 0, 0, 0));
        assert_eq!(civil(-1), (1969, 12, 31, 23, 59, 59));
    }
}
