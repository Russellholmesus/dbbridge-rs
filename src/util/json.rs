//! Minimal JSON value, parser and serializer.
//!
//! The protocol carries control messages as JSON, and the peer validates them
//! strictly (no duplicate keys, no unknown fields, no trailing data). Rather
//! than pull in a crate, this module implements exactly what the protocol
//! needs, with the same strictness:
//!
//! * numbers keep their literal text, so a 64-bit offset round-trips exactly;
//! * duplicate object keys are rejected;
//! * unpaired UTF-16 surrogate escapes are rejected;
//! * trailing data and control characters inside strings are rejected.

use std::collections::HashSet;
use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    /// A number, kept as its literal text.
    Num(String),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Parses an unsigned integer from either a JSON number or a decimal
    /// string. The protocol carries 64-bit offsets as strings (`"offset"`),
    /// so both forms are accepted, but never a sign, fraction or exponent.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Num(n) | Json::Str(n) => canonical_offset(n),
            _ => None,
        }
    }

    /// A canonical decimal offset: no sign, no leading zeros. This is the form
    /// the wire format requires, so a non-canonical value is a protocol error
    /// rather than a number to fix up.
    pub fn offset(&self, key: &str) -> Result<u64, String> {
        let s = self
            .get(key)
            .and_then(Json::as_str)
            .ok_or_else(|| format!("missing or non-string field {key:?}"))?;
        canonical_offset(s).ok_or_else(|| format!("non-canonical offset in {key:?}"))
    }

    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(a) => Some(a),
            _ => None,
        }
    }

    /// A required string field.
    pub fn str_field(&self, key: &str) -> Result<&str, String> {
        self.get(key)
            .and_then(Json::as_str)
            .ok_or_else(|| format!("missing or non-string field {key:?}"))
    }

    pub fn u64_field(&self, key: &str) -> Result<u64, String> {
        self.get(key)
            .and_then(Json::as_u64)
            .ok_or_else(|| format!("missing or non-numeric field {key:?}"))
    }

    pub fn bool_field(&self, key: &str) -> Result<bool, String> {
        self.get(key)
            .and_then(Json::as_bool)
            .ok_or_else(|| format!("missing or non-boolean field {key:?}"))
    }

    /// Reject fields not present in the protocol shape for this object.
    pub fn reject_unknown_fields(&self, allowed: &[&str]) -> Result<(), String> {
        let fields = match self {
            Json::Obj(fields) => fields,
            _ => return Err("expected JSON object".into()),
        };
        let allowed: HashSet<&str> = allowed.iter().copied().collect();
        for (key, _) in fields {
            if !allowed.contains(key.as_str()) {
                return Err(format!("unknown JSON field {key:?}"));
            }
        }
        Ok(())
    }
}

impl fmt::Display for Json {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = String::new();
        write_json(self, &mut out);
        f.write_str(&out)
    }
}

impl From<&str> for Json {
    fn from(v: &str) -> Self {
        Json::Str(v.to_string())
    }
}

impl From<String> for Json {
    fn from(v: String) -> Self {
        Json::Str(v)
    }
}

impl From<bool> for Json {
    fn from(v: bool) -> Self {
        Json::Bool(v)
    }
}

impl From<u64> for Json {
    fn from(v: u64) -> Self {
        Json::Num(v.to_string())
    }
}

impl From<i64> for Json {
    fn from(v: i64) -> Self {
        Json::Num(v.to_string())
    }
}

impl From<Vec<Json>> for Json {
    fn from(v: Vec<Json>) -> Self {
        Json::Arr(v)
    }
}

impl<T: Into<Json>> From<Option<T>> for Json {
    fn from(v: Option<T>) -> Self {
        match v {
            Some(x) => x.into(),
            None => Json::Null,
        }
    }
}

/// Builds an object, keeping field order (the peer does not care, but stable
/// output makes logs and tests readable).
pub fn obj(pairs: Vec<(&str, Json)>) -> Json {
    Json::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

pub fn write_json(v: &Json, out: &mut String) {
    match v {
        Json::Null => out.push_str("null"),
        Json::Bool(true) => out.push_str("true"),
        Json::Bool(false) => out.push_str("false"),
        Json::Num(n) => out.push_str(n),
        Json::Str(s) => write_string(s, out),
        Json::Arr(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json(item, out);
            }
            out.push(']');
        }
        Json::Obj(fields) => {
            out.push('{');
            for (i, (k, val)) in fields.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(k, out);
                out.push(':');
                write_json(val, out);
            }
            out.push('}');
        }
    }
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

const MAX_DEPTH: usize = 32;

/// Parses a canonical decimal offset (`"0"`, `"17"`, never `"017"` or `"+1"`).
pub fn canonical_offset(s: &str) -> Option<u64> {
    if s.is_empty() || (s.len() > 1 && s.starts_with('0')) {
        return None;
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u64>().ok()
}

const MAX_CONTROL_BODY: usize = 16 * 1024;

/// Parses one UTF-8 JSON value, rejecting oversized or trailing data.
pub fn parse(input: &str) -> Result<Json, String> {
    parse_bytes(input.as_bytes())
}

/// Parses one UTF-8 JSON value with a caller-specified byte limit.
pub fn parse_limited(input: &str, max_bytes: usize) -> Result<Json, String> {
    parse_bytes_limited(input.as_bytes(), max_bytes)
}

/// Parses one JSON value from wire bytes. UTF-8 validation happens before any
/// parsing, so invalid byte sequences cannot be replaced with U+FFFD.
pub fn parse_bytes(input: &[u8]) -> Result<Json, String> {
    if input.len() > MAX_CONTROL_BODY {
        return Err("JSON control body exceeds 16 KiB".into());
    }
    parse_validated_bytes(input)
}

/// Parses one JSON value with a caller-specified byte limit.
pub fn parse_bytes_limited(input: &[u8], max_bytes: usize) -> Result<Json, String> {
    if input.len() > max_bytes {
        return Err(format!("JSON exceeds maximum size of {max_bytes} bytes"));
    }
    parse_validated_bytes(input)
}

fn parse_validated_bytes(input: &[u8]) -> Result<Json, String> {
    std::str::from_utf8(input).map_err(|_| "invalid UTF-8 in JSON body".to_string())?;
    let mut p = Parser {
        b: input,
        i: 0,
        depth: 0,
    };
    p.skip_ws();
    let v = p.value()?;
    p.skip_ws();
    if p.i != p.b.len() {
        return Err(format!("trailing JSON at byte {}", p.i));
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while self.i < self.b.len() {
            match self.b[self.i] {
                b' ' | b'\t' | b'\n' | b'\r' => self.i += 1,
                _ => break,
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn expect(&mut self, c: u8) -> Result<(), String> {
        if self.peek() == Some(c) {
            self.i += 1;
            Ok(())
        } else {
            Err(format!("expected {:?} at byte {}", c as char, self.i))
        }
    }

    fn value(&mut self) -> Result<Json, String> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err("JSON nesting limit".into());
        }
        let v = match self.peek() {
            Some(b'{') => self.object()?,
            Some(b'[') => self.array()?,
            Some(b'"') => Json::Str(self.string()?),
            Some(b't') => {
                self.literal("true")?;
                Json::Bool(true)
            }
            Some(b'f') => {
                self.literal("false")?;
                Json::Bool(false)
            }
            Some(b'n') => {
                self.literal("null")?;
                Json::Null
            }
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number()?,
            Some(c) => return Err(format!("unexpected byte 0x{c:02x} at {}", self.i)),
            None => return Err("unexpected end of JSON".into()),
        };
        self.depth -= 1;
        Ok(v)
    }

    fn literal(&mut self, lit: &str) -> Result<(), String> {
        if self.b[self.i..].starts_with(lit.as_bytes()) {
            self.i += lit.len();
            Ok(())
        } else {
            Err(format!("invalid literal at byte {}", self.i))
        }
    }

    fn object(&mut self) -> Result<Json, String> {
        self.expect(b'{')?;
        let mut fields: Vec<(String, Json)> = Vec::new();
        let mut keys = HashSet::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Json::Obj(fields));
        }
        loop {
            self.skip_ws();
            let key = self.string()?;
            if !keys.insert(key.clone()) {
                return Err(format!("duplicate JSON key {key:?}"));
            }
            self.skip_ws();
            self.expect(b':')?;
            self.skip_ws();
            let val = self.value()?;
            fields.push((key, val));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Json::Obj(fields));
                }
                _ => return Err(format!("expected ',' or '}}' at byte {}", self.i)),
            }
        }
    }

    fn array(&mut self) -> Result<Json, String> {
        self.expect(b'[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Json::Arr(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value()?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b']') => {
                    self.i += 1;
                    return Ok(Json::Arr(items));
                }
                _ => return Err(format!("expected ',' or ']' at byte {}", self.i)),
            }
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let c = self.peek().ok_or("unterminated JSON string")?;
            match c {
                b'"' => {
                    self.i += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.i += 1;
                    let e = self.peek().ok_or("unterminated escape")?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let ch = if (0xD800..0xDC00).contains(&hi) {
                                // A high surrogate must be followed by a low one.
                                if self.peek() != Some(b'\\') {
                                    return Err("unpaired UTF-16 surrogate escape".into());
                                }
                                self.i += 1;
                                if self.peek() != Some(b'u') {
                                    return Err("unpaired UTF-16 surrogate escape".into());
                                }
                                self.i += 1;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err("unpaired UTF-16 surrogate escape".into());
                                }
                                let cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
                                char::from_u32(cp).ok_or("invalid surrogate pair")?
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return Err("unpaired UTF-16 surrogate escape".into());
                            } else {
                                char::from_u32(hi).ok_or("invalid code point")?
                            };
                            out.push(ch);
                        }
                        _ => return Err(format!("invalid escape \\{}", e as char)),
                    }
                }
                c if c < 0x20 => {
                    return Err("raw control character in JSON string".into());
                }
                _ => {
                    // Copy one UTF-8 scalar. The input came from &str, so the
                    // bytes are valid UTF-8; find the sequence length.
                    let len = utf8_len(c);
                    let end = (self.i + len).min(self.b.len());
                    let s = std::str::from_utf8(&self.b[self.i..end])
                        .map_err(|_| "invalid UTF-8 in JSON string".to_string())?;
                    out.push_str(s);
                    self.i = end;
                }
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, String> {
        if self.i + 4 > self.b.len() {
            return Err("truncated \\u escape".into());
        }
        let s = std::str::from_utf8(&self.b[self.i..self.i + 4])
            .map_err(|_| "invalid \\u escape".to_string())?;
        let v = u32::from_str_radix(s, 16).map_err(|_| "invalid \\u escape".to_string())?;
        self.i += 4;
        Ok(v)
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        let digits_start = self.i;
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.i += 1;
        }
        if self.i == digits_start {
            return Err(format!("invalid number at byte {start}"));
        }
        // A leading zero must stand alone (no "01"), like the JSON grammar.
        if self.b[digits_start] == b'0' && self.i - digits_start > 1 {
            return Err(format!("non-canonical number at byte {start}"));
        }
        if self.peek() == Some(b'.') {
            self.i += 1;
            let f = self.i;
            while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                self.i += 1;
            }
            if self.i == f {
                return Err(format!("invalid number at byte {start}"));
            }
        }
        if matches!(self.peek(), Some(b'e') | Some(b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+') | Some(b'-')) {
                self.i += 1;
            }
            let e = self.i;
            while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                self.i += 1;
            }
            if self.i == e {
                return Err(format!("invalid number at byte {start}"));
            }
        }
        let text = std::str::from_utf8(&self.b[start..self.i])
            .map_err(|_| "invalid number".to_string())?;
        Ok(Json::Num(text.to_string()))
    }
}

fn utf8_len(first: u8) -> usize {
    match first {
        0x00..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FuzzRng(u64);

    impl FuzzRng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn bytes(&mut self, max_len: usize) -> Vec<u8> {
            let len = self.next() as usize % (max_len + 1);
            (0..len).map(|_| self.next() as u8).collect()
        }
    }

    fn run_json_fuzz(iterations: usize) {
        let mut rng = FuzzRng(0x42c7_19a5_e30d_8bf1);
        for iteration in 0..iterations {
            let mut raw = rng.bytes(192);
            match iteration % 4 {
                1 => {
                    let mut input = br#"{"fuzz":"#.to_vec();
                    input.extend_from_slice(&raw);
                    input.extend_from_slice(b"\"}");
                    raw = input;
                }
                2 => {
                    let mut input = b"[".to_vec();
                    input.extend_from_slice(&raw);
                    input.push(b']');
                    raw = input;
                }
                3 => {
                    let mut input = br#"{"fuzz": "#.to_vec();
                    input.extend_from_slice(&raw);
                    input.push(b'}');
                    raw = input;
                }
                _ => {}
            }
            assert!(raw.len() <= 208, "fuzz input must stay bounded");
            let _ = parse_bytes(&raw);
        }
    }

    #[test]
    fn fuzz_json_parser() {
        run_json_fuzz(100_000);
    }

    #[test]
    #[ignore = "one-million iteration parser fuzz run"]
    fn fuzz_json_parser_long() {
        run_json_fuzz(1_000_000);
    }

    #[test]
    fn parses_control_message() {
        let s = r#"{"type":"ack_up","session_id":"s1","instance_id":"i1","epoch":"1","stream_id":"st","ack_up_offset":"1024","up_fin_applied":false}"#;
        let v = parse(s).unwrap();
        assert_eq!(v.str_field("type").unwrap(), "ack_up");
        assert_eq!(v.offset("ack_up_offset").unwrap(), 1024);
        assert!(!v.bool_field("up_fin_applied").unwrap());
    }

    #[test]
    fn rejects_duplicates_and_trailing() {
        assert!(parse(r#"{"a":1,"a":2}"#).is_err());
        assert!(parse(r#"{} {}"#).is_err());
        assert!(parse(r#"{"a":01}"#).is_err());
    }

    #[test]
    fn rejects_plus_and_leading_zero() {
        assert!(parse(r#"{"offset":"+1"}"#)
            .unwrap()
            .u64_field("offset")
            .is_err());
        assert!(parse(r#"{"offset":"01"}"#)
            .unwrap()
            .u64_field("offset")
            .is_err());
        assert_eq!(parse(r#"{"offset":"0"}"#).unwrap().offset("offset"), Ok(0));
        assert!(parse(r#"{"offset":+1}"#).is_err());
    }

    #[test]
    fn rejects_unknown_fields() {
        let value = parse(r#"{"type":"ping","nonce":"n","extra":true}"#).unwrap();
        assert!(value.reject_unknown_fields(&["type", "nonce"]).is_err());
    }

    #[test]
    fn rejects_lone_surrogate() {
        assert!(parse(r#"{"value":"\uD800"}"#).is_err());
        assert!(parse(r#"{"value":"\uDC00"}"#).is_err());
        assert_eq!(
            parse(r#"{"value":"\uD834\uDD1E"}"#)
                .unwrap()
                .str_field("value")
                .unwrap(),
            "𝄞"
        );
    }

    #[test]
    fn rejects_invalid_utf8_and_oversized_control_body() {
        assert!(parse_bytes(br#"{"value":"ok"}"#).is_ok());
        assert!(parse_bytes(&[b'"', 0xff, b'"']).is_err());
        let oversized = vec![b' '; MAX_CONTROL_BODY + 1];
        assert!(parse_bytes(&oversized).is_err());
    }

    #[test]
    fn custom_limit_is_separate_from_control_body_limit() {
        let input = format!("\"{}\"", "x".repeat(MAX_CONTROL_BODY));
        assert!(parse(&input).is_err());
        assert!(parse_limited(&input, MAX_CONTROL_BODY + 16).is_ok());
        assert!(parse_limited(&input, MAX_CONTROL_BODY).is_err());
    }

    #[test]
    fn round_trips_big_offsets() {
        let n = u64::MAX;
        let v = obj(vec![("offset", Json::from(n))]);
        let s = v.to_string();
        assert_eq!(parse(&s).unwrap().u64_field("offset").unwrap(), n);
    }

    #[test]
    fn escapes_strings() {
        let v = Json::from("a\"b\\c\nd\u{1}");
        let s = v.to_string();
        assert_eq!(parse(&s).unwrap(), v);
    }
}
