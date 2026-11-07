const NESTING_LIMIT: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Top,
    Object,
    Array,
}

#[derive(Clone, Copy)]
struct Entry {
    kind: Kind,
    len: usize,
}

impl Entry {
    fn need_object_name(self) -> bool {
        self.kind == Kind::Object && self.len % 2 == 0
    }
    fn need_object_value(self) -> bool {
        self.kind == Kind::Object && self.len % 2 == 1
    }
}

/// A raw `jsontext` error before `transformSyntacticError`.
#[derive(Clone, Debug, PartialEq)]
enum RawErr {
    Eof,
    UnexpectedEof,
    Msg(String),
}

/// strconv.QuoteRune (jsonwire.QuoteRune on valid UTF-8).
fn quote_rune(ch: char) -> String {
    let body = match ch {
        '\x07' => "\\a".to_string(),
        '\x08' => "\\b".to_string(),
        '\x0c' => "\\f".to_string(),
        '\n' => "\\n".to_string(),
        '\r' => "\\r".to_string(),
        '\t' => "\\t".to_string(),
        '\x0b' => "\\v".to_string(),
        '\\' => "\\\\".to_string(),
        '\'' => "\\'".to_string(),
        c if (c as u32) < 0x20 || c as u32 == 0x7f => format!("\\x{:02x}", c as u32),
        c if c.is_control() => format!("\\u{:04x}", c as u32),
        c => c.to_string(),
    };
    format!("'{body}'")
}

/// jsonwire.InvalidTextError.Error.
fn invalid_text(label: &str, what: &str, where_: &str) -> String {
    let what_s = if what.chars().count() == 1 {
        quote_rune(what.chars().next().unwrap())
    } else if what
        .chars()
        .any(|c| c == '`' || c == '\u{fffd}' || c.is_whitespace() || c.is_control())
    {
        format!("{what:?}")
    } else {
        format!("`{what}`")
    };
    format!("invalid {label} {what_s} {where_}")
        .trim_end_matches(' ')
        .to_string()
}

fn transform(msg: &str) -> String {
    let mut m = msg.to_string();
    if let Some(i) = m.find(" (expecting") {
        if !m.contains(" in literal") {
            m.truncate(i);
        }
    }
    m.replace("object name", "object key")
        .replace("at start of value", "looking for beginning of value")
        .replace(
            "at start of string",
            "looking for beginning of object key string",
        )
        .replace("after object value", "after object key:value pair")
        .replace("in number", "in numeric literal")
}

fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\r' | b'\n')
}

enum Tok {
    Delim(u8),
    Str(String),
    Scalar,
}

struct Dec<'a> {
    b: &'a [u8],
    prev_end: usize,
    last: Entry,
    stack: Vec<Entry>,
    /// The sticky `json.Decoder.err` (set by `More`).
    err: Option<String>,
}

impl<'a> Dec<'a> {
    fn ws(&self, mut pos: usize) -> usize {
        while pos < self.b.len() && is_space(self.b[pos]) {
            pos += 1;
        }
        pos
    }

    fn char_at(&self, pos: usize) -> String {
        std::str::from_utf8(&self.b[pos..])
            .ok()
            .and_then(|s| s.chars().next())
            .map(String::from)
            .unwrap_or_default()
    }

    fn need_delim(&self, next: u8) -> u8 {
        if self.last.need_object_value() {
            b':'
        } else if self.last.len > 0 && next != b'}' && next != b']' && !self.stack.is_empty() {
            b','
        } else {
            0
        }
    }

    fn check_delim(&self, delim: u8, next: u8) -> RawErr {
        let where_ = match self.need_delim(next) {
            b':' if delim != b':' => "after object name (expecting ':')",
            b',' if delim != b',' => {
                if self.last.kind == Kind::Object {
                    "after object value (expecting ',' or '}')"
                } else {
                    "after array element (expecting ',' or ']')"
                }
            }
            _ => "at start of value",
        };
        let pos = self.ws(self.prev_end);
        RawErr::Msg(invalid_text("character", &self.char_at(pos), where_))
    }

    /// `decoderState.PeekKind` (the position of the next token and its
    /// normalized kind byte).
    fn scan_next(&self) -> Result<(usize, u8), RawErr> {
        let mut pos = self.ws(self.prev_end);
        if pos >= self.b.len() {
            return Err(if self.stack.is_empty() {
                RawErr::Eof
            } else {
                RawErr::UnexpectedEof
            });
        }
        let mut delim = 0;
        if matches!(self.b[pos], b':' | b',') {
            delim = self.b[pos];
            pos = self.ws(pos + 1);
            if pos >= self.b.len() {
                if self.need_delim(b'"') != delim {
                    return Err(self.check_delim(delim, b'"'));
                }
                return Err(RawErr::UnexpectedEof);
            }
        }
        let next = match self.b[pos] {
            b'-' | b'0'..=b'9' => b'0',
            c => c,
        };
        if self.need_delim(next) != delim {
            return Err(self.check_delim(delim, next));
        }
        Ok((pos, next))
    }

    fn append_scalar(&mut self, is_string: bool) -> Result<(), RawErr> {
        if !is_string && self.last.need_object_name() {
            return Err(RawErr::Msg("object member name must be a string".into()));
        }
        self.last.len += 1;
        Ok(())
    }

    fn mismatch(&self, pos: usize) -> RawErr {
        let mut where_ = "at start of value";
        if !self.stack.is_empty() && self.last.len > 0 {
            where_ = match self.last.kind {
                Kind::Array => "after array element (expecting ',' or ']')",
                Kind::Object => "after object value (expecting ',' or '}')",
                Kind::Top => where_,
            };
        }
        RawErr::Msg(invalid_text("character", &self.char_at(pos), where_))
    }

    /// `decoderState.ReadToken`.
    fn read_token(&mut self) -> Result<Tok, RawErr> {
        let (pos, next) = self.scan_next()?;
        let b = self.b;
        match next {
            b'n' | b'f' | b't' => {
                let lit: &str = match next {
                    b'n' => "null",
                    b'f' => "false",
                    _ => "true",
                };
                for (k, want) in lit.bytes().enumerate() {
                    match b.get(pos + k) {
                        None => return Err(RawErr::UnexpectedEof),
                        Some(&got) if got != want => {
                            return Err(RawErr::Msg(invalid_text(
                                "character",
                                &self.char_at(pos + k),
                                &format!(
                                    "in literal {lit} (expecting {})",
                                    quote_rune(want as char)
                                ),
                            )))
                        }
                        _ => {}
                    }
                }
                self.append_scalar(false)?;
                self.prev_end = pos + lit.len();
                Ok(Tok::Scalar)
            }
            b'"' => {
                let (end, s) = self.consume_string(pos)?;
                self.append_scalar(true)?;
                self.prev_end = end;
                Ok(Tok::Str(s))
            }
            b'0' => {
                let end = self.consume_number(pos)?;
                self.append_scalar(false)?;
                self.prev_end = end;
                Ok(Tok::Scalar)
            }
            b'{' | b'[' => {
                if self.last.need_object_name() {
                    return Err(RawErr::Msg("object member name must be a string".into()));
                }
                self.last.len += 1;
                self.stack.push(self.last);
                self.last = Entry {
                    kind: if next == b'{' {
                        Kind::Object
                    } else {
                        Kind::Array
                    },
                    len: 0,
                };
                self.prev_end = pos + 1;
                Ok(Tok::Delim(next))
            }
            b'}' => {
                if self.last.kind != Kind::Object {
                    return Err(self.mismatch(pos));
                }
                if self.last.need_object_value() {
                    return Err(RawErr::Msg("missing value after object name".into()));
                }
                self.last = self.stack.pop().expect("object has a parent");
                self.prev_end = pos + 1;
                Ok(Tok::Delim(next))
            }
            b']' => {
                if self.last.kind != Kind::Array || self.stack.is_empty() {
                    return Err(self.mismatch(pos));
                }
                self.last = self.stack.pop().expect("array has a parent");
                self.prev_end = pos + 1;
                Ok(Tok::Delim(next))
            }
            _ => Err(RawErr::Msg(invalid_text(
                "character",
                &self.char_at(pos),
                "at start of value",
            ))),
        }
    }

    /// jsonwire.ConsumeStringResumable (valid UTF-8 input, surrogates
    /// already checked) returning the end offset and the decoded value.
    fn consume_string(&self, pos: usize) -> Result<(usize, String), RawErr> {
        let b = self.b;
        let mut n = pos + 1;
        let mut out = String::new();
        loop {
            let Some(&c) = b.get(n) else {
                return Err(RawErr::UnexpectedEof);
            };
            match c {
                b'"' => return Ok((n + 1, out)),
                b'\\' => {
                    let Some(&e) = b.get(n + 1) else {
                        return Err(RawErr::UnexpectedEof);
                    };
                    let bad = |what: &[u8]| {
                        RawErr::Msg(invalid_text(
                            "escape sequence",
                            &String::from_utf8_lossy(what),
                            "in string",
                        ))
                    };
                    match e {
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {
                            out.push(match e {
                                b'b' => '\x08',
                                b'f' => '\x0c',
                                b'n' => '\n',
                                b'r' => '\r',
                                b't' => '\t',
                                x => x as char,
                            });
                            n += 2;
                        }
                        b'u' => {
                            if b.len() < n + 6 {
                                if b[n + 2..].iter().all(u8::is_ascii_hexdigit) {
                                    return Err(RawErr::UnexpectedEof);
                                }
                                return Err(bad(&b[n..]));
                            }
                            let hex = &b[n + 2..n + 6];
                            if !hex.iter().all(u8::is_ascii_hexdigit) {
                                return Err(bad(&b[n..n + 6]));
                            }
                            let v =
                                u32::from_str_radix(std::str::from_utf8(hex).unwrap(), 16).unwrap();
                            n += 6;
                            if (0xD800..0xDC00).contains(&v) && b.len() >= n + 6 {
                                let lo = u32::from_str_radix(
                                    std::str::from_utf8(&b[n + 2..n + 6]).unwrap_or("0"),
                                    16,
                                )
                                .unwrap_or(0);
                                let cp = 0x10000
                                    + ((v - 0xD800) << 10)
                                    + (lo.wrapping_sub(0xDC00) & 0x3ff);
                                out.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
                                n += 6;
                            } else {
                                out.push(char::from_u32(v).unwrap_or('\u{fffd}'));
                            }
                        }
                        _ => return Err(bad(&b[n..n + 2])),
                    }
                }
                c if c < 0x20 => {
                    return Err(RawErr::Msg(invalid_text(
                        "character",
                        &self.char_at(n),
                        "in string (expecting non-control character)",
                    )))
                }
                _ => {
                    let ch = self.char_at(n);
                    n += ch.len();
                    out.push_str(&ch);
                }
            }
        }
    }

    /// jsonwire.ConsumeNumber.
    fn consume_number(&self, pos: usize) -> Result<usize, RawErr> {
        let b = self.b;
        let digit_err = |p: usize| {
            RawErr::Msg(invalid_text(
                "character",
                &self.char_at(p),
                "in number (expecting digit)",
            ))
        };
        let mut n = pos;
        if b[n] == b'-' {
            n += 1;
        }
        match b.get(n) {
            None => return Err(RawErr::UnexpectedEof),
            Some(b'0') => n += 1,
            Some(b'1'..=b'9') => {
                while b.get(n).is_some_and(u8::is_ascii_digit) {
                    n += 1;
                }
            }
            Some(_) => return Err(digit_err(n)),
        }
        if b.get(n) == Some(&b'.') {
            n += 1;
            match b.get(n) {
                None => return Err(RawErr::UnexpectedEof),
                Some(d) if d.is_ascii_digit() => {}
                Some(_) => return Err(digit_err(n)),
            }
            while b.get(n).is_some_and(u8::is_ascii_digit) {
                n += 1;
            }
        }
        if matches!(b.get(n), Some(b'e' | b'E')) {
            n += 1;
            if matches!(b.get(n), Some(b'+' | b'-')) {
                n += 1;
            }
            match b.get(n) {
                None => return Err(RawErr::UnexpectedEof),
                Some(d) if d.is_ascii_digit() => {}
                Some(_) => return Err(digit_err(n)),
            }
            while b.get(n).is_some_and(u8::is_ascii_digit) {
                n += 1;
            }
        }
        Ok(n)
    }

    /// v1 `json.Decoder.Token`.
    fn token(&mut self) -> Result<Tok, String> {
        if let Some(e) = &self.err {
            return Err(e.clone());
        }
        match self.read_token() {
            Ok(t) => Ok(t),
            Err(RawErr::Eof) => Err("EOF".into()),
            Err(RawErr::UnexpectedEof) => {
                let unread = &self.b[self.prev_end..];
                if unread.iter().all(|c| b" \r\n\t,:".contains(c)) {
                    Err("EOF".into())
                } else {
                    Err("unexpected EOF".into())
                }
            }
            Err(RawErr::Msg(m)) => Err(transform(&m)),
        }
    }

    /// v1 `json.Decoder.More`.
    fn more(&mut self) -> bool {
        if self.err.is_some() {
            return true;
        }
        match self.scan_next() {
            Ok((_, k)) => k != b']' && k != b'}',
            Err(RawErr::Eof) => {
                self.err = Some("EOF".into());
                false
            }
            Err(RawErr::UnexpectedEof) => {
                self.err = Some("unexpected end of JSON input".into());
                true
            }
            Err(RawErr::Msg(m)) => {
                self.err = Some(transform(&m));
                true
            }
        }
    }

    fn check_value(&mut self, depth: usize) -> Result<(), String> {
        if depth > NESTING_LIMIT {
            return Err("JSON nesting limit".into());
        }
        let open = match self.token()? {
            Tok::Delim(c @ (b'{' | b'[')) => c,
            _ => return Ok(()),
        };
        if open == b'{' {
            let mut keys = std::collections::HashSet::new();
            while self.more() {
                match self.token()? {
                    Tok::Str(k) if keys.insert(k.clone()) => {}
                    _ => return Err("duplicate JSON key".into()),
                }
                self.check_value(depth + 1)?;
            }
        } else {
            while self.more() {
                self.check_value(depth + 1)?;
            }
        }
        self.token().map(|_| ())
    }
}

fn check_surrogates(b: &[u8]) -> Result<(), String> {
    let hex4 = |i: usize| -> Option<u32> {
        if i + 6 > b.len() || b[i] != b'\\' || b[i + 1] != b'u' {
            return None;
        }
        u32::from_str_radix(std::str::from_utf8(&b[i + 2..i + 6]).ok()?, 16).ok()
    };
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\\' {
            i += 1;
            continue;
        }
        let Some(r) = hex4(i) else {
            i += 2;
            continue;
        };
        if (0xD800..=0xDBFF).contains(&r) {
            match hex4(i + 6) {
                Some(lo) if (0xDC00..=0xDFFF).contains(&lo) => i += 12,
                _ => return Err("JSON string has an unpaired UTF-16 surrogate escape".into()),
            }
        } else if (0xDC00..=0xDFFF).contains(&r) {
            return Err("JSON string has an unpaired UTF-16 surrogate escape".into());
        } else {
            i += 6;
        }
    }
    Ok(())
}

pub fn decode_json_precheck(b: &[u8], limit: usize) -> Result<(), String> {
    if b.len() > limit || std::str::from_utf8(b).is_err() {
        return Err("JSON limit or UTF-8 violation".into());
    }
    check_surrogates(b)?;
    let mut d = Dec {
        b,
        prev_end: 0,
        last: Entry {
            kind: Kind::Top,
            len: 0,
        },
        stack: Vec::new(),
        err: None,
    };
    d.check_value(0)?;
    match d.token() {
        Err(e) if e == "EOF" => Ok(()),
        _ => Err("trailing JSON".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::decode_json_precheck as check;

    fn err(s: &str) -> String {
        check(s.as_bytes(), 1 << 20).unwrap_err()
    }

    #[test]
    fn spec_decode_json_error_texts() {
        let cases: &[(&str, &str)] = &[
            (
                "{bad",
                "invalid character 'b' looking for beginning of value",
            ),
            ("", "EOF"),
            ("{", "unexpected end of JSON input"),
            ("{\"a\"", "EOF"),
            ("{\"a\":", "EOF"),
            ("{\"a\":\"x", "unexpected EOF"),
            ("{\"a\":tru", "unexpected EOF"),
            ("{\"a\" 1}", "invalid character '1' after object key"),
            (
                "{\"a\":1 \"b\":2}",
                "invalid character '\"' after object key:value pair",
            ),
            ("[1 2]", "invalid character '2' after array element"),
            (
                "{\"a\":x}",
                "invalid character 'x' looking for beginning of value",
            ),
            (
                "{\"a\":tx}",
                "invalid character 'x' in literal true (expecting 'r')",
            ),
            ("{\"a\":-x}", "invalid character 'x' in numeric literal"),
            ("{\"a\":\"\\q\"}", "invalid escape sequence `\\q` in string"),
            ("{\"a\":\"\n\"}", "invalid character '\\n' in string"),
            ("{\"a\":\"1\",\"a\":\"2\"}", "duplicate JSON key"),
            ("{} x", "trailing JSON"),
            ("{}{}", "trailing JSON"),
            (
                "\"\\ud800\"",
                "JSON string has an unpaired UTF-16 surrogate escape",
            ),
            (
                "{\"a\":1,bad",
                "invalid character 'b' looking for beginning of value",
            ),
            ("{\"a\":1.x}", "invalid character 'x' in numeric literal"),
            ("{\"a\":1e}", "invalid character '}' in numeric literal"),
            (
                "{\"a\":01}",
                "invalid character '1' after object key:value pair",
            ),
            ("   ", "EOF"),
            ("}", "invalid character '}' looking for beginning of value"),
            ("]", "invalid character ']' looking for beginning of value"),
            (
                "{\"a\":[1,]}",
                "invalid character ',' looking for beginning of value",
            ),
            (
                "{\"a\":\"\\u12g4\"}",
                "invalid escape sequence `\\u12g4` in string",
            ),
            (
                "{\"a\":nul}",
                "invalid character '}' in literal null (expecting 'l')",
            ),
            ("{\"a\":-}", "invalid character '}' in numeric literal"),
        ];
        for (input, want) in cases {
            assert_eq!(&err(input), want, "input {input:?}");
        }
        assert_eq!(err(&"[".repeat(40)), "JSON nesting limit");
        assert!(check(b"{\"A\":\"b\"}", 1 << 20).is_ok());
        assert!(check(b" [1, -2.5e3, true, null, {\"k\": []}] ", 1 << 20).is_ok());
        assert_eq!(
            check(b"{}", 1).unwrap_err(),
            "JSON limit or UTF-8 violation"
        );
    }
}
