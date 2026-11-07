//! Flow syntax: `{a: 1, b: [x, y]}`.
//!
//! Block syntax lives in the parent module; this is the other half of YAML's
//! two notations. A flow value may nest arbitrarily and may appear wherever a
//! scalar may appear (`endpoints: [{id: ep, url: "..."}]`), so the parser has
//! to share the scalar rules — hence `unquote_prefix` comes from the parent
//! rather than being reimplemented here.

use super::{nesting_limit_error, parse_plain_scalar, unquote_prefix, Yaml, MAX_NESTING_DEPTH};

pub(super) struct FlowParser<'a> {
    pub(super) chars: &'a [u8],
    pub(super) i: usize,
    pub(super) number: usize,
    pub(super) depth: usize,
}

impl<'a> FlowParser<'a> {
    pub(super) fn skip_ws(&mut self) {
        while self.i < self.chars.len()
            && (self.chars[self.i] == b' ' || self.chars[self.i] == b'\t')
        {
            self.i += 1;
        }
    }

    pub(super) fn value(&mut self) -> Result<Yaml, String> {
        self.skip_ws();
        match self.chars.get(self.i) {
            Some(b'&') => {
                let start = self.i + 1;
                while self.i < self.chars.len()
                    && !matches!(self.chars[self.i], b' ' | b'\t' | b',' | b'}' | b']')
                {
                    self.i += 1;
                }
                let name = std::str::from_utf8(&self.chars[start..self.i])
                    .map_err(|_| format!("line {}: invalid UTF-8", self.number))?
                    .to_string();
                if name.is_empty() || !matches!(self.chars.get(self.i), Some(b' ' | b'\t')) {
                    return Err(format!("line {}: YAML anchor has no value", self.number));
                }
                let v = self.value()?;
                super::define_anchor(&name, &v);
                Ok(v)
            }
            Some(b'{') => self.map(),
            Some(b'[') => self.seq(),
            Some(b'"') | Some(b'\'') => {
                let rest = std::str::from_utf8(&self.chars[self.i..])
                    .map_err(|_| format!("line {}: invalid UTF-8", self.number))?;
                let (s, used) = unquote_prefix(rest, self.number)?;
                self.i += used;
                Ok(Yaml::Str(s))
            }
            Some(_) => {
                let start = self.i;
                while self.i < self.chars.len() {
                    match self.chars[self.i] {
                        b',' | b'}' | b']' => break,
                        _ => self.i += 1,
                    }
                }
                let raw = std::str::from_utf8(&self.chars[start..self.i])
                    .map_err(|_| format!("line {}: invalid UTF-8", self.number))?
                    .trim();
                parse_plain_scalar(raw, self.number)
            }
            None => Err(format!(
                "line {}: unexpected end of flow value",
                self.number
            )),
        }
    }

    fn map(&mut self) -> Result<Yaml, String> {
        if self.depth >= MAX_NESTING_DEPTH {
            return Err(nesting_limit_error(self.number));
        }
        self.i += 1; // '{'
        let mut fields: Vec<(String, Yaml)> = Vec::new();
        self.skip_ws();
        if self.chars.get(self.i) == Some(&b'}') {
            self.i += 1;
            return Ok(Yaml::Map(fields));
        }
        loop {
            self.skip_ws();
            let key = match self.chars.get(self.i) {
                Some(b'"') | Some(b'\'') => {
                    let rest = std::str::from_utf8(&self.chars[self.i..])
                        .map_err(|_| format!("line {}: invalid UTF-8", self.number))?;
                    let (s, used) = unquote_prefix(rest, self.number)?;
                    self.i += used;
                    s
                }
                _ => {
                    let start = self.i;
                    while self.i < self.chars.len() && self.chars[self.i] != b':' {
                        self.i += 1;
                    }
                    std::str::from_utf8(&self.chars[start..self.i])
                        .map_err(|_| format!("line {}: invalid UTF-8", self.number))?
                        .trim()
                        .to_string()
                }
            };
            if self.chars.get(self.i) != Some(&b':') {
                return Err(format!(
                    "line {}: expected ':' in flow mapping",
                    self.number
                ));
            }
            self.i += 1;
            self.depth += 1;
            let value_result = self.value();
            self.depth -= 1;
            let value = value_result?;
            if fields.iter().any(|(k, _)| *k == key) {
                return Err(format!("line {}: duplicate key {key:?}", self.number));
            }
            fields.push((key, value));
            self.skip_ws();
            match self.chars.get(self.i) {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Yaml::Map(fields));
                }
                _ => return Err(format!("line {}: expected ',' or '}}'", self.number)),
            }
        }
    }

    fn seq(&mut self) -> Result<Yaml, String> {
        if self.depth >= MAX_NESTING_DEPTH {
            return Err(nesting_limit_error(self.number));
        }
        self.i += 1; // '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.chars.get(self.i) == Some(&b']') {
            self.i += 1;
            return Ok(Yaml::Seq(items));
        }
        loop {
            self.depth += 1;
            let value_result = self.value();
            self.depth -= 1;
            items.push(value_result?);
            self.skip_ws();
            match self.chars.get(self.i) {
                Some(b',') => {
                    self.i += 1;
                }
                Some(b']') => {
                    self.i += 1;
                    return Ok(Yaml::Seq(items));
                }
                _ => return Err(format!("line {}: expected ',' or ']'", self.number)),
            }
        }
    }
}
