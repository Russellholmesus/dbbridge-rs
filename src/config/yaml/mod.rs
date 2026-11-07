use std::fmt;

mod flow;

use flow::FlowParser;

pub(super) const MAX_NESTING_DEPTH: usize = 32;

/// Upper bound on the number of nodes all aliases of one document may
/// expand to.
const ALIAS_EXPANSION_LIMIT: usize = 1_000_000;

thread_local! {
    static ANCHORS: std::cell::RefCell<std::collections::HashMap<String, Yaml>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
    static EXPANDED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn node_count(v: &Yaml) -> usize {
    match v {
        Yaml::Seq(items) => 1 + items.iter().map(node_count).sum::<usize>(),
        Yaml::Map(fields) => 1 + fields.iter().map(|(_, v)| node_count(v)).sum::<usize>(),
        _ => 1,
    }
}

fn valid_anchor_name(name: &str) -> bool {
    !name.is_empty()
        && !name
            .chars()
            .any(|c| c.is_whitespace() || ",[]{}".contains(c))
}

/// Records `&name` for `value` (a later anchor of the same name wins, as in YAML).
pub(super) fn define_anchor(name: &str, value: &Yaml) {
    ANCHORS.with(|a| a.borrow_mut().insert(name.to_string(), value.clone()));
}

/// Resolves `*name`, charging its size to the document's expansion budget.
pub(super) fn resolve_alias(name: &str, number: usize) -> Result<Yaml, String> {
    if !valid_anchor_name(name) {
        return Err(format!("line {number}: invalid YAML alias"));
    }
    let value = ANCHORS
        .with(|a| a.borrow().get(name).cloned())
        .ok_or_else(|| format!("line {number}: unknown anchor '{name}' referenced"))?;
    let total = EXPANDED.with(|e| {
        let total = e.get().saturating_add(node_count(&value));
        e.set(total);
        total
    });
    if total > ALIAS_EXPANSION_LIMIT {
        return Err(format!(
            "line {number}: YAML alias expansion limit exceeded"
        ));
    }
    Ok(value)
}

/// Splits a leading `&name ` off `text`, returning the name and the rest.
fn split_anchor(text: &str, number: usize) -> Result<Option<(&str, &str)>, String> {
    let Some(rest) = text.strip_prefix('&') else {
        return Ok(None);
    };
    let Some(split) = rest.find(char::is_whitespace) else {
        return Err(format!("line {number}: YAML anchor has no value"));
    };
    let name = &rest[..split];
    if !valid_anchor_name(name) {
        return Err(format!("line {number}: invalid YAML anchor"));
    }
    let value = rest[split..].trim_start();
    if value.is_empty() {
        return Err(format!("line {number}: YAML anchor has no value"));
    }
    Ok(Some((name, value)))
}

pub(super) fn nesting_limit_error(number: usize) -> String {
    format!("line {number}: Error [DBB-CFG-001]: YAML nesting limit exceeded")
}

#[derive(Debug, Clone, PartialEq)]
pub enum Yaml {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Seq(Vec<Yaml>),
    Map(Vec<(String, Yaml)>),
}

const FLOAT_PREFIX: &str = "\u{0}dbbridge-yaml-float:";

pub(super) fn is_float_scalar(s: &str) -> bool {
    s.starts_with(FLOAT_PREFIX)
}

pub(super) fn float_scalar_value(s: &str) -> Option<&str> {
    s.strip_prefix(FLOAT_PREFIX)
}

impl Yaml {
    pub fn get(&self, key: &str) -> Option<&Yaml> {
        match self {
            Yaml::Map(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Yaml::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Yaml::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_seq(&self) -> Option<&[Yaml]> {
        match self {
            Yaml::Seq(s) => Some(s),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Yaml::Null)
    }

    /// A string field, with `Int`/`Bool` accepted as their literal text so a
    /// port like `listen: 8080` still reads as a string.
    pub fn str_of(&self, key: &str) -> Option<String> {
        match self.get(key)? {
            Yaml::Str(s) => Some(float_scalar_value(s).unwrap_or(s).to_string()),
            Yaml::Int(i) => Some(i.to_string()),
            Yaml::Bool(b) => Some(b.to_string()),
            _ => None,
        }
    }

    pub fn bool_of(&self, key: &str) -> Option<bool> {
        self.get(key).and_then(Yaml::as_bool)
    }

    pub fn i64_of(&self, key: &str) -> Option<i64> {
        match self.get(key)? {
            Yaml::Int(i) => Some(*i),
            Yaml::Str(s) => s.parse().ok(),
            _ => None,
        }
    }

    pub fn seq_of(&self, key: &str) -> Option<&[Yaml]> {
        self.get(key).and_then(Yaml::as_seq)
    }
}

impl fmt::Display for Yaml {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Yaml::Null => f.write_str("null"),
            Yaml::Bool(b) => write!(f, "{b}"),
            Yaml::Int(i) => write!(f, "{i}"),
            Yaml::Str(s) => write!(f, "{:?}", float_scalar_value(s).unwrap_or(s)),
            Yaml::Seq(items) => {
                let parts: Vec<String> = items.iter().map(|v| v.to_string()).collect();
                write!(f, "[{}]", parts.join(", "))
            }
            Yaml::Map(fields) => {
                let parts: Vec<String> = fields.iter().map(|(k, v)| format!("{k}: {v}")).collect();
                write!(f, "{{{}}}", parts.join(", "))
            }
        }
    }
}

#[derive(Debug, Clone)]
struct Line {
    indent: usize,
    text: String,
    number: usize,
}

/// Parses a whole document.
pub fn parse(input: &str) -> Result<Yaml, String> {
    ANCHORS.with(|a| a.borrow_mut().clear());
    EXPANDED.with(|e| e.set(0));
    let mut lines = Vec::new();
    let mut document_started = false;
    let mut document_ended = false;
    let mut content_seen = false;
    for (idx, raw) in input.lines().enumerate() {
        let number = idx + 1;
        let marker = raw.trim();
        if marker == "---" {
            if document_started || content_seen || document_ended {
                return Err("configuration must contain exactly one YAML document".into());
            }
            document_started = true;
            continue;
        }
        if marker == "..." {
            if document_ended {
                return Err("configuration must contain exactly one YAML document".into());
            }
            document_ended = true;
            continue;
        }
        if document_ended {
            if !marker.is_empty() && !marker.starts_with('#') {
                return Err("configuration must contain exactly one YAML document".into());
            }
            continue;
        }
        if raw.trim().is_empty() {
            continue;
        }
        if raw.trim_start().starts_with('#') {
            continue;
        }
        let stripped = strip_comment(raw);
        if stripped.trim().is_empty() {
            continue;
        }
        content_seen = true;
        let content = stripped.trim_start_matches([' ', '\t']);
        let leading = &stripped[..stripped.len() - content.len()];
        if leading.contains('\t') {
            return Err(format!("line {number}: tab in indentation"));
        }
        lines.push(Line {
            indent: leading.len(),
            text: content.trim_end().to_string(),
            number,
        });
    }
    if lines.is_empty() {
        return Ok(Yaml::Null);
    }
    let base = lines[0].indent;
    let mut pos = 0usize;
    let value = parse_block(&mut lines, &mut pos, base, 0)?;
    if pos != lines.len() {
        return Err(format!(
            "line {}: unexpected content (indentation mismatch)",
            lines[pos].number
        ));
    }
    Ok(value)
}

const BOOL_KEYS: &[&str] = &[
    "enabled",
    "verify",
    "allow_insecure_skip_verify",
    "allow_insecure_http",
    "allow_insecure_listen",
    "allow_remote",
];

pub(super) fn reject_explicit_null(doc: &Yaml) -> Result<(), String> {
    fn visit(value: &Yaml, path: &str, map_keys_are_names: bool) -> Result<(), String> {
        match value {
            Yaml::Null => Err(format!(
                "{path}: explicit null is not allowed; omit optional fields"
            )),
            Yaml::Seq(items) => {
                for (index, item) in items.iter().enumerate() {
                    visit(item, &format!("{path}[{index}]"), false)?;
                }
                Ok(())
            }
            Yaml::Map(fields) => {
                for (key, item) in fields {
                    let child = format!("{path}.{key}");
                    if matches!(item, Yaml::Null) {
                        return visit(item, &child, false);
                    }
                    if !map_keys_are_names
                        && BOOL_KEYS.contains(&key.as_str())
                        && !matches!(item, Yaml::Bool(_))
                    {
                        return Err(format!("{child} must be a boolean"));
                    }
                    let names = !map_keys_are_names && path == "config" && key == "targets";
                    visit(item, &child, names)?;
                }
                Ok(())
            }
            Yaml::Bool(_) | Yaml::Int(_) | Yaml::Str(_) => Ok(()),
        }
    }
    visit(doc, "config", false)
}

/// Removes a trailing `#` comment, honouring quotes.
fn strip_comment(s: &str) -> &str {
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let c = bytes[i];
        match quote {
            Some(q) => {
                if q == b'"' && c == b'\\' {
                    i += 2;
                    continue;
                }
                if c == q {
                    quote = None;
                }
            }
            None => {
                if (c == b'"' || c == b'\'')
                    && (i == 0
                        || bytes[i - 1].is_ascii_whitespace()
                        || matches!(bytes[i - 1], b':' | b',' | b'[' | b'{'))
                {
                    quote = Some(c);
                } else if c == b'#' && (i == 0 || bytes[i - 1] == b' ' || bytes[i - 1] == b'\t') {
                    return &s[..i];
                }
            }
        }
        i += 1;
    }
    s
}

fn parse_block(
    lines: &mut Vec<Line>,
    pos: &mut usize,
    indent: usize,
    depth: usize,
) -> Result<Yaml, String> {
    if *pos >= lines.len() {
        return Ok(Yaml::Null);
    }
    if lines[*pos].indent < indent {
        return Ok(Yaml::Null);
    }
    if is_seq_item(&lines[*pos].text) {
        parse_seq(lines, pos, indent, depth)
    } else {
        parse_map(lines, pos, indent, depth)
    }
}

fn is_seq_item(text: &str) -> bool {
    text == "-" || text.starts_with("- ")
}

fn parse_seq(
    lines: &mut Vec<Line>,
    pos: &mut usize,
    indent: usize,
    depth: usize,
) -> Result<Yaml, String> {
    if depth >= MAX_NESTING_DEPTH {
        let number = lines.get(*pos).map(|line| line.number).unwrap_or(0);
        return Err(nesting_limit_error(number));
    }
    let mut items = Vec::new();
    while *pos < lines.len() {
        let line = &lines[*pos];
        if line.indent != indent || !is_seq_item(&line.text) {
            break;
        }
        let number = line.number;
        let rest = line.text[1..].trim_start().to_string();
        if rest.is_empty() {
            *pos += 1;
            let next_indent = lines.get(*pos).map(|l| l.indent).unwrap_or(indent);
            if *pos < lines.len() && next_indent > indent {
                items.push(parse_block(lines, pos, next_indent, depth + 1)?);
            } else {
                items.push(Yaml::Null);
            }
            continue;
        }
        // `- key: value` starts a mapping whose keys align after the dash; the
        // line is rewritten at that indent so the map parser sees it as the
        // first key of the block.
        if starts_mapping(&rest) {
            let item_indent = indent + (line.text.len() - rest.len()).max(2);
            lines[*pos] = Line {
                indent: item_indent,
                text: rest,
                number,
            };
            items.push(parse_map(lines, pos, item_indent, depth + 1)?);
        } else {
            items.push(parse_scalar(&rest, number, depth + 1)?);
            *pos += 1;
        }
    }
    Ok(Yaml::Seq(items))
}

fn starts_mapping(text: &str) -> bool {
    if text.starts_with('{') || text.starts_with('[') {
        return false;
    }
    split_key(text).is_some()
}

/// Splits `key: rest` at the first colon outside quotes that is followed by a
/// space or the end of the line.
fn split_key(text: &str) -> Option<(String, String)> {
    let bytes = text.as_bytes();
    let mut i = 0;
    let mut quote: Option<u8> = None;
    while i < bytes.len() {
        let c = bytes[i];
        match quote {
            Some(q) => {
                if q == b'"' && c == b'\\' {
                    i += 2;
                    continue;
                }
                if c == q {
                    quote = None;
                }
            }
            None => {
                if c == b'"' || c == b'\'' {
                    quote = Some(c);
                } else if c == b':' && (i + 1 == bytes.len() || bytes[i + 1] == b' ') {
                    let key = unquote(text[..i].trim());
                    let rest = text[i + 1..].trim().to_string();
                    return Some((key, rest));
                }
            }
        }
        i += 1;
    }
    None
}

fn parse_map(
    lines: &mut Vec<Line>,
    pos: &mut usize,
    indent: usize,
    depth: usize,
) -> Result<Yaml, String> {
    if depth >= MAX_NESTING_DEPTH {
        let number = lines.get(*pos).map(|line| line.number).unwrap_or(0);
        return Err(nesting_limit_error(number));
    }
    let mut fields: Vec<(String, Yaml)> = Vec::new();
    while *pos < lines.len() {
        let line = &lines[*pos];
        if line.indent < indent {
            break;
        }
        if line.indent > indent {
            return Err(format!(
                "line {}: unexpected indentation (expected {} spaces)",
                line.number, indent
            ));
        }
        if is_seq_item(&line.text) {
            break;
        }
        let number = line.number;
        let text = line.text.clone();
        let (key, rest) =
            split_key(&text).ok_or_else(|| format!("line {number}: expected `key: value`"))?;
        if key.is_empty() {
            return Err(format!("line {number}: empty mapping key"));
        }
        if fields.iter().any(|(k, _)| *k == key) {
            return Err(format!("line {number}: duplicate key {key:?}"));
        }
        *pos += 1;
        if rest.is_empty() {
            let next_indent = lines.get(*pos).map(|l| l.indent).unwrap_or(0);
            if *pos < lines.len() && next_indent > indent {
                fields.push((key, parse_block(lines, pos, next_indent, depth + 1)?));
            } else if *pos < lines.len() && next_indent == indent && is_seq_item(&lines[*pos].text)
            {
                // A sequence may sit at the same indent as its parent key.
                fields.push((key, parse_seq(lines, pos, indent, depth + 1)?));
            } else {
                fields.push((key, Yaml::Null));
            }
        } else {
            fields.push((key, parse_scalar(&rest, number, depth + 1)?));
        }
    }
    Ok(Yaml::Map(fields))
}

fn parse_scalar(text: &str, number: usize, depth: usize) -> Result<Yaml, String> {
    let text = text.trim();
    if let Some((name, value)) = split_anchor(text, number)? {
        let v = parse_scalar(value, number, depth)?;
        define_anchor(name, &v);
        return Ok(v);
    }
    if text.starts_with('{') || text.starts_with('[') {
        let mut p = FlowParser {
            chars: text.as_bytes(),
            i: 0,
            number,
            depth,
        };
        let v = p.value()?;
        p.skip_ws();
        if p.i != p.chars.len() {
            return Err(format!("line {number}: trailing content after flow value"));
        }
        return Ok(v);
    }
    if text.starts_with('"') || text.starts_with('\'') {
        let (s, used) = unquote_prefix(text, number)?;
        if !text[used..].trim().is_empty() {
            return Err(format!(
                "line {number}: trailing content after quoted string"
            ));
        }
        return Ok(Yaml::Str(s));
    }
    parse_plain_scalar(text, number)
}

pub(super) fn parse_plain_scalar(text: &str, number: usize) -> Result<Yaml, String> {
    let text = text.trim();
    if let Some((name, value)) = split_anchor(text, number)? {
        let v = parse_plain_scalar(value, number)?;
        define_anchor(name, &v);
        return Ok(v);
    }
    if let Some(name) = text.strip_prefix('*') {
        return resolve_alias(name, number);
    }
    if text.starts_with('%') {
        return Err(format!(
            "line {number}: unexpected YAML directive token {text:?}"
        ));
    }
    if is_yaml_float(text) {
        return Ok(Yaml::Str(format!("{FLOAT_PREFIX}{text}")));
    }
    Ok(match text {
        "" | "~" | "null" | "Null" | "NULL" => Yaml::Null,
        "true" | "True" | "TRUE" => Yaml::Bool(true),
        "false" | "False" | "FALSE" => Yaml::Bool(false),
        t => match t.parse::<i64>() {
            Ok(i) => Yaml::Int(i),
            Err(_) => Yaml::Str(t.to_string()),
        },
    })
}

fn is_yaml_float(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    if matches!(lower.as_str(), ".nan" | ".inf" | "+.inf" | "-.inf") {
        return true;
    }
    if !text.contains('.') && !lower.contains('e') {
        return false;
    }
    text.parse::<f64>().is_ok()
}

fn unquote(s: &str) -> String {
    unquote_prefix(s, 0)
        .map(|(v, _)| v)
        .unwrap_or_else(|_| s.to_string())
}

/// Decodes a leading quoted string, returning it and the number of bytes used.
/// Private: `flow` is a child module, so it can reach this without widening the
/// module's own API.
fn unquote_prefix(s: &str, number: usize) -> Result<(String, usize), String> {
    let bytes = s.as_bytes();
    let quote = *bytes
        .first()
        .ok_or_else(|| format!("line {number}: empty quoted string"))?;
    let mut out = String::new();
    let mut i = 1;
    while i < bytes.len() {
        let c = bytes[i];
        if quote == b'\'' {
            if c == b'\'' {
                if bytes.get(i + 1) == Some(&b'\'') {
                    out.push('\'');
                    i += 2;
                    continue;
                }
                return Ok((out, i + 1));
            }
            let rest = std::str::from_utf8(&bytes[i..])
                .map_err(|_| format!("line {number}: invalid UTF-8 in string"))?;
            let ch = rest
                .chars()
                .next()
                .ok_or_else(|| format!("line {number}: invalid UTF-8 in string"))?;
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }
        match c {
            b'"' => return Ok((out, i + 1)),
            b'\\' => {
                let e = *bytes
                    .get(i + 1)
                    .ok_or_else(|| format!("line {number}: unterminated escape"))?;
                i += 2;
                match e {
                    b'0' => out.push('\0'),
                    b'a' => out.push('\u{7}'),
                    b'b' => out.push('\u{8}'),
                    b'n' => out.push('\n'),
                    b't' => out.push('\t'),
                    b'v' => out.push('\u{b}'),
                    b'f' => out.push('\u{c}'),
                    b'r' => out.push('\r'),
                    b'e' => out.push('\u{1b}'),
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b' ' => out.push(' '),
                    b'N' => out.push('\u{85}'),
                    b'_' => out.push('\u{a0}'),
                    b'L' => out.push('\u{2028}'),
                    b'P' => out.push('\u{2029}'),
                    b'x' => out.push(decode_escape(bytes, &mut i, 2, number)?),
                    b'u' => out.push(decode_escape(bytes, &mut i, 4, number)?),
                    b'U' => out.push(decode_escape(bytes, &mut i, 8, number)?),
                    other => {
                        return Err(format!("line {number}: unknown escape \\{}", other as char))
                    }
                }
            }
            _ => {
                let len = match c {
                    0x00..=0x7f => 1,
                    0xc0..=0xdf => 2,
                    0xe0..=0xef => 3,
                    _ => 4,
                };
                let end = (i + len).min(bytes.len());
                out.push_str(
                    std::str::from_utf8(&bytes[i..end])
                        .map_err(|_| format!("line {number}: invalid UTF-8 in string"))?,
                );
                i = end;
            }
        }
    }
    Err(format!("line {number}: unterminated quoted string"))
}

fn decode_escape(
    bytes: &[u8],
    i: &mut usize,
    digits: usize,
    number: usize,
) -> Result<char, String> {
    let end = i
        .checked_add(digits)
        .ok_or_else(|| format!("line {number}: invalid escape"))?;
    if end > bytes.len() {
        return Err(format!("line {number}: incomplete Unicode escape"));
    }
    let mut value = 0u32;
    for &b in &bytes[*i..end] {
        value = value * 16
            + (b as char)
                .to_digit(16)
                .ok_or_else(|| format!("line {number}: invalid hex escape"))?;
    }
    *i = end;
    if (0xd800..=0xdfff).contains(&value) || value > 0x10ffff {
        return Err(format!("line {number}: invalid Unicode code point"));
    }
    char::from_u32(value).ok_or_else(|| format!("line {number}: invalid Unicode code point"))
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

    fn run_yaml_fuzz(iterations: usize) {
        let mut rng = FuzzRng(0xb70e_2a63_491d_f8c5);
        for iteration in 0..iterations {
            let bytes = rng.bytes(128);
            let text = String::from_utf8_lossy(&bytes);
            let input = match iteration % 4 {
                0 => text.into_owned(),
                1 => format!("fuzz: {text}\n"),
                2 => format!("fuzz: [{text}]\n"),
                _ => format!("fuzz: {{{text}}}\n"),
            };
            assert!(input.len() <= 416, "fuzz input must stay bounded");
            let _ = parse(&input);
        }
    }

    #[test]
    fn fuzz_yaml_parser() {
        run_yaml_fuzz(100_000);
    }

    #[test]
    #[ignore = "one-million iteration parser fuzz run"]
    fn fuzz_yaml_parser_long() {
        run_yaml_fuzz(1_000_000);
    }

    #[test]
    fn parses_nested_config() {
        let src = r#"
node:
  id: plant-a
http:
  enabled: false
  listen: "127.0.0.1:18082"
peers:
  - id: hq-b
    expected_node_id: hq-b
    endpoints:
      - {id: ep, url: "http://127.0.0.1:18080", priority: 1}
    failover: {enabled: true, strategy: priority}
listeners:
  - id: mysql-local
    listen: "127.0.0.1:13306"
    peer: hq-b
    target: mysql-primary
targets:
  mysql-primary:
    address: "127.0.0.1:3306"
    allowed_cidrs: ["127.0.0.1/32"]
transport:
  frame_size: 32768
  heartbeat: 15s
  recovery:
    enabled: true
    grace: 30s
"#;
        let doc = parse(src).unwrap();
        assert_eq!(doc.get("node").unwrap().str_of("id").unwrap(), "plant-a");
        assert!(!doc.get("http").unwrap().bool_of("enabled").unwrap());
        let peers = doc.seq_of("peers").unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].str_of("id").unwrap(), "hq-b");
        let eps = peers[0].seq_of("endpoints").unwrap();
        assert_eq!(eps[0].str_of("url").unwrap(), "http://127.0.0.1:18080");
        assert_eq!(eps[0].i64_of("priority").unwrap(), 1);
        assert!(peers[0]
            .get("failover")
            .unwrap()
            .bool_of("enabled")
            .unwrap());
        assert_eq!(
            doc.get("targets")
                .unwrap()
                .get("mysql-primary")
                .unwrap()
                .seq_of("allowed_cidrs")
                .unwrap()[0]
                .as_str()
                .unwrap(),
            "127.0.0.1/32"
        );
        let t = doc.get("transport").unwrap();
        assert_eq!(t.i64_of("frame_size").unwrap(), 32768);
        assert_eq!(t.str_of("heartbeat").unwrap(), "15s");
        assert!(t.get("recovery").unwrap().bool_of("enabled").unwrap());
    }

    #[test]
    fn rejects_bad_shapes() {
        assert!(parse("a:\n\tb: 1\n").is_err());
        assert!(parse("a: 1\na: 2\n").is_err());
        assert!(parse("a:\n    b: 1\n  c: 2\n").is_err());
    }

    #[test]
    fn empty_mapping_key_is_an_error_not_a_panic() {
        assert!(parse(":\n").unwrap_err().contains("empty mapping key"));
        assert!(unquote_prefix("", 1)
            .unwrap_err()
            .contains("empty quoted string"));
    }

    #[test]
    fn deep_flow_nesting_is_an_error() {
        let src = format!("k: {}", "[".repeat(50_000));
        let error = parse(&src).expect_err("deep flow nesting must be rejected");
        assert!(error.contains("DBB-CFG-001"));
        assert!(error.contains("YAML nesting limit"));
    }

    #[test]
    fn strips_comments_but_not_inside_quotes() {
        let doc = parse("url: \"http://x/#frag\" # trailing\n").unwrap();
        assert_eq!(doc.str_of("url").unwrap(), "http://x/#frag");
    }

    #[test]
    fn single_quoted_utf8() {
        let doc = parse("s: '你好，世界''s'\n").unwrap();
        assert_eq!(doc.str_of("s").unwrap(), "你好，世界's");
    }

    #[test]
    fn flow_and_block_literals_agree() {
        let doc = parse("block: [true, FALSE, null, ~, 42, hello]\nflow: {a: true, b: FALSE, c: null, d: ~, e: 42, f: hello}\n").unwrap();
        assert_eq!(
            doc.get("block").unwrap().as_seq().unwrap(),
            &[
                Yaml::Bool(true),
                Yaml::Bool(false),
                Yaml::Null,
                Yaml::Null,
                Yaml::Int(42),
                Yaml::Str("hello".into())
            ]
        );
        assert_eq!(doc.get("flow").unwrap().get("b"), Some(&Yaml::Bool(false)));
    }

    #[test]
    fn apostrophe_does_not_hide_comment() {
        let doc = parse("value: don't # comment\n").unwrap();
        assert_eq!(doc.str_of("value").unwrap(), "don't");
    }

    #[test]
    fn double_quoted_unicode_escapes() {
        let doc = parse(r#"s: "\u4F60\x20\U00004E16""#).unwrap();
        assert_eq!(doc.str_of("s").unwrap(), "你 世");
        assert!(parse(r#"s: "\q""#).is_err());
        assert!(parse(r#"s: "\uD800""#).is_err());
    }
}
