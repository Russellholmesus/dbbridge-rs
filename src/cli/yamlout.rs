//! The part of `gopkg.in/yaml.v3`'s encoder (`SetIndent(2)`, block style)
//! that `gen-config` needs: maps with yaml.v3's key order, sequences, and
//! scalars quoted exactly when yaml.v3 would quote them.

use std::cmp::Ordering;

#[derive(Clone, Debug)]
pub enum Node {
    Map(Vec<(String, Node)>),
    Seq(Vec<Node>),
    Str(String),
    Int(i64),
    Bool(bool),
}

impl Node {
    pub fn str(s: impl Into<String>) -> Node {
        Node::Str(s.into())
    }
    pub fn map(items: Vec<(&str, Node)>) -> Node {
        Node::Map(items.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }
    pub fn strs(items: &[String]) -> Node {
        Node::Seq(items.iter().map(|s| Node::Str(s.clone())).collect())
    }
    /// Inserts or replaces `key` in a map node.
    pub fn set(&mut self, key: &str, value: Node) {
        if let Node::Map(items) = self {
            if let Some(slot) = items.iter_mut().find(|(k, _)| k == key) {
                slot.1 = value;
            } else {
                items.push((key.to_string(), value));
            }
        }
    }
    pub fn get_mut(&mut self, key: &str) -> Option<&mut Node> {
        match self {
            Node::Map(items) => items.iter_mut().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
}

/// Encodes a document the way `yaml.NewEncoder` + `SetIndent(2)` does.
pub fn encode(doc: &Node) -> String {
    let mut out = String::new();
    match doc {
        Node::Map(_) | Node::Seq(_) => emit_block(doc, 0, &mut out),
        scalar => {
            out.push_str(&scalar_text(scalar));
            out.push('\n');
        }
    }
    out
}

fn is_empty_collection(node: &Node) -> bool {
    matches!(node, Node::Map(m) if m.is_empty()) || matches!(node, Node::Seq(s) if s.is_empty())
}

fn flow_empty(node: &Node) -> &'static str {
    if matches!(node, Node::Map(_)) {
        "{}"
    } else {
        "[]"
    }
}

fn emit_block(node: &Node, indent: usize, out: &mut String) {
    let pad = " ".repeat(indent);
    match node {
        Node::Map(items) => {
            let mut sorted: Vec<&(String, Node)> = items.iter().collect();
            sorted.sort_by(|a, b| key_cmp(&a.0, &b.0));
            for (key, value) in sorted {
                out.push_str(&pad);
                emit_entry(key, value, indent, out);
            }
        }
        Node::Seq(items) => {
            for item in items {
                out.push_str(&pad);
                emit_seq_item(item, indent, out);
            }
        }
        scalar => {
            out.push_str(&pad);
            out.push_str(&scalar_text(scalar));
            out.push('\n');
        }
    }
}

/// `key: value` where the key is already indented.
fn emit_entry(key: &str, value: &Node, indent: usize, out: &mut String) {
    out.push_str(&scalar_text(&Node::Str(key.to_string())));
    out.push(':');
    match value {
        v if is_empty_collection(v) => {
            out.push(' ');
            out.push_str(flow_empty(v));
            out.push('\n');
        }
        Node::Map(_) | Node::Seq(_) => {
            out.push('\n');
            emit_block(value, indent + 2, out);
        }
        scalar => {
            out.push(' ');
            out.push_str(&scalar_text(scalar));
            out.push('\n');
        }
    }
}

/// `- item` where the dash is already indented.
fn emit_seq_item(item: &Node, indent: usize, out: &mut String) {
    out.push_str("- ");
    match item {
        v if is_empty_collection(v) => {
            out.push_str(flow_empty(v));
            out.push('\n');
        }
        Node::Map(items) => {
            let mut sorted: Vec<&(String, Node)> = items.iter().collect();
            sorted.sort_by(|a, b| key_cmp(&a.0, &b.0));
            for (i, (key, value)) in sorted.into_iter().enumerate() {
                if i > 0 {
                    out.push_str(&" ".repeat(indent + 2));
                }
                emit_entry(key, value, indent + 2, out);
            }
        }
        Node::Seq(_) => {
            // yaml.v3 puts a nested sequence's first item on the dash line.
            let mut nested = String::new();
            emit_block(item, indent + 2, &mut nested);
            out.push_str(nested.trim_start());
        }
        scalar => {
            out.push_str(&scalar_text(scalar));
            out.push('\n');
        }
    }
}

fn scalar_text(node: &Node) -> String {
    match node {
        Node::Int(v) => v.to_string(),
        Node::Bool(v) => v.to_string(),
        Node::Str(s) => quote_string(s),
        _ => String::new(),
    }
}

/// yaml.v3 `encoder.stringv` followed by libyaml's style selection.
pub fn quote_string(s: &str) -> String {
    if s.contains('\n') {
        // Not produced by gen-config; keep it valid with double quotes.
        return double_quoted(s);
    }
    let ambiguous = resolves_to_non_string(s) || is_base60_float(s) || is_old_bool(s);
    if ambiguous {
        return double_quoted(s);
    }
    if plain_allowed(s) {
        return s.to_string();
    }
    if single_allowed(s) {
        return format!("'{}'", s.replace('\'', "''"));
    }
    double_quoted(s)
}

fn double_quoted(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '\0' => out.push_str("\\0"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\x{:02X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// yaml.v3 `resolve` for an untagged plain scalar: anything that is not
/// `!!str` (null, bool, int, float, merge) must be quoted.
fn resolves_to_non_string(s: &str) -> bool {
    match s {
        "" | "~" | "null" | "Null" | "NULL" => return true,
        "true" | "True" | "TRUE" | "false" | "False" | "FALSE" => return true,
        ".inf" | ".Inf" | ".INF" | "+.inf" | "+.Inf" | "+.INF" | "-.inf" | "-.Inf" | "-.INF" => {
            return true
        }
        ".nan" | ".NaN" | ".NAN" | "<<" => return true,
        _ => {}
    }
    let first = s.as_bytes()[0];
    if !(first == b'+' || first == b'-' || first == b'.' || first.is_ascii_digit()) {
        return false;
    }
    let plain: String = s.chars().filter(|c| *c != '_').collect();
    if crate::cli::flags::parse_spec_int(&plain).is_ok() {
        return true;
    }
    // ParseUint for values above i64::MAX.
    if !plain.is_empty() && plain.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    if is_yaml_float(&plain) {
        return true;
    }
    // yaml.v3 also resolves 0b/-0b binary and 0o octal.
    let unsigned = plain
        .strip_prefix('-')
        .or_else(|| plain.strip_prefix('+'))
        .unwrap_or(&plain);
    if let Some(bits) = unsigned.strip_prefix("0b") {
        return !bits.is_empty() && bits.bytes().all(|b| b == b'0' || b == b'1');
    }
    if let Some(oct) = unsigned.strip_prefix("0o") {
        return !oct.is_empty() && oct.bytes().all(|b| (b'0'..=b'7').contains(&b));
    }
    false
}

/// `^[-+]?(\.[0-9]+|[0-9]+(\.[0-9]*)?)([eE][-+]?[0-9]+)?$`
fn is_yaml_float(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        i += 1;
    }
    let digits = |i: &mut usize| {
        let start = *i;
        while *i < b.len() && b[*i].is_ascii_digit() {
            *i += 1;
        }
        *i - start
    };
    if i < b.len() && b[i] == b'.' {
        i += 1;
        if digits(&mut i) == 0 {
            return false;
        }
    } else {
        if digits(&mut i) == 0 {
            return false;
        }
        if i < b.len() && b[i] == b'.' {
            i += 1;
            digits(&mut i);
        }
    }
    if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
        i += 1;
        if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
            i += 1;
        }
        if digits(&mut i) == 0 {
            return false;
        }
    }
    i == b.len()
}

/// `^[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+(?:\.[0-9_]*)?$`
fn is_base60_float(s: &str) -> bool {
    let b = s.as_bytes();
    let mut i = 0;
    if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
        i += 1;
    }
    if i >= b.len() || !b[i].is_ascii_digit() {
        return false;
    }
    i += 1;
    while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'_') {
        i += 1;
    }
    let mut groups = 0;
    while i < b.len() && b[i] == b':' {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() && i - start < 2 {
            i += 1;
        }
        let group = &b[start..i];
        let ok = match group.len() {
            1 => true,
            2 => group[0] <= b'5',
            _ => false,
        };
        if !ok {
            return false;
        }
        groups += 1;
    }
    if groups == 0 {
        return false;
    }
    if i < b.len() && b[i] == b'.' {
        i += 1;
        while i < b.len() && (b[i].is_ascii_digit() || b[i] == b'_') {
            i += 1;
        }
    }
    i == b.len()
}

fn is_old_bool(s: &str) -> bool {
    matches!(
        s,
        "y" | "Y"
            | "yes"
            | "Yes"
            | "YES"
            | "on"
            | "On"
            | "ON"
            | "n"
            | "N"
            | "no"
            | "No"
            | "NO"
            | "off"
            | "Off"
            | "OFF"
    )
}

fn is_blank(c: Option<char>) -> bool {
    matches!(c, None | Some(' ') | Some('\t') | Some('\r') | Some('\n'))
}

/// libyaml `yaml_emitter_analyze_scalar` → block plain allowed.
fn plain_allowed(s: &str) -> bool {
    if s.starts_with("---") || s.starts_with("...") {
        return false;
    }
    let chars: Vec<char> = s.chars().collect();
    if chars.first() == Some(&' ') || chars.last() == Some(&' ') {
        return false;
    }
    for (i, &c) in chars.iter().enumerate() {
        let next = chars.get(i + 1).copied();
        let prev = if i == 0 { None } else { Some(chars[i - 1]) };
        if !printable(c) {
            return false;
        }
        if i == 0 {
            match c {
                '#' | ',' | '[' | ']' | '{' | '}' | '&' | '*' | '!' | '|' | '>' | '\'' | '"'
                | '%' | '@' | '`' => return false,
                '?' | ':' | '-' if is_blank(next) => return false,
                _ => {}
            }
        } else {
            if c == ':' && is_blank(next) {
                return false;
            }
            if c == '#' && is_blank(prev) {
                return false;
            }
        }
        if c == '\t' {
            return false;
        }
    }
    true
}

fn single_allowed(s: &str) -> bool {
    s.chars().all(printable)
}

fn printable(c: char) -> bool {
    let v = c as u32;
    v == 0x9
        || v == 0xA
        || v == 0xD
        || (0x20..=0x7E).contains(&v)
        || v == 0x85
        || (0xA0..=0xD7FF).contains(&v)
        || ((0xE000..=0xFFFD).contains(&v) && v != 0xFEFF)
        || (0x10000..=0x10FFFF).contains(&v)
}

/// yaml.v3 `keyList.Less` for string keys.
pub fn key_cmp(a: &str, b: &str) -> Ordering {
    if key_less(a, b) {
        Ordering::Less
    } else if key_less(b, a) {
        Ordering::Greater
    } else {
        Ordering::Equal
    }
}

fn key_less(a: &str, b: &str) -> bool {
    let ar: Vec<char> = a.chars().collect();
    let br: Vec<char> = b.chars().collect();
    let mut digits = false;
    let mut i = 0;
    while i < ar.len() && i < br.len() {
        if ar[i] == br[i] {
            digits = ar[i].is_numeric();
            i += 1;
            continue;
        }
        let al = ar[i].is_alphabetic();
        let bl = br[i].is_alphabetic();
        if al && bl {
            return ar[i] < br[i];
        }
        if al || bl {
            return if digits { al } else { bl };
        }
        let (mut an, mut bn): (i64, i64) = (0, 0);
        if ar[i] == '0' || br[i] == '0' {
            let mut j = i;
            while j > 0 && ar[j - 1].is_numeric() {
                j -= 1;
                if ar[j] != '0' {
                    an = 1;
                    bn = 1;
                    break;
                }
            }
        }
        let mut ai = i;
        while ai < ar.len() && ar[ai].is_ascii_digit() {
            an = an.wrapping_mul(10).wrapping_add(ar[ai] as i64 - '0' as i64);
            ai += 1;
        }
        let mut bi = i;
        while bi < br.len() && br[bi].is_ascii_digit() {
            bn = bn.wrapping_mul(10).wrapping_add(br[bi] as i64 - '0' as i64);
            bi += 1;
        }
        if an != bn {
            return an < bn;
        }
        if ai != bi {
            return ai < bi;
        }
        return ar[i] < br[i];
    }
    ar.len() < br.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_matches_yaml_v3() {
        for (input, want) in [
            ("1.5", "\"1.5\""),
            ("127.0.0.1:3306", "127.0.0.1:3306"),
            ("http://127.0.0.1:18081", "http://127.0.0.1:18081"),
            ("127.0.0.1/32", "127.0.0.1/32"),
            ("30s", "30s"),
            ("48MiB", "48MiB"),
            ("yes", "\"yes\""),
            ("true", "\"true\""),
            ("123", "\"123\""),
            ("1e3", "\"1e3\""),
            ("10:30", "\"10:30\""),
            ("", "\"\""),
            ("[::1]:3306", "'[::1]:3306'"),
            ("::1", "::1"),
            ("a: b", "'a: b'"),
            ("#x", "'#x'"),
            ("a #x", "'a #x'"),
            ("a#x", "a#x"),
            ("- x", "'- x'"),
            ("-x", "-x"),
            (" lead", "' lead'"),
            ("~", "\"~\""),
            ("@x", "'@x'"),
            ("0x1F", "\"0x1F\""),
            ("0b101", "\"0b101\""),
            ("1_000", "\"1_000\""),
            (".inf", "\".inf\""),
        ] {
            assert_eq!(quote_string(input), want, "{input}");
        }
    }

    #[test]
    fn key_order_matches_yaml_v3_key_list() {
        let mut keys = vec![
            "protocol_version",
            "protocol",
            "allowed_cidrs",
            "allow_insecure_http",
            "a10",
            "a2",
            "a_b",
            "ab",
        ];
        keys.sort_by(|a, b| key_cmp(a, b));
        assert_eq!(
            keys,
            vec![
                "a_b",
                "a2",
                "a10",
                "ab",
                "allow_insecure_http",
                "allowed_cidrs",
                "protocol",
                "protocol_version"
            ]
        );
    }

    #[test]
    fn nested_layout_matches_spec_generated_pair() {
        let doc = Node::map(vec![
            (
                "peers",
                Node::Seq(vec![Node::map(vec![
                    ("id", Node::str("B")),
                    (
                        "endpoints",
                        Node::Seq(vec![Node::map(vec![
                            ("url", Node::str("http://127.0.0.1:18081")),
                            ("priority", Node::Int(1)),
                            ("id", Node::str("link-1")),
                        ])]),
                    ),
                    ("tls", Node::map(vec![("verify", Node::Bool(true))])),
                ])]),
            ),
            ("admin", Node::map(vec![("enabled", Node::Bool(true))])),
            (
                "auth",
                Node::map(vec![(
                    "inbound_peers",
                    Node::Seq(vec![Node::map(vec![
                        ("token_files", Node::strs(&["shared.token".into()])),
                        ("allowed_targets", Node::strs(&["mysql".into()])),
                    ])]),
                )]),
            ),
        ]);
        assert_eq!(
            encode(&doc),
            "admin:\n  enabled: true\nauth:\n  inbound_peers:\n    - allowed_targets:\n        - mysql\n      token_files:\n        - shared.token\npeers:\n  - endpoints:\n      - id: link-1\n        priority: 1\n        url: http://127.0.0.1:18081\n    id: B\n    tls:\n      verify: true\n"
        );
    }
}
