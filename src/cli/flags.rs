use std::collections::BTreeMap;
use std::fmt::Write as _;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Bool,
    Str,
    Int,
    List,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Bool(bool),
    Str(String),
    Int(i64),
    List(Vec<String>),
}

impl Value {
    fn string(&self) -> String {
        match self {
            Value::Bool(v) => v.to_string(),
            Value::Str(v) => v.clone(),
            Value::Int(v) => v.to_string(),
            Value::List(v) => v.join(","),
        }
    }
}

struct Flag {
    name: String,
    usage: String,
    kind: Kind,
    /// `Flag.DefValue`: the default rendered with `Value.String()`.
    def_value: String,
    /// Storage slot; aliases (`-c`/`-config`, `-o`/`-output`) share one.
    slot: String,
}

/// How `-h` prints the options of this set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Usage {
    Default,
    Command,
}

pub struct FlagSet {
    name: String,
    flags: Vec<Flag>,
    values: BTreeMap<String, Value>,
    usage: Usage,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    Help,
    Message(String),
}

impl FlagSet {
    pub fn new(name: &str, usage: Usage) -> Self {
        FlagSet {
            name: name.to_string(),
            flags: Vec::new(),
            values: BTreeMap::new(),
            usage,
        }
    }

    fn define(&mut self, name: &str, slot: &str, kind: Kind, default: Value, usage: &str) {
        let def_value = default.string();
        self.values.entry(slot.to_string()).or_insert(default);
        self.flags.push(Flag {
            name: name.to_string(),
            usage: usage.to_string(),
            kind,
            def_value,
            slot: slot.to_string(),
        });
    }

    pub fn string(&mut self, name: &str, default: &str, usage: &str) {
        self.define(name, name, Kind::Str, Value::Str(default.into()), usage);
    }
    /// `fs.StringVar(p, name, ...)` sharing `slot` with another flag.
    pub fn string_alias(&mut self, name: &str, slot: &str, default: &str, usage: &str) {
        self.define(name, slot, Kind::Str, Value::Str(default.into()), usage);
    }
    pub fn bool(&mut self, name: &str, default: bool, usage: &str) {
        self.define(name, name, Kind::Bool, Value::Bool(default), usage);
    }
    pub fn int(&mut self, name: &str, default: i64, usage: &str) {
        self.define(name, name, Kind::Int, Value::Int(default), usage);
    }
    pub fn list(&mut self, name: &str, usage: &str) {
        self.define(name, name, Kind::List, Value::List(Vec::new()), usage);
    }

    pub fn get_str(&self, slot: &str) -> String {
        match self.values.get(slot) {
            Some(Value::Str(v)) => v.clone(),
            _ => String::new(),
        }
    }
    pub fn get_bool(&self, slot: &str) -> bool {
        matches!(self.values.get(slot), Some(Value::Bool(true)))
    }
    pub fn get_int(&self, slot: &str) -> i64 {
        match self.values.get(slot) {
            Some(Value::Int(v)) => *v,
            _ => 0,
        }
    }
    pub fn get_list(&self, slot: &str) -> Vec<String> {
        match self.values.get(slot) {
            Some(Value::List(v)) => v.clone(),
            _ => Vec::new(),
        }
    }

    pub fn usage_text(&self) -> String {
        let mut out = String::new();
        let mut sorted: Vec<&Flag> = self.flags.iter().collect();
        sorted.sort_by(|a, b| a.name.cmp(&b.name));
        match self.usage {
            Usage::Command => {
                let _ = write!(out, "Usage: dbbridge {} [options]\n\nOptions:\n", self.name);
                for f in sorted {
                    let def = if !f.def_value.is_empty() && f.def_value != "false" {
                        format!(" (default {})", f.def_value)
                    } else {
                        String::new()
                    };
                    let _ = writeln!(out, "  -{}\n    \t{}{}", f.name, f.usage, def);
                }
            }
            Usage::Default => {
                let _ = writeln!(out, "Usage of {}:", self.name);
                for f in sorted {
                    out.push_str(&print_default(f));
                }
            }
        }
        out
    }

    fn fail(&self, diag: &mut String, message: String) -> ParseError {
        diag.push_str(&message);
        diag.push('\n');
        diag.push_str(&self.usage_text());
        ParseError::Message(message)
    }

    /// `fs.Parse(args)`; diagnostics go to `diag` (the set's output). Returns
    /// the remaining positional arguments.
    pub fn parse(&mut self, args: &[String], diag: &mut String) -> Result<Vec<String>, ParseError> {
        let mut rest: &[String] = args;
        loop {
            let Some(s) = rest.first() else {
                return Ok(Vec::new());
            };
            let bytes = s.as_bytes();
            if bytes.len() < 2 || bytes[0] != b'-' {
                return Ok(rest.to_vec());
            }
            let mut minuses = 1;
            if bytes[1] == b'-' {
                minuses += 1;
                if bytes.len() == 2 {
                    return Ok(rest[1..].to_vec());
                }
            }
            let mut name = &s[minuses..];
            if name.is_empty() || name.starts_with('-') || name.starts_with('=') {
                return Err(self.fail(diag, format!("bad flag syntax: {s}")));
            }
            rest = &rest[1..];
            let mut value: Option<&str> = None;
            if let Some(i) = name[1..].find('=') {
                value = Some(&name[i + 2..]);
                name = &name[..i + 1];
            }
            let Some(index) = self.flags.iter().position(|f| f.name == name) else {
                if name == "help" || name == "h" {
                    diag.push_str(&self.usage_text());
                    return Err(ParseError::Help);
                }
                return Err(self.fail(diag, format!("flag provided but not defined: -{name}")));
            };
            let (kind, slot) = (self.flags[index].kind, self.flags[index].slot.clone());
            match kind {
                Kind::Bool => {
                    let raw = value.unwrap_or("true");
                    match parse_bool(raw) {
                        Some(v) => {
                            self.values.insert(slot, Value::Bool(v));
                        }
                        None => {
                            return Err(self.fail(
                                diag,
                                format!(
                                    "invalid boolean value {} for -{name}: parse error",
                                    spec_quote(raw)
                                ),
                            ))
                        }
                    }
                }
                _ => {
                    let raw = match value {
                        Some(v) => v.to_string(),
                        None => match rest.first() {
                            Some(next) => {
                                let next = next.clone();
                                rest = &rest[1..];
                                next
                            }
                            None => {
                                return Err(
                                    self.fail(diag, format!("flag needs an argument: -{name}"))
                                )
                            }
                        },
                    };
                    match kind {
                        Kind::Str => {
                            self.values.insert(slot, Value::Str(raw));
                        }
                        Kind::List => {
                            if let Some(Value::List(items)) = self.values.get_mut(&slot) {
                                items.push(raw);
                            }
                        }
                        Kind::Int => match parse_spec_int(&raw) {
                            Ok(v) => {
                                self.values.insert(slot, Value::Int(v));
                            }
                            Err(reason) => {
                                return Err(self.fail(
                                    diag,
                                    format!(
                                        "invalid value {} for flag -{name}: {reason}",
                                        spec_quote(&raw)
                                    ),
                                ))
                            }
                        },
                        Kind::Bool => unreachable!(),
                    }
                }
            }
        }
    }
}

fn print_default(f: &Flag) -> String {
    let mut b = format!("  -{}", f.name);
    let type_name = match f.kind {
        Kind::Bool => "",
        Kind::Str => "string",
        Kind::Int => "int",
        Kind::List => "value",
    };
    if !type_name.is_empty() {
        b.push(' ');
        b.push_str(type_name);
    }
    if b.len() <= 4 {
        b.push('\t');
    } else {
        b.push_str("\n    \t");
    }
    b.push_str(&f.usage.replace('\n', "\n    \t"));
    let zero = match f.kind {
        Kind::Bool => "false",
        Kind::Int => "0",
        Kind::Str | Kind::List => "",
    };
    if f.def_value != zero {
        if f.kind == Kind::Str {
            let _ = write!(b, " (default {})", spec_quote(&f.def_value));
        } else {
            let _ = write!(b, " (default {})", f.def_value);
        }
    }
    b.push('\n');
    b
}

/// `strconv.ParseBool`.
pub fn parse_bool(s: &str) -> Option<bool> {
    match s {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

/// `strconv.ParseInt(s, 0, 64)` with the error text `flag` reports.
pub fn parse_spec_int(s: &str) -> Result<i64, &'static str> {
    const PARSE: &str = "parse error";
    const RANGE: &str = "value out of range";
    let (neg, body) = match s.as_bytes().first() {
        Some(b'+') => (false, &s[1..]),
        Some(b'-') => (true, &s[1..]),
        _ => (false, s),
    };
    if body.is_empty() {
        return Err(PARSE);
    }
    let lower = body.to_ascii_lowercase();
    let (base, digits, prefixed) = if lower.starts_with("0x") {
        (16, &body[2..], true)
    } else if lower.starts_with("0b") {
        (2, &body[2..], true)
    } else if lower.starts_with("0o") {
        (8, &body[2..], true)
    } else if body.len() > 1 && body.starts_with('0') {
        (8, &body[1..], true)
    } else {
        (10, body, false)
    };
    if digits.is_empty() && !(base == 8 && !lower.starts_with("0o")) {
        return Err(PARSE);
    }
    // Underscores are allowed only between digits (or after a base prefix).
    if body.contains('_') {
        let mut prev_digit = prefixed;
        for c in digits.chars() {
            if c == '_' {
                if !prev_digit {
                    return Err(PARSE);
                }
                prev_digit = false;
            } else {
                prev_digit = true;
            }
        }
        if !prev_digit {
            return Err(PARSE);
        }
    }
    let mut value: u128 = 0;
    let mut any = false;
    for c in digits.chars() {
        if c == '_' {
            continue;
        }
        let d = c.to_digit(base).ok_or(PARSE)? as u128;
        value = value.saturating_mul(base as u128).saturating_add(d);
        any = true;
    }
    if !any && base != 8 {
        return Err(PARSE);
    }
    let limit: u128 = if neg { 1u128 << 63 } else { (1u128 << 63) - 1 };
    if value > limit {
        return Err(RANGE);
    }
    Ok(if neg {
        (value as i128).wrapping_neg() as i64
    } else {
        value as i64
    })
}

pub fn spec_quote(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x07' => out.push_str("\\a"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\x0b' => out.push_str("\\v"),
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                let _ = write!(out, "\\x{:02x}", c as u32);
            }
            '\u{FFFD}' => out.push_str("\\ufffd"),
            c if c.is_control() => {
                let v = c as u32;
                if v < 0x10000 {
                    let _ = write!(out, "\\u{v:04x}");
                } else {
                    let _ = write!(out, "\\U{v:08x}");
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn set() -> FlagSet {
        let mut fs = FlagSet::new("check-config", Usage::Command);
        fs.string("config", "", "Path to YAML configuration");
        fs.string_alias("c", "config", "", "Configuration path (shorthand)");
        fs.string("log-level", "info", "debug, info, warn, error");
        fs.bool("offline", false, "Do not read tokens");
        fs.int("n", 7, "count");
        fs.list("peer", "repeatable");
        fs
    }

    #[test]
    fn spec_flag_syntax_forms() {
        let mut fs = set();
        let mut diag = String::new();
        let rest = fs
            .parse(
                &args(&[
                    "-c",
                    "a.yaml",
                    "--log-level=debug",
                    "-offline",
                    "-peer",
                    "x",
                    "--peer=y",
                    "-n",
                    "0x10",
                ]),
                &mut diag,
            )
            .unwrap();
        assert!(rest.is_empty());
        assert_eq!(fs.get_str("config"), "a.yaml");
        assert_eq!(fs.get_str("log-level"), "debug");
        assert!(fs.get_bool("offline"));
        assert_eq!(fs.get_list("peer"), vec!["x", "y"]);
        assert_eq!(fs.get_int("n"), 16);
        assert!(diag.is_empty());
    }

    #[test]
    fn first_positional_stops_parsing_and_double_dash_terminates() {
        let mut fs = set();
        let mut diag = String::new();
        let rest = fs
            .parse(&args(&["-offline", "extra", "-c", "x"]), &mut diag)
            .unwrap();
        assert_eq!(rest, args(&["extra", "-c", "x"]));
        let mut fs = set();
        let rest = fs.parse(&args(&["--", "-c"]), &mut diag).unwrap();
        assert_eq!(rest, args(&["-c"]));
        // A bool flag never takes the next argument.
        let mut fs = set();
        let rest = fs.parse(&args(&["-offline", "false"]), &mut diag).unwrap();
        assert!(fs.get_bool("offline"));
        assert_eq!(rest, args(&["false"]));
    }

    #[test]
    fn errors_match_spec_failf_text() {
        let cases: &[(&[&str], &str)] = &[
            (&["-start"], "flag provided but not defined: -start"),
            (&["-c"], "flag needs an argument: -c"),
            (
                &["-offline=maybe"],
                "invalid boolean value \"maybe\" for -offline: parse error",
            ),
            (&["-n", "x"], "invalid value \"x\" for flag -n: parse error"),
            (
                &["-n", "99999999999999999999"],
                "invalid value \"99999999999999999999\" for flag -n: value out of range",
            ),
            (&["---x"], "bad flag syntax: ---x"),
            (&["-=x"], "bad flag syntax: -=x"),
        ];
        for (input, want) in cases {
            let mut fs = set();
            let mut diag = String::new();
            assert_eq!(
                fs.parse(&args(input), &mut diag),
                Err(ParseError::Message(want.to_string()))
            );
            assert!(
                diag.starts_with(&format!("{want}\nUsage: dbbridge check-config [options]\n")),
                "{diag}"
            );
        }
    }

    #[test]
    fn help_prints_usage_and_reports_err_help() {
        for flag in ["-h", "--help", "-help"] {
            let mut fs = set();
            let mut diag = String::new();
            assert_eq!(fs.parse(&args(&[flag]), &mut diag), Err(ParseError::Help));
            assert_eq!(diag, fs.usage_text());
        }
    }

    #[test]
    fn default_usage_matches_print_defaults() {
        let mut fs = FlagSet::new("gen-config", Usage::Default);
        fs.string("o", ".", "Output directory (shorthand)");
        fs.bool("recovery", true, "Enable session recovery on both nodes");
        fs.bool("force", false, "Replace");
        fs.int("max-sessions", 200, "quota");
        fs.list("a-peer-url", "Remote origin");
        fs.string("token-file", "", "Token");
        assert_eq!(
            fs.usage_text(),
            "Usage of gen-config:\n  -a-peer-url value\n    \tRemote origin\n  -force\n    \tReplace\n  -max-sessions int\n    \tquota (default 200)\n  -o string\n    \tOutput directory (shorthand) (default \".\")\n  -recovery\n    \tEnable session recovery on both nodes (default true)\n  -token-file string\n    \tToken\n"
        );
    }

    #[test]
    fn spec_int_parsing_table() {
        assert_eq!(parse_spec_int("200"), Ok(200));
        assert_eq!(parse_spec_int("-5"), Ok(-5));
        assert_eq!(parse_spec_int("+5"), Ok(5));
        assert_eq!(parse_spec_int("010"), Ok(8));
        assert_eq!(parse_spec_int("0b101"), Ok(5));
        assert_eq!(parse_spec_int("0o17"), Ok(15));
        assert_eq!(parse_spec_int("1_000"), Ok(1000));
        assert_eq!(parse_spec_int("0"), Ok(0));
        assert_eq!(parse_spec_int("_1"), Err("parse error"));
        assert_eq!(parse_spec_int("1__0"), Err("parse error"));
        assert_eq!(parse_spec_int("0x"), Err("parse error"));
        assert_eq!(parse_spec_int("09"), Err("parse error"));
        assert_eq!(parse_spec_int(""), Err("parse error"));
        assert_eq!(parse_spec_int("9223372036854775807"), Ok(i64::MAX));
        assert_eq!(parse_spec_int("-9223372036854775808"), Ok(i64::MIN));
        assert_eq!(
            parse_spec_int("9223372036854775808"),
            Err("value out of range")
        );
    }
}
