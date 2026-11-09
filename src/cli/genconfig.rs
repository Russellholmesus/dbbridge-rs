use std::fs;
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use super::yamlout::{self, Node};
use crate::error::{Error, Result};

pub const DEFAULT_ADMIN_LISTEN: &str = "127.0.0.1:18090";
const MAX_TOKEN_BYTES: usize = 8192;

#[derive(Clone, Debug, Default)]
pub struct NodeOptions {
    pub node_id: String,
    pub listen: String,
    pub http_listen: String,
    pub admin_listen: String,
    pub target_id: String,
    pub target_address: String,
    pub tls_cert: String,
    pub tls_key: String,
    pub peer_urls: Vec<String>,
    pub allowed_cidrs: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct PairOptions {
    pub output_dir: String,
    pub mode: String,
    pub token_file: String,
    pub protocol: String,
    pub a: NodeOptions,
    pub b: NodeOptions,
    pub recovery: bool,
    pub allow_insecure_http: bool,
    pub force: bool,
    pub max_sessions: i64,
    pub reverse: bool,
}

impl Default for PairOptions {
    fn default() -> Self {
        PairOptions {
            output_dir: ".".into(),
            mode: "bidirectional".into(),
            token_file: String::new(),
            protocol: "auto".into(),
            recovery: true,
            allow_insecure_http: false,
            force: false,
            max_sessions: 200,
            reverse: false,
            a: NodeOptions {
                node_id: "A".into(),
                listen: "127.0.0.1:13306".into(),
                http_listen: "127.0.0.1:18080".into(),
                admin_listen: "127.0.0.1:18090".into(),
                target_id: "mysql".into(),
                target_address: "127.0.0.1:3306".into(),
                ..NodeOptions::default()
            },
            b: NodeOptions {
                node_id: "B".into(),
                listen: "127.0.0.1:13307".into(),
                http_listen: "127.0.0.1:18081".into(),
                admin_listen: "127.0.0.1:18091".into(),
                target_id: "mysql".into(),
                target_address: "127.0.0.1:3306".into(),
                ..NodeOptions::default()
            },
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct GenerateOptions {
    pub output: String,
    pub role: String,
    pub node_id: String,
    pub peer_id: String,
    pub listen: String,
    pub http_listen: String,
    pub target_id: String,
    pub target_address: String,
    pub token_file: String,
    pub protocol: String,
    pub peer_target_id: String,
    pub admin_listen: String,
    pub tls_cert: String,
    pub tls_key: String,
    pub peer_urls: Vec<String>,
    pub allowed_cidrs: Vec<String>,
    pub recovery: bool,
    pub allow_insecure_http: bool,
    pub force: bool,
    pub max_sessions: i64,
    pub inbound_max_sessions: i64,
    pub reverse: bool,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Default)]
pub struct GeneratedFiles {
    pub config: PathBuf,
    pub token_file: PathBuf,
    pub token_created: bool,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Default)]
pub struct GeneratedPairFiles {
    pub config_a: PathBuf,
    pub config_b: PathBuf,
    pub token_file: PathBuf,
    pub token_created: bool,
}

fn err(message: impl Into<String>) -> Error {
    Error::local(message)
}

fn errno_text(e: &io::Error) -> String {
    crate::util::spec_errno_text(e)
}

/// `*fs.PathError` text: `op path: errno`.
fn path_error(op: &str, path: &Path, e: &io::Error) -> Error {
    err(format!("{op} {}: {}", path.display(), errno_text(e)))
}

/// `filepath.Clean`.
pub fn clean(path: &str) -> String {
    if path.is_empty() {
        return ".".into();
    }
    let rooted = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if matches!(parts.last(), Some(p) if *p != "..") {
                    parts.pop();
                } else if !rooted {
                    parts.push("..");
                }
            }
            p => parts.push(p),
        }
    }
    let joined = parts.join("/");
    match (rooted, joined.is_empty()) {
        (true, _) => format!("/{joined}"),
        (false, true) => ".".into(),
        (false, false) => joined,
    }
}

/// `os.Getwd`: `$PWD` when it names the current directory.
fn getwd() -> Result<String> {
    let cwd = std::env::current_dir().map_err(|e| err(format!("getwd: {}", errno_text(&e))))?;
    #[cfg(unix)]
    if let Ok(pwd) = std::env::var("PWD") {
        use std::os::unix::fs::MetadataExt;
        if pwd.starts_with('/') {
            if let (Ok(a), Ok(b)) = (fs::metadata(&pwd), fs::metadata(".")) {
                if a.dev() == b.dev() && a.ino() == b.ino() {
                    return Ok(pwd);
                }
            }
        }
    }
    Ok(cwd.to_string_lossy().into_owned())
}

/// `filepath.Abs`.
pub fn abs(path: &str) -> Result<String> {
    if path.starts_with('/') {
        return Ok(clean(path));
    }
    Ok(clean(&format!("{}/{}", getwd()?, path)))
}

fn dir_of(path: &str) -> String {
    match path.rfind('/') {
        Some(0) => "/".into(),
        Some(i) => clean(&path[..i]),
        None => ".".into(),
    }
}

/// `filepath.Rel` for two absolute paths.
pub fn rel(base: &str, target: &str) -> String {
    let base = clean(base);
    let target = clean(target);
    if base == target {
        return ".".into();
    }
    let b: Vec<&str> = base.split('/').filter(|s| !s.is_empty()).collect();
    let t: Vec<&str> = target.split('/').filter(|s| !s.is_empty()).collect();
    let mut i = 0;
    while i < b.len() && i < t.len() && b[i] == t[i] {
        i += 1;
    }
    let mut parts: Vec<&str> = std::iter::repeat_n("..", b.len() - i).collect();
    parts.extend_from_slice(&t[i..]);
    parts.join("/")
}

/// `os.MkdirAll`.
pub fn mkdir_all(path: &str, mode: u32) -> Result<()> {
    if let Ok(meta) = fs::metadata(path) {
        if meta.is_dir() {
            return Ok(());
        }
        return Err(err(format!("mkdir {path}: not a directory")));
    }
    let bytes = path.as_bytes();
    let mut i = bytes.len();
    while i > 0 && bytes[i - 1] == b'/' {
        i -= 1;
    }
    let mut j = i;
    while j > 0 && bytes[j - 1] != b'/' {
        j -= 1;
    }
    if j > 1 {
        mkdir_all(&path[..j - 1], mode)?;
    }
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    if let Err(e) = builder.create(path) {
        if matches!(fs::symlink_metadata(path), Ok(m) if m.is_dir()) {
            return Ok(());
        }
        return Err(path_error("mkdir", Path::new(path), &e));
    }
    Ok(())
}

fn lstat(path: &str) -> io::Result<fs::Metadata> {
    fs::symlink_metadata(path)
}

/// `fileutil.WriteNew`: never follows or replaces an existing file. Returns
/// whether a file this call created exists at `path` after an error.
fn write_new(path: &str, data: &[u8], mode: u32) -> std::result::Result<bool, (bool, Error)> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = options
        .open(path)
        .map_err(|e| (false, path_error("open", Path::new(path), &e)))?;
    let written = file.write_all(data).and_then(|_| file.sync_all());
    if let Err(e) = written {
        drop(file);
        let _ = fs::remove_file(path);
        return Err((false, path_error("write", Path::new(path), &e)));
    }
    drop(file);
    sync_dir(&dir_of(path)).map_err(|e| (true, e))?;
    Ok(true)
}

fn sync_dir(dir: &str) -> Result<()> {
    let d = fs::File::open(dir).map_err(|e| path_error("open", Path::new(dir), &e))?;
    d.sync_all()
        .map_err(|e| path_error("sync", Path::new(dir), &e))
}

/// `os.CreateTemp(dir, pattern)`: returns the open file and its name.
fn create_temp(dir: &str, pattern: &str) -> Result<(fs::File, String)> {
    let (prefix, suffix) = match pattern.rfind('*') {
        Some(i) => (&pattern[..i], &pattern[i + 1..]),
        None => (pattern, ""),
    };
    for _ in 0..10000 {
        let n = crate::util::random_u64().map_err(crate::util::random_error)? as u32;
        let name = format!("{dir}/{prefix}{n}{suffix}");
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&name) {
            Ok(file) => return Ok((file, name)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(err(format!(
                    "open {dir}/{prefix}*{suffix}: {}",
                    errno_text(&e)
                )));
            }
        }
    }
    Err(err(format!("open {dir}/{prefix}*{suffix}: file exists")))
}

/// `fileutil.PreserveAttributes`.
fn preserve_attributes(previous: &fs::Metadata, path: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        fs::set_permissions(path, fs::Permissions::from_mode(previous.mode() & 0o777))
            .map_err(|e| path_error("chmod", Path::new(path), &e))?;
        let c = std::ffi::CString::new(path).map_err(|_| err("invalid path"))?;
        extern "C" {
            fn lchown(path: *const std::os::raw::c_char, uid: u32, gid: u32) -> i32;
        }
        // SAFETY: c is a valid NUL-terminated path.
        if unsafe { lchown(c.as_ptr(), previous.uid(), previous.gid()) } != 0 {
            let e = io::Error::last_os_error();
            if !matches!(e.raw_os_error(), Some(1) | Some(13)) {
                return Err(path_error("lchown", Path::new(path), &e));
            }
        }
    }
    #[cfg(not(unix))]
    let _ = (previous, path);
    Ok(())
}

#[cfg(unix)]
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}
#[cfg(not(unix))]
fn same_file(_: &fs::Metadata, _: &fs::Metadata) -> bool {
    false
}

/// `net.SplitHostPort`.
pub fn split_host_port(hostport: &str) -> std::result::Result<(String, String), String> {
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

/// `net.JoinHostPort`.
fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// `net.ParseIP` (no zones), normalised so an IPv4-mapped address is IPv4.
fn parse_ip(host: &str) -> Option<IpAddr> {
    let ip: IpAddr = host.parse().ok()?;
    if let IpAddr::V6(v6) = ip {
        if let Some(v4) = v6.to_ipv4_mapped() {
            return Some(IpAddr::V4(v4));
        }
    }
    Some(ip)
}

// ---------------------------------------------------------------- Generate

fn validate_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_TOKEN_BYTES
        && !token.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// `generatedMetadataLimitMiB`.
pub fn generated_metadata_limit_mib(max_sessions: i64) -> i64 {
    const PER_SESSION: i64 = 112 << 10;
    const OVERHEAD: i64 = 4 << 20;
    let need = max_sessions
        .saturating_mul(PER_SESSION)
        .saturating_add(OVERHEAD);
    if need <= 32 << 20 {
        return 0;
    }
    (need + (1 << 20) - 1) >> 20
}

fn endpoints(urls: &[String]) -> Node {
    Node::Seq(
        urls.iter()
            .enumerate()
            .map(|(i, url)| {
                Node::map(vec![
                    ("id", Node::str(format!("link-{}", i + 1))),
                    ("url", Node::str(url.clone())),
                    ("priority", Node::Int(i as i64 + 1)),
                ])
            })
            .collect(),
    )
}

fn generated_http(o: &GenerateOptions) -> Result<Node> {
    let mut http = Node::map(vec![
        ("enabled", Node::Bool(true)),
        ("listen", Node::str(o.http_listen.clone())),
    ]);
    if !o.tls_cert.is_empty() {
        let cert = abs(&o.tls_cert)?;
        let key = abs(&o.tls_key)?;
        http.set(
            "tls",
            Node::map(vec![
                ("enabled", Node::Bool(true)),
                ("cert_file", Node::str(cert)),
                ("key_file", Node::str(key)),
            ]),
        );
    }
    Ok(http)
}

const HEADER: &str = "# Generated by dbbridge gen-config. Keep the token file private and share it with the matching peer.\n# Token files and the auth/token settings below are re-read every auth.reload_interval (default 5s) and on SIGHUP;\n# other settings take effect after a restart.\n";

/// The YAML document `Generate` writes, without validation or file I/O.
fn render(o: &GenerateOptions, token_ref: &str) -> Result<String> {
    let admin_listen = if o.admin_listen.is_empty() {
        DEFAULT_ADMIN_LISTEN.to_string()
    } else {
        o.admin_listen.clone()
    };
    let mut m = Node::map(vec![
        (
            "node",
            Node::map(vec![("id", Node::str(o.node_id.clone()))]),
        ),
        (
            "admin",
            Node::map(vec![
                ("enabled", Node::Bool(true)),
                ("listen", Node::str(admin_listen)),
            ]),
        ),
        (
            "limits",
            Node::map(vec![("max_sessions", Node::Int(o.max_sessions))]),
        ),
        (
            "transport",
            Node::map(vec![
                ("protocol", Node::str(o.protocol.clone())),
                ("protocol_version", Node::str("1.5")),
                ("sql_replay", Node::Bool(false)),
                (
                    "recovery",
                    Node::map(vec![
                        ("enabled", Node::Bool(o.recovery)),
                        ("grace", Node::str("30s")),
                        ("barrier_timeout", Node::str("5s")),
                    ]),
                ),
            ]),
        ),
    ]);
    let limit = generated_metadata_limit_mib(o.max_sessions);
    if limit > 0 {
        if let Some(t) = m.get_mut("transport") {
            t.set("metadata_limit", Node::str(format!("{limit}MiB")));
        }
    }
    if o.role != "egress" {
        let mut peer = Node::map(vec![
            ("id", Node::str(o.peer_id.clone())),
            ("expected_node_id", Node::str(o.peer_id.clone())),
            ("credential_ref", Node::str(o.peer_id.clone())),
            ("token_file", Node::str(token_ref)),
            ("tls", Node::map(vec![("verify", Node::Bool(true))])),
            ("endpoints", endpoints(&o.peer_urls)),
        ]);
        if o.allow_insecure_http {
            peer.set("allow_insecure_http", Node::Bool(true));
        }
        if o.reverse {
            peer = Node::map(vec![
                ("id", Node::str(o.peer_id.clone())),
                ("mode", Node::str("reverse")),
                ("expected_node_id", Node::str(o.peer_id.clone())),
                ("credential_ref", Node::str(o.peer_id.clone())),
                ("token_file", Node::str(token_ref)),
            ]);
            m.set("http", generated_http(o)?);
        }
        m.set("peers", Node::Seq(vec![peer]));
        let remote_target = if o.peer_target_id.is_empty() {
            o.target_id.clone()
        } else {
            o.peer_target_id.clone()
        };
        m.set(
            "listeners",
            Node::Seq(vec![Node::map(vec![
                ("id", Node::str("database-local")),
                ("listen", Node::str(o.listen.clone())),
                ("peer", Node::str(o.peer_id.clone())),
                ("target", Node::str(remote_target)),
            ])]),
        );
    }
    if o.role != "ingress" {
        let mut inbound = o.max_sessions;
        if o.inbound_max_sessions > 0 && o.inbound_max_sessions < inbound {
            inbound = o.inbound_max_sessions;
        }
        if o.reverse {
            let transport = if o.protocol.is_empty() {
                "auto".to_string()
            } else {
                o.protocol.clone()
            };
            let mut rev = Node::map(vec![
                ("enabled", Node::Bool(true)),
                ("peer_node_id", Node::str(o.peer_id.clone())),
                ("token_file", Node::str(token_ref)),
                ("transport", Node::str(transport)),
                ("tls", Node::map(vec![("verify", Node::Bool(true))])),
                ("endpoints", endpoints(&o.peer_urls)),
            ]);
            if o.allow_insecure_http {
                rev.set("allow_insecure_http", Node::Bool(true));
            }
            m.set("reverse", rev);
        } else {
            m.set("http", generated_http(o)?);
        }
        m.set(
            "targets",
            Node::Map(vec![(
                o.target_id.clone(),
                Node::map(vec![
                    ("network", Node::str("tcp")),
                    ("address", Node::str(o.target_address.clone())),
                    ("allowed_cidrs", Node::strs(&o.allowed_cidrs)),
                ]),
            )]),
        );
        m.set(
            "auth",
            Node::map(vec![(
                "inbound_peers",
                Node::Seq(vec![Node::map(vec![
                    ("id", Node::str(o.peer_id.clone())),
                    ("token_files", Node::strs(&[token_ref.to_string()])),
                    (
                        "allowed_targets",
                        Node::strs(std::slice::from_ref(&o.target_id)),
                    ),
                    ("max_sessions", Node::Int(inbound)),
                ])]),
            )]),
        );
    }
    Ok(format!("{HEADER}{}", yamlout::encode(&m)))
}

pub fn generate(mut o: GenerateOptions) -> Result<GeneratedFiles> {
    if !matches!(o.role.as_str(), "ingress" | "egress" | "peer") {
        return Err(err("role must be ingress, egress, or peer"));
    }
    if o.node_id.is_empty() || o.peer_id.is_empty() || o.node_id == o.peer_id {
        return Err(err("node-id and peer-id must be nonempty and different"));
    }
    if o.output.is_empty() {
        return Err(err("output path is required"));
    }
    let output = abs(&o.output)?;
    let mut previous = None;
    match lstat(&output) {
        Ok(info) => {
            if !o.force {
                return Err(err(format!(
                    "config already exists: {output} (use --force to replace it)"
                )));
            }
            if !info.file_type().is_file() {
                return Err(err("refusing to replace a non-regular config file"));
            }
            previous = Some(info);
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(path_error("lstat", Path::new(&output), &e)),
    }
    let mut token_path = o.token_file.clone();
    if token_path.is_empty() {
        let base = match output.rfind('.') {
            Some(i) if i > output.rfind('/').unwrap_or(0) => output[..i].to_string(),
            _ => output.clone(),
        };
        token_path = format!("{base}.token");
    }
    let token_path = abs(&token_path)?;
    if output == token_path {
        return Err(err("config and token paths must differ"));
    }
    if o.max_sessions <= 0 {
        return Err(err("max-sessions must be positive"));
    }
    if o.tls_cert.is_empty() != o.tls_key.is_empty() {
        return Err(err("tls-cert and tls-key must be supplied together"));
    }
    if o.reverse && o.role == "peer" {
        return Err(err(
            "reverse mode needs role ingress (public side) or egress (database side)",
        ));
    }
    if o.role == "ingress" && !o.tls_cert.is_empty() && !o.reverse {
        return Err(err(
            "ingress has no HTTP server; TLS server options need egress or peer role",
        ));
    }
    if o.reverse && o.role == "egress" && !o.tls_cert.is_empty() {
        return Err(err("the database side of reverse mode has no HTTP server; TLS server options belong to the public (ingress) side"));
    }
    if o.peer_urls.is_empty() {
        o.peer_urls = vec!["http://127.0.0.1:18080".into()];
    }
    if o.role != "ingress" && o.allowed_cidrs.is_empty() {
        let (host, _) =
            split_host_port(&o.target_address).map_err(|e| err(format!("target-address: {e}")))?;
        let Some(ip) = parse_ip(&host) else {
            return Err(err("hostname targets require an explicit --allow-cidr"));
        };
        let bits = if ip.is_ipv4() { 32 } else { 128 };
        o.allowed_cidrs = vec![format!("{ip}/{bits}")];
    }
    mkdir_all(&dir_of(&output), 0o750)?;
    mkdir_all(&dir_of(&token_path), 0o750)?;
    let mut created = false;
    match lstat(&token_path) {
        Ok(info) => {
            if !info.file_type().is_file() {
                return Err(err("token must be a regular file"));
            }
        }
        Err(e) if e.kind() != io::ErrorKind::NotFound => {
            return Err(path_error("lstat", Path::new(&token_path), &e))
        }
        Err(_) => {
            let secret = crate::util::random_hex(32).map_err(crate::util::random_error)?;
            match write_new(&token_path, format!("{secret}\n").as_bytes(), 0o600) {
                Ok(c) => created = c,
                Err((c, e)) => {
                    if c {
                        let _ = fs::remove_file(&token_path);
                    }
                    return Err(e);
                }
            }
        }
    }
    let result = generate_with_token(&o, &output, &token_path, previous);
    match result {
        Ok(()) => Ok(GeneratedFiles {
            config: PathBuf::from(&output),
            token_file: PathBuf::from(&token_path),
            token_created: created,
        }),
        Err(e) => {
            if created {
                let _ = fs::remove_file(&token_path);
            }
            Err(e)
        }
    }
}

fn generate_with_token(
    o: &GenerateOptions,
    output: &str,
    token_path: &str,
    previous: Option<fs::Metadata>,
) -> Result<()> {
    let mut secret = Vec::new();
    fs::File::open(token_path)
        .map_err(|e| path_error("open", Path::new(token_path), &e))?
        .take((MAX_TOKEN_BYTES + 3) as u64)
        .read_to_end(&mut secret)
        .map_err(|e| path_error("read", Path::new(token_path), &e))?;
    let text = String::from_utf8_lossy(&secret);
    let text = text.strip_suffix('\n').unwrap_or(&text);
    let text = text.strip_suffix('\r').unwrap_or(text);
    if !validate_token(text) {
        return Err(err(format!(
            "token file {token_path} is empty, larger than {MAX_TOKEN_BYTES} bytes, or malformed"
        )));
    }
    let token_ref = rel(&dir_of(output), token_path);
    let data = render(o, &token_ref)?;
    // Validate with the real loader, including credential and TLS checks.
    let (mut temp, temp_name) = create_temp(&dir_of(output), ".dbbridge-config-*.yaml")?;
    let validated = (|| {
        temp.write_all(data.as_bytes())
            .map_err(|e| path_error("write", Path::new(&temp_name), &e))?;
        drop(temp);
        crate::config::load(Path::new(&temp_name)).map_err(|e| {
            Error::new(
                &e.code,
                format!("generated config validation: {}", e.message),
            )
        })?;
        if o.force {
            if let Some(previous) = &previous {
                preserve_attributes(previous, &temp_name).map_err(|e| {
                    Error::new(
                        &e.code,
                        format!("keep permissions of {output}: {}", e.message),
                    )
                })?;
            }
            fs::File::open(&temp_name)
                .and_then(|f| f.sync_all())
                .map_err(|e| path_error("sync", Path::new(&temp_name), &e))?;
            fs::rename(&temp_name, output)
                .map_err(|e| err(format!("rename {temp_name} {output}: {}", errno_text(&e))))?;
            sync_dir(&dir_of(output))?;
            Ok(())
        } else {
            match write_new(output, data.as_bytes(), 0o600) {
                Ok(_) => Ok(()),
                Err((wrote, e)) => {
                    if wrote {
                        let _ = fs::remove_file(output);
                    }
                    Err(e)
                }
            }
        }
    })();
    let _ = fs::remove_file(&temp_name);
    validated
}

// ---------------------------------------------------------------- GeneratePair

fn pair_endpoint(node: &NodeOptions) -> Result<String> {
    let (mut host, port) = split_host_port(&node.http_listen)
        .map_err(|e| err(format!("node {} http-listen: {e}", node.node_id)))?;
    let ip = parse_ip(&host);
    if host.is_empty() || ip.map(|ip| ip.is_unspecified()).unwrap_or(false) {
        host = match host.parse::<IpAddr>() {
            Ok(IpAddr::V6(v6)) if v6.to_ipv4_mapped().is_none() => "::1".into(),
            _ => "127.0.0.1".into(),
        };
    }
    let scheme = if node.tls_cert.is_empty() {
        "http"
    } else {
        "https"
    };
    Ok(format!("{scheme}://{}", join_host_port(&host, &port)))
}

fn check_pair_output(path: &str, force: bool) -> Result<()> {
    match lstat(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(path_error("lstat", Path::new(path), &e)),
        Ok(info) => {
            if !info.file_type().is_file() {
                return Err(err(format!("refusing non-regular config file: {path}")));
            }
            if !force {
                return Err(err(format!(
                    "config already exists: {path} (use --force to replace the pair)"
                )));
            }
            Ok(())
        }
    }
}

fn reserve_pair_path(dir: &str, pattern: &str) -> Result<String> {
    let (file, name) = create_temp(dir, pattern)?;
    drop(file);
    fs::remove_file(&name).map_err(|e| path_error("remove", Path::new(&name), &e))?;
    Ok(name)
}

struct PairOutput {
    path: String,
    backup: String,
    data: Vec<u8>,
    written: bool,
}

/// `fileutil.WriteNew`'s signature: `Ok(created)` or `Err((created, error))`.
type WriteNew<'a> = &'a dyn Fn(&str, &[u8], u32) -> std::result::Result<bool, (bool, Error)>;

fn publish_pair(
    outputs: &mut [PairOutput],
    force: bool,
    write_new_fn: WriteNew,
) -> (bool, Result<()>) {
    let result = (|| -> Result<()> {
        for item in outputs.iter_mut() {
            check_pair_output(&item.path, force)?;
            let mut previous = None;
            match lstat(&item.path) {
                Ok(info) => {
                    previous = Some(info);
                    let backup = reserve_pair_path(&dir_of(&item.path), ".dbbridge-pair-backup-*")?;
                    fs::rename(&item.path, &backup).map_err(|e| {
                        err(format!("rename {} {backup}: {}", item.path, errno_text(&e)))
                    })?;
                    item.backup = backup;
                    sync_dir(&dir_of(&item.path))?;
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(path_error("lstat", Path::new(&item.path), &e)),
            }
            match write_new_fn(&item.path, &item.data, 0o600) {
                Ok(w) => item.written = w,
                Err((w, e)) => {
                    item.written = w;
                    return Err(e);
                }
            }
            if let Some(previous) = &previous {
                preserve_attributes(previous, &item.path).map_err(|e| {
                    err(format!("keep permissions of {}: {}", item.path, e.message))
                })?;
            }
        }
        Ok(())
    })();
    if let Err(e) = result {
        let mut rollback: Vec<String> = Vec::new();
        for item in outputs.iter().rev() {
            if item.written {
                if let Err(re) = fs::remove_file(&item.path) {
                    rollback.push(path_error("remove", Path::new(&item.path), &re).message);
                }
            }
            if !item.backup.is_empty() {
                if let Err(re) = fs::rename(&item.backup, &item.path) {
                    rollback.push(format!(
                        "rename {} {}: {}",
                        item.backup,
                        item.path,
                        errno_text(&re)
                    ));
                }
            }
        }
        if !rollback.is_empty() {
            return (
                true,
                Err(err(format!(
                    "{}\nrestore original pair (backups retained where restoration failed): {}",
                    e.message,
                    rollback.join("\n")
                ))),
            );
        }
        return (false, Err(e));
    }
    let mut errors: Vec<String> = Vec::new();
    let mut dirs: Vec<String> = Vec::new();
    for item in outputs.iter() {
        if !item.backup.is_empty() {
            if let Err(e) = fs::remove_file(&item.backup) {
                errors.push(format!(
                    "pair published; remove old backup {}: {}",
                    item.backup,
                    path_error("remove", Path::new(&item.backup), &e).message
                ));
            }
        }
        let d = dir_of(&item.path);
        if !dirs.contains(&d) {
            dirs.push(d);
        }
    }
    for d in dirs {
        if let Err(e) = sync_dir(&d) {
            errors.push(format!("pair published; sync directory {d}: {}", e.message));
        }
    }
    if errors.is_empty() {
        (true, Ok(()))
    } else {
        (true, Err(err(errors.join("\n"))))
    }
}

/// `inboundQuota`.
fn inbound_quota(role: &str, max_sessions: i64) -> i64 {
    if role == "peer" && max_sessions > 1 {
        max_sessions / 2
    } else {
        0
    }
}

pub fn generate_pair(o: &PairOptions) -> Result<GeneratedPairFiles> {
    let roles: [&str; 2] = match o.mode.as_str() {
        "bidirectional" => ["peer", "peer"],
        "a-to-b" => ["ingress", "egress"],
        "b-to-a" => ["egress", "ingress"],
        _ => return Err(err("mode must be bidirectional, a-to-b, or b-to-a")),
    };
    if o.reverse && o.mode == "bidirectional" {
        return Err(err("reverse mode needs --mode a-to-b or b-to-a (the egress node is the database side behind NAT)"));
    }
    if o.a.node_id.is_empty() || o.b.node_id.is_empty() || o.a.node_id == o.b.node_id {
        return Err(err("node IDs for A and B must be nonempty and different"));
    }
    if o.output_dir.is_empty() {
        return Err(err("output directory is required"));
    }
    let dir = abs(&o.output_dir)?;
    let paths = [format!("{dir}/peer-a.yaml"), format!("{dir}/peer-b.yaml")];
    let paths = [clean(&paths[0]), clean(&paths[1])];
    let token = if o.token_file.is_empty() {
        clean(&format!("{dir}/shared.token"))
    } else {
        o.token_file.clone()
    };
    let token = abs(&token)?;
    for path in &paths {
        if *path == token {
            return Err(err("configuration and token paths must differ"));
        }
        check_pair_output(path, o.force)?;
        if let (Ok(cfg), Ok(tok)) = (fs::metadata(path), fs::metadata(&token)) {
            if same_file(&cfg, &tok) {
                return Err(err("configuration and token files must differ"));
            }
        }
    }
    mkdir_all(&dir, 0o750)?;
    let mut created_token = false;
    let mut keep_token = false;
    let mut staged: Vec<String> = Vec::new();
    let result = (|| -> Result<GeneratedPairFiles> {
        let mut nodes = [o.a.clone(), o.b.clone()];
        for (i, admin) in [DEFAULT_ADMIN_LISTEN, "127.0.0.1:18091"].iter().enumerate() {
            if nodes[i].admin_listen.is_empty() {
                nodes[i].admin_listen = admin.to_string();
            }
        }
        let mut outputs: Vec<PairOutput> = Vec::new();
        for i in 0..2 {
            let node = &nodes[i];
            let other = &nodes[1 - i];
            let mut urls = node.peer_urls.clone();
            let mut dialer = roles[i] != "egress";
            if o.reverse {
                dialer = roles[i] == "egress";
            }
            if dialer && urls.is_empty() {
                urls = vec![pair_endpoint(other)?];
            }
            let stage = reserve_pair_path(&dir, ".dbbridge-pair-*.yaml")?;
            staged.push(stage.clone());
            let generated = generate(GenerateOptions {
                output: stage.clone(),
                role: roles[i].to_string(),
                node_id: node.node_id.clone(),
                peer_id: other.node_id.clone(),
                listen: node.listen.clone(),
                http_listen: node.http_listen.clone(),
                admin_listen: node.admin_listen.clone(),
                target_id: node.target_id.clone(),
                peer_target_id: other.target_id.clone(),
                target_address: node.target_address.clone(),
                token_file: token.clone(),
                protocol: o.protocol.clone(),
                tls_cert: node.tls_cert.clone(),
                tls_key: node.tls_key.clone(),
                peer_urls: urls,
                allowed_cidrs: node.allowed_cidrs.clone(),
                recovery: o.recovery,
                allow_insecure_http: o.allow_insecure_http,
                force: false,
                max_sessions: o.max_sessions,
                inbound_max_sessions: inbound_quota(roles[i], o.max_sessions),
                reverse: o.reverse,
            })
            .map_err(|e| {
                Error::new(
                    &e.code,
                    format!("generate node {}: {}", node.node_id, e.message),
                )
            })?;
            created_token = created_token || generated.token_created;
            let data = fs::read(&stage).map_err(|e| path_error("open", Path::new(&stage), &e))?;
            outputs.push(PairOutput {
                path: paths[i].clone(),
                backup: String::new(),
                data,
                written: false,
            });
        }
        let (keep, published) = publish_pair(&mut outputs, o.force, &write_new);
        keep_token = keep;
        published?;
        Ok(GeneratedPairFiles {
            config_a: PathBuf::from(&paths[0]),
            config_b: PathBuf::from(&paths[1]),
            token_file: PathBuf::from(&token),
            token_created: created_token,
        })
    })();
    for path in &staged {
        let _ = fs::remove_file(path);
    }
    if created_token && !keep_token {
        if let Err(e) = fs::remove_file(&token) {
            if e.kind() != io::ErrorKind::NotFound {
                if let Err(mut first) = result {
                    first.message = format!(
                        "{}\nremove newly created token: {}",
                        first.message,
                        path_error("remove", Path::new(&token), &e).message
                    );
                    return Err(first);
                }
            }
        }
    }
    result
}

#[cfg(test)]
#[path = "spec_fileutil_tests.rs"]
mod spec_fileutil_tests;

#[cfg(test)]
#[path = "spec_genconfig2_tests.rs"]
mod spec_genconfig2_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{self, Config, Protocol};

    fn temp_dir(tag: &str) -> String {
        let dir = std::env::temp_dir().join(format!(
            "dbb-gen-{tag}-{}",
            crate::util::random_hex(6).unwrap()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir.to_string_lossy().into_owned()
    }

    fn pair_options(tag: &str) -> PairOptions {
        PairOptions {
            output_dir: format!("{}/pair paths $percent% space", temp_dir(tag)),
            ..PairOptions::default()
        }
    }

    fn generate_options(tag: &str, role: &str) -> GenerateOptions {
        GenerateOptions {
            output: format!("{}/peer.yaml", temp_dir(tag)),
            role: role.into(),
            node_id: "A".into(),
            peer_id: "B".into(),
            listen: "127.0.0.1:13306".into(),
            http_listen: "127.0.0.1:18080".into(),
            target_id: "mysql".into(),
            target_address: "127.0.0.1:3306".into(),
            protocol: "auto".into(),
            recovery: true,
            max_sessions: 200,
            ..GenerateOptions::default()
        }
    }

    fn load(path: &Path) -> Config {
        config::load(path).unwrap_or_else(|e| panic!("{}: {}", path.display(), e.message))
    }

    fn load_pair(files: &GeneratedPairFiles) -> (Config, Config) {
        (load(&files.config_a), load(&files.config_b))
    }

    fn origin(u: &crate::net::Url) -> String {
        let default = if u.is_tls() { 443 } else { 80 };
        let host = if u.host.contains(':') {
            format!("[{}]", u.host)
        } else {
            u.host.clone()
        };
        if u.port == default {
            format!("{}://{host}", u.scheme)
        } else {
            format!("{}://{host}:{}", u.scheme, u.port)
        }
    }

    fn mode(path: &str) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn read_pair(files: &GeneratedPairFiles) -> [Vec<u8>; 3] {
        [
            fs::read(&files.config_a).unwrap(),
            fs::read(&files.config_b).unwrap(),
            fs::read(&files.token_file).unwrap(),
        ]
    }

    fn entries(dir: &str) -> usize {
        fs::read_dir(dir).map(|d| d.count()).unwrap_or(0)
    }

    fn assert_no_pair_temporary_files(dir: &str) {
        let leftovers: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(".dbbridge-pair-"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temporary pair files remain: {leftovers:?}"
        );
    }

    #[cfg(feature = "tls")]
    fn test_certificate_pair() -> (String, String) {
        let dir = temp_dir("cert");
        let cert = format!("{dir}/cert.pem");
        let key = format!("{dir}/key.pem");
        fs::write(&cert, include_str!("../net/testdata/localhost-cert.pem")).unwrap();
        fs::write(&key, include_str!("../net/testdata/localhost-key.pem")).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        (cert, key)
    }

    #[test]
    fn path_helpers_follow_spec_filepath() {
        assert_eq!(clean("a//b/./../c/"), "a/c");
        assert_eq!(clean("/../x"), "/x");
        assert_eq!(clean("../../x"), "../../x");
        assert_eq!(clean(""), ".");
        assert_eq!(rel("/a/b", "/a/b/c.token"), "c.token");
        assert_eq!(rel("/a/b", "/a/x/t"), "../x/t");
        assert_eq!(rel("/a/b", "/a/b"), ".");
        assert_eq!(
            split_host_port("127.0.0.1:80"),
            Ok(("127.0.0.1".into(), "80".into()))
        );
        assert_eq!(split_host_port("[::1]:80"), Ok(("::1".into(), "80".into())));
        assert_eq!(
            split_host_port("db"),
            Err("address db: missing port in address".into())
        );
        assert_eq!(
            split_host_port("::1:80"),
            Err("address ::1:80: too many colons in address".into())
        );
        assert_eq!(generated_metadata_limit_mib(200), 0);
        assert_eq!(generated_metadata_limit_mib(400), 48);
    }

    #[test]
    fn generate_pair_mode_carrier_recovery_matrix() {
        for m in ["bidirectional", "a-to-b", "b-to-a"] {
            for protocol in ["auto", "ws", "http-sse"] {
                for recovery in [false, true] {
                    let mut o = pair_options("matrix");
                    o.mode = m.into();
                    o.protocol = protocol.into();
                    o.recovery = recovery;
                    o.a.target_id = "database-at-a".into();
                    o.b.target_id = "database-at-b".into();
                    o.a.target_address = "127.0.0.2:3306".into();
                    o.b.target_address = "[::1]:1433".into();
                    let files = generate_pair(&o)
                        .unwrap_or_else(|e| panic!("{m} {protocol}: {}", e.message));
                    let (a, b) = load_pair(&files);
                    assert!(a.node.id == "A" && b.node.id == "B" && files.token_created);
                    for (i, cfg) in [&a, &b].into_iter().enumerate() {
                        assert_eq!(cfg.transport.protocol, Protocol::parse(protocol).unwrap());
                        assert_eq!(cfg.transport.recovery_enabled, recovery);
                        let outbound = (i == 0 && m != "b-to-a") || (i == 1 && m != "a-to-b");
                        let inbound = (i == 0 && m != "a-to-b") || (i == 1 && m != "b-to-a");
                        assert_eq!(cfg.http.enabled, inbound, "{m} node {i}");
                        assert_eq!(cfg.listeners.len() == 1, outbound, "{m} node {i}");
                        assert_eq!(cfg.targets.len() == 1, inbound, "{m} node {i}");
                    }
                    let check =
                        |local: &Config, remote: &Config, url: &str, target: &str, cidr: &str| {
                            let peer = &local.peers[0];
                            assert_eq!(peer.id, remote.node.id);
                            assert_eq!(peer.expected_node_id, remote.node.id);
                            assert_eq!(origin(&peer.endpoints[0].url), url);
                            assert!(peer.tls.verify);
                            assert_eq!(local.listeners[0].target, target);
                            assert_eq!(remote.inbound[0].id, local.node.id);
                            assert_eq!(remote.inbound[0].allowed_targets[0], target);
                            assert_eq!(remote.target(target).unwrap().allowed_cidrs[0], cidr);
                            assert_eq!(peer.token, remote.inbound[0].tokens[0]);
                        };
                    if m != "b-to-a" {
                        check(&a, &b, "http://127.0.0.1:18081", "database-at-b", "::1/128");
                    }
                    if m != "a-to-b" {
                        check(
                            &b,
                            &a,
                            "http://127.0.0.1:18080",
                            "database-at-a",
                            "127.0.0.2/32",
                        );
                    }
                    let secret = fs::read_to_string(&files.token_file).unwrap();
                    assert_eq!(secret.trim().len(), 64);
                    for path in [&files.config_a, &files.config_b, &files.token_file] {
                        let data = fs::read_to_string(path).unwrap();
                        assert!(
                            path == &files.token_file || !data.contains(secret.trim()),
                            "config contains secret"
                        );
                        assert_eq!(mode(&path.to_string_lossy()), 0o600);
                    }
                    assert_no_pair_temporary_files(&o.output_dir);
                }
            }
        }
    }

    #[test]
    fn generate_pair_overwrite_and_validation_rollback() {
        let mut o = pair_options("overwrite");
        let files = generate_pair(&o).unwrap();
        let before = read_pair(&files);
        assert!(generate_pair(&o).is_err(), "overwrote pair without force");
        o.force = true;
        o.a.listen = "127.0.0.1:13316".into();
        o.b.listen = "127.0.0.1:13317".into();
        let files = generate_pair(&o).unwrap();
        let after = read_pair(&files);
        assert!(!files.token_created);
        assert_eq!(before[2], after[2]);
        assert_ne!(before[0], after[0]);
        assert_ne!(before[1], after[1]);
        o.b.target_address = "database.internal:3306".into();
        assert!(
            generate_pair(&o).is_err(),
            "accepted hostname backend without CIDR"
        );
        assert_eq!(
            read_pair(&files),
            after,
            "failed second config validation changed the pair"
        );
        assert_no_pair_temporary_files(&o.output_dir);
        let mut bad = pair_options("overwrite-bad");
        bad.b.tls_cert = "missing.crt".into();
        bad.b.tls_key = "missing.key".into();
        assert!(
            generate_pair(&bad).is_err(),
            "accepted missing second-node TLS material"
        );
        assert_eq!(
            entries(&bad.output_dir),
            0,
            "failed generation left partial configs or a new token"
        );
    }

    #[test]
    fn generate_pair_existing_second_file_and_token_path_protection() {
        for existing in ["peer-b.yaml", "shared.token"] {
            let mut o = pair_options("existing");
            fs::create_dir_all(&o.output_dir).unwrap();
            let path = format!("{}/{existing}", o.output_dir);
            fs::write(&path, "preserve-existing\n").unwrap();
            if existing == "shared.token" {
                o.b.target_address = "invalid-address".into();
            }
            assert!(
                generate_pair(&o).is_err(),
                "accepted existing config or invalid second backend"
            );
            assert_eq!(entries(&o.output_dir), 1, "partial pair left behind");
            assert_eq!(fs::read_to_string(&path).unwrap(), "preserve-existing\n");
        }
        for name in ["peer-a.yaml", "peer-b.yaml"] {
            let mut o = pair_options("tokenpath");
            o.token_file = format!("{}/{name}", o.output_dir);
            assert_eq!(
                generate_pair(&o).unwrap_err().message,
                "configuration and token paths must differ"
            );
        }
    }

    #[test]
    fn publish_pair_rollback_on_second_write_failure() {
        for force in [false, true] {
            let dir = temp_dir("publish");
            let mut outputs = vec![
                PairOutput {
                    path: format!("{dir}/peer-a.yaml"),
                    backup: String::new(),
                    data: b"new-a".to_vec(),
                    written: false,
                },
                PairOutput {
                    path: format!("{dir}/peer-b.yaml"),
                    backup: String::new(),
                    data: b"new-b".to_vec(),
                    written: false,
                },
            ];
            if force {
                for o in &outputs {
                    fs::write(
                        &o.path,
                        format!(
                            "old-{}",
                            Path::new(&o.path).file_name().unwrap().to_string_lossy()
                        ),
                    )
                    .unwrap();
                }
            }
            let second = outputs[1].path.clone();
            let (keep, result) = publish_pair(&mut outputs, force, &|path, data, mode| {
                if path == second {
                    return Err((false, Error::local("injected second publication failure")));
                }
                write_new(path, data, mode)
            });
            assert!(
                result.is_err() && !keep,
                "second write failure did not report successful rollback"
            );
            for o in &outputs {
                let read = fs::read_to_string(&o.path);
                if force {
                    let name = Path::new(&o.path)
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .into_owned();
                    assert_eq!(
                        read.unwrap(),
                        format!("old-{name}"),
                        "original pair was not restored"
                    );
                } else {
                    assert!(read.is_err(), "rollback left {}", o.path);
                }
            }
            assert_no_pair_temporary_files(&dir);
        }
    }

    #[test]
    fn publish_pair_rolls_back_file_created_before_failure() {
        let dir = temp_dir("publish-created");
        let mut outputs = vec![
            PairOutput {
                path: format!("{dir}/peer-a.yaml"),
                backup: String::new(),
                data: b"a\n".to_vec(),
                written: false,
            },
            PairOutput {
                path: format!("{dir}/peer-b.yaml"),
                backup: String::new(),
                data: b"b\n".to_vec(),
                written: false,
            },
        ];
        let n = std::cell::Cell::new(0);
        let (keep, result) = publish_pair(&mut outputs, false, &|path, data, mode| {
            let created = write_new(path, data, mode)?;
            n.set(n.get() + 1);
            if n.get() == 2 {
                return Err((
                    true,
                    Error::local("injected directory sync failure after creation"),
                ));
            }
            Ok(created)
        });
        assert!(result.is_err() && !keep);
        for o in &outputs {
            assert!(!Path::new(&o.path).exists(), "rollback left {}", o.path);
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn generate_pair_endpoints_and_external_token() {
        let mut o = pair_options("ext");
        o.a.node_id = "factory".into();
        o.b.node_id = "cloud".into();
        o.a.target_address = "database.internal:1433".into();
        o.a.allowed_cidrs = vec!["10.0.0.0/8".into()];
        o.a.peer_urls = vec![
            "https://b-primary.example.com".into(),
            "https://b-backup.example.com".into(),
        ];
        o.b.peer_urls = vec!["https://a.example.com".into()];
        o.token_file = format!("{}/common.token", temp_dir("ext-token"));
        let files = generate_pair(&o).unwrap();
        let (a, b) = load_pair(&files);
        assert_eq!(a.peers[0].endpoints.len(), 2);
        assert_eq!(a.peers[0].endpoints[1].priority, 2);
        assert_eq!(origin(&a.peers[0].endpoints[1].url), o.a.peer_urls[1]);
        assert_eq!(origin(&b.peers[0].endpoints[0].url), o.b.peer_urls[0]);
        assert_eq!(a.peers[0].token, b.inbound[0].tokens[0]);
        assert_eq!(b.peers[0].token, a.inbound[0].tokens[0]);
        for (listen, cert, expected) in [
            ("0.0.0.0:8080", "", "http://127.0.0.1:8080"),
            ("[::]:8443", "cert", "https://[::1]:8443"),
            ("192.0.2.1:8080", "", "http://192.0.2.1:8080"),
        ] {
            let node = NodeOptions {
                http_listen: listen.into(),
                tls_cert: cert.into(),
                ..NodeOptions::default()
            };
            assert_eq!(pair_endpoint(&node).unwrap(), expected);
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn generate_pair_tls_and_remote_plaintext_policy() {
        let mut o = pair_options("tls");
        (o.a.tls_cert, o.a.tls_key) = test_certificate_pair();
        (o.b.tls_cert, o.b.tls_key) = test_certificate_pair();
        let files = generate_pair(&o).unwrap();
        let (a, b) = load_pair(&files);
        assert!(a.http.tls.enabled && b.http.tls.enabled);
        assert_eq!(
            origin(&a.peers[0].endpoints[0].url),
            "https://127.0.0.1:18081"
        );
        assert_eq!(
            origin(&b.peers[0].endpoints[0].url),
            "https://127.0.0.1:18080"
        );
        let mut o = pair_options("plaintext");
        o.b.peer_urls = vec!["http://192.0.2.1:18080".into()];
        assert!(
            generate_pair(&o).is_err(),
            "remote plaintext was enabled implicitly"
        );
        assert_eq!(
            entries(&o.output_dir),
            0,
            "rejected second endpoint left a partial pair or token"
        );
        o.allow_insecure_http = true;
        generate_pair(&o).unwrap();
    }

    #[test]
    fn generate_pair_rejects_non_regular_and_aliased_outputs() {
        let mut o = pair_options("nonregular");
        o.force = true;
        fs::create_dir_all(format!("{}/peer-b.yaml", o.output_dir)).unwrap();
        assert!(generate_pair(&o).is_err(), "force replaced a directory");
        for link in ["hardlink", "symlink"] {
            let mut o = pair_options(link);
            o.force = true;
            fs::create_dir_all(&o.output_dir).unwrap();
            o.token_file = format!("{}/existing.token", o.output_dir);
            let original = "keep-this-existing-token\n";
            fs::write(&o.token_file, original).unwrap();
            let target = format!("{}/peer-b.yaml", o.output_dir);
            if link == "hardlink" {
                fs::hard_link(&o.token_file, &target).unwrap();
            } else {
                std::os::unix::fs::symlink(&o.token_file, &target).unwrap();
            }
            assert!(
                generate_pair(&o).is_err(),
                "accepted aliased config/token output ({link})"
            );
            assert_eq!(fs::read_to_string(&o.token_file).unwrap(), original);
        }
    }

    #[cfg(feature = "tls")]
    #[test]
    fn generate_role_carrier_recovery_matrix() {
        for role in ["ingress", "egress", "peer"] {
            for protocol in ["auto", "ws", "http-sse"] {
                for recovery in [false, true] {
                    let mut o = generate_options("role", role);
                    o.protocol = protocol.into();
                    o.recovery = recovery;
                    o.peer_urls = vec![
                        "https://primary.invalid".into(),
                        "https://backup.invalid".into(),
                    ];
                    let files = generate(o).unwrap_or_else(|e| panic!("{role}: {}", e.message));
                    let cfg = load(&files.config);
                    assert_eq!(cfg.transport.protocol, Protocol::parse(protocol).unwrap());
                    assert_eq!(cfg.transport.recovery_enabled, recovery);
                    assert_eq!(cfg.http.enabled, role != "ingress");
                    assert_eq!(!cfg.listeners.is_empty(), role != "egress");
                    if role != "egress" {
                        assert_eq!(cfg.peers[0].endpoints.len(), 2);
                        assert!(cfg.peers[0].tls.verify);
                    }
                    if role != "ingress" {
                        assert_eq!(
                            cfg.target("mysql").unwrap().allowed_cidrs[0],
                            "127.0.0.1/32"
                        );
                    }
                    assert_eq!(
                        fs::read_to_string(&files.token_file).unwrap().trim().len(),
                        64
                    );
                    assert_eq!(mode(&files.token_file.to_string_lossy()), 0o600);
                }
            }
        }
    }

    #[test]
    fn generate_overwrite_and_rollback() {
        let mut o = generate_options("ovr", "ingress");
        let files = generate(o.clone()).unwrap();
        let original = fs::read(&files.config).unwrap();
        let token = fs::read(&files.token_file).unwrap();
        assert_eq!(
            generate(o.clone()).unwrap_err().message,
            format!(
                "config already exists: {} (use --force to replace it)",
                files.config.display()
            )
        );
        o.force = true;
        o.listen = "127.0.0.1:13307".into();
        generate(o.clone()).unwrap();
        let updated = fs::read(&files.config).unwrap();
        assert_ne!(original, updated);
        assert_eq!(fs::read(&files.token_file).unwrap(), token);
        o.protocol = "unsupported".into();
        assert!(generate(o.clone()).is_err(), "invalid config generated");
        assert_eq!(
            fs::read(&files.config).unwrap(),
            updated,
            "failed generation changed existing config"
        );
        let mut bad = generate_options("ovr-bad", "peer");
        bad.protocol = "unsupported".into();
        assert!(generate(bad.clone()).is_err());
        assert!(
            !Path::new(&bad.output).exists(),
            "invalid config left behind"
        );
        assert!(
            !Path::new(&format!("{}/peer.token", dir_of(&bad.output))).exists(),
            "new secret left behind"
        );
    }

    #[test]
    fn generate_shared_token_and_hostname_policy() {
        let mut a = generate_options("shared-a", "egress");
        a.node_id = "B".into();
        a.peer_id = "A".into();
        let server = generate(a).unwrap();
        let mut b = generate_options("shared-b", "ingress");
        b.token_file = server.token_file.to_string_lossy().into_owned();
        let client = generate(b).unwrap();
        let cb = load(&server.config);
        let ca = load(&client.config);
        assert_eq!(ca.peers[0].token, cb.inbound[0].tokens[0]);
        assert!(!client.token_created);
        let mut o = generate_options("hostname", "egress");
        o.target_address = "db.internal:3306".into();
        assert_eq!(
            generate(o.clone()).unwrap_err().message,
            "hostname targets require an explicit --allow-cidr"
        );
        o.allowed_cidrs = vec!["10.0.0.0/8".into()];
        generate(o).unwrap();
    }

    #[cfg(feature = "tls")]
    #[test]
    fn generate_tls_material_validation() {
        let mut o = generate_options("tlsmat", "egress");
        (o.tls_cert, o.tls_key) = test_certificate_pair();
        generate(o).unwrap();
        let mut o = generate_options("tlsmat-missing", "egress");
        o.tls_cert = "missing.crt".into();
        o.tls_key = "missing.key".into();
        let e = generate(o).unwrap_err();
        assert_eq!(e.code, config::CODE_TLS, "{}", e.message);
    }

    #[test]
    fn force_keeps_config_mode() {
        use std::os::unix::fs::PermissionsExt;
        let mut o = PairOptions {
            output_dir: temp_dir("mode"),
            ..PairOptions::default()
        };
        generate_pair(&o).unwrap();
        let a = format!("{}/peer-a.yaml", o.output_dir);
        fs::set_permissions(&a, fs::Permissions::from_mode(0o640)).unwrap();
        o.force = true;
        generate_pair(&o).unwrap();
        assert_eq!(mode(&a), 0o640, "pair --force reset the mode");
        assert_eq!(
            mode(&format!("{}/peer-b.yaml", o.output_dir)),
            0o600,
            "untouched file mode changed"
        );
        let mut single = generate_options("mode-single", "egress");
        generate(single.clone()).unwrap();
        fs::set_permissions(&single.output, fs::Permissions::from_mode(0o640)).unwrap();
        single.force = true;
        generate(single.clone()).unwrap();
        assert_eq!(
            mode(&single.output),
            0o640,
            "Generate --force reset the mode"
        );
    }

    #[test]
    fn generated_insecure_http_uses_per_peer_key() {
        let mut o = PairOptions {
            output_dir: temp_dir("insecure"),
            ..PairOptions::default()
        };
        o.allow_insecure_http = true;
        o.a.peer_urls = vec!["http://b.example.invalid:18081".into()];
        let files = generate_pair(&o).unwrap();
        let text = fs::read_to_string(&files.config_a).unwrap();
        assert!(text.contains("allow_insecure_http: true"), "{text}");
        let cfg = load(&files.config_a);
        assert_eq!(
            origin(&cfg.peers[0].endpoints[0].url),
            "http://b.example.invalid:18081"
        );
    }

    /// gen-config rejects option combinations before touching the disk.
    #[test]
    fn generate_rejects_bad_options_without_side_effects() {
        let o = generate_options("opts", "egress");
        let mut bad_role = o.clone();
        bad_role.role = "x".into();
        assert_eq!(
            generate(bad_role).unwrap_err().message,
            "role must be ingress, egress, or peer"
        );
        let mut zero = o.clone();
        zero.max_sessions = 0;
        assert_eq!(
            generate(zero).unwrap_err().message,
            "max-sessions must be positive"
        );
        let mut tls = o.clone();
        tls.tls_cert = "c.pem".into();
        assert_eq!(
            generate(tls).unwrap_err().message,
            "tls-cert and tls-key must be supplied together"
        );
        let mut ing = o.clone();
        ing.role = "ingress".into();
        ing.tls_cert = "c".into();
        ing.tls_key = "k".into();
        assert!(generate(ing)
            .unwrap_err()
            .message
            .starts_with("ingress has no HTTP server"));
        assert!(!Path::new(&o.output).exists());
        let mut rev = pair_options("revbidir");
        rev.reverse = true;
        assert!(generate_pair(&rev)
            .unwrap_err()
            .message
            .starts_with("reverse mode needs --mode a-to-b or b-to-a"));
        let mut same = pair_options("same");
        same.b.node_id = "A".into();
        assert_eq!(
            generate_pair(&same).unwrap_err().message,
            "node IDs for A and B must be nonempty and different"
        );
    }
}
