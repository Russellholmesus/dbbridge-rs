//! Linux systemd service preparation and lifecycle management.
//!
//! The module deliberately keeps systemd commands behind an injectable runner:
//! unit generation, rollback and ownership checks are testable without writing
//! to `/etc/systemd/system` or requiring a running system manager.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
};

use crate::config;
use crate::error::{Error, Result};
use crate::util::json::{self, Json};

pub const MARKER: &str = "Managed by DBBridge";
const SERVICE_CODE: &str = config::CODE_SERVICE_INSTALL;
const SYSTEM_UNIT_DIR: &str = "/etc/systemd/system";

#[derive(Debug, Clone)]
pub struct Options {
    pub name: String,
    pub config: PathBuf,
    pub executable: Option<PathBuf>,
    pub account: Option<String>,
    pub log_level: String,
    pub log_format: String,
    pub start: bool,
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub platform: String,
    pub name: String,
    pub executable: PathBuf,
    pub arguments: Vec<String>,
    pub working_directory: PathBuf,
    pub account: String,
    pub automatic: bool,
    pub start: bool,
    pub unit_file: PathBuf,
    pub unit: String,
    pub warnings: Vec<String>,
    pub environment_file: Option<PathBuf>,
    pub environment_names: Vec<String>,
    environment: BTreeMap<String, String>,
    read_paths: Vec<PathBuf>,
}

pub fn ensure_supported() -> Result<()> {
    ensure_platform_supported(std::env::consts::OS)
}

fn ensure_platform_supported(platform: &str) -> Result<()> {
    if platform == "linux" {
        Ok(())
    } else {
        Err(service_error(
            "service management is supported only on Linux systemd",
        ))
    }
}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && !name.ends_with(".service")
}

pub fn prepare(options: &Options) -> Result<Plan> {
    ensure_supported()?;
    if !valid_name(&options.name) {
        return Err(service_error(
            "service-name must be 1-64 letters/digits/._-, without a .service suffix",
        ));
    }
    if options.log_level != "debug"
        && options.log_level != "info"
        && options.log_level != "warn"
        && options.log_level != "error"
    {
        return Err(Error::local("invalid --log-level"));
    }
    if options.log_format != "text" && options.log_format != "json" {
        return Err(Error::local("invalid --log-format"));
    }

    let config_path = absolute(&options.config)?;
    let cfg = config::load(&config_path).map_err(|e| {
        let code = if e.code.is_empty() {
            config::CODE_CONFIG_INVALID
        } else {
            e.code.as_str()
        };
        Error::new(code, format!("config preflight: {}", e.message))
    })?;
    let references = credential_references(&config_path)?;
    let environment = snapshot_values(&references)?;
    let executable = match &options.executable {
        Some(path) => absolute(path)?,
        None => invoked_executable()?,
    };
    let executable_metadata = fs::metadata(&executable)
        .map_err(|e| service_error(format!("service executable {}: {e}", executable.display())))?;
    if !executable_metadata.is_file() {
        return Err(service_error(format!(
            "service executable {} must be a regular file (or a symlink to one)",
            executable.display()
        )));
    }

    let account = options
        .account
        .clone()
        .unwrap_or_else(|| "root".to_string());
    if !valid_account(&account) {
        return Err(service_error("invalid --service-user"));
    }
    let working_directory = config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let environment_file = (!environment.is_empty())
        .then(|| working_directory.join(format!("{}.service-env.json", options.name)));
    let environment_names = environment.keys().cloned().collect::<Vec<_>>();
    let mut arguments = vec![
        "run".to_string(),
        "--config".to_string(),
        config_path.to_string_lossy().into_owned(),
        "--service-name".to_string(),
        options.name.clone(),
        "--log-level".to_string(),
        options.log_level.clone(),
        "--log-format".to_string(),
        options.log_format.clone(),
    ];
    if let Some(path) = &environment_file {
        arguments.push("--env-file".into());
        arguments.push(path.to_string_lossy().into_owned());
    }
    let mut read_paths = references.read_paths.into_iter().collect::<Vec<_>>();
    if let Some(path) = &environment_file {
        read_paths.push(path.clone());
    }
    let unit_file = PathBuf::from(SYSTEM_UNIT_DIR).join(format!("{}.service", options.name));
    let unit = systemd_unit(
        &options.name,
        &account,
        &executable,
        &config_path,
        &options.log_level,
        &options.log_format,
        &working_directory,
        cfg.max_shutdown_duration(),
        cfg.limits.max_sessions,
        uses_privileged_port(&cfg),
        environment_file.as_deref(),
        &read_paths,
    )?;
    let mut warnings = Vec::new();
    if matches!(account.as_str(), "root" | "0") {
        warnings.push("the service runs as root without capabilities (empty CapabilityBoundingSet): root cannot bypass file permissions, so the configuration, credentials and their directories must be readable by uid 0 through their mode bits; prefer a dedicated account with --service-user".into());
    }
    if let Ok(resolved) = fs::canonicalize(&executable) {
        if resolved != executable {
            warnings.push(format!(
                "service executable {} is a symbolic link to {}; the service starts whatever the link points to when it starts",
                executable.display(),
                resolved.display()
            ));
        }
    }
    warnings.extend(cfg.warnings.iter().cloned());
    Ok(Plan {
        platform: "linux".into(),
        name: options.name.clone(),
        executable,
        arguments,
        working_directory,
        account,
        automatic: true,
        start: options.start,
        unit_file,
        unit,
        warnings,
        environment_file,
        environment_names,
        environment,
        read_paths,
    })
}

pub fn install(options: &Options, dry_run: bool) -> Result<Plan> {
    let plan = prepare(options)?;
    if dry_run {
        return Ok(plan);
    }
    systemd_available()?;
    let account = lookup_account(&plan.account)?;
    for path in &plan.read_paths {
        check_account_access(path, &account, 0o4)?;
    }
    check_account_access(&plan.executable, &account, 0o1)?;
    if let Some(environment_file) = &plan.environment_file {
        if let Some(parent) = environment_file.parent() {
            check_account_access(parent, &account, 0o1)?;
        }
    }
    install_at(Path::new(SYSTEM_UNIT_DIR), &plan, Some(&account), systemctl)
        .map_err(|e| service_error(e.message))?;
    Ok(plan)
}

pub fn uninstall(name: &str, dry_run: bool) -> Result<()> {
    ensure_supported()?;
    if !valid_name(name) {
        return Err(service_error("invalid service-name"));
    }
    if dry_run {
        return owned_unit(Path::new(SYSTEM_UNIT_DIR), name).map(|_| ());
    }
    systemd_available()?;
    uninstall_at(Path::new(SYSTEM_UNIT_DIR), name, systemctl).map_err(|e| service_error(e.message))
}

fn service_error(message: impl Into<String>) -> Error {
    Error::new(SERVICE_CODE, message)
}

fn absolute(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .map_err(|e| service_error(format!("current directory: {e}")))
    }
}

fn invoked_executable() -> Result<PathBuf> {
    let arg0 = std::env::args_os().next();
    if let Some(path) = arg0 {
        let path = PathBuf::from(path);
        if path.components().count() > 1 {
            return absolute(&path);
        }
        if let Some(path_value) = std::env::var_os("PATH") {
            for dir in std::env::split_paths(&path_value) {
                let candidate = dir.join(&path);
                if candidate.is_file() {
                    return absolute(&candidate);
                }
            }
        }
    }
    std::env::current_exe()
        .map_err(|e| service_error(format!("cannot determine dbbridge executable: {e}")))
}

fn valid_account(account: &str) -> bool {
    !account.is_empty()
        && account.len() <= 128
        && account
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'$'))
        && !account.starts_with('-')
}

#[derive(Default)]
struct CredentialReferences {
    required_env: BTreeSet<String>,
    optional_env: BTreeSet<String>,
    read_paths: BTreeSet<PathBuf>,
}

fn add_env_name(value: Option<String>, required: bool, refs: &mut CredentialReferences) {
    let Some(name) = value.filter(|name| !name.is_empty()) else {
        return;
    };
    if required {
        refs.required_env.insert(name);
    } else {
        refs.optional_env.insert(name);
    }
}

fn add_path(value: Option<String>, base: &Path, refs: &mut CredentialReferences) {
    let Some(value) = value.filter(|value| !value.is_empty()) else {
        return;
    };
    let path = PathBuf::from(value);
    refs.read_paths.insert(if path.is_absolute() {
        path
    } else {
        base.join(path)
    });
}

fn collect_inbound_env(
    doc: &crate::config::yaml::Yaml,
    base: &Path,
    refs: &mut CredentialReferences,
) {
    for identity in doc.seq_of("inbound_peers").unwrap_or_default() {
        let enabled = identity.bool_of("enabled").unwrap_or(true);
        if let Some(names) = identity.seq_of("token_envs") {
            for name in names {
                add_env_name(name.as_str().map(str::to_string), enabled, refs);
            }
        }
        if enabled {
            if let Some(paths) = identity.seq_of("token_files") {
                for path in paths {
                    add_path(path.as_str().map(str::to_string), base, refs);
                }
            }
        }
    }
}

fn collect_credentials_document(
    doc: &crate::config::yaml::Yaml,
    base: &Path,
    refs: &mut CredentialReferences,
) {
    collect_inbound_env(doc, base, refs);
    for peer in doc.seq_of("outbound_peers").unwrap_or_default() {
        add_env_name(peer.str_of("token_env"), true, refs);
        add_path(peer.str_of("token_file"), base, refs);
    }
}

fn read_yaml(path: &Path, code: &str) -> Result<crate::config::yaml::Yaml> {
    const MAX_CONFIG_BYTES: usize = 1 << 20;
    let bytes = fs::read(path).map_err(|e| Error::new(code, format!("{}: {e}", path.display())))?;
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(Error::new(
            code,
            format!(
                "{}: file exceeds maximum size of {MAX_CONFIG_BYTES} bytes",
                path.display()
            ),
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|e| Error::new(code, format!("{}: {e}", path.display())))?;
    crate::config::yaml::parse(text)
        .map_err(|e| Error::new(code, format!("{}: {e}", path.display())))
}

fn credential_references(config_path: &Path) -> Result<CredentialReferences> {
    use crate::config::yaml::Yaml;

    let mut refs = CredentialReferences::default();
    refs.read_paths.insert(config_path.to_path_buf());
    let doc = read_yaml(config_path, config::CODE_CONFIG_READ)?;
    let base = config_path.parent().unwrap_or_else(|| Path::new("."));

    for peer in doc.seq_of("peers").unwrap_or_default() {
        add_env_name(peer.str_of("token_env"), true, &mut refs);
        add_path(peer.str_of("token_file"), base, &mut refs);
        if let Some(tls) = peer.get("tls") {
            add_path(tls.str_of("ca_file"), base, &mut refs);
        }
    }

    if let Some(reverse) = doc.get("reverse") {
        if reverse.bool_of("enabled").unwrap_or(false) {
            add_env_name(reverse.str_of("token_env"), true, &mut refs);
            add_path(reverse.str_of("token_file"), base, &mut refs);
            if let Some(tls) = reverse.get("tls") {
                add_path(tls.str_of("ca_file"), base, &mut refs);
            }
        }
    }

    if let Some(http) = doc.get("http") {
        if http.bool_of("enabled").unwrap_or(false) {
            if let Some(tls) = http.get("tls") {
                if tls.bool_of("enabled").unwrap_or(false) {
                    add_path(tls.str_of("cert_file"), base, &mut refs);
                    add_path(tls.str_of("key_file"), base, &mut refs);
                }
            }
        }
    }

    if let Some(auth) = doc.get("auth") {
        collect_inbound_env(auth, base, &mut refs);
        if let Some(credentials_file) = auth
            .str_of("credentials_file")
            .filter(|value| !value.is_empty())
        {
            let path = PathBuf::from(credentials_file);
            let path = if path.is_absolute() {
                path
            } else {
                base.join(path)
            };
            refs.read_paths.insert(path.clone());
            let credentials = read_yaml(&path, config::CODE_CREDENTIAL)?;
            let credentials_base = path.parent().unwrap_or(base);
            collect_credentials_document(&credentials, credentials_base, &mut refs);
        }
    }

    // Keep this import use explicit: the root YAML may be a scalar when called
    // directly by a test, but the regular config loader rejects that first.
    let _ = Yaml::Null;
    Ok(refs)
}

fn safe_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == b'_')
        || !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return false;
    }
    let upper = name.to_ascii_uppercase();
    let blocked = [
        "HOME",
        "PATH",
        "SYSTEMROOT",
        "WINDIR",
        "COMSPEC",
        "USERPROFILE",
        "TEMP",
        "TMP",
        "TMPDIR",
        "NOTIFY_SOCKET",
        "LISTEN_PID",
        "LISTEN_FDS",
        "LISTEN_FDNAMES",
        "WATCHDOG_USEC",
        "WATCHDOG_PID",
        "GODEBUG",
        "GOTRACEBACK",
        "GOMAXPROCS",
        "GOMEMLIMIT",
        "GOGC",
        "GOFIPS140",
        "GOCOVERDIR",
        "GORACE",
        "GOENV",
        "GOROOT",
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "NO_PROXY",
        "ALL_PROXY",
        "REQUEST_METHOD",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "TZ",
        "ZONEINFO",
    ];
    !blocked.contains(&upper.as_str()) && !upper.starts_with("LD_") && !upper.starts_with("DYLD_")
}

fn snapshot_values(refs: &CredentialReferences) -> Result<BTreeMap<String, String>> {
    let mut names = refs.required_env.clone();
    for name in &refs.optional_env {
        if !names.contains(name) && env::var(name).is_ok_and(|value| !value.is_empty()) {
            names.insert(name.clone());
        }
    }
    let mut values = BTreeMap::new();
    for name in names {
        if !safe_env_name(&name) {
            return Err(Error::new(
                config::CODE_ENVIRONMENT,
                format!("unsupported credential environment name {name:?}"),
            ));
        }
        let value = env::var(&name).map_err(|_| {
            Error::new(
                config::CODE_ENVIRONMENT,
                format!("credential environment {name} is missing or malformed"),
            )
        })?;
        if value.is_empty() || value.contains(['\0', '\r', '\n']) {
            return Err(Error::new(
                config::CODE_ENVIRONMENT,
                format!("credential environment {name} is missing or malformed"),
            ));
        }
        values.insert(name, value);
    }
    Ok(values)
}

fn uses_privileged_port(cfg: &config::Config) -> bool {
    let mut addresses = Vec::new();
    if cfg.http.enabled {
        addresses.push(cfg.http.listen.as_str());
    }
    if cfg.admin.enabled {
        addresses.push(cfg.admin.listen.as_str());
    }
    addresses.extend(cfg.listeners.iter().map(|l| l.listen.as_str()));
    addresses.into_iter().any(|address| {
        address
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok())
            .is_some_and(|port| port > 0 && port < 1024)
    })
}

fn unit_quote(value: &str, command: bool) -> Result<String> {
    if value.chars().any(|ch| ch.is_control()) {
        return Err(service_error(
            "control characters are not supported in systemd unit values",
        ));
    }
    let mut escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%");
    if command {
        escaped = escaped.replace('$', "$$");
    }
    Ok(format!("\"{escaped}\""))
}

#[allow(clippy::too_many_arguments)]
fn systemd_unit(
    name: &str,
    account: &str,
    executable: &Path,
    config: &Path,
    log_level: &str,
    log_format: &str,
    working_directory: &Path,
    shutdown_timeout: Duration,
    max_sessions: u32,
    low_port: bool,
    environment_file: Option<&Path>,
    read_paths: &[PathBuf],
) -> Result<String> {
    if !valid_name(name) || !valid_account(account) {
        return Err(service_error("invalid systemd service/account name"));
    }
    let executable_arg = unit_quote(&executable.to_string_lossy(), true)?;
    let mut arguments = vec![
        "run".to_string(),
        "--config".to_string(),
        config.to_string_lossy().into_owned(),
        "--service-name".to_string(),
        name.to_string(),
        "--log-level".to_string(),
        log_level.to_string(),
        "--log-format".to_string(),
        log_format.to_string(),
    ];
    if let Some(path) = environment_file {
        arguments.push("--env-file".into());
        arguments.push(path.to_string_lossy().into_owned());
    }
    let arguments = arguments
        .iter()
        .map(|argument| unit_quote(argument, true))
        .collect::<Result<Vec<_>>>()?
        .join(" ");
    let workdir = working_directory.to_string_lossy();
    if workdir.chars().any(|ch| ch.is_control()) || workdir.trim() != workdir.as_ref() {
        return Err(service_error("invalid systemd working directory"));
    }
    let workdir = workdir.replace('%', "%%");
    let stop = (shutdown_timeout + Duration::from_secs(15)).max(Duration::from_secs(45));
    let nofile = 8192u64.max(
        u64::from(max_sessions)
            .saturating_mul(4)
            .saturating_add(1024),
    );
    let caps = if low_port { "CAP_NET_BIND_SERVICE" } else { "" };
    let mut paths = vec![
        executable.to_path_buf(),
        config.to_path_buf(),
        working_directory.to_path_buf(),
    ];
    paths.extend(read_paths.iter().cloned());
    let originals = paths.clone();
    for path in originals {
        if let Ok(resolved) = fs::canonicalize(path) {
            if !paths.contains(&resolved) {
                paths.push(resolved);
            }
        }
    }
    let mut protect_home = "true";
    let mut private_tmp = "true";
    for path in paths {
        let with_slash = format!("{}/", path.to_string_lossy());
        if ["/home/", "/root/", "/run/user/"]
            .iter()
            .any(|prefix| with_slash.starts_with(prefix))
        {
            protect_home = "read-only";
        }
        if ["/tmp/", "/var/tmp/"]
            .iter()
            .any(|prefix| with_slash.starts_with(prefix))
        {
            private_tmp = "false";
        }
    }
    Ok(format!(
        "# {MARKER}\n\
[Unit]\n\
Description=DBBridge peer node ({name})\n\
After=network-online.target\n\
Wants=network-online.target\n\
StartLimitIntervalSec=300\n\
StartLimitBurst=10\n\
\n\
[Service]\n\
Type=notify\n\
NotifyAccess=main\n\
User={account}\n\
WorkingDirectory={workdir}\n\
ExecStart={executable_arg} {arguments}\n\
ExecReload=/bin/kill -HUP $MAINPID\n\
Restart=on-failure\n\
RestartSec=5s\n\
RestartPreventExitStatus=78\n\
TimeoutStartSec=30s\n\
TimeoutStopSec={}s\n\
KillSignal=SIGTERM\n\
NoNewPrivileges=true\n\
UMask=0077\n\
LimitNOFILE={nofile}\n\
StandardOutput=journal\n\
StandardError=journal\n\
CapabilityBoundingSet={caps}\n\
AmbientCapabilities={caps}\n\
ProtectSystem=strict\n\
ProtectHome={protect_home}\n\
PrivateTmp={private_tmp}\n\
PrivateDevices=true\n\
ProtectKernelTunables=true\n\
ProtectKernelModules=true\n\
ProtectKernelLogs=true\n\
ProtectControlGroups=true\n\
ProtectClock=true\n\
ProtectHostname=true\n\
RestrictNamespaces=true\n\
RestrictRealtime=true\n\
RestrictSUIDSGID=true\n\
LockPersonality=true\n\
MemoryDenyWriteExecute=true\n\
SystemCallArchitectures=native\n\
SystemCallFilter=@system-service\n\
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n\
\n\
[Install]\n\
WantedBy=multi-user.target\n",
        stop.as_secs()
    ))
}

fn systemd_available() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        if unsafe { geteuid() } != 0 {
            return Err(service_error(
                "systemd service installation requires root (use sudo)",
            ));
        }
        let info = fs::metadata("/run/systemd/system").map_err(|_| {
            service_error("systemd is not running as the system manager; use --dry-run to preview")
        })?;
        if !info.is_dir() {
            return Err(service_error(
                "systemd is not running as the system manager; use --dry-run to preview",
            ));
        }
        let _ = info.uid();
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(service_error(
            "service management is supported only on Linux systemd",
        ))
    }
}

#[cfg(target_os = "linux")]
extern "C" {
    fn geteuid() -> u32;
    fn chown(path: *const std::os::raw::c_char, owner: u32, group: u32) -> i32;
}

fn systemctl(args: &[String]) -> Result<()> {
    let output = Command::new("systemctl")
        .args(args)
        .output()
        .map_err(|e| service_error(format!("cannot execute systemctl: {e}")))?;
    if output.status.success() {
        Ok(())
    } else {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(service_error(format!(
            "systemctl {} failed ({}): {}",
            args.join(" "),
            output.status,
            detail
        )))
    }
}

fn unit_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{name}.service"))
}

fn create_unit(path: &Path, contents: &str) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o644);
    }
    let mut file = options
        .open(path)
        .map_err(|e| service_error(format!("{}: {e}", path.display())))?;
    if let Err(e) = file.write_all(contents.as_bytes()) {
        let _ = fs::remove_file(path);
        return Err(service_error(format!("{}: {e}", path.display())));
    }
    if let Err(e) = file.sync_all() {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(service_error(format!("{}: {e}", path.display())));
    }
    Ok(())
}

const MAX_ENVIRONMENT_BYTES: usize = 1 << 20;

/// Loads a private credential snapshot before configuration parsing.
/// Existing non-empty process variables take precedence over the snapshot.
pub fn load_environment(path: &Path) -> Result<()> {
    let values = read_environment_values(path, true)?;
    for (name, value) in values {
        if let Some(current) = env::var_os(&name) {
            if !current.is_empty() {
                if current.to_str() != Some(value.as_str()) {
                    eprintln!("Warning: environment snapshot value ignored; process environment already sets {name}");
                }
                continue;
            }
        }
        env::set_var(&name, value);
    }
    Ok(())
}

fn read_environment_values(path: &Path, check_owner: bool) -> Result<BTreeMap<String, String>> {
    let file = fs::File::open(path).map_err(|e| {
        Error::new(
            config::CODE_ENVIRONMENT,
            format!(
                "open {}: {}",
                path.display(),
                crate::util::spec_errno_text(&e)
            ),
        )
    })?;
    let decode_error = |message: String| {
        Error::new(
            config::CODE_ENVIRONMENT,
            format!("service environment: {message}"),
        )
    };
    let mut bytes = Vec::new();
    (&file)
        .take((MAX_ENVIRONMENT_BYTES as u64) + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| decode_error(crate::util::spec_errno_text(&e)))?;
    if bytes.len() > MAX_ENVIRONMENT_BYTES {
        return Err(decode_error("JSON limit or UTF-8 violation".into()));
    }
    crate::util::spec_json::decode_json_precheck(&bytes, MAX_ENVIRONMENT_BYTES)
        .map_err(decode_error)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| decode_error("JSON limit or UTF-8 violation".into()))?;
    let parsed = json::parse_limited(text, MAX_ENVIRONMENT_BYTES).map_err(decode_error)?;
    let kind = |v: &Json| match v {
        Json::Null => "null",
        Json::Bool(_) => "bool",
        Json::Num(_) => "number",
        Json::Str(_) => "string",
        Json::Arr(_) => "array",
        Json::Obj(_) => "object",
    };
    let fields = match parsed {
        Json::Obj(fields) => fields,
        Json::Null => Vec::new(),
        other => {
            return Err(decode_error(format!(
                "json: cannot unmarshal {} into Go value of type map[string]jsontext.Value",
                kind(&other)
            )))
        }
    };
    let mut values = BTreeMap::new();
    for (name, value) in fields {
        let value = match value {
            Json::Str(value) => value,
            Json::Null => {
                return Err(decode_error(
                    "null is not allowed for scalar or object fields".into(),
                ))
            }
            other if name.is_empty() => {
                return Err(decode_error(format!(
                    "json: cannot unmarshal {} into Go value of type string",
                    kind(&other)
                )))
            }
            other => {
                return Err(decode_error(format!(
                    "json: cannot unmarshal {} into Go struct field .{name} of type string",
                    kind(&other)
                )))
            }
        };
        if !safe_env_name(&name) || value.is_empty() || value.contains('\0') {
            return Err(Error::new(
                config::CODE_ENVIRONMENT,
                "invalid service environment entry",
            ));
        }
        values.insert(name, value);
    }
    let metadata = file
        .metadata()
        .map_err(|e| environment_error(path, crate::util::spec_errno_text(&e)))?;
    validate_environment_metadata(path, &metadata, check_owner)
        .map_err(|message| environment_error(path, message))?;
    Ok(values)
}

fn validate_environment_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    check_owner: bool,
) -> std::result::Result<(), String> {
    if !metadata.file_type().is_file() {
        return Err("not a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "mode {mode:04o} allows group/other access; use chmod 600"
            ));
        }
    }
    #[cfg(target_os = "linux")]
    if check_owner {
        use std::os::unix::fs::MetadataExt;
        let uid = metadata.uid();
        let current_uid = unsafe { geteuid() };
        if uid != current_uid && uid != 0 {
            return Err(format!(
                "owned by uid {uid}, not the service account (uid {current_uid}) or root"
            ));
        }
    }
    let _ = path;
    Ok(())
}

fn environment_error(path: &Path, message: impl std::fmt::Display) -> Error {
    Error::new(
        config::CODE_ENVIRONMENT,
        format!("service environment {}: {message}", path.display()),
    )
}

fn environment_bytes(values: &BTreeMap<String, String>) -> Vec<u8> {
    let mut output = String::from("{");
    if !values.is_empty() {
        output.push('\n');
        for (index, (name, value)) in values.iter().enumerate() {
            output.push_str("  ");
            json::write_json(&Json::Str(name.clone()), &mut output);
            output.push_str(": ");
            json::write_json(&Json::Str(value.clone()), &mut output);
            if index + 1 != values.len() {
                output.push(',');
            }
            output.push('\n');
        }
    }
    output.push_str("}\n");
    output.into_bytes()
}

fn save_environment(plan: &Plan, account: Option<&ServiceAccount>) -> Result<bool> {
    let Some(path) = plan.environment_file.as_deref() else {
        return Ok(false);
    };
    if plan.environment.is_empty() {
        return Ok(false);
    }
    let contents = environment_bytes(&plan.environment);
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_environment_metadata(path, &metadata, false)
                .map_err(|message| service_error(format!("service environment: {message}")))?;
            let existing =
                fs::read(path).map_err(|e| service_error(format!("{}: {e}", path.display())))?;
            if existing != contents {
                return Err(service_error(
                    "service environment snapshot already exists with different values; update it explicitly before reinstalling",
                ));
            }
            if let Some(account) = account {
                check_account_access(path, account, 0o4)?;
            }
            Ok(false)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(path)
                .map_err(|e| service_error(format!("{}: {e}", path.display())))?;
            let created = (|| -> Result<()> {
                file.write_all(&contents)
                    .map_err(|e| service_error(format!("{}: {e}", path.display())))?;
                file.sync_all()
                    .map_err(|e| service_error(format!("{}: {e}", path.display())))?;
                if let Some(account) = account {
                    set_snapshot_owner(path, account).map_err(|e| {
                        service_error(format!("service environment ownership: {e}"))
                    })?;
                    file.sync_all()
                        .map_err(|e| service_error(format!("{}: {e}", path.display())))?;
                    check_account_access(path, account, 0o4)?;
                }
                let metadata = file
                    .metadata()
                    .map_err(|e| service_error(format!("{}: {e}", path.display())))?;
                validate_environment_metadata(path, &metadata, false)
                    .map_err(|message| service_error(format!("service environment: {message}")))
            })();
            if let Err(error) = created {
                drop(file);
                let _ = fs::remove_file(path);
                return Err(error);
            }
            Ok(true)
        }
        Err(error) => Err(service_error(format!("{}: {error}", path.display()))),
    }
}

fn remove_created_environment(plan: &Plan, created: bool) {
    if created {
        if let Some(path) = &plan.environment_file {
            let _ = fs::remove_file(path);
        }
    }
}

#[derive(Debug, Clone)]
struct ServiceAccount {
    uid: u32,
    gid: u32,
    groups: BTreeSet<u32>,
}

#[cfg(target_os = "linux")]
fn lookup_account(name_or_id: &str) -> Result<ServiceAccount> {
    let passwd = fs::read_to_string("/etc/passwd")
        .map_err(|e| service_error(format!("service account database: {e}")))?;
    let wanted_uid = name_or_id.parse::<u32>().ok();
    let record = passwd.lines().find_map(|line| {
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() < 4
            || (fields[0] != name_or_id && wanted_uid != fields[2].parse::<u32>().ok())
        {
            return None;
        }
        Some((
            fields[0].to_string(),
            fields[2].parse::<u32>().ok()?,
            fields[3].parse::<u32>().ok()?,
        ))
    });
    let (name, uid, gid) = record
        .ok_or_else(|| service_error(format!("service account: unknown user {name_or_id:?}")))?;
    let mut groups = BTreeSet::from([gid]);
    if let Ok(group_file) = fs::read_to_string("/etc/group") {
        for line in group_file.lines() {
            let fields = line.split(':').collect::<Vec<_>>();
            if fields.len() >= 4 && fields[3].split(',').any(|member| member == name) {
                if let Ok(group_id) = fields[2].parse::<u32>() {
                    groups.insert(group_id);
                }
            }
        }
    }
    Ok(ServiceAccount { uid, gid, groups })
}

#[cfg(not(target_os = "linux"))]
fn lookup_account(_name_or_id: &str) -> Result<ServiceAccount> {
    Err(service_error(
        "service account lookup is supported only on Linux",
    ))
}

#[cfg(target_os = "linux")]
fn check_account_access(path: &Path, account: &ServiceAccount, want: u32) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let access = |candidate: &Path, bit: u32| -> std::io::Result<bool> {
        let metadata = fs::metadata(candidate)?;
        let mode = metadata.mode();
        Ok(if metadata.uid() == account.uid {
            mode & (bit << 6) != 0
        } else if account.groups.contains(&metadata.gid()) {
            mode & (bit << 3) != 0
        } else {
            mode & bit != 0
        })
    };

    let mut directory = path.parent().unwrap_or_else(|| Path::new("/"));
    loop {
        let allowed = access(directory, 0o1)
            .map_err(|e| service_error(format!("{}: {e}", directory.display())))?;
        if !allowed {
            return Err(service_error(format!(
                "service account cannot traverse directory {} needed for {} (execute permission required)",
                directory.display(), path.display()
            )));
        }
        let parent = directory.parent();
        match parent {
            Some(next) if next != directory => directory = next,
            _ => break,
        }
    }
    let allowed =
        access(path, want).map_err(|e| service_error(format!("{}: {e}", path.display())))?;
    if !allowed {
        let hint = if account.uid == 0 {
            "root has no DAC-bypass capabilities in the unit; grant uid 0 read/execute permission or choose a service account that can access the file"
        } else {
            "grant the service account read/execute access or choose another --service-user"
        };
        return Err(service_error(format!(
            "service account cannot access {}; {hint}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn check_account_access(_path: &Path, _account: &ServiceAccount, _want: u32) -> Result<()> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn set_snapshot_owner(path: &Path, account: &ServiceAccount) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let result = unsafe { chown(path.as_ptr(), account.uid, account.gid) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
fn set_snapshot_owner(_path: &Path, _account: &ServiceAccount) -> std::io::Result<()> {
    Ok(())
}

fn install_at<F>(
    dir: &Path,
    plan: &Plan,
    account: Option<&ServiceAccount>,
    mut command: F,
) -> Result<()>
where
    F: FnMut(&[String]) -> Result<()>,
{
    fs::create_dir_all(dir).map_err(|e| service_error(format!("{}: {e}", dir.display())))?;
    let path = unit_path(dir, &plan.name);
    if fs::symlink_metadata(&path).is_ok() {
        return Err(service_error(format!(
            "service already exists: {}; uninstall it before reinstalling",
            plan.name
        )));
    }
    let created_environment = save_environment(plan, account)?;
    if let Err(error) = create_unit(&path, &plan.unit) {
        remove_created_environment(plan, created_environment);
        return Err(error);
    }
    if let Err(err) = command(&["daemon-reload".into()]) {
        let _ = fs::remove_file(&path);
        let _ = command(&["daemon-reload".into()]);
        remove_created_environment(plan, created_environment);
        return Err(err);
    }
    let unit = format!("{}.service", plan.name);
    if let Err(err) = command(&["enable".into(), unit.clone()]) {
        let _ = command(&["disable".into(), unit.clone()]);
        let _ = fs::remove_file(&path);
        let _ = command(&["daemon-reload".into()]);
        remove_created_environment(plan, created_environment);
        return Err(err);
    }
    if plan.start {
        command(&["start".into(), unit]).map_err(|e| {
            service_error(format!(
                "service installed and enabled, but start failed: {}",
                e.message
            ))
        })?;
    }
    Ok(())
}

fn owned_unit(dir: &Path, name: &str) -> Result<(PathBuf, String)> {
    if !valid_name(name) {
        return Err(service_error("invalid --service-name"));
    }
    let path = unit_path(dir, name);
    let info = fs::symlink_metadata(&path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            service_error(format!(
                "service {name} is not installed ({} not found)",
                path.display()
            ))
        } else {
            service_error(format!("{}: {e}", path.display()))
        }
    })?;
    if !info.file_type().is_file() {
        return Err(service_error("refusing to remove a non-regular unit"));
    }
    let contents =
        fs::read_to_string(&path).map_err(|e| service_error(format!("{}: {e}", path.display())))?;
    if !contents.starts_with(&format!("# {MARKER}\n")) {
        return Err(service_error(
            "refusing to remove a unit not installed by DBBridge",
        ));
    }
    Ok((path, contents))
}

fn uninstall_at<F>(dir: &Path, name: &str, mut command: F) -> Result<()>
where
    F: FnMut(&[String]) -> Result<()>,
{
    let (path, contents) = owned_unit(dir, name)?;
    let unit = format!("{name}.service");
    let stop_wait = unit_stop_wait(&contents).as_secs().to_string();
    command(&["disable".into(), "--now".into(), unit])
        .map_err(|e| service_error(format!("{} (stop timeout budget: {stop_wait}s)", e.message)))?;
    fs::remove_file(&path).map_err(|e| service_error(format!("{}: {e}", path.display())))?;
    command(&["daemon-reload".into()])
}

fn unit_stop_wait(contents: &str) -> Duration {
    let mut wait = Duration::from_secs(120);
    for line in contents.lines() {
        if let Some(value) = line.trim().strip_prefix("TimeoutStopSec=") {
            if let Ok(seconds) = value.strip_suffix('s').unwrap_or(value).parse::<u64>() {
                wait = wait.max(Duration::from_secs(seconds.saturating_add(30)));
            }
        }
    }
    wait
}

#[cfg(target_os = "linux")]
pub fn notify(state: &str) -> std::io::Result<()> {
    let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
        return Ok(());
    };
    notify_to(&path.to_string_lossy(), state)
}

#[cfg(target_os = "linux")]
fn notify_to(path: &str, state: &str) -> std::io::Result<()> {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram};
    if path.is_empty() {
        return Ok(());
    }
    let socket = UnixDatagram::unbound()?;
    let address = if let Some(abstract_name) = path.strip_prefix('@') {
        SocketAddr::from_abstract_name(abstract_name.as_bytes())?
    } else {
        SocketAddr::from_pathname(Path::new(path))?
    };
    socket.connect_addr(&address)?;
    socket.set_write_timeout(Some(Duration::from_secs(1)))?;
    socket.send(state.as_bytes())?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn notify(_state: &str) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
#[path = "service_spec3_tests.rs"]
mod go3_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn current_test_service_account() -> Option<ServiceAccount> {
        #[cfg(target_os = "linux")]
        {
            let uid = unsafe { geteuid() };
            Some(lookup_account(&uid.to_string()).unwrap())
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }

    fn fixture(dir: &Path) -> (Options, PathBuf) {
        fs::create_dir_all(dir).unwrap();
        let config = dir.join("node.yaml");
        fs::write(&config, "node:\n  id: test-node\n").unwrap();
        let executable = std::env::current_exe().unwrap();
        (
            Options {
                name: "dbbridge-test".into(),
                config,
                executable: Some(executable),
                account: Some("root".into()),
                log_level: "info".into(),
                log_format: "text".into(),
                start: false,
            },
            dir.to_path_buf(),
        )
    }

    #[test]
    fn service_names_and_accounts_are_restricted() {
        for name in ["", "../x", "x/y", "space name", "bad\nname", "x.service"] {
            assert!(!valid_name(name), "accepted {name:?}");
        }
        for name in ["dbbridge", "dbbridge-1", "A.b_c"] {
            assert!(valid_name(name), "rejected {name:?}");
        }
        assert!(!valid_account("--systemd"));
        assert!(valid_account("dbbridge_svc"));
    }

    #[test]
    fn service_management_is_linux_only() {
        assert!(ensure_platform_supported("linux").is_ok());
        let error = ensure_platform_supported("windows").unwrap_err();
        assert_eq!(error.code, config::CODE_SERVICE_INSTALL);
        assert!(error.message.contains("Linux systemd"));
    }

    #[test]
    fn environment_name_deny_list_matches_process_control_policy() {
        for name in [
            "PATH",
            "NOTIFY_SOCKET",
            "LISTEN_FDS",
            "HTTP_PROXY",
            "SSL_CERT_FILE",
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
        ] {
            assert!(!safe_env_name(name), "accepted unsafe {name}");
        }
        for name in ["CODEX_HOME", "DBBRIDGE_TOKEN", "_CREDENTIAL_3"] {
            assert!(safe_env_name(name), "rejected safe {name}");
        }
        for name in ["", "1TOKEN", "BAD-NAME", "TOKEN\n"] {
            assert!(!safe_env_name(name), "accepted malformed {name:?}");
        }
    }

    #[test]
    fn unit_escapes_arguments_and_rejects_newlines() {
        let quoted = unit_quote(r#"/opt/db "bridge"/$literal%/dbbridge"#, true).unwrap();
        assert!(quoted.contains(r#"\"bridge\""#));
        assert!(quoted.contains("$$literal%%"));
        assert!(unit_quote("bad\nvalue", true).is_err());
    }

    #[test]
    fn generated_unit_quotes_paths_and_sets_graceful_stop_budget() {
        let executable = Path::new(r#"/opt/db "bridge"/$literal%/dbbridge"#);
        let config = Path::new(r#"/etc/db "bridge"/$literal%/node.yaml"#);
        let expected_executable = unit_quote(&executable.to_string_lossy(), true).unwrap();
        let expected_config = unit_quote(&config.to_string_lossy(), true).unwrap();
        let unit = systemd_unit(
            "dbbridge-test",
            "root",
            executable,
            config,
            "info",
            "text",
            Path::new("/etc/dbbridge"),
            Duration::from_secs(65),
            200,
            false,
            None,
            &[],
        )
        .unwrap();
        assert!(unit.contains(&format!(
            "ExecStart={expected_executable} \"run\" \"--config\" {expected_config}"
        )));
        assert!(unit.contains("TimeoutStopSec=80s\n"));
        assert!(unit.contains("StartLimitIntervalSec=300\nStartLimitBurst=10\n"));
    }

    #[test]
    fn generated_unit_has_hardening_restart_policy_and_shutdown_budget() {
        let unit = systemd_unit(
            "dbbridge-test",
            "root",
            Path::new("/usr/bin/dbbridge"),
            Path::new("/etc/dbbridge/node.yaml"),
            "warn",
            "json",
            Path::new("/etc/dbbridge"),
            Duration::from_secs(45),
            5000,
            false,
            None,
            &[],
        )
        .unwrap();
        for directive in [
            "StartLimitIntervalSec=300\n",
            "StartLimitBurst=10\n",
            "Type=notify\n",
            "NotifyAccess=main\n",
            "\"--service-name\" \"dbbridge-test\" \"--log-level\" \"warn\" \"--log-format\" \"json\"\n",
            "RestartSec=5s\n",
            "ProtectHome=true\n",
            "PrivateTmp=true\n",
            "ProtectSystem=strict\n",
            "PrivateDevices=true\n",
            "ProtectKernelTunables=true\n",
            "ProtectKernelModules=true\n",
            "ProtectKernelLogs=true\n",
            "ProtectControlGroups=true\n",
            "ProtectClock=true\n",
            "ProtectHostname=true\n",
            "RestrictNamespaces=true\n",
            "RestrictRealtime=true\n",
            "RestrictSUIDSGID=true\n",
            "LockPersonality=true\n",
            "MemoryDenyWriteExecute=true\n",
            "SystemCallArchitectures=native\n",
            "SystemCallFilter=@system-service\n",
            "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n",
            "Restart=on-failure\n",
            "RestartPreventExitStatus=78\n",
            "TimeoutStopSec=60s\n",
            "LimitNOFILE=21024\n",
            "NoNewPrivileges=true\n",
            "CapabilityBoundingSet=\n",
        ] {
            assert!(unit.contains(directive), "missing {directive}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn generated_unit_tracks_symlinked_home_tmp_and_low_port_paths() {
        use std::os::unix::fs::symlink;

        let dir = std::env::temp_dir().join(format!(
            "dbb-unit-paths-{}",
            crate::util::random_hex(6).unwrap()
        ));
        let home_path = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/root"))
            .join(format!(
                "dbb-unit-home-{}",
                crate::util::random_hex(6).unwrap()
            ));
        fs::create_dir_all(&dir).unwrap();
        fs::write(&home_path, "test").unwrap();
        let config_link = dir.join("config-link.yaml");
        symlink(&home_path, &config_link).unwrap();
        let unit = systemd_unit(
            "dbbridge-test",
            "root",
            Path::new("/usr/bin/dbbridge"),
            &config_link,
            "info",
            "text",
            &dir,
            Duration::from_secs(30),
            200,
            true,
            None,
            std::slice::from_ref(&home_path),
        )
        .unwrap();
        assert!(unit.contains("ProtectHome=read-only\n"));
        assert!(unit.contains("PrivateTmp=false\n"));
        assert!(unit.contains("LimitNOFILE=8192\n"));
        assert!(unit.contains("CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n"));
        assert!(unit.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE\n"));
        fs::remove_file(config_link).unwrap();
        fs::remove_file(home_path).unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn prepare_validates_without_writing_system_files() {
        let dir = std::env::temp_dir().join(format!(
            "dbb-service-{}",
            crate::util::random_hex(6).unwrap()
        ));
        let (options, _) = fixture(&dir);
        let plan = prepare(&options).unwrap();
        assert_eq!(
            PathBuf::from(&plan.arguments[2]),
            fs::canonicalize(&options.config).unwrap()
        );
        assert!(plan.unit.starts_with("# Managed by DBBridge\n"));
        assert!(plan.unit.contains("TimeoutStopSec=60s\n"));
        assert!(!plan.unit_file.exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn prepare_warns_for_default_root_and_collects_read_paths() {
        let dir = std::env::temp_dir().join(format!(
            "dbb-root-warning-{}",
            crate::util::random_hex(6).unwrap()
        ));
        let (mut options, _) = fixture(&dir);
        options.account = None;
        let config_path = fs::canonicalize(&options.config).unwrap();
        let plan = prepare(&options).unwrap();
        assert_eq!(plan.account, "root");
        assert!(plan
            .warnings
            .iter()
            .any(|warning| warning.contains("runs as root without capabilities")));
        assert!(plan.read_paths.contains(&config_path));
        assert!(!plan.unit_file.exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn prepare_preserves_configuration_error_code() {
        let dir = std::env::temp_dir().join(format!(
            "dbb-preflight-error-{}",
            crate::util::random_hex(6).unwrap()
        ));
        let (options, _) = fixture(&dir);
        fs::write(
            &options.config,
            "node: {id: test-node}\nhttp: {enabled: true, unknown_option: true}\n",
        )
        .unwrap();
        let error = prepare(&options).unwrap_err();
        assert_eq!(error.code, config::CODE_CONFIG_READ);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn prepare_snapshots_referenced_and_optional_credentials_without_writing() {
        let dir = std::env::temp_dir().join(format!(
            "dbb-env-plan-{}",
            crate::util::random_hex(6).unwrap()
        ));
        fs::create_dir_all(&dir).unwrap();
        let suffix = crate::util::random_hex(6).unwrap().to_ascii_uppercase();
        let main_name = format!("DBB_SNAPSHOT_MAIN_{suffix}");
        let unreferenced_name = format!("DBB_SNAPSHOT_EXTRA_{suffix}");
        let optional_name = format!("DBB_SNAPSHOT_OPTIONAL_{suffix}");
        env::set_var(&main_name, "main-token-snapshot-value");
        env::set_var(&unreferenced_name, "unused-outbound-snapshot-value");
        env::set_var(&optional_name, "disabled-identity-token-value");
        let credentials = format!(
            "version: 1\noutbound_peers:\n  - id: upstream\n    token_env: {main_name}\
\n  - id: unused-outbound\n    token_env: {unreferenced_name}\
\ninbound_peers:\n  - id: dormant\n    enabled: false\n    token_envs: [{optional_name}]\n    allowed_targets: [db]\n"
        );
        fs::write(dir.join("credentials.yaml"), credentials).unwrap();
        let config_path = dir.join("node.yaml");
        fs::write(
            &config_path,
            "node: {id: node-b}\nhttp:\n  enabled: true\n  listen: \"127.0.0.1:18080\"\ntargets:\n  db: {network: tcp, address: \"127.0.0.1:3306\"}\nauth:\n  credentials_file: credentials.yaml\npeers:\n  - id: upstream\n    expected_node_id: node-a\n    credential_ref: upstream\n    endpoints: [{id: primary, url: \"http://127.0.0.1:19080\"}]\n",
        )
        .unwrap();
        let options = Options {
            name: "snapshot-test".into(),
            config: config_path.clone(),
            executable: Some(std::env::current_exe().unwrap()),
            account: Some("root".into()),
            log_level: "info".into(),
            log_format: "text".into(),
            start: false,
        };

        let plan = prepare(&options).unwrap();
        assert_eq!(
            plan.environment_names,
            vec![
                unreferenced_name.clone(),
                main_name.clone(),
                optional_name.clone()
            ]
        );
        let environment_file = dir.join("snapshot-test.service-env.json");
        assert_eq!(
            plan.environment_file.as_deref(),
            Some(environment_file.as_path())
        );
        assert_eq!(plan.arguments[plan.arguments.len() - 2], "--env-file");
        assert_eq!(
            plan.arguments.last().unwrap(),
            environment_file.to_string_lossy().as_ref()
        );
        assert!(plan.unit.contains("\"--env-file\""));
        assert!(plan.read_paths.contains(&dir.join("credentials.yaml")));
        assert!(
            !environment_file.exists(),
            "preflight must not write credentials"
        );
        let dry_run = install(&options, true).unwrap();
        assert_eq!(dry_run.environment_names, plan.environment_names);
        assert!(!environment_file.exists(), "install dry-run wrote snapshot");

        env::remove_var(main_name);
        env::remove_var(unreferenced_name);
        env::remove_var(optional_name);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn prepare_snapshots_reverse_only_credentials() {
        let dir = std::env::temp_dir().join(format!(
            "dbb-reverse-snapshot-{}",
            crate::util::random_hex(6).unwrap()
        ));
        fs::create_dir_all(&dir).unwrap();
        let suffix = crate::util::random_hex(6).unwrap().to_ascii_uppercase();
        let name = format!("DBB_REVERSE_SNAPSHOT_{suffix}");
        env::set_var(&name, "reverse-only-snapshot-value");
        let config_path = dir.join("node.yaml");
        fs::write(
            &config_path,
            format!(
                "node: {{id: node-b}}\nhttp:\n  enabled: true\n  listen: \"127.0.0.1:18080\"\nreverse:\n  enabled: true\n  peer_node_id: node-a\n  token_env: {name}\n  endpoints: [{{id: public, url: \"http://127.0.0.1:19080\"}}]\n"
            ),
        )
        .unwrap();
        let options = Options {
            name: "reverse-snapshot".into(),
            config: config_path.clone(),
            executable: Some(std::env::current_exe().unwrap()),
            account: Some("root".into()),
            log_level: "info".into(),
            log_format: "text".into(),
            start: false,
        };
        let plan = prepare(&options).unwrap();
        assert_eq!(plan.environment_names, vec![name.clone()]);
        assert_eq!(
            plan.environment_file.as_deref(),
            Some(dir.join("reverse-snapshot.service-env.json").as_path())
        );
        assert!(plan.read_paths.contains(&config_path));
        assert!(!dir.join("reverse-snapshot.service-env.json").exists());
        env::remove_var(name);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn service_file_collection_includes_reverse_tls_and_skips_disabled_tokens() {
        let dir = std::env::temp_dir().join(format!(
            "dbb-service-files-{}",
            crate::util::random_hex(6).unwrap()
        ));
        fs::create_dir_all(&dir).unwrap();
        let config_path = dir.join("node.yaml");
        fs::write(
            &config_path,
            "node: {id: node-b}\npeers:\n  - id: upstream\n    token_file: peer.token\n    tls: {ca_file: peer-ca.pem}\nreverse:\n  enabled: true\n  token_env: DBB_REVERSE_SERVICE_TOKEN\n  token_file: reverse.token\n  tls: {ca_file: reverse-ca.pem}\nhttp:\n  enabled: true\n  tls: {enabled: true, cert_file: server.pem, key_file: server.key}\nauth:\n  inbound_peers:\n    - id: dormant\n      enabled: false\n      token_envs: [DBB_DORMANT_TOKEN]\n      token_files: [missing-dormant.token]\n      allowed_targets: [db]\n    - id: active\n      enabled: true\n      token_envs: [DBB_ACTIVE_TOKEN]\n      token_files: [active.token]\n      allowed_targets: [db]\n",
        )
        .unwrap();

        let refs = credential_references(&config_path).unwrap();
        assert!(refs.required_env.contains("DBB_REVERSE_SERVICE_TOKEN"));
        assert!(refs.required_env.contains("DBB_ACTIVE_TOKEN"));
        assert!(refs.optional_env.contains("DBB_DORMANT_TOKEN"));
        for path in [
            "node.yaml",
            "peer.token",
            "peer-ca.pem",
            "reverse.token",
            "reverse-ca.pem",
            "server.pem",
            "server.key",
            "active.token",
        ] {
            assert!(refs.read_paths.contains(&dir.join(path)), "missing {path}");
        }
        assert!(!refs.read_paths.contains(&dir.join("missing-dormant.token")));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn environment_loader_requires_private_json_and_preserves_process_values() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "dbb-env-load-{}",
            crate::util::random_hex(6).unwrap()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("environment.json");
        let name = format!(
            "DBB_ENV_LOAD_{}",
            crate::util::random_hex(6).unwrap().to_ascii_uppercase()
        );
        let values = BTreeMap::from([(name.clone(), "captured-secret-value".to_string())]);
        fs::write(&path, environment_bytes(&values)).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        env::remove_var(&name);
        load_environment(&path).unwrap();
        assert_eq!(env::var(&name).unwrap(), "captured-secret-value");

        env::set_var(&name, "process-value-wins");
        load_environment(&path).unwrap();
        assert_eq!(env::var(&name).unwrap(), "process-value-wins");

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_environment(&path)
            .unwrap_err()
            .message
            .contains("mode"));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        for body in [
            r#"{"PATH":"unsafe"}"#,
            r#"{"NOTIFY_SOCKET":"unsafe"}"#,
            r#"{"1INVALID":"unsafe"}"#,
            r#"{"TOKEN":null}"#,
            r#"{"TOKEN":42}"#,
            r#"{"TOKEN":"one","TOKEN":"two"}"#,
            "not-json",
        ] {
            fs::write(&path, body).unwrap();
            assert!(load_environment(&path).is_err(), "accepted {body}");
        }
        fs::write(&path, vec![b' '; MAX_ENVIRONMENT_BYTES + 1]).unwrap();
        assert!(load_environment(&path)
            .unwrap_err()
            .message
            .contains("JSON limit or UTF-8 violation"));

        env::remove_var(name);
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn account_access_uses_mode_bits_and_does_not_give_root_a_bypass() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "dbb-account-access-{}",
            crate::util::random_hex(6).unwrap()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("private.conf");
        fs::write(&path, "private").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let current_uid = unsafe { geteuid() };
        let current = lookup_account(&current_uid.to_string()).unwrap();
        assert!(check_account_access(&path, &current, 0o4).is_ok());
        let public_path = dir.join("public.conf");
        fs::write(&public_path, "public").unwrap();
        fs::set_permissions(&public_path, fs::Permissions::from_mode(0o644)).unwrap();

        let other = ServiceAccount {
            uid: current_uid.wrapping_add(1),
            gid: current.gid.wrapping_add(1),
            groups: BTreeSet::new(),
        };
        assert!(check_account_access(&path, &other, 0o4).is_err());
        assert!(check_account_access(&public_path, &other, 0o4).is_ok());
        let group_path = dir.join("group-readable.conf");
        fs::write(&group_path, "group-readable").unwrap();
        fs::set_permissions(&group_path, fs::Permissions::from_mode(0o640)).unwrap();
        let group_member = ServiceAccount {
            uid: other.uid,
            gid: current.gid,
            groups: BTreeSet::from([current.gid]),
        };
        assert!(check_account_access(&group_path, &group_member, 0o4).is_ok());

        let guarded_dir = dir.join("no-traverse");
        fs::create_dir(&guarded_dir).unwrap();
        let guarded_path = guarded_dir.join("world-readable.conf");
        fs::write(&guarded_path, "world-readable").unwrap();
        fs::set_permissions(&guarded_path, fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(&guarded_dir, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(check_account_access(&guarded_path, &other, 0o4).is_err());
        let root = ServiceAccount {
            uid: 0,
            gid: 0,
            groups: BTreeSet::new(),
        };
        assert!(check_account_access(&public_path, &root, 0o4).is_ok());
        if current_uid != 0 {
            assert!(check_account_access(&path, &root, 0o4).is_err());
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn install_rolls_back_registration_but_keeps_successful_start_failure() {
        let dir =
            std::env::temp_dir().join(format!("dbb-unit-{}", crate::util::random_hex(6).unwrap()));
        fs::create_dir_all(&dir).unwrap();
        let snapshot = dir.join("dbbridge-test.service-env.json");
        let account = current_test_service_account();
        let plan = Plan {
            platform: "linux".into(),
            name: "dbbridge-test".into(),
            executable: PathBuf::from("/usr/bin/dbbridge"),
            arguments: Vec::new(),
            working_directory: dir.clone(),
            account: account
                .as_ref()
                .map(|account| account.uid.to_string())
                .unwrap_or_else(|| "root".into()),
            automatic: true,
            start: false,
            unit_file: dir.join("dbbridge-test.service"),
            unit: format!("# {MARKER}\n[Service]\nType=notify\n"),
            warnings: Vec::new(),
            environment_file: Some(snapshot.clone()),
            environment_names: vec!["DBB_TEST_CREDENTIAL".into()],
            environment: BTreeMap::from([(
                "DBB_TEST_CREDENTIAL".into(),
                "private-test-value".into(),
            )]),
            read_paths: Vec::new(),
        };
        for failing in ["daemon-reload", "enable"] {
            let calls = RefCell::new(Vec::<String>::new());
            let result = install_at(&dir, &plan, account.as_ref(), |args| {
                calls.borrow_mut().push(args.join(" "));
                if args.first().is_some_and(|a| a == failing) {
                    Err(service_error("injected command failure"))
                } else {
                    Ok(())
                }
            });
            assert!(result.is_err());
            assert!(!plan.unit_file.exists());
            assert!(
                !snapshot.exists(),
                "failed registration left snapshot behind"
            );
        }
        let mut started = plan.clone();
        started.start = true;
        let result = install_at(&dir, &started, account.as_ref(), |args| {
            if args.first().is_some_and(|a| a == "start") {
                Err(service_error("injected start failure"))
            } else {
                Ok(())
            }
        });
        assert!(result
            .unwrap_err()
            .message
            .contains("installed and enabled"));
        assert!(started.unit_file.exists());
        assert!(
            snapshot.exists(),
            "start failure must preserve installed credentials"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn duplicate_install_has_no_systemctl_side_effects() {
        let dir =
            std::env::temp_dir().join(format!("dbb-dupe-{}", crate::util::random_hex(6).unwrap()));
        fs::create_dir_all(&dir).unwrap();
        let plan = Plan {
            platform: "linux".into(),
            name: "dbbridge-test".into(),
            executable: PathBuf::from("/usr/bin/dbbridge"),
            arguments: Vec::new(),
            working_directory: dir.clone(),
            account: "root".into(),
            automatic: true,
            start: false,
            unit_file: dir.join("dbbridge-test.service"),
            unit: format!("# {MARKER}\n"),
            warnings: Vec::new(),
            environment_file: None,
            environment_names: Vec::new(),
            environment: BTreeMap::new(),
            read_paths: Vec::new(),
        };
        fs::write(&plan.unit_file, &plan.unit).unwrap();
        let calls = RefCell::new(0usize);
        assert!(install_at(&dir, &plan, None, |_| {
            *calls.borrow_mut() += 1;
            Ok(())
        })
        .is_err());
        assert_eq!(*calls.borrow(), 0);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn uninstall_refuses_unowned_and_non_regular_units() {
        let dir =
            std::env::temp_dir().join(format!("dbb-owned-{}", crate::util::random_hex(6).unwrap()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            unit_path(&dir, "foreign"),
            "[Service]\nExecStart=/bin/true\n",
        )
        .unwrap();
        assert!(owned_unit(&dir, "foreign")
            .unwrap_err()
            .message
            .contains("not installed by DBBridge"));
        let foreign_calls = RefCell::new(0usize);
        assert!(uninstall_at(&dir, "foreign", |_| {
            *foreign_calls.borrow_mut() += 1;
            Ok(())
        })
        .is_err());
        assert_eq!(*foreign_calls.borrow(), 0);
        fs::create_dir(unit_path(&dir, "directory")).unwrap();
        assert!(owned_unit(&dir, "directory")
            .unwrap_err()
            .message
            .contains("non-regular"));
        let non_regular_calls = RefCell::new(0usize);
        assert!(uninstall_at(&dir, "directory", |_| {
            *non_regular_calls.borrow_mut() += 1;
            Ok(())
        })
        .is_err());
        assert_eq!(*non_regular_calls.borrow(), 0);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn uninstall_stops_owned_unit_and_preserves_config() {
        let dir = std::env::temp_dir().join(format!(
            "dbb-uninstall-{}",
            crate::util::random_hex(6).unwrap()
        ));
        fs::create_dir_all(&dir).unwrap();
        let config = dir.join("node.yaml");
        fs::write(&config, "node:\n  id: test-node\n").unwrap();
        fs::write(
            unit_path(&dir, "dbbridge-test"),
            format!("# {MARKER}\nTimeoutStopSec=180s\n[Service]\n"),
        )
        .unwrap();
        let calls = RefCell::new(Vec::<String>::new());
        uninstall_at(&dir, "dbbridge-test", |args| {
            calls.borrow_mut().push(args.join(" "));
            Ok(())
        })
        .unwrap();
        assert!(calls.borrow()[0].contains("disable --now dbbridge-test.service"));
        assert_eq!(
            unit_stop_wait("TimeoutStopSec=180s\n"),
            Duration::from_secs(210)
        );
        assert_eq!(
            unit_stop_wait("TimeoutStopSec=60s\n"),
            Duration::from_secs(120)
        );
        assert_eq!(
            unit_stop_wait("TimeoutStopSec=330s\n"),
            Duration::from_secs(360)
        );
        assert!(config.exists());
        assert!(!unit_path(&dir, "dbbridge-test").exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn executable_symlink_path_is_kept_in_the_plan() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let dir = std::env::temp_dir()
                .join(format!("dbb-link-{}", crate::util::random_hex(6).unwrap()));
            let (mut options, _) = fixture(&dir);
            let actual = dir.join("real-dbbridge");
            fs::write(&actual, "not executed").unwrap();
            let link = dir.join("dbbridge-link");
            symlink(&actual, &link).unwrap();
            options.executable = Some(link.clone());
            let plan = prepare(&options).unwrap();
            assert_eq!(plan.executable, link);
            assert!(plan.warnings.iter().any(|warning| {
                warning.contains("symbolic link")
                    && warning.contains(actual.to_string_lossy().as_ref())
            }));
            fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn notify_is_a_noop_without_systemd_environment() {
        let previous = std::env::var_os("NOTIFY_SOCKET");
        std::env::remove_var("NOTIFY_SOCKET");
        assert!(notify("READY=1").is_ok());
        if let Some(value) = previous {
            std::env::set_var("NOTIFY_SOCKET", value);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn notify_sends_ready_and_stopping_to_unix_datagram_socket() {
        use std::os::unix::net::UnixDatagram;
        let dir = std::env::temp_dir().join(format!(
            "dbb-notify-{}",
            crate::util::random_hex(6).unwrap()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("notify.sock");
        let listener = UnixDatagram::bind(&path).unwrap();
        listener
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let previous = std::env::var_os("NOTIFY_SOCKET");
        std::env::set_var("NOTIFY_SOCKET", &path);
        notify("READY=1").unwrap();
        let mut buffer = [0u8; 32];
        let (len, _) = listener.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..len], b"READY=1");
        notify("STOPPING=1").unwrap();
        let (len, _) = listener.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..len], b"STOPPING=1");
        if let Some(value) = previous {
            std::env::set_var("NOTIFY_SOCKET", value);
        } else {
            std::env::remove_var("NOTIFY_SOCKET");
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
