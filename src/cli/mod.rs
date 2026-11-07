pub mod flags;
pub mod genconfig;
pub mod yamlout;

use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use self::flags::{FlagSet, ParseError, Usage};
use crate::admin::Admin;
use crate::config;
use crate::egress;
use crate::error::{Error, Result};
use crate::ingress::Ingress;
use crate::metrics::Metrics;
use crate::util::json::{self, Json};

const EXIT_OK: i32 = 0;
const EXIT_FAILURE: i32 = 1;
const EXIT_CONFIG: i32 = 78;
const EXIT_INTERRUPTED: i32 = 130;

#[derive(Debug)]
pub struct Failure {
    pub error: Error,
    pub exit: i32,
}

impl Failure {
    fn plain(error: Error) -> Self {
        Failure {
            error,
            exit: EXIT_FAILURE,
        }
    }
    fn config(error: Error) -> Self {
        Failure {
            error,
            exit: EXIT_CONFIG,
        }
    }
}

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Failure::plain(error)
    }
}

type CmdResult = std::result::Result<(), Failure>;

pub fn run(args: &[String]) -> i32 {
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let mut out = stdout.lock();
    let mut err = stderr.lock();
    if args.first().map(String::as_str) == Some("run") {
        // `run` streams logs while it serves; it never buffers its output.
        drop(out);
        drop(err);
        return match cmd_run(&args[1..]) {
            Ok(code) => code,
            Err(failure) => {
                let mut e = std::io::stderr();
                print_error(&mut e, &failure.error);
                failure.exit
            }
        };
    }
    let result = execute(args, &mut out, &mut err);
    if let Err(failure) = &result {
        let _ = out.flush();
        print_error(&mut err, &failure.error);
    }
    exit_status(&result)
}

fn exit_status(result: &CmdResult) -> i32 {
    match result {
        Ok(()) => EXIT_OK,
        Err(failure) => failure.exit,
    }
}

#[cfg(test)]
mod spec_service3_tests;

#[cfg(test)]
mod spec_exit_status_tests {
    use super::{exit_status, Failure};
    use crate::error::Error;

    #[test]
    fn spec_exit_status() {
        assert_eq!(exit_status(&Ok(())), 0);
        assert_eq!(exit_status(&Err(Failure::plain(Error::local("x")))), 1);
        assert_eq!(
            exit_status(&Err(Failure {
                error: Error::local("x"),
                exit: 78,
            })),
            78
        );
        assert_eq!(exit_status(&Err(Failure::config(Error::local("x")))), 78);
    }
}

fn print_error(w: &mut dyn Write, e: &Error) {
    if e.code.is_empty() {
        let _ = writeln!(w, "Error: {}", e.message);
    } else {
        let _ = writeln!(w, "Error [{}]: {}", e.code, e.message);
    }
}

pub fn execute(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> CmdResult {
    let Some(command) = args.first().map(String::as_str) else {
        print_help(out);
        return Err(Failure::plain(Error::local("a command is required")));
    };
    let rest = &args[1..];
    match command {
        "version" | "-v" | "--version" => {
            if !rest.is_empty() {
                return Err(Failure::plain(Error::local("version accepts no arguments")));
            }
            let _ = writeln!(out, "{}", version_line());
            Ok(())
        }
        "help" | "-h" | "--help" => {
            print_help(out);
            Ok(())
        }
        "gen-config" => cmd_gen_config(rest, out, err),
        "uninstall" => cmd_uninstall(rest, out, err),
        "run" => match run_preflight(rest, err)? {
            Some(_) => Err(Failure::plain(Error::local(
                "run is only available from the process entry point",
            ))),
            None => Ok(()),
        },
        "check-config" => cmd_check_config(rest, out, err),
        "install" => cmd_install(rest, out, err),
        other => Err(Failure::plain(Error::local(format!(
            "unknown command: {other}"
        )))),
    }
}

fn version_line() -> String {
    format!(
        "dbbridge version {} (commit: {}, built: {}, runtime: {}, protocol: {})",
        crate::VERSION,
        crate::COMMIT,
        crate::BUILD_DATE,
        crate::RUSTC_VERSION,
        crate::wire::PROTOCOL_VERSION
    )
}

fn is_config_code(code: &str) -> bool {
    matches!(
        code,
        config::CODE_CONFIG_READ
            | config::CODE_CONFIG_INVALID
            | config::CODE_CREDENTIAL
            | config::CODE_ENVIRONMENT
            | config::CODE_LISTEN
            | config::CODE_TLS
            | config::CODE_PEER_MODE
            | config::CODE_REVERSE
    )
}

fn print_help(out: &mut dyn Write) {
    let _ = out.write_all(HELP.as_bytes());
}

const HELP: &str = "dbbridge - Peer-to-peer Database WS / HTTP-SSE Proxy

Usage:
  dbbridge <command> [options]

Commands:
  run             Run the peer node in the foreground or under a service manager
  gen-config      Generate a matched configuration pair (bidirectional by default)
  check-config    Validate a YAML configuration file and exit
  install         Install as Windows service or Linux systemd service
  uninstall       Stop and remove a service installed by DBBridge
  version         Print version information
  help            Print this help message

Common options (run, check-config, install):
  --config, -c        YAML configuration path (required)
  --log-level         debug, info, warn, error (default: info)
  --log-format        text, json (default: text)
  --env-file          Private service credential snapshot (normally automatic)

run options:
  --service-name      Service identity used for the Windows event log (default: dbbridge)

check-config options:
  --offline           Validate schema, defaults, references and listen addresses
                      without reading tokens, environment variables or TLS files

install options:
  --service-name      Service identity (default: dbbridge)
  --service-user      Linux account, or Windows LocalSystem/LocalService/NetworkService
  --exec-path         Executable written to the service definition (default: the
                      path dbbridge was invoked with; symbolic links are kept)
  --start             Also start after installation (default: false)
  --dry-run           Print the installation plan without changing the system

uninstall options:
  --service-name      Service identity (default: dbbridge)
  --dry-run           Check that the service exists and is managed by DBBridge

Credentials (token files, and the auth and token settings of the configuration
or credentials file) are re-read every auth.reload_interval and on SIGHUP
(Linux) or 'sc.exe control <name> paramchange' (Windows). Tokens taken from
environment variables only change with a restart.

Errors print a stable code, for example \"Error [DBB-CFG-002]: ...\".
Exit status: 0 success; 78 configuration or credential error (check-config,
run, install); 130 forced exit by a second interrupt during shutdown; 1 other
errors.

Examples:
  dbbridge gen-config
  dbbridge gen-config -o ./pair --a-peer-url https://b.example.com --b-peer-url https://a.example.com
  dbbridge gen-config -o ./reverse --mode a-to-b --reverse --b-peer-url https://a.example.com
  dbbridge check-config --config peer-b.yaml --offline
  dbbridge install --config peer-b.yaml --dry-run
  dbbridge install --config peer-b.yaml --service-user dbbridge --start
  dbbridge run --config peer-a.yaml
  dbbridge uninstall --service-name dbbridge

Use 'dbbridge gen-config --help' for generator options.
";

fn parse_flags(
    fs: &mut FlagSet,
    args: &[String],
    err: &mut dyn Write,
) -> std::result::Result<bool, Failure> {
    let mut diag = String::new();
    let parsed = fs.parse(args, &mut diag);
    let _ = err.write_all(diag.as_bytes());
    match parsed {
        Ok(rest) => match rest.first() {
            Some(arg) => Err(Failure::plain(Error::local(format!(
                "unexpected positional argument: {arg}"
            )))),
            None => Ok(true),
        },
        Err(ParseError::Help) => Ok(false),
        Err(ParseError::Message(message)) => Err(Failure::plain(Error::local(message))),
    }
}

/// The flag set of `run`, `check-config` and `install`.
fn command_flags(command: &str) -> FlagSet {
    let mut fs = FlagSet::new(command, Usage::Command);
    fs.string("config", "", "Path to YAML configuration");
    fs.string_alias("c", "config", "", "Configuration path (shorthand)");
    fs.string("log-level", "info", "debug, info, warn, error");
    fs.string("log-format", "text", "text or json");
    fs.string("env-file", "", "Private credential snapshot");
    match command {
        "run" => fs.string("service-name", "dbbridge", "Service identity"),
        "check-config" => fs.bool(
            "offline",
            false,
            "Do not read tokens, environment variables or TLS files",
        ),
        "install" => {
            fs.string("service-name", "dbbridge", "Service identity");
            fs.string(
                "service-user",
                "",
                "Linux account; Windows built-in service account",
            );
            fs.string("exec-path", "", "Executable path written to the service definition (default: the path dbbridge was invoked with; symlinks are kept)");
            fs.bool("start", false, "Start after installation");
            fs.bool("dry-run", false, "Print service installation plan only");
        }
        _ => {}
    }
    fs
}

/// Parses and checks the common options. `Ok(None)` means `--help` was shown.
fn common_options(
    command: &str,
    args: &[String],
    err: &mut dyn Write,
) -> std::result::Result<Option<FlagSet>, Failure> {
    let mut fs = command_flags(command);
    if !parse_flags(&mut fs, args, err)? {
        return Ok(None);
    }
    if fs.get_str("config").is_empty() {
        return Err(Failure::plain(Error::local("--config is required")));
    }
    if !matches!(
        fs.get_str("log-level").as_str(),
        "debug" | "info" | "warn" | "error"
    ) {
        return Err(Failure::plain(Error::local("invalid --log-level")));
    }
    if !matches!(fs.get_str("log-format").as_str(), "text" | "json") {
        return Err(Failure::plain(Error::local("invalid --log-format")));
    }
    Ok(Some(fs))
}

fn load_environment(path: &str) -> std::result::Result<(), Failure> {
    if path.is_empty() {
        return Ok(());
    }
    crate::service::load_environment(Path::new(path)).map_err(|e| {
        let code = if e.code.is_empty() {
            config::CODE_ENVIRONMENT
        } else {
            e.code.as_str()
        };
        Failure::config(Error::new(code, e.message))
    })
}

fn cmd_check_config(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> CmdResult {
    let Some(fs) = common_options("check-config", args, err)? else {
        return Ok(());
    };
    load_environment(&fs.get_str("env-file"))?;
    let path = fs.get_str("config");
    let offline = fs.get_bool("offline");
    let cfg = config::load_with_options(Path::new(&path), offline).map_err(|e| {
        Failure::config(Error::new(&e.code, format!("config check: {}", e.message)))
    })?;
    for warning in &cfg.warnings {
        let _ = writeln!(err, "Warning: {warning}");
    }
    if offline {
        let _ = writeln!(
            out,
            "Config {path} is structurally valid (offline: tokens, environment variables and TLS files were not checked). Node ID: {}",
            cfg.node.id
        );
    } else {
        let _ = writeln!(out, "Config {path} is valid. Node ID: {}", cfg.node.id);
    }
    Ok(())
}

fn cmd_install(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> CmdResult {
    let Some(fs) = common_options("install", args, err)? else {
        return Ok(());
    };
    load_environment(&fs.get_str("env-file"))?;
    let exec_path = fs.get_str("exec-path");
    let account = fs.get_str("service-user");
    let options = crate::service::Options {
        name: fs.get_str("service-name"),
        config: fs.get_str("config").into(),
        executable: (!exec_path.is_empty()).then(|| exec_path.into()),
        account: (!account.is_empty()).then_some(account),
        log_level: fs.get_str("log-level"),
        log_format: fs.get_str("log-format"),
        start: fs.get_bool("start"),
    };
    let dry_run = fs.get_bool("dry-run");
    let plan = crate::service::install(&options, dry_run).map_err(|e| {
        if is_config_code(&e.code) {
            Failure::config(e)
        } else {
            let code = if e.code.is_empty() {
                config::CODE_SERVICE_INSTALL
            } else {
                e.code.as_str()
            };
            Failure::plain(Error::new(code, e.message))
        }
    })?;
    for warning in &plan.warnings {
        let _ = writeln!(err, "Warning: {warning}");
    }
    if dry_run {
        let _ = writeln!(out, "{}", service_plan_json(&plan));
        return Ok(());
    }
    let _ = writeln!(
        out,
        "Service {} installed for {} with automatic startup.",
        plan.name, plan.platform
    );
    if let Some(file) = &plan.environment_file {
        let _ = writeln!(out, "Credential environment snapshot: {}", file.display());
    }
    if plan.start {
        let _ = writeln!(out, "Service started.");
    } else {
        let _ = writeln!(
            out,
            "Start with systemctl start <name>.service (Linux) or sc.exe start <name> (Windows)."
        );
    }
    Ok(())
}

fn cmd_uninstall(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> CmdResult {
    let mut fs = FlagSet::new("uninstall", Usage::Default);
    fs.string("service-name", "dbbridge", "Service identity");
    fs.bool(
        "dry-run",
        false,
        "Preview removal without changing the system",
    );
    if !parse_flags(&mut fs, args, err)? {
        return Ok(());
    }
    let name = fs.get_str("service-name");
    let dry = fs.get_bool("dry-run");
    crate::service::uninstall(&name, dry).map_err(|e| {
        let code = if e.code.is_empty() {
            config::CODE_SERVICE_INSTALL
        } else {
            e.code.as_str()
        };
        Failure::plain(Error::new(code, e.message))
    })?;
    if dry {
        let _ = writeln!(out, "Would stop and remove service {name}; configuration, credentials and the service credential snapshot are retained.");
    } else {
        let _ = writeln!(
            out,
            "Service {name} removed; configuration and credentials retained."
        );
    }
    Ok(())
}

fn cmd_gen_config(args: &[String], out: &mut dyn Write, err: &mut dyn Write) -> CmdResult {
    let d = genconfig::PairOptions::default();
    let mut fs = FlagSet::new("gen-config", Usage::Default);
    fs.string(
        "output",
        &d.output_dir,
        "Directory for peer-a.yaml, peer-b.yaml, and shared.token",
    );
    fs.string_alias("o", "output", &d.output_dir, "Output directory (shorthand)");
    fs.string(
        "mode",
        &d.mode,
        "bidirectional, a-to-b, or b-to-a; always generates both nodes",
    );
    fs.string(
        "token-file",
        "",
        "Shared token path relative to current directory; default: <output>/shared.token",
    );
    fs.string("protocol", &d.protocol, "auto, ws, or http-sse");
    fs.bool(
        "recovery",
        d.recovery,
        "Enable session recovery on both nodes",
    );
    fs.bool(
        "allow-insecure-http",
        false,
        "Allow non-loopback plaintext HTTP to the peer (writes peers[].allow_insecure_http)",
    );
    fs.bool(
        "force",
        false,
        "Replace both configs after validation; never replace the token",
    );
    fs.bool("reverse", false, "Reverse mode (needs --mode a-to-b or b-to-a): the egress node, behind NAT, dials a tunnel to the ingress node's HTTP listener");
    fs.int(
        "max-sessions",
        d.max_sessions,
        "Global and inbound peer session quota per node",
    );
    for (p, node) in [("a", &d.a), ("b", &d.b)] {
        fs.string(
            &format!("{p}-node-id"),
            &node.node_id,
            &format!("Node {p} identity"),
        );
        fs.string(
            &format!("{p}-listen"),
            &node.listen,
            &format!("Node {p} local TCP proxy listen address"),
        );
        fs.string(
            &format!("{p}-http-listen"),
            &node.http_listen,
            &format!("Node {p} inbound HTTP listen address"),
        );
        fs.string(
            &format!("{p}-admin-listen"),
            &node.admin_listen,
            &format!("Node {p} loopback admin address for /healthz, /readyz and /metrics"),
        );
        fs.string(
            &format!("{p}-target-id"),
            &node.target_id,
            &format!("Node {p} local backend target ID (referenced by the other node)"),
        );
        fs.string(
            &format!("{p}-target-address"),
            &node.target_address,
            &format!("Node {p} local backend DB address"),
        );
        fs.string(
            &format!("{p}-tls-cert"),
            "",
            &format!("Node {p} existing inbound TLS certificate"),
        );
        fs.string(
            &format!("{p}-tls-key"),
            "",
            &format!("Node {p} existing inbound TLS private key"),
        );
        fs.list(&format!("{p}-peer-url"), &format!("Remote origin dialed by node {p}; repeat for failover (default: other node's HTTP listener)"));
        fs.list(
            &format!("{p}-allow-cidr"),
            &format!(
                "Node {p} allowed backend network; repeat as needed (default: exact target IP)"
            ),
        );
    }
    if !parse_flags(&mut fs, args, err)? {
        return Ok(());
    }
    let node = |p: &str| genconfig::NodeOptions {
        node_id: fs.get_str(&format!("{p}-node-id")),
        listen: fs.get_str(&format!("{p}-listen")),
        http_listen: fs.get_str(&format!("{p}-http-listen")),
        admin_listen: fs.get_str(&format!("{p}-admin-listen")),
        target_id: fs.get_str(&format!("{p}-target-id")),
        target_address: fs.get_str(&format!("{p}-target-address")),
        tls_cert: fs.get_str(&format!("{p}-tls-cert")),
        tls_key: fs.get_str(&format!("{p}-tls-key")),
        peer_urls: fs.get_list(&format!("{p}-peer-url")),
        allowed_cidrs: fs.get_list(&format!("{p}-allow-cidr")),
    };
    let o = genconfig::PairOptions {
        output_dir: fs.get_str("output"),
        mode: fs.get_str("mode"),
        token_file: fs.get_str("token-file"),
        protocol: fs.get_str("protocol"),
        a: node("a"),
        b: node("b"),
        recovery: fs.get_bool("recovery"),
        allow_insecure_http: fs.get_bool("allow-insecure-http"),
        force: fs.get_bool("force"),
        max_sessions: fs.get_int("max-sessions"),
        reverse: fs.get_bool("reverse"),
    };
    let files = genconfig::generate_pair(&o)?;
    let mut mode = o.mode.clone();
    if o.reverse {
        mode.push_str(", reverse");
    }
    let _ = write!(
        out,
        "Configuration pair generated and validated (mode: {mode}):\n  A: {}\n  B: {}\nShared token file: {} (deploy a copy with each node; its value is not printed)\n",
        files.config_a.display(),
        files.config_b.display(),
        files.token_file.display()
    );
    Ok(())
}

fn run_preflight(
    args: &[String],
    err: &mut dyn Write,
) -> std::result::Result<Option<FlagSet>, Failure> {
    let Some(fs) = common_options("run", args, err)? else {
        return Ok(None);
    };
    if !crate::service::valid_name(&fs.get_str("service-name")) {
        return Err(Failure::plain(Error::local("invalid --service-name")));
    }
    Ok(Some(fs))
}

pub(crate) fn service_plan_json(plan: &crate::service::Plan) -> String {
    let mut fields = vec![
        ("platform".into(), Json::Str(plan.platform.clone())),
        ("name".into(), Json::Str(plan.name.clone())),
        (
            "executable".into(),
            Json::Str(plan.executable.to_string_lossy().into_owned()),
        ),
        (
            "arguments".into(),
            Json::Arr(plan.arguments.iter().cloned().map(Json::Str).collect()),
        ),
        (
            "working_directory".into(),
            Json::Str(plan.working_directory.to_string_lossy().into_owned()),
        ),
        ("account".into(), Json::Str(plan.account.clone())),
        ("automatic".into(), Json::Bool(plan.automatic)),
        ("start".into(), Json::Bool(plan.start)),
        (
            "unit_file".into(),
            Json::Str(plan.unit_file.to_string_lossy().into_owned()),
        ),
        ("unit".into(), Json::Str(plan.unit.clone())),
    ];
    if let Some(environment_file) = &plan.environment_file {
        fields.push((
            "environment_file".into(),
            Json::Str(environment_file.to_string_lossy().into_owned()),
        ));
        fields.push((
            "environment_names".into(),
            Json::Arr(
                plan.environment_names
                    .iter()
                    .cloned()
                    .map(Json::Str)
                    .collect(),
            ),
        ));
    }
    if !plan.warnings.is_empty() {
        fields.push((
            "warnings".into(),
            Json::Arr(plan.warnings.iter().cloned().map(Json::Str).collect()),
        ));
    }
    let mut output = String::new();
    write_pretty_json(&Json::Obj(fields), 0, &mut output);
    output
}

fn write_pretty_json(value: &Json, depth: usize, output: &mut String) {
    match value {
        Json::Obj(fields) if fields.is_empty() => output.push_str("{}"),
        Json::Obj(fields) => {
            output.push('{');
            for (index, (key, item)) in fields.iter().enumerate() {
                output.push('\n');
                output.push_str(&"  ".repeat(depth + 1));
                json::write_json(&Json::Str(key.clone()), output);
                output.push_str(": ");
                write_pretty_json(item, depth + 1, output);
                if index + 1 != fields.len() {
                    output.push(',');
                }
            }
            output.push('\n');
            output.push_str(&"  ".repeat(depth));
            output.push('}');
        }
        Json::Arr(items) if items.is_empty() => output.push_str("[]"),
        Json::Arr(items) => {
            output.push('[');
            for (index, item) in items.iter().enumerate() {
                output.push('\n');
                output.push_str(&"  ".repeat(depth + 1));
                write_pretty_json(item, depth + 1, output);
                if index + 1 != items.len() {
                    output.push(',');
                }
            }
            output.push('\n');
            output.push_str(&"  ".repeat(depth));
            output.push(']');
        }
        scalar => json::write_json(scalar, output),
    }
}

/// Binding is the only reliable way to prove a listen address is usable
/// before `run` starts serving; a busy port fails `run` with
/// `DBB-CFG-010 failed to start node`, never `check-config`.
fn check_listen_addresses(cfg: &config::Config) -> Result<()> {
    let mut addrs: Vec<(&str, &str)> = Vec::new();
    if cfg.http.enabled {
        addrs.push(("http.listen", cfg.http.listen.as_str()));
    }
    if cfg.admin.enabled {
        addrs.push(("admin.listen", cfg.admin.listen.as_str()));
    }
    for l in &cfg.listeners {
        addrs.push(("listeners[].listen", l.listen.as_str()));
    }
    for (field, addr) in addrs {
        if !crate::admin::can_bind(addr) {
            return Err(Error::new(
                config::CODE_LISTEN,
                format!("{field} {addr}: cannot bind (in use or not permitted)"),
            ));
        }
    }
    Ok(())
}

fn cmd_run(args: &[String]) -> std::result::Result<i32, Failure> {
    let mut stderr = std::io::stderr();
    let Some(fs) = run_preflight(args, &mut stderr)? else {
        return Ok(EXIT_OK);
    };
    crate::slog::init(&fs.get_str("log-level"), &fs.get_str("log-format"));
    if let Err(failure) = load_environment(&fs.get_str("env-file")) {
        crate::node_log::environment_failed(&failure.error);
        return Err(failure);
    }
    let path = std::path::PathBuf::from(fs.get_str("config"));
    let cfg = match config::load(&path) {
        Ok(cfg) => Arc::new(cfg),
        Err(e) => {
            crate::node_log::config_failed(&e);
            return Err(Failure::config(e));
        }
    };
    for warning in &cfg.warnings {
        crate::node_log::config_warning(warning);
    }
    serve(cfg).map_err(Failure::plain)
}

fn serve(cfg: Arc<config::Config>) -> Result<i32> {
    if let Err(error) = check_listen_addresses(&cfg) {
        crate::node_log::start_failed(&error.message);
        return Err(Error::new(
            config::CODE_START_FAILED,
            format!("failed to start node: {}", error.message),
        ));
    }
    for line in config::describe(&cfg) {
        crate::slog::debug(&line, &[]);
    }
    crate::node_log::starting(&cfg.node.id);

    let started = Instant::now();
    let metrics = Arc::new(Metrics::new());
    metrics.configure_resources(&cfg);
    let shutdown = Arc::new(AtomicBool::new(false));
    let ready = Arc::new(AtomicBool::new(false));
    signals::reset();
    signals::install();
    let auth = Arc::new(crate::auth::Authenticator::with_metrics(
        cfg.clone(),
        metrics.clone(),
    ));

    let mut handles: Vec<std::thread::JoinHandle<()>> = Vec::new();
    let auth_thread;
    let mut admin_addr = None;
    let mut egress_control: Option<Arc<egress::Server>> = None;
    let fatal: Arc<std::sync::Mutex<Option<Error>>> = Arc::new(std::sync::Mutex::new(None));
    let has_fatal = |fatal: &std::sync::Mutex<Option<Error>>| {
        fatal.lock().map(|slot| slot.is_some()).unwrap_or(true)
    };

    let ready_check = crate::admin::ReadyCheckSlot::default();
    if cfg.admin.enabled {
        let (handle, addr) = Admin::start_with_check(
            cfg.clone(),
            metrics.clone(),
            started,
            shutdown.clone(),
            ready.clone(),
            ready_check.clone(),
        )?;
        handles.push(handle);
        admin_addr = Some(addr);
        crate::node_log::admin_started(&cfg.admin.listen);
    }

    crate::set_user_agent(&cfg.transport.user_agent);
    let ingress = if cfg.ingress_role() {
        Some(
            Ingress::new(cfg.clone())
                .with_auth(auth.clone())
                .with_metrics(metrics.clone()),
        )
    } else {
        None
    };
    let hub = ingress.as_ref().and_then(|i| i.hub.clone());
    if let Some(ingress) = &ingress {
        let fatal = fatal.clone();
        ingress.set_fatal_handler(Arc::new(move |e: Error| {
            crate::slog::error(
                "ingress listener stopped accepting",
                &[("err", e.message.as_str().into())],
            );
            if let Ok(mut slot) = fatal.lock() {
                slot.get_or_insert(e);
            }
        }));
    }

    // Streams arriving over a tunnel are served by the egress HTTP server.
    let tunnel_listener = if cfg.reverse.enabled {
        Some(Arc::new(crate::tunnel::client::TunnelListener::new()))
    } else {
        None
    };

    if cfg.egress_role() {
        let mut server = egress::Server::new(cfg.clone(), metrics.clone());
        server.auth = auth.clone();
        server.hub = hub.clone();
        server.tunnels = tunnel_listener.clone();
        let server = Arc::new(server);
        let weak_server = Arc::downgrade(&server);
        let reload_hub = hub.as_ref().map(Arc::downgrade);
        auth.set_reload_callback(Arc::new(move |snapshot| {
            if let Some(server) = weak_server.upgrade() {
                server.on_auth_reload(snapshot);
            }
            if let Some(hub) = reload_hub.as_ref().and_then(std::sync::Weak::upgrade) {
                hub.revalidate(&snapshot.outbound);
            }
        }));
        egress_control = Some(server.clone());
        let sd = shutdown.clone();
        let s = server.clone();
        let fatal = fatal.clone();
        let stopping = shutdown.clone();
        handles.push(std::thread::spawn(move || {
            if let Err(e) = s.listen(sd) {
                crate::slog::error(
                    "egress server stopped serving",
                    &[("err", e.message.as_str().into())],
                );
                // A node whose egress cannot serve must not linger as a
                // healthy-looking process: stop and exit non-zero.
                if stopping.load(Ordering::Relaxed) {
                    return;
                }
                if let Ok(mut slot) = fatal.lock() {
                    slot.get_or_insert(Error::new(
                        config::CODE_START_FAILED,
                        format!("failed to start node: egress: {}", e.message),
                    ));
                }
            }
        }));
    }

    auth_thread = auth.start(shutdown.clone(), signals::take_hup_logged);

    if let Some(ingress) = &ingress {
        handles.extend(ingress.start(shutdown.clone())?);
    }

    // The database side dials out only once its own egress is serving, so a
    // stream the public side opens always has somewhere to land.
    let reverse_client = match &tunnel_listener {
        Some(ln) => {
            let c = crate::tunnel::client::Client::new(cfg.clone(), ln.clone())
                .with_auth(auth.clone())
                .with_metrics(metrics.clone());
            let hs = c.start();
            handles.extend(hs);
            crate::node_log::reverse_starting(
                &cfg.reverse.peer_node_id,
                cfg.reverse.endpoints.len(),
                cfg.reverse.tunnels_per_endpoint as usize,
            );
            Some(c)
        }
        None => None,
    };

    if reverse_client.is_some() || hub.is_some() {
        let client = reverse_client.clone();
        let hub = hub.clone();
        let http_enabled = cfg.http.enabled;
        let peer_node_id = cfg.reverse.peer_node_id.clone();
        let check: crate::admin::ReadyCheck = Arc::new(move || {
            let missing = hub.as_ref().map(|h| h.missing_peers()).unwrap_or_default();
            crate::admin::reverse_readiness(
                http_enabled,
                &peer_node_id,
                client.as_ref().map(|c| c.live_count()),
                &missing,
            )
        });
        *ready_check
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(check);
    }
    ready.store(true, Ordering::Relaxed);
    if let Err(e) = crate::service::notify("READY=1") {
        crate::node_log::notify_failed("READY=1", &e);
    }

    while !signals::stop() && !has_fatal(&fatal) {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if let Some(err) = fatal
        .lock()
        .ok()
        .and_then(|slot| slot.as_ref().map(|e| e.message.clone()))
    {
        crate::node_log::fatal(&err);
    } else {
        crate::node_log::termination_requested();
    }
    if let Err(e) = crate::service::notify("STOPPING=1") {
        crate::node_log::notify_failed("STOPPING=1", &e);
    }
    crate::node_log::shutting_down(&cfg.node.id);
    let teardown_budget = cfg.max_shutdown_duration();
    let hard_deadline = Instant::now() + teardown_budget;
    ready.store(false, Ordering::Relaxed);
    // Drain: the egress refuses new sessions, the listeners stop accepting,
    // and open sessions run on until they finish or shutdown_timeout passes.
    if let Some(server) = &egress_control {
        server.drain();
    }
    if let Some(ingress) = &ingress {
        ingress.drain();
    }
    drain(
        &cfg,
        Instant::now() + cfg.transport.shutdown_timeout,
        ingress.as_ref(),
        egress_control.as_deref(),
    );
    if let Some(ingress) = &ingress {
        let close_deadline = hard_deadline
            .checked_sub(std::time::Duration::from_secs(1))
            .unwrap_or_else(Instant::now)
            .max(Instant::now());
        ingress.close_until(close_deadline);
    }
    shutdown.store(true, Ordering::Relaxed);
    let _ = auth_thread.join();
    if let Some(h) = &hub {
        h.close();
    }
    if let Some(server) = &egress_control {
        server.request_shutdown();
    }
    if let Some(c) = &reverse_client {
        c.stop();
    }
    if let Some(ingress) = &ingress {
        ingress.request_shutdown();
    }
    if let Some(addr) = admin_addr {
        let _ = crate::net::wake_tcp_listener(addr);
    }
    // A single reaper joins every worker; the main thread waits on its
    // completion notification rather than polling JoinHandle::is_finished.
    let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
    let ingress_metrics = ingress.as_ref().map(|i| i.metrics.clone());
    std::thread::spawn(move || {
        let mut panics = 0usize;
        for handle in handles {
            if handle.join().is_err() {
                panics += 1;
            }
        }
        if let Some(m) = ingress_metrics {
            while m.ingress_connection_count() > 0 {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
        let _ = done_tx.send(panics);
    });
    let deadline = hard_deadline;
    let teardown_timeout = teardown_budget;
    loop {
        if signals::stop_count() > 1 {
            return Ok(EXIT_INTERRUPTED);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            crate::node_log::teardown_exceeded(teardown_timeout);
            break;
        }
        match done_rx.recv_timeout(remaining.min(std::time::Duration::from_millis(50))) {
            Ok(0) => break,
            Ok(panics) => {
                crate::node_log::workers_panicked(panics);
                break;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    crate::node_log::stopped();
    if let Some(error) = fatal.lock().ok().and_then(|mut slot| slot.take()) {
        return Err(error);
    }
    crate::node_log::exited_cleanly();
    Ok(if signals::stop_count() > 1 {
        EXIT_INTERRUPTED
    } else {
        EXIT_OK
    })
}

const DRAIN_PROGRESS_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

fn drain(
    cfg: &config::Config,
    deadline: Instant,
    ingress: Option<&Ingress>,
    egress: Option<&egress::Server>,
) {
    let mut next = Instant::now();
    loop {
        let local = ingress.map_or(0, Ingress::count);
        let remote = egress.map_or(0, egress::Server::session_count);
        if local == 0 && remote == 0 {
            return;
        }
        let now = Instant::now();
        if now >= deadline {
            crate::slog::warn(
                "drain timeout reached; closing the remaining sessions",
                &[
                    ("local_connections", local.into()),
                    ("remote_sessions", remote.into()),
                    ("shutdown_timeout", cfg.transport.shutdown_timeout.into()),
                ],
            );
            return;
        }
        if now >= next {
            let remaining = deadline - now;
            let remaining =
                std::time::Duration::from_secs((remaining.as_millis() as u64 + 500) / 1000);
            crate::slog::info(
                "draining: waiting for open sessions to finish (send the signal again to force exit)",
                &[
                    ("local_connections", local.into()),
                    ("remote_sessions", remote.into()),
                    ("remaining", remaining.into()),
                ],
            );
            next = now + DRAIN_PROGRESS_INTERVAL;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

mod signals {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    pub static STOP: AtomicBool = AtomicBool::new(false);
    pub static HUP: AtomicBool = AtomicBool::new(false);
    pub static STOP_COUNT: AtomicUsize = AtomicUsize::new(0);
    /// Whether a second termination signal force-exits the process (only
    /// while `run` serves; unit tests drive the counters directly).
    pub static FORCE_EXIT: AtomicBool = AtomicBool::new(false);

    pub const FORCE_MESSAGE: &[u8] = b"second termination signal received; forcing exit\n";

    /// write(2) on fd 2 without std's stderr lock or allocation, so it is
    /// async-signal-safe (`File::write` is a direct write(2) call).
    #[cfg(unix)]
    fn write_stderr_raw(message: &[u8]) {
        use std::io::Write;
        use std::os::unix::io::FromRawFd;
        // SAFETY: fd 2 stays open for the process lifetime; ManuallyDrop
        // keeps the File from closing it.
        let mut stderr = std::mem::ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(2) });
        let _ = stderr.write(message);
    }

    pub fn reset() {
        STOP.store(false, Ordering::SeqCst);
        HUP.store(false, Ordering::SeqCst);
        STOP_COUNT.store(0, Ordering::SeqCst);
    }
    pub fn stop_count() -> usize {
        STOP_COUNT.load(Ordering::SeqCst)
    }

    pub fn stop() -> bool {
        STOP.load(Ordering::SeqCst)
    }
    pub fn take_hup() -> bool {
        HUP.swap(false, Ordering::SeqCst)
    }

    pub fn take_hup_logged() -> bool {
        let hup = take_hup();
        if hup {
            crate::slog::info(
                "SIGHUP received; re-reading credentials (use SIGTERM to stop)",
                &[],
            );
        }
        hup
    }

    /// Records one termination signal; returns true when it is the second
    /// and the process must force-exit.
    pub fn on_termination() -> bool {
        STOP.store(true, Ordering::SeqCst);
        let previous = STOP_COUNT.fetch_add(1, Ordering::SeqCst);
        previous >= 1 && FORCE_EXIT.load(Ordering::SeqCst)
    }

    #[cfg(unix)]
    mod sys {
        pub const SIGHUP: i32 = 1;
        pub const SIGINT: i32 = 2;
        pub const SIGTERM: i32 = 15;
        #[cfg(any(target_os = "linux", target_os = "android"))]
        pub const SA_RESTART: u64 = 0x1000_0000;
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        pub const SA_RESTART: u64 = 0x0002;

        /// `struct sigaction` on Linux (glibc and musl share the kernel-facing
        /// layout used by the libc wrapper: handler, mask, flags, restorer).
        #[cfg(target_os = "linux")]
        #[repr(C)]
        pub struct SigAction {
            pub handler: usize,
            pub mask: [u64; 16],
            pub flags: i32,
            pub restorer: usize,
        }

        extern "C" {
            pub fn sigaction(signum: i32, act: *const SigAction, old: *mut SigAction) -> i32;
            pub fn _exit(code: i32) -> !;
        }
    }

    #[cfg(unix)]
    extern "C" fn hup_handler(_sig: i32) {
        HUP.store(true, Ordering::SeqCst);
    }

    #[cfg(all(test, target_os = "linux"))]
    pub fn install_hangup() {
        install_handlers(&[(sys::SIGHUP, hup_handler as extern "C" fn(i32) as usize)]);
    }

    #[cfg(target_os = "linux")]
    pub fn install() {
        extern "C" fn handler(_sig: i32) {
            if on_termination() {
                // SAFETY: write(2) and _exit(2) are async-signal-safe.
                unsafe {
                    write_stderr_raw(FORCE_MESSAGE);
                    sys::_exit(super::EXIT_INTERRUPTED);
                }
            }
        }
        FORCE_EXIT.store(true, Ordering::SeqCst);
        install_handlers(&[
            (sys::SIGINT, handler as extern "C" fn(i32) as usize),
            (sys::SIGTERM, handler as extern "C" fn(i32) as usize),
            (sys::SIGHUP, hup_handler as extern "C" fn(i32) as usize),
        ]);
    }

    #[cfg(target_os = "linux")]
    fn install_handlers(handlers: &[(i32, usize)]) {
        for &(signum, f) in handlers {
            let act = sys::SigAction {
                handler: f,
                mask: [0; 16],
                flags: sys::SA_RESTART as i32,
                restorer: 0,
            };
            // SAFETY: act is a fully initialised sigaction for a valid signal.
            let rc = unsafe { sys::sigaction(signum, &act, std::ptr::null_mut()) };
            if rc != 0 {
                crate::slog::warn(
                    "installing signal handler failed",
                    &[
                        ("signal", (signum as i64).into()),
                        ("err", crate::slog::err(std::io::Error::last_os_error())),
                    ],
                );
            }
        }
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    pub fn install() {
        extern "C" fn handler(_sig: i32) {
            if on_termination() {
                unsafe {
                    write_stderr_raw(FORCE_MESSAGE);
                    sys::_exit(super::EXIT_INTERRUPTED);
                }
            }
        }
        extern "C" {
            fn signal(signum: i32, handler: usize) -> usize;
        }
        FORCE_EXIT.store(true, Ordering::SeqCst);
        unsafe {
            signal(sys::SIGINT, handler as *const () as usize);
            signal(sys::SIGTERM, handler as *const () as usize);
            signal(sys::SIGHUP, hup_handler as *const () as usize);
        }
    }

    #[cfg(windows)]
    pub fn install() {
        extern "system" fn handler(_ctrl: u32) -> i32 {
            if on_termination() {
                std::process::exit(super::EXIT_INTERRUPTED);
            }
            1
        }
        extern "system" {
            fn SetConsoleCtrlHandler(
                handler: Option<extern "system" fn(u32) -> i32>,
                add: i32,
            ) -> i32;
        }
        FORCE_EXIT.store(true, Ordering::SeqCst);
        unsafe {
            SetConsoleCtrlHandler(Some(handler), 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        execute, service_plan_json, signals, version_line, Failure, EXIT_CONFIG, EXIT_FAILURE, HELP,
    };

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn exec(list: &[&str]) -> (Result<(), Failure>, String, String) {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let r = execute(&args(list), &mut out, &mut err);
        (
            r,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    fn temp_dir(tag: &str) -> String {
        let dir = std::env::temp_dir().join(format!(
            "dbb-cli-{tag}-{}",
            crate::util::random_hex(6).unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.to_string_lossy().into_owned()
    }

    #[test]
    fn version_uses_spec_field_order() {
        assert_eq!(
            version_line(),
            format!(
                "dbbridge version {} (commit: {}, built: {}, runtime: {}, protocol: 1.5)",
                crate::VERSION,
                crate::COMMIT,
                crate::BUILD_DATE,
                crate::RUSTC_VERSION,
            )
        );
        for flag in ["version", "-v", "--version"] {
            let (r, out, _) = exec(&[flag]);
            assert!(r.is_ok());
            assert_eq!(out, format!("{}\n", version_line()));
        }
        let (r, _, _) = exec(&["version", "extra"]);
        assert_eq!(r.unwrap_err().error.message, "version accepts no arguments");
    }

    #[test]
    fn no_arguments_print_help_and_fail() {
        let (r, out, _) = exec(&[]);
        let f = r.unwrap_err();
        assert_eq!(
            (f.exit, f.error.message.as_str()),
            (EXIT_FAILURE, "a command is required")
        );
        assert_eq!(out, HELP);
        for flag in ["help", "-h", "--help"] {
            let (r, out, _) = exec(&[flag]);
            assert!(r.is_ok());
            assert_eq!(out, HELP);
        }
    }

    #[test]
    fn rejects_ambiguous_or_unsupported_arguments() {
        for list in [
            &["gen-config", "--mode", "invalid"][..],
            &["gen-config", "--role", "egress"],
            &["run"],
            &["install"],
            &["version", "extra"],
            &["gen-config", "extra"],
            &["uninstall", "--service-name", "../ssh", "--dry-run"],
            &["run", "-c", "unused", "--dry-run"],
            &["check-config", "-c", "unused", "--install"],
            &["--config", "unused"],
            &["--install", "-c", "unused", "--dry-run"],
            &["run", "-c", "unused", "--start"],
            &["run", "-c", "unused", "--log-format", "invalid"],
            &["unknown"],
        ] {
            let (r, _, _) = exec(list);
            assert!(r.is_err(), "accepted {list:?}");
        }
        for list in [
            &["help"][..],
            &["gen-config", "--help"],
            &["run", "--help"],
            &["--version"],
        ] {
            let (r, out, err) = exec(list);
            assert!(r.is_ok(), "{list:?}");
            assert!(!(out + &err).trim().is_empty(), "{list:?}");
        }
        let (r, _, _) = exec(&[
            "uninstall",
            "--service-name",
            "dbbridge-preview-absent",
            "--dry-run",
        ]);
        let f = r.unwrap_err();
        assert_eq!(f.exit, EXIT_FAILURE);
        assert_eq!(f.error.code, crate::config::CODE_SERVICE_INSTALL);
        assert!(
            f.error.message.contains("not installed"),
            "{}",
            f.error.message
        );
    }

    #[test]
    fn flag_errors_print_spec_diagnostics_and_usage() {
        let (r, _, err) = exec(&["check-config", "--start", "-c", "f"]);
        let f = r.unwrap_err();
        assert_eq!(f.exit, EXIT_FAILURE);
        assert_eq!(f.error.message, "flag provided but not defined: -start");
        assert!(err.starts_with("flag provided but not defined: -start\nUsage: dbbridge check-config [options]\n\nOptions:\n  -c\n    \tConfiguration path (shorthand)\n"));
        let (r, _, _) = exec(&["run", "-c", "a.yaml", "extra"]);
        assert_eq!(
            r.unwrap_err().error.message,
            "unexpected positional argument: extra"
        );
        let (r, _, _) = exec(&["run", "--log-level", "trace", "-c", "a.yaml"]);
        assert_eq!(r.unwrap_err().error.message, "invalid --log-level");
        let (r, _, _) = exec(&["run", "-c", "a.yaml", "--service-name", "bad/name"]);
        assert_eq!(r.unwrap_err().error.message, "invalid --service-name");
        let (r, _, _) = exec(&["check-config", "--offline=maybe", "-c", "a"]);
        assert_eq!(
            r.unwrap_err().error.message,
            "invalid boolean value \"maybe\" for -offline: parse error"
        );
        let (r, _, _) = exec(&["gen-config", "--max-sessions", "lots"]);
        assert_eq!(
            r.unwrap_err().error.message,
            "invalid value \"lots\" for flag -max-sessions: parse error"
        );
    }

    #[test]
    fn command_help_lists_only_its_options() {
        let (r, out, help) = exec(&["run", "--help"]);
        assert!(r.is_ok() && out.is_empty());
        for hidden in [
            "-dry-run",
            "-start",
            "-service-user",
            "-offline",
            "-exec-path",
        ] {
            assert!(
                !help.contains(&format!("{hidden}\n")),
                "run help lists {hidden}"
            );
        }
        assert!(help.contains("  -log-level\n    \tdebug, info, warn, error (default info)\n"));
        let (_, _, help) = exec(&["install", "--help"]);
        assert!(help.contains("-exec-path\n") && !help.contains("-offline\n"));
        let (_, _, help) = exec(&["uninstall", "-h"]);
        assert_eq!(help, "Usage of uninstall:\n  -dry-run\n    \tPreview removal without changing the system\n  -service-name string\n    \tService identity (default \"dbbridge\")\n");
        let (_, _, help) = exec(&["gen-config", "-help"]);
        assert!(help.starts_with("Usage of gen-config:\n  -a-admin-listen string\n"));
        assert!(help
            .contains("  -recovery\n    \tEnable session recovery on both nodes (default true)\n"));
        assert_eq!(
            help.matches("\n  -").count(),
            30,
            "gen-config defines 30 flags"
        );
    }

    #[test]
    fn generate_then_check_config_and_install_preview() {
        let dir = temp_dir("gen");
        let (r, out, _) = exec(&["gen-config", "-o", &dir]);
        assert!(r.is_ok(), "{:?}", r.err().map(|f| f.error.message));
        assert_eq!(out, format!("Configuration pair generated and validated (mode: bidirectional):\n  A: {dir}/peer-a.yaml\n  B: {dir}/peer-b.yaml\nShared token file: {dir}/shared.token (deploy a copy with each node; its value is not printed)\n"));
        let secret = std::fs::read_to_string(format!("{dir}/shared.token")).unwrap();
        assert!(!out.contains(secret.trim()));
        let path = format!("{dir}/peer-a.yaml");
        let (r, out, _) = exec(&["check-config", "-c", &path]);
        assert!(r.is_ok());
        assert_eq!(out, format!("Config {path} is valid. Node ID: A\n"));
        let (r, out, _) = exec(&["check-config", "--offline", "--config", &path]);
        assert!(r.is_ok());
        assert!(out.starts_with(&format!("Config {path} is structurally valid (offline:")));
        for flag in ["-c", "--config"] {
            let (r, out, _) = exec(&[
                "install",
                flag,
                &path,
                "--dry-run",
                "--exec-path",
                "/bin/true",
            ]);
            assert!(r.is_ok(), "{:?}", r.err().map(|f| f.error.message));
            assert!(out.contains("\"name\": \"dbbridge\""));
            assert!(!out.contains(secret.trim()));
        }
        // gen-config refuses to overwrite and exits 1.
        let (r, _, _) = exec(&["gen-config", "-o", &dir]);
        let f = r.unwrap_err();
        assert_eq!(f.exit, EXIT_FAILURE);
        assert!(f
            .error
            .message
            .ends_with("(use --force to replace the pair)"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(feature = "tls")]
    #[test]
    fn generate_pair_per_node_cli_options() {
        let dir = temp_dir("pernode");
        let (r, _, _) = exec(&[
            "gen-config",
            "-o",
            &dir,
            "--a-node-id",
            "factory",
            "--b-node-id",
            "cloud",
            "--a-target-id",
            "factory-db",
            "--b-target-id",
            "cloud-db",
            "--a-listen",
            "127.0.0.1:15432",
            "--b-listen",
            "127.0.0.1:11433",
            "--a-peer-url",
            "https://cloud-primary.example.com",
            "--a-peer-url",
            "https://cloud-backup.example.com",
            "--b-peer-url",
            "https://factory.example.com",
            "--a-target-address",
            "db.internal:5432",
            "--a-allow-cidr",
            "10.0.0.0/8",
            "--b-target-address",
            "127.0.0.1:1433",
            "--protocol",
            "http-sse",
            "--recovery=false",
        ]);
        assert!(r.is_ok(), "{:?}", r.err().map(|f| f.error.message));
        let a = crate::config::load(std::path::Path::new(&format!("{dir}/peer-a.yaml"))).unwrap();
        let b = crate::config::load(std::path::Path::new(&format!("{dir}/peer-b.yaml"))).unwrap();
        assert_eq!(a.node.id, "factory");
        assert_eq!(b.node.id, "cloud");
        assert_eq!(a.listeners[0].target, "cloud-db");
        assert_eq!(b.listeners[0].target, "factory-db");
        assert_eq!(a.peers[0].endpoints.len(), 2);
        assert_eq!(
            a.transport.protocol,
            crate::config::Protocol::parse("http-sse").unwrap()
        );
        assert!(!b.transport.recovery_enabled);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn install_and_check_config_errors_exit_78() {
        let dir = temp_dir("bad");
        let path = format!("{dir}/bad.yaml");
        std::fs::write(&path, "node: {id: A}\nbogus: 1\n").unwrap();
        for list in [
            &["install", "-c", &path, "--dry-run"][..],
            &["check-config", "-c", &path],
        ] {
            let (r, _, _) = exec(list);
            let f = r.unwrap_err();
            assert_eq!(f.exit, EXIT_CONFIG, "{list:?}");
            assert_eq!(f.error.code, crate::config::CODE_CONFIG_READ);
        }
        let (r, _, _) = exec(&["check-config", "-c", &path]);
        assert!(r.unwrap_err().error.message.starts_with("config check: "));
        // A missing env file is a configuration error (78, DBB-CFG-006).
        let (r, _, _) = exec(&[
            "check-config",
            "-c",
            &path,
            "--env-file",
            &format!("{dir}/missing.json"),
        ]);
        let f = r.unwrap_err();
        assert_eq!(
            (f.exit, f.error.code.as_str()),
            (EXIT_CONFIG, crate::config::CODE_ENVIRONMENT)
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn install_exec_path_flag_is_install_only() {
        let dir = temp_dir("exec");
        assert!(exec(&["gen-config", "-o", &dir]).0.is_ok());
        let config = format!("{dir}/peer-a.yaml");
        let exe = std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let (r, out, _) = exec(&["install", "-c", &config, "--dry-run", "--exec-path", &exe]);
        assert!(r.is_ok());
        assert!(out.contains(&format!("\"executable\": \"{exe}\"")));
        let (r, _, _) = exec(&["run", "-c", &config, "--exec-path", &exe]);
        assert_eq!(
            r.unwrap_err().error.message,
            "flag provided but not defined: -exec-path"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn second_termination_signal_forces_exit() {
        signals::reset();
        signals::FORCE_EXIT.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(!signals::on_termination());
        assert!(signals::stop());
        assert!(signals::on_termination());
        signals::FORCE_EXIT.store(false, std::sync::atomic::Ordering::SeqCst);
        signals::reset();
        assert!(!signals::stop());
        assert_eq!(
            signals::FORCE_MESSAGE,
            b"second termination signal received; forcing exit\n"
        );
    }

    #[test]
    fn service_plan_json_hides_captured_credentials() {
        let dir = std::env::temp_dir().join(format!(
            "dbb-cli-plan-redaction-{}",
            crate::util::random_hex(6).unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let suffix = crate::util::random_hex(6).unwrap().to_ascii_uppercase();
        let name = format!("DBB_CLI_PLAN_SECRET_{suffix}");
        let secret = "do-not-serialize-this-token";
        std::env::set_var(&name, secret);
        std::fs::write(
            dir.join("credentials.yaml"),
            format!("version: 1\noutbound_peers:\n  - id: upstream\n    token_env: {name}\n"),
        )
        .unwrap();
        let config = dir.join("node.yaml");
        std::fs::write(
            &config,
            "node: {id: node-b}\nhttp:\n  enabled: true\n  listen: \"127.0.0.1:18080\"\ntargets:\n  db: {network: tcp, address: \"127.0.0.1:3306\"}\nauth:\n  credentials_file: credentials.yaml\npeers:\n  - id: upstream\n    expected_node_id: node-a\n    credential_ref: upstream\n    endpoints: [{id: primary, url: \"http://127.0.0.1:19080\"}]\n",
        )
        .unwrap();
        let plan = crate::service::prepare(&crate::service::Options {
            name: "redaction-test".into(),
            config,
            executable: Some(std::env::current_exe().unwrap()),
            account: Some("root".into()),
            log_level: "info".into(),
            log_format: "text".into(),
            start: false,
        })
        .unwrap();
        let output = service_plan_json(&plan);
        assert!(output.contains(&name));
        assert!(!output.contains(secret));
        assert!(!plan.environment_file.unwrap().exists());
        std::env::remove_var(name);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
