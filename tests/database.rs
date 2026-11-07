//! Optional real-MySQL/MariaDB integration coverage for the Rust binary.
//!
//! Set DBB_MYSQL_DSN and/or DBB_MARIADB_DSN to a TCP DSN, for
//! example `user:password@tcp(127.0.0.1:3306)/isolated_test_db`. The test uses
//! the mysql/mariadb CLI as its SQL client, so it adds no Rust runtime or test
//! dependencies. All writes are confined to a session-local temporary table.

use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);
const PAYLOAD_LEN: usize = 550_000;

#[derive(Debug)]
struct DatabaseDsn {
    user: String,
    password: String,
    host: String,
    port: u16,
    database: String,
}

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let unique = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "dbbridge-rust-database-{}-{stamp}-{unique}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create private database-test directory");
        set_private_permissions(&path, true);
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct RunningPeer(Child);

impl Drop for RunningPeer {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

#[test]
fn real_mysql_or_mariadb_through_rust_proxy() {
    let engines = [("MySQL", "DBB_MYSQL_DSN"), ("MariaDB", "DBB_MARIADB_DSN")];
    let configured: Vec<_> = engines
        .iter()
        .filter_map(|(name, variable)| {
            std::env::var(variable)
                .ok()
                .filter(|dsn| !dsn.trim().is_empty())
                .map(|dsn| (*name, *variable, dsn))
        })
        .collect();

    if configured.is_empty() {
        println!(
            "SKIP: set DBB_MYSQL_DSN and/or DBB_MARIADB_DSN to run real database integration cases"
        );
        return;
    }

    let client = mysql_client().unwrap_or_else(|| {
        panic!("a mysql or mariadb command-line client is required when a database DSN is set")
    });

    for (engine, variable, raw_dsn) in configured {
        let dsn = parse_dsn(&raw_dsn)
            .unwrap_or_else(|reason| panic!("{variable} is invalid (redacted): {reason}"));
        for protocol in ["ws", "http-sse"] {
            for recovery in [false, true] {
                run_database_case(&client, engine, &dsn, protocol, recovery);
            }
        }
    }
}

fn run_database_case(
    mysql: &Path,
    engine: &str,
    dsn: &DatabaseDsn,
    protocol: &str,
    recovery: bool,
) {
    let case = format!("{engine}/{protocol}/recovery={recovery}");
    let work = TestDir::new();
    let b_addr = free_address();
    let a_addr = free_address();
    let token = fresh_token();

    let target_address = if dsn.host.contains(':') {
        format!("[{}]:{}", dsn.host, dsn.port)
    } else {
        format!("{}:{}", dsn.host, dsn.port)
    };
    let b_config = format!(
        "node:\n  id: B\nhttp:\n  enabled: true\n  listen: {b_addr:?}\ntargets:\n  test-db:\n    network: tcp\n    address: {:?}\nauth:\n  inbound_peers:\n    - id: A\n      token_envs: [DBB_DATABASE_TEST_TOKEN]\n      allowed_targets: [test-db]\ntransport:\n  recovery:\n    enabled: {recovery}\n",
        target_address
    );
    let b_peer = start_peer(&work, "b", &b_config, &b_addr, &token);

    let a_config = format!(
        "node:\n  id: A\npeers:\n  - id: B\n    expected_node_id: B\n    credential_ref: B\n    token_env: DBB_DATABASE_TEST_TOKEN\n    endpoints:\n      - id: primary\n        url: {:?}\nlisteners:\n  - id: test\n    listen: {a_addr:?}\n    peer: B\n    target: test-db\ntransport:\n  protocol: {protocol}\n  recovery:\n    enabled: {recovery}\n",
        format!("http://{b_addr}")
    );
    let a_peer = start_peer(&work, "a", &a_config, &a_addr, &token);

    let credentials = write_client_config(work.path(), dsn, &a_addr);
    let sql_path = work.path().join("exercise.sql");
    let (sql, expected_hex) = integration_sql();
    write_private(&sql_path, sql.as_bytes());

    let output = Command::new(mysql)
        // mysql clients require --defaults-extra-file to be the first option.
        .arg(format!("--defaults-extra-file={}", credentials.display()))
        .env_remove("DBB_MYSQL_DSN")
        .env_remove("DBB_MARIADB_DSN")
        .env_remove("MYSQL_PWD")
        .args([
            "--batch",
            "--raw",
            "--skip-column-names",
            "--binary-mode",
            "--skip-reconnect",
        ])
        .stdin(Stdio::from(File::open(&sql_path).expect("open SQL script")))
        .output()
        .unwrap_or_else(|_| panic!("{case}: could not start mysql client"));

    if !output.status.success() {
        panic!("{case}: SQL exercise failed (credentials and DSN redacted)");
    }

    let stdout = String::from_utf8(output.stdout)
        .unwrap_or_else(|_| panic!("{case}: mysql client returned non-UTF-8 output"));
    let rows: Vec<_> = stdout.lines().collect();
    assert_eq!(
        rows.len(),
        2,
        "{case}: expected identity and payload result rows"
    );

    let identity: Vec<_> = rows[0].split('\t').collect();
    assert_eq!(identity.len(), 2, "{case}: malformed identity result");
    let version = identity[0];
    let before = identity[1];
    if engine == "MariaDB" {
        assert!(
            version.to_ascii_lowercase().contains("mariadb"),
            "DBB_MARIADB_DSN does not refer to MariaDB"
        );
    }

    let result: Vec<_> = rows[1].split('\t').collect();
    assert_eq!(result.len(), 2, "{case}: malformed payload result");
    assert_eq!(result[0], expected_hex, "{case}: stored BLOB bytes differ");
    assert_eq!(
        result[1], before,
        "{case}: backend connection identity changed"
    );

    // Keep both children alive through the entire SQL exchange.
    drop(a_peer);
    drop(b_peer);
    println!(
        "{case}: temporary table, transaction, prepared SQL, {PAYLOAD_LEN}-byte BLOB and backend connection identity verified"
    );
}

fn start_peer(
    work: &TestDir,
    label: &str,
    config: &str,
    address: &str,
    token: &str,
) -> RunningPeer {
    let config_path = work.path().join(format!("{label}.yaml"));
    write_private(&config_path, config.as_bytes());
    let log_path = work.path().join(format!("{label}.log"));
    let log = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&log_path)
        .expect("create private peer log");
    set_private_permissions(&log_path, false);
    let stdout = log.try_clone().expect("clone peer log handle");
    let mut child = Command::new(env!("CARGO_BIN_EXE_dbbridge"))
        .args([
            "run",
            "--config",
            config_path.to_str().expect("UTF-8 temporary path"),
            "--log-level",
            "error",
        ])
        .env_remove("DBB_MYSQL_DSN")
        .env_remove("DBB_MARIADB_DSN")
        .env("DBB_DATABASE_TEST_TOKEN", token)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap_or_else(|_| panic!("cannot start Rust peer {label}"));

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if child.try_wait().expect("check Rust peer status").is_some() {
            panic!(
                "Rust peer {label} exited before readiness; private log: {}",
                log_path.display()
            );
        }
        if TcpStream::connect_timeout(
            &address.parse().expect("peer listen address"),
            Duration::from_millis(50),
        )
        .is_ok()
        {
            return RunningPeer(child);
        }
        thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!(
        "Rust peer {label} readiness deadline exceeded; private log: {}",
        log_path.display()
    );
}

fn free_address() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("allocate loopback port");
    listener
        .local_addr()
        .expect("read allocated address")
        .to_string()
}

fn integration_sql() -> (String, String) {
    let payload: Vec<u8> = (0..PAYLOAD_LEN)
        .map(|index| [0, 255, 13, 10, 128][index % 5])
        .collect();
    let expected_hex = hex_upper(&payload);
    let sql = format!(
        "SELECT VERSION(), CONNECTION_ID();\nCREATE TEMPORARY TABLE dbbridge_rust_patch_test (id INT PRIMARY KEY, payload LONGBLOB);\nSTART TRANSACTION;\nPREPARE dbbridge_insert FROM 'INSERT INTO dbbridge_rust_patch_test VALUES (1, ?)';\nSET @dbbridge_payload = UNHEX('{expected_hex}');\nEXECUTE dbbridge_insert USING @dbbridge_payload;\nDEALLOCATE PREPARE dbbridge_insert;\nCOMMIT;\nSELECT HEX(payload), CONNECTION_ID() FROM dbbridge_rust_patch_test WHERE id = 1;\n"
    );
    (sql, expected_hex)
}

fn write_client_config(work: &Path, dsn: &DatabaseDsn, proxy_addr: &str) -> PathBuf {
    let port = proxy_addr
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .expect("allocated proxy port");
    let content = format!(
        "[client]\nuser=\"{}\"\npassword=\"{}\"\nhost=\"127.0.0.1\"\nport={port}\ndatabase=\"{}\"\nprotocol=TCP\nconnect-timeout=5\n",
        option_file_escape(&dsn.user),
        option_file_escape(&dsn.password),
        option_file_escape(&dsn.database)
    );
    let path = work.join("mysql-client.cnf");
    write_private(&path, content.as_bytes());
    path
}

fn parse_dsn(raw: &str) -> Result<DatabaseDsn, &'static str> {
    let marker = "@tcp(";
    let marker_at = raw
        .find(marker)
        .ok_or("expected user[:password]@tcp(host[:port])/database")?;
    let (user_info, after_marker) = raw.split_at(marker_at);
    let after_marker = &after_marker[marker.len()..];
    let address_end = after_marker.find(')').ok_or("unterminated TCP address")?;
    let address = &after_marker[..address_end];
    let database_part = after_marker[address_end + 1..]
        .strip_prefix('/')
        .ok_or("expected database name after TCP address")?;
    let database = database_part.split('?').next().unwrap_or_default();
    if database.is_empty() {
        return Err("DSN must select a database");
    }

    let (user, password) = match user_info.split_once(':') {
        Some((user, password)) => (
            unescape_dsn_component(user)?,
            unescape_dsn_component(password)?,
        ),
        None => (unescape_dsn_component(user_info)?, String::new()),
    };
    if user.is_empty() {
        return Err("DSN username must not be empty");
    }

    let (host, port) = parse_tcp_address(address)?;
    for value in [&user, &password, &host, database] {
        if value.chars().any(char::is_control) {
            return Err("DSN fields must not contain control characters");
        }
    }
    Ok(DatabaseDsn {
        user,
        password,
        host,
        port,
        database: database.to_owned(),
    })
}

fn parse_tcp_address(address: &str) -> Result<(String, u16), &'static str> {
    if address.is_empty() || address.starts_with('/') {
        return Err("DSN must use a TCP host, not a Unix socket");
    }
    if let Some(bracketed) = address.strip_prefix('[') {
        let close = bracketed
            .find(']')
            .ok_or("invalid bracketed IPv6 address")?;
        let host = &bracketed[..close];
        let remainder = &bracketed[close + 1..];
        let port = if remainder.is_empty() {
            3306
        } else {
            remainder
                .strip_prefix(':')
                .ok_or("invalid bracketed IPv6 port")?
                .parse::<u16>()
                .map_err(|_| "invalid TCP port")?
        };
        if host.is_empty() {
            return Err("TCP host must not be empty");
        }
        return Ok((host.to_owned(), port));
    }
    match address.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => Ok((
            host.to_owned(),
            port.parse::<u16>().map_err(|_| "invalid TCP port")?,
        )),
        Some(_) => Err("TCP host must not be empty"),
        None => Ok((address.to_owned(), 3306)),
    }
}

fn unescape_dsn_component(value: &str) -> Result<String, &'static str> {
    let mut output = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            output.push(chars.next().ok_or("trailing escape in DSN credentials")?);
        } else {
            output.push(ch);
        }
    }
    Ok(output)
}

fn option_file_escape(value: &str) -> String {
    let mut result = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            _ => result.push(ch),
        }
    }
    result
}

fn mysql_client() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os("MYSQL_CLIENT") {
        let path = PathBuf::from(explicit);
        return path.exists().then_some(path);
    }
    ["mysql", "mariadb"]
        .iter()
        .find_map(|name| find_on_path(name))
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
}

fn fresh_token() -> String {
    let mut bytes = [0u8; 32];
    #[cfg(unix)]
    File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(&mut bytes))
        .expect("read integration-test token from OS entropy");
    #[cfg(windows)]
    {
        #[link(name = "bcrypt")]
        extern "system" {
            fn BCryptGenRandom(
                algorithm: *mut core::ffi::c_void,
                buffer: *mut u8,
                len: u32,
                flags: u32,
            ) -> i32;
        }
        let status = unsafe {
            BCryptGenRandom(
                std::ptr::null_mut(),
                bytes.as_mut_ptr(),
                bytes.len() as u32,
                0x0000_0002,
            )
        };
        assert_eq!(status, 0, "read integration-test token from OS entropy");
    }
    #[cfg(not(any(unix, windows)))]
    panic!("integration-test token has no OS entropy implementation on this target");
    hex_lower(&bytes)
}

fn hex_upper(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap_or_else(|_| panic!("write private test file {}", path.display()));
    set_private_permissions(path, false);
}

#[test]
fn parses_spec_style_database_dsns_without_exposing_credentials() {
    let dsn = parse_dsn(r"app:p\:ss@tcp(db.example:3307)/isolated?charset=utf8mb4")
        .expect("valid TCP DSN");
    assert_eq!(dsn.user, "app");
    assert_eq!(dsn.password, "p:ss");
    assert_eq!(dsn.host, "db.example");
    assert_eq!(dsn.port, 3307);
    assert_eq!(dsn.database, "isolated");

    let ipv6 = parse_dsn("app@tcp([::1])/isolated").expect("valid IPv6 DSN");
    assert_eq!(ipv6.host, "::1");
    assert_eq!(ipv6.port, 3306);
    assert_eq!(ipv6.password, "");

    assert!(parse_dsn("app@tcp(/tmp/mysql.sock)/isolated").is_err());
    assert!(parse_dsn("app@tcp(127.0.0.1:3306)/").is_err());
}

#[cfg(unix)]
fn set_private_permissions(path: &Path, directory: bool) {
    use std::os::unix::fs::PermissionsExt;
    let mode = if directory { 0o700 } else { 0o600 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .expect("set private test permissions");
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path, _directory: bool) {}
