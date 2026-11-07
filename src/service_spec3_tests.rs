use super::*;

fn temp(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "dbb-spec-svc-{tag}-{}",
        crate::util::random_hex(6).unwrap()
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn service_fixture(tag: &str) -> (Options, PathBuf) {
    let dir = temp(tag);
    let path = dir.join("peer.yaml");
    crate::cli::genconfig::generate(crate::cli::genconfig::GenerateOptions {
        output: path.to_string_lossy().into_owned(),
        role: "ingress".into(),
        node_id: "A".into(),
        peer_id: "B".into(),
        listen: "127.0.0.1:0".into(),
        target_id: "mysql".into(),
        protocol: "auto".into(),
        recovery: true,
        max_sessions: 10,
        ..Default::default()
    })
    .unwrap_or_else(|e| panic!("generate: {}", e.message));
    (
        Options {
            name: "dbbridge-test".into(),
            config: path,
            executable: Some(std::env::current_exe().unwrap()),
            account: None,
            log_level: "info".into(),
            log_format: "json".into(),
            start: false,
        },
        dir,
    )
}

#[cfg(target_os = "linux")]
fn current_uid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { geteuid() }
}

#[test]
fn spec_environment_deny_list() {
    for name in [
        "GODEBUG",
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "NO_PROXY",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "LD_PRELOAD",
        "ld_library_path",
    ] {
        assert!(
            !safe_env_name(name),
            "{name} accepted in credential snapshot"
        );
    }
    assert!(
        safe_env_name("DBB_TOKEN_A_TO_B"),
        "ordinary credential name rejected"
    );
}

#[test]
fn spec_environment_names() {
    for name in [
        "GOFIPS140",
        "GOCOVERDIR",
        "REQUEST_METHOD",
        "LISTEN_FDNAMES",
        "DYLD_INSERT_LIBRARIES",
        "TZ",
    ] {
        assert!(!safe_env_name(name), "{name} accepted");
    }
    for name in ["CODEX_HOME", "DBB_TOKEN_X", "PLANT_A_SECRET"] {
        assert!(safe_env_name(name), "{name} rejected");
    }
}

#[test]
fn spec_unit_restart_policy_nofile_and_stop_budget() {
    let unit = |max_sessions| {
        systemd_unit(
            "dbbridge-test",
            "dbbridge",
            Path::new("/opt/dbbridge/dbbridge"),
            Path::new("/etc/dbbridge/peer.yaml"),
            "info",
            "text",
            Path::new("/etc/dbbridge"),
            Duration::from_secs(45),
            max_sessions,
            false,
            None,
            &[],
        )
        .unwrap()
    };
    let text = unit(5000);
    for directive in [
        "RestartPreventExitStatus=78\n",
        "LimitNOFILE=21024\n",
        "TimeoutStopSec=60s\n",
        "StartLimitIntervalSec=300\n",
        "StartLimitBurst=10\n",
        "CapabilityBoundingSet=\n",
    ] {
        assert!(
            text.contains(&format!("\n{directive}")),
            "unit lacks {directive:?}"
        );
    }
    assert!(
        unit(200).contains("\nLimitNOFILE=8192\n"),
        "descriptor limit below the 8192 floor"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn spec_prepare_uses_max_shutdown_duration() {
    let (o, dir) = service_fixture("stop-budget");
    let p = prepare(&o).unwrap_or_else(|e| panic!("{}", e.message));
    let cfg = config::load(&o.config).unwrap();
    assert_eq!(
        cfg.max_shutdown_duration(),
        Duration::from_secs(45),
        "plan stop budget, want shutdown_timeout 30s + teardown 15s"
    );
    assert_eq!(p.platform, "linux");
    assert!(
        p.unit.contains("\nTimeoutStopSec=60s\n"),
        "unit stop timeout:\n{}",
        p.unit
    );
    fs::remove_dir_all(dir).ok();
}

#[test]
fn spec_unit_escapes_paths_and_sets_graceful_stop_budget() {
    let generate = |config: &str| {
        systemd_unit(
            "dbbridge-test",
            "root",
            Path::new(r#"/opt/db "bridge"/$literal%/dbbridge"#),
            Path::new(config),
            "info",
            "text",
            Path::new("/etc/db bridge/%configs"),
            Duration::from_secs(65),
            200,
            false,
            None,
            &[],
        )
    };
    let unit = generate("/etc/db bridge/$config%.yaml").unwrap();
    for fragment in [
        "Type=notify",
        "NotifyAccess=main",
        "$$literal%%",
        r#"\"bridge\""#,
        "$$config%%.yaml",
        "TimeoutStopSec=80s",
        "WorkingDirectory=/etc/db bridge/%%configs",
    ] {
        assert!(
            unit.contains(fragment),
            "missing unit escape/setting: {fragment}\n{unit}"
        );
    }
    assert!(
        generate("/etc/db bridge/$config%.yaml\nbad\nvalue").is_err(),
        "newline injection accepted"
    );
    for name in [
        "../other",
        "other/service",
        "space name",
        "x\ny",
        "dbbridge.service",
        "",
    ] {
        assert!(!valid_name(name), "accepted unsafe service name {name:?}");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn spec_snapshot_covers_every_resolved_token_variable() {
    let dir = temp("snapshot");
    let t = crate::util::random_hex(4).unwrap().to_ascii_uppercase();
    let (b, c, d) = (
        format!("SNAP_TOKEN_B_{t}"),
        format!("SNAP_TOKEN_C_{t}"),
        format!("SNAP_TOKEN_D_UNSET_{t}"),
    );
    let auth = format!("version: 1\noutbound_peers:\n  - {{id: B, token_env: {b}}}\n  - {{id: C, token_env: {c}}}\ninbound_peers:\n  - {{id: D, enabled: false, token_envs: [{d}], allowed_targets: [db]}}\n");
    let cfg = "node: {id: A}\nauth: {credentials_file: auth.yaml}\npeers:\n  - id: B\n    expected_node_id: B\n    credential_ref: B\n    endpoints: [{id: e1, url: \"http://127.0.0.1:18080\", priority: 1}]\nlisteners: [{id: l1, listen: \"127.0.0.1:0\", peer: B, target: db}]\n";
    fs::write(dir.join("auth.yaml"), auth).unwrap();
    let path = dir.join("peer.yaml");
    fs::write(&path, cfg).unwrap();
    env::set_var(&b, "token-b-0123456789abcdef");
    env::set_var(&c, "token-c-0123456789abcdef");
    let p = prepare(&Options {
        name: "snap".into(),
        config: path.clone(),
        executable: Some(std::env::current_exe().unwrap()),
        account: None,
        log_level: "info".into(),
        log_format: "json".into(),
        start: false,
    })
    .unwrap_or_else(|e| panic!("{}", e.message));
    assert_eq!(
        p.environment_names.len(),
        2,
        "snapshot names: {:?}",
        p.environment_names
    );
    save_environment(&p, None).unwrap_or_else(|e| panic!("{}", e.message));
    env::remove_var(&b);
    env::remove_var(&c);
    load_environment(p.environment_file.as_deref().unwrap())
        .unwrap_or_else(|e| panic!("{}", e.message));
    config::load(&path)
        .unwrap_or_else(|e| panic!("installed service cannot load its config: {}", e.message));
    env::remove_var(&b);
    env::remove_var(&c);
    fs::remove_dir_all(dir).ok();
}

#[cfg(target_os = "linux")]
#[test]
fn spec_prepare_does_not_write_and_hides_credentials() {
    use std::os::unix::fs::PermissionsExt;
    let (o, dir) = service_fixture("hides");
    let secret_name = format!(
        "SERVICE_TEST_SECRET_{}",
        crate::util::random_hex(4).unwrap().to_ascii_uppercase()
    );
    env::set_var(&secret_name, "private-captured-credential");
    let b = fs::read_to_string(&o.config).unwrap();
    let text = b.replace(
        "token_file: peer.token",
        &format!("token_env: {secret_name}"),
    );
    assert_ne!(text, b, "fixture did not replace token source");
    fs::write(&o.config, text).unwrap();
    let mut p = prepare(&o).unwrap_or_else(|e| panic!("{}", e.message));
    let env_file = p
        .environment_file
        .clone()
        .expect("credential environment was not captured");
    assert_eq!(
        p.environment_names.len(),
        1,
        "credential environment was not captured"
    );
    let serialized = crate::cli::service_plan_json(&p);
    assert!(
        !serialized.contains("private-captured-credential"),
        "preview leaked a secret"
    );
    assert!(!env_file.exists(), "preflight wrote credentials");
    assert!(
        save_environment(&p, None).unwrap_or_else(|e| panic!("{}", e.message)),
        "snapshot not created"
    );
    let mode = fs::metadata(&env_file).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "snapshot permissions");
    env::remove_var(&secret_name);
    load_environment(&env_file).unwrap_or_else(|e| panic!("{}", e.message));
    assert_eq!(
        env::var(&secret_name).as_deref(),
        Ok("private-captured-credential"),
        "snapshot did not restore referenced credential"
    );
    env::set_var(&secret_name, "different-current-value");
    load_environment(&env_file).unwrap();
    assert_eq!(
        env::var(&secret_name).as_deref(),
        Ok("different-current-value"),
        "snapshot overrode a variable already set in the process environment"
    );
    assert!(
        !save_environment(&p, None).unwrap(),
        "same snapshot should be reused"
    );
    p.environment.insert(secret_name.clone(), "changed".into());
    assert!(
        save_environment(&p, None).is_err(),
        "different snapshot overwritten"
    );
    env::remove_var(&secret_name);
    fs::remove_dir_all(dir).ok();
}

#[cfg(target_os = "linux")]
#[test]
fn spec_systemd_install_rollback_duplicate_and_uninstall() {
    use std::cell::RefCell;
    for failed in ["", "daemon-reload", "enable", "start"] {
        let (mut o, dir) = service_fixture("install");
        o.start = failed == "start";
        o.account = Some(current_uid().to_string());
        let mut p = prepare(&o).unwrap_or_else(|e| panic!("{failed}: {}", e.message));
        let account = lookup_account(&p.account).unwrap();
        p.environment_file = Some(p.working_directory.join("test-env.json"));
        p.environment = BTreeMap::from([(
            "SERVICE_TEST_TOKEN".to_string(),
            "private-fixture".to_string(),
        )]);
        let calls = RefCell::new(Vec::<String>::new());
        let manager_dir = temp("units");
        let result = install_at(&manager_dir, &p, Some(&account), |args| {
            calls.borrow_mut().push(args.join(" "));
            if args[0] == failed {
                Err(service_error("injected systemctl failure"))
            } else {
                Ok(())
            }
        });
        assert_eq!(
            result.is_ok(),
            failed.is_empty(),
            "failure={failed} error={:?}",
            result.err().map(|e| e.message)
        );
        let unit = manager_dir.join(format!("{}.service", p.name));
        let env_file = p.environment_file.clone().unwrap();
        if failed == "daemon-reload" || failed == "enable" {
            assert!(
                !unit.exists() && !env_file.exists(),
                "failed registration left unit/credentials behind"
            );
            fs::remove_dir_all(dir).ok();
            fs::remove_dir_all(manager_dir).ok();
            continue;
        }
        assert!(
            unit.exists() && env_file.exists(),
            "successful registration was not retained"
        );
        let before = calls.borrow().len();
        assert!(
            install_at(&manager_dir, &p, Some(&account), |args| {
                calls.borrow_mut().push(args.join(" "));
                Ok(())
            })
            .is_err()
                && calls.borrow().len() == before,
            "duplicate installation mutated existing service"
        );
        uninstall_at(&manager_dir, &p.name, |args| {
            calls.borrow_mut().push(args.join(" "));
            Ok(())
        })
        .unwrap_or_else(|e| panic!("{}", e.message));
        assert!(!unit.exists(), "unit not removed");
        assert!(o.config.exists(), "uninstall deleted config");
        assert!(env_file.exists(), "uninstall deleted credentials");
        fs::remove_dir_all(dir).ok();
        fs::remove_dir_all(manager_dir).ok();
    }
}

#[cfg(target_os = "linux")]
#[test]
fn spec_readiness_notification() {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram};
    let dir = temp("notify");
    let fs_path = dir.join("dbbridge-notify.sock");
    let abstract_name = format!("dbbridge-notify-{}", crate::util::random_hex(6).unwrap());
    let fs_socket = UnixDatagram::bind(&fs_path).unwrap();
    let abstract_socket =
        UnixDatagram::bind_addr(&SocketAddr::from_abstract_name(abstract_name.as_bytes()).unwrap())
            .unwrap();
    for (path, socket) in [
        (fs_path.to_string_lossy().into_owned(), &fs_socket),
        (format!("@{abstract_name}"), &abstract_socket),
    ] {
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        notify_to(&path, "READY=1").unwrap_or_else(|e| panic!("{path}: {e}"));
        let mut buf = [0u8; 64];
        let n = socket.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"READY=1", "notification to {path}");
    }
    // Foreground mode: nothing is sent anywhere and no error is reported.
    notify_to("", "READY=1").unwrap();
    fs_socket.set_nonblocking(true).unwrap();
    abstract_socket.set_nonblocking(true).unwrap();
    let mut buf = [0u8; 8];
    assert!(fs_socket.recv(&mut buf).is_err());
    assert!(abstract_socket.recv(&mut buf).is_err());
    fs::remove_dir_all(dir).ok();
}

#[cfg(target_os = "linux")]
#[test]
fn spec_unit_accepted_by_systemd_analyze() {
    let Some(tool) = ["/usr/bin/systemd-analyze", "/bin/systemd-analyze"]
        .into_iter()
        .map(Path::new)
        .find(|p| p.exists())
    else {
        eprintln!("systemd-analyze not installed");
        return;
    };
    let root = temp("analyze");
    let dir = root.join("paths $literal% with space");
    fs::create_dir(&dir).unwrap();
    let unit = systemd_unit(
        "dbbridge-verify",
        &current_uid().to_string(),
        Path::new("/bin/true"),
        &dir.join("peer.yaml"),
        "info",
        "text",
        &dir,
        Duration::from_secs(30),
        200,
        false,
        None,
        &[],
    )
    .unwrap();
    let units = temp("analyze-unit");
    let path = units.join("dbbridge-verify.service");
    fs::write(&path, unit).unwrap();
    let output = Command::new(tool)
        .arg("verify")
        .arg("--man=no")
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "systemd rejected generated unit: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    fs::remove_dir_all(root).ok();
    fs::remove_dir_all(units).ok();
}
