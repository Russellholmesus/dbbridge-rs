use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=DBBRIDGE_VERSION");
    println!("cargo:rerun-if-env-changed=DBBRIDGE_COMMIT");
    println!("cargo:rerun-if-env-changed=DBBRIDGE_BUILD_DATE");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");

    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let version = Command::new(rustc)
        .arg("--version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|output| {
            let mut parts = output.split_whitespace();
            let compiler = parts.next()?;
            let version = parts.next()?;
            Some(format!("{compiler} {version}"))
        })
        .unwrap_or_else(|| "rustc unknown".to_string());
    println!("cargo:rustc-env=DBBRIDGE_RUSTC_VERSION={version}");

    // Commit: an injected DBBRIDGE_COMMIT wins (option_env! in main.rs reads
    // it directly); otherwise ask git, and leave it unset ("unknown") when the
    // source is not a git checkout (e.g. built from `git archive`).
    if env::var_os("DBBRIDGE_COMMIT").is_none() {
        if let Some(commit) = git(&["rev-parse", "--short=12", "HEAD"]) {
            println!("cargo:rustc-env=DBBRIDGE_COMMIT={commit}");
            rerun_on_git_head();
        }
    }

    // Build date: an injected DBBRIDGE_BUILD_DATE wins; otherwise
    // SOURCE_DATE_EPOCH (reproducible builds), else the current UTC time.
    if env::var_os("DBBRIDGE_BUILD_DATE").is_none() {
        let secs = env::var("SOURCE_DATE_EPOCH")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .or_else(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .ok()
                    .map(|d| d.as_secs())
            });
        if let Some(secs) = secs {
            println!("cargo:rustc-env=DBBRIDGE_BUILD_DATE={}", rfc3339_utc(secs));
        }
    }
}

fn git(args: &[&str]) -> Option<String> {
    let dir = env::var_os("CARGO_MANIFEST_DIR").map(PathBuf::from)?;
    let out = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .ok()
        .filter(|o| o.status.success())?;
    let s = String::from_utf8(out.stdout).ok()?;
    Some(s.trim().to_string())
}

/// Rebuild when HEAD moves (new commit, branch switch), also in worktrees.
fn rerun_on_git_head() {
    let abs = |p: String| -> PathBuf {
        let p = PathBuf::from(p);
        if p.is_absolute() {
            p
        } else {
            env::var_os("CARGO_MANIFEST_DIR")
                .map(PathBuf::from)
                .unwrap_or_default()
                .join(p)
        }
    };
    let watch = |p: &Path| {
        if p.exists() {
            println!("cargo:rerun-if-changed={}", p.display());
        }
    };
    if let Some(git_dir) = git(&["rev-parse", "--git-dir"]).map(abs) {
        watch(&git_dir.join("HEAD"));
    }
    if let Some(common) = git(&["rev-parse", "--git-common-dir"]).map(abs) {
        watch(&common.join("packed-refs"));
        if let Some(head_ref) = git(&["symbolic-ref", "-q", "HEAD"]) {
            watch(&common.join(head_ref));
        }
    }
}

/// Seconds since the Unix epoch as `YYYY-MM-DDTHH:MM:SSZ`.
fn rfc3339_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3_600,
        (rem % 3_600) / 60,
        rem % 60
    )
}
