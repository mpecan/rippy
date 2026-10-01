#![allow(dead_code, unused_imports, clippy::expect_used, clippy::panic)]

pub mod catalog;
pub mod surfaces;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::Duration;

/// Isolated homes older than this belong to finished runs and are swept.
const STALE_HOME_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// An empty `$HOME` shared by every spawn in this test process, at
/// `CARGO_TARGET_TMPDIR/isolated-home/<test binary>-<pid>`.
///
/// Keying by pid means two concurrent runs of the same test binary (two
/// `cargo test`s, or nextest's process-per-test) never share or wipe each
/// other's home. Cargo never cleans `CARGO_TARGET_TMPDIR`, so each process
/// sweeps sibling homes untouched for a day; `cargo clean` removes the rest.
///
/// Treat this home as read-only: tests run in parallel against it, and rippy
/// writes files such as `trusted.json` non-atomically. A test that makes rippy
/// write under `$HOME` (`trust --yes`, `init`, `--global` edits, tracking)
/// must override `HOME` with its own temp dir.
pub fn isolated_home() -> &'static Path {
    static HOME: OnceLock<PathBuf> = OnceLock::new();
    HOME.get_or_init(|| {
        let exe = std::env::current_exe().expect("test binary path");
        let stem = exe.file_stem().expect("test binary name").to_string_lossy();
        let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("isolated-home");
        sweep_stale_homes(&root);
        let home = root.join(format!("{stem}-{}", std::process::id()));
        // A leftover from an earlier process that had this pid.
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).expect("create isolated HOME");
        home
    })
}

fn sweep_stale_homes(root: &Path) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let stale = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .is_some_and(|age| age > STALE_HOME_AGE);
        if stale {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
}

/// The only way a test should spawn `rippy`: the developer's own `$HOME`
/// config (`tracking = "on"`, `[jev]`, trusted.json) must never apply to, or
/// be written by, a test run. A test needing its own home overrides `HOME`
/// with a real directory; never clear or empty it, or rippy falls back to the
/// passwd home (see `tests/test_isolation.rs`).
pub fn rippy_command() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_rippy"));
    cmd.env("HOME", isolated_home())
        .env_remove("RIPPY_CONFIG")
        .env_remove("DIPPY_CONFIG");
    cmd
}

fn run_rippy_cmd(
    json: &str,
    mode: &str,
    extra_args: &[&str],
    dir: Option<&Path>,
) -> (String, String, i32) {
    let mut cmd = rippy_command();
    cmd.arg("--mode").arg(mode);
    for arg in extra_args {
        cmd.arg(arg);
    }
    if let Some(d) = dir {
        cmd.current_dir(d);
    }
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().unwrap();
    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().unwrap();
        // Ignore broken pipe — child may reject oversized input
        let _ = stdin.write_all(json.as_bytes());
    }
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);
    (stdout, stderr, code)
}

pub fn run_rippy_with_stderr(json: &str, mode: &str, extra_args: &[&str]) -> (String, String, i32) {
    run_rippy_cmd(json, mode, extra_args, None)
}

pub fn run_rippy(json: &str, mode: &str, extra_args: &[&str]) -> (String, i32) {
    let (stdout, _, code) = run_rippy_cmd(json, mode, extra_args, None);
    (stdout, code)
}

pub fn run_rippy_in_dir(json: &str, mode: &str, dir: &Path) -> (String, i32) {
    let (stdout, _, code) = run_rippy_cmd(json, mode, &[], Some(dir));
    (stdout, code)
}

pub fn run_rippy_in_dir_with_args(
    json: &str,
    mode: &str,
    dir: &Path,
    extra_args: &[&str],
) -> (String, i32) {
    let (stdout, _, code) = run_rippy_cmd(json, mode, extra_args, Some(dir));
    (stdout, code)
}

#[path = "analyzer.rs"]
mod analyzer;

pub use analyzer::{ISOLATED_CONFIG, isolated_analyzer};
