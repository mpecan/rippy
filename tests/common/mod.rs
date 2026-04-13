#![allow(dead_code, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;

use rippy_cli::analyzer::Analyzer;
use rippy_cli::config::Config;
use rippy_cli::environment::Environment;

pub fn rippy_binary() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_BIN_EXE_rippy"));
    if !path.exists() {
        path = PathBuf::from("target/debug/rippy");
    }
    path
}

fn run_rippy_cmd(
    json: &str,
    mode: &str,
    extra_args: &[&str],
    dir: Option<&Path>,
) -> (String, String, i32) {
    let mut cmd = Command::new(rippy_binary());
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

// ---------------------------------------------------------------------------
// Library-level test utilities (no subprocess, used by catalog & proptest)
// ---------------------------------------------------------------------------

static TEST_DIR: LazyLock<PathBuf> = LazyLock::new(|| {
    let dir = std::env::temp_dir().join("rippy-test-shared");
    std::fs::create_dir_all(&dir).ok();
    dir
});

/// Stdlib config with no home directory — isolated from developer machine.
/// Parsed once and reused across all tests in a process.
pub static ISOLATED_CONFIG: LazyLock<Config> =
    LazyLock::new(|| Config::load_with_home(&TEST_DIR, None, None).expect("stdlib config loads"));

/// Build a fresh `Analyzer` with stdlib rules, fully isolated from developer
/// config (no `~/.rippy/`, no `~/.claude/`).
pub fn isolated_analyzer() -> Analyzer {
    let env = Environment::for_test(TEST_DIR.clone());
    Analyzer::from_env(ISOLATED_CONFIG.clone(), env).expect("Analyzer::from_env succeeds")
}
