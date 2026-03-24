#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

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
