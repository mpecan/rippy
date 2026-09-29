//! The default build has no Jev support, and says so rather than silently
//! ignoring an enabled `[jev]` section (docs/jev.md#configuration).

#![cfg(not(feature = "jev"))]
#![allow(clippy::unwrap_used)]

mod common;

use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn version_has_no_jev_suffix() {
    let out = Command::new(common::rippy_binary())
        .arg("--version")
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&out.stdout).contains("+jev"));
}

#[test]
fn an_enabled_jev_section_warns_and_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("jev.toml");
    std::fs::write(&config, "[jev]\nenabled = true\n").unwrap();
    let mut child = Command::new(common::rippy_binary())
        .args(["--mode", "claude", "--config"])
        .arg(&config)
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .env_remove("RIPPY_CONFIG")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(br#"{"tool_name":"Bash","tool_input":{"command":"rippy-default-cli list"}}"#)
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"permissionDecision\":\"ask\""),
        "{stdout}"
    );
    assert!(
        stdout.contains("rippy-default-cli (unknown command)"),
        "{stdout}"
    );
    assert!(!stdout.contains("jev"), "{stdout}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("this rippy build has no Jev support"));
}
