//! The hook path must never answer with a bare error (#182): an agent reads a
//! non-blocking hook failure as an auto-approval, so a malformed payload has to
//! come back as a forced Ask in the caller's own wire format. Subcommands are
//! read by humans and keep the plain error path.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::process::Command;

use common::{rippy_binary, run_rippy};

#[test]
fn malformed_payload_asks_in_gemini_and_cursor_modes() {
    let (gemini, _) = run_rippy("not json at all", "gemini", &[]);
    let json: serde_json::Value = serde_json::from_str(&gemini).expect("valid gemini JSON");
    assert_eq!(json["decision"], "deny", "{gemini}");

    let (cursor, _) = run_rippy("{ truncated", "cursor", &[]);
    let json: serde_json::Value = serde_json::from_str(&cursor).expect("valid cursor JSON");
    assert_eq!(json["permission"], "ask", "{cursor}");
}

#[test]
fn empty_payload_asks_rather_than_erroring() {
    let (stdout, code) = run_rippy("", "claude", &[]);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid claude JSON");
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"], "ask",
        "{stdout}"
    );
    assert_eq!(code, 0);
    assert!(json.get("error").is_none(), "{stdout}");
}

#[test]
fn subcommands_still_report_real_errors() {
    let out = Command::new(rippy_binary())
        .args(["inspect", "--config", "/nonexistent/rippy.toml", "ls"])
        .output()
        .expect("spawn rippy inspect");
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\"error\""), "{stdout}");
}

#[test]
fn unknown_subcommand_flag_still_reports_usage() {
    let out = Command::new(rippy_binary())
        .args(["list", "--definitely-not-a-flag"])
        .output()
        .expect("spawn rippy list");
    assert_eq!(out.status.code(), Some(2));
}
