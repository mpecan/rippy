#![allow(clippy::unwrap_used)]

mod common;
use common::{run_rippy, run_rippy_with_stderr};

// MCP tests

#[test]
fn mcp_tool_asks_by_default() {
    let json = r#"{"tool_name":"mcp__server__tool","tool_input":{}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
}

// Error handling

/// A terminal error on the hook path must not answer with a bare
/// `{"error":...}` + exit 1: Claude Code reads that as a non-blocking hook
/// failure and runs the command un-gated (#182).
#[test]
fn malformed_json_asks_instead_of_erroring() {
    let (stdout, code) = run_rippy("not json", "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
    assert!(v["error"].as_str().is_none(), "{stdout}");
}

// Verbose mode tests

#[test]
fn verbose_traces_to_stderr() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#;
    let (stdout, stderr, code) = run_rippy_with_stderr(json, "claude", &["--verbose"]);
    assert_eq!(code, 0);
    // stdout is still valid JSON
    let _v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    // stderr contains trace lines
    assert!(
        stderr.contains("[rippy]"),
        "stderr should contain [rippy] trace lines"
    );
    assert!(
        stderr.contains("command:"),
        "stderr should trace the command"
    );
}

#[test]
fn verbose_handler_trace() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"git push origin main"}}"#;
    let (_stdout, stderr, code) = run_rippy_with_stderr(json, "claude", &["--verbose"]);
    assert_eq!(code, 0);
    assert!(
        stderr.contains("[rippy] handler:"),
        "stderr should show handler decision"
    );
}

// Resource limit tests (Issue #3)

#[test]
fn oversized_input_asks_instead_of_erroring() {
    // Send > 1MB of input
    let big_json = format!(
        r#"{{"tool_name":"Bash","tool_input":{{"command":"echo {}"}}}}"#,
        "x".repeat(1_100_000)
    );
    let (stdout, code) = run_rippy(&big_json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let out = &v["hookSpecificOutput"];
    assert_eq!(out["permissionDecision"], "ask");
    assert!(
        out["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("limit"),
        "{stdout}"
    );
}

// Fail-closed on unparseable command (Issue #150): a valid payload carrying a
// command rable cannot parse must NOT exit 1 (non-blocking for Claude -> the
// command runs un-gated). The verdict must be a fail-closed Ask on a blocking
// exit code for every mode.

const UNPARSEABLE_PAYLOAD: &str =
    r#"{"tool_name":"Bash","tool_input":{"command":"echo $( ( unbalanced"}}"#;

#[test]
fn claude_unparseable_command_asks_not_fail_open() {
    let (stdout, code) = run_rippy(UNPARSEABLE_PAYLOAD, "claude", &[]);
    assert_ne!(code, 1, "exit 1 is non-blocking for Claude (fail-open)");
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
}

#[test]
fn gemini_unparseable_command_denies_not_fail_open() {
    let (stdout, code) = run_rippy(UNPARSEABLE_PAYLOAD, "gemini", &[]);
    assert_ne!(code, 1);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    // Gemini has no "ask"; an uncertain Ask maps to deny (blocking).
    assert_eq!(v["decision"], "deny");
}

#[test]
fn cursor_unparseable_command_asks_not_fail_open() {
    let (stdout, code) = run_rippy(UNPARSEABLE_PAYLOAD, "cursor", &[]);
    assert_ne!(code, 1);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["permission"], "ask");
}

// Logging integration test (Issue #2)

#[test]
fn log_file_receives_entry() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("rippy.log");
    let config_path = dir.path().join("config");
    std::fs::write(&config_path, format!("set log {}", log_path.display())).unwrap();

    let json = r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#;
    let (_stdout, code) = run_rippy(json, "claude", &["--config", config_path.to_str().unwrap()]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&log_path).unwrap();
    let entry: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
    assert_eq!(entry["decision"], "allow");
    assert_eq!(entry["command"], "ls");
}
