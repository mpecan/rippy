#![allow(clippy::unwrap_used)]

mod common;
use common::{run_rippy, run_rippy_with_stderr};

// ---- MCP tests ----

#[test]
fn mcp_tool_asks_by_default() {
    let json = r#"{"tool_name":"mcp__server__tool","tool_input":{}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
}

// ---- Error handling ----

#[test]
fn malformed_json_returns_error() {
    let (stdout, code) = run_rippy("not json", "claude", &[]);
    assert_eq!(code, 1);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(v["error"].as_str().is_some());
}

// ---- Verbose mode tests ----

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
    assert_eq!(code, 2);
    assert!(
        stderr.contains("[rippy] handler:"),
        "stderr should show handler decision"
    );
}

// ---- Resource limit tests (Issue #3) ----

#[test]
fn oversized_input_returns_error() {
    // Send > 1MB of input
    let big_json = format!(
        r#"{{"tool_name":"Bash","tool_input":{{"command":"echo {}"}}}}"#,
        "x".repeat(1_100_000)
    );
    let (stdout, code) = run_rippy(&big_json, "claude", &[]);
    assert_eq!(code, 1);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(v["error"].as_str().unwrap().contains("limit"));
}

// ---- Logging integration test (Issue #2) ----

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
