#![allow(clippy::unwrap_used)]

mod common;
use common::run_rippy;

// ---- Inspect integration tests ----

#[test]
fn inspect_list_with_config() {
    let dir = tempfile::TempDir::new().unwrap();
    let config = dir.path().join("test.toml");
    std::fs::write(
        &config,
        "[[rules]]\naction = \"deny\"\npattern = \"rm -rf *\"\nmessage = \"use trash\"\n",
    )
    .unwrap();

    let output = std::process::Command::new(common::rippy_binary())
        .args(["inspect", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("deny"));
    assert!(stdout.contains("rm -rf *"));
    assert!(stdout.contains("Handlers:"));
    assert!(stdout.contains("Simple safe:"));
}

#[test]
fn inspect_trace_safe_command() {
    let output = std::process::Command::new(common::rippy_binary())
        .args(["inspect", "cat /tmp/file"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("ALLOW"));
    assert!(stdout.contains("Allowlist"));
}

#[test]
fn inspect_trace_with_config_rule() {
    let dir = tempfile::TempDir::new().unwrap();
    let config = dir.path().join("test.toml");
    std::fs::write(
        &config,
        "[[rules]]\naction = \"deny\"\npattern = \"echo evil\"\nmessage = \"no evil allowed\"\n",
    )
    .unwrap();

    let output = std::process::Command::new(common::rippy_binary())
        .args(["inspect", "--config"])
        .arg(&config)
        .arg("echo evil")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("DENY"));
    assert!(stdout.contains("no evil allowed"));
}

#[test]
fn inspect_json_output() {
    let output = std::process::Command::new(common::rippy_binary())
        .args(["inspect", "--json", "cat /tmp/file"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["decision"], "allow");
    assert!(parsed["steps"].is_array());
}

#[test]
fn inspect_list_json_output() {
    let dir = tempfile::TempDir::new().unwrap();
    let config = dir.path().join("test.toml");
    std::fs::write(&config, "[[rules]]\naction = \"allow\"\npattern = \"ls\"\n").unwrap();

    let output = std::process::Command::new(common::rippy_binary())
        .args(["inspect", "--json", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(parsed["config_sources"].is_array());
    assert!(parsed["handler_count"].is_number());
    assert!(parsed["simple_safe_count"].is_number());
}

// ---- Stats integration tests ----

#[test]
fn stats_json_from_populated_db() {
    let dir = tempfile::TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");

    // Populate the DB directly.
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         CREATE TABLE decisions (
             id INTEGER PRIMARY KEY,
             timestamp TEXT NOT NULL DEFAULT (datetime('now')),
             session_id TEXT, mode TEXT, tool_name TEXT NOT NULL,
             command TEXT, decision TEXT NOT NULL, reason TEXT, payload_json TEXT
         );
         INSERT INTO decisions (tool_name, command, decision, reason) VALUES ('Bash', 'git status', 'allow', 'safe');
         INSERT INTO decisions (tool_name, command, decision, reason) VALUES ('Bash', 'git push', 'ask', 'review');
         INSERT INTO decisions (tool_name, command, decision, reason) VALUES ('Bash', 'rm -rf /', 'deny', 'dangerous');",
    )
    .unwrap();
    drop(conn);

    let output = std::process::Command::new(common::rippy_binary())
        .args(["stats", "--json", "--db"])
        .arg(&db_path)
        .output()
        .unwrap();
    assert!(output.status.success(), "stats failed: {:?}", output.status);
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["counts"]["total"], 3);
    assert_eq!(parsed["counts"]["allow"], 1);
    assert_eq!(parsed["counts"]["ask"], 1);
    assert_eq!(parsed["counts"]["deny"], 1);
}

// ---- Stdlib regression tests ----

#[test]
fn stdlib_cargo_test_allowed() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"cargo test --release"}}"#;
    let (_, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
}

#[test]
fn stdlib_cargo_run_asks() {
    let dir = tempfile::TempDir::new().unwrap();
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"cargo run"}}"#;
    let (_, code) = common::run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 2);
}

#[test]
fn stdlib_rm_asks() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/test"}}"#;
    let (_, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 2);
}

#[test]
fn stdlib_sudo_asks() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"sudo apt install foo"}}"#;
    let (_, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 2);
}

#[test]
fn init_stdout_prints_stdlib() {
    let output = std::process::Command::new(common::rippy_binary())
        .args(["init", "--stdout"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("[[rules]]"));
    assert!(stdout.contains("cargo"));
}

#[test]
fn init_creates_config_file() {
    let dir = tempfile::TempDir::new().unwrap();
    let output = std::process::Command::new(common::rippy_binary())
        .args(["init"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());

    let content = std::fs::read_to_string(dir.path().join(".rippy.toml")).unwrap();
    // Non-interactive init defaults to develop package
    assert!(content.contains("[settings]"));
    assert!(content.contains("package = \"develop\""));
}

#[test]
fn init_with_package_flag() {
    let dir = tempfile::TempDir::new().unwrap();
    let output = std::process::Command::new(common::rippy_binary())
        .args(["init", "--package", "review"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());

    let content = std::fs::read_to_string(dir.path().join(".rippy.toml")).unwrap();
    assert!(content.contains("package = \"review\""));
}

#[test]
fn init_stdout_still_works() {
    let output = std::process::Command::new(common::rippy_binary())
        .args(["init", "--stdout"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("[[rules]]"));
    assert!(stdout.contains("cargo"));
}

#[test]
fn init_refuses_existing() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(dir.path().join(".rippy.toml"), "existing").unwrap();
    let output = std::process::Command::new(common::rippy_binary())
        .args(["init"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
}

// ---- Flag discovery tests ----

#[test]
fn discover_finds_curl_flags() {
    let home = tempfile::TempDir::new().unwrap();
    let output = std::process::Command::new(common::rippy_binary())
        .args(["discover", "curl", "--json"])
        .env("HOME", home.path())
        .output()
        .unwrap();
    // curl might not be installed in CI, so just check exit code 0 or graceful error
    if output.status.success() {
        let stdout = String::from_utf8(output.stdout).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
        let arr = parsed.as_array().unwrap();
        // curl has many flag aliases
        assert!(!arr.is_empty());
    }
}

#[test]
fn discover_without_args_errors() {
    let output = std::process::Command::new(common::rippy_binary())
        .args(["discover"])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

// ---- Session file suggest tests ----

#[test]
fn suggest_from_session_file() {
    let dir = tempfile::TempDir::new().unwrap();
    let session_file = dir.path().join("test-session.jsonl");
    // Write a sample session JSONL with Bash tool calls.
    let jsonl = [
        r#"{"type":"assistant","message":{"content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"git status"}}]}}"#,
        r#"{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"t1","content":"ok"}]}}"#,
        r#"{"type":"assistant","message":{"content":[{"type":"tool_use","id":"t2","name":"Bash","input":{"command":"git status"}}]}}"#,
        r#"{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"t2","content":"ok"}]}}"#,
        r#"{"type":"assistant","message":{"content":[{"type":"tool_use","id":"t3","name":"Bash","input":{"command":"git status"}}]}}"#,
        r#"{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"t3","content":"ok"}]}}"#,
        r#"{"type":"assistant","message":{"content":[{"type":"tool_use","id":"t4","name":"Bash","input":{"command":"rm -rf /"}}]}}"#,
        r#"{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"t4","is_error":true,"content":"denied"}]}}"#,
        r#"{"type":"assistant","message":{"content":[{"type":"tool_use","id":"t5","name":"Bash","input":{"command":"rm -rf /"}}]}}"#,
        r#"{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"t5","is_error":true,"content":"denied"}]}}"#,
        r#"{"type":"assistant","message":{"content":[{"type":"tool_use","id":"t6","name":"Bash","input":{"command":"rm -rf /"}}]}}"#,
        r#"{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"t6","is_error":true,"content":"denied"}]}}"#,
    ];
    std::fs::write(&session_file, jsonl.join("\n")).unwrap();

    let output = std::process::Command::new(common::rippy_binary())
        .args([
            "suggest",
            "--session-file",
            session_file.to_str().unwrap(),
            "--json",
            "--min-count",
            "2",
        ])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let suggestions: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let arr = suggestions.as_array().unwrap();
    assert!(arr.len() >= 2);

    // Should have allow and deny suggestions
    let actions: Vec<&str> = arr.iter().filter_map(|s| s["action"].as_str()).collect();
    assert!(actions.contains(&"allow"));
    assert!(actions.contains(&"deny"));
}

// ---- Debug command tests ----

#[test]
fn debug_shows_allow_verdict() {
    let output = std::process::Command::new(common::rippy_binary())
        .args(["debug", "git status"])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code().unwrap_or(-1),
        0,
        "debug always exits 0"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ALLOW"), "should show ALLOW, got: {stdout}");
    assert!(stdout.contains("Config sources:"), "should show sources");
    assert!(stdout.contains("Decision trace:"), "should show trace");
}

#[test]
fn debug_shows_deny_with_reason() {
    let dir = tempfile::TempDir::new().unwrap();
    let config_path = dir.path().join("test.toml");
    std::fs::write(
        &config_path,
        "[[rules]]\naction = \"deny\"\npattern = \"rm -rf *\"\nmessage = \"use trash\"\n",
    )
    .unwrap();
    let config_str = config_path.to_str().unwrap();
    let output = std::process::Command::new(common::rippy_binary())
        .args(["debug", "rm -rf /tmp", "--config", config_str])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("DENY"), "should show DENY, got: {stdout}");
    assert!(
        stdout.contains("use trash"),
        "should show reason, got: {stdout}"
    );
}

#[test]
fn debug_json_output_valid() {
    let output = std::process::Command::new(common::rippy_binary())
        .args(["debug", "ls", "--json"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["decision"], "allow");
    assert!(v["sources"].is_array());
    assert!(v["steps"].is_array());
}

#[test]
fn debug_shows_config_source_override() {
    let dir = tempfile::TempDir::new().unwrap();
    let config_path = dir.path().join("custom.toml");
    std::fs::write(&config_path, "").unwrap();
    let config_str = config_path.to_str().unwrap();
    let output = std::process::Command::new(common::rippy_binary())
        .args(["debug", "echo hello", "--config", config_str])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("override"),
        "should show override, got: {stdout}"
    );
}

#[test]
fn debug_unknown_command_shows_ask() {
    let output = std::process::Command::new(common::rippy_binary())
        .args(["debug", "totally_unknown_command_xyz"])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code().unwrap_or(-1),
        0,
        "debug always exits 0"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("ASK"),
        "unknown cmd should show ASK, got: {stdout}"
    );
}

#[test]
fn debug_shows_resolved_command_for_arithmetic() {
    let output = std::process::Command::new(common::rippy_binary())
        .args(["debug", "echo $((2+2))"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Resolved: echo 4"),
        "should show resolved arithmetic, got: {stdout}"
    );
    assert!(
        stdout.contains("ALLOW"),
        "resolved arithmetic should allow, got: {stdout}"
    );
}

#[test]
fn debug_json_includes_resolved_field() {
    let output = std::process::Command::new(common::rippy_binary())
        .args(["debug", "echo $'\\x41'", "--json"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["resolved"], "echo A");
    assert_eq!(v["decision"], "allow");
}
