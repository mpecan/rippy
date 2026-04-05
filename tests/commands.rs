#![allow(clippy::unwrap_used)]

mod common;
use common::{run_rippy, run_rippy_in_dir};

// ---- Complex commands ----

#[test]
fn bash_c_recurses() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"bash -c 'ls -la'"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn wrapper_time_git_status() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"time git status"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn redirect_to_dev_null_safe() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"echo foo > /dev/null"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn redirect_to_file_asks() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"echo foo > /tmp/output.txt"}}"#;
    let (_stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 2);
}

// ---- Heredoc tests ----

#[test]
fn heredoc_safe_allows() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"cat <<EOF\nhello\nEOF"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

// ---- rippy allow/deny/ask subcommand tests ----

#[test]
fn allow_command_creates_toml_rule() {
    let dir = tempfile::TempDir::new().unwrap();
    let output = std::process::Command::new(common::rippy_binary())
        .args(["allow", "git status"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());

    let content = std::fs::read_to_string(dir.path().join(".rippy.toml")).unwrap();
    assert!(content.contains("action = \"allow\""));
    assert!(content.contains("pattern = \"git status\""));
}

#[test]
fn deny_command_with_message() {
    let dir = tempfile::TempDir::new().unwrap();
    let output = std::process::Command::new(common::rippy_binary())
        .args(["deny", "rm -rf *", "use trash instead"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());

    let content = std::fs::read_to_string(dir.path().join(".rippy.toml")).unwrap();
    assert!(content.contains("action = \"deny\""));
    assert!(content.contains("message = \"use trash instead\""));
}

#[test]
fn ask_command_creates_toml_rule() {
    let dir = tempfile::TempDir::new().unwrap();
    let output = std::process::Command::new(common::rippy_binary())
        .args(["ask", "docker run *"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());

    let content = std::fs::read_to_string(dir.path().join(".rippy.toml")).unwrap();
    assert!(content.contains("action = \"ask\""));
    assert!(content.contains("pattern = \"docker run *\""));
}

#[test]
fn allow_global_writes_to_home_config() {
    let dir = tempfile::TempDir::new().unwrap();
    let output = std::process::Command::new(common::rippy_binary())
        .args(["allow", "git status", "--global"])
        .env("HOME", dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());

    let content = std::fs::read_to_string(dir.path().join(".rippy/config.toml")).unwrap();
    assert!(content.contains("action = \"allow\""));
    assert!(content.contains("pattern = \"git status\""));
}

#[test]
fn suggest_from_command_output() {
    let dir = tempfile::TempDir::new().unwrap();
    let output = std::process::Command::new(common::rippy_binary())
        .args(["suggest", "--from-command", "git push origin main"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("git push origin main"));
    assert!(stdout.contains("git push *"));
    assert!(stdout.contains("git *"));

    // Suggest should NOT create a config file
    assert!(!dir.path().join(".rippy.toml").exists());
}

#[test]
fn suggest_from_db_json() {
    let dir = tempfile::TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");

    // Populate a tracking DB directly using rusqlite.
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         CREATE TABLE decisions (
             id INTEGER PRIMARY KEY,
             timestamp TEXT NOT NULL DEFAULT (datetime('now')),
             session_id TEXT, mode TEXT, tool_name TEXT NOT NULL,
             command TEXT, decision TEXT NOT NULL, reason TEXT, payload_json TEXT
         );",
    )
    .unwrap();
    // 15x allow git status
    for _ in 0..15 {
        conn.execute(
            "INSERT INTO decisions (tool_name, command, decision, reason) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params!["Bash", "git status", "allow", "safe"],
        )
        .unwrap();
    }
    // 8x deny rm -rf /
    for _ in 0..8 {
        conn.execute(
            "INSERT INTO decisions (tool_name, command, decision, reason) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params!["Bash", "rm -rf /", "deny", "dangerous"],
        )
        .unwrap();
    }
    drop(conn);

    let output = std::process::Command::new(common::rippy_binary())
        .args([
            "suggest",
            "--db",
            db_path.to_str().unwrap(),
            "--json",
            "--min-count",
            "3",
        ])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let suggestions: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let arr = suggestions.as_array().unwrap();
    assert!(arr.len() >= 2);

    // Should have a suggestion with allow action and one with deny
    let actions: Vec<&str> = arr.iter().filter_map(|s| s["action"].as_str()).collect();
    assert!(actions.contains(&"allow"));
    assert!(actions.contains(&"deny"));
}

// ---- Structured command matching tests ----

#[test]
fn structured_rule_denies_force_push() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        dir.path().join(".rippy.toml"),
        r#"
[[rules]]
action = "deny"
command = "git"
subcommand = "push"
flags = ["--force", "-f"]
message = "No force push"
"#,
    )
    .unwrap();
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"git push --force origin main"}}"#;
    let (_stdout, code) = run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 2);
}

#[test]
fn structured_rule_allows_safe_subcommands() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        dir.path().join(".rippy.toml"),
        r#"
[[rules]]
action = "allow"
command = "git"
subcommands = ["status", "log", "diff"]
"#,
    )
    .unwrap();

    let json = r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#;
    let (_stdout, code) = run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 0);

    // git push is NOT in the subcommands list, falls through to handler
    let json2 = r#"{"tool_name":"Bash","tool_input":{"command":"git push origin main"}}"#;
    let (_stdout2, code2) = run_rippy_in_dir(json2, "claude", dir.path());
    // git push without force is "ask" from handler
    assert_eq!(code2, 2);
}

#[test]
fn structured_rule_with_flag_position_independence() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        dir.path().join(".rippy.toml"),
        r#"
[[rules]]
action = "deny"
command = "git"
subcommand = "push"
flags = ["-f"]
message = "No force push"
"#,
    )
    .unwrap();

    // Flag at end
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"git push origin main -f"}}"#;
    let (_, code) = run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 2);

    // Combined short flags
    let json2 = r#"{"tool_name":"Bash","tool_input":{"command":"git push -fv origin"}}"#;
    let (_, code2) = run_rippy_in_dir(json2, "claude", dir.path());
    assert_eq!(code2, 2);
}
