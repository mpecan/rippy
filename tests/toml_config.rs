#![allow(clippy::unwrap_used)]

mod common;
use common::{run_rippy, run_rippy_in_dir, run_rippy_in_dir_with_args};

// ---- TOML config integration tests ----

#[test]
fn toml_config_allows_command() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        dir.path().join(".rippy.toml"),
        "[[rules]]\naction = \"allow\"\npattern = \"echo hello\"\n",
    )
    .unwrap();

    let json = r#"{"tool_name":"Bash","tool_input":{"command":"echo hello"}}"#;
    let (stdout, code) = run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn toml_config_denies_with_message() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        dir.path().join(".rippy.toml"),
        r#"
[[rules]]
action = "deny"
pattern = "rm -rf *"
message = "Use trash-cli instead of rm -rf"
"#,
    )
    .unwrap();

    let json = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp"}}"#;
    let config = dir.path().join(".rippy.toml");
    let config_str = config.to_str().unwrap();
    let (stdout, code) =
        run_rippy_in_dir_with_args(json, "claude", dir.path(), &["--config", config_str]);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(
        v["hookSpecificOutput"]["permissionDecisionReason"],
        "Use trash-cli instead of rm -rf"
    );
}

#[test]
fn toml_config_takes_precedence_over_legacy() {
    let dir = tempfile::TempDir::new().unwrap();
    // Legacy config denies git status.
    std::fs::write(dir.path().join(".rippy"), "deny git status\n").unwrap();
    // TOML config allows it — should win.
    std::fs::write(
        dir.path().join(".rippy.toml"),
        "[[rules]]\naction = \"allow\"\npattern = \"git status\"\n",
    )
    .unwrap();

    let json = r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#;
    let (stdout, code) = run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn toml_config_via_config_flag() {
    let dir = tempfile::TempDir::new().unwrap();
    let config_path = dir.path().join("custom.toml");
    std::fs::write(
        &config_path,
        "[[rules]]\naction = \"deny\"\npattern = \"echo *\"\nmessage = \"no echo\"\n",
    )
    .unwrap();

    let json = r#"{"tool_name":"Bash","tool_input":{"command":"echo test"}}"#;
    let config_str = config_path.to_str().unwrap();
    let (stdout, code) = run_rippy(json, "claude", &["--config", config_str]);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(
        v["hookSpecificOutput"]["permissionDecisionReason"],
        "no echo"
    );
}

#[test]
fn migrate_stdout_produces_valid_toml() {
    let dir = tempfile::TempDir::new().unwrap();
    let config = dir.path().join(".rippy");
    std::fs::write(&config, "allow git status\ndeny rm -rf \"use trash\"\n").unwrap();

    let output = std::process::Command::new(common::rippy_binary())
        .args(["migrate", "--stdout"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "migrate failed: {:?}",
        output.status
    );

    let toml_str = String::from_utf8(output.stdout).unwrap();
    assert!(toml_str.contains("action = \"allow\""));
    assert!(toml_str.contains("pattern = \"git status\""));
    assert!(toml_str.contains("action = \"deny\""));
    assert!(toml_str.contains("message = \"use trash\""));
}

// ---- Config weakening annotation tests ----

#[test]
fn config_weakening_verdict_annotated() {
    // A project config that allows a command the stdlib denies should produce
    // a verdict reason mentioning "overrides".
    let dir = tempfile::TempDir::new().unwrap();

    // Project config: allow rm -rf (overrides stdlib handler which returns ask).
    std::fs::write(
        dir.path().join(".rippy.toml"),
        "[[rules]]\naction = \"allow\"\npattern = \"rm -rf *\"\n",
    )
    .unwrap();

    // Global config: trust all project configs so the project config is loaded.
    let home = dir.path().join("fakehome");
    let rippy_dir = home.join(".rippy");
    std::fs::create_dir_all(&rippy_dir).unwrap();
    std::fs::write(
        rippy_dir.join("config.toml"),
        "[settings]\ntrust-project-configs = true\n",
    )
    .unwrap();

    let json = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/stuff"}}"#;
    let mut cmd = std::process::Command::new(common::rippy_binary());
    cmd.arg("--mode")
        .arg("claude")
        .current_dir(dir.path())
        .env("HOME", &home)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().unwrap();
    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().unwrap();
        let _ = stdin.write_all(json.as_bytes());
    }
    let output = child.wait_with_output().unwrap();
    let code = output.status.code().unwrap_or(-1);
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    assert_eq!(code, 0, "allow rule should approve, stdout: {stdout_str}");
    let v: serde_json::Value = serde_json::from_str(&stdout_str).unwrap();
    let reason = v["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap_or("");
    assert!(
        reason.contains("overrides"),
        "verdict should mention override, got: {reason}"
    );
}

#[test]
fn config_tightening_verdict_normal() {
    // A config that only adds deny rules should NOT produce an annotation.
    let dir = tempfile::TempDir::new().unwrap();
    let config_path = dir.path().join("tighten.toml");
    std::fs::write(
        &config_path,
        "[[rules]]\naction = \"deny\"\npattern = \"echo *\"\nmessage = \"blocked\"\n",
    )
    .unwrap();

    let json = r#"{"tool_name":"Bash","tool_input":{"command":"echo hello"}}"#;
    let config_str = config_path.to_str().unwrap();
    let (stdout, code) = run_rippy(json, "claude", &["--config", config_str]);
    assert_eq!(code, 2, "deny rule should block");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let reason = v["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap_or("");
    assert!(
        !reason.contains("overrides"),
        "tightening should not mention override, got: {reason}"
    );
}

#[test]
fn config_no_override_normal_reason() {
    // Without project/override config, verdicts have normal reasons.
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let reason = v["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap_or("");
    assert!(
        !reason.contains("overrides"),
        "no override config → no annotation, got: {reason}"
    );
}
