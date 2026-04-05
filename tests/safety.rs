#![allow(clippy::unwrap_used)]

mod common;
use common::{run_rippy, run_rippy_in_dir_with_args};

// ---- Python -c safety analysis tests ----

#[test]
fn python_c_print_allows() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"python -c 'print(1)'"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn python_c_import_os_asks() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"python -c 'import os; os.system(\"rm -rf /\")'"}}"#;
    let (_stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 2);
}

#[test]
fn python_c_import_json_allows() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"python -c 'import json; print(json.dumps({}))'"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn python_script_asks() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"python script.py"}}"#;
    let (_stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 2);
}

// ---- CC permission rules tests ----

#[test]
fn cc_allow_rule_auto_approves() {
    let dir = tempfile::tempdir().unwrap();
    let claude_dir = dir.path().join(".claude");
    std::fs::create_dir(&claude_dir).unwrap();
    std::fs::write(
        claude_dir.join("settings.local.json"),
        r#"{"permissions": {"allow": ["Bash(git push)"]}}"#,
    )
    .unwrap();
    // git push normally asks, but CC allow rule should auto-approve
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"git push origin main"}}"#;
    let (stdout, code) = common::run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn cc_deny_rule_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let claude_dir = dir.path().join(".claude");
    std::fs::create_dir(&claude_dir).unwrap();
    std::fs::write(
        claude_dir.join("settings.json"),
        r#"{"permissions": {"deny": ["Bash(ls)"]}}"#,
    )
    .unwrap();
    // ls is normally safe, but CC deny rule should block it
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#;
    let (stdout, code) = common::run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn cc_ask_rule_prompts() {
    let dir = tempfile::tempdir().unwrap();
    let claude_dir = dir.path().join(".claude");
    std::fs::create_dir(&claude_dir).unwrap();
    std::fs::write(
        claude_dir.join("settings.json"),
        r#"{"permissions": {"ask": ["Bash(git status)"]}}"#,
    )
    .unwrap();
    // git status is normally safe, but CC ask rule should prompt
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#;
    let (_stdout, code) = common::run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 2);
}

// ---- Self-protection integration tests ----

#[test]
fn self_protect_denies_write_to_rippy_config() {
    let json = r#"{"tool_name":"Write","tool_input":{"file_path":".rippy","content":"allow *"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    let reason = v["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert!(reason.contains("protected"));
}

#[test]
fn self_protect_denies_edit_to_rippy_toml() {
    let json = r#"{"tool_name":"Edit","tool_input":{"file_path":".rippy.toml","old_string":"deny","new_string":"allow"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn self_protect_denies_redirect_to_rippy() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"echo 'allow *' > .rippy"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn self_protect_allows_read_of_rippy_config() {
    // Reading .rippy is fine — only writes/edits are blocked.
    let json = r#"{"tool_name":"Read","tool_input":{"file_path":".rippy"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    // Should passthrough (no rule matches for reads), exit 0.
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    // Passthrough = empty JSON or no permissionDecision override.
    assert!(
        v.as_object().is_some_and(serde_json::Map::is_empty)
            || v["hookSpecificOutput"]["permissionDecision"] != "deny"
    );
}

#[test]
fn self_protect_disabled_allows_write() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        dir.path().join(".rippy.toml"),
        "[settings]\nself-protect = false\n",
    )
    .unwrap();

    let json = r#"{"tool_name":"Write","tool_input":{"file_path":".rippy","content":"allow *"}}"#;
    let config = dir.path().join(".rippy.toml");
    let config_str = config.to_str().unwrap();
    let (_stdout, code) =
        run_rippy_in_dir_with_args(json, "claude", dir.path(), &["--config", config_str]);
    // With self-protect off and no deny-write rule, this should passthrough (exit 0).
    assert_eq!(code, 0);
}
