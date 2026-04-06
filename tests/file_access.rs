#![allow(clippy::unwrap_used)]

mod common;
use common::{run_rippy_in_dir, run_rippy_in_dir_with_args};

// ---- File-access integration tests ----

#[test]
fn file_read_denied_by_rule() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        dir.path().join(".rippy.toml"),
        "[[rules]]\naction = \"deny-read\"\npattern = \"**/.env*\"\nmessage = \"no env access\"\n",
    )
    .unwrap();

    let json = r#"{"tool_name":"Read","tool_input":{"file_path":".env.local"}}"#;
    let config = dir.path().join(".rippy.toml");
    let config_str = config.to_str().unwrap();
    let (stdout, code) =
        run_rippy_in_dir_with_args(json, "claude", dir.path(), &["--config", config_str]);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(
        v["hookSpecificOutput"]["permissionDecisionReason"],
        "no env access"
    );
}

#[test]
fn file_write_denied_by_rule() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        dir.path().join(".rippy.toml"),
        "[[rules]]\naction = \"deny-write\"\npattern = \"**/.rippy*\"\nmessage = \"config protected\"\n",
    )
    .unwrap();

    let json =
        r#"{"tool_name":"Write","tool_input":{"file_path":".rippy.toml","content":"allow *"}}"#;
    let (stdout, code) = run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn file_read_passthrough_no_rules() {
    let dir = tempfile::TempDir::new().unwrap();
    // No .rippy config at all — file tools should passthrough.
    let json = r#"{"tool_name":"Read","tool_input":{"file_path":"main.rs"}}"#;
    let (stdout, code) = run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 0);
    // Passthrough outputs empty JSON.
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(v.as_object().is_some_and(serde_json::Map::is_empty));
}

#[test]
fn file_read_allowed_by_explicit_rule() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        dir.path().join(".rippy.toml"),
        "[[rules]]\naction = \"allow-read\"\npattern = \"**\"\n",
    )
    .unwrap();

    let json = r#"{"tool_name":"Read","tool_input":{"file_path":"anything.txt"}}"#;
    let config = dir.path().join(".rippy.toml");
    let config_str = config.to_str().unwrap();
    let (stdout, code) =
        run_rippy_in_dir_with_args(json, "claude", dir.path(), &["--config", config_str]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn edit_tool_matched_by_rule() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        dir.path().join(".rippy.toml"),
        "[[rules]]\naction = \"ask-edit\"\npattern = \"**/node_modules/**\"\nmessage = \"vendor files\"\n",
    )
    .unwrap();

    let json = r#"{"tool_name":"Edit","tool_input":{"file_path":"node_modules/pkg/index.js","old_string":"a","new_string":"b"}}"#;
    let config = dir.path().join(".rippy.toml");
    let config_str = config.to_str().unwrap();
    let (stdout, code) =
        run_rippy_in_dir_with_args(json, "claude", dir.path(), &["--config", config_str]);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
    assert_eq!(
        v["hookSpecificOutput"]["permissionDecisionReason"],
        "vendor files"
    );
}
