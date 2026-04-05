#![allow(clippy::unwrap_used)]

mod common;
use common::{run_rippy, run_rippy_in_dir, run_rippy_in_dir_with_args};

// ---- Config tests ----

#[test]
fn config_deny_overrides() {
    let config_path = format!("{}/tests/fixtures/test.rippy", env!("CARGO_MANIFEST_DIR"));
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/stuff"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &["--config", &config_path]);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(
        v["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("use trash instead")
    );
}

#[test]
fn config_allow_overrides() {
    let config_path = format!("{}/tests/fixtures/test.rippy", env!("CARGO_MANIFEST_DIR"));
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &["--config", &config_path]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

// ---- Recommended config tests (#16) ----

fn recommended_config_path() -> String {
    format!("{}/examples/recommended.rippy", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn recommended_config_allows_defaults_read() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"defaults read com.apple.finder"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &["--config", &recommended_config_path()]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn recommended_config_asks_defaults_write() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"defaults write com.apple.finder key val"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &["--config", &recommended_config_path()]);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
}

#[test]
fn recommended_config_asks_kill() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"kill -9 1234"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &["--config", &recommended_config_path()]);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
}

#[test]
fn recommended_config_asks_dd() {
    let json =
        r#"{"tool_name":"Bash","tool_input":{"command":"dd if=/dev/zero of=/dev/sda bs=1M"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &["--config", &recommended_config_path()]);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
}

#[test]
fn recommended_config_allows_xattr_bare() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"xattr"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &["--config", &recommended_config_path()]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn recommended_config_asks_xattr_write() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"xattr -w attr val file.txt"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &["--config", &recommended_config_path()]);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
}

#[test]
fn recommended_config_allows_ansible_doc() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"ansible-doc copy"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &["--config", &recommended_config_path()]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn recommended_config_allows_diskutil_list() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"diskutil list"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &["--config", &recommended_config_path()]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn recommended_config_exact_match_dmesg_allows_bare() {
    // dmesg| uses exact match — bare `dmesg` is allowed
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"dmesg"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &["--config", &recommended_config_path()]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn recommended_config_exact_match_dmesg_asks_clear() {
    // dmesg -c needs approval even though bare dmesg is allowed
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"dmesg -c"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &["--config", &recommended_config_path()]);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
}

// ---- Conditional rule tests ----

#[test]
fn conditional_rule_file_exists_skipped_when_missing() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        dir.path().join(".rippy.toml"),
        r#"
[[rules]]
action = "deny"
pattern = "echo *"
message = "blocked"

[rules.when]
file-exists = "Cargo.toml"
"#,
    )
    .unwrap();
    // Cargo.toml does NOT exist in tmpdir, so condition fails and rule is skipped.
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"echo hello"}}"#;
    let (_stdout, code) = run_rippy_in_dir(json, "claude", dir.path());
    // echo is in simple_safe → allowed
    assert_eq!(code, 0);
}

#[test]
fn conditional_rule_file_exists_applies_when_present() {
    let dir = tempfile::TempDir::new().unwrap();
    // Create the sentinel file so the condition passes.
    std::fs::write(dir.path().join("Cargo.toml"), "").unwrap();
    std::fs::write(
        dir.path().join(".rippy.toml"),
        r#"
[[rules]]
action = "deny"
pattern = "echo *"
message = "blocked"

[rules.when]
file-exists = "Cargo.toml"
"#,
    )
    .unwrap();
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"echo hello"}}"#;
    let config = dir.path().join(".rippy.toml");
    let config_str = config.to_str().unwrap();
    let (stdout, code) =
        run_rippy_in_dir_with_args(json, "claude", dir.path(), &["--config", config_str]);
    // Cargo.toml exists → condition passes → deny rule applies
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn conditional_rule_branch_not_main() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        dir.path().join(".rippy.toml"),
        r#"
[[rules]]
action = "deny"
pattern = "echo *"
message = "only blocked on main"

[rules.when]
branch = { eq = "main" }
"#,
    )
    .unwrap();
    // tmpdir is not a git repo → no branch → condition fails → rule skipped
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"echo hello"}}"#;
    let (_stdout, code) = run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 0);
}
