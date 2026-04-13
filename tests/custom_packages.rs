#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Integration tests for user-defined custom packages (#103).
//!
//! These tests spin up `rippy` as a subprocess with a temporary `HOME` pointing
//! at a directory containing `~/.rippy/packages/*.toml` files, verifying that
//! custom packages are discovered, loaded, and layered correctly.

use std::path::Path;
use std::process::{Command, Stdio};

mod common;

fn rippy_with_home(args: &[&str], home: &Path) -> (String, String, i32) {
    let mut cmd = Command::new(common::rippy_binary());
    for arg in args {
        cmd.arg(arg);
    }
    cmd.env("HOME", home)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = cmd.output().unwrap();
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.code().unwrap_or(-1),
    )
}

fn rippy_hook_with_home(json: &str, mode: &str, cwd: &Path, home: &Path) -> (String, String, i32) {
    let mut cmd = Command::new(common::rippy_binary());
    cmd.arg("--mode").arg(mode);
    cmd.current_dir(cwd)
        .env("HOME", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().unwrap();
        let _ = stdin.write_all(json.as_bytes());
    }
    let output = child.wait_with_output().unwrap();
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.code().unwrap_or(-1),
    )
}

fn write_custom_package(home: &Path, name: &str, body: &str) {
    let dir = home.join(".rippy/packages");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(format!("{name}.toml")), body).unwrap();
}

#[test]
fn profile_list_includes_custom_package() {
    let home = tempfile::tempdir().unwrap();
    write_custom_package(
        home.path(),
        "corp",
        "[meta]\nname = \"corp\"\ntagline = \"Corporate standard\"\nshield = \"===.\"\n",
    );

    let (stdout, _stderr, code) = rippy_with_home(&["profile", "list"], home.path());
    assert_eq!(code, 0, "profile list should succeed: {stdout}");
    assert!(
        stdout.contains("corp"),
        "output should mention corp: {stdout}"
    );
    assert!(
        stdout.contains("Custom packages:"),
        "output should have custom section header: {stdout}"
    );
    assert!(
        stdout.contains("Corporate standard"),
        "output should show tagline: {stdout}"
    );
}

#[test]
fn profile_list_json_includes_custom_flag() {
    let home = tempfile::tempdir().unwrap();
    write_custom_package(
        home.path(),
        "corp",
        "[meta]\nname = \"corp\"\ntagline = \"Corporate standard\"\n",
    );

    let (stdout, _stderr, code) = rippy_with_home(&["profile", "list", "--json"], home.path());
    assert_eq!(code, 0);
    let entries: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let arr = entries.as_array().unwrap();
    let corp = arr
        .iter()
        .find(|e| e["name"] == "corp")
        .expect("corp should be in list");
    assert_eq!(corp["custom"], true);
    let develop = arr.iter().find(|e| e["name"] == "develop").unwrap();
    assert_eq!(develop["custom"], false);
}

#[test]
fn profile_show_custom_package() {
    let home = tempfile::tempdir().unwrap();
    write_custom_package(
        home.path(),
        "corp",
        r#"
[meta]
name = "corp"
tagline = "Corporate standard"
shield = "===."

[[rules]]
action = "deny"
pattern = "curl"
message = "network requests require approval"
"#,
    );

    let (stdout, _stderr, code) = rippy_with_home(&["profile", "show", "corp"], home.path());
    assert_eq!(code, 0, "profile show should succeed: {stdout}");
    assert!(stdout.contains("corp"));
    assert!(stdout.contains("Corporate standard"));
    assert!(stdout.contains("curl"));
    assert!(stdout.contains("network requests require approval"));
}

#[test]
fn profile_show_custom_renders_inherited_rules() {
    let home = tempfile::tempdir().unwrap();
    write_custom_package(
        home.path(),
        "team",
        r#"
[meta]
name = "team"
tagline = "Team package"
extends = "develop"

[[rules]]
action = "deny"
pattern = "npm publish"
message = "team policy"
"#,
    );

    let (stdout, _stderr, code) =
        rippy_with_home(&["profile", "show", "team", "--json"], home.path());
    assert_eq!(code, 0);
    let output: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let rules = output["rules"].as_array().unwrap();

    // Should include both the develop-inherited rules and the team rule.
    let team_rule = rules.iter().find(|r| {
        r["description"]
            .as_str()
            .unwrap_or("")
            .contains("npm publish")
    });
    assert!(
        team_rule.is_some(),
        "team rule should appear in show output"
    );

    // Develop typically has rules for cargo.
    let has_develop_rule = rules
        .iter()
        .any(|r| r["description"].as_str().unwrap_or("").contains("cargo"));
    assert!(has_develop_rule, "inherited develop rules should appear");
}

#[test]
fn profile_show_unknown_package_errors() {
    let home = tempfile::tempdir().unwrap();
    let (stdout, stderr, code) = rippy_with_home(&["profile", "show", "nope"], home.path());
    assert_ne!(code, 0, "unknown package should fail: {stdout} / {stderr}");
    assert!(
        stderr.contains("nope") || stdout.contains("nope"),
        "error should mention the name: {stdout} / {stderr}"
    );
}

#[test]
fn config_with_custom_package_blocks_command() {
    let home = tempfile::tempdir().unwrap();
    write_custom_package(
        home.path(),
        "corp",
        r#"
[meta]
name = "corp"
tagline = "Corporate"
extends = "develop"

[[rules]]
action = "deny"
pattern = "npm publish"
message = "corp policy: no publish"
"#,
    );
    // Global config activates the custom package + trusts project configs so
    // we don't need a trust DB to take effect.
    std::fs::write(
        home.path().join(".rippy/config.toml"),
        "[settings]\npackage = \"corp\"\ntrust-project-configs = true\n",
    )
    .unwrap();

    let project = tempfile::tempdir().unwrap();
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"npm publish"}}"#;
    let (stdout, _stderr, code) = rippy_hook_with_home(json, "claude", project.path(), home.path());

    // corp policy denies → exit code 2, reason contains "corp policy"
    assert_eq!(code, 2, "should deny, got stdout: {stdout}");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    let reason = v["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap_or("");
    assert!(reason.contains("corp policy"), "reason: {reason}");
}

#[test]
fn config_with_custom_package_inherits_develop_allowances() {
    let home = tempfile::tempdir().unwrap();
    write_custom_package(
        home.path(),
        "corp",
        r#"
[meta]
name = "corp"
extends = "develop"
"#,
    );
    std::fs::write(
        home.path().join(".rippy/config.toml"),
        "[settings]\npackage = \"corp\"\ntrust-project-configs = true\n",
    )
    .unwrap();

    let project = tempfile::tempdir().unwrap();
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"cargo test"}}"#;
    let (stdout, _stderr, code) = rippy_hook_with_home(json, "claude", project.path(), home.path());

    // develop package allows cargo test
    assert_eq!(code, 0, "should allow cargo test, got stdout: {stdout}");
}

#[test]
fn profile_list_with_malformed_custom_still_shows_valid() {
    let home = tempfile::tempdir().unwrap();
    write_custom_package(
        home.path(),
        "good",
        "[meta]\nname = \"good\"\ntagline = \"Valid package\"\n",
    );
    // Write a malformed package file directly
    let dir = home.path().join(".rippy/packages");
    std::fs::write(dir.join("broken.toml"), "not valid [[").unwrap();

    let (stdout, stderr, code) = rippy_with_home(&["profile", "list"], home.path());
    assert_eq!(code, 0, "list should succeed even with one malformed file");
    assert!(
        stdout.contains("good"),
        "valid package should still appear: {stdout}"
    );
    assert!(
        stderr.contains("broken.toml") || stderr.contains("skipping"),
        "malformed file should produce a warning on stderr: {stderr}"
    );
}

#[test]
fn profile_show_malformed_custom_errors_with_path() {
    let home = tempfile::tempdir().unwrap();
    let dir = home.path().join(".rippy/packages");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("broken.toml"), "not valid [[").unwrap();

    let (stdout, stderr, code) = rippy_with_home(&["profile", "show", "broken"], home.path());
    assert_ne!(code, 0, "malformed package should error");
    // rippy prints errors to stdout as JSON; path should appear there.
    assert!(
        stdout.contains("broken.toml") || stderr.contains("broken.toml"),
        "error should mention path: stdout={stdout} / stderr={stderr}"
    );
}

#[test]
fn builtin_takes_priority_over_custom_with_same_name() {
    let home = tempfile::tempdir().unwrap();
    write_custom_package(
        home.path(),
        "develop",
        "[meta]\nname = \"develop\"\ntagline = \"This should be shadowed\"\n",
    );

    let (stdout, stderr, code) = rippy_with_home(&["profile", "show", "develop"], home.path());
    assert_eq!(code, 0);
    // Built-in's tagline is used, not the custom file's.
    assert!(
        stdout.contains("Let me code"),
        "should show built-in tagline: {stdout}"
    );
    assert!(
        stderr.contains("shadowed"),
        "stderr should warn about shadowing: {stderr}"
    );
}
