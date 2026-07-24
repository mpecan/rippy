//! Integration tests for safe scopes (#134): opt-in cross-repo research
//! directories where reads are allowed but writes still ask, plus the
//! `rippy scope` CLI and the opt-in/transparency guarantees.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::PathBuf;
use std::process::Command;

use rippy_cli::analyzer::Analyzer;
use rippy_cli::config::{Config, ConfigDirective};
use rippy_cli::environment::Environment;
use rippy_cli::verdict::Decision;

fn analyzer_with_scope(scope: &str, cwd: &str) -> Analyzer {
    let config = Config::from_directives(vec![ConfigDirective::SafeScope(PathBuf::from(scope))]);
    let env = Environment::for_test(PathBuf::from(cwd));
    Analyzer::from_env(config, env).expect("analyzer builds")
}

fn decide(analyzer: &mut Analyzer, command: &str) -> Decision {
    analyzer
        .analyze(command)
        .expect("analyze succeeds")
        .decision
}

// ---------------------------------------------------------------------------
// Within a declared scope: reads allowed, writes still ask.
// ---------------------------------------------------------------------------

#[test]
fn cd_into_declared_scope_allows() {
    let mut a = analyzer_with_scope("/opt/repos", "/project");
    assert_eq!(decide(&mut a, "cd /opt/repos/other"), Decision::Allow);
}

#[test]
fn git_read_in_declared_scope_allows() {
    let mut a = analyzer_with_scope("/opt/repos", "/project");
    assert_eq!(
        decide(&mut a, "git -C /opt/repos/other log"),
        Decision::Allow
    );
}

#[test]
fn git_write_in_declared_scope_still_asks() {
    let mut a = analyzer_with_scope("/opt/repos", "/project");
    assert_eq!(
        decide(&mut a, "git -C /opt/repos/other push"),
        Decision::Ask
    );
}

#[test]
fn mkdir_in_declared_scope_allows() {
    let mut a = analyzer_with_scope("/opt/repos", "/project");
    assert_eq!(decide(&mut a, "mkdir /opt/repos/new"), Decision::Allow);
}

// ---------------------------------------------------------------------------
// Nothing outside the project becomes safe without opt-in.
// ---------------------------------------------------------------------------

#[test]
fn cd_outside_declared_scope_still_asks() {
    let mut a = analyzer_with_scope("/opt/repos", "/project");
    assert_eq!(decide(&mut a, "cd /etc"), Decision::Ask);
}

#[test]
fn git_read_outside_any_scope_still_asks() {
    // Rejected-widening guarantee: read-only git against an undeclared repo
    // keeps prompting (its .git/config could run code).
    let mut a = analyzer_with_scope("/opt/repos", "/project");
    assert_eq!(decide(&mut a, "git -C /opt/other log"), Decision::Ask);
}

// ---------------------------------------------------------------------------
// End-to-end via --config, including plan permission mode.
// ---------------------------------------------------------------------------

fn scopes_fixture() -> String {
    format!("{}/tests/fixtures/scopes.toml", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn e2e_cd_into_scope_allows() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"cd /opt/repos/sub"}}"#;
    let (stdout, code) = common::run_rippy(json, "claude", &["--config", &scopes_fixture()]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn e2e_plan_mode_undeclared_dir_still_asks() {
    // Plan mode must NOT widen access to an undeclared directory.
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"cd /some-undeclared"},"permission_mode":"plan"}"#;
    let (stdout, _code) = common::run_rippy(json, "claude", &["--config", &scopes_fixture()]);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_ne!(
        v["hookSpecificOutput"]["permissionDecision"], "allow",
        "plan mode must not auto-approve an undeclared out-of-scope cd: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// Untrusted project config declaring scopes is NOT honored.
// ---------------------------------------------------------------------------

#[test]
fn untrusted_project_scope_not_honored() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        dir.path().join(".rippy.toml"),
        "[scopes]\nsafe = [\"/opt/repos\"]\n",
    )
    .unwrap();

    // The project config is untrusted, so its scope must not take effect:
    // cd into the (would-be) scope still asks.
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"cd /opt/repos/x"}}"#;
    let (stdout, _code) = common::run_rippy_in_dir(json, "claude", dir.path());
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_ne!(
        v["hookSpecificOutput"]["permissionDecision"], "allow",
        "untrusted scope must not auto-approve: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// `rippy scope` CLI smoke test.
// ---------------------------------------------------------------------------

fn run_scope(dir: &std::path::Path, args: &[&str]) -> i32 {
    let output = Command::new(common::rippy_binary())
        .arg("scope")
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    output.status.code().unwrap_or(-1)
}

#[test]
fn cli_scope_add_list_remove() {
    let dir = tempfile::TempDir::new().unwrap();

    assert_eq!(run_scope(dir.path(), &["add", "/opt/smoke"]), 0);
    let content = std::fs::read_to_string(dir.path().join(".rippy.toml")).unwrap();
    assert!(content.contains("[scopes]"));
    assert!(content.contains("/opt/smoke"));

    // list succeeds.
    assert_eq!(run_scope(dir.path(), &["list"]), 0);

    // remove clears it.
    assert_eq!(run_scope(dir.path(), &["remove", "/opt/smoke"]), 0);
    let after = std::fs::read_to_string(dir.path().join(".rippy.toml")).unwrap();
    assert!(!after.contains("/opt/smoke"));
}

#[test]
fn cli_scope_add_rejects_root() {
    let dir = tempfile::TempDir::new().unwrap();
    assert_ne!(run_scope(dir.path(), &["add", "/"]), 0);
    // No config file should have been created for a rejected scope.
    assert!(!dir.path().join(".rippy.toml").exists());
}
