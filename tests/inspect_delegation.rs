//! End-to-end proof that the shipped binary's explain path and hook path agree.
//!
//! `rippy inspect` is what a reviewer reads to understand a decision, so a
//! decision it reports that the hook would not make is a correctness bug (#167,
//! and #137 before it). Both commands run from the same cwd with the same
//! `--config` and an isolated `$HOME`, so the only variable is the code path.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::Path;
use std::process::{Command, Stdio};

use common::rippy_binary;

/// Commands spanning the routing shapes the old parallel implementation got
/// wrong: compound forms, redirects, env prefixes, expansions.
const SPREAD: &[&str] = &[
    "ls -la",
    "git status",
    "git push origin main",
    "some_unknown_tool --flag",
    "ls -la | head",
    "git log --oneline && git status",
    "ls; echo done",
    "ls && rm -rf /",
    "echo secret > .env",
    "echo hi > /dev/null",
    "cat < /etc/hosts",
    "ls 2>&1",
    "VAR=x echo hi",
    "LD_PRELOAD=/tmp/x ls",
    "x=$(ls); echo $x",
    "for i in 1 2 3; do echo $i; done",
    "tar --help",
    "if",
];

fn inspect_decision(cwd: &Path, home: &Path, config: Option<&Path>, command: &str) -> String {
    let mut cmd = Command::new(rippy_binary());
    cmd.arg("inspect").arg("--json");
    if let Some(path) = config {
        cmd.arg("--config").arg(path);
    }
    cmd.arg(command).current_dir(cwd).env("HOME", home);
    let output = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("inspect emitted invalid JSON for {command:?}: {e}\n{stdout}"));
    parsed["decision"].as_str().unwrap().to_owned()
}

fn hook_decision(cwd: &Path, home: &Path, config: Option<&Path>, command: &str) -> String {
    let payload = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": command },
    })
    .to_string();

    let mut cmd = Command::new(rippy_binary());
    cmd.arg("--mode").arg("claude");
    if let Some(path) = config {
        cmd.arg("--config").arg(path);
    }
    cmd.current_dir(cwd)
        .env("HOME", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().unwrap();
    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(payload.as_bytes()).unwrap();
    }
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("hook emitted invalid JSON for {command:?}: {e}\n{stdout}"));
    parsed["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn assert_agree(cwd: &Path, home: &Path, config: Option<&Path>, command: &str) {
    let inspect = inspect_decision(cwd, home, config, command);
    let hook = hook_decision(cwd, home, config, command);
    assert_eq!(
        inspect, hook,
        "`rippy inspect` and the hook disagree on {command:?}"
    );
}

#[test]
fn inspect_binary_agrees_with_hook_binary() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    for command in SPREAD {
        assert_agree(cwd.path(), home.path(), None, command);
    }
}

#[test]
fn inspect_binary_agrees_on_a_whole_string_allow_rule() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let config = cwd.path().join("allow-ls.toml");
    std::fs::write(
        &config,
        "[[rules]]\naction = \"allow\"\npattern = \"ls*\"\n",
    )
    .unwrap();

    for command in ["ls -la", "ls && rm -rf /", "ls | sh"] {
        assert_agree(cwd.path(), home.path(), Some(&config), command);
    }
}

#[test]
fn inspect_binary_agrees_on_a_conditional_rule() {
    let cwd = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let config = cwd.path().join("conditional.toml");
    std::fs::write(
        &config,
        "[[rules]]\naction = \"deny\"\npattern = \"ls*\"\nmessage = \"denied here\"\n\n\
         [rules.when.cwd]\nunder = \"/\"\n",
    )
    .unwrap();

    assert_agree(cwd.path(), home.path(), Some(&config), "ls -la");
    assert_eq!(
        inspect_decision(cwd.path(), home.path(), Some(&config), "ls -la"),
        "deny",
        "a cwd-conditional rule must fire in the explain path"
    );
}
