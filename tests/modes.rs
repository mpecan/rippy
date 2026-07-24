#![allow(clippy::unwrap_used)]

mod common;
use common::run_rippy;

// Claude mode tests

#[test]
fn claude_allow_safe_command() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    // Regression (#125): Claude requires hookEventName inside hookSpecificOutput.
    assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn claude_ask_dangerous_command() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    // Regression (#125): non-allow decisions must carry hookEventName too.
    assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
}

#[test]
fn claude_pipeline_safe() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"cat file | grep pattern | sort"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn claude_git_push_asks() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"git push origin main"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
}

// Gemini mode tests

#[test]
fn gemini_allow_safe() {
    let json = r#"{"tool_name":"bash","tool_input":"ls -la"}"#;
    let (stdout, code) = run_rippy(json, "gemini", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["decision"], "allow");
}

#[test]
fn gemini_deny_dangerous() {
    let json = r#"{"tool_name":"bash","tool_input":"rm -rf /"}"#;
    let (stdout, code) = run_rippy(json, "gemini", &[]);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    // Gemini maps Ask to deny
    assert_eq!(v["decision"], "deny");
}

// Cursor mode tests

#[test]
fn cursor_allow_safe() {
    let json = r#"{"tool_name":"bash","command":"echo hello"}"#;
    let (stdout, code) = run_rippy(json, "cursor", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["permission"], "allow");
}

// Codex mode

#[test]
fn codex_mode_safe_command() {
    let json = r#"{"tool_name":"bash","tool_input":"ls -la"}"#;
    let (stdout, code) = run_rippy(json, "codex", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["decision"], "allow");
}

#[test]
fn codex_mode_dangerous_command() {
    let json = r#"{"tool_name":"bash","tool_input":"rm -rf /"}"#;
    let (stdout, code) = run_rippy(json, "codex", &[]);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["decision"], "deny");
}

// PostToolUse

// hook_event_name is the explicit signal a real Claude Code PostToolUse
// invocation sends; genuine post-hook calls must keep allowing without
// re-analysis (#161). PostToolUse allows via exit 0 and carries the
// PostToolUse event name, not a PreToolUse-only permissionDecision (#125).
#[test]
fn post_tool_use_returns_allow() {
    let json = concat!(
        r#"{"tool_name":"Bash","tool_input":{"command":"ls"},"#,
        r#""tool_result":{"output":"file.txt"},"hook_event_name":"PostToolUse"}"#
    );
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PostToolUse");
    assert!(v["hookSpecificOutput"].get("permissionDecision").is_none());
}

// #161: a tool_result key alone (no explicit hook_event_name) must not skip
// analysis of a dangerous command.

#[test]
fn tool_result_without_event_name_does_not_bypass_dangerous_command() {
    let json = concat!(
        r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf ~/important"},"#,
        r#""tool_result":{}}"#
    );
    let (stdout, code) = run_rippy(json, "claude", &[]);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
    assert_eq!(code, 0);
}

#[test]
fn tool_result_without_event_name_still_allows_safe_command() {
    // Contrast pair: the fix must not turn a benign command into an ask just
    // because it carries an incidental tool_result key.
    let json = concat!(
        r#"{"tool_name":"Bash","tool_input":{"command":"git status"},"#,
        r#""tool_result":{}}"#
    );
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn cursor_tool_result_without_event_name_is_analyzed() {
    let json = r#"{"tool_name":"bash","command":"rm -rf ~/important","tool_result":{}}"#;
    let (stdout, code) = run_rippy(json, "cursor", &[]);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_ne!(v["permission"], "allow");
    let _ = code;
}

// Auto-mode coexistence (#128)

#[test]
fn claude_auto_mode_defers_uncertain_ask() {
    // `git push origin main` is an ask verdict; in an auto mode rippy defers.
    let json = concat!(
        r#"{"tool_name":"Bash","tool_input":{"command":"git push origin main"},"#,
        r#""permission_mode":"acceptEdits"}"#
    );
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "defer");
}

#[test]
fn claude_manual_mode_keeps_ask() {
    // Same command without an auto permission_mode still forces the prompt,
    // and now exits 0 (JSON permissionDecision drives; exit 2 is deny-only).
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"git push origin main"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
}

#[test]
fn claude_deny_holds_in_bypass_mode() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join(".rippy.toml");
    std::fs::write(
        &config_path,
        "[[rules]]\naction = \"deny\"\npattern = \"rm -rf *\"\nmessage = \"blocked\"\n",
    )
    .unwrap();
    let json = concat!(
        r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/x"},"#,
        r#""permission_mode":"bypassPermissions"}"#
    );
    let (stdout, code) = run_rippy(json, "claude", &["--config", config_path.to_str().unwrap()]);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn claude_auto_mode_knob_off_forces_ask() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join(".rippy.toml");
    std::fs::write(&config_path, "[settings]\nauto-mode = \"ask\"\n").unwrap();
    let json = concat!(
        r#"{"tool_name":"Bash","tool_input":{"command":"git push origin main"},"#,
        r#""permission_mode":"acceptEdits"}"#
    );
    let (stdout, code) = run_rippy(json, "claude", &["--config", config_path.to_str().unwrap()]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
}

// Dippy backward compat

#[test]
fn dippy_config_file_loaded() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join(".dippy");
    std::fs::write(&config_path, "deny rm -rf \"blocked by dippy config\"").unwrap();
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &["--config", config_path.to_str().unwrap()]);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
}

// Empty command

#[test]
fn empty_command_in_payload() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":""}}"#;
    let (_stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
}
