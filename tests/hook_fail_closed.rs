//! The hook path must never answer with a bare error (#182): an agent reads a
//! non-blocking hook failure as an auto-approval, so a malformed payload has to
//! come back as a forced Ask in the caller's own wire format. Subcommands are
//! read by humans and keep the plain error path.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::process::Command;

use common::{rippy_binary, run_rippy};

#[test]
fn malformed_payload_asks_in_gemini_and_cursor_modes() {
    let (gemini, _) = run_rippy("not json at all", "gemini", &[]);
    let json: serde_json::Value = serde_json::from_str(&gemini).expect("valid gemini JSON");
    assert_eq!(json["decision"], "deny", "{gemini}");

    let (cursor, _) = run_rippy("{ truncated", "cursor", &[]);
    let json: serde_json::Value = serde_json::from_str(&cursor).expect("valid cursor JSON");
    assert_eq!(json["permission"], "ask", "{cursor}");
}

#[test]
fn empty_payload_asks_rather_than_erroring() {
    let (stdout, code) = run_rippy("", "claude", &[]);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid claude JSON");
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"], "ask",
        "{stdout}"
    );
    assert_eq!(code, 0);
    assert!(json.get("error").is_none(), "{stdout}");
}

/// Run `command` through the real hook and return the Ask's reason, failing if
/// the process died instead of answering.
fn hook_ask_reason(command: &str) -> String {
    let payload = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": { "command": command },
    })
    .to_string();
    let (stdout, stderr, code) = common::run_rippy_with_stderr(&payload, "claude", &[]);
    assert!(
        code == 0 || code == 2,
        "rippy died on deep input (code {code}): {stderr}"
    );
    let json: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("valid JSON ({e}): {stdout:?}"));
    assert_eq!(
        json["hookSpecificOutput"]["permissionDecision"], "ask",
        "{stdout}"
    );
    json["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

/// Every depth here overflowed rable's recursive-descent parser before #195.
/// A stack overflow aborts rather than unwinds, so `fail_closed`'s
/// `catch_unwind` net never saw it: the process died with an empty stdout,
/// which an agent reads as an approval. Only a subprocess can observe that,
/// which is why there is no `known_fail_opens` reproducer for #195.
#[test]
fn deeply_nested_constructs_ask_instead_of_aborting() {
    for opener in [
        "case x in a) ",
        "for i in a; do ",
        "if true; then ",
        "while true; do ",
        "until true; do ",
        "select i in a; do ",
        "{ ",
        "( ",
        "$( ",
        "$((",
        "f() { ",
    ] {
        let reason = hook_ask_reason(&opener.repeat(600));
        assert!(reason.contains("too complex"), "{opener:?}: {reason}");
    }
}

#[test]
fn a_flat_statement_chain_asks_instead_of_aborting() {
    for separator in [";", "&&", "|", "\n"] {
        let command = vec!["a"; 50_000].join(separator);
        let reason = hook_ask_reason(&command);
        assert!(reason.contains("too complex"), "{separator:?}: {reason}");
    }
}

/// The bound refuses shapes, not scripts: a normally nested command still gets
/// a real verdict rather than the blanket Ask.
#[test]
fn a_legitimately_nested_command_still_gets_a_real_verdict() {
    let payload = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {
            "command": "for f in *.rs; do if [ -f \"$f\" ]; then \
                        case \"$f\" in *_test.rs) echo test ;; *) echo src ;; esac; fi; done",
        },
    })
    .to_string();
    let (stdout, code) = run_rippy(&payload, "claude", &[]);
    assert_eq!(code, 0, "{stdout}");
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid claude JSON");
    let reason = json["hookSpecificOutput"]["permissionDecisionReason"].to_string();
    assert!(!reason.contains("too complex"), "{stdout}");
}

#[test]
fn subcommands_still_report_real_errors() {
    let out = Command::new(rippy_binary())
        .args(["inspect", "--config", "/nonexistent/rippy.toml", "ls"])
        .output()
        .expect("spawn rippy inspect");
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("\"error\""), "{stdout}");
}

#[test]
fn unknown_subcommand_flag_still_reports_usage() {
    let out = Command::new(rippy_binary())
        .args(["list", "--definitely-not-a-flag"])
        .output()
        .expect("spawn rippy list");
    assert_eq!(out.status.code(), Some(2));
}
