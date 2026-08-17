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
        "<( ",
        "${",
        "` ",
        "[[ ",
        "f() { ",
    ] {
        hook_ask_reason(&opener.repeat(600));
    }
}

/// The first fix for #195 lexed quotes so it could skip quoted spans. Every
/// string here desynced that lexer — an apostrophe in a comment or a heredoc
/// body, `\'` inside `$'…'`, a stray quote re-balanced further along — and the
/// scan then skipped the nesting it existed to measure, so the process aborted
/// again. The scan counts openers and never skips, so none of them can.
#[test]
fn quoting_the_scanner_cannot_read_still_asks_instead_of_aborting() {
    let deep = "( ".repeat(600);
    let heads = "if true; then ".repeat(600);
    let chain = vec!["a"; 20_000].join(";");
    for (what, command) in [
        ("apostrophe in a comment", format!("echo hi #'\n{deep}")),
        ("double quote in a comment", format!("echo hi # \"\n{deep}")),
        ("apostrophe in English prose", format!("# don't\n{heads}")),
        ("re-balanced stray quote", format!("# '\n{deep} '")),
        ("heredoc body", format!("cat <<EOF\ndon't\nEOF\n{deep}")),
        (
            "quoted heredoc delimiter",
            format!("cat <<'EOF'\nit's\nEOF\n{deep}"),
        ),
        ("ANSI-C quoting", format!("echo $'\\'' {deep}")),
        ("statement chain behind a comment", format!("# '\n{chain}")),
        ("inner command", format!("bash -c \"# it's\n{deep}\"")),
    ] {
        let reason = hook_ask_reason(&command);
        assert!(!reason.is_empty(), "{what}: empty reason");
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

/// A hook that never answers is read as a hook that failed, so the shapes whose
/// parse time explodes are refused for their cost rather than their depth:
/// unclosed `{a,` scans to end-of-input per brace, and nested `$(` is
/// super-linear. Each of these takes minutes unbounded.
#[test]
fn shapes_that_would_hang_the_parser_ask_promptly() {
    for command in ["{a,".repeat(50_000), format!("echo {}", "$(".repeat(1_000))] {
        let started = std::time::Instant::now();
        let reason = hook_ask_reason(&command);
        assert!(reason.contains("too complex"), "{reason}");
        assert!(started.elapsed().as_secs() < 10, "{reason}");
    }
}

/// `(`, backticks, `[[` and the compound keywords carry no rippy bound at
/// all: rable stops its own descent at 1 000 frames, and the parse thread's
/// stack is sized for that. This pins the assumption — the widest such input
/// the 1 MB stdin cap can carry still has to come back with a verdict, so a
/// rable release that dropped the cap would fail here rather than in the field.
#[test]
fn the_widest_plain_nesting_the_input_cap_allows_still_answers() {
    for (opener, count) in [
        ("( ", 400_000),
        ("` ", 400_000),
        ("[[ ", 250_000),
        ("if true; then ", 60_000),
        ("case x in a) ", 60_000),
    ] {
        let payload = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": { "command": opener.repeat(count) },
        })
        .to_string();
        let (stdout, stderr, code) = common::run_rippy_with_stderr(&payload, "claude", &[]);
        assert!(
            code == 0 || code == 2,
            "rippy died on {opener:?} x{count} (code {code}): {stderr}"
        );
        serde_json::from_str::<serde_json::Value>(&stdout)
            .unwrap_or_else(|e| panic!("{opener:?}: valid JSON ({e}): {stdout:?}"));
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

/// Writing prose through a heredoc is an everyday agent action, and the first
/// #195 fix charged every English `if`/`for`/`case` and every `(see below` in
/// the body against the nesting bound. These are the shapes it wrongly refused;
/// ground truth is the analyzer, not `rippy inspect` (CLAUDE.md).
#[test]
fn ordinary_documents_and_scripts_are_not_refused_for_their_shape() {
    let doc = (0..1_200)
        .map(|i| format!("line {i} of the notes"))
        .collect::<Vec<_>>()
        .join("\n");
    let prose = "It's a note (see below, and don't worry) if you want; for each\n".repeat(400);
    let script = (0..500)
        .map(|i| format!("echo \"line {i}\""))
        .collect::<Vec<_>>()
        .join("\n");
    let mut analyzer = common::isolated_analyzer();
    for (what, command) in [
        (
            "1200-line document",
            format!("cat > /tmp/notes.txt <<'EOF'\n{doc}\nEOF"),
        ),
        (
            "prose with apostrophes and unbalanced parens",
            format!("cat > /tmp/notes.md <<'EOF'\n{prose}EOF"),
        ),
        (
            "unquoted heredoc delimiter",
            format!("cat > /tmp/notes.md <<EOF\n{prose}EOF"),
        ),
        (
            "40 markdown \"(see below\" lines",
            format!(
                "cat > /tmp/a.md <<'EOF'\n{}EOF",
                "some text (see below\n".repeat(40)
            ),
        ),
        ("500-line script", script),
        ("250-command chain", vec!["echo x"; 250].join(" && ")),
        (
            "for/if/case nested normally",
            "for f in *.rs; do if [ -f \"$f\" ]; then \
             case \"$f\" in *_t.rs) echo t ;; *) echo s ;; esac; fi; done"
                .to_owned(),
        ),
    ] {
        let verdict = analyzer.analyze(&command).expect("analyze answers");
        assert_eq!(
            verdict.decision,
            rippy_cli::verdict::Decision::Allow,
            "{what}: {}",
            verdict.reason
        );
    }
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
