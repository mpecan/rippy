//! Reproducers for confirmed fail-opens that are not yet fixed.
//!
//! Per CLAUDE.md, a *known* fail-open is pinned as an `#[ignore]`d reproducer
//! plus a tracked issue rather than by softening an assertion. Each test below
//! asserts the behaviour rippy *should* have; each fails today. Remove the
//! `#[ignore]` in the PR that fixes the cited issue — that is the signal the
//! fix actually landed.
//!
//! Run them deliberately with `cargo test --test known_fail_opens -- --ignored`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::isolated_analyzer;
use rippy_cli::verdict::Decision;

/// #193 — the `case` subject word used to go unanalyzed.
///
/// `NodeKind::Case` carries the subject as `word`, which
/// `analyzer_control_flow.rs` discarded via `..`. Bash expands the subject
/// before matching, so the substituted command really does run.
#[test]
fn case_subject_expansion_is_analyzed() {
    let mut a = isolated_analyzer();
    for cmd in [
        "case $(reboot) in a) echo hi;; esac",
        "case `reboot` in a) echo hi;; esac",
        "case ${x:-$(reboot)} in a) echo hi;; esac",
    ] {
        let v = a.analyze(cmd).unwrap();
        assert_ne!(
            v.decision,
            Decision::Allow,
            "case subject expansion auto-approved: {cmd}"
        );
    }
}

/// #193 — the safe neighbour. A `case` with no expansion in its subject stays
/// approvable, so the fix must not simply Ask on every `case`.
#[test]
fn case_without_expansion_still_allows() {
    let mut a = isolated_analyzer();
    let v = a.analyze("case x in a) echo hi;; esac").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

/// #197 — `ConditionalExpr` used to drop its `redirects`, so a write attached to
/// a `[[ ]]` test was never analyzed and self-protection degraded to Ask.
///
/// The sibling `ArithmeticCommand` arm always handled this correctly, which is
/// the contrast that made the omission visible.
#[test]
fn conditional_expr_redirect_is_analyzed() {
    let mut a = isolated_analyzer();
    let cond = a.analyze("[[ -f foo ]] > ~/.rippy/config.toml").unwrap();
    assert_eq!(
        cond.decision,
        Decision::Deny,
        "self-protect downgraded for a [[ ]] redirect"
    );
}

/// #197 — the contrast: the same redirect on an arithmetic command already
/// reaches Deny today. This test passes now and guards the reference behaviour
/// the fix should bring `[[ ]]` in line with.
#[test]
fn arithmetic_command_redirect_is_analyzed() {
    let mut a = isolated_analyzer();
    let arith = a.analyze("(( i = 1 )) > ~/.rippy/config.toml").unwrap();
    assert_eq!(arith.decision, Decision::Deny);
}

/// #198 — `tar --to-command <prog>` used to recurse into `prog` and discard the
/// tar verdict, so appending it *lowered* `tar -xf` from Ask to Allow.
#[test]
fn tar_to_command_does_not_downgrade_extraction() {
    let mut a = isolated_analyzer();
    let v = a.analyze("tar -xf a.tar --to-command cat").unwrap();
    assert_ne!(
        v.decision,
        Decision::Allow,
        "--to-command downgraded an extraction that asks on its own"
    );
}

/// #198 — the glued spelling reaches the program-exec-flag guard and already
/// asks. It is the same command; only the separator differs.
#[test]
fn tar_to_command_glued_spelling_asks() {
    let mut a = isolated_analyzer();
    let v = a.analyze("tar --to-command=cat -xf a.tar").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

/// #199 — every `-c`/`-e` occurrence is classified, not just the first: both
/// clients run all of them, so a read-only leading statement must not launder
/// a write in a later one.
#[test]
fn every_sql_command_flag_is_classified() {
    let mut a = isolated_analyzer();
    for cmd in [
        r#"psql -c "SELECT 1" -c "DROP TABLE t""#,
        r#"mysql -e "SELECT 1" -e "DROP TABLE t""#,
    ] {
        let v = a.analyze(cmd).unwrap();
        assert_ne!(
            v.decision,
            Decision::Allow,
            "second statement ignored: {cmd}"
        );
    }
}

/// #199 — the same statements in the other order are already caught, which is
/// what shows the gap is per-occurrence parsing rather than SQL classification.
#[test]
fn sql_write_in_the_first_command_flag_asks() {
    let mut a = isolated_analyzer();
    let v = a
        .analyze(r#"psql -c "DROP TABLE t" -c "SELECT 1""#)
        .unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

/// #200 — git global flags that choose executed code reached no guard, because
/// the subcommand hunt skipped every `-`-prefixed token.
#[test]
fn git_global_flags_that_select_code_are_checked() {
    let mut a = isolated_analyzer();
    for cmd in [
        "git --exec-path=/tmp/evil status",
        "git --git-dir=/tmp/evil status",
        "git --git-dir /tmp/evil status",
    ] {
        let v = a.analyze(cmd).unwrap();
        assert_ne!(v.decision, Decision::Allow, "global flag skipped: {cmd}");
    }
}

/// #200 — the contrast: an inert global flag is still recognized, so the fix is
/// an allowlist rather than an Ask on everything that starts with a dash.
#[test]
fn git_inert_global_flag_still_allows() {
    let mut a = isolated_analyzer();
    let v = a.analyze("git --no-pager status").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}
