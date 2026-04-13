//! Data-driven test runner with individual test functions generated from TOML.
//!
//! Each `[[case]]` and `[[contrast]]` entry in `tests/data/catalog/*.toml`
//! becomes a distinct `#[test]` function, so `cargo test` shows each case
//! individually. Adding a new test case requires only editing a TOML file.
//!
//! The build script (`build.rs`) reads the TOML files at compile time and
//! generates the test functions into `$OUT_DIR/catalog_generated_tests.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::isolated_analyzer;
use rippy_cli::analyzer::Analyzer;
use rippy_cli::verdict::Decision;

// ---------------------------------------------------------------------------
// Assertion helpers called by generated test functions
// ---------------------------------------------------------------------------

fn parse_decision(s: &str) -> Decision {
    match s {
        "allow" => Decision::Allow,
        "ask" => Decision::Ask,
        "deny" => Decision::Deny,
        other => panic!("unknown decision: {other:?}"),
    }
}

/// A single catalog test case.
struct Case<'a> {
    file: &'a str,
    idx: usize,
    command: &'a str,
    decision: &'a str,
    reason_contains: Option<&'a str>,
}

fn run_case(analyzer: &mut Analyzer, c: &Case<'_>) {
    let verdict = analyzer.analyze(c.command).unwrap_or_else(|e| {
        panic!(
            "[{} #{}] analyze({:?}) failed: {e}",
            c.file, c.idx, c.command
        )
    });

    let expected = parse_decision(c.decision);
    assert_eq!(
        verdict.decision, expected,
        "[{} #{}] {:?}: expected {expected:?}, got {:?}. reason: {:?}",
        c.file, c.idx, c.command, verdict.decision, verdict.reason,
    );

    if let Some(pattern) = c.reason_contains {
        assert!(
            verdict
                .reason
                .to_lowercase()
                .contains(&pattern.to_lowercase()),
            "[{} #{}] {:?}: reason {:?} missing {:?}",
            c.file,
            c.idx,
            c.command,
            verdict.reason,
            pattern,
        );
    }
}

/// A contrast test case — template + inner command.
struct Contrast<'a> {
    desc: &'a str,
    template: &'a str,
    inner: &'a str,
    expect_allow: bool,
    reason_contains: Option<&'a str>,
}

fn run_contrast(analyzer: &mut Analyzer, c: &Contrast<'_>) {
    let cmd = c.template.replace("{CMD}", c.inner);
    let verdict = analyzer
        .analyze(&cmd)
        .unwrap_or_else(|e| panic!("[{}] analyze({cmd:?}) failed: {e}", c.desc));

    if c.expect_allow {
        assert_eq!(
            verdict.decision,
            Decision::Allow,
            "[{} safe] {cmd:?}: expected Allow, got {:?}. reason: {:?}",
            c.desc,
            verdict.decision,
            verdict.reason,
        );
    } else {
        assert!(
            verdict.decision >= Decision::Ask,
            "[{} danger] {cmd:?}: expected Ask/Deny, got {:?}. reason: {:?}",
            c.desc,
            verdict.decision,
            verdict.reason,
        );
    }

    if let Some(pattern) = c.reason_contains {
        assert!(
            verdict
                .reason
                .to_lowercase()
                .contains(&pattern.to_lowercase()),
            "[{}] {cmd:?}: reason {:?} missing {:?}",
            c.desc,
            verdict.reason,
            pattern,
        );
    }
}

fn run_contrast_safe(analyzer: &mut Analyzer, desc: &str, template: &str, inner: &str) {
    run_contrast(
        analyzer,
        &Contrast {
            desc,
            template,
            inner,
            expect_allow: true,
            reason_contains: None,
        },
    );
}

fn run_contrast_danger(
    analyzer: &mut Analyzer,
    desc: &str,
    template: &str,
    inner: &str,
    reason_contains: Option<&str>,
) {
    run_contrast(
        analyzer,
        &Contrast {
            desc,
            template,
            inner,
            expect_allow: false,
            reason_contains,
        },
    );
}

// ---------------------------------------------------------------------------
// Generated tests — one #[test] per TOML entry
// ---------------------------------------------------------------------------

include!(concat!(env!("OUT_DIR"), "/catalog_generated_tests.rs"));
