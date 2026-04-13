//! Data-driven test runner with individual test functions generated from TOML.
//!
//! Each `[[case]]` and `[[contrast]]` entry in `tests/data/catalog/*.toml`
//! becomes a distinct `#[test]` function, so `cargo test` shows each case
//! individually. Adding a new test case requires only editing a TOML file.
//!
//! The build script (`build.rs`) reads the TOML files at compile time and
//! generates the test functions into `$OUT_DIR/catalog_generated_tests.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::LazyLock;

use rippy_cli::analyzer::Analyzer;
use rippy_cli::config::Config;
use rippy_cli::environment::Environment;
use rippy_cli::verdict::Decision;

// ---------------------------------------------------------------------------
// Shared config (built once, cloned per test)
// ---------------------------------------------------------------------------

/// Stdlib config isolated from the developer machine — no HOME means no
/// `~/.rippy/config` and no `~/.claude/settings.json` leaking in.
static STDLIB_CONFIG: LazyLock<Config> = LazyLock::new(|| {
    let tmp = std::env::temp_dir().join("rippy-catalog-tests");
    std::fs::create_dir_all(&tmp).ok();
    Config::load_with_home(&tmp, None, None).expect("stdlib config loads")
});

/// Build a fresh `Analyzer` with stdlib rules and no HOME.
fn isolated_analyzer() -> Analyzer {
    let tmp = std::env::temp_dir().join("rippy-catalog-tests");
    let env = Environment::from_system(tmp, false, false).with_home(None);
    Analyzer::from_env(STDLIB_CONFIG.clone(), env).expect("Analyzer::from_env succeeds")
}

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

/// A single catalog test case for `run_case`.
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

fn run_contrast_safe(analyzer: &mut Analyzer, desc: &str, template: &str, inner: &str) {
    let cmd = template.replace("{CMD}", inner);
    let verdict = analyzer
        .analyze(&cmd)
        .unwrap_or_else(|e| panic!("[{desc} safe] analyze({cmd:?}) failed: {e}"));
    assert_eq!(
        verdict.decision,
        Decision::Allow,
        "[{desc} safe] {cmd:?}: expected Allow, got {:?}. reason: {:?}",
        verdict.decision,
        verdict.reason,
    );
}

fn run_contrast_danger(
    analyzer: &mut Analyzer,
    desc: &str,
    template: &str,
    inner: &str,
    reason_contains: Option<&str>,
) {
    let cmd = template.replace("{CMD}", inner);
    let verdict = analyzer
        .analyze(&cmd)
        .unwrap_or_else(|e| panic!("[{desc} danger] analyze({cmd:?}) failed: {e}"));
    assert!(
        verdict.decision >= Decision::Ask,
        "[{desc} danger] {cmd:?}: expected Ask/Deny, got {:?}. reason: {:?}",
        verdict.decision,
        verdict.reason,
    );
    if let Some(pattern) = reason_contains {
        assert!(
            verdict
                .reason
                .to_lowercase()
                .contains(&pattern.to_lowercase()),
            "[{desc} danger] {cmd:?}: reason {:?} missing {:?}",
            verdict.reason,
            pattern,
        );
    }
}

// ---------------------------------------------------------------------------
// Generated tests — one #[test] per TOML entry
// ---------------------------------------------------------------------------

include!(concat!(env!("OUT_DIR"), "/catalog_generated_tests.rs"));
