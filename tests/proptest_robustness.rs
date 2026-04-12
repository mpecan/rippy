//! Property-based robustness tests for rippy's parsing/analysis surfaces.
//!
//! These tests don't check that rippy produces *correct* verdicts on adversarial
//! input — only that it produces *some* verdict (or `Result::Err`) without
//! panicking, aborting, or hanging. The four surfaces covered correspond to the
//! four attack surfaces enumerated in issue #77:
//!
//! 1. JSON payload parsing (`Payload::parse`)
//! 2. Bash AST parsing + analysis (`BashParser::parse` + `Analyzer::analyze`)
//! 3. Glob pattern matching (`Pattern::matches`)
//! 4. Config file parsing (`Config::load_from_str`, both formats)
//!
//! Failures discovered by proptest are auto-persisted to
//! `proptest-regressions/proptest_robustness.txt` and should be committed so
//! they re-run on every `cargo test`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use proptest::prelude::*;
use rippy_cli::analyzer::Analyzer;
use rippy_cli::config::{Config, ConfigFormat};
use rippy_cli::parser::BashParser;
use rippy_cli::pattern::Pattern;
use rippy_cli::payload::Payload;

/// Build a fresh analyzer with an empty config and a stable working directory.
/// We deliberately use `Config::empty()` so commands fall through to the full
/// analyzer pipeline rather than short-circuiting on stdlib rule matches.
fn fresh_analyzer() -> Analyzer {
    Analyzer::new(
        Config::empty(),
        /* remote */ false,
        PathBuf::from("/tmp"),
        /* verbose */ false,
    )
    .expect("Analyzer::new with empty config and /tmp cwd is infallible")
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        max_shrink_iters: 256,
        .. ProptestConfig::default()
    })]

    /// `Payload::parse` must not panic on any UTF-8 string.
    #[test]
    fn payload_parse_no_panic_on_strings(s in "[\\s\\S]{0,4096}") {
        let _ = Payload::parse(&s, None);
    }

    /// `Payload::parse` must not panic on random bytes that happen to be valid UTF-8.
    /// Random `Vec<u8>` exercises the JSON tokenizer's lexer paths more aggressively
    /// than regex-generated strings.
    #[test]
    fn payload_parse_no_panic_on_random_bytes(
        bytes in proptest::collection::vec(any::<u8>(), 0..4096)
    ) {
        if let Ok(s) = std::str::from_utf8(&bytes) {
            let _ = Payload::parse(s, None);
        }
    }

    /// `BashParser::parse` followed by `Analyzer::analyze` must not panic on any
    /// UTF-8 string within the production input cap.
    #[test]
    fn parser_and_analyzer_no_panic(source in "[\\s\\S]{0,4096}") {
        let mut parser = BashParser::new().expect("BashParser::new is infallible");
        let _ = parser.parse(&source);

        let mut analyzer = fresh_analyzer();
        let _ = analyzer.analyze(&source);
    }

    /// `Pattern::matches` must not panic for any (pattern, input) pair.
    /// Plus an invariant: a literal pattern (no glob metachars) re-built in
    /// exact-match form (`pat|`) must always match its own source string.
    #[test]
    fn pattern_matches_no_panic_and_literal_self_match(
        pat in "[\\s\\S]{0,256}",
        input in "[\\s\\S]{0,1024}",
    ) {
        let pattern = Pattern::new(&pat);
        let _ = pattern.matches(&input);

        if !pat.is_empty() && !pat.chars().any(|c| matches!(c, '*' | '?' | '[' | '|')) {
            let exact = Pattern::new(&format!("{pat}|"));
            prop_assert!(
                exact.matches(&pat),
                "literal exact-match pattern {pat:?} failed to self-match",
            );
        }
    }

    /// `Config::load_from_str` must not panic on any UTF-8 input, in either format.
    /// We exercise both dispatch paths (TOML and Lines) per iteration so a single
    /// failing input shrinks to the smallest reproducer regardless of which branch
    /// triggered the bug.
    #[test]
    fn config_load_from_str_no_panic(s in "[\\s\\S]{0,4096}") {
        let _ = Config::load_from_str(&s, ConfigFormat::Toml);
        let _ = Config::load_from_str(&s, ConfigFormat::Lines);
    }
}
