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

/// Strategy: `$(cat <<DELIM\n<body>\nDELIM\n)`. Biases proptest toward the
/// heredoc-in-cmdsub shape fixed by rable issues #26 and #29.
fn cmdsub_heredoc_strategy() -> impl Strategy<Value = String> {
    let delim = prop_oneof![Just("EOF"), Just("END"), Just("FOO")];
    (delim, any::<bool>(), "[\\s\\S]{0,512}").prop_map(|(d, quoted, body)| {
        let opener = if quoted {
            format!("<<'{d}'")
        } else {
            format!("<<{d}")
        };
        format!("$(cat {opener}\n{body}\n{d}\n)")
    })
}

/// Strategy: random tree of depth 0–4 wrapping a safe-looking leaf command
/// in `$(...)`, `` `...` ``, or `<(...)`. Biases proptest toward nested
/// substitutions — the shape fixed by rable issues #29/#30/#31.
fn nested_substitution_strategy() -> impl Strategy<Value = String> {
    let leaf = prop_oneof![
        Just("echo hi".to_string()),
        Just("ls".to_string()),
        Just("pwd".to_string()),
        Just("cat file".to_string()),
    ];
    leaf.prop_recursive(
        /* depth */ 4,
        /* desired size */ 32,
        /* items per collection */ 1,
        |inner| {
            prop_oneof![
                inner.clone().prop_map(|s| format!("$({s})")),
                inner.clone().prop_map(|s| format!("`{s}`")),
                inner.prop_map(|s| format!("<({s})")),
            ]
        },
    )
}

/// Strategy: random mix of backtick, backslash, double-quote, single-quote,
/// and letter characters. Exercises rable 0.1.15's backtick escape-handling
/// rewrite (issue #30), which has to correctly handle `\``, `\\`, nested
/// backticks, and backticks inside double quotes.
fn escaped_backtick_strategy() -> impl Strategy<Value = String> {
    "[`\\\\\"'a ]{0,64}".prop_map(String::from)
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

    /// `$(cat <<DELIM\n<body>\nDELIM\n)` must not panic for any body, quoted
    /// or unquoted. Biases proptest toward the heredoc-in-cmdsub shape fixed
    /// by rable #26/#29.
    #[test]
    fn cmdsub_with_heredoc_no_panic(source in cmdsub_heredoc_strategy()) {
        let mut parser = BashParser::new().expect("BashParser::new is infallible");
        let _ = parser.parse(&source);

        let mut analyzer = fresh_analyzer();
        let _ = analyzer.analyze(&source);
    }

    /// Nested trees of `$(...)`, `` `...` ``, and `<(...)` up to depth 4 must
    /// not panic. Biases proptest toward the fork-and-merge reentry paths
    /// introduced in rable 0.1.15 (issues #29/#30/#31).
    #[test]
    fn nested_substitutions_no_panic(source in nested_substitution_strategy()) {
        let mut parser = BashParser::new().expect("BashParser::new is infallible");
        let _ = parser.parse(&source);

        let mut analyzer = fresh_analyzer();
        let _ = analyzer.analyze(&source);
    }

    /// Random mixes of backtick / backslash / quote / letter characters must
    /// not panic. Exercises the rable 0.1.15 backtick escape-handling rewrite
    /// (issue #30).
    #[test]
    fn escaped_backtick_no_panic(source in escaped_backtick_strategy()) {
        let mut parser = BashParser::new().expect("BashParser::new is infallible");
        let _ = parser.parse(&source);

        let mut analyzer = fresh_analyzer();
        let _ = analyzer.analyze(&source);
    }
}
