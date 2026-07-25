//! Shared metamorphic harness (issue #168).
//!
//! A metamorphic test needs no oracle for the *correct* verdict: it asserts a
//! relation between the verdict for a command and the verdict for a
//! mechanically transformed version of it. rippy's spec — never `Allow`
//! something harmful — is exactly such a relation, so a danger-injecting
//! transform must never lower restrictiveness.
//!
//! This directory is included both by `tests/proptest_metamorphic.rs` (fast,
//! runs under `cargo test`) and by `fuzz/fuzz_targets/metamorphic.rs` (deep,
//! coverage-guided). See docs/fuzzing.md.

#![allow(dead_code)]

pub(crate) mod grammar;
pub(crate) mod invariants;

#[path = "../common/analyzer.rs"]
pub(crate) mod analyzer;
