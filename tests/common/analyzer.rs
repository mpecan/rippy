//! Library-level analyzer harness shared by the integration tests and by the
//! `fuzz/` targets, which `#[path]`-include this file so that a fuzzing run and
//! a `cargo test` run analyze under identical isolation semantics.

#![allow(dead_code, clippy::expect_used)]

use std::path::PathBuf;
use std::sync::LazyLock;

use rippy_cli::analyzer::Analyzer;
use rippy_cli::config::Config;
use rippy_cli::environment::Environment;

static TEST_DIR: LazyLock<PathBuf> = LazyLock::new(|| {
    let dir = std::env::temp_dir().join("rippy-test-shared");
    std::fs::create_dir_all(&dir).ok();
    dir
});

/// Stdlib config with no home directory — isolated from developer machine.
/// Parsed once and reused across all tests in a process.
pub static ISOLATED_CONFIG: LazyLock<Config> =
    LazyLock::new(|| Config::load_with_home(&TEST_DIR, None, None).expect("stdlib config loads"));

/// Build a fresh `Analyzer` with stdlib rules, fully isolated from developer
/// config (no `~/.rippy/`, no `~/.claude/`).
pub fn isolated_analyzer() -> Analyzer {
    let env = Environment::for_test(TEST_DIR.clone());
    Analyzer::from_env(ISOLATED_CONFIG.clone(), env).expect("Analyzer::from_env succeeds")
}
