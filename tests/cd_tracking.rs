//! `cd` tracking across a list, with an injected working directory.
//!
//! These cannot be catalog cases. The verdict turns on whether the resolved
//! redirect target lands in a safe directory, and the catalog runner's cwd is
//! `std::env::temp_dir()` — `/tmp` on Linux, `/var/folders/...` on macOS. A
//! catalog case would pass on one and fail on the other. CLAUDE.md routes
//! cwd-relative resolution here for exactly this reason.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::PathBuf;

use common::ISOLATED_CONFIG;
use rippy_cli::analyzer::Analyzer;
use rippy_cli::environment::Environment;
use rippy_cli::verdict::Decision;

/// A directory that is not on any safe-write list, on any platform, so the
/// contrast below comes from the `cd` alone rather than from the starting cwd.
const UNSAFE_CWD: &str = "/opt/rippy-cd-tracking-test";

/// Same stdlib config the catalog runner uses — only the cwd differs, which is
/// the whole point of these tests.
fn analyzer_at(cwd: &str) -> Analyzer {
    let env = Environment::for_test(PathBuf::from(cwd));
    Analyzer::from_env(ISOLATED_CONFIG.clone(), env).expect("Analyzer::from_env succeeds")
}

/// A real `cd` moves the tracked cwd, so `../x` resolves to `/tmp/x` and the
/// write is approved as a safe-dir write.
#[test]
fn cd_retargets_the_tracked_cwd() {
    let mut a = analyzer_at(UNSAFE_CWD);
    let v = a.analyze("cd /tmp/sub && echo hi > ../x").unwrap();
    assert_eq!(v.decision, Decision::Allow, "reason: {}", v.reason);
}

/// Only `cd` may retarget it. `extract_cd_target` guards on `name != "cd"`;
/// inverting that guard makes every command retarget the tracked cwd to its
/// first argument, so `echo /tmp/sub` would relocate the analyzer into a safe
/// directory and launder the write that follows. This is the half that kills
/// the mutant — the `cd` case above is satisfied by it too.
#[test]
fn non_cd_command_does_not_retarget_the_tracked_cwd() {
    let mut a = analyzer_at(UNSAFE_CWD);
    let v = a.analyze("echo /tmp/sub && echo hi > ../x").unwrap();
    assert_eq!(v.decision, Decision::Ask, "reason: {}", v.reason);
}

/// The same pair from a cwd inside `/tmp`. Pinned because the catalog runner
/// sits at `temp_dir()`, where the starting cwd's own parent is already a safe
/// dir — that difference is what makes these tests, not catalog cases.
#[test]
fn contrast_holds_from_a_cwd_inside_tmp() {
    let mut a = analyzer_at("/tmp");
    let allowed = a.analyze("cd /tmp/sub && echo hi > ../x").unwrap();
    assert_eq!(
        allowed.decision,
        Decision::Allow,
        "reason: {}",
        allowed.reason
    );

    let mut a = analyzer_at("/tmp");
    let asked = a.analyze("echo /tmp/sub && echo hi > ../x").unwrap();
    assert_eq!(asked.decision, Decision::Ask, "reason: {}", asked.reason);
}
