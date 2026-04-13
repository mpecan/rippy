//! Property-based security tests for rippy's verdict correctness.
//!
//! Unlike `proptest_robustness.rs` (which tests crash-resistance), these tests
//! verify that rippy produces *correct* verdicts when safe and dangerous
//! commands are composed through various injection vectors.
//!
//! Four strategy groups:
//!
//! 1. **Safe command passthrough** — `SIMPLE_SAFE` commands must always Allow.
//! 2. **Injection detection** — safe + dangerous via operators must Ask/Deny.
//! 3. **Recursive construct contrast** — safe inner allows, dangerous inner asks.
//! 4. **Wrapper transparency** — wrappers must not mask the inner verdict.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use proptest::prelude::*;
use rippy_cli::allowlists;
use rippy_cli::analyzer::Analyzer;
use rippy_cli::config::Config;
use rippy_cli::environment::Environment;
use rippy_cli::verdict::Decision;

/// Build an analyzer with stdlib rules, fully isolated from developer config.
/// No HOME means no `~/.rippy/config` or `~/.claude/settings.json`.
fn stdlib_analyzer() -> Analyzer {
    let tmp = PathBuf::from("/tmp/rippy-proptest-security");
    std::fs::create_dir_all(&tmp).ok();
    let config = Config::load_with_home(&tmp, None, None).expect("stdlib config loads");
    let env = Environment::from_system(tmp, false, false).with_home(None);
    Analyzer::from_env(config, env).expect("analyzer init")
}

/// Commands known to be dangerous — curated for proptest composition.
const DANGEROUS_COMMANDS: &[&str] = &[
    "rm -rf /",
    "dd if=/dev/zero of=/dev/sda",
    "chmod 777 /",
    "shred /dev/sda",
];

/// Injection separators that create compound commands.
const INJECTION_VECTORS: &[&str] = &["; ", " && ", " || "];

/// Typical safe arguments for `SIMPLE_SAFE` commands.
const SAFE_ARGS: &[&str] = &["", "-la", "-v", "file.txt", "/tmp/foo", "-r .", "-n 10"];

/// Simple safe commands suitable as inner commands (no special chars).
const SAFE_INNER_COMMANDS: &[&str] = &[
    "ls -la",
    "echo hello",
    "cat file.txt",
    "grep pattern file",
    "wc -l file",
    "head -10 file",
    "tail -5 file",
    "pwd",
    "whoami",
    "date",
];

/// Templates for constructs that recurse into an inner command.
const RECURSIVE_TEMPLATES: &[&str] = &[
    "bash -c '{CMD}'",
    "sh -c '{CMD}'",
    "docker exec container {CMD}",
    "env FOO=bar {CMD}",
    "xargs {CMD}",
    "time {CMD}",
    "nice {CMD}",
];

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 512,
        max_shrink_iters: 256,
        .. ProptestConfig::default()
    })]

    // -----------------------------------------------------------------------
    // Strategy 1: Safe command passthrough
    // -----------------------------------------------------------------------

    /// Any `SIMPLE_SAFE` command with typical arguments must be allowed.
    #[test]
    fn safe_command_passthrough(
        cmd_idx in 0..164_usize,
        arg_idx in 0..SAFE_ARGS.len(),
    ) {
        let safe_cmds = allowlists::all_simple_safe();
        if cmd_idx >= safe_cmds.len() {
            return Ok(());
        }
        let cmd = safe_cmds[cmd_idx];
        let arg = SAFE_ARGS[arg_idx];
        let full = if arg.is_empty() {
            cmd.to_string()
        } else {
            format!("{cmd} {arg}")
        };

        let mut analyzer = stdlib_analyzer();
        let verdict = analyzer.analyze(&full).expect("analyze succeeds");
        let msg = format!(
            "SIMPLE_SAFE command {:?} was not allowed: {:?}",
            full, verdict.reason,
        );
        prop_assert!(verdict.decision == Decision::Allow, "{}", msg);
    }

    // -----------------------------------------------------------------------
    // Strategy 2: Injection detection
    // -----------------------------------------------------------------------

    /// A safe command joined to a dangerous command via any injection operator
    /// must produce Ask or Deny — never Allow.
    #[test]
    fn injection_detection(
        safe_idx in 0..SAFE_INNER_COMMANDS.len(),
        danger_idx in 0..DANGEROUS_COMMANDS.len(),
        vector_idx in 0..INJECTION_VECTORS.len(),
    ) {
        let safe = SAFE_INNER_COMMANDS[safe_idx];
        let danger = DANGEROUS_COMMANDS[danger_idx];
        let vector = INJECTION_VECTORS[vector_idx];
        let full = format!("{safe}{vector}{danger}");

        let mut analyzer = stdlib_analyzer();
        let verdict = analyzer.analyze(&full).expect("analyze succeeds");
        let msg = format!(
            "Injection not caught: {:?} => {:?} ({:?})",
            full, verdict.decision, verdict.reason,
        );
        prop_assert!(verdict.decision >= Decision::Ask, "{}", msg);
    }

    // -----------------------------------------------------------------------
    // Strategy 3: Recursive construct contrast
    // -----------------------------------------------------------------------

    /// Recursive constructs with safe inner commands must Allow.
    #[test]
    fn contrast_safe_inner(
        template_idx in 0..RECURSIVE_TEMPLATES.len(),
        inner_idx in 0..SAFE_INNER_COMMANDS.len(),
    ) {
        let template = RECURSIVE_TEMPLATES[template_idx];
        let inner = SAFE_INNER_COMMANDS[inner_idx];
        let cmd = template.replace("{CMD}", inner);

        let mut analyzer = stdlib_analyzer();
        let verdict = analyzer.analyze(&cmd).expect("analyze succeeds");
        let msg = format!(
            "Safe inner blocked: {:?} => {:?}",
            cmd, verdict.reason,
        );
        prop_assert!(verdict.decision == Decision::Allow, "{}", msg);
    }

    /// Recursive constructs with dangerous inner commands must Ask or Deny.
    #[test]
    fn contrast_dangerous_inner(
        template_idx in 0..RECURSIVE_TEMPLATES.len(),
        danger_idx in 0..DANGEROUS_COMMANDS.len(),
    ) {
        let template = RECURSIVE_TEMPLATES[template_idx];
        let danger = DANGEROUS_COMMANDS[danger_idx];
        let cmd = template.replace("{CMD}", danger);

        let mut analyzer = stdlib_analyzer();
        let verdict = analyzer.analyze(&cmd).expect("analyze succeeds");
        let msg = format!(
            "Dangerous inner allowed: {:?} => {:?}",
            cmd, verdict.reason,
        );
        prop_assert!(verdict.decision >= Decision::Ask, "{}", msg);
    }

    // -----------------------------------------------------------------------
    // Strategy 4: Wrapper transparency
    // -----------------------------------------------------------------------

    /// Wrapper commands must be transparent: wrapping a safe command allows.
    #[test]
    fn wrapper_safe_passthrough(
        wrapper_idx in 0..8_usize,
        inner_idx in 0..SAFE_INNER_COMMANDS.len(),
    ) {
        let wrappers = allowlists::all_wrappers();
        if wrapper_idx >= wrappers.len() {
            return Ok(());
        }
        let wrapper = wrappers[wrapper_idx];
        let inner = SAFE_INNER_COMMANDS[inner_idx];
        let cmd = format!("{wrapper} {inner}");

        let mut analyzer = stdlib_analyzer();
        let verdict = analyzer.analyze(&cmd).expect("analyze succeeds");
        let msg = format!(
            "Wrapper {} blocked safe inner: {:?} => {:?}",
            wrapper, cmd, verdict.reason,
        );
        prop_assert!(verdict.decision == Decision::Allow, "{}", msg);
    }

    /// Wrapper commands wrapping a dangerous command must Ask or Deny.
    #[test]
    fn wrapper_dangerous_detected(
        wrapper_idx in 0..8_usize,
        danger_idx in 0..DANGEROUS_COMMANDS.len(),
    ) {
        let wrappers = allowlists::all_wrappers();
        if wrapper_idx >= wrappers.len() {
            return Ok(());
        }
        let wrapper = wrappers[wrapper_idx];
        let danger = DANGEROUS_COMMANDS[danger_idx];
        let cmd = format!("{wrapper} {danger}");

        let mut analyzer = stdlib_analyzer();
        let verdict = analyzer.analyze(&cmd).expect("analyze succeeds");
        let msg = format!(
            "Wrapper {} missed dangerous: {:?} => {:?}",
            wrapper, cmd, verdict.reason,
        );
        prop_assert!(verdict.decision >= Decision::Ask, "{}", msg);
    }
}
