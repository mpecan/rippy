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

mod common;

use std::sync::LazyLock;

use proptest::prelude::*;
use rippy_cli::allowlists;
use rippy_cli::analyzer::Analyzer;
use rippy_cli::config::{Config, ConfigDirective};
use rippy_cli::environment::Environment;
use rippy_cli::verdict::Decision;

/// Candidate safe-scope inputs, including dangerous/degenerate ones (`/`, `~`,
/// empty) that must never widen auto-approval to an unrelated path.
const SCOPE_INPUTS: &[&str] = &["/", "~", "", "/opt", "/opt/repos", "/srv/work"];

/// Absolute paths that are NOT under any legitimate `SCOPE_INPUTS` prefix, nor
/// under the test cwd (`/project`) or the default safe dirs.
const OUTSIDE_PATHS: &[&str] = &[
    "/etc/secrets",
    "/usr/local/bin",
    "/var/log/syslog",
    "/root/.ssh",
];

fn analyzer_with_scope_input(scope: &str) -> Analyzer {
    let config = Config::from_directives(vec![ConfigDirective::SafeScope(
        std::path::PathBuf::from(scope),
    )]);
    let env = Environment::for_test(std::path::PathBuf::from("/project"));
    Analyzer::from_env(config, env).expect("analyzer builds")
}

/// Cached sorted lists — avoid re-sorting on every proptest iteration.
static SAFE_CMDS: LazyLock<Vec<&'static str>> = LazyLock::new(allowlists::all_simple_safe);
static WRAPPERS: LazyLock<Vec<&'static str>> = LazyLock::new(allowlists::all_wrappers);

/// Commands known to be dangerous — curated for proptest composition.
const DANGEROUS_COMMANDS: &[&str] = &[
    "rm -rf /",
    "dd if=/dev/zero of=/dev/sda",
    "chmod 777 /",
    "shred /dev/sda",
];

/// Injection separators that create compound commands.
const INJECTION_VECTORS: &[&str] = &["; ", " && ", " || "];

/// File-write redirect operators. `&>`/`>&` parse as fd duplication but with a
/// path target are file writes, so they must be guarded identically to `>`/`>>`.
const WRITE_REDIRECT_OPS: &[&str] = &[">", ">>", "&>", ">&"];

/// Git repo-redirect flag forms — separated (`--git-dir PATH`) and attached
/// (`--git-dir=PATH`). All must be scope-checked identically so a redirect to
/// an outside repo cannot be smuggled past the guard via the `=` form (#134).
/// `{P}` is replaced with the target path.
const GIT_REDIRECT_TEMPLATES: &[&str] = &[
    "git -C {P} log",
    "git --git-dir {P} log",
    "git --git-dir={P} log",
    "git --work-tree {P} status",
    "git --work-tree={P} status",
];

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
    "env CI=bar {CMD}",
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

    // Strategy 1: Safe command passthrough

    /// Any `SIMPLE_SAFE` command with typical arguments must be allowed.
    #[test]
    fn safe_command_passthrough(
        cmd_idx in 0..SAFE_CMDS.len(),
        arg_idx in 0..SAFE_ARGS.len(),
    ) {
        let cmd = SAFE_CMDS[cmd_idx];
        let arg = SAFE_ARGS[arg_idx];
        let full = if arg.is_empty() {
            cmd.to_string()
        } else {
            format!("{cmd} {arg}")
        };

        let mut analyzer = common::isolated_analyzer();
        let verdict = analyzer.analyze(&full).expect("analyze succeeds");
        let msg = format!(
            "SIMPLE_SAFE command {:?} was not allowed: {:?}",
            full, verdict.reason,
        );
        prop_assert!(verdict.decision == Decision::Allow, "{}", msg);
    }

    // Strategy 2: Injection detection

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

        let mut analyzer = common::isolated_analyzer();
        let verdict = analyzer.analyze(&full).expect("analyze succeeds");
        let msg = format!(
            "Injection not caught: {:?} => {:?} ({:?})",
            full, verdict.decision, verdict.reason,
        );
        prop_assert!(verdict.decision >= Decision::Ask, "{}", msg);
    }

    // Strategy 3: Recursive construct contrast

    /// Recursive constructs with safe inner commands must Allow.
    #[test]
    fn contrast_safe_inner(
        template_idx in 0..RECURSIVE_TEMPLATES.len(),
        inner_idx in 0..SAFE_INNER_COMMANDS.len(),
    ) {
        let template = RECURSIVE_TEMPLATES[template_idx];
        let inner = SAFE_INNER_COMMANDS[inner_idx];
        let cmd = template.replace("{CMD}", inner);

        let mut analyzer = common::isolated_analyzer();
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

        let mut analyzer = common::isolated_analyzer();
        let verdict = analyzer.analyze(&cmd).expect("analyze succeeds");
        let msg = format!(
            "Dangerous inner allowed: {:?} => {:?}",
            cmd, verdict.reason,
        );
        prop_assert!(verdict.decision >= Decision::Ask, "{}", msg);
    }

    // Strategy 4: Wrapper transparency

    /// Wrapper commands must be transparent: wrapping a safe command allows.
    #[test]
    fn wrapper_safe_passthrough(
        wrapper_idx in 0..WRAPPERS.len(),
        inner_idx in 0..SAFE_INNER_COMMANDS.len(),
    ) {
        let wrapper = WRAPPERS[wrapper_idx];
        let inner = SAFE_INNER_COMMANDS[inner_idx];
        let cmd = format!("{wrapper} {inner}");

        let mut analyzer = common::isolated_analyzer();
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
        wrapper_idx in 0..WRAPPERS.len(),
        danger_idx in 0..DANGEROUS_COMMANDS.len(),
    ) {
        let wrapper = WRAPPERS[wrapper_idx];
        let danger = DANGEROUS_COMMANDS[danger_idx];
        let cmd = format!("{wrapper} {danger}");

        let mut analyzer = common::isolated_analyzer();
        let verdict = analyzer.analyze(&cmd).expect("analyze succeeds");
        let msg = format!(
            "Wrapper {} missed dangerous: {:?} => {:?}",
            wrapper, cmd, verdict.reason,
        );
        prop_assert!(verdict.decision >= Decision::Ask, "{}", msg);
    }

    /// A declared safe scope (even a degenerate `/`, `~`, or empty input) must
    /// never auto-approve a `cd` into a path outside a genuine declared prefix.
    /// Guards the root/broad-scope bypass and the prefix-boundary guarantee (#134).
    #[test]
    fn declared_scope_never_auto_approves_outside_path(
        scope_idx in 0..SCOPE_INPUTS.len(),
        path_idx in 0..OUTSIDE_PATHS.len(),
    ) {
        let scope = SCOPE_INPUTS[scope_idx];
        let outside = OUTSIDE_PATHS[path_idx];
        let mut analyzer = analyzer_with_scope_input(scope);
        let cmd = format!("cd {outside}");
        let verdict = analyzer.analyze(&cmd).expect("analyze succeeds");
        prop_assert!(
            verdict.decision >= Decision::Ask,
            "scope {:?} auto-approved outside path {:?} => {:?}",
            scope, outside, verdict.reason,
        );
    }

    /// A write redirect whose target is outside every declared scope and the
    /// default safe dirs must never auto-approve (#136) — the redirect analogue
    /// of `git_repo_redirect_outside_never_auto_approves`. The `&>`/`>&` forms
    /// (parsed as fd-dup but really file writes) are included so they cannot
    /// bypass the safe-dir/self-protection pipeline via the "fd redirect" allow.
    #[test]
    fn write_redirect_outside_never_auto_approves(
        scope_idx in 0..SCOPE_INPUTS.len(),
        path_idx in 0..OUTSIDE_PATHS.len(),
        op_idx in 0..WRITE_REDIRECT_OPS.len(),
    ) {
        let scope = SCOPE_INPUTS[scope_idx];
        let outside = OUTSIDE_PATHS[path_idx];
        let op = WRITE_REDIRECT_OPS[op_idx];
        let cmd = format!("echo x {op} {outside}");
        let mut analyzer = analyzer_with_scope_input(scope);
        let verdict = analyzer.analyze(&cmd).expect("analyze succeeds");
        prop_assert!(
            verdict.decision >= Decision::Ask,
            "write redirect {:?} with scope {:?} auto-approved outside path => {:?}",
            cmd, scope, verdict.reason,
        );
    }

    /// A read-only git command redirected (any flag form, separated or `=`) to a
    /// path outside every declared scope must never auto-approve — the attached
    /// `=` form must not slip past the guard the separated form enforces (#134).
    #[test]
    fn git_repo_redirect_outside_never_auto_approves(
        scope_idx in 0..SCOPE_INPUTS.len(),
        tmpl_idx in 0..GIT_REDIRECT_TEMPLATES.len(),
        path_idx in 0..OUTSIDE_PATHS.len(),
    ) {
        let scope = SCOPE_INPUTS[scope_idx];
        let template = GIT_REDIRECT_TEMPLATES[tmpl_idx];
        let outside = OUTSIDE_PATHS[path_idx];
        let cmd = template.replace("{P}", outside);
        let mut analyzer = analyzer_with_scope_input(scope);
        let verdict = analyzer.analyze(&cmd).expect("analyze succeeds");
        prop_assert!(
            verdict.decision >= Decision::Ask,
            "redirect {:?} with scope {:?} auto-approved outside path => {:?}",
            cmd, scope, verdict.reason,
        );
    }
}
