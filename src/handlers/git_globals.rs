//! git's global-flag region — the tokens between `git` and its subcommand.
//!
//! The region is walked with an allowlist. Git keeps adding global flags that
//! choose which code runs (`--exec-path=<dir>`, `-c`, `--git-dir`), so a token
//! that is not known to be inert is handed back as the subcommand and lands on
//! the Ask fallthrough instead of being skipped unexamined (#200).

use super::Classification;
use crate::verdict::AllowReason;

/// Global flags that take a value argument (skip both flag and value).
const GLOBAL_VALUE_FLAGS: &[&str] = &[
    "-C",
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--super-prefix",
    "--config-env",
    "--attr-source",
];

/// Inert globals git accepts only in the attached `--flag=<value>` spelling.
/// Listing them apart from [`GLOBAL_VALUE_FLAGS`] keeps a bare `--list-cmds`
/// from swallowing the following token as a value git would never read.
const GLOBAL_EQ_ONLY_FLAGS: &[&str] = &["--list-cmds"];

/// Global flags that are standalone (skip just the flag).
const GLOBAL_FLAGS: &[&str] = &[
    "--no-pager",
    "--bare",
    "--no-replace-objects",
    "--literal-pathspecs",
    "--glob-pathspecs",
    "--noglob-pathspecs",
    "--icase-pathspecs",
    "--no-optional-locks",
    "--no-advice",
    "--no-lazy-fetch",
    "--html-path",
    "--man-path",
    "--info-path",
    "--paginate",
    "-p",
    "-P",
    "--version",
    "-v",
    "--help",
    "-h",
];

/// `--exec-path=<dir>` relocates the directory git resolves its
/// `git-<subcommand>` helper binaries from, so a directory holding an
/// executable named `git-status` turns `git status` into arbitrary execution.
///
/// The bare spelling sets nothing: git prints the compiled-in exec path and
/// exits before any subcommand runs (verified on git 2.55, which ignores every
/// argument after it), so it is an approval rather than the dangerous half.
/// Only the global region is scanned — after the subcommand the same word is
/// just an operand, e.g. `git grep -- --exec-path` searches for the literal.
pub(super) fn check_exec_path_flag(globals: &[String]) -> Option<Classification> {
    globals.iter().find_map(|arg| {
        if arg.starts_with("--exec-path=") {
            Some(Classification::Ask(
                "git --exec-path=<dir> relocates the binaries git executes".into(),
            ))
        } else if arg == "--exec-path" {
            Some(Classification::Allow(AllowReason::handler(
                "git --exec-path (prints the exec path and exits)",
            )))
        } else {
            None
        }
    })
}

/// A separated value flag consumes the token after it — unless that token is
/// itself flag-shaped. `git -C --git-dir=/tmp/evil status` fed `--git-dir=…` to
/// `-C` as its value and skipped past it, so no guard ever examined the
/// redirect (#200 follow-up).
fn value_flag_width(next: Option<&String>) -> usize {
    if next.is_some_and(|v| v.starts_with('-')) {
        1
    } else {
        2
    }
}

/// How many arguments a known-inert global flag occupies, or `None` when the
/// token is not one — the subcommand itself, or a flag that must fail closed.
fn inert_global_flag_width(arg: &str, next: Option<&String>) -> Option<usize> {
    if GLOBAL_FLAGS.contains(&arg) {
        return Some(1);
    }
    match arg.split_once('=') {
        Some((base, _)) => (GLOBAL_VALUE_FLAGS.contains(&base)
            || GLOBAL_EQ_ONLY_FLAGS.contains(&base))
        .then_some(1),
        None if GLOBAL_VALUE_FLAGS.contains(&arg) => Some(value_flag_width(next)),
        None => None,
    }
}

/// Index of the first token that is not a known-inert global flag — the
/// subcommand — or `None` when every token is one.
fn subcommand_index(args: &[String]) -> Option<usize> {
    let mut i = 0;
    while i < args.len() {
        match inert_global_flag_width(&args[i], args.get(i + 1)) {
            Some(width) => i += width,
            None => return Some(i),
        }
    }
    None
}

/// The global-flag region: the tokens git parses before the subcommand, plus
/// the token that ends the region.
///
/// The terminator is included because a global flag that must fail closed is
/// precisely the one the inert allowlist does not recognize, so a guard reading
/// only the recognized prefix would never see `--exec-path=<dir>`. Everything
/// after it belongs to the subcommand and is that subcommand's business.
pub(super) fn global_region(args: &[String]) -> &[String] {
    subcommand_index(args).map_or(args, |i| &args[..=i])
}

/// Walk past the global flags to the subcommand and its arguments; empty when
/// the arguments hold no subcommand.
pub(super) fn extract_subcommand(args: &[String]) -> (String, Vec<String>) {
    subcommand_index(args).map_or_else(
        || (String::new(), Vec::new()),
        |i| (args[i].clone(), args[i + 1..].to_vec()),
    )
}
