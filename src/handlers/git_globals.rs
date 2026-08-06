//! git's global-flag region — the tokens between `git` and its subcommand.
//!
//! The region is walked with an allowlist. Git keeps adding global flags that
//! choose which code runs (`--exec-path`, `-c`, `--git-dir`), so a token that is
//! not known to be inert is handed back as the subcommand and lands on the Ask
//! fallthrough instead of being skipped unexamined (#200).

use super::Classification;

/// Global flags that take a value argument (skip both flag and value).
const GLOBAL_VALUE_FLAGS: &[&str] = &[
    "-C",
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--super-prefix",
    "--config-env",
];

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
    "--paginate",
    "-p",
    "-P",
    "--version",
    "-v",
    "--help",
    "-h",
];

/// Global flags that choose which executables git runs. `--exec-path[=DIR]`
/// makes git resolve its `git-<subcommand>` helper binaries from `DIR`, so a
/// directory holding an executable named `git-status` turns `git status` into
/// arbitrary execution. There is no safe form (#200).
const EXEC_SELECTING_FLAGS: &[&str] = &["--exec-path"];

/// `Ask` when any argument is an [`EXEC_SELECTING_FLAGS`] member, in either the
/// attached or the separated spelling.
pub(super) fn check_exec_selecting_flags(args: &[String]) -> Option<Classification> {
    args.iter()
        .map(|arg| arg.split_once('=').map_or(arg.as_str(), |(base, _)| base))
        .find(|base| EXEC_SELECTING_FLAGS.contains(base))
        .map(|base| Classification::Ask(format!("git {base} relocates the binaries git executes")))
}

/// How many arguments a known-inert global flag occupies, or `None` when the
/// token is not one — the subcommand itself, or a flag that must fail closed.
fn inert_global_flag_width(arg: &str) -> Option<usize> {
    if GLOBAL_FLAGS.contains(&arg) {
        return Some(1);
    }
    match arg.split_once('=') {
        Some((base, _)) if GLOBAL_VALUE_FLAGS.contains(&base) => Some(1),
        None if GLOBAL_VALUE_FLAGS.contains(&arg) => Some(2),
        _ => None,
    }
}

/// Walk past the global flags to the subcommand and its arguments; empty when
/// the arguments hold no subcommand.
pub(super) fn extract_subcommand(args: &[String]) -> (String, Vec<String>) {
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if let Some(width) = inert_global_flag_width(arg) {
            i += width;
            continue;
        }
        return (arg.clone(), args[i + 1..].to_vec());
    }
    (String::new(), Vec::new())
}
