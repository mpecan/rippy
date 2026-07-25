//! Sub-subcommand classifiers for git verbs whose safety depends on a nested
//! verb or flag (`git branch -d`, `git config --get`, `git remote show`, …).
//!
//! The safe sets live here as named constants rather than inline match arms so
//! `GitHandler::allow_surface` and these classifiers read the same data — the
//! catalog cannot then disagree with the code it documents.

use super::{Classification, has_flag};
use crate::verdict::AllowReason;

/// `git branch` flags that create, delete, rename or re-point a branch.
pub(super) const BRANCH_MODIFY_FLAGS: &[&str] =
    &["-d", "-D", "-m", "-M", "-c", "-C", "--set-upstream-to"];

/// `git tag` deletion flags.
pub(super) const TAG_DELETE_FLAGS: &[&str] = &["-d", "--delete"];

/// `git remote` sub-subcommands that only read (empty = bare `git remote`).
pub(super) const REMOTE_SAFE: &[&str] = &["show", "get-url", ""];

/// `git stash` sub-subcommands that only read.
pub(super) const STASH_SAFE: &[&str] = &["list", "show"];

/// `git config` flags that read a value.
pub(super) const CONFIG_READ_FLAGS: &[&str] =
    &["--get", "--get-all", "--list", "-l", "--get-regexp"];

/// `git config` flags that write a value.
pub(super) const CONFIG_WRITE_FLAGS: &[&str] = &["--unset", "--add", "--edit", "--replace-all"];

/// `git notes` sub-subcommands that only read (empty = bare `git notes`).
pub(super) const NOTES_SAFE: &[&str] = &["list", "show", ""];

/// `git bisect` sub-subcommands that only read.
pub(super) const BISECT_SAFE: &[&str] = &["log", "visualize", "view"];

/// `git lfs` sub-subcommands that only read.
pub(super) const LFS_SAFE: &[&str] = &["fetch", "ls-files", "status", "env", "version"];

fn sub_of(args: &[String]) -> &str {
    args.first().map_or("", String::as_str)
}

pub(super) fn classify_branch(args: &[String]) -> Classification {
    if has_flag(args, BRANCH_MODIFY_FLAGS) {
        Classification::Ask("git branch (modify)".into())
    } else {
        Classification::Allow(AllowReason::handler("git branch (list)"))
    }
}

pub(super) fn classify_tag(args: &[String]) -> Classification {
    if has_flag(args, TAG_DELETE_FLAGS) {
        Classification::Ask("git tag (delete)".into())
    } else if args.iter().any(|a| !a.starts_with('-')) {
        Classification::Ask("git tag (create)".into())
    } else {
        Classification::Allow(AllowReason::handler("git tag (list)"))
    }
}

pub(super) fn classify_remote(args: &[String]) -> Classification {
    let sub = sub_of(args);
    if sub == "get-url" {
        return Classification::Allow(AllowReason::handler("git remote get-url"));
    }
    if REMOTE_SAFE.contains(&sub) {
        Classification::Allow(AllowReason::handler("git remote (view)"))
    } else {
        Classification::Ask(format!("git remote {sub}"))
    }
}

pub(super) fn classify_stash(args: &[String]) -> Classification {
    let sub = sub_of(args);
    if STASH_SAFE.contains(&sub) {
        Classification::Allow(AllowReason::handler(format!("git stash {sub}")))
    } else if sub.is_empty() {
        Classification::Ask("git stash".into())
    } else {
        Classification::Ask(format!("git stash {sub}"))
    }
}

pub(super) fn classify_config(args: &[String]) -> Classification {
    if has_flag(args, CONFIG_READ_FLAGS) {
        Classification::Allow(AllowReason::handler("git config (read)"))
    } else if has_flag(args, CONFIG_WRITE_FLAGS) {
        Classification::Ask("git config (write)".into())
    } else if args.len() <= 1 {
        Classification::Allow(AllowReason::handler("git config (read)"))
    } else {
        Classification::Ask("git config (write)".into())
    }
}

pub(super) fn classify_notes(args: &[String]) -> Classification {
    let sub = sub_of(args);
    if NOTES_SAFE.contains(&sub) {
        Classification::Allow(AllowReason::handler(format!("git notes {sub}")))
    } else {
        Classification::Ask(format!("git notes {sub}"))
    }
}

pub(super) fn classify_bisect(args: &[String]) -> Classification {
    let sub = sub_of(args);
    if BISECT_SAFE.contains(&sub) {
        Classification::Allow(AllowReason::handler(format!("git bisect {sub}")))
    } else {
        Classification::Ask(format!("git bisect {sub}"))
    }
}

pub(super) fn classify_lfs(args: &[String]) -> Classification {
    let sub = sub_of(args);
    if LFS_SAFE.contains(&sub) {
        Classification::Allow(AllowReason::handler(format!("git lfs {sub}")))
    } else {
        Classification::Ask(format!("git lfs {sub}"))
    }
}
