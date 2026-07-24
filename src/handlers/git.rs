use std::path::Path;

use super::{Classification, Handler, HandlerContext, has_flag, is_within_scope, normalize_path};

pub static GIT_HANDLER: GitHandler = GitHandler;

pub struct GitHandler;

const SAFE_SUBCOMMANDS: &[&str] = &[
    "status",
    "log",
    "show",
    "diff",
    "blame",
    "annotate",
    "shortlog",
    "describe",
    "rev-parse",
    "rev-list",
    "reflog",
    "whatchanged",
    "diff-tree",
    "diff-files",
    "diff-index",
    "range-diff",
    "format-patch",
    "difftool",
    "grep",
    "ls-files",
    "ls-tree",
    "ls-remote",
    "cat-file",
    "verify-commit",
    "verify-tag",
    "name-rev",
    "merge-base",
    "show-ref",
    "show-branch",
    "check-ignore",
    "cherry",
    "for-each-ref",
    "count-objects",
    "fsck",
    "var",
    "request-pull",
    "archive",
    "fetch",
    "version",
    "help",
];

const ASK_SUBCOMMANDS: &[&str] = &[
    "commit",
    "add",
    "rm",
    "mv",
    "restore",
    "reset",
    "revert",
    "push",
    "pull",
    "checkout",
    "switch",
    "merge",
    "rebase",
    "cherry-pick",
    "clean",
    "gc",
    "prune",
    "filter-branch",
    "filter-repo",
    "submodule",
    "worktree",
    "init",
    "clone",
    "am",
    "apply",
];

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
];

impl Handler for GitHandler {
    fn commands(&self) -> &[&str] {
        &["git"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        // Check if -C, --git-dir, or --work-tree points outside allowed scope
        if let Some(verdict) = check_repo_path_flags(ctx) {
            return verdict;
        }

        let (sub, sub_args) = extract_subcommand(ctx.args);
        let desc = format!("git {sub}");

        if sub.is_empty() {
            return Classification::Allow("git (no subcommand)".into());
        }

        if SAFE_SUBCOMMANDS.contains(&sub.as_str()) {
            return Classification::Allow(desc);
        }

        if ASK_SUBCOMMANDS.contains(&sub.as_str()) {
            return Classification::Ask(desc);
        }

        // Complex subcommands with sub-subcommand analysis
        match sub.as_str() {
            "branch" => classify_branch(&sub_args),
            "tag" => classify_tag(&sub_args),
            "remote" => classify_remote(&sub_args),
            "stash" => classify_stash(&sub_args),
            "config" => classify_config(&sub_args),
            "notes" => classify_notes(&sub_args),
            "bisect" => classify_bisect(&sub_args),
            "lfs" => classify_lfs(&sub_args),
            _ => Classification::Ask(desc),
        }
    }
}

/// Flags that redirect git to a different repository location. `-C` takes a
/// separate value argument; `--git-dir`/`--work-tree` accept either a separate
/// value or an attached `=` form (`--git-dir=PATH`).
const REPO_PATH_FLAGS: &[&str] = &["-C", "--git-dir", "--work-tree"];

/// Repo-redirect flags that also support the attached `--flag=PATH` form.
const REPO_PATH_EQ_FLAGS: &[&str] = &["--git-dir", "--work-tree"];

/// If git is invoked with -C, --git-dir, or --work-tree pointing outside
/// the allowed scope, return Ask. Otherwise return None to continue
/// normal classification. Both the separated (`--git-dir PATH`) and attached
/// (`--git-dir=PATH`) forms are checked so the redirect cannot be smuggled past
/// the scope guard.
fn check_repo_path_flags(ctx: &HandlerContext) -> Option<Classification> {
    let normalized_cwd = normalize_path(ctx.working_directory);
    let mut i = 0;
    while i < ctx.args.len() {
        let arg = ctx.args[i].as_str();
        if let Some((flag, value)) = repo_redirect_target(arg, ctx.args.get(i + 1)) {
            if let Some(verdict) = repo_flag_out_of_scope(flag, value, &normalized_cwd, ctx) {
                return Some(verdict);
            }
            // The attached `=` form consumes one arg; the separated form two.
            i += if arg.contains('=') { 1 } else { 2 };
            continue;
        }
        i += 1;
    }
    None
}

/// If `arg` is a repo-redirect flag, return the `(flag-label, target-path)` it
/// points at — handling both `--git-dir PATH` (value in `next`) and the
/// attached `--git-dir=PATH` form.
fn repo_redirect_target<'a>(arg: &'a str, next: Option<&'a String>) -> Option<(&'a str, &'a str)> {
    if REPO_PATH_FLAGS.contains(&arg) {
        return next.map(|v| (arg, v.as_str()));
    }
    for flag in REPO_PATH_EQ_FLAGS {
        if let Some(value) = arg
            .strip_prefix(flag)
            .and_then(|rest| rest.strip_prefix('='))
        {
            return Some((flag, value));
        }
    }
    None
}

/// Return `Ask` when a repo-redirect flag targets a path outside the allowed
/// scope, otherwise `None`.
fn repo_flag_out_of_scope(
    flag: &str,
    value: &str,
    normalized_cwd: &Path,
    ctx: &HandlerContext,
) -> Option<Classification> {
    let resolved = if Path::new(value).is_absolute() {
        normalize_path(Path::new(value))
    } else {
        normalize_path(&ctx.working_directory.join(value))
    };
    if is_within_scope(&resolved, normalized_cwd, ctx.safe_scopes) {
        None
    } else {
        Some(Classification::Ask(format!(
            "git {flag} targets outside allowed scope ({value})"
        )))
    }
}

fn extract_subcommand(args: &[String]) -> (String, Vec<String>) {
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if GLOBAL_VALUE_FLAGS.contains(&arg.as_str()) {
            i += 2; // skip flag and its value
            continue;
        }
        if GLOBAL_FLAGS.contains(&arg.as_str()) {
            i += 1;
            continue;
        }
        if arg.starts_with('-') {
            i += 1;
            continue;
        }
        return (arg.clone(), args[i + 1..].to_vec());
    }
    (String::new(), Vec::new())
}

fn classify_branch(args: &[String]) -> Classification {
    if has_flag(
        args,
        &["-d", "-D", "-m", "-M", "-c", "-C", "--set-upstream-to"],
    ) {
        Classification::Ask("git branch (modify)".into())
    } else {
        Classification::Allow("git branch (list)".into())
    }
}

fn classify_tag(args: &[String]) -> Classification {
    if has_flag(args, &["-d", "--delete"]) {
        Classification::Ask("git tag (delete)".into())
    } else if args.iter().any(|a| !a.starts_with('-')) {
        Classification::Ask("git tag (create)".into())
    } else {
        Classification::Allow("git tag (list)".into())
    }
}

fn classify_remote(args: &[String]) -> Classification {
    let sub = args.first().map_or("", String::as_str);
    match sub {
        "show" | "" => Classification::Allow("git remote (view)".into()),
        "get-url" => Classification::Allow("git remote get-url".into()),
        _ => Classification::Ask(format!("git remote {sub}")),
    }
}

fn classify_stash(args: &[String]) -> Classification {
    let sub = args.first().map_or("", String::as_str);
    match sub {
        "list" | "show" => Classification::Allow(format!("git stash {sub}")),
        "" => Classification::Ask("git stash".into()),
        _ => Classification::Ask(format!("git stash {sub}")),
    }
}

fn classify_config(args: &[String]) -> Classification {
    if has_flag(
        args,
        &["--get", "--get-all", "--list", "-l", "--get-regexp"],
    ) {
        Classification::Allow("git config (read)".into())
    } else if has_flag(args, &["--unset", "--add", "--edit", "--replace-all"]) {
        Classification::Ask("git config (write)".into())
    } else if args.len() <= 1 {
        // Single key read
        Classification::Allow("git config (read)".into())
    } else {
        Classification::Ask("git config (write)".into())
    }
}

fn classify_notes(args: &[String]) -> Classification {
    let sub = args.first().map_or("", String::as_str);
    match sub {
        "list" | "show" | "" => Classification::Allow(format!("git notes {sub}")),
        _ => Classification::Ask(format!("git notes {sub}")),
    }
}

fn classify_bisect(args: &[String]) -> Classification {
    let sub = args.first().map_or("", String::as_str);
    match sub {
        "log" | "visualize" | "view" => Classification::Allow(format!("git bisect {sub}")),
        _ => Classification::Ask(format!("git bisect {sub}")),
    }
}

fn classify_lfs(args: &[String]) -> Classification {
    let sub = args.first().map_or("", String::as_str);
    match sub {
        "fetch" | "ls-files" | "status" | "env" | "version" => {
            Classification::Allow(format!("git lfs {sub}"))
        }
        _ => Classification::Ask(format!("git lfs {sub}")),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {

    use super::*;

    // Pure subcommand->decision cases (safe/ask subcommands, branch -d, stash list,
    // tag) and ABSOLUTE out-of-scope repo redirects are covered by the catalog
    // (tests/data/catalog/handlers_git.toml). The tests below need injected state
    // the catalog cannot reach: a cwd-relative/in-project target (fixed `/tmp` cwd)
    // or a non-empty `safe_scopes`.
    #[test]
    fn global_flags_skipped() {
        let args = vec!["-C".into(), "/tmp".into(), "status".into()];
        let result = GIT_HANDLER.classify(&HandlerContext::test("git", &args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn git_dir_eq_within_declared_scope_allows() {
        let allowed = vec![std::path::PathBuf::from("/opt/repos")];
        let args = vec!["--git-dir=/opt/repos/other/.git".into(), "log".into()];
        let ctx = HandlerContext {
            safe_scopes: &allowed,
            ..HandlerContext::test("git", &args)
        };
        assert!(matches!(
            GIT_HANDLER.classify(&ctx),
            Classification::Allow(_)
        ));
    }

    #[test]
    fn git_dir_eq_within_project_allows() {
        // `=` form pointing inside the project directory still resolves normally.
        let args = vec!["--git-dir=/tmp/sub/.git".into(), "status".into()];
        let result = GIT_HANDLER.classify(&HandlerContext::test("git", &args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn dash_c_within_project_allows() {
        let args = vec!["-C".into(), "/tmp/subdir".into(), "status".into()];
        let result = GIT_HANDLER.classify(&HandlerContext::test("git", &args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn dash_c_relative_allows() {
        let args = vec!["-C".into(), "subdir".into(), "status".into()];
        let result = GIT_HANDLER.classify(&HandlerContext::test("git", &args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    // Rejected-widening guard: read-only `git -C <undeclared> log` must still
    // Ask. An arbitrary repo's `.git/config` (pager/alias) can run code even on
    // a "read" subcommand, so scope opt-in is required — see #134.
    #[test]
    fn dash_c_undeclared_read_only_still_asks() {
        let args = vec!["-C".into(), "/opt/other-repo".into(), "log".into()];
        let result = GIT_HANDLER.classify(&HandlerContext::test("git", &args));
        assert!(matches!(result, Classification::Ask(_)));
    }

    // Within a declared scope, the same read-only command is allowed (parity).
    #[test]
    fn dash_c_declared_scope_read_only_allows() {
        let allowed = vec![std::path::PathBuf::from("/opt/repos")];
        let args = vec!["-C".into(), "/opt/repos/other".into(), "log".into()];
        let ctx = HandlerContext {
            safe_scopes: &allowed,
            ..HandlerContext::test("git", &args)
        };
        assert!(matches!(
            GIT_HANDLER.classify(&ctx),
            Classification::Allow(_)
        ));
    }

    // Within a declared scope, a writing subcommand still Asks (write guard).
    #[test]
    fn dash_c_declared_scope_write_still_asks() {
        let allowed = vec![std::path::PathBuf::from("/opt/repos")];
        let args = vec!["-C".into(), "/opt/repos/other".into(), "push".into()];
        let ctx = HandlerContext {
            safe_scopes: &allowed,
            ..HandlerContext::test("git", &args)
        };
        assert!(matches!(GIT_HANDLER.classify(&ctx), Classification::Ask(_)));
    }

    #[test]
    fn dash_c_config_allowed() {
        let allowed = vec![std::path::PathBuf::from("/opt/repos")];
        let args = vec!["-C".into(), "/opt/repos/other".into(), "status".into()];
        let ctx = HandlerContext {
            safe_scopes: &allowed,
            ..HandlerContext::test("git", &args)
        };
        assert!(matches!(
            GIT_HANDLER.classify(&ctx),
            Classification::Allow(_)
        ));
    }
}
