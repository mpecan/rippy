use std::path::Path;

use super::{
    AllowEntry, Classification, Handler, HandlerContext, git_subcommands, has_flag,
    is_within_scope, normalize_path, positional_args, surface,
};
use crate::verdict::AllowReason;

pub(crate) static GIT_HANDLER: GitHandler = GitHandler;

pub(crate) struct GitHandler;

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

/// Config keys `-c`/`--config-env` may set without asking. Deliberately an
/// allowlist, not a denylist: any key not listed here (core.pager,
/// core.sshCommand, alias.*, uploadpack.packObjectsHook, protocol.*.allow, ...)
/// can run arbitrary commands via git's config, so unknown keys fail closed.
const SAFE_CONFIG_KEYS: &[&str] = &[
    "user.name",
    "user.email",
    "color.ui",
    "core.autocrlf",
    "core.quotepath",
    "init.defaultbranch",
    "pull.rebase",
    "advice.detachedhead",
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

        if let Some(verdict) = check_config_overrides(ctx.args) {
            return verdict;
        }

        let (sub, sub_args) = extract_subcommand(ctx.args);
        let desc = format!("git {sub}");

        if sub.is_empty() {
            return Classification::Allow(AllowReason::handler("git (no subcommand)"));
        }

        if SAFE_SUBCOMMANDS.contains(&sub.as_str()) {
            return classify_safe_subcommand(&sub, &sub_args, &desc);
        }

        if ASK_SUBCOMMANDS.contains(&sub.as_str()) {
            return Classification::Ask(desc);
        }

        // Complex subcommands with sub-subcommand analysis
        match sub.as_str() {
            "branch" => git_subcommands::classify_branch(&sub_args),
            "tag" => git_subcommands::classify_tag(&sub_args),
            "remote" => git_subcommands::classify_remote(&sub_args),
            "stash" => git_subcommands::classify_stash(&sub_args),
            "config" => git_subcommands::classify_config(&sub_args),
            "notes" => git_subcommands::classify_notes(&sub_args),
            "bisect" => git_subcommands::classify_bisect(&sub_args),
            "lfs" => git_subcommands::classify_lfs(&sub_args),
            _ => Classification::Ask(desc),
        }
    }

    fn allow_surface(&self) -> Vec<AllowEntry> {
        git_allow_surface()
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

/// Scrutinize `-c key=value` and `--config-env` overrides before subcommand
/// dispatch: `extract_subcommand` skips them to find the subcommand, but their
/// key must be checked against `SAFE_CONFIG_KEYS` first, since these can carry
/// RCE-bearing keys (core.pager, core.sshCommand, uploadpack.packObjectsHook, ...).
fn check_config_overrides(args: &[String]) -> Option<Classification> {
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg == "-c" {
            if let Some(kv) = args.get(i + 1)
                && let Some(verdict) = check_config_kv(kv)
            {
                return Some(verdict);
            }
            i += 2;
            continue;
        }
        if let Some(kv) = arg.strip_prefix("--config-env=") {
            if let Some(verdict) = check_config_kv(kv) {
                return Some(verdict);
            }
            i += 1;
            continue;
        }
        if arg == "--config-env" {
            if let Some(kv) = args.get(i + 1)
                && let Some(verdict) = check_config_kv(kv)
            {
                return Some(verdict);
            }
            i += 2;
            continue;
        }
        i += 1;
    }
    None
}

/// `None` when `kv`'s key (case-insensitive, up to the first `=`) is on the
/// safe allowlist; `Some(Ask)` otherwise.
fn check_config_kv(kv: &str) -> Option<Classification> {
    let key = kv.split('=').next().unwrap_or(kv).to_lowercase();
    if SAFE_CONFIG_KEYS.contains(&key.as_str()) {
        None
    } else {
        Some(Classification::Ask(format!(
            "git -c {kv} is not on the safe config allowlist"
        )))
    }
}

/// Dispatch a `SAFE_SUBCOMMANDS` member to its flag-aware classifier, falling
/// through to a plain `Allow` for members with no dangerous flags.
fn classify_safe_subcommand(sub: &str, args: &[String], desc: &str) -> Classification {
    GUARDED_SAFE_SUBCOMMANDS
        .iter()
        .find(|(name, _, _)| *name == sub)
        .map_or_else(
            || Classification::Allow(AllowReason::handler(desc)),
            |(_, _, classify)| classify(args, desc),
        )
}

fn classify_diff(args: &[String], desc: &str) -> Classification {
    if has_flag(args, &["--ext-diff"]) {
        return Classification::Ask("git diff --ext-diff (enables external diff driver)".into());
    }
    classify_output_path(args, &["--output"], &["-o", "--output"], desc)
}

fn classify_archive(args: &[String], desc: &str) -> Classification {
    classify_output_path(args, &["--output"], &["-o", "--output"], desc)
}

fn classify_format_patch(args: &[String], desc: &str) -> Classification {
    classify_output_path(
        args,
        &["--output-directory"],
        &["-o", "--output-directory"],
        desc,
    )
}

/// Flags whose attached (`--flag=PATH`) or separated (`--flag PATH` / `-o PATH`)
/// value names a write target; routes through `WithRedirects` so the existing
/// write-scope pipeline decides Allow (e.g. /tmp) vs Ask.
fn classify_output_path(
    args: &[String],
    eq_flags: &[&str],
    space_flags: &[&str],
    desc: &str,
) -> Classification {
    if let Some(path) = flag_path_value(args, eq_flags, space_flags) {
        return Classification::WithRedirects(AllowReason::handler(desc), vec![path]);
    }
    Classification::Allow(AllowReason::handler(desc))
}

fn flag_path_value(args: &[String], eq_flags: &[&str], space_flags: &[&str]) -> Option<String> {
    for arg in args {
        for flag in eq_flags {
            if let Some(value) = arg
                .strip_prefix(flag)
                .and_then(|rest| rest.strip_prefix('='))
            {
                return Some(value.to_owned());
            }
        }
    }
    let mut i = 0;
    while i < args.len() {
        if space_flags.contains(&args[i].as_str()) {
            return args.get(i + 1).cloned();
        }
        i += 1;
    }
    None
}

/// True if `arg` is a single-dash short-flag cluster (e.g. `-nOid`, `-xid`) that
/// contains `letter` anywhere after the leading dash. Git's getopt-style short
/// options allow a value-taking flag to appear anywhere in the cluster with the
/// remaining characters as its attached value (e.g. `-nOid` = `-n -Oid`), not
/// just as the first character, so this checks containment rather than prefix.
fn short_cluster_contains(arg: &str, letter: char) -> bool {
    arg.starts_with('-') && !arg.starts_with("--") && arg[1..].contains(letter)
}

fn classify_grep(args: &[String], desc: &str) -> Classification {
    let pager_flag = args.iter().any(|a| {
        short_cluster_contains(a, 'O')
            || a == "--open-files-in-pager"
            || a.starts_with("--open-files-in-pager=")
    });
    if pager_flag {
        Classification::Ask(
            "git grep --open-files-in-pager (launches external pager/command)".into(),
        )
    } else {
        Classification::Allow(AllowReason::handler(desc))
    }
}

fn classify_difftool(args: &[String], desc: &str) -> Classification {
    let extcmd_flag = args
        .iter()
        .any(|a| short_cluster_contains(a, 'x') || a == "--extcmd" || a.starts_with("--extcmd="));
    if extcmd_flag {
        Classification::Ask("git difftool --extcmd (launches external command)".into())
    } else {
        Classification::Allow(AllowReason::handler(desc))
    }
}

/// True if `remote` is scp-like remote syntax (`user@host:path` or `host:path`),
/// which git treats as an SSH transport URL causing network egress the same as
/// an explicit `ssh://` URL. Distinguished from local refspecs (e.g.
/// `origin master:master`) by requiring no `/` before the colon, since refspecs
/// name refs (`refs/heads/...`) or branches, not bare hostnames.
fn is_scp_like_remote(remote: &str) -> bool {
    let Some(colon_idx) = remote.find(':') else {
        return false;
    };
    let host_part = &remote[..colon_idx];
    !host_part.is_empty() && !host_part.contains('/') && !host_part.contains('\\')
}

fn classify_fetch(args: &[String], desc: &str) -> Classification {
    let positionals = positional_args(args);
    if let Some(url) = positionals
        .iter()
        .find(|a| a.contains("://") || a.contains("::"))
    {
        return Classification::Ask(format!("git fetch (remote URL: {url})"));
    }
    if let Some(remote) = positionals.first().filter(|r| is_scp_like_remote(r)) {
        return Classification::Ask(format!("git fetch (remote URL: {remote})"));
    }
    Classification::Allow(AllowReason::handler(desc))
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

type SubClassifier = fn(&[String], &str) -> Classification;

/// The `SAFE_SUBCOMMANDS` members whose approval is conditional: the condition,
/// and the classifier that enforces it.
///
/// One table drives both `classify_safe_subcommand` and the catalog guard text,
/// so a new conditional subcommand cannot be documented as unconditional.
const GUARDED_SAFE_SUBCOMMANDS: &[(&str, &str, SubClassifier)] = &[
    (
        "diff",
        "no --ext-diff; an --output target runs the redirect pipeline",
        classify_diff,
    ),
    (
        "archive",
        "an -o/--output target runs the redirect pipeline",
        classify_archive,
    ),
    (
        "format-patch",
        "an -o/--output-directory target runs the redirect pipeline",
        classify_format_patch,
    ),
    ("grep", "no -O/--open-files-in-pager", classify_grep),
    ("difftool", "no -x/--extcmd", classify_difftool),
    (
        "fetch",
        "no URL-like or scp-like remote operand",
        classify_fetch,
    ),
];

fn guard_for(sub: &str) -> &'static str {
    GUARDED_SAFE_SUBCOMMANDS
        .iter()
        .find(|(name, _, _)| *name == sub)
        .map_or("", |(_, guard, _)| *guard)
}

/// Every `git` invocation `classify` approves, as data. Mirrors the dispatch in
/// [`GitHandler::classify`]; see the module constants it reads.
fn git_allow_surface() -> Vec<AllowEntry> {
    let scope_guard = "-C/--git-dir/--work-tree must stay in the cwd or a declared safe \
                       scope, and any -c/--config-env key must be on the safe config-key list";
    let mut entries = vec![
        AllowEntry::guarded("git", format!("no subcommand; {scope_guard}")),
        AllowEntry::guarded(
            "git -c <key>=<value> <subcommand>",
            format!(
                "gate only, not an approval — the key must be one of {}, and the \
                 `<subcommand>` still has to be approved by its own row",
                SAFE_CONFIG_KEYS.join(", ")
            ),
        ),
    ];
    for sub in SAFE_SUBCOMMANDS {
        entries.push(AllowEntry::guarded(format!("git {sub}"), guard_for(sub)));
    }
    entries.push(AllowEntry::guarded(
        "git branch",
        format!("none of {}", git_subcommands::BRANCH_MODIFY_FLAGS.join(" ")),
    ));
    entries.push(AllowEntry::guarded(
        "git tag",
        format!(
            "no positional tag name and none of {}",
            git_subcommands::TAG_DELETE_FLAGS.join(" ")
        ),
    ));
    entries.extend(surface::subcommands(
        "git remote",
        git_subcommands::REMOTE_SAFE,
    ));
    entries.extend(surface::subcommands(
        "git stash",
        git_subcommands::STASH_SAFE,
    ));
    entries.extend(surface::subcommands(
        "git notes",
        git_subcommands::NOTES_SAFE,
    ));
    entries.extend(surface::subcommands(
        "git bisect",
        git_subcommands::BISECT_SAFE,
    ));
    entries.extend(surface::subcommands("git lfs", git_subcommands::LFS_SAFE));
    entries.push(AllowEntry::guarded(
        "git config",
        format!(
            "one of {} present, or at most one argument (bare `git config` included) and \
             none of {}",
            git_subcommands::CONFIG_READ_FLAGS.join(" "),
            git_subcommands::CONFIG_WRITE_FLAGS.join(" ")
        ),
    ));
    entries
}

#[cfg(test)]
mod tests {

    use super::*;

    // Pure subcommand->decision cases (safe/ask subcommands, branch -d, stash list,
    // tag) and ABSOLUTE out-of-scope repo redirects are covered by the catalog
    // (tests/data/catalog/handlers_git.toml). The tests below need injected state
    // the catalog cannot reach: a cwd-relative/in-project target (fixed `/tmp` cwd)
    // or a non-empty `safe_scopes`.
    /// A guarded entry naming a subcommand outside `SAFE_SUBCOMMANDS` never
    /// runs and never renders a catalog row.
    #[test]
    fn every_guarded_subcommand_is_a_safe_subcommand() {
        for (name, guard, _) in GUARDED_SAFE_SUBCOMMANDS {
            assert!(
                SAFE_SUBCOMMANDS.contains(name),
                "{name} is guarded but not in SAFE_SUBCOMMANDS"
            );
            assert!(!guard.is_empty(), "{name} declares an empty guard");
        }
    }

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
