use super::{Classification, Handler, HandlerContext, has_flag};

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
        // Skip global flags to find the real subcommand
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
    use std::path::Path;

    use super::*;

    fn ctx(args: &[String]) -> HandlerContext<'_> {
        HandlerContext {
            command_name: "git",
            args,
            working_directory: Path::new("/tmp"),
            remote: false,
        }
    }

    #[test]
    fn safe_commands() {
        for sub in &["status", "log", "diff", "fetch", "show", "blame"] {
            let args = vec![sub.to_string()];
            let result = GIT_HANDLER.classify(&ctx(&args));
            assert!(
                matches!(result, Classification::Allow(_)),
                "expected allow for git {sub}"
            );
        }
    }

    #[test]
    fn ask_commands() {
        for sub in &["commit", "push", "merge", "reset", "checkout"] {
            let args = vec![sub.to_string()];
            let result = GIT_HANDLER.classify(&ctx(&args));
            assert!(
                matches!(result, Classification::Ask(_)),
                "expected ask for git {sub}"
            );
        }
    }

    #[test]
    fn branch_list_is_safe() {
        let args = vec!["branch".into()];
        let result = GIT_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn branch_delete_is_ask() {
        let args = vec!["branch".into(), "-D".into(), "feature".into()];
        let result = GIT_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Ask(_)));
    }

    #[test]
    fn stash_list_is_safe() {
        let args = vec!["stash".into(), "list".into()];
        let result = GIT_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn global_flags_skipped() {
        let args = vec!["-C".into(), "/tmp".into(), "status".into()];
        let result = GIT_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Allow(_)));
    }
}
