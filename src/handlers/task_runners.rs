use super::{Classification, Handler, HandlerContext, first_positional};

// ---- just ----

pub static JUST_HANDLER: JustHandler = JustHandler;

pub struct JustHandler;

/// Read-only introspection flags that make `just` print-and-exit.
/// These only short-circuit recipe execution when they appear BEFORE any recipe
/// name. Once a recipe name is seen, `just` passes trailing args (including
/// these flags) to the recipe and RUNS it — e.g. `just deploy --list` executes
/// `deploy` with `--list` as an argument. So we only treat them as introspection
/// when no positional (recipe) token precedes them. Never add run-capable flags
/// here (e.g. --fmt, --init, --choose, --set).
const READONLY_JUST_FLAGS: &[&str] = &[
    "--list",
    "-l",
    "--summary",
    "--dump",
    "--variables",
    "--evaluate",
    "--show",
    "-s",
];

impl Handler for JustHandler {
    fn commands(&self) -> &[&str] {
        &["just"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        // Only the leading run of flags (before the first recipe name) is
        // interpreted by `just` itself; a read-only flag there is introspection.
        let introspection = ctx
            .args
            .iter()
            .take_while(|a| a.starts_with('-'))
            .any(|a| READONLY_JUST_FLAGS.contains(&a.as_str()));
        if introspection {
            return Classification::Allow("just (introspection)".into());
        }
        // Bare `just` runs the default recipe (arbitrary code); a bare recipe
        // name (optionally with trailing flags) runs that recipe. Both must Ask.
        let sub = ctx.args.first().map_or("", String::as_str);
        Classification::Ask(format!("just {sub}"))
    }
}

// ---- mise ----

pub static MISE_HANDLER: MiseHandler = MiseHandler;

pub struct MiseHandler;

/// Read-only mise subcommands. Excludes run/exec/install/use/up/set/config/
/// plugin/activate and friends, which execute code or mutate state. `tasks` is
/// handled separately because it has execution/mutation child subcommands.
const MISE_SAFE: &[&str] = &[
    "ls",
    "list",
    "current",
    "doctor",
    "dr",
    "env",
    "where",
    "which",
    "bin-paths",
    "ls-remote",
    "version",
];

/// `mise tasks` child subcommands that execute a task or mutate/launch an
/// editor. Everything else under `mise tasks` (ls/info/deps/validate, a bare
/// task name for info, or no child at all) is read-only. `r` is the alias for
/// `run`.
const MISE_TASKS_UNSAFE: &[&str] = &["run", "r", "add", "edit"];

impl Handler for MiseHandler {
    fn commands(&self) -> &[&str] {
        &["mise"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        let sub = ctx.args.first().map_or("", String::as_str);
        if sub == "tasks" {
            return classify_mise_tasks(ctx);
        }
        if MISE_SAFE.contains(&sub) {
            return Classification::Allow(format!("mise {sub}"));
        }
        Classification::Ask(format!("mise {sub}"))
    }
}

/// Classify `mise tasks ...`. Bare `tasks` lists tasks (read-only), but the
/// `run`/`r`/`add`/`edit` child subcommands execute or mutate, so they Ask.
fn classify_mise_tasks(ctx: &HandlerContext) -> Classification {
    // args[0] == "tasks"; inspect the first positional child (skip flags).
    let child = first_positional(&ctx.args[1..]).unwrap_or("");
    if MISE_TASKS_UNSAFE.contains(&child) {
        return Classification::Ask(format!("mise tasks {child}"));
    }
    if child.is_empty() {
        Classification::Allow("mise tasks".into())
    } else {
        Classification::Allow(format!("mise tasks {child}"))
    }
}

// ---- tokf ----

pub static TOKF_HANDLER: TokfHandler = TokfHandler;

pub struct TokfHandler;

/// Read-only tokf subcommands. Excludes config/cache/history (mutate state)
/// and network/auth subcommands, which fall through to Ask.
const TOKF_SAFE: &[&str] = &[
    "raw",
    "ls",
    "which",
    "show",
    "info",
    "gain",
    "check",
    "apply",
    "verify",
    "discover",
    "doctor",
    "completions",
    "rewrite",
];

/// tokf subcommands that wrap and run an arbitrary inner command.
const TOKF_WRAPPERS: &[&str] = &["run", "err", "test", "summary"];

impl Handler for TokfHandler {
    fn commands(&self) -> &[&str] {
        &["tokf"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        let sub = ctx.args.first().map_or("", String::as_str);

        if TOKF_SAFE.contains(&sub) {
            return Classification::Allow(format!("tokf {sub}"));
        }

        if TOKF_WRAPPERS.contains(&sub) {
            let inner: Vec<&str> = ctx.args[1..]
                .iter()
                .skip_while(|a| a.starts_with('-'))
                .map(String::as_str)
                .collect();
            if inner.is_empty() {
                return Classification::Ask(format!("tokf {sub} (no command)"));
            }
            return Classification::Recurse(inner.join(" "));
        }

        Classification::Ask(format!("tokf {sub}"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {

    use super::*;

    fn classify_just(args: &[&str]) -> Classification {
        let owned: Vec<String> = args.iter().map(|s| (*s).into()).collect();
        JUST_HANDLER.classify(&HandlerContext::test("just", &owned))
    }

    fn classify_mise(args: &[&str]) -> Classification {
        let owned: Vec<String> = args.iter().map(|s| (*s).into()).collect();
        MISE_HANDLER.classify(&HandlerContext::test("mise", &owned))
    }

    fn classify_tokf(args: &[&str]) -> Classification {
        let owned: Vec<String> = args.iter().map(|s| (*s).into()).collect();
        TOKF_HANDLER.classify(&HandlerContext::test("tokf", &owned))
    }

    // ---- just ----

    #[test]
    fn just_list_allows() {
        assert!(matches!(
            classify_just(&["--list"]),
            Classification::Allow(_)
        ));
    }

    #[test]
    fn just_summary_allows() {
        assert!(matches!(
            classify_just(&["--summary"]),
            Classification::Allow(_)
        ));
    }

    #[test]
    fn just_dump_allows() {
        assert!(matches!(
            classify_just(&["--dump"]),
            Classification::Allow(_)
        ));
    }

    #[test]
    fn just_show_allows() {
        assert!(matches!(
            classify_just(&["--show", "build"]),
            Classification::Allow(_)
        ));
    }

    #[test]
    fn just_recipe_asks() {
        assert!(matches!(classify_just(&["build"]), Classification::Ask(_)));
    }

    #[test]
    fn just_bare_asks() {
        // Bare `just` runs the default recipe = arbitrary code. Must Ask.
        assert!(matches!(classify_just(&[]), Classification::Ask(_)));
    }

    #[test]
    fn just_fmt_asks() {
        assert!(matches!(classify_just(&["--fmt"]), Classification::Ask(_)));
    }

    #[test]
    fn just_short_flags_allow() {
        // Leading read-only short/long flags are introspection.
        for flag in ["-l", "-s", "--variables", "--evaluate"] {
            assert!(
                matches!(classify_just(&[flag]), Classification::Allow(_)),
                "expected Allow for `just {flag}`"
            );
        }
    }

    #[test]
    fn just_flag_after_recipe_asks() {
        // A read-only flag placed AFTER a recipe name is a recipe argument and
        // `just` RUNS the recipe. Must Ask, never Allow. (Issue #135 regression)
        for flag in [
            "--list",
            "--dump",
            "--show",
            "-l",
            "-s",
            "--evaluate",
            "--variables",
        ] {
            assert!(
                matches!(classify_just(&["deploy", flag]), Classification::Ask(_)),
                "expected Ask for `just deploy {flag}`"
            );
        }
        assert!(matches!(
            classify_just(&["build", "--list"]),
            Classification::Ask(_)
        ));
    }

    // ---- mise ----

    #[test]
    fn mise_tasks_allows() {
        assert!(matches!(
            classify_mise(&["tasks"]),
            Classification::Allow(_)
        ));
    }

    #[test]
    fn mise_ls_allows() {
        assert!(matches!(classify_mise(&["ls"]), Classification::Allow(_)));
    }

    #[test]
    fn mise_current_allows() {
        assert!(matches!(
            classify_mise(&["current"]),
            Classification::Allow(_)
        ));
    }

    #[test]
    fn mise_doctor_allows() {
        assert!(matches!(
            classify_mise(&["doctor"]),
            Classification::Allow(_)
        ));
    }

    #[test]
    fn mise_env_allows() {
        assert!(matches!(classify_mise(&["env"]), Classification::Allow(_)));
    }

    #[test]
    fn mise_run_asks() {
        assert!(matches!(
            classify_mise(&["run", "lint"]),
            Classification::Ask(_)
        ));
    }

    #[test]
    fn mise_exec_asks() {
        assert!(matches!(
            classify_mise(&["exec", "--", "rm"]),
            Classification::Ask(_)
        ));
    }

    #[test]
    fn mise_install_asks() {
        assert!(matches!(
            classify_mise(&["install"]),
            Classification::Ask(_)
        ));
    }

    #[test]
    fn mise_use_asks() {
        assert!(matches!(classify_mise(&["use"]), Classification::Ask(_)));
    }

    #[test]
    fn mise_settings_asks() {
        assert!(matches!(
            classify_mise(&["settings"]),
            Classification::Ask(_)
        ));
    }

    #[test]
    fn mise_bare_asks() {
        assert!(matches!(classify_mise(&[]), Classification::Ask(_)));
    }

    #[test]
    fn mise_safe_subcommands_allow() {
        // Every read-only top-level subcommand must Allow (guards typos).
        for sub in MISE_SAFE {
            assert!(
                matches!(classify_mise(&[sub]), Classification::Allow(_)),
                "expected Allow for `mise {sub}`"
            );
        }
    }

    #[test]
    fn mise_tasks_readonly_children_allow() {
        for args in [
            &["tasks"][..],
            &["tasks", "ls"][..],
            &["tasks", "info", "build"][..],
            &["tasks", "deps"][..],
            &["tasks", "validate"][..],
            &["tasks", "--json"][..],
            &["tasks", "somerecipe"][..], // bare task name = info (read-only)
        ] {
            assert!(
                matches!(classify_mise(args), Classification::Allow(_)),
                "expected Allow for `mise {}`",
                args.join(" ")
            );
        }
    }

    #[test]
    fn mise_tasks_run_asks() {
        // `mise tasks run <task>` executes the task. Must Ask. (Issue #135)
        for args in [
            &["tasks", "run", "pwn"][..],
            &["tasks", "r", "pwn"][..],
            &["tasks", "add", "pwn"][..],
            &["tasks", "edit", "pwn"][..],
        ] {
            assert!(
                matches!(classify_mise(args), Classification::Ask(_)),
                "expected Ask for `mise {}`",
                args.join(" ")
            );
        }
    }

    // ---- tokf ----

    #[test]
    fn tokf_raw_allows() {
        assert!(matches!(
            classify_tokf(&["raw", "last"]),
            Classification::Allow(_)
        ));
    }

    #[test]
    fn tokf_ls_allows() {
        assert!(matches!(classify_tokf(&["ls"]), Classification::Allow(_)));
    }

    #[test]
    fn tokf_which_allows() {
        assert!(matches!(
            classify_tokf(&["which", "cargo"]),
            Classification::Allow(_)
        ));
    }

    #[test]
    fn tokf_show_allows() {
        assert!(matches!(
            classify_tokf(&["show", "cargo"]),
            Classification::Allow(_)
        ));
    }

    #[test]
    fn tokf_rewrite_allows() {
        assert!(matches!(
            classify_tokf(&["rewrite"]),
            Classification::Allow(_)
        ));
    }

    #[test]
    fn tokf_run_recurses() {
        assert!(matches!(
            classify_tokf(&["run", "git", "status"]),
            Classification::Recurse(_)
        ));
    }

    #[test]
    fn tokf_err_recurses() {
        assert!(matches!(
            classify_tokf(&["err", "cargo", "build"]),
            Classification::Recurse(_)
        ));
    }

    #[test]
    fn tokf_test_recurses() {
        assert!(matches!(
            classify_tokf(&["test", "cargo", "test"]),
            Classification::Recurse(_)
        ));
    }

    #[test]
    fn tokf_summary_recurses() {
        assert!(matches!(
            classify_tokf(&["summary", "git", "log"]),
            Classification::Recurse(_)
        ));
    }

    #[test]
    fn tokf_test_inner_danger_recurses() {
        // The wrapper strips itself and recurses on the inner command; the
        // analyzer then re-evaluates the danger. The handler yields Recurse
        // with the exact inner command so `rm -rf /` is not hidden.
        assert!(matches!(
            classify_tokf(&["test", "rm", "-rf", "/"]),
            Classification::Recurse(cmd) if cmd == "rm -rf /"
        ));
    }

    #[test]
    fn tokf_wrappers_empty_ask() {
        for w in TOKF_WRAPPERS {
            assert!(
                matches!(classify_tokf(&[w]), Classification::Ask(_)),
                "expected Ask for bare `tokf {w}`"
            );
        }
    }

    #[test]
    fn tokf_safe_subcommands_allow() {
        // Every read-only subcommand must Allow (guards typos in TOKF_SAFE).
        for sub in TOKF_SAFE {
            assert!(
                matches!(classify_tokf(&[sub]), Classification::Allow(_)),
                "expected Allow for `tokf {sub}`"
            );
        }
    }

    #[test]
    fn tokf_run_empty_asks() {
        assert!(matches!(classify_tokf(&["run"]), Classification::Ask(_)));
    }

    #[test]
    fn tokf_config_asks() {
        assert!(matches!(classify_tokf(&["config"]), Classification::Ask(_)));
    }

    #[test]
    fn tokf_cache_asks() {
        assert!(matches!(classify_tokf(&["cache"]), Classification::Ask(_)));
    }

    #[test]
    fn tokf_history_asks() {
        assert!(matches!(
            classify_tokf(&["history"]),
            Classification::Ask(_)
        ));
    }

    #[test]
    fn tokf_search_asks() {
        assert!(matches!(classify_tokf(&["search"]), Classification::Ask(_)));
    }

    #[test]
    fn tokf_unknown_asks() {
        assert!(matches!(
            classify_tokf(&["frobnicate"]),
            Classification::Ask(_)
        ));
    }
}
