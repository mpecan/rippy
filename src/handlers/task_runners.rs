use super::{Classification, Handler, HandlerContext, has_flag};

// ---- just ----

pub static JUST_HANDLER: JustHandler = JustHandler;

pub struct JustHandler;

/// Read-only introspection flags that make `just` print-and-exit.
/// These short-circuit recipe execution even when a recipe name trails them,
/// so allowing on their presence is safe. Never add run-capable flags here
/// (e.g. --fmt, --init, --choose, --set).
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
        if has_flag(ctx.args, READONLY_JUST_FLAGS) {
            return Classification::Allow("just (introspection)".into());
        }
        // Bare `just` runs the default recipe (arbitrary code); a bare recipe
        // name runs that recipe. Both must Ask.
        let sub = ctx.args.first().map_or("", String::as_str);
        Classification::Ask(format!("just {sub}"))
    }
}

// ---- mise ----

pub static MISE_HANDLER: MiseHandler = MiseHandler;

pub struct MiseHandler;

/// Read-only mise subcommands. Excludes run/exec/install/use/up/set/config/
/// plugin/activate and friends, which execute code or mutate state.
const MISE_SAFE: &[&str] = &[
    "tasks",
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

impl Handler for MiseHandler {
    fn commands(&self) -> &[&str] {
        &["mise"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        let sub = ctx.args.first().map_or("", String::as_str);
        if MISE_SAFE.contains(&sub) {
            return Classification::Allow(format!("mise {sub}"));
        }
        Classification::Ask(format!("mise {sub}"))
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
    use std::path::Path;

    use super::*;

    fn ctx<'a>(args: &'a [String], cmd: &'a str) -> HandlerContext<'a> {
        HandlerContext {
            command_name: cmd,
            args,
            working_directory: Path::new("/tmp"),
            remote: false,
            receives_piped_input: false,
            cd_allowed_dirs: &[],
        }
    }

    fn classify_just(args: &[&str]) -> Classification {
        let owned: Vec<String> = args.iter().map(|s| (*s).into()).collect();
        JUST_HANDLER.classify(&ctx(&owned, "just"))
    }

    fn classify_mise(args: &[&str]) -> Classification {
        let owned: Vec<String> = args.iter().map(|s| (*s).into()).collect();
        MISE_HANDLER.classify(&ctx(&owned, "mise"))
    }

    fn classify_tokf(args: &[&str]) -> Classification {
        let owned: Vec<String> = args.iter().map(|s| (*s).into()).collect();
        TOKF_HANDLER.classify(&ctx(&owned, "tokf"))
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
