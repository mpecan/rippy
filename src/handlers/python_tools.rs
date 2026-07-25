use super::{AllowEntry, Classification, Handler, HandlerContext, has_flag, surface};
use crate::verdict::AllowReason;

// uv

pub(crate) static UV_HANDLER: UvHandler = UvHandler;

pub(crate) struct UvHandler;

const UV_SAFE: &[&str] = &["sync", "lock", "tree", "version", "help", "venv", "export"];

/// `uv` groups whose second token decides safety.
const UV_NESTED_SAFE: &[(&str, &[&str])] = &[
    ("pip", &["list", "freeze", "show", "check", "tree"]),
    ("python", &["list", "find", "dir"]),
    ("cache", &["dir"]),
];

impl Handler for UvHandler {
    fn commands(&self) -> &[&str] {
        &["uv", "uvx"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if ctx.command_name == "uvx" {
            return Classification::Ask(format!(
                "uvx {}",
                ctx.args.first().map_or("", String::as_str)
            ));
        }

        let sub = ctx.args.first().map_or("", String::as_str);

        if UV_SAFE.contains(&sub) {
            return Classification::Allow(AllowReason::handler(format!("uv {sub}")));
        }

        if sub == "run" {
            // Delegate inner command
            let inner: Vec<&str> = ctx.args[1..]
                .iter()
                .skip_while(|a| a.starts_with('-'))
                .map(String::as_str)
                .collect();
            if inner.is_empty() {
                return Classification::Ask("uv run (no command)".into());
            }
            return Classification::Recurse(inner.join(" "));
        }

        for (parent, safe) in UV_NESTED_SAFE {
            if sub == *parent {
                let child = ctx.args.get(1).map_or("", String::as_str);
                return if safe.contains(&child) {
                    Classification::Allow(AllowReason::handler(format!("uv {parent} {child}")))
                } else {
                    Classification::Ask(format!("uv {parent} {child}"))
                };
            }
        }

        Classification::Ask(format!("uv {sub}"))
    }

    fn allow_surface(&self) -> Vec<AllowEntry> {
        // `uvx` always asks and `uv run` re-analyzes its inner command.
        let mut entries = surface::subcommands("uv", UV_SAFE);
        for (parent, safe) in UV_NESTED_SAFE {
            entries.extend(surface::subcommands(&format!("uv {parent}"), safe));
        }
        entries
    }
}

// ruff

pub(crate) static RUFF_HANDLER: RuffHandler = RuffHandler;

pub(crate) struct RuffHandler;

impl Handler for RuffHandler {
    fn commands(&self) -> &[&str] {
        &["ruff"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        let sub = ctx.args.first().map_or("", String::as_str);
        if sub == "format" || sub == "clean" || has_flag(ctx.args, &["--fix", "--fix-only"]) {
            return Classification::Ask(format!("ruff {sub} (modifying)"));
        }
        Classification::Allow(AllowReason::handler(format!("ruff {sub}")))
    }

    fn allow_surface(&self) -> Vec<AllowEntry> {
        vec![AllowEntry::guarded(
            "ruff <subcommand>",
            "subcommand is neither `format` nor `clean`, and neither --fix nor --fix-only present",
        )]
    }
}

// black

pub(crate) static BLACK_HANDLER: BlackHandler = BlackHandler;

pub(crate) struct BlackHandler;

impl Handler for BlackHandler {
    fn commands(&self) -> &[&str] {
        &["black"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if has_flag(ctx.args, &["--check", "--diff"]) {
            return Classification::Allow(AllowReason::handler("black (check only)"));
        }
        Classification::Ask("black (format)".into())
    }

    fn allow_surface(&self) -> Vec<AllowEntry> {
        vec![AllowEntry::new("black --check|--diff")]
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    // uv sync / uv pip list / ruff / black command->decision cases are covered by
    // tests/data/catalog/handlers_task_runners.toml. This test asserts the Recurse
    // variant for `uv run`, which a command string cannot express.
    #[test]
    fn uv_run_recurses() {
        let args: Vec<String> = vec!["run".into(), "python".into()];
        let result = UV_HANDLER.classify(&HandlerContext::test("uv", &args));
        assert!(matches!(result, Classification::Recurse(_)));
    }
}
