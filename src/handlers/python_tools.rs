use super::{Classification, Handler, HandlerContext, has_flag};

// uv

pub(crate) static UV_HANDLER: UvHandler = UvHandler;

pub(crate) struct UvHandler;

const UV_SAFE: &[&str] = &["sync", "lock", "tree", "version", "help", "venv", "export"];

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
            return Classification::Allow(format!("uv {sub}"));
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

        if sub == "pip" {
            let pip_sub = ctx.args.get(1).map_or("", String::as_str);
            return match pip_sub {
                "list" | "freeze" | "show" | "check" | "tree" => {
                    Classification::Allow(format!("uv pip {pip_sub}"))
                }
                _ => Classification::Ask(format!("uv pip {pip_sub}")),
            };
        }

        if sub == "python" {
            let py_sub = ctx.args.get(1).map_or("", String::as_str);
            return match py_sub {
                "list" | "find" | "dir" => Classification::Allow(format!("uv python {py_sub}")),
                _ => Classification::Ask(format!("uv python {py_sub}")),
            };
        }

        if sub == "cache" {
            let cache_sub = ctx.args.get(1).map_or("", String::as_str);
            return match cache_sub {
                "dir" => Classification::Allow("uv cache dir".into()),
                _ => Classification::Ask(format!("uv cache {cache_sub}")),
            };
        }

        Classification::Ask(format!("uv {sub}"))
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
        Classification::Allow(format!("ruff {sub}"))
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
            return Classification::Allow("black (check only)".into());
        }
        Classification::Ask("black (format)".into())
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
