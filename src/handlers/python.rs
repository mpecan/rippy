use super::{Classification, Handler, HandlerContext, has_flag};

pub static PYTHON_HANDLER: PythonHandler = PythonHandler;

pub struct PythonHandler;

impl Handler for PythonHandler {
    fn commands(&self) -> &[&str] {
        &[
            "python",
            "python3",
            "python3.8",
            "python3.9",
            "python3.10",
            "python3.11",
            "python3.12",
            "python3.13",
            "python3.14",
        ]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if has_flag(ctx.args, &["--version", "-V", "-VV", "--help", "-h"]) {
            return Classification::Allow("python version/help".into());
        }

        // -c inline code
        if has_flag(ctx.args, &["-c"]) {
            return Classification::Ask("python -c (inline code execution)".into());
        }

        // -m module
        if has_flag(ctx.args, &["-m"]) {
            let module = ctx
                .args
                .iter()
                .skip_while(|a| a.as_str() != "-m")
                .nth(1)
                .map_or("", String::as_str);
            return match module {
                "calendar" | "json.tool" | "this" | "antigravity" => {
                    Classification::Allow(format!("python -m {module}"))
                }
                _ => Classification::Ask(format!("python -m {module}")),
            };
        }

        // -i interactive
        if has_flag(ctx.args, &["-i"]) {
            return Classification::Ask("python -i (interactive)".into());
        }

        // No args = interactive
        if ctx.args.is_empty() {
            return Classification::Ask("python (interactive)".into());
        }

        // Script execution
        Classification::Ask("python script execution".into())
    }
}
