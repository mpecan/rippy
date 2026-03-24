use super::{Classification, Handler, HandlerContext, first_positional, get_flag_value, has_flag};
use crate::python_safety::is_python_source_safe;

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

        // -c inline code — analyze source for dangerous patterns
        if let Some(source) = get_flag_value(ctx.args, &["-c"]) {
            return if is_python_source_safe(&source) {
                Classification::Allow("python -c (safe inline code)".into())
            } else {
                Classification::Ask("python -c (potentially dangerous code)".into())
            };
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

        // Script execution — try to read and analyze the file
        let script = first_positional(ctx.args).unwrap_or("");
        if let Some(source) = ctx.read_file(script) {
            return if is_python_source_safe(&source) {
                Classification::Allow(format!("python {script} (safe script)"))
            } else {
                Classification::Ask(format!("python {script} (potentially dangerous)"))
            };
        }
        Classification::Ask("python script execution".into())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::path::Path;

    use super::*;

    fn ctx(args: &[String]) -> HandlerContext<'_> {
        HandlerContext {
            command_name: "python",
            args,
            working_directory: Path::new("/tmp"),
            remote: false,
        }
    }

    #[test]
    fn version_allows() {
        let args = vec!["--version".into()];
        let result = PYTHON_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn c_safe_print_allows() {
        let args = vec!["-c".into(), "print(1)".into()];
        let result = PYTHON_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn c_import_json_allows() {
        let args = vec!["-c".into(), "import json; print(json.dumps({}))".into()];
        let result = PYTHON_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn c_import_os_asks() {
        let args = vec!["-c".into(), "import os; os.system('ls')".into()];
        let result = PYTHON_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Ask(_)));
    }

    #[test]
    fn c_eval_asks() {
        let args = vec!["-c".into(), "eval('1+1')".into()];
        let result = PYTHON_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Ask(_)));
    }

    #[test]
    fn script_file_asks() {
        let args = vec!["script.py".into()];
        let result = PYTHON_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Ask(_)));
    }

    #[test]
    fn no_args_asks() {
        let args: Vec<String> = vec![];
        let result = PYTHON_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Ask(_)));
    }

    #[test]
    fn m_safe_module_allows() {
        let args = vec!["-m".into(), "json.tool".into()];
        let result = PYTHON_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn m_unknown_module_asks() {
        let args = vec!["-m".into(), "http.server".into()];
        let result = PYTHON_HANDLER.classify(&ctx(&args));
        assert!(matches!(result, Classification::Ask(_)));
    }

    #[test]
    fn script_file_safe_allows() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("safe.py"),
            "import json\nprint(json.dumps({}))",
        )
        .unwrap();
        let args = vec!["safe.py".into()];
        let ctx = HandlerContext {
            command_name: "python",
            args: &args,
            working_directory: dir.path(),
            remote: false,
        };
        let result = PYTHON_HANDLER.classify(&ctx);
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn script_file_dangerous_asks() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("evil.py"),
            "import os\nos.system('rm -rf /')",
        )
        .unwrap();
        let args = vec!["evil.py".into()];
        let ctx = HandlerContext {
            command_name: "python",
            args: &args,
            working_directory: dir.path(),
            remote: false,
        };
        let result = PYTHON_HANDLER.classify(&ctx);
        assert!(matches!(result, Classification::Ask(_)));
    }

    #[test]
    fn script_file_missing_asks() {
        let dir = tempfile::tempdir().unwrap();
        let args = vec!["missing.py".into()];
        let ctx = HandlerContext {
            command_name: "python",
            args: &args,
            working_directory: dir.path(),
            remote: false,
        };
        let result = PYTHON_HANDLER.classify(&ctx);
        assert!(matches!(result, Classification::Ask(_)));
    }
}
