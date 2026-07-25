use super::{
    AllowEntry, Classification, Handler, HandlerContext, first_positional, get_flag_value,
    has_flag, is_sole_help_flag, surface,
};
use crate::python_safety::is_python_source_safe;
use crate::verdict::AllowReason;

pub(crate) static PYTHON_HANDLER: PythonHandler = PythonHandler;

pub(crate) struct PythonHandler;

/// Stdlib modules `-m` may run: they print and exit, taking no code from argv.
const SAFE_MODULES: &[&str] = &["calendar", "json.tool", "this", "antigravity"];

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
        if is_sole_help_flag(ctx.args, &["--version", "-V", "-VV", "--help", "-h"]) {
            return Classification::Allow(AllowReason::handler("python version/help"));
        }

        // -c inline code — analyze source for dangerous patterns
        if let Some(source) = get_flag_value(ctx.args, &["-c"]) {
            return if is_python_source_safe(&source) {
                Classification::Allow(AllowReason::handler("python -c (safe inline code)"))
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
            return if SAFE_MODULES.contains(&module) {
                Classification::Allow(AllowReason::handler(format!("python -m {module}")))
            } else {
                Classification::Ask(format!("python -m {module}"))
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
                Classification::Allow(AllowReason::handler(format!(
                    "python {script} (safe script)"
                )))
            } else {
                Classification::Ask(format!("python {script} (potentially dangerous)"))
            };
        }
        Classification::Ask("python script execution".into())
    }

    fn allow_surface(&self) -> Vec<AllowEntry> {
        let safe_source = "source passes the analysis in src/python_safety.rs";
        let mut entries = vec![
            AllowEntry::guarded("python --version|-V|-VV|--help|-h", "sole argument"),
            AllowEntry::guarded("python -c <code>", safe_source),
        ];
        entries.extend(surface::subcommands("python -m", SAFE_MODULES));
        entries.push(AllowEntry::guarded(
            "python <script>",
            format!("script readable from the working directory and its {safe_source}"),
        ));
        entries
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used)]
mod tests {

    use super::*;

    // Command->decision cases (version/-c inline/-m/no-args/missing-script) are
    // covered by tests/data/catalog/handlers_interpreters.toml. The remaining
    // tests exercise read_file, which the catalog cannot inject.
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
            working_directory: dir.path(),
            ..HandlerContext::test("python", &args)
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
            working_directory: dir.path(),
            ..HandlerContext::test("python", &args)
        };
        let result = PYTHON_HANDLER.classify(&ctx);
        assert!(matches!(result, Classification::Ask(_)));
    }

    #[test]
    fn script_file_missing_asks() {
        let dir = tempfile::tempdir().unwrap();
        let args = vec!["missing.py".into()];
        let ctx = HandlerContext {
            working_directory: dir.path(),
            ..HandlerContext::test("python", &args)
        };
        let result = PYTHON_HANDLER.classify(&ctx);
        assert!(matches!(result, Classification::Ask(_)));
    }
}
