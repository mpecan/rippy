use super::{AllowEntry, Classification, Handler, HandlerContext};
use crate::handlers::script_code;

pub(crate) static SHELL_HANDLER: ShellHandler = ShellHandler;

pub(crate) struct ShellHandler;

impl Handler for ShellHandler {
    fn commands(&self) -> &[&str] {
        &["bash", "sh", "zsh", "dash", "ksh", "fish"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        for (i, arg) in ctx.args.iter().enumerate() {
            if arg == "-c" {
                let Some(inner) = ctx.args.get(i + 1) else {
                    return Classification::Ask(format!("{} -c (no command)", ctx.command_name));
                };
                // If there are positional args after the -c command string,
                // they could be injected via $0/$1. Conservative: return Ask.
                if ctx.args.len() > i + 2 {
                    return Classification::Ask(format!(
                        "{} -c with positional arguments",
                        ctx.command_name
                    ));
                }
                return Classification::Recurse(inner.clone());
            }
        }

        // Script file — try to read and recurse through tree-sitter-bash
        if let Some(script) = ctx.args.first()
            && !script.starts_with('-')
            && let Some(contents) = ctx.read_file(script)
        {
            return Classification::Recurse(contents);
        }

        let script = ctx
            .args
            .iter()
            .find(|a| !a.starts_with('-'))
            .map_or("", String::as_str);
        script_code(ctx, script, format!("{} (interactive)", ctx.command_name))
    }

    /// Empty by design: this handler only re-analyzes a `-c` body or a script's
    /// contents, or asks. It never mints an approval of its own.
    fn allow_surface(&self) -> Vec<AllowEntry> {
        Vec::new()
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used)]
mod tests {

    use super::*;
    use crate::verdict::UncertainKind;

    #[test]
    fn bash_c_simple_recurses() {
        let args: Vec<String> = vec!["-c".into(), "git status".into()];
        let result = SHELL_HANDLER.classify(&HandlerContext::test("bash", &args));
        assert!(matches!(result, Classification::Recurse(cmd) if cmd == "git status"));
    }

    #[test]
    fn bash_c_with_positional_args_asks() {
        let args: Vec<String> = vec!["-c".into(), "$0 $1".into(), "rm".into(), "-rf /".into()];
        let result = SHELL_HANDLER.classify(&HandlerContext::test("bash", &args));
        assert!(matches!(result, Classification::Ask(reason) if reason.contains("positional")));
    }

    #[test]
    fn bash_interactive_asks() {
        let args: Vec<String> = vec![];
        let result = SHELL_HANDLER.classify(&HandlerContext::test("bash", &args));
        let reason = match &result {
            Classification::Uncertain(UncertainKind::OpaqueInput, r) => r.as_str(),
            _ => "",
        };
        assert!(reason.contains("interactive"), "{result:?}");
    }

    #[test]
    fn sh_c_no_command_asks() {
        let args: Vec<String> = vec!["-c".into()];
        let result = SHELL_HANDLER.classify(&HandlerContext::test("sh", &args));
        assert!(matches!(result, Classification::Ask(reason) if reason.contains("no command")));
    }

    #[test]
    fn bash_script_file_recurses() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("test.sh"), "git status\nls -la").unwrap();
        let args = vec!["test.sh".into()];
        let ctx = HandlerContext {
            working_directory: dir.path(),
            ..HandlerContext::test("bash", &args)
        };
        let result = SHELL_HANDLER.classify(&ctx);
        assert!(matches!(result, Classification::Recurse(cmd) if cmd.contains("git status")));
    }

    #[test]
    fn bash_script_missing_asks() {
        let dir = tempfile::tempdir().unwrap();
        let args = vec!["missing.sh".into()];
        let ctx = HandlerContext {
            working_directory: dir.path(),
            ..HandlerContext::test("bash", &args)
        };
        let result = SHELL_HANDLER.classify(&ctx);
        assert!(matches!(
            result,
            Classification::Uncertain(UncertainKind::ProjectDefined, _)
        ));
    }
}
