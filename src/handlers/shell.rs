use super::{Classification, Handler, HandlerContext};

pub static SHELL_HANDLER: ShellHandler = ShellHandler;

pub struct ShellHandler;

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

        Classification::Ask(format!("{} (interactive)", ctx.command_name))
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
        }
    }

    #[test]
    fn bash_c_simple_recurses() {
        let args: Vec<String> = vec!["-c".into(), "git status".into()];
        let result = SHELL_HANDLER.classify(&ctx(&args, "bash"));
        assert!(matches!(result, Classification::Recurse(cmd) if cmd == "git status"));
    }

    #[test]
    fn bash_c_with_positional_args_asks() {
        let args: Vec<String> = vec!["-c".into(), "$0 $1".into(), "rm".into(), "-rf /".into()];
        let result = SHELL_HANDLER.classify(&ctx(&args, "bash"));
        assert!(matches!(result, Classification::Ask(reason) if reason.contains("positional")));
    }

    #[test]
    fn bash_interactive_asks() {
        let args: Vec<String> = vec![];
        let result = SHELL_HANDLER.classify(&ctx(&args, "bash"));
        assert!(matches!(result, Classification::Ask(reason) if reason.contains("interactive")));
    }

    #[test]
    fn sh_c_no_command_asks() {
        let args: Vec<String> = vec!["-c".into()];
        let result = SHELL_HANDLER.classify(&ctx(&args, "sh"));
        assert!(matches!(result, Classification::Ask(reason) if reason.contains("no command")));
    }

    #[test]
    fn bash_script_file_recurses() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("test.sh"), "git status\nls -la").unwrap();
        let args = vec!["test.sh".into()];
        let ctx = HandlerContext {
            command_name: "bash",
            args: &args,
            working_directory: dir.path(),
            remote: false,
        };
        let result = SHELL_HANDLER.classify(&ctx);
        assert!(matches!(result, Classification::Recurse(cmd) if cmd.contains("git status")));
    }

    #[test]
    fn bash_script_missing_asks() {
        let dir = tempfile::tempdir().unwrap();
        let args = vec!["missing.sh".into()];
        let ctx = HandlerContext {
            command_name: "bash",
            args: &args,
            working_directory: dir.path(),
            remote: false,
        };
        let result = SHELL_HANDLER.classify(&ctx);
        assert!(matches!(result, Classification::Ask(_)));
    }
}
