use super::{Classification, Handler, HandlerContext};

pub static SHELL_HANDLER: ShellHandler = ShellHandler;

pub struct ShellHandler;

impl Handler for ShellHandler {
    fn commands(&self) -> &[&str] {
        &["bash", "sh", "zsh", "dash", "ksh", "fish"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        // Look for -c flag with inline command
        for (i, arg) in ctx.args.iter().enumerate() {
            if arg == "-c" {
                if let Some(inner) = ctx.args.get(i + 1) {
                    return Classification::Recurse(inner.clone());
                }
                return Classification::Ask(format!("{} -c (no command)", ctx.command_name));
            }
        }

        // No -c = interactive shell
        Classification::Ask(format!("{} (interactive)", ctx.command_name))
    }
}
