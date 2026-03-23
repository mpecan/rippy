use super::{Classification, Handler, HandlerContext, has_flag};

pub static FIND_HANDLER: FindHandler = FindHandler;

pub struct FindHandler;

impl Handler for FindHandler {
    fn commands(&self) -> &[&str] {
        &["find"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if has_flag(ctx.args, &["-delete"]) {
            return Classification::Ask("find -delete".into());
        }

        if has_flag(ctx.args, &["-ok", "-okdir"]) {
            return Classification::Ask("find -ok (interactive)".into());
        }

        // -exec / -execdir: extract inner command and delegate
        for (i, arg) in ctx.args.iter().enumerate() {
            if arg == "-exec" || arg == "-execdir" {
                let inner_args: Vec<&str> = ctx.args[i + 1..]
                    .iter()
                    .take_while(|a| a.as_str() != ";" && a.as_str() != "+")
                    .map(String::as_str)
                    .collect();
                if !inner_args.is_empty() {
                    return Classification::Recurse(inner_args.join(" "));
                }
                return Classification::Ask(format!("find {arg}"));
            }
        }

        Classification::Allow("find (search only)".into())
    }
}
