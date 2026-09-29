use super::{AllowEntry, Classification, Handler, HandlerContext, has_flag, placeholder_injects};
use crate::verdict::AllowReason;

pub(crate) static FIND_HANDLER: FindHandler = FindHandler;

pub(crate) struct FindHandler;

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

        if has_flag(ctx.args, &["-fprint", "-fprint0", "-fprintf", "-fls"]) {
            return Classification::Ask("find (writes to file)".into());
        }

        // -exec / -execdir: extract inner command and delegate
        for (i, arg) in ctx.args.iter().enumerate() {
            if arg == "-exec" || arg == "-execdir" {
                let inner_args: Vec<String> = ctx.args[i + 1..]
                    .iter()
                    .take_while(|a| a.as_str() != ";" && a.as_str() != "+")
                    .cloned()
                    .collect();
                if placeholder_injects(&inner_args, &["{}"]) {
                    return Classification::Ask(format!("find {arg} (file names become code)"));
                }
                if !inner_args.is_empty() {
                    return Classification::Recurse(crate::resolve::shell_join(&inner_args));
                }
                return Classification::Ask(format!("find {arg}"));
            }
        }

        Classification::Allow(AllowReason::handler("find (search only)"))
    }

    fn allow_surface(&self) -> Vec<AllowEntry> {
        vec![AllowEntry::guarded(
            "find <path> <expression>",
            "no -delete, -ok/-okdir, -fprint/-fprint0/-fprintf/-fls, -exec or -execdir",
        )]
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    // find search/-delete/-ok command->decision cases are covered by
    // tests/data/catalog/handlers_text_system.toml. This test asserts the Recurse
    // variant and exact inner-command extraction, which a command string can't check.
    #[test]
    fn find_exec_recurses() {
        let args: Vec<String> = vec![
            ".".into(),
            "-name".into(),
            "*.rs".into(),
            "-exec".into(),
            "wc".into(),
            "-l".into(),
            "{}".into(),
            ";".into(),
        ];
        let result = FIND_HANDLER.classify(&HandlerContext::test("find", &args));
        // Re-joined with quoting, so each argument re-parses as one word.
        let expected = crate::resolve::shell_join(&["wc".into(), "-l".into(), "{}".into()]);
        assert!(matches!(result, Classification::Recurse(cmd) if cmd == expected));
    }
}
