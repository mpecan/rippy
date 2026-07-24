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

        if has_flag(ctx.args, &["-fprint", "-fprint0", "-fprintf", "-fls"]) {
            return Classification::Ask("find (writes to file)".into());
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
        assert!(matches!(result, Classification::Recurse(cmd) if cmd == "wc -l {}"));
    }
}
