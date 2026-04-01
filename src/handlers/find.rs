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
            receives_piped_input: false,
            cd_allowed_dirs: &[],
        }
    }

    #[test]
    fn find_search_only_allows() {
        let args: Vec<String> = vec![".".into(), "-name".into(), "*.rs".into()];
        let result = FIND_HANDLER.classify(&ctx(&args, "find"));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn find_delete_asks() {
        let args: Vec<String> = vec![".".into(), "-name".into(), "*.tmp".into(), "-delete".into()];
        let result = FIND_HANDLER.classify(&ctx(&args, "find"));
        assert!(matches!(result, Classification::Ask(reason) if reason.contains("delete")));
    }

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
        let result = FIND_HANDLER.classify(&ctx(&args, "find"));
        assert!(matches!(result, Classification::Recurse(cmd) if cmd == "wc -l {}"));
    }

    #[test]
    fn find_ok_asks() {
        let args: Vec<String> = vec![
            ".".into(),
            "-ok".into(),
            "rm".into(),
            "{}".into(),
            ";".into(),
        ];
        let result = FIND_HANDLER.classify(&ctx(&args, "find"));
        assert!(matches!(result, Classification::Ask(reason) if reason.contains("ok")));
    }
}
