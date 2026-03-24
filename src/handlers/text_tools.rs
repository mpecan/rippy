use super::{Classification, Handler, HandlerContext, has_flag};

// ---- sed ----

pub static SED_HANDLER: SedHandler = SedHandler;

pub struct SedHandler;

impl Handler for SedHandler {
    fn commands(&self) -> &[&str] {
        &["sed"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if has_flag(ctx.args, &["-i"]) || ctx.args.iter().any(|a| a.starts_with("-i")) {
            return Classification::Ask("sed -i (in-place edit)".into());
        }

        // Scan sed expressions for dangerous commands
        if let Some(reason) = check_sed_expression(ctx.args) {
            return Classification::Ask(reason);
        }

        Classification::Allow("sed (filter)".into())
    }
}

/// Check sed expression arguments for `w` (write) and `e` (execute) commands.
fn check_sed_expression(args: &[String]) -> Option<String> {
    for arg in args {
        if arg.starts_with('-') {
            continue;
        }
        // `e` command — executes shell command
        if arg == "e" || arg.starts_with("e ") || arg.contains(";e ") || arg.contains(";e\n") {
            return Some("sed e (shell execution)".into());
        }
        // `w` flag on s command — writes matches to file (e.g., s/x/y/w file)
        if arg.contains("/w ") || arg.contains("/w\t") {
            return Some("sed w (writes to file)".into());
        }
        // Standalone `w` command (e.g., `w output.txt`)
        if arg == "w" || arg.starts_with("w ") {
            return Some("sed w (writes to file)".into());
        }
    }
    None
}

// ---- awk ----

pub static AWK_HANDLER: AwkHandler = AwkHandler;

pub struct AwkHandler;

impl Handler for AwkHandler {
    fn commands(&self) -> &[&str] {
        &["awk", "gawk", "mawk", "nawk"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if has_flag(ctx.args, &["-f"]) {
            return Classification::Ask(format!("{} -f (script file)", ctx.command_name));
        }

        // Scan the awk program for dangerous patterns
        if let Some(reason) = check_awk_program(ctx.args, ctx.command_name) {
            return Classification::Ask(reason);
        }

        Classification::Allow(format!("{} (filter)", ctx.command_name))
    }
}

/// Check awk program arguments for `system()`, pipe-to-command, and file redirects.
fn check_awk_program(args: &[String], cmd_name: &str) -> Option<String> {
    for arg in args {
        if arg.starts_with('-') {
            continue;
        }
        // system() calls
        if arg.contains("system(") {
            return Some(format!("{cmd_name} system() (shell execution)"));
        }
        // Pipe to command: | "cmd" or |"cmd"
        if arg.contains("| \"") || arg.contains("|\"") {
            return Some(format!("{cmd_name} pipe to command"));
        }
        // File redirects: > "file" or >> "file"
        if arg.contains("> \"") || arg.contains(">>\"") || arg.contains(">> \"") {
            return Some(format!("{cmd_name} file redirect"));
        }
    }
    None
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

    // sed tests
    #[test]
    fn sed_simple_filter_allows() {
        let args: Vec<String> = vec!["s/x/y/".into(), "file.txt".into()];
        let result = SED_HANDLER.classify(&ctx(&args, "sed"));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn sed_inplace_asks() {
        let args: Vec<String> = vec!["-i".into(), "s/x/y/".into(), "file.txt".into()];
        let result = SED_HANDLER.classify(&ctx(&args, "sed"));
        assert!(matches!(result, Classification::Ask(_)));
    }

    #[test]
    fn sed_w_command_asks() {
        let args: Vec<String> = vec!["s/x/y/w output.txt".into(), "file.txt".into()];
        let result = SED_HANDLER.classify(&ctx(&args, "sed"));
        assert!(matches!(result, Classification::Ask(r) if r.contains("writes to file")));
    }

    #[test]
    fn sed_e_command_asks() {
        let args: Vec<String> = vec!["e date".into()];
        let result = SED_HANDLER.classify(&ctx(&args, "sed"));
        assert!(matches!(result, Classification::Ask(r) if r.contains("shell execution")));
    }

    #[test]
    fn sed_standalone_w_asks() {
        let args: Vec<String> = vec!["w output.txt".into()];
        let result = SED_HANDLER.classify(&ctx(&args, "sed"));
        assert!(matches!(result, Classification::Ask(r) if r.contains("writes to file")));
    }

    // awk tests
    #[test]
    fn awk_simple_filter_allows() {
        let args: Vec<String> = vec!["{print}".into(), "file.txt".into()];
        let result = AWK_HANDLER.classify(&ctx(&args, "awk"));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn awk_f_flag_asks() {
        let args: Vec<String> = vec!["-f".into(), "script.awk".into()];
        let result = AWK_HANDLER.classify(&ctx(&args, "awk"));
        assert!(matches!(result, Classification::Ask(_)));
    }

    #[test]
    fn awk_system_call_asks() {
        let args: Vec<String> = vec![r#"{system("rm -rf /")}"#.into(), "file.txt".into()];
        let result = AWK_HANDLER.classify(&ctx(&args, "awk"));
        assert!(matches!(result, Classification::Ask(r) if r.contains("system()")));
    }

    #[test]
    fn awk_pipe_to_command_asks() {
        let args: Vec<String> = vec![r#"{print | "sort"}"#.into(), "file.txt".into()];
        let result = AWK_HANDLER.classify(&ctx(&args, "awk"));
        assert!(matches!(result, Classification::Ask(r) if r.contains("pipe")));
    }

    #[test]
    fn awk_file_redirect_asks() {
        let args: Vec<String> = vec![r#"{print > "output.txt"}"#.into(), "file.txt".into()];
        let result = AWK_HANDLER.classify(&ctx(&args, "awk"));
        assert!(matches!(result, Classification::Ask(r) if r.contains("file redirect")));
    }

    #[test]
    fn awk_append_redirect_asks() {
        let args: Vec<String> = vec![r#"{print >> "log.txt"}"#.into(), "file.txt".into()];
        let result = AWK_HANDLER.classify(&ctx(&args, "awk"));
        assert!(matches!(result, Classification::Ask(r) if r.contains("file redirect")));
    }

    #[test]
    fn gawk_system_call_asks() {
        let args: Vec<String> = vec![r#"{system("echo hi")}"#.into()];
        let result = AWK_HANDLER.classify(&ctx(&args, "gawk"));
        assert!(matches!(result, Classification::Ask(r) if r.contains("system()")));
    }
}
