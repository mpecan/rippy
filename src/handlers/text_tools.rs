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
        // `w` flag on s command — s/pat/repl/[flags]w file
        // The `w` must appear in the flags section after the 3rd delimiter
        if sed_has_write_flag(arg) {
            return Some("sed w (writes to file)".into());
        }
        // Standalone `w` command (e.g., `w output.txt`)
        if arg == "w" || arg.starts_with("w ") {
            return Some("sed w (writes to file)".into());
        }
    }
    None
}

/// Check if a sed `s` command has a `w` flag after the third delimiter.
/// e.g., `s/foo/bar/gw output.txt` — the `w` is in the flags section.
/// Avoids false positives like `s/foo/w bar/` where `w` is in the replacement.
fn sed_has_write_flag(expr: &str) -> bool {
    // Handle each semicolon-separated command
    for cmd in expr.split(';') {
        let cmd = cmd.trim();
        if !cmd.starts_with('s') || cmd.len() < 4 {
            continue;
        }
        // The delimiter is the character after 's'
        let delim = cmd.as_bytes()[1];
        // Find the 3rd occurrence of the delimiter (end of replacement)
        let mut count = 0u8;
        let mut flags_start = None;
        for (i, &b) in cmd.as_bytes()[1..].iter().enumerate() {
            if b == delim {
                count += 1;
                if count == 3 {
                    flags_start = Some(i + 2); // +1 for skip, +1 for after delim
                    break;
                }
            }
        }
        if let Some(start) = flags_start {
            let flags = &cmd[start..];
            if flags.contains('w') {
                return true;
            }
        }
    }
    false
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
        if arg.contains("system(") {
            return Some(format!("{cmd_name} system() (shell execution)"));
        }
        // Pipe to command: `| "cmd"` — require space before `|` or `|` after
        // a statement keyword to avoid matching `|"` inside string literals
        if awk_has_pipe_to_command(arg) {
            return Some(format!("{cmd_name} pipe to command"));
        }
        // File redirects: `> "file"` or `>> "file"`
        if awk_has_file_redirect(arg) {
            return Some(format!("{cmd_name} file redirect"));
        }
    }
    None
}

/// Detect awk pipe-to-command patterns: `print ... | "cmd"`.
fn awk_has_pipe_to_command(program: &str) -> bool {
    // Look for `| "` preceded by a space (statement context, not inside a string)
    program.contains(" | \"") || program.contains("\t| \"")
}

/// Detect awk file redirect patterns: `print ... > "file"` or `>> "file"`.
fn awk_has_file_redirect(program: &str) -> bool {
    // `>> "` is always a redirect in awk
    if program.contains(">> \"") || program.contains(">>\"") {
        return true;
    }
    // `> "` preceded by a space (to avoid matching `->` or `=>` patterns)
    program.contains(" > \"") || program.contains("\t> \"")
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

    // False positive prevention tests
    #[test]
    fn sed_w_in_replacement_allows() {
        // `w` in the replacement text is NOT a write flag
        let args: Vec<String> = vec!["s/foo/w bar/".into(), "file.txt".into()];
        let result = SED_HANDLER.classify(&ctx(&args, "sed"));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn sed_w_flag_with_g_asks() {
        // s/foo/bar/gw output.txt — w is in the flags section
        let args: Vec<String> = vec!["s/foo/bar/gw output.txt".into(), "file.txt".into()];
        let result = SED_HANDLER.classify(&ctx(&args, "sed"));
        assert!(matches!(result, Classification::Ask(r) if r.contains("writes to file")));
    }
}
