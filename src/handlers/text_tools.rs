use super::{Classification, Handler, HandlerContext, get_flag_value, has_flag};

// sed

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
        // `e` command executes a shell command.
        if arg == "e" || arg.starts_with("e ") || arg.contains(";e ") || arg.contains(";e\n") {
            return Some("sed e (shell execution)".into());
        }
        if sed_has_write_flag(arg) {
            return Some("sed w (writes to file)".into());
        }
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

pub static AWK_HANDLER: AwkHandler = AwkHandler;

pub struct AwkHandler;

impl Handler for AwkHandler {
    fn commands(&self) -> &[&str] {
        &["awk", "gawk", "mawk", "nawk"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if let Some(path) = get_flag_value(ctx.args, &["-f"]) {
            if let Some(program) = ctx.read_file(&path) {
                return check_awk_source(&program, ctx.command_name);
            }
            return Classification::Ask(format!("{} -f (script file)", ctx.command_name));
        }

        if let Some(reason) = check_awk_program(ctx.args, ctx.command_name) {
            return Classification::Ask(reason);
        }

        Classification::Allow(format!("{} (filter)", ctx.command_name))
    }
}

/// Check an awk source string for dangerous patterns.
fn check_awk_source(program: &str, cmd_name: &str) -> Classification {
    if program.contains("system(") {
        return Classification::Ask(format!("{cmd_name} -f system() (shell execution)"));
    }
    if awk_has_pipe_to_command(program) {
        return Classification::Ask(format!("{cmd_name} -f pipe to command"));
    }
    if awk_has_file_redirect(program) {
        return Classification::Ask(format!("{cmd_name} -f file redirect"));
    }
    Classification::Allow(format!("{cmd_name} -f (safe script)"))
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
        if awk_has_pipe_to_command(arg) {
            return Some(format!("{cmd_name} pipe to command"));
        }
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
    if program.contains(">> \"") || program.contains(">>\"") {
        return true;
    }
    // Require a space before `> "` to avoid matching `->` or `=>`.
    program.contains(" > \"") || program.contains("\t> \"")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {

    use super::*;

    // Inline sed/awk command->decision cases are covered by
    // tests/data/catalog/handlers_text_system.toml. The awk `-f` tests below
    // exercise read_file on real script content, which the catalog cannot inject.
    #[test]
    fn awk_f_safe_file_allows() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("safe.awk"), "{print $1}").unwrap();
        let args: Vec<String> = vec!["-f".into(), "safe.awk".into(), "data.txt".into()];
        let ctx = HandlerContext {
            working_directory: dir.path(),
            ..HandlerContext::test("awk", &args)
        };
        let result = AWK_HANDLER.classify(&ctx);
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn awk_f_system_file_asks() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("evil.awk"), r#"{system("rm -rf /")}"#).unwrap();
        let args: Vec<String> = vec!["-f".into(), "evil.awk".into()];
        let ctx = HandlerContext {
            working_directory: dir.path(),
            ..HandlerContext::test("awk", &args)
        };
        let result = AWK_HANDLER.classify(&ctx);
        assert!(matches!(result, Classification::Ask(_)));
    }

    #[test]
    fn awk_f_missing_file_asks() {
        let dir = tempfile::tempdir().unwrap();
        let args: Vec<String> = vec!["-f".into(), "missing.awk".into()];
        let ctx = HandlerContext {
            working_directory: dir.path(),
            ..HandlerContext::test("awk", &args)
        };
        let result = AWK_HANDLER.classify(&ctx);
        assert!(matches!(result, Classification::Ask(_)));
    }
}
