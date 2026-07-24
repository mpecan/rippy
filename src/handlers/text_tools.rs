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

/// Check sed expression arguments for `w`/`e` flags on `s///` and bare `e`/`w`
/// (possibly address-prefixed) commands.
fn check_sed_expression(args: &[String]) -> Option<String> {
    for arg in args {
        if arg.starts_with('-') {
            continue;
        }
        for cmd in arg.split(['\n', ';']) {
            if let Some(reason) = check_sed_command(cmd.trim()) {
                return Some(reason);
            }
        }
    }
    None
}

/// Check a single (already semicolon-split) sed command segment.
fn check_sed_command(cmd: &str) -> Option<String> {
    if sed_has_dangerous_flag(cmd) {
        return Some("sed w/e flag (writes to file or executes)".into());
    }
    let rest = strip_sed_address(cmd);
    if is_bare_e_command(rest) {
        return Some("sed e (shell execution)".into());
    }
    if rest == "w" || rest.starts_with("w ") {
        return Some("sed w (writes to file)".into());
    }
    None
}

/// Strip a leading sed address (`N`, `N,M`, `$`, `/regex/`, optionally
/// followed by `!`) from a command segment, returning the remaining command.
fn strip_sed_address(cmd: &str) -> &str {
    let bytes = cmd.as_bytes();
    let mut i = 0;
    let len = bytes.len();

    if i < len && bytes[i] == b'/' {
        i += 1;
        while i < len && bytes[i] != b'/' {
            i += 1;
        }
        if i < len {
            i += 1; // skip closing '/'
        }
    } else {
        while i < len && (bytes[i].is_ascii_digit() || bytes[i] == b',' || bytes[i] == b'$') {
            i += 1;
        }
    }
    if i < len && bytes[i] == b'!' {
        i += 1;
    }
    cmd[i..].trim_start()
}

/// Check whether a (address-stripped) command is a bare `e` execute command,
/// e.g. `e`, `e cmd`.
fn is_bare_e_command(rest: &str) -> bool {
    rest == "e" || rest.starts_with("e ") || rest.starts_with("e\t")
}

/// Check if a sed `s` command has a `w` (write) or `e` (execute) flag after
/// the third delimiter. e.g., `s/foo/bar/gw output.txt` or `s/x/id/e` — the
/// flag is in the flags section, after the replacement text ends.
/// Avoids false positives like `s/foo/w bar/` where `w` is in the replacement.
fn sed_has_dangerous_flag(expr: &str) -> bool {
    let cmd = expr.trim();
    if !cmd.starts_with('s') || cmd.len() < 4 {
        return false;
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
        return flags.contains('w') || flags.contains('e');
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
    if awk_has_system_call(program) {
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
        if awk_has_system_call(arg) {
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

/// Detect an awk `system(...)` call, tolerating whitespace between the
/// function name and its opening paren (`system ("id")` is valid awk syntax
/// and was missed by a plain `"system("` substring match).
fn awk_has_system_call(program: &str) -> bool {
    let bytes = program.as_bytes();
    let Some(mut idx) = program.find("system") else {
        return false;
    };
    loop {
        let before_ok =
            idx == 0 || !bytes[idx - 1].is_ascii_alphanumeric() && bytes[idx - 1] != b'_';
        let after = &program[idx + 6..];
        let trimmed = after.trim_start();
        if before_ok && trimmed.starts_with('(') {
            return true;
        }
        match program[idx + 6..].find("system") {
            Some(next) => idx = idx + 6 + next,
            None => return false,
        }
    }
}

/// Detect awk pipe-to-command patterns: `print ... | "cmd"`, `"cmd" | getline`,
/// `print | cmd_var`. Awk's grammar has no bitwise/single-pipe operator other
/// than pipe-to-command / pipe-from-command-into-getline, so any `|` that is
/// not part of a `||` logical-or is unconditionally one of those two forms —
/// this replaces the old spacing/quote-anchored substring match, which missed
/// no-space calls (`|"sh"`) and pipes to a variable holding a command.
fn awk_has_pipe_to_command(program: &str) -> bool {
    let bytes = program.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b != b'|' {
            continue;
        }
        let prev_is_pipe = i > 0 && bytes[i - 1] == b'|';
        let next_is_pipe = i + 1 < bytes.len() && bytes[i + 1] == b'|';
        if !prev_is_pipe && !next_is_pipe {
            return true;
        }
    }
    false
}

/// Detect awk file redirect patterns: `print ... > "file"` / `>> "file"`
/// (destination quoted, optionally space-delimited), plus the no-space form
/// where the redirect operator immediately follows a closing quote
/// (`"x">"/tmp/evil"`). Anchored to a quote adjacent to the `>`/`>>` (not a
/// bare operator) so numeric/string comparisons like `$1 > 100` or
/// `a >= b` keep Allowing.
fn awk_has_file_redirect(program: &str) -> bool {
    if program.contains(">> \"")
        || program.contains(">>\"")
        || program.contains(" > \"")
        || program.contains("\t> \"")
    {
        return true;
    }

    let bytes = program.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        // Only check the first '>' of a possible ">>" run.
        if b != b'>' || (i > 0 && bytes[i - 1] == b'>') {
            continue;
        }
        let mut k = i;
        while k > 0 && bytes[k - 1].is_ascii_whitespace() {
            k -= 1;
        }
        if k > 0 && bytes[k - 1] == b'"' {
            return true;
        }
    }
    false
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
