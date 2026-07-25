use super::{
    AllowEntry, Classification, Handler, HandlerContext, get_flag_value, has_flag,
    has_flag_or_prefixed, has_glued_short_flag,
};
use crate::verdict::AllowReason;

// sed

pub(crate) static SED_HANDLER: SedHandler = SedHandler;

pub(crate) struct SedHandler;

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

        Classification::Allow(AllowReason::handler("sed (filter)"))
    }

    fn allow_surface(&self) -> Vec<AllowEntry> {
        vec![AllowEntry::guarded(
            "sed <script> [<file>...]",
            "no -i (in-place), and no `w`/`e` command or `s///w`/`s///e` flag in the script",
        )]
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
    let mut chars = cmd.char_indices();
    if chars.next().map(|(_, c)| c) != Some('s') {
        return false;
    }
    // A byte delimiter would match the lead byte of a multi-byte scalar and
    // then slice mid-character; see docs/security-invariants.md#non-ascii-inline-code.
    let Some((_, delim)) = chars.next() else {
        return false;
    };
    let mut count = 0u8;
    for (i, c) in chars {
        if c == delim {
            count += 1;
            if count == 2 {
                let flags = &cmd[i + delim.len_utf8()..];
                return flags.contains('w') || flags.contains('e');
            }
        }
    }
    false
}

pub(crate) static AWK_HANDLER: AwkHandler = AwkHandler;

pub(crate) struct AwkHandler;

impl Handler for AwkHandler {
    fn commands(&self) -> &[&str] {
        &["awk", "gawk", "mawk", "nawk"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if has_awk_flag(ctx.args, "-f", &["-f", "--file"]) {
            let program = awk_script_path(ctx.args).and_then(|path| ctx.read_file(&path));
            return program.map_or_else(
                || Classification::Ask(format!("{} -f (script file)", ctx.command_name)),
                |program| check_awk_source(&program, ctx.command_name),
            );
        }

        if has_awk_flag(ctx.args, "-l", &["-l", "--load"]) {
            return Classification::Ask(format!("{} -l (loads shared library)", ctx.command_name));
        }

        if let Some(reason) = check_awk_include(ctx.args, ctx.command_name) {
            return Classification::Ask(reason);
        }

        if let Some(reason) = check_awk_program(ctx.args, ctx.command_name) {
            return Classification::Ask(reason);
        }

        Classification::Allow(AllowReason::handler(format!(
            "{} (filter)",
            ctx.command_name
        )))
    }

    fn allow_surface(&self) -> Vec<AllowEntry> {
        let guard = "no system() call, pipe-to-command or file redirect in the program, and no \
                     -i/--include or -l/--load flag";
        vec![
            AllowEntry::guarded("awk <program> [<file>...]", guard),
            AllowEntry::guarded(
                "awk -f <script>",
                format!("script readable from the working directory; {guard}"),
            ),
        ]
    }
}

/// Whether a code-loading flag is present in any spelling: bare (`-f`),
/// `flag=value`, or glued short (`-fscript`). A flag with no value at all still
/// counts, so a malformed invocation cannot fall through to the filter surface.
fn has_awk_flag(args: &[String], short: &str, spellings: &[&str]) -> bool {
    has_flag_or_prefixed(args, spellings) || has_glued_short_flag(args, &[short])
}

/// Extract the script path from any spelling of `-f`: `-f s`, `-fs`,
/// `--file s`, `--file=s`.
fn awk_script_path(args: &[String]) -> Option<String> {
    get_flag_value(args, &["-f", "--file"]).or_else(|| attached_flag_value(args, "-f", "--file="))
}

/// Check for gawk's `-i`/`--include`, which either rewrites the input file in
/// place (`-i inplace`) or loads an arbitrary awk source file. Unlike `-f`'s
/// plain relative path, `-i` searches `AWKPATH`, so a same-named local file is
/// not trustworthy evidence of what gawk actually loads — always Ask.
fn check_awk_include(args: &[String], cmd_name: &str) -> Option<String> {
    let value = get_flag_value(args, &["-i", "--include"])
        .or_else(|| attached_flag_value(args, "-i", "--include="))?;
    if value == "inplace" || value.starts_with("inplace:") {
        Some(format!("{cmd_name} -i inplace (rewrites file)"))
    } else {
        Some(format!("{cmd_name} -i (include file)"))
    }
}

/// Extract the value attached to a flag: glued to the short form (`-iinplace`)
/// or joined to the long form with `=` (`--include=inplace`).
fn attached_flag_value(args: &[String], short: &str, long_prefix: &str) -> Option<String> {
    for arg in args {
        if let Some(value) = arg.strip_prefix(long_prefix) {
            return Some(value.to_owned());
        }
        if let Some(value) = arg.strip_prefix(short)
            && !value.is_empty()
        {
            return Some(value.to_owned());
        }
    }
    None
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
    Classification::Allow(AllowReason::handler(format!("{cmd_name} -f (safe script)")))
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

/// A byte is a "word" character for the purposes of distinguishing awk's `/`
/// division operator (follows an identifier/number/`)`/`]`/`$`) from a `/regex/`
/// literal start (follows anything else, including the start of the program).
const fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b')' || b == b']' || b == b'$'
}

/// Skip over a double-quoted string literal starting at `quote_idx` (the
/// opening `"`), honoring backslash escapes. Returns the index just past the
/// closing quote (or the end of the program if unterminated).
fn skip_awk_string(bytes: &[u8], quote_idx: usize) -> usize {
    let mut j = quote_idx + 1;
    while j < bytes.len() {
        if bytes[j] == b'\\' {
            j += 2;
            continue;
        }
        if bytes[j] == b'"' {
            return j + 1;
        }
        j += 1;
    }
    j
}

/// Skip over a `/regex/` literal starting at `slash_idx` (the opening `/`),
/// honoring backslash escapes. Returns the index just past the closing `/`
/// (or the end of the program if unterminated).
fn skip_awk_regex(bytes: &[u8], slash_idx: usize) -> usize {
    let mut j = slash_idx + 1;
    while j < bytes.len() {
        if bytes[j] == b'\\' {
            j += 2;
            continue;
        }
        if bytes[j] == b'/' {
            return j + 1;
        }
        j += 1;
    }
    j
}

/// Detect awk pipe-to-command patterns: `print ... | "cmd"`, `"cmd" | getline`,
/// `print | cmd_var`. Awk's grammar has no bitwise/single-pipe operator other
/// than pipe-to-command / pipe-from-command-into-getline, so any `|` that is
/// not part of a `||` logical-or and not inside a string or `/regex/` literal
/// (where `|` is ordinary alternation, e.g. `/foo|bar/`) is unconditionally
/// one of those two forms.
fn awk_has_pipe_to_command(program: &str) -> bool {
    let bytes = program.as_bytes();
    let mut prev_significant: Option<u8> = None;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'"' {
            i = skip_awk_string(bytes, i);
            prev_significant = Some(b'"');
            continue;
        }
        if b == b'/' && !matches!(prev_significant, Some(c) if is_word_byte(c)) {
            i = skip_awk_regex(bytes, i);
            prev_significant = Some(b'/');
            continue;
        }
        if b == b'|' {
            let prev_is_pipe = i > 0 && bytes[i - 1] == b'|';
            let next_is_pipe = i + 1 < bytes.len() && bytes[i + 1] == b'|';
            if !prev_is_pipe && !next_is_pipe {
                return true;
            }
        }
        if !b.is_ascii_whitespace() {
            prev_significant = Some(b);
        }
        i += 1;
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
#[expect(clippy::unwrap_used)]
mod tests {

    use super::*;

    // Inline sed/awk command->decision cases are covered by
    // tests/data/catalog/handlers_text_system.toml. The awk `-f` tests below
    // exercise read_file on real script content, which the catalog cannot inject.

    /// A multi-byte delimiter used to panic here: the delimiter was read as a
    /// single byte, so it matched the lead byte of each `ї` and produced a
    /// flags offset inside a scalar. See docs/security-invariants.md#non-ascii-inline-code.
    #[test]
    fn non_ascii_sed_delimiter_is_classified_without_panicking() {
        assert!(!sed_has_dangerous_flag("sїaїbїc"));
        assert!(sed_has_dangerous_flag("sїaїbїw"));
        assert!(!sed_has_dangerous_flag("s/foo/w bar/"));
        assert!(sed_has_dangerous_flag("s/foo/bar/gw out.txt"));
    }

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
    fn awk_regex_alternation_is_not_pipe() {
        assert!(!awk_has_pipe_to_command("/foo|bar/ {print}"));
    }

    #[test]
    fn awk_regex_alternation_field_match_is_not_pipe() {
        assert!(!awk_has_pipe_to_command("$1 ~ /a|b/ {print}"));
    }

    #[test]
    fn awk_regex_alternation_in_gsub_is_not_pipe() {
        assert!(!awk_has_pipe_to_command(r#"{gsub(/x|y/,"z")}"#));
    }

    #[test]
    fn awk_string_literal_pipe_is_not_pipe_to_command() {
        assert!(!awk_has_pipe_to_command(r#"BEGIN{print "a|b"}"#));
    }

    #[test]
    fn awk_pipe_to_command_still_detected() {
        assert!(awk_has_pipe_to_command(r#"{print $0 | "sort"}"#));
    }

    #[test]
    fn awk_pipe_to_command_no_space_still_detected() {
        assert!(awk_has_pipe_to_command(r#"{print $0|"sh"}"#));
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
