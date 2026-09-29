use super::{AllowEntry, Classification, Handler, HandlerContext, has_flag, placeholder_injects};
use crate::ast;
use crate::resolve;
use crate::verdict::AllowReason;

// env

pub(crate) static ENV_HANDLER: EnvHandler = EnvHandler;

pub(crate) struct EnvHandler;

impl Handler for EnvHandler {
    fn commands(&self) -> &[&str] {
        &["env"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        // `env -S`/`--split-string` reparses its payload as the whole command line;
        // recurse so it cannot smuggle a dangerous prefix or inner command past the
        // analyzer. see docs/security-invariants.md#dangerous-env-name
        let call = parse_env(ctx.args);
        if let (Some(payload), Some(span)) = (&call.split, call.split_span) {
            if payload.trim().is_empty() {
                return Classification::Ask("env (split-string)".into());
            }
            return Classification::Recurse(spliced_line(ctx.args, payload, span));
        }
        if call.unknown {
            return Classification::Ask("env (unrecognised option)".into());
        }

        // A bodiless `env LD_PRELOAD=x` is gated here; with a command, the
        // assignments stay a prefix so the analyzer's gate combines with the
        // command's own verdict.
        let dangerous = call
            .assigned
            .iter()
            .filter_map(|a| a.split_once('=').map(|(n, _)| n))
            .any(ast::is_dangerous_env_name);
        if dangerous && call.inner.is_empty() {
            return Classification::Ask("env (unrecognized env-var assignment)".into());
        }

        if call.alt_path {
            return Classification::Ask("env -P (looks the program up in another path)".into());
        }
        if call.chdir {
            return Classification::Ask("env -C (runs the command in another directory)".into());
        }
        if call.inner.is_empty() {
            return Classification::Allow(AllowReason::handler("env (print environment)"));
        }
        let prefix = assignment_prefix(call.assigned);
        let inner = format!("{prefix}{}", resolve::shell_join(call.inner));
        // A name the shell cannot spell (`#=1`, `a b=1`) cannot ride along as
        // a prefix, and bare it re-parses as a comment or a command.
        match call.assigned.iter().find(|a| !is_shell_name(a)) {
            Some(odd) => Classification::RecurseAtLeast(
                inner,
                Box::new(Classification::Ask(format!(
                    "env (unusual env-var name in {odd})"
                ))),
            ),
            None => Classification::Recurse(inner),
        }
    }

    fn allow_surface(&self) -> Vec<AllowEntry> {
        vec![AllowEntry::guarded(
            "env [NAME=VALUE]...",
            "no inner command, no -S/--split-string, and no assignment to a code-influencing \
             variable (see docs/security-invariants.md#dangerous-env-name)",
        )]
    }
}

/// `env`'s options that take a value, as the rest of a short cluster or the
/// next word: `-u NAME`, `-C DIR`, `-P PATH`, `-S STRING`, `-a ARG0`.
const ENV_VALUE_SHORT: &[char] = &['u', 'C', 'P', 'S', 'a'];
const ENV_VALUE_LONG: &[&str] = &["--unset", "--chdir", "--split-string", "--argv0"];
/// Every long option GNU `env` knows; getopt accepts any unique prefix.
const ENV_LONG: &[&str] = &[
    "--unset",
    "--chdir",
    "--split-string",
    "--argv0",
    "--ignore-environment",
    "--null",
    "--debug",
    "--block-signal",
    "--default-signal",
    "--ignore-signal",
    "--list-signal-handling",
    "--help",
    "--version",
];
/// `env`'s boolean short options; any other letter is not understood.
const ENV_FLAG_SHORT: &[char] = &['i', 'v', '0'];

/// What an `env` invocation does, from its argv.
struct EnvCall<'a> {
    /// The command `env` runs, verbatim with its own flags and operands:
    /// dropping every `-x`/`a=b` word once turned `env find . -delete` into
    /// `find .`.
    inner: &'a [String],
    /// The `NAME=VALUE` words `env` sets, before `inner`; words after the
    /// command (`git -c core.pager=x`) are its arguments.
    assigned: &'a [String],
    /// `-C DIR`: the command runs elsewhere, so its relative paths resolve
    /// against a directory rippy does not see.
    chdir: bool,
    /// `-P PATH` (BSD): the program is looked up in `PATH`, as with a
    /// `PATH=` prefix.
    alt_path: bool,
    /// `-S STRING`: `STRING` is re-parsed as the whole command line.
    /// see docs/security-invariants.md#dangerous-env-name
    split: Option<String>,
    /// Where the `-S` word(s) sit in argv, and any short options clustered
    /// before the `S` (`-iS`): GNU env splices the split words in their place
    /// and keeps going, so what follows still runs.
    split_span: Option<(usize, usize, &'a str)>,
    /// An option letter rippy does not know, so the command boundary is not
    /// certain.
    unknown: bool,
}

fn parse_env(args: &[String]) -> EnvCall<'_> {
    let mut call = EnvCall {
        inner: &[],
        assigned: &[],
        chdir: false,
        alt_path: false,
        split: None,
        split_span: None,
        unknown: false,
    };
    let mut options_done = false;
    let mut i = 0;
    while let Some(arg) = args.get(i) {
        let at = i;
        let mut prefix = "";
        i += 1;
        if arg == "--" && !options_done {
            options_done = true;
        } else if !options_done && arg.starts_with("--") {
            i += long_option(arg, args.get(i), &mut call);
        } else if !options_done && arg.len() > 1 && arg.starts_with('-') {
            for (pos, c) in arg.char_indices().skip(1) {
                if ENV_VALUE_SHORT.contains(&c) {
                    prefix = if pos > 1 { &arg[..pos] } else { "" };
                    let rest = &arg[pos + 1..];
                    let value = if rest.is_empty() {
                        i += 1;
                        args.get(i - 1).map(String::as_str)
                    } else {
                        Some(rest)
                    };
                    call.note(&format!("-{c}"), value);
                    break;
                }
                call.unknown |= !ENV_FLAG_SHORT.contains(&c);
            }
        } else if arg.split_once('=').is_some_and(|(n, _)| !n.is_empty()) {
            call.assigned = assignments_through(args, call.assigned, at);
            options_done = true;
        } else {
            call.inner = &args[i - 1..];
            break;
        }
        if call.split.is_some() {
            call.split_span = Some((at, i, prefix));
            break;
        }
    }
    call
}

/// Record one long option; returns 1 when it took the next word as its value.
fn long_option<'a>(arg: &'a str, next: Option<&'a String>, call: &mut EnvCall<'a>) -> usize {
    let (name, inline) = arg
        .split_once('=')
        .map_or((arg, None), |(n, v)| (n, Some(v)));
    let Some(name) = env_long(name) else {
        call.unknown = true;
        return 0;
    };
    if inline.is_none() && ENV_VALUE_LONG.contains(&name) {
        call.note(name, next.map(String::as_str));
        return 1;
    }
    call.note(name, inline);
    0
}

/// `NAME=VALUE ` for each assignment, the value quoted and the name left bare
/// so the shell still reads it as an assignment.
fn assignment_prefix(assigned: &[String]) -> String {
    assigned
        .iter()
        .filter(|a| is_shell_name(a))
        .filter_map(|a| a.split_once('='))
        .fold(String::new(), |mut out, (n, v)| {
            out.push_str(n);
            out.push('=');
            out.push_str(&resolve::shell_join(&[v.to_owned()]));
            out.push(' ');
            out
        })
}

/// Whether `NAME=VALUE`'s name is one the shell reads as an assignment.
fn is_shell_name(assignment: &str) -> bool {
    let name = assignment.split_once('=').map_or("", |(n, _)| n);
    name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// `current` extended by the assignment at `at`: assignments are contiguous,
/// since the first other word ends them.
fn assignments_through<'a>(args: &'a [String], current: &'a [String], at: usize) -> &'a [String] {
    let start = if current.is_empty() {
        at
    } else {
        at + 1 - current.len()
    };
    &args[start..=at]
}

/// The command line `env` runs once the `-S` payload is spliced into argv in
/// place of the option: `env -S 'CI=1' rm x` runs `rm x`, not just `CI=1`.
fn spliced_line(args: &[String], payload: &str, span: (usize, usize, &str)) -> String {
    let (start, end, prefix) = span;
    let before = resolve::shell_join(&args[..start]);
    let after = resolve::shell_join(args.get(end..).unwrap_or_default());
    format!("env {before} {prefix} {payload} {after}")
}

/// The long option `name` abbreviates, if it names exactly one.
fn env_long(name: &str) -> Option<&'static str> {
    if let Some(exact) = ENV_LONG.iter().find(|l| **l == name) {
        return Some(exact);
    }
    let mut matches = ENV_LONG.iter().filter(|l| l.starts_with(name));
    match (matches.next(), matches.next()) {
        (Some(only), None) if name.len() > 2 => Some(only),
        _ => None,
    }
}

impl EnvCall<'_> {
    /// Record one option, spelled `-C` or `--chdir`, with its value.
    fn note(&mut self, flag: &str, value: Option<&str>) {
        match flag {
            "-C" | "--chdir" => self.chdir = true,
            "-P" => self.alt_path = true,
            "-S" | "--split-string" => self.split = Some(value.unwrap_or_default().to_owned()),
            _ => {}
        }
    }
}

// xargs

pub(crate) static XARGS_HANDLER: XargsHandler = XargsHandler;

pub(crate) struct XargsHandler;

/// Flags that take a value argument (skip both flag and value).
const XARGS_VALUE_FLAGS: &[&str] = &[
    "-I",
    "-n",
    "-P",
    "-L",
    "-s",
    "-E",
    "-d",
    "--max-args",
    "--max-procs",
    "--max-lines",
    "--max-chars",
    "--delimiter",
    "--eof",
    "--replace",
];

impl Handler for XargsHandler {
    fn commands(&self) -> &[&str] {
        &["xargs"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if has_flag(ctx.args, &["-p", "--interactive"]) {
            return Classification::Ask("xargs (interactive)".into());
        }
        let inner_start = find_xargs_inner_command(ctx.args);
        if let Some(placeholder) = xargs_placeholder(&ctx.args[..inner_start])
            && placeholder_injects(&ctx.args[inner_start..], &[placeholder.as_str()])
        {
            return Classification::Ask("xargs -I (input becomes code)".into());
        }
        if ctx.args[inner_start..].is_empty() {
            return Classification::Ask("xargs (no command)".into());
        }
        Classification::Recurse(resolve::shell_join(&ctx.args[inner_start..]))
    }

    /// Empty by design: `xargs` only re-analyzes its inner command, or asks.
    fn allow_surface(&self) -> Vec<AllowEntry> {
        Vec::new()
    }
}

/// Skip xargs flags (including flags that take value arguments) to find the inner command.
/// The replace string of `xargs -I STR`, `-ISTR`, `-i[STR]` or
/// `--replace[=STR]` (both default to `{}`), from xargs's own options.
fn xargs_placeholder(options: &[String]) -> Option<String> {
    let mut found = None;
    for (i, arg) in options.iter().enumerate() {
        if arg == "-I" {
            found = options.get(i + 1).cloned();
        } else if let Some(s) = arg
            .strip_prefix("-I")
            .or_else(|| arg.strip_prefix("--replace="))
        {
            found = Some(s.to_owned());
        } else if let Some(s) = arg.strip_prefix("-i") {
            found = Some(if s.is_empty() {
                "{}".to_owned()
            } else {
                s.to_owned()
            });
        } else if arg == "--replace" {
            found = Some("{}".to_owned());
        }
    }
    found.filter(|p| !p.is_empty())
}

fn find_xargs_inner_command(args: &[String]) -> usize {
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if XARGS_VALUE_FLAGS.contains(&arg) {
            i += 2; // skip flag + its value
        } else if XARGS_VALUE_FLAGS.iter().any(|f| arg.starts_with(f)) {
            i += 1; // value is attached (e.g., -n5)
        } else if arg.starts_with('-') {
            i += 1; // boolean flag
        } else {
            return i; // first positional = start of inner command
        }
    }
    args.len()
}

#[cfg(test)]
mod tests {

    use super::*;

    fn strings(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| (*s).to_owned()).collect()
    }

    fn inner(a: &[&str]) -> Vec<String> {
        parse_env(&strings(a)).inner.to_vec()
    }

    #[test]
    fn env_inner_command_keeps_the_inner_flags() {
        assert_eq!(
            inner(&["-i", "-u", "X", "FOO=1", "find", ".", "-delete"]),
            strings(&["find", ".", "-delete"])
        );
        let dd = ["dd", "if=/dev/zero", "of=/dev/sda"];
        assert_eq!(inner(&dd), strings(&dd));
        assert_eq!(inner(&["--", "ls", "-la"]), strings(&["ls", "-la"]));
        assert_eq!(inner(&["--", "FOO=1", "ls"]), strings(&["ls"]));
        // env reads no options after its first assignment: `-i` is the command.
        assert_eq!(inner(&["FOO=1", "-i"]), strings(&["-i"]));
    }

    // Code-quality review: long options with a separate value and short
    // clusters were not skipped, so the value was taken as the command.
    #[test]
    fn env_option_values_are_skipped_in_every_spelling() {
        let rm = strings(&["rm", "-rf", "foo"]);
        assert_eq!(inner(&["--unset", "cat", "rm", "-rf", "foo"]), rm);
        assert_eq!(inner(&["-iu", "cat", "rm", "-rf", "foo"]), rm);
        assert_eq!(inner(&["-uX", "rm", "-rf", "foo"]), rm);
        assert_eq!(inner(&["--unset=X", "rm", "-rf", "foo"]), rm);
    }

    #[test]
    fn env_chdir_and_alt_path_are_flagged() {
        assert!(parse_env(&strings(&["-C", "/etc", "ls"])).chdir);
        assert!(parse_env(&strings(&["-iC", "/etc", "ls"])).chdir);
        assert!(parse_env(&strings(&["--chdir=/etc", "ls"])).chdir);
        assert!(parse_env(&strings(&["-P", "./bin", "ls"])).alt_path);
        assert!(!parse_env(&strings(&["-i", "ls"])).chdir);
    }

    #[test]
    fn env_long_options_resolve_by_unique_prefix() {
        let args = strings(&["--ch", "/etc", "ls"]);
        let abbreviated = parse_env(&args);
        assert!(abbreviated.chdir);
        assert_eq!(abbreviated.inner, strings(&["ls"]));
        assert!(parse_env(&strings(&["--frobnicate", "ls"])).unknown);
        assert!(parse_env(&strings(&["--", "ls"])).inner == strings(&["ls"]));
        assert!(!parse_env(&strings(&["--ignore-env", "ls"])).unknown);
    }

    #[test]
    fn xargs_simple_inner_command() {
        let args: Vec<String> = vec!["rm".into()];
        let result = XARGS_HANDLER.classify(&HandlerContext::test("xargs", &args));
        assert!(matches!(result, Classification::Recurse(cmd) if cmd == "rm"));
    }

    #[test]
    fn xargs_skips_value_flags() {
        let args: Vec<String> = vec!["-n".into(), "5".into(), "grep".into(), "pattern".into()];
        let result = XARGS_HANDLER.classify(&HandlerContext::test("xargs", &args));
        assert!(
            matches!(result, Classification::Recurse(cmd) if cmd == "grep pattern"),
            "expected 'grep pattern'"
        );
    }

    #[test]
    fn xargs_skips_attached_value_flags() {
        let args: Vec<String> = vec!["-n5".into(), "grep".into(), "pattern".into()];
        let result = XARGS_HANDLER.classify(&HandlerContext::test("xargs", &args));
        assert!(matches!(result, Classification::Recurse(cmd) if cmd == "grep pattern"));
    }

    #[test]
    fn xargs_multiple_flags_with_values() {
        let args: Vec<String> = vec![
            "-P".into(),
            "4".into(),
            "-n".into(),
            "1".into(),
            "echo".into(),
        ];
        let result = XARGS_HANDLER.classify(&HandlerContext::test("xargs", &args));
        assert!(matches!(result, Classification::Recurse(cmd) if cmd == "echo"));
    }

    #[test]
    fn xargs_interactive_asks() {
        let args: Vec<String> = vec!["-p".into(), "rm".into()];
        let result = XARGS_HANDLER.classify(&HandlerContext::test("xargs", &args));
        assert!(matches!(result, Classification::Ask(_)));
    }

    #[test]
    fn xargs_no_inner_command() {
        let args: Vec<String> = vec!["-0".into(), "-n".into(), "5".into()];
        let result = XARGS_HANDLER.classify(&HandlerContext::test("xargs", &args));
        assert!(matches!(result, Classification::Ask(reason) if reason.contains("no command")));
    }

    #[test]
    fn xargs_replace_flag() {
        let args: Vec<String> = vec!["-I".into(), "{}".into(), "echo".into(), "{}".into()];
        let result = XARGS_HANDLER.classify(&HandlerContext::test("xargs", &args));
        assert!(matches!(result, Classification::Recurse(cmd) if cmd.starts_with("echo")));
    }

    #[test]
    fn env_bare_allows() {
        let args: Vec<String> = vec![];
        let result = ENV_HANDLER.classify(&HandlerContext::test("env", &args));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn env_with_command_recurses() {
        let args: Vec<String> = vec!["CI=bar".into(), "git".into(), "status".into()];
        let result = ENV_HANDLER.classify(&HandlerContext::test("env", &args));
        assert!(matches!(result, Classification::Recurse(_)));
    }

    #[test]
    fn split_string_separate_arg() {
        let args: Vec<String> = vec!["-S".into(), "LD_PRELOAD=x cat f".into()];
        assert_eq!(
            parse_env(&args).split.as_deref(),
            Some("LD_PRELOAD=x cat f")
        );
    }

    #[test]
    fn split_string_attached_short_and_long() {
        let short: Vec<String> = vec!["-SFOO=1 cat".into()];
        assert_eq!(parse_env(&short).split.as_deref(), Some("FOO=1 cat"));
        let long: Vec<String> = vec!["--split-string=FOO=1 cat".into()];
        assert_eq!(parse_env(&long).split.as_deref(), Some("FOO=1 cat"));
    }

    #[test]
    fn split_string_bundled_boolean_cluster() {
        let next: Vec<String> = vec!["-vS".into(), "FOO=1 cat".into()];
        assert_eq!(parse_env(&next).split.as_deref(), Some("FOO=1 cat"));
        let attached: Vec<String> = vec!["-vSFOO=1 cat".into()];
        assert_eq!(parse_env(&attached).split.as_deref(), Some("FOO=1 cat"));
    }

    #[test]
    fn short_clusters_are_parsed_getopt_style() {
        // `-u` takes the rest of its word, so `-uS` unsets `S`: no split.
        let args: Vec<String> = vec!["-uS".into(), "cat".into(), "f".into()];
        assert_eq!(parse_env(&args).split, None);
        assert_eq!(parse_env(&args).inner, &args[1..]);
        // An unknown letter leaves the command boundary uncertain: ask.
        let args: Vec<String> = vec!["-iZ".into(), "cat".into()];
        let result = ENV_HANDLER.classify(&HandlerContext::test("env", &args));
        assert!(matches!(result, Classification::Ask(_)));
    }

    // Acceptance review: `-S` in the inner command's arguments was read as
    // env's own, so `env rm -rf / -S ls` was judged as `ls`.
    #[test]
    fn split_string_is_only_an_env_option() {
        let args: Vec<String> = vec![
            "rm".into(),
            "-rf".into(),
            "/".into(),
            "-S".into(),
            "ls".into(),
        ];
        assert_eq!(parse_env(&args).split, None);
        assert_eq!(parse_env(&args).inner, &args[..]);
    }

    #[test]
    fn split_string_absent() {
        let args: Vec<String> = vec!["-i".into(), "FOO=1".into(), "cat".into()];
        assert_eq!(parse_env(&args).split, None);
    }
}
