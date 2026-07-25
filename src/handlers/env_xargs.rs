use super::{AllowEntry, Classification, Handler, HandlerContext, has_flag};
use crate::ast;
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
        if let Some(payload) = split_string_payload(ctx.args) {
            if payload.trim().is_empty() {
                return Classification::Ask("env (split-string)".into());
            }
            return Classification::Recurse(payload);
        }

        // Gate code-influencing NAME=VALUE args before the bare-env allow so a
        // bodiless `env LD_PRELOAD=x` cannot slip through.
        let dangerous_assignment = ctx
            .args
            .iter()
            .filter(|a| a.contains('=') && !a.starts_with('-'))
            .filter_map(|a| a.split_once('=').map(|(n, _)| n))
            .any(ast::is_dangerous_env_name);
        if dangerous_assignment {
            return Classification::Ask("env (dangerous env-var assignment)".into());
        }

        let positionals: Vec<&str> = ctx
            .args
            .iter()
            .filter(|a| !a.starts_with('-') && !a.contains('='))
            .map(String::as_str)
            .collect();

        if positionals.is_empty() {
            return Classification::Allow(AllowReason::handler("env (print environment)"));
        }

        // Delegate inner command
        Classification::Recurse(positionals.join(" "))
    }

    fn allow_surface(&self) -> Vec<AllowEntry> {
        vec![AllowEntry::guarded(
            "env [NAME=VALUE]...",
            "no inner command, no -S/--split-string, and no assignment to a code-influencing \
             variable (see docs/security-invariants.md#dangerous-env-name)",
        )]
    }
}

/// Extract the payload of a GNU `env` split-string option (`-S`, `-SSTR`,
/// `--split-string=STR`, a `-vS`-style short cluster), or `None` when absent.
///
/// A cluster whose leading chars are not known boolean flags (e.g. `-uS`, where
/// `-u` consumes an argument) is treated as split-string with an empty payload
/// so the caller fails closed rather than mis-parsing the option boundary.
fn split_string_payload(args: &[String]) -> Option<String> {
    for (i, arg) in args.iter().enumerate() {
        let a = arg.as_str();
        if let Some(v) = a.strip_prefix("--split-string=") {
            return Some(v.to_string());
        }
        if a == "--split-string" || a == "-S" {
            return Some(args.get(i + 1).map(String::to_string).unwrap_or_default());
        }
        if a.starts_with('-')
            && !a.starts_with("--")
            && let Some(idx) = a.find('S')
        {
            if !a[1..idx].chars().all(|c| matches!(c, 'i' | 'v' | '0')) {
                return Some(String::new());
            }
            let rest = &a[idx + 1..];
            if rest.is_empty() {
                return Some(args.get(i + 1).map(String::to_string).unwrap_or_default());
            }
            return Some(rest.to_string());
        }
    }
    None
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
        let inner: Vec<&str> = ctx.args[inner_start..].iter().map(String::as_str).collect();
        if inner.is_empty() {
            return Classification::Ask("xargs (no command)".into());
        }
        Classification::Recurse(inner.join(" "))
    }

    /// Empty by design: `xargs` only re-analyzes its inner command, or asks.
    fn allow_surface(&self) -> Vec<AllowEntry> {
        Vec::new()
    }
}

/// Skip xargs flags (including flags that take value arguments) to find the inner command.
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
        let args: Vec<String> = vec!["FOO=bar".into(), "git".into(), "status".into()];
        let result = ENV_HANDLER.classify(&HandlerContext::test("env", &args));
        assert!(matches!(result, Classification::Recurse(_)));
    }

    #[test]
    fn split_string_separate_arg() {
        let args: Vec<String> = vec!["-S".into(), "LD_PRELOAD=x cat f".into()];
        assert_eq!(
            split_string_payload(&args).as_deref(),
            Some("LD_PRELOAD=x cat f")
        );
    }

    #[test]
    fn split_string_attached_short_and_long() {
        let short: Vec<String> = vec!["-SFOO=1 cat".into()];
        assert_eq!(split_string_payload(&short).as_deref(), Some("FOO=1 cat"));
        let long: Vec<String> = vec!["--split-string=FOO=1 cat".into()];
        assert_eq!(split_string_payload(&long).as_deref(), Some("FOO=1 cat"));
    }

    #[test]
    fn split_string_bundled_boolean_cluster() {
        let next: Vec<String> = vec!["-vS".into(), "FOO=1 cat".into()];
        assert_eq!(split_string_payload(&next).as_deref(), Some("FOO=1 cat"));
        let attached: Vec<String> = vec!["-vSFOO=1 cat".into()];
        assert_eq!(
            split_string_payload(&attached).as_deref(),
            Some("FOO=1 cat")
        );
    }

    #[test]
    fn split_string_uncertain_cluster_fails_closed() {
        // `-u` consumes an argument, so the S boundary is ambiguous: fail closed.
        let args: Vec<String> = vec!["-uS".into(), "FOO=1 cat".into()];
        assert_eq!(split_string_payload(&args).as_deref(), Some(""));
        let result = ENV_HANDLER.classify(&HandlerContext::test("env", &args));
        assert!(matches!(result, Classification::Ask(_)));
    }

    #[test]
    fn split_string_absent() {
        let args: Vec<String> = vec!["-i".into(), "FOO=1".into(), "cat".into()];
        assert_eq!(split_string_payload(&args), None);
    }
}
