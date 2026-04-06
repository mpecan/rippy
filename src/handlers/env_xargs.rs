use super::{Classification, Handler, HandlerContext, has_flag};

// ---- env ----

pub static ENV_HANDLER: EnvHandler = EnvHandler;

pub struct EnvHandler;

impl Handler for EnvHandler {
    fn commands(&self) -> &[&str] {
        &["env"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        // Bare `env` prints environment
        let positionals: Vec<&str> = ctx
            .args
            .iter()
            .filter(|a| !a.starts_with('-') && !a.contains('='))
            .map(String::as_str)
            .collect();

        if positionals.is_empty() {
            return Classification::Allow("env (print environment)".into());
        }

        // Delegate inner command
        Classification::Recurse(positionals.join(" "))
    }
}

// ---- xargs ----

pub static XARGS_HANDLER: XargsHandler = XargsHandler;

pub struct XargsHandler;

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
    fn xargs_simple_inner_command() {
        let args: Vec<String> = vec!["rm".into()];
        let result = XARGS_HANDLER.classify(&ctx(&args, "xargs"));
        assert!(matches!(result, Classification::Recurse(cmd) if cmd == "rm"));
    }

    #[test]
    fn xargs_skips_value_flags() {
        let args: Vec<String> = vec!["-n".into(), "5".into(), "grep".into(), "pattern".into()];
        let result = XARGS_HANDLER.classify(&ctx(&args, "xargs"));
        assert!(
            matches!(result, Classification::Recurse(cmd) if cmd == "grep pattern"),
            "expected 'grep pattern'"
        );
    }

    #[test]
    fn xargs_skips_attached_value_flags() {
        let args: Vec<String> = vec!["-n5".into(), "grep".into(), "pattern".into()];
        let result = XARGS_HANDLER.classify(&ctx(&args, "xargs"));
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
        let result = XARGS_HANDLER.classify(&ctx(&args, "xargs"));
        assert!(matches!(result, Classification::Recurse(cmd) if cmd == "echo"));
    }

    #[test]
    fn xargs_interactive_asks() {
        let args: Vec<String> = vec!["-p".into(), "rm".into()];
        let result = XARGS_HANDLER.classify(&ctx(&args, "xargs"));
        assert!(matches!(result, Classification::Ask(_)));
    }

    #[test]
    fn xargs_no_inner_command() {
        let args: Vec<String> = vec!["-0".into(), "-n".into(), "5".into()];
        let result = XARGS_HANDLER.classify(&ctx(&args, "xargs"));
        assert!(matches!(result, Classification::Ask(reason) if reason.contains("no command")));
    }

    #[test]
    fn xargs_replace_flag() {
        let args: Vec<String> = vec!["-I".into(), "{}".into(), "echo".into(), "{}".into()];
        let result = XARGS_HANDLER.classify(&ctx(&args, "xargs"));
        assert!(matches!(result, Classification::Recurse(cmd) if cmd.starts_with("echo")));
    }

    #[test]
    fn env_bare_allows() {
        let args: Vec<String> = vec![];
        let result = ENV_HANDLER.classify(&ctx(&args, "env"));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn env_with_command_recurses() {
        let args: Vec<String> = vec!["FOO=bar".into(), "git".into(), "status".into()];
        let result = ENV_HANDLER.classify(&ctx(&args, "env"));
        assert!(matches!(result, Classification::Recurse(_)));
    }
}
