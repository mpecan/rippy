use super::{Classification, Handler, HandlerContext, SubcommandHandler, has_flag};

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

// ---- tar ----

pub static TAR_HANDLER: TarHandler = TarHandler;

pub struct TarHandler;

impl Handler for TarHandler {
    fn commands(&self) -> &[&str] {
        &["tar"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if has_flag(ctx.args, &["-t", "--list"]) {
            return Classification::Allow("tar (list)".into());
        }
        // --to-command delegates
        if let Some(pos) = ctx.args.iter().position(|a| a == "--to-command")
            && let Some(cmd) = ctx.args.get(pos + 1)
        {
            return Classification::Recurse(cmd.clone());
        }
        Classification::Ask("tar (create/extract)".into())
    }
}

// ---- wget ----

pub static WGET_HANDLER: WgetHandler = WgetHandler;

pub struct WgetHandler;

impl Handler for WgetHandler {
    fn commands(&self) -> &[&str] {
        &["wget"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if has_flag(ctx.args, &["--spider"]) {
            return Classification::Allow("wget --spider".into());
        }
        if has_flag(ctx.args, &["--help", "-h", "--version", "-V"]) {
            return Classification::Allow("wget help/version".into());
        }
        Classification::Ask("wget (download)".into())
    }
}

// ---- uv ----

pub static UV_HANDLER: UvHandler = UvHandler;

pub struct UvHandler;

const UV_SAFE: &[&str] = &["sync", "lock", "tree", "version", "help", "venv", "export"];

impl Handler for UvHandler {
    fn commands(&self) -> &[&str] {
        &["uv", "uvx"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if ctx.command_name == "uvx" {
            return Classification::Ask(format!(
                "uvx {}",
                ctx.args.first().map_or("", String::as_str)
            ));
        }

        let sub = ctx.args.first().map_or("", String::as_str);

        if UV_SAFE.contains(&sub) {
            return Classification::Allow(format!("uv {sub}"));
        }

        if sub == "run" {
            // Delegate inner command
            let inner: Vec<&str> = ctx.args[1..]
                .iter()
                .skip_while(|a| a.starts_with('-'))
                .map(String::as_str)
                .collect();
            if inner.is_empty() {
                return Classification::Ask("uv run (no command)".into());
            }
            return Classification::Recurse(inner.join(" "));
        }

        if sub == "pip" {
            let pip_sub = ctx.args.get(1).map_or("", String::as_str);
            return match pip_sub {
                "list" | "freeze" | "show" | "check" | "tree" => {
                    Classification::Allow(format!("uv pip {pip_sub}"))
                }
                _ => Classification::Ask(format!("uv pip {pip_sub}")),
            };
        }

        if sub == "python" {
            let py_sub = ctx.args.get(1).map_or("", String::as_str);
            return match py_sub {
                "list" | "find" | "dir" => Classification::Allow(format!("uv python {py_sub}")),
                _ => Classification::Ask(format!("uv python {py_sub}")),
            };
        }

        if sub == "cache" {
            let cache_sub = ctx.args.get(1).map_or("", String::as_str);
            return match cache_sub {
                "dir" => Classification::Allow("uv cache dir".into()),
                _ => Classification::Ask(format!("uv cache {cache_sub}")),
            };
        }

        Classification::Ask(format!("uv {sub}"))
    }
}

// ---- Simple misc handlers via SubcommandHandler ----

pub static GZIP_HANDLER: SubcommandHandler = SubcommandHandler::new(
    &["gzip", "gunzip"],
    &["--stdout", "-c", "--list", "-l", "--test", "-t"],
    &[],
    "gzip",
);

pub static UNZIP_HANDLER: SubcommandHandler = SubcommandHandler::new(
    &["unzip", "7z", "7za", "7zr", "7zz"],
    &["l", "t"],                // list and test
    &["x", "e", "a", "d", "u"], // extract, add, delete, update
    "archive",
);

pub static MKTEMP_HANDLER: MktempHandler = MktempHandler;

pub struct MktempHandler;

impl Handler for MktempHandler {
    fn commands(&self) -> &[&str] {
        &["mktemp"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if has_flag(ctx.args, &["-u"]) {
            return Classification::Allow("mktemp -u (dry run)".into());
        }
        Classification::Ask("mktemp".into())
    }
}

pub static TEE_HANDLER: TeeHandler = TeeHandler;

pub struct TeeHandler;

impl Handler for TeeHandler {
    fn commands(&self) -> &[&str] {
        &["tee"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        let files: Vec<&str> = ctx
            .args
            .iter()
            .filter(|a| !a.starts_with('-'))
            .map(String::as_str)
            .collect();
        if files.is_empty() {
            return Classification::Allow("tee (stdout only)".into());
        }
        Classification::WithRedirects(
            crate::verdict::Decision::Allow,
            "tee".into(),
            files.iter().map(|f| (*f).to_owned()).collect(),
        )
    }
}

pub static SORT_HANDLER: SortHandler = SortHandler;

pub struct SortHandler;

impl Handler for SortHandler {
    fn commands(&self) -> &[&str] {
        &["sort"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if let Some(pos) = ctx.args.iter().position(|a| a == "-o")
            && let Some(file) = ctx.args.get(pos + 1)
        {
            return Classification::WithRedirects(
                crate::verdict::Decision::Allow,
                "sort -o".into(),
                vec![file.clone()],
            );
        }
        Classification::Allow("sort".into())
    }
}

pub static OPEN_HANDLER: OpenHandler = OpenHandler;

pub struct OpenHandler;

impl Handler for OpenHandler {
    fn commands(&self) -> &[&str] {
        &["open"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if has_flag(ctx.args, &["-R"]) {
            return Classification::Allow("open -R (reveal)".into());
        }
        Classification::Ask("open".into())
    }
}

pub static YQ_HANDLER: YqHandler = YqHandler;

pub struct YqHandler;

impl Handler for YqHandler {
    fn commands(&self) -> &[&str] {
        &["yq"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if has_flag(ctx.args, &["-i", "--inplace"]) {
            return Classification::Ask("yq -i (in-place)".into());
        }
        Classification::Allow("yq (filter)".into())
    }
}

pub static RUFF_HANDLER: RuffHandler = RuffHandler;

pub struct RuffHandler;

impl Handler for RuffHandler {
    fn commands(&self) -> &[&str] {
        &["ruff"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        let sub = ctx.args.first().map_or("", String::as_str);
        if sub == "format" || sub == "clean" || has_flag(ctx.args, &["--fix", "--fix-only"]) {
            return Classification::Ask(format!("ruff {sub} (modifying)"));
        }
        Classification::Allow(format!("ruff {sub}"))
    }
}

pub static BLACK_HANDLER: BlackHandler = BlackHandler;

pub struct BlackHandler;

impl Handler for BlackHandler {
    fn commands(&self) -> &[&str] {
        &["black"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if has_flag(ctx.args, &["--check", "--diff"]) {
            return Classification::Allow("black (check only)".into());
        }
        Classification::Ask("black (format)".into())
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

    #[test]
    fn uv_sync_allows() {
        let args: Vec<String> = vec!["sync".into()];
        let result = UV_HANDLER.classify(&ctx(&args, "uv"));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn uv_run_recurses() {
        let args: Vec<String> = vec!["run".into(), "python".into()];
        let result = UV_HANDLER.classify(&ctx(&args, "uv"));
        assert!(matches!(result, Classification::Recurse(_)));
    }

    #[test]
    fn uv_pip_list_allows() {
        let args: Vec<String> = vec!["pip".into(), "list".into()];
        let result = UV_HANDLER.classify(&ctx(&args, "uv"));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn tar_list_allows() {
        let args: Vec<String> = vec!["-t".into(), "archive.tar".into()];
        let result = TAR_HANDLER.classify(&ctx(&args, "tar"));
        assert!(matches!(result, Classification::Allow(_)));
    }

    #[test]
    fn tar_extract_asks() {
        let args: Vec<String> = vec!["-x".into(), "archive.tar".into()];
        let result = TAR_HANDLER.classify(&ctx(&args, "tar"));
        assert!(matches!(result, Classification::Ask(_)));
    }
}
