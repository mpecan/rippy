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

impl Handler for XargsHandler {
    fn commands(&self) -> &[&str] {
        &["xargs"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if has_flag(ctx.args, &["-p", "--interactive"]) {
            return Classification::Ask("xargs (interactive)".into());
        }
        // Extract inner command (first positional after xargs flags)
        let inner: Vec<&str> = ctx
            .args
            .iter()
            .skip_while(|a| a.starts_with('-'))
            .map(String::as_str)
            .collect();
        if inner.is_empty() {
            return Classification::Ask("xargs (no command)".into());
        }
        Classification::Recurse(inner.join(" "))
    }
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
