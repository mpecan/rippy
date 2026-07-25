use super::{
    Classification, Handler, HandlerContext, SubcommandHandler, has_flag, has_flag_or_prefixed,
    has_glued_short_flag, is_sole_help_flag,
};
use crate::verdict::AllowReason;

/// tar flags that spawn an external program (RCE regardless of archive flags used).
///
/// A denylist is used here rather than an allowlist because tar has dozens of
/// benign flags (`-z`/`-j`/`-v`/`-f`/`-C`) that an allowlist would over-restrict.
const TAR_PROGRAM_EXEC_FLAGS: &[&str] = &[
    "--use-compress-program",
    "-I",
    "--to-command",
    "--checkpoint-action",
    "--rmt-command",
    "-F",
    "--info-script",
    "--new-volume-script",
];

// tar

pub(crate) static TAR_HANDLER: TarHandler = TarHandler;

pub(crate) struct TarHandler;

impl Handler for TarHandler {
    fn commands(&self) -> &[&str] {
        &["tar"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        // --to-command delegates to an arbitrary program; recurse before any
        // other check so its target is evaluated rather than short-circuited.
        if let Some(pos) = ctx.args.iter().position(|a| a == "--to-command")
            && let Some(cmd) = ctx.args.get(pos + 1)
        {
            return Classification::Recurse(cmd.clone());
        }
        if has_flag_or_prefixed(ctx.args, TAR_PROGRAM_EXEC_FLAGS)
            || has_glued_short_flag(ctx.args, TAR_PROGRAM_EXEC_FLAGS)
        {
            return Classification::Ask("tar (runs external program)".into());
        }
        if has_flag(ctx.args, &["-t", "--list"]) {
            return Classification::Allow(AllowReason::handler("tar (list)"));
        }
        Classification::Ask("tar (create/extract)".into())
    }
}

// wget

pub(crate) static WGET_HANDLER: WgetHandler = WgetHandler;

pub(crate) struct WgetHandler;

impl Handler for WgetHandler {
    fn commands(&self) -> &[&str] {
        &["wget"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if has_flag(ctx.args, &["--spider"]) {
            return Classification::Allow(AllowReason::handler("wget --spider"));
        }
        if is_sole_help_flag(ctx.args, &["--help", "-h", "--version", "-V"]) {
            return Classification::Allow(AllowReason::handler("wget help/version"));
        }
        Classification::Ask("wget (download)".into())
    }
}

// gzip / unzip

pub(crate) static GZIP_HANDLER: SubcommandHandler = SubcommandHandler::new(
    &["gzip", "gunzip"],
    &["--stdout", "-c", "--list", "-l", "--test", "-t"],
    &[],
    "gzip",
);

pub(crate) static UNZIP_HANDLER: SubcommandHandler = SubcommandHandler::new(
    &["unzip", "7z", "7za", "7zr", "7zz"],
    &["l", "t"],                // list and test
    &["x", "e", "a", "d", "u"], // extract, add, delete, update
    "archive",
);

// mktemp

pub(crate) static MKTEMP_HANDLER: MktempHandler = MktempHandler;

pub(crate) struct MktempHandler;

impl Handler for MktempHandler {
    fn commands(&self) -> &[&str] {
        &["mktemp"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if has_flag(ctx.args, &["-u"]) {
            return Classification::Allow(AllowReason::handler("mktemp -u (dry run)"));
        }
        Classification::Ask("mktemp".into())
    }
}

// tee

pub(crate) static TEE_HANDLER: TeeHandler = TeeHandler;

pub(crate) struct TeeHandler;

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
            return Classification::Allow(AllowReason::handler("tee (stdout only)"));
        }
        Classification::WithRedirects(
            AllowReason::handler("tee"),
            files.iter().map(|f| (*f).to_owned()).collect(),
        )
    }
}

// sort

pub(crate) static SORT_HANDLER: SortHandler = SortHandler;

pub(crate) struct SortHandler;

impl Handler for SortHandler {
    fn commands(&self) -> &[&str] {
        &["sort"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if let Some(pos) = ctx.args.iter().position(|a| a == "-o" || a == "--output")
            && let Some(file) = ctx.args.get(pos + 1)
        {
            return Classification::WithRedirects(
                AllowReason::handler("sort -o"),
                vec![file.clone()],
            );
        }
        if let Some(file) = attached_output_value(ctx.args) {
            return Classification::WithRedirects(AllowReason::handler("sort -o"), vec![file]);
        }
        if has_flag_or_prefixed(ctx.args, &["-o", "--output"]) {
            return Classification::Ask("sort (output target not extractable)".into());
        }
        Classification::Allow(AllowReason::handler("sort"))
    }
}

/// Extract the path from an attached `sort` output flag: `--output=path` or `-oPATH`.
fn attached_output_value(args: &[String]) -> Option<String> {
    for arg in args {
        if let Some(path) = arg.strip_prefix("--output=") {
            return Some(path.to_owned());
        }
        if let Some(path) = arg.strip_prefix("-o")
            && !path.is_empty()
        {
            return Some(path.to_owned());
        }
    }
    None
}

// open

pub(crate) static OPEN_HANDLER: OpenHandler = OpenHandler;

pub(crate) struct OpenHandler;

impl Handler for OpenHandler {
    fn commands(&self) -> &[&str] {
        &["open"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if has_flag(ctx.args, &["-R"]) {
            return Classification::Allow(AllowReason::handler("open -R (reveal)"));
        }
        Classification::Ask("open".into())
    }
}

// yq

pub(crate) static YQ_HANDLER: YqHandler = YqHandler;

pub(crate) struct YqHandler;

impl Handler for YqHandler {
    fn commands(&self) -> &[&str] {
        &["yq"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if has_flag(ctx.args, &["-i", "--inplace"]) {
            return Classification::Ask("yq -i (in-place)".into());
        }
        Classification::Allow(AllowReason::handler("yq (filter)"))
    }
}

// Behavioral coverage (tar list/extract, wget, mktemp, open, yq) lives in
// tests/data/catalog/handlers_text_system.toml — pure command->decision mappings
// exercised through the real parse+analyze pipeline. The tee/sort `-o` redirect
// paths return WithRedirects and are covered by redirect integration tests.
