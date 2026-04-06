use super::{Classification, Handler, HandlerContext, SubcommandHandler, has_flag};

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

// ---- gzip / unzip ----

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

// ---- mktemp ----

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

// ---- tee ----

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

// ---- sort ----

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

// ---- open ----

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

// ---- yq ----

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
