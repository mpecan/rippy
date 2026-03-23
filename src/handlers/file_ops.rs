use super::{Classification, Handler, HandlerContext};

pub static FILE_OPS_HANDLER: FileOpsHandler = FileOpsHandler;

pub struct FileOpsHandler;

impl Handler for FileOpsHandler {
    fn commands(&self) -> &[&str] {
        &[
            "rm", "mv", "cp", "mkdir", "touch", "chmod", "chown", "chgrp", "ln", "install",
        ]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        Classification::Ask(format!("{} (file operation)", ctx.command_name))
    }
}
