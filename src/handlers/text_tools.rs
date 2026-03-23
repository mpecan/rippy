use super::{Classification, Handler, HandlerContext, has_flag};

// ---- sed ----

pub static SED_HANDLER: SedHandler = SedHandler;

pub struct SedHandler;

impl Handler for SedHandler {
    fn commands(&self) -> &[&str] {
        &["sed"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        // -i means in-place editing
        if has_flag(ctx.args, &["-i"]) || ctx.args.iter().any(|a| a.starts_with("-i")) {
            return Classification::Ask("sed -i (in-place edit)".into());
        }
        Classification::Allow("sed (filter)".into())
    }
}

// ---- awk ----

pub static AWK_HANDLER: AwkHandler = AwkHandler;

pub struct AwkHandler;

impl Handler for AwkHandler {
    fn commands(&self) -> &[&str] {
        &["awk", "gawk", "mawk", "nawk"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        // -f flag means script file execution
        if has_flag(ctx.args, &["-f"]) {
            return Classification::Ask(format!("{} -f (script file)", ctx.command_name));
        }
        Classification::Allow(format!("{} (filter)", ctx.command_name))
    }
}
