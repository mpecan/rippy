use super::{Classification, Handler, HandlerContext, first_positional, get_flag_value, has_flag};
use crate::ruby_safety::is_ruby_source_safe;

pub static RUBY_HANDLER: RubyHandler = RubyHandler;

pub struct RubyHandler;

impl Handler for RubyHandler {
    fn commands(&self) -> &[&str] {
        &["ruby", "irb"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if has_flag(ctx.args, &["--version", "-v", "--help", "-h"]) {
            return Classification::Allow(format!("{} version/help", ctx.command_name));
        }

        // irb is always interactive
        if ctx.command_name == "irb" {
            return Classification::Ask("irb (interactive)".into());
        }

        // -e inline code — analyze source for dangerous patterns
        if let Some(source) = get_flag_value(ctx.args, &["-e"]) {
            return if is_ruby_source_safe(&source) {
                Classification::Allow("ruby -e (safe inline code)".into())
            } else {
                Classification::Ask("ruby -e (potentially dangerous code)".into())
            };
        }

        // No args = interactive
        if ctx.args.is_empty() {
            return Classification::Ask("ruby (interactive)".into());
        }

        // Script file execution — try to read and analyze
        let script = first_positional(ctx.args).unwrap_or("");
        if let Some(source) = ctx.read_file(script) {
            return if is_ruby_source_safe(&source) {
                Classification::Allow(format!("ruby {script} (safe script)"))
            } else {
                Classification::Ask(format!("ruby {script} (potentially dangerous)"))
            };
        }
        Classification::Ask("ruby script execution".into())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::path::Path;

    use super::*;

    fn ctx(args: &[String]) -> HandlerContext<'_> {
        HandlerContext {
            command_name: "ruby",
            args,
            working_directory: Path::new("/tmp"),
            remote: false,
            receives_piped_input: false,
            cd_allowed_dirs: &[],
        }
    }

    #[test]
    fn version_allows() {
        let args = vec!["--version".into()];
        assert!(matches!(
            RUBY_HANDLER.classify(&ctx(&args)),
            Classification::Allow(_)
        ));
    }

    #[test]
    fn e_safe_puts_allows() {
        let args = vec!["-e".into(), "puts 'hello'".into()];
        assert!(matches!(
            RUBY_HANDLER.classify(&ctx(&args)),
            Classification::Allow(_)
        ));
    }

    #[test]
    fn e_system_asks() {
        let args = vec!["-e".into(), "system('rm -rf /')".into()];
        assert!(matches!(
            RUBY_HANDLER.classify(&ctx(&args)),
            Classification::Ask(_)
        ));
    }

    #[test]
    fn e_backtick_asks() {
        let args = vec!["-e".into(), "`ls`".into()];
        assert!(matches!(
            RUBY_HANDLER.classify(&ctx(&args)),
            Classification::Ask(_)
        ));
    }

    #[test]
    fn no_args_asks() {
        let args: Vec<String> = vec![];
        assert!(matches!(
            RUBY_HANDLER.classify(&ctx(&args)),
            Classification::Ask(_)
        ));
    }

    #[test]
    fn irb_asks() {
        let ctx = HandlerContext {
            command_name: "irb",
            args: &[],
            working_directory: Path::new("/tmp"),
            remote: false,
            receives_piped_input: false,
            cd_allowed_dirs: &[],
        };
        assert!(matches!(
            RUBY_HANDLER.classify(&ctx),
            Classification::Ask(_)
        ));
    }

    #[test]
    fn script_file_missing_asks() {
        let args = vec!["script.rb".into()];
        assert!(matches!(
            RUBY_HANDLER.classify(&ctx(&args)),
            Classification::Ask(_)
        ));
    }

    #[test]
    fn script_file_safe_allows() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("safe.rb"), "puts 'hello'").unwrap();
        let args = vec!["safe.rb".into()];
        let ctx = HandlerContext {
            command_name: "ruby",
            args: &args,
            working_directory: dir.path(),
            remote: false,
            receives_piped_input: false,
            cd_allowed_dirs: &[],
        };
        assert!(matches!(
            RUBY_HANDLER.classify(&ctx),
            Classification::Allow(_)
        ));
    }

    #[test]
    fn script_file_dangerous_asks() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("evil.rb"), "system('rm -rf /')").unwrap();
        let args = vec!["evil.rb".into()];
        let ctx = HandlerContext {
            command_name: "ruby",
            args: &args,
            working_directory: dir.path(),
            remote: false,
            receives_piped_input: false,
            cd_allowed_dirs: &[],
        };
        assert!(matches!(
            RUBY_HANDLER.classify(&ctx),
            Classification::Ask(_)
        ));
    }
}
