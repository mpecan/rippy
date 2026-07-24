use super::{
    Classification, Handler, HandlerContext, first_positional, get_flag_value, is_sole_help_flag,
};
use crate::ruby_safety::is_ruby_source_safe;

pub static RUBY_HANDLER: RubyHandler = RubyHandler;

pub struct RubyHandler;

impl Handler for RubyHandler {
    fn commands(&self) -> &[&str] {
        &["ruby", "irb"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if is_sole_help_flag(ctx.args, &["--version", "-v", "--help", "-h"]) {
            return Classification::Allow(format!("{} version/help", ctx.command_name));
        }

        if ctx.command_name == "irb" {
            return Classification::Ask("irb (interactive)".into());
        }

        // -e inline code: analyze source for dangerous patterns.
        if let Some(source) = get_flag_value(ctx.args, &["-e"]) {
            return if is_ruby_source_safe(&source) {
                Classification::Allow("ruby -e (safe inline code)".into())
            } else {
                Classification::Ask("ruby -e (potentially dangerous code)".into())
            };
        }

        if ctx.args.is_empty() {
            return Classification::Ask("ruby (interactive)".into());
        }

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

    use super::*;

    // Handler-level safe/dangerous inline distinction. NOTE: the full pipeline's
    // isolated stdlib config has a catch-all `command=ruby` rule that Asks, so the
    // safe-inline Allow is only observable at the handler level here — the catalog
    // covers the pipeline's fail-closed Ask. See tests/data/catalog/handlers_interpreters.toml.
    #[test]
    fn e_safe_puts_allows() {
        let args = vec!["-e".into(), "puts 'hello'".into()];
        assert!(matches!(
            RUBY_HANDLER.classify(&HandlerContext::test("ruby", &args)),
            Classification::Allow(_)
        ));
    }

    // Handler-level danger arm: `-e` inline dangerous code must Ask. The catalog's
    // isolated stdlib catch-all Asks for any `ruby`, masking this arm at the pipeline
    // level, so the safety-critical danger->Ask direction is only observable here.
    #[test]
    fn e_dangerous_system_asks() {
        let args = vec!["-e".into(), "system('rm -rf /')".into()];
        assert!(matches!(
            RUBY_HANDLER.classify(&HandlerContext::test("ruby", &args)),
            Classification::Ask(_)
        ));
    }

    #[test]
    fn script_file_safe_allows() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("safe.rb"), "puts 'hello'").unwrap();
        let args = vec!["safe.rb".into()];
        let ctx = HandlerContext {
            working_directory: dir.path(),
            ..HandlerContext::test("ruby", &args)
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
            working_directory: dir.path(),
            ..HandlerContext::test("ruby", &args)
        };
        assert!(matches!(
            RUBY_HANDLER.classify(&ctx),
            Classification::Ask(_)
        ));
    }
}
