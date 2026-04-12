use super::{Classification, Handler, HandlerContext, first_positional, get_flag_value, has_flag};
use crate::perl_safety::is_perl_source_safe;

pub static PERL_HANDLER: PerlHandler = PerlHandler;

pub struct PerlHandler;

impl Handler for PerlHandler {
    fn commands(&self) -> &[&str] {
        &["perl"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if has_flag(ctx.args, &["--version", "-v", "--help", "-h"]) {
            return Classification::Allow("perl version/help".into());
        }

        // -e / -E inline code — analyze source for dangerous patterns
        if let Some(source) = get_flag_value(ctx.args, &["-e", "-E"]) {
            return if is_perl_source_safe(&source) {
                Classification::Allow("perl -e (safe inline code)".into())
            } else {
                Classification::Ask("perl -e (potentially dangerous code)".into())
            };
        }

        // No args = reads from stdin
        if ctx.args.is_empty() {
            return Classification::Ask("perl (reads stdin)".into());
        }

        // Script file execution — try to read and analyze
        let script = first_positional(ctx.args).unwrap_or("");
        if let Some(source) = ctx.read_file(script) {
            return if is_perl_source_safe(&source) {
                Classification::Allow(format!("perl {script} (safe script)"))
            } else {
                Classification::Ask(format!("perl {script} (potentially dangerous)"))
            };
        }
        Classification::Ask("perl script execution".into())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::path::Path;

    use super::*;

    fn ctx(args: &[String]) -> HandlerContext<'_> {
        HandlerContext {
            command_name: "perl",
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
            PERL_HANDLER.classify(&ctx(&args)),
            Classification::Allow(_)
        ));
    }

    #[test]
    fn e_safe_print_allows() {
        let args = vec!["-e".into(), "print 'hello\\n'".into()];
        assert!(matches!(
            PERL_HANDLER.classify(&ctx(&args)),
            Classification::Allow(_)
        ));
    }

    #[test]
    fn e_system_asks() {
        let args = vec!["-e".into(), "system('rm -rf /')".into()];
        assert!(matches!(
            PERL_HANDLER.classify(&ctx(&args)),
            Classification::Ask(_)
        ));
    }

    #[test]
    fn e_backtick_asks() {
        let args = vec!["-e".into(), "`ls`".into()];
        assert!(matches!(
            PERL_HANDLER.classify(&ctx(&args)),
            Classification::Ask(_)
        ));
    }

    #[test]
    fn upper_e_asks_for_dangerous() {
        let args = vec!["-E".into(), "system('ls')".into()];
        assert!(matches!(
            PERL_HANDLER.classify(&ctx(&args)),
            Classification::Ask(_)
        ));
    }

    #[test]
    fn no_args_asks() {
        let args: Vec<String> = vec![];
        assert!(matches!(
            PERL_HANDLER.classify(&ctx(&args)),
            Classification::Ask(_)
        ));
    }

    #[test]
    fn script_file_missing_asks() {
        let args = vec!["script.pl".into()];
        assert!(matches!(
            PERL_HANDLER.classify(&ctx(&args)),
            Classification::Ask(_)
        ));
    }

    #[test]
    fn script_file_safe_allows() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("safe.pl"), "print 'hello\\n'").unwrap();
        let args = vec!["safe.pl".into()];
        let ctx = HandlerContext {
            command_name: "perl",
            args: &args,
            working_directory: dir.path(),
            remote: false,
            receives_piped_input: false,
            cd_allowed_dirs: &[],
        };
        assert!(matches!(
            PERL_HANDLER.classify(&ctx),
            Classification::Allow(_)
        ));
    }

    #[test]
    fn script_file_dangerous_asks() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("evil.pl"), "system('rm -rf /')").unwrap();
        let args = vec!["evil.pl".into()];
        let ctx = HandlerContext {
            command_name: "perl",
            args: &args,
            working_directory: dir.path(),
            remote: false,
            receives_piped_input: false,
            cd_allowed_dirs: &[],
        };
        assert!(matches!(
            PERL_HANDLER.classify(&ctx),
            Classification::Ask(_)
        ));
    }
}
