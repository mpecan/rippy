use super::{
    Classification, Handler, HandlerContext, first_positional, get_flag_values, is_sole_help_flag,
};
use crate::perl_safety::is_perl_source_safe;

pub static PERL_HANDLER: PerlHandler = PerlHandler;

pub struct PerlHandler;

impl Handler for PerlHandler {
    fn commands(&self) -> &[&str] {
        &["perl"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        if is_sole_help_flag(ctx.args, &["--version", "-v", "--help", "-h"]) {
            return Classification::Allow("perl version/help".into());
        }

        // -e / -E inline code — Perl concatenates every fragment with "\n" at
        // runtime, so all occurrences must be analyzed together, not just the first.
        let fragments = get_flag_values(ctx.args, &["-e", "-E"]);
        if !fragments.is_empty() {
            let source = fragments.join("\n");
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

    use super::*;

    // Handler-level safe-inline Allow. The full pipeline Asks (catch-all
    // `command=perl` rule); catalog covers the pipeline decision.
    #[test]
    fn e_safe_print_allows() {
        let args = vec!["-e".into(), "print 'hello\\n'".into()];
        assert!(matches!(
            PERL_HANDLER.classify(&HandlerContext::test("perl", &args)),
            Classification::Allow(_)
        ));
    }

    // Handler-level danger arm: `-e`/`-E` inline dangerous code must Ask. The catalog's
    // isolated stdlib catch-all Asks for any `perl`, masking this arm at the pipeline
    // level, so the safety-critical danger->Ask direction is only observable here.
    #[test]
    fn e_dangerous_system_asks() {
        let args = vec!["-e".into(), "system('rm -rf /')".into()];
        assert!(matches!(
            PERL_HANDLER.classify(&HandlerContext::test("perl", &args)),
            Classification::Ask(_)
        ));
    }

    // Every -e fragment is concatenated for analysis, not just the first, so a
    // dangerous call hidden in a later fragment must still Ask.
    #[test]
    fn second_e_fragment_dangerous_asks() {
        let args = vec![
            "-e".into(),
            "1".into(),
            "-e".into(),
            "system(\"id\")".into(),
        ];
        assert!(matches!(
            PERL_HANDLER.classify(&HandlerContext::test("perl", &args)),
            Classification::Ask(_)
        ));
    }

    #[test]
    fn upper_e_dangerous_system_asks() {
        let args = vec!["-E".into(), "system('rm -rf /')".into()];
        assert!(matches!(
            PERL_HANDLER.classify(&HandlerContext::test("perl", &args)),
            Classification::Ask(_)
        ));
    }

    #[test]
    fn script_file_safe_allows() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("safe.pl"), "print 'hello\\n'").unwrap();
        let args = vec!["safe.pl".into()];
        let ctx = HandlerContext {
            working_directory: dir.path(),
            ..HandlerContext::test("perl", &args)
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
            working_directory: dir.path(),
            ..HandlerContext::test("perl", &args)
        };
        assert!(matches!(
            PERL_HANDLER.classify(&ctx),
            Classification::Ask(_)
        ));
    }
}
