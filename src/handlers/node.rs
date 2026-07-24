use super::{
    Classification, Handler, HandlerContext, first_positional, get_flag_value, has_flag,
    is_sole_help_flag,
};
use crate::node_safety::is_node_source_safe;

pub static NODE_HANDLER: NodeHandler = NodeHandler;

pub struct NodeHandler;

impl Handler for NodeHandler {
    fn commands(&self) -> &[&str] {
        &["node", "nodejs", "deno"]
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        // `-V` (capital) is deno's version flag; node/nodejs use `-v`. Listing
        // both is safe because the flag must be the SOLE argument to short-circuit.
        if is_sole_help_flag(ctx.args, &["--version", "-v", "-V", "--help", "-h"]) {
            return Classification::Allow(format!("{} version/help", ctx.command_name));
        }

        // deno eval subcommand — inline code as next positional arg
        if ctx.command_name == "deno" && ctx.args.first().map(String::as_str) == Some("eval") {
            let source = ctx.args.get(1).map_or("", String::as_str);
            return classify_inline(ctx.command_name, source);
        }

        // -e / --eval inline code — analyze source for dangerous patterns
        if let Some(source) = get_flag_value(ctx.args, &["-e", "--eval"]) {
            return classify_inline(ctx.command_name, &source);
        }

        // -p / --print evaluates an expression and prints the result
        if let Some(source) = get_flag_value(ctx.args, &["-p", "--print"]) {
            return classify_inline(ctx.command_name, &source);
        }

        // Interactive REPL
        if has_flag(ctx.args, &["-i", "--interactive"]) || ctx.args.is_empty() {
            return Classification::Ask(format!("{} (interactive)", ctx.command_name));
        }

        // Script file execution — try to read and analyze
        let script = first_positional(ctx.args).unwrap_or("");
        if let Some(source) = ctx.read_file(script) {
            return if is_node_source_safe(&source) {
                Classification::Allow(format!("{} {script} (safe script)", ctx.command_name))
            } else {
                Classification::Ask(format!(
                    "{} {script} (potentially dangerous)",
                    ctx.command_name
                ))
            };
        }
        Classification::Ask(format!("{} script execution", ctx.command_name))
    }
}

fn classify_inline(cmd: &str, source: &str) -> Classification {
    if is_node_source_safe(source) {
        Classification::Allow(format!("{cmd} -e (safe inline code)"))
    } else {
        Classification::Ask(format!("{cmd} -e (potentially dangerous code)"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {

    use super::*;

    // Command->decision cases are covered by the catalog
    // (tests/data/catalog/handlers_interpreters.toml). Retained tests exercise the
    // handler-level safe/dangerous distinction (the pipeline Asks via a catch-all
    // `command=node` rule) and read_file, neither reachable from a command string.
    #[test]
    fn deno_capital_v_version_allows() {
        // deno uses `-V` for --version; a lone version flag must short-circuit.
        let args = vec!["-V".into()];
        let ctx = HandlerContext {
            command_name: "deno",
            args: &args,
            working_directory: Path::new("/tmp"),
            remote: false,
            receives_piped_input: false,
            safe_scopes: &[],
        };
        assert!(matches!(
            NODE_HANDLER.classify(&ctx),
            Classification::Allow(_)
        ));
    }

    #[test]
    fn e_safe_console_log_allows() {
        let args = vec!["-e".into(), "console.log('hi')".into()];
        assert!(matches!(
            NODE_HANDLER.classify(&HandlerContext::test("node", &args)),
            Classification::Allow(_)
        ));
    }

    #[test]
    fn p_safe_allows() {
        let args = vec!["-p".into(), "Math.PI".into()];
        assert!(matches!(
            NODE_HANDLER.classify(&HandlerContext::test("node", &args)),
            Classification::Allow(_)
        ));
    }

    // Handler-level danger arm: `-e`/`-p` inline dangerous code and `deno eval` must
    // Ask. The catalog's isolated stdlib catch-all Asks for any node/deno, masking these
    // arms at the pipeline level, so the safety-critical danger->Ask direction is only
    // observable here.
    #[test]
    fn e_dangerous_require_child_process_asks() {
        let args = vec![
            "-e".into(),
            "require('child_process').execSync('rm -rf /')".into(),
        ];
        assert!(matches!(
            NODE_HANDLER.classify(&HandlerContext::test("node", &args)),
            Classification::Ask(_)
        ));
    }

    #[test]
    fn p_dangerous_eval_asks() {
        let args = vec!["-p".into(), "eval('code')".into()];
        assert!(matches!(
            NODE_HANDLER.classify(&HandlerContext::test("node", &args)),
            Classification::Ask(_)
        ));
    }

    #[test]
    fn deno_eval_dangerous_asks() {
        let args = vec![
            "eval".into(),
            "require('child_process').execSync('rm -rf /')".into(),
        ];
        assert!(matches!(
            NODE_HANDLER.classify(&HandlerContext::test("deno", &args)),
            Classification::Ask(_)
        ));
    }

    #[test]
    fn script_file_safe_allows() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("safe.js"), "console.log('hello')").unwrap();
        let args = vec!["safe.js".into()];
        let ctx = HandlerContext {
            working_directory: dir.path(),
            ..HandlerContext::test("node", &args)
        };
        assert!(matches!(
            NODE_HANDLER.classify(&ctx),
            Classification::Allow(_)
        ));
    }

    #[test]
    fn script_file_dangerous_asks() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("evil.js"),
            "require('child_process').execSync('rm -rf /')",
        )
        .unwrap();
        let args = vec!["evil.js".into()];
        let ctx = HandlerContext {
            working_directory: dir.path(),
            ..HandlerContext::test("node", &args)
        };
        assert!(matches!(
            NODE_HANDLER.classify(&ctx),
            Classification::Ask(_)
        ));
    }

    #[test]
    fn deno_eval_safe_allows() {
        let args = vec!["eval".into(), "console.log('hi')".into()];
        let ctx = HandlerContext::test("deno", &args);
        assert!(matches!(
            NODE_HANDLER.classify(&ctx),
            Classification::Allow(_)
        ));
    }
}
