use std::path::{Path, PathBuf};

use tree_sitter::Node;

use crate::allowlists;
use crate::ast;
use crate::config::Config;
use crate::error::RippyError;
use crate::handlers::{self, Classification, HandlerContext};
use crate::parser::BashParser;
use crate::verdict::Verdict;

/// The core analysis engine: parses a command and produces a safety verdict.
pub struct Analyzer {
    pub config: Config,
    pub parser: BashParser,
    pub remote: bool,
    pub working_directory: PathBuf,
}

impl Analyzer {
    /// Analyze a shell command string and return a safety verdict.
    ///
    /// # Errors
    ///
    /// Returns `RippyError::Parse` if the command cannot be parsed.
    pub fn analyze(&mut self, command: &str) -> Result<Verdict, RippyError> {
        // Check config command rules first (user rules override everything)
        if let Some(verdict) = self.config.match_command(command) {
            return Ok(verdict);
        }

        let tree = self.parser.parse(command)?;
        let root = tree.root_node();
        let cwd = self.working_directory.clone();
        Ok(self.analyze_node(root, command, &cwd))
    }

    fn analyze_node(&self, node: Node, source: &str, cwd: &Path) -> Verdict {
        match node.kind() {
            "program" | "pipeline" | "list" | "if_statement" | "while_statement"
            | "for_statement" | "case_statement" | "negated_command" | "compound_statement" => {
                self.analyze_children(node, source, cwd)
            }
            "command" => self.analyze_command(node, source, cwd),
            kind @ ("subshell" | "command_substitution" | "process_substitution") => {
                let inner = self.analyze_children(node, source, cwd);
                most_restrictive(inner, Verdict::ask(kind))
            }
            "function_definition" => Verdict::ask("function definition"),
            "redirected_statement" => self.analyze_redirected(node, source, cwd),
            "variable_assignment" => Self::analyze_assignment(node, source),
            _ if node.has_error() => Verdict::ask("unparseable command"),
            _ => self.analyze_children_or_allow(node, source, cwd),
        }
    }

    fn analyze_children(&self, node: Node, source: &str, cwd: &Path) -> Verdict {
        let mut verdicts = Vec::new();
        let mut cursor = node.walk();
        let mut current_cwd = cwd.to_owned();

        for child in node.named_children(&mut cursor) {
            let v = self.analyze_node(child, source, &current_cwd);

            // Track cd commands for working directory
            if child.kind() == "command"
                && let Some(dir) = extract_cd_target(child, source)
            {
                current_cwd = if Path::new(&dir).is_absolute() {
                    PathBuf::from(&dir)
                } else {
                    current_cwd.join(&dir)
                };
            }

            verdicts.push(v);
        }

        Verdict::combine(&verdicts)
    }

    fn analyze_children_or_allow(&self, node: Node, source: &str, cwd: &Path) -> Verdict {
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        if children.is_empty() {
            return Verdict::allow("");
        }
        let verdicts: Vec<Verdict> = children
            .iter()
            .map(|c| self.analyze_node(*c, source, cwd))
            .collect();
        Verdict::combine(&verdicts)
    }

    fn analyze_command(&self, node: Node, source: &str, cwd: &Path) -> Verdict {
        let Some(raw_name) = ast::command_name(node, source) else {
            return Verdict::allow("empty command");
        };
        let name = raw_name.to_owned();

        let args = ast::command_args(node, source);

        // Resolve aliases
        let resolved = self.config.resolve_alias(&name);
        let cmd_name = if resolved == name {
            name.clone()
        } else {
            resolved.to_owned()
        };

        // Wrapper commands: analyze inner command
        if allowlists::is_wrapper(&cmd_name) {
            if args.is_empty() {
                return Verdict::allow(format!("{cmd_name} (no inner command)"));
            }
            let inner = args.join(" ");
            return self.analyze_inner_command(&inner, cwd);
        }

        // Simple safe commands (but check for embedded expansions)
        if allowlists::is_simple_safe(&cmd_name) {
            if ast::has_expansions(node) {
                let inner_verdict = self.analyze_children(node, source, cwd);
                return most_restrictive(
                    Verdict::allow(format!("{cmd_name} is safe")),
                    inner_verdict,
                );
            }
            return Verdict::allow(format!("{cmd_name} is safe"));
        }

        // --help / --version on any command
        if args
            .iter()
            .any(|a| a == "--help" || a == "-h" || a == "--version")
        {
            return Verdict::allow(format!("{cmd_name} help/version"));
        }

        // Handler delegation
        if let Some(handler) = handlers::get_handler(&cmd_name) {
            let ctx = HandlerContext {
                command_name: &cmd_name,
                args: &args,
                working_directory: cwd,
                remote: self.remote,
            };
            return self.apply_classification(handler.classify(&ctx), cwd);
        }

        // Default: ask
        self.default_verdict(&cmd_name)
    }

    fn analyze_redirected(&self, node: Node, source: &str, cwd: &Path) -> Verdict {
        let mut cmd_verdict = Verdict::allow("");
        let mut redirect_verdicts = Vec::new();

        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if child.kind() == "file_redirect" {
                if let Some((op, target)) = ast::redirect_info(child, source) {
                    redirect_verdicts.push(self.analyze_redirect(op, &target));
                }
            } else {
                cmd_verdict = self.analyze_node(child, source, cwd);
            }
        }

        redirect_verdicts.push(cmd_verdict);
        Verdict::combine(&redirect_verdicts)
    }

    fn analyze_redirect(&self, op: ast::RedirectOp, target: &str) -> Verdict {
        // Read redirects are safe
        if op == ast::RedirectOp::Read {
            return Verdict::allow("input redirect");
        }

        // /dev/null is always safe
        if target == "/dev/null" || target == "/dev/stdout" || target == "/dev/stderr" {
            return Verdict::allow(format!("redirect to {target}"));
        }

        // FD duplication (2>&1 etc) is safe
        if op == ast::RedirectOp::FdDup {
            return Verdict::allow("fd redirect");
        }

        // Check config redirect rules
        if let Some(verdict) = self.config.match_redirect(target) {
            return verdict;
        }

        Verdict::ask(format!("redirect to {target}"))
    }

    fn analyze_assignment(node: Node, _source: &str) -> Verdict {
        if ast::has_expansions(node) {
            return Verdict::ask("assignment with command substitution");
        }
        Verdict::allow("variable assignment")
    }

    fn analyze_inner_command(&self, inner: &str, cwd: &Path) -> Verdict {
        let Ok(tree) = Self::parser_for_inner().parse(inner) else {
            return Verdict::ask("unparseable inner command");
        };
        self.analyze_node(tree.root_node(), inner, cwd)
    }

    fn apply_classification(&self, class: Classification, cwd: &Path) -> Verdict {
        match class {
            Classification::Allow(desc) => Verdict::allow(desc),
            Classification::Ask(desc) => Verdict::ask(desc),
            Classification::Deny(desc) => Verdict::deny(desc),
            Classification::Recurse(inner) => self.analyze_inner_command(&inner, cwd),
            Classification::WithRedirects(decision, desc, targets) => {
                let mut verdicts = vec![Verdict {
                    decision,
                    reason: desc,
                }];
                for target in &targets {
                    verdicts.push(self.analyze_redirect(ast::RedirectOp::Write, target));
                }
                Verdict::combine(&verdicts)
            }
        }
    }

    fn default_verdict(&self, cmd_name: &str) -> Verdict {
        self.config.default_action.map_or_else(
            || Verdict::ask(format!("{cmd_name} (unknown command)")),
            |action| Verdict {
                decision: action,
                reason: format!("{cmd_name} (default action)"),
            },
        )
    }

    /// Create a temporary parser for inner command analysis.
    /// This is needed because the main parser holds a mutable borrow.
    fn parser_for_inner() -> BashParser {
        BashParser::new().unwrap_or_else(|_| {
            // This should never fail since we already initialized once
            unreachable!("bash parser initialization should not fail twice")
        })
    }
}

fn extract_cd_target(node: Node, source: &str) -> Option<String> {
    let name = ast::command_name(node, source)?;
    if name != "cd" {
        return None;
    }
    let args = ast::command_args(node, source);
    args.first().cloned()
}

fn most_restrictive(a: Verdict, b: Verdict) -> Verdict {
    if a.decision >= b.decision { a } else { b }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::verdict::Decision;

    fn make_analyzer() -> Analyzer {
        Analyzer {
            config: Config::empty(),
            parser: BashParser::new().unwrap(),
            remote: false,
            working_directory: PathBuf::from("/tmp"),
        }
    }

    #[test]
    fn simple_safe_command() {
        let mut a = make_analyzer();
        let v = a.analyze("ls -la").unwrap();
        assert_eq!(v.decision, Decision::Allow);
    }

    #[test]
    fn git_status_safe() {
        let mut a = make_analyzer();
        let v = a.analyze("git status").unwrap();
        assert_eq!(v.decision, Decision::Allow);
    }

    #[test]
    fn git_push_asks() {
        let mut a = make_analyzer();
        let v = a.analyze("git push").unwrap();
        assert_eq!(v.decision, Decision::Ask);
    }

    #[test]
    fn rm_rf_asks() {
        let mut a = make_analyzer();
        let v = a.analyze("rm -rf /").unwrap();
        assert_eq!(v.decision, Decision::Ask);
    }

    #[test]
    fn pipeline_safe() {
        let mut a = make_analyzer();
        let v = a.analyze("cat file.txt | grep pattern").unwrap();
        assert_eq!(v.decision, Decision::Allow);
    }

    #[test]
    fn pipeline_mixed() {
        let mut a = make_analyzer();
        let v = a.analyze("cat file.txt | rm -rf /tmp").unwrap();
        assert_eq!(v.decision, Decision::Ask);
    }

    #[test]
    fn redirect_to_dev_null() {
        let mut a = make_analyzer();
        let v = a.analyze("echo foo > /dev/null").unwrap();
        assert_eq!(v.decision, Decision::Allow);
    }

    #[test]
    fn redirect_to_file_asks() {
        let mut a = make_analyzer();
        let v = a.analyze("echo foo > output.txt").unwrap();
        assert_eq!(v.decision, Decision::Ask);
    }

    #[test]
    fn wrapper_command_analyzes_inner() {
        let mut a = make_analyzer();
        let v = a.analyze("time git status").unwrap();
        assert_eq!(v.decision, Decision::Allow);
    }

    #[test]
    fn wrapper_command_unsafe_inner() {
        let mut a = make_analyzer();
        let v = a.analyze("time git push").unwrap();
        assert_eq!(v.decision, Decision::Ask);
    }

    #[test]
    fn command_substitution_asks() {
        let mut a = make_analyzer();
        let v = a.analyze("echo $(rm -rf /)").unwrap();
        assert_eq!(v.decision, Decision::Ask);
    }

    #[test]
    fn shell_c_recurses() {
        let mut a = make_analyzer();
        let v = a.analyze("bash -c 'git status'").unwrap();
        assert_eq!(v.decision, Decision::Allow);
    }

    #[test]
    fn shell_c_unsafe() {
        let mut a = make_analyzer();
        let v = a.analyze("bash -c 'rm -rf /'").unwrap();
        assert_eq!(v.decision, Decision::Ask);
    }

    #[test]
    fn config_override_allows() {
        use crate::config::Rule;
        use crate::pattern::Pattern;

        let config = Config::from_rules(vec![Rule::Command {
            kind: Decision::Allow,
            pattern: Pattern::new("rm -rf /tmp"),
            message: Some("cleanup allowed".into()),
        }]);
        let mut a = Analyzer {
            config,
            parser: BashParser::new().unwrap(),
            remote: false,
            working_directory: PathBuf::from("/tmp"),
        };
        let v = a.analyze("rm -rf /tmp").unwrap();
        assert_eq!(v.decision, Decision::Allow);
    }

    #[test]
    fn help_flag_always_safe() {
        let mut a = make_analyzer();
        let v = a.analyze("npm --help").unwrap();
        assert_eq!(v.decision, Decision::Allow);
    }

    #[test]
    fn list_and() {
        let mut a = make_analyzer();
        let v = a.analyze("ls && echo done").unwrap();
        assert_eq!(v.decision, Decision::Allow);
    }

    #[test]
    fn unknown_command_asks() {
        let mut a = make_analyzer();
        let v = a.analyze("some_unknown_tool --flag").unwrap();
        assert_eq!(v.decision, Decision::Ask);
    }
}
