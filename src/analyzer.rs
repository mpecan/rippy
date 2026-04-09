use std::path::{Path, PathBuf};

use rable::{Node, NodeKind};

use crate::allowlists;
use crate::ast;
use crate::cc_permissions::{self, CcRules};
use crate::condition::MatchContext;
use crate::config::Config;
use crate::error::RippyError;
use crate::handlers::{self, Classification, HandlerContext};
use crate::parser::BashParser;
use crate::resolve::{self, EnvLookup, VarLookup};
use crate::verdict::{Decision, Verdict};

const MAX_DEPTH: usize = 256;

/// Maximum length (bytes) of a resolved command string. Resolution that
/// would produce a longer string falls back to Ask, preventing pathological
/// expansions (e.g., variables that contain other expansions, deeply
/// recursive aliases) from blowing up memory.
const MAX_RESOLVED_LEN: usize = 16_384;

/// Maximum number of nested resolution passes. Each call to `try_resolve`
/// re-parses the resolved command and may resolve again; this cap is
/// independent of `MAX_DEPTH` (which bounds AST node nesting) and prevents
/// `A=$B; B=$C; C=$A` cycles from blowing the stack.
const MAX_RESOLUTION_DEPTH: usize = 8;

/// The core analysis engine: parses a command and produces a safety verdict.
pub struct Analyzer {
    pub config: Config,
    pub parser: BashParser,
    pub remote: bool,
    pub working_directory: PathBuf,
    pub verbose: bool,
    cc_rules: CcRules,
    /// Cached current git branch name.
    git_branch: Option<String>,
    /// Set to true when analyzing a command that receives piped input.
    piped: bool,
    /// Variable lookup used for static expansion resolution.
    /// Defaults to `EnvLookup` (real process environment); tests inject mocks.
    var_lookup: Box<dyn VarLookup>,
    /// Tracks how many nested expansion-resolution passes have run for the
    /// current command. Bounded by `MAX_RESOLUTION_DEPTH` to prevent cycles.
    resolution_depth: usize,
}

impl Analyzer {
    /// Create a new analyzer using the real process environment for variable lookups.
    ///
    /// # Errors
    ///
    /// Returns `RippyError::Parse` if the bash parser cannot be initialized.
    pub fn new(
        config: Config,
        remote: bool,
        working_directory: PathBuf,
        verbose: bool,
    ) -> Result<Self, RippyError> {
        Self::new_with_var_lookup(
            config,
            remote,
            working_directory,
            verbose,
            Box::new(EnvLookup),
        )
    }

    /// Create a new analyzer with a custom variable lookup (used by tests
    /// to inject deterministic env values via `MockLookup`).
    ///
    /// # Errors
    ///
    /// Returns `RippyError::Parse` if the bash parser cannot be initialized.
    pub fn new_with_var_lookup(
        config: Config,
        remote: bool,
        working_directory: PathBuf,
        verbose: bool,
        var_lookup: Box<dyn VarLookup>,
    ) -> Result<Self, RippyError> {
        let cc_rules = cc_permissions::load_cc_rules(&working_directory);
        let git_branch = crate::condition::detect_git_branch(&working_directory);
        Ok(Self {
            parser: BashParser::new()?,
            config,
            remote,
            working_directory,
            verbose,
            cc_rules,
            git_branch,
            piped: false,
            var_lookup,
            resolution_depth: 0,
        })
    }

    /// Build a `MatchContext` for condition evaluation.
    fn match_ctx(&self) -> MatchContext<'_> {
        MatchContext {
            branch: self.git_branch.as_deref(),
            cwd: &self.working_directory,
        }
    }

    /// Analyze a shell command string and return a safety verdict.
    ///
    /// # Errors
    ///
    /// Returns `RippyError::Parse` if the command cannot be parsed.
    pub fn analyze(&mut self, command: &str) -> Result<Verdict, RippyError> {
        if let Some(decision) = self.cc_rules.check(command) {
            if self.verbose {
                eprintln!(
                    "[rippy] CC permission rule matched: {command} -> {}",
                    decision.as_str()
                );
            }
            return Ok(cc_decision_to_verdict(decision, command));
        }

        if let Some(verdict) = self.config.match_command(command, Some(&self.match_ctx())) {
            if self.verbose {
                eprintln!(
                    "[rippy] config rule matched: {command} -> {}",
                    verdict.decision.as_str()
                );
            }
            return Ok(verdict);
        }

        let nodes = self.parser.parse(command)?;
        let cwd = self.working_directory.clone();
        Ok(self.analyze_nodes(&nodes, &cwd, 0))
    }

    fn analyze_nodes(&mut self, nodes: &[Node], cwd: &Path, depth: usize) -> Verdict {
        if nodes.is_empty() {
            return Verdict::allow("");
        }
        let verdicts: Vec<Verdict> = nodes
            .iter()
            .map(|n| self.analyze_node(n, cwd, depth))
            .collect();
        Verdict::combine(&verdicts)
    }

    fn analyze_node(&mut self, node: &Node, cwd: &Path, depth: usize) -> Verdict {
        if depth > MAX_DEPTH {
            return Verdict::ask("nesting depth exceeded");
        }
        match &node.kind {
            NodeKind::Command {
                words, redirects, ..
            } => self.analyze_command_node(words, redirects, cwd, depth),
            NodeKind::Pipeline { commands, .. } => self.analyze_pipeline(commands, cwd, depth),
            NodeKind::List { items } => self.analyze_list(items, cwd, depth),
            NodeKind::If { .. }
            | NodeKind::While { .. }
            | NodeKind::Until { .. }
            | NodeKind::For { .. }
            | NodeKind::ForArith { .. }
            | NodeKind::Select { .. }
            | NodeKind::Case { .. }
            | NodeKind::BraceGroup { .. } => self.analyze_control_flow(node, cwd, depth),
            NodeKind::Subshell { body, redirects } => {
                let mut verdicts = vec![self.analyze_node(body, cwd, depth + 1)];
                verdicts.extend(self.analyze_redirects(redirects, cwd, depth));
                Verdict::combine(&verdicts)
            }
            NodeKind::CommandSubstitution { command, .. }
            | NodeKind::ProcessSubstitution { command, .. } => {
                let inner = self.analyze_node(command, cwd, depth + 1);
                most_restrictive(inner, Verdict::ask("command substitution"))
            }
            NodeKind::Function { .. } => Verdict::ask("function definition"),
            NodeKind::Negation { pipeline } | NodeKind::Time { pipeline, .. } => {
                self.analyze_node(pipeline, cwd, depth + 1)
            }
            NodeKind::HereDoc {
                quoted, content, ..
            } => Self::analyze_heredoc_node(*quoted, Some(content.as_str())),
            NodeKind::Coproc { command, .. } => self.analyze_node(command, cwd, depth + 1),
            NodeKind::ConditionalExpr { body, .. } => self.analyze_node(body, cwd, depth + 1),
            NodeKind::ArithmeticCommand { redirects, .. } => {
                let redirect_verdicts = self.analyze_redirects(redirects, cwd, depth);
                Verdict::combine(&redirect_verdicts)
            }
            _ if ast::is_expansion_node(&node.kind) => Verdict::ask("shell expansion"),
            _ => Verdict::allow(""),
        }
    }

    fn analyze_control_flow(&mut self, node: &Node, cwd: &Path, depth: usize) -> Verdict {
        match &node.kind {
            NodeKind::If {
                condition,
                then_body,
                else_body,
                redirects,
            } => {
                let mut parts: Vec<&Node> = vec![condition.as_ref(), then_body.as_ref()];
                if let Some(eb) = else_body.as_deref() {
                    parts.push(eb);
                }
                self.analyze_compound(&parts, redirects, cwd, depth)
            }
            NodeKind::While {
                condition,
                body,
                redirects,
            }
            | NodeKind::Until {
                condition,
                body,
                redirects,
            } => self.analyze_compound(&[condition.as_ref(), body.as_ref()], redirects, cwd, depth),
            NodeKind::For {
                body, redirects, ..
            }
            | NodeKind::ForArith {
                body, redirects, ..
            }
            | NodeKind::Select {
                body, redirects, ..
            }
            | NodeKind::BraceGroup { body, redirects } => {
                self.analyze_compound(&[body.as_ref()], redirects, cwd, depth)
            }
            NodeKind::Case {
                patterns,
                redirects,
                ..
            } => {
                let mut verdicts: Vec<Verdict> = patterns
                    .iter()
                    .filter_map(|p| p.body.as_ref())
                    .map(|b| self.analyze_node(b, cwd, depth + 1))
                    .collect();
                verdicts.extend(self.analyze_redirects(redirects, cwd, depth));
                Verdict::combine(&verdicts)
            }
            _ => Verdict::allow(""),
        }
    }

    fn analyze_pipeline(&mut self, commands: &[Node], cwd: &Path, depth: usize) -> Verdict {
        let has_unsafe_redirect = commands.iter().any(ast::has_unsafe_file_redirect);

        let mut verdicts: Vec<Verdict> = commands
            .iter()
            .enumerate()
            .map(|(i, cmd)| self.analyze_pipeline_command(cmd, i > 0, cwd, depth + 1))
            .collect();

        if has_unsafe_redirect {
            verdicts.push(Verdict::ask("pipeline writes to file"));
        }

        Verdict::combine(&verdicts)
    }

    fn analyze_pipeline_command(
        &mut self,
        node: &Node,
        piped: bool,
        cwd: &Path,
        depth: usize,
    ) -> Verdict {
        let prev_piped = self.piped;
        self.piped = piped;
        let v = self.analyze_node(node, cwd, depth);
        self.piped = prev_piped;
        v
    }

    fn analyze_list(&mut self, items: &[rable::ListItem], cwd: &Path, depth: usize) -> Verdict {
        let mut verdicts = Vec::new();
        let mut current_cwd = cwd.to_owned();
        let mut is_harmless_fallback = false;

        for (i, item) in items.iter().enumerate() {
            let v = self.analyze_node(&item.command, &current_cwd, depth + 1);

            if let Some(dir) = extract_cd_target(&item.command) {
                current_cwd = if Path::new(&dir).is_absolute() {
                    PathBuf::from(&dir)
                } else {
                    current_cwd.join(&dir)
                };
            }

            // In `|| true` patterns, only include the fallback if it's non-trivial
            if is_harmless_fallback && v.decision == Decision::Allow {
                is_harmless_fallback = false;
                continue;
            }
            is_harmless_fallback = false;

            if item.operator == Some(rable::ListOperator::Or)
                && items
                    .get(i + 1)
                    .is_some_and(|next| ast::is_harmless_fallback(&next.command))
            {
                is_harmless_fallback = true;
            }

            verdicts.push(v);
        }

        Verdict::combine(&verdicts)
    }

    fn analyze_compound(
        &mut self,
        parts: &[&Node],
        redirects: &[Node],
        cwd: &Path,
        depth: usize,
    ) -> Verdict {
        let mut verdicts: Vec<Verdict> = parts
            .iter()
            .map(|b| self.analyze_node(b, cwd, depth + 1))
            .collect();
        verdicts.extend(self.analyze_redirects(redirects, cwd, depth));
        Verdict::combine(&verdicts)
    }

    fn analyze_command_node(
        &mut self,
        words: &[Node],
        redirects: &[Node],
        cwd: &Path,
        depth: usize,
    ) -> Verdict {
        // Static expansion resolution: if any words contain expansions, attempt
        // to resolve them and re-classify the resolved command through the full
        // pipeline. This applies uniformly to safe-list, wrapper, and handler
        // paths — the resolved command goes back through analyze_inner_command.
        if let Some(resolved_verdict) = self.try_resolve(words, cwd, depth) {
            // Use Verdict::combine (not most_restrictive) so the resolved_command
            // field is preserved even when a redirect verdict dominates the
            // decision — combine borrows resolved_command from any input verdict.
            let mut verdicts = vec![resolved_verdict];
            verdicts.extend(self.analyze_redirects(redirects, cwd, depth));
            return Verdict::combine(&verdicts);
        }

        let Some(raw_name) = ast::command_name_from_words(words) else {
            return Verdict::allow("empty command");
        };
        let name = raw_name.to_owned();
        let args = ast::command_args_from_words(words);

        let resolved = self.config.resolve_alias(&name);
        let cmd_name = if resolved == name {
            name.clone()
        } else {
            resolved.to_owned()
        };

        if self.verbose {
            eprintln!("[rippy] command: {cmd_name}");
        }

        if allowlists::is_wrapper(&cmd_name) {
            if args.is_empty() {
                return Verdict::allow(format!("{cmd_name} (no inner command)"));
            }
            let inner = args.join(" ");
            return self.analyze_inner_command(&inner, cwd, depth);
        }

        if allowlists::is_simple_safe(&cmd_name) {
            if self.verbose {
                eprintln!("[rippy] allowlist: {cmd_name} is safe");
            }
            let mut v = Verdict::allow(format!("{cmd_name} is safe"));
            for rv in self.analyze_redirects(redirects, cwd, depth) {
                v = most_restrictive(v, rv);
            }
            return v;
        }

        if args
            .iter()
            .any(|a| a == "--help" || a == "-h" || a == "--version")
        {
            return Verdict::allow(format!("{cmd_name} help/version"));
        }

        let handler_verdict = self.classify_with_handler(&cmd_name, &args, cwd, depth);

        let redirect_verdicts = self.analyze_redirects(redirects, cwd, depth);
        if redirect_verdicts.is_empty() {
            handler_verdict
        } else {
            let mut all = vec![handler_verdict];
            all.extend(redirect_verdicts);
            Verdict::combine(&all)
        }
    }

    fn analyze_redirects(&self, redirects: &[Node], _cwd: &Path, _depth: usize) -> Vec<Verdict> {
        let mut verdicts = Vec::new();
        for redir in redirects {
            match &redir.kind {
                NodeKind::Redirect { .. } => {
                    if let Some((op, target)) = ast::redirect_info(redir) {
                        verdicts.push(self.analyze_redirect(op, &target));
                    }
                }
                NodeKind::HereDoc {
                    quoted, content, ..
                } => {
                    verdicts.push(Self::analyze_heredoc_node(*quoted, Some(content.as_str())));
                }
                _ => {}
            }
        }
        verdicts
    }

    fn classify_with_handler(
        &mut self,
        cmd_name: &str,
        args: &[String],
        cwd: &Path,
        depth: usize,
    ) -> Verdict {
        if let Some(handler) = handlers::get_handler(cmd_name) {
            let ctx = HandlerContext {
                command_name: cmd_name,
                args,
                working_directory: cwd,
                remote: self.remote,
                receives_piped_input: self.piped,
                cd_allowed_dirs: &self.config.cd_allowed_dirs,
            };
            let classification = handler.classify(&ctx);
            if self.verbose {
                eprintln!("[rippy] handler: {cmd_name} -> {classification:?}");
            }
            return self.apply_classification(classification, cwd, depth);
        }

        if self.verbose {
            eprintln!("[rippy] no handler for: {cmd_name}");
        }
        self.default_verdict(cmd_name)
    }

    fn analyze_redirect(&self, op: ast::RedirectOp, target: &str) -> Verdict {
        if op == ast::RedirectOp::Read {
            return Verdict::allow("input redirect");
        }
        if ast::is_safe_redirect_target(target) {
            return Verdict::allow(format!("redirect to {target}"));
        }
        if op == ast::RedirectOp::FdDup {
            return Verdict::allow("fd redirect");
        }
        if self.config.self_protect && crate::self_protect::is_protected_path(target) {
            return Verdict::deny(crate::self_protect::PROTECTION_MESSAGE);
        }
        if let Some(verdict) = self.config.match_redirect(target, Some(&self.match_ctx())) {
            return verdict;
        }
        Verdict::ask(format!("redirect to {target}"))
    }

    fn analyze_heredoc_node(quoted: bool, content: Option<&str>) -> Verdict {
        if quoted {
            return Verdict::allow("heredoc");
        }
        if let Some(body) = content
            && ast::has_shell_expansion_pattern(body)
        {
            return Verdict::ask("heredoc with expansion");
        }
        Verdict::allow("heredoc")
    }

    fn analyze_inner_command(&mut self, inner: &str, cwd: &Path, depth: usize) -> Verdict {
        let Ok(nodes) = self.parser.parse(inner) else {
            return Verdict::ask("unparseable inner command");
        };
        self.analyze_nodes(&nodes, cwd, depth)
    }

    /// Attempt to statically resolve any shell expansions in `words` and
    /// re-classify the resolved command through the full pipeline.
    ///
    /// Returns:
    /// - `None` when there are no expansions to resolve (caller proceeds normally)
    /// - `Some(verdict)` when expansions were present:
    ///   - On unresolvable expansions, an `Ask` verdict with a diagnostic reason
    ///   - On command-position dynamic execution (`$cmd args`), an `Ask` verdict
    ///     regardless of whether resolution succeeded
    ///   - Otherwise, the verdict of re-analyzing the resolved command
    ///     (annotated with the resolved form for transparency)
    fn try_resolve(&mut self, words: &[Node], cwd: &Path, depth: usize) -> Option<Verdict> {
        if !ast::has_expansions_in_slices(words, &[]) {
            return None;
        }
        // Bail out on runaway resolution before doing any work. Each nested
        // call increments `resolution_depth`; cycles like `A=$B; B=$A` are
        // caught here even if individual depths are small.
        if self.resolution_depth >= MAX_RESOLUTION_DEPTH {
            return Some(Verdict::ask("shell expansion (resolution depth exceeded)"));
        }
        let resolved = resolve::resolve_command_args(words, self.var_lookup.as_ref());
        let Some(args) = resolved.args else {
            let reason = resolved.failure_reason.map_or_else(
                || "shell expansion".to_string(),
                |r| format!("shell expansion ({r})"),
            );
            return Some(Verdict::ask(reason));
        };
        let resolved_command = resolve::shell_join(&args);
        // Refuse to materialize pathologically large resolved commands.
        if resolved_command.len() > MAX_RESOLVED_LEN {
            return Some(Verdict::ask(format!(
                "shell expansion (resolved command exceeds {MAX_RESOLVED_LEN}-byte limit)"
            )));
        }
        if self.verbose {
            eprintln!("[rippy] resolved: {resolved_command}");
        }
        if resolved.command_position_dynamic {
            return Some(
                Verdict::ask(format!("dynamic command (resolved: {resolved_command})"))
                    .with_resolution(resolved_command),
            );
        }
        // Track nesting around the recursive analyze_inner_command call.
        self.resolution_depth += 1;
        let inner = self.analyze_inner_command(&resolved_command, cwd, depth + 1);
        self.resolution_depth -= 1;
        Some(annotate_with_resolution(inner, &resolved_command))
    }

    fn apply_classification(&mut self, class: Classification, cwd: &Path, depth: usize) -> Verdict {
        match class {
            Classification::Allow(desc) => Verdict::allow(desc),
            Classification::Ask(desc) => Verdict::ask(desc),
            Classification::Deny(desc) => Verdict::deny(desc),
            Classification::Recurse(inner) => {
                if self.verbose {
                    eprintln!("[rippy] recurse: {inner}");
                }
                self.analyze_inner_command(&inner, cwd, depth)
            }
            Classification::RecurseRemote(inner) => {
                if self.verbose {
                    eprintln!("[rippy] recurse (remote): {inner}");
                }
                let prev_remote = self.remote;
                self.remote = true;
                let v = self.analyze_inner_command(&inner, cwd, depth);
                self.remote = prev_remote;
                v
            }
            Classification::WithRedirects(decision, desc, targets) => {
                let mut verdicts = vec![Verdict {
                    decision,
                    reason: desc,
                    resolved_command: None,
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
            |action| {
                let mut reason = format!("{cmd_name} (default action)");
                if action == Decision::Allow {
                    reason.push_str(self.config.weakening_suffix());
                }
                Verdict {
                    decision: action,
                    reason,
                    resolved_command: None,
                }
            },
        )
    }
}

fn cc_decision_to_verdict(decision: Decision, command: &str) -> Verdict {
    let reason = match decision {
        Decision::Allow => format!("{command} (CC permission: allow)"),
        Decision::Ask => format!("{command} (CC permission: ask)"),
        Decision::Deny => format!("{command} (CC permission: deny)"),
    };
    Verdict {
        decision,
        reason,
        resolved_command: None,
    }
}

/// Annotate a verdict with the resolved command form: appends `(resolved: <cmd>)`
/// to the reason (idempotent) and stores the resolved command in `resolved_command`.
fn annotate_with_resolution(mut v: Verdict, resolved: &str) -> Verdict {
    if !v.reason.contains("(resolved:") {
        v.reason = if v.reason.is_empty() {
            format!("(resolved: {resolved})")
        } else {
            format!("{} (resolved: {resolved})", v.reason)
        };
    }
    v.resolved_command = Some(resolved.to_string());
    v
}

fn extract_cd_target(node: &Node) -> Option<String> {
    let name = ast::command_name(node)?;
    if name != "cd" {
        return None;
    }
    let args = ast::command_args(node);
    args.first().cloned()
}

fn most_restrictive(a: Verdict, b: Verdict) -> Verdict {
    if a.decision >= b.decision { a } else { b }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::literal_string_with_formatting_args)]
mod tests {
    use super::*;
    use crate::resolve::tests::MockLookup;
    use crate::verdict::Decision;

    fn make_analyzer() -> Analyzer {
        // Use an empty MockLookup so default tests are deterministic regardless
        // of the host environment.
        make_analyzer_with(MockLookup::new())
    }

    fn make_analyzer_with(lookup: MockLookup) -> Analyzer {
        Analyzer::new_with_var_lookup(
            Config::empty(),
            false,
            PathBuf::from("/tmp"),
            false,
            Box::new(lookup),
        )
        .unwrap()
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
        use crate::config::{ConfigDirective, Rule, RuleTarget};

        let config = Config::from_directives(vec![ConfigDirective::Rule(
            Rule::new(RuleTarget::Command, Decision::Allow, "rm -rf /tmp")
                .with_message("cleanup allowed"),
        )]);
        let mut a = Analyzer::new(config, false, PathBuf::from("/tmp"), false).unwrap();
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

    #[test]
    fn depth_limit_exceeded() {
        let mut a = make_analyzer();
        let nodes = a.parser.parse("echo ok").unwrap();
        let v = a.analyze_node(&nodes[0], Path::new("/tmp"), MAX_DEPTH + 1);
        assert_eq!(v.decision, Decision::Ask);
        assert!(v.reason.contains("nesting depth exceeded"));
    }

    #[test]
    fn depth_at_max_still_works() {
        let mut a = make_analyzer();
        let nodes = a.parser.parse("echo ok").unwrap();
        let v = a.analyze_node(&nodes[0], Path::new("/tmp"), MAX_DEPTH - 2);
        assert_eq!(v.decision, Decision::Allow);
    }

    #[test]
    fn subshell_safe_allows() {
        let mut a = make_analyzer();
        let v = a.analyze("(echo ok)").unwrap();
        assert_eq!(v.decision, Decision::Allow); // subshell is transparent
    }

    #[test]
    fn heredoc_safe_allows() {
        let mut a = make_analyzer();
        let v = a.analyze("cat <<EOF\nhello world\nEOF").unwrap();
        assert_eq!(v.decision, Decision::Allow);
    }

    #[test]
    fn heredoc_quoted_delimiter_allows_even_with_expansion_syntax() {
        let mut a = make_analyzer();
        let v = a.analyze("cat <<'EOF'\n$(rm -rf /)\nEOF").unwrap();
        assert_eq!(v.decision, Decision::Allow);
    }

    #[test]
    fn nested_substitution_asks() {
        let mut a = make_analyzer();
        let v = a.analyze("echo $(echo $(whoami))").unwrap();
        assert_eq!(v.decision, Decision::Ask);
    }

    #[test]
    fn complex_pipeline_all_safe() {
        let mut a = make_analyzer();
        let v = a.analyze("cat file | grep pattern | head -5").unwrap();
        assert_eq!(v.decision, Decision::Allow);
    }

    #[test]
    fn if_statement_safe() {
        let mut a = make_analyzer();
        let v = a.analyze("if true; then echo yes; fi").unwrap();
        assert_eq!(v.decision, Decision::Allow);
    }

    #[test]
    fn if_statement_unsafe_body() {
        let mut a = make_analyzer();
        let v = a.analyze("if true; then rm -rf /; fi").unwrap();
        assert_eq!(v.decision, Decision::Ask);
    }

    #[test]
    fn for_loop_unsafe() {
        let mut a = make_analyzer();
        let v = a.analyze("for i in 1 2 3; do rm -rf /; done").unwrap();
        assert_eq!(v.decision, Decision::Ask);
    }

    #[test]
    fn empty_command_allows() {
        let mut a = make_analyzer();
        let v = a.analyze("").unwrap();
        assert_eq!(v.decision, Decision::Allow);
    }

    #[test]
    fn case_statement() {
        let mut a = make_analyzer();
        let v = a.analyze("case x in a) echo yes;; esac").unwrap();
        assert_eq!(v.decision, Decision::Allow);
    }

    #[test]
    fn cc_allow_rule_overrides_handler() {
        let dir = tempfile::tempdir().unwrap();
        let claude_dir = dir.path().join(".claude");
        std::fs::create_dir(&claude_dir).unwrap();
        std::fs::write(
            claude_dir.join("settings.local.json"),
            r#"{"permissions": {"allow": ["Bash(git push)"]}}"#,
        )
        .unwrap();
        let mut a = Analyzer::new(Config::empty(), false, dir.path().to_path_buf(), false).unwrap();
        let v = a.analyze("git push origin main").unwrap();
        assert_eq!(v.decision, Decision::Allow);
    }

    #[test]
    fn cc_deny_rule_overrides_handler() {
        let dir = tempfile::tempdir().unwrap();
        let claude_dir = dir.path().join(".claude");
        std::fs::create_dir(&claude_dir).unwrap();
        std::fs::write(
            claude_dir.join("settings.json"),
            r#"{"permissions": {"deny": ["Bash(ls)"]}}"#,
        )
        .unwrap();
        let mut a = Analyzer::new(Config::empty(), false, dir.path().to_path_buf(), false).unwrap();
        let v = a.analyze("ls").unwrap();
        assert_eq!(v.decision, Decision::Deny);
    }

    #[test]
    fn cc_rules_checked_before_rippy_config() {
        use crate::config::{ConfigDirective, Rule, RuleTarget};

        let dir = tempfile::tempdir().unwrap();
        let claude_dir = dir.path().join(".claude");
        std::fs::create_dir(&claude_dir).unwrap();
        std::fs::write(
            claude_dir.join("settings.local.json"),
            r#"{"permissions": {"allow": ["Bash(rm -rf /tmp)"]}}"#,
        )
        .unwrap();

        let config = Config::from_directives(vec![ConfigDirective::Rule(
            Rule::new(RuleTarget::Command, Decision::Ask, "rm -rf /tmp").with_message("dangerous"),
        )]);
        let mut a = Analyzer::new(config, false, dir.path().to_path_buf(), false).unwrap();
        let v = a.analyze("rm -rf /tmp").unwrap();
        assert_eq!(v.decision, Decision::Allow);
    }

    #[test]
    fn pipeline_with_file_redirect_asks() {
        let mut a = make_analyzer();
        let v = a.analyze("cat file | grep pattern > out.txt").unwrap();
        assert_eq!(v.decision, Decision::Ask);
    }

    #[test]
    fn pipeline_with_dev_null_allows() {
        let mut a = make_analyzer();
        let v = a.analyze("ls | grep foo > /dev/null").unwrap();
        assert_eq!(v.decision, Decision::Allow);
    }

    #[test]
    fn pipeline_mid_redirect_asks() {
        let mut a = make_analyzer();
        let v = a.analyze("echo hello > file.txt | cat").unwrap();
        assert_eq!(v.decision, Decision::Ask);
    }

    #[test]
    fn subshell_unsafe_propagates() {
        let mut a = make_analyzer();
        let v = a.analyze("(rm -rf /)").unwrap();
        assert_eq!(v.decision, Decision::Ask);
    }

    #[test]
    fn subshell_with_redirect_asks() {
        let mut a = make_analyzer();
        let v = a.analyze("(echo ok) > file.txt").unwrap();
        assert_eq!(v.decision, Decision::Ask);
    }

    #[test]
    fn or_true_uses_cmd_verdict() {
        let mut a = make_analyzer();
        let v = a.analyze("git push || true").unwrap();
        assert_eq!(v.decision, Decision::Ask);
    }

    #[test]
    fn safe_cmd_or_true_allows() {
        let mut a = make_analyzer();
        let v = a.analyze("ls || true").unwrap();
        assert_eq!(v.decision, Decision::Allow);
    }

    #[test]
    fn or_colon_uses_cmd_verdict() {
        let mut a = make_analyzer();
        let v = a.analyze("ls || :").unwrap();
        assert_eq!(v.decision, Decision::Allow);
    }

    #[test]
    fn or_with_unsafe_fallback_combines() {
        let mut a = make_analyzer();
        let v = a.analyze("ls || rm -rf /").unwrap();
        assert_eq!(v.decision, Decision::Ask);
    }

    #[test]
    fn and_combines_normally() {
        let mut a = make_analyzer();
        let v = a.analyze("ls && git push").unwrap();
        assert_eq!(v.decision, Decision::Ask);
    }

    #[test]
    fn command_substitution_floor_is_ask() {
        let mut a = make_analyzer();
        let v = a.analyze("echo $(ls)").unwrap();
        // Even though ls is safe, command substitution has an Ask floor
        assert_eq!(v.decision, Decision::Ask);
    }

    #[test]
    fn or_harmless_fallback_with_redirect_asks() {
        let mut a = make_analyzer();
        let v = a.analyze("ls || echo fail > log.txt").unwrap();
        assert_eq!(v.decision, Decision::Ask);
    }

    // ---- Expansion resolution tests ----

    #[test]
    fn param_expansion_in_safe_command_resolves_to_value() {
        let mut a = make_analyzer_with(MockLookup::new().with("HOME", "/Users/test"));
        let v = a.analyze("echo ${HOME}").unwrap();
        assert_eq!(v.decision, Decision::Allow);
        assert_eq!(v.resolved_command.as_deref(), Some("echo /Users/test"));
        assert!(v.reason.contains("(resolved: echo /Users/test)"));
    }

    #[test]
    fn simple_var_in_safe_command_resolves_to_value() {
        let mut a = make_analyzer_with(MockLookup::new().with("HOME", "/Users/test"));
        let v = a.analyze("echo $HOME").unwrap();
        assert_eq!(v.decision, Decision::Allow);
        assert_eq!(v.resolved_command.as_deref(), Some("echo /Users/test"));
    }

    #[test]
    fn ansi_c_in_safe_command_resolves_to_literal() {
        let mut a = make_analyzer();
        let v = a.analyze("echo $'\\x41'").unwrap();
        assert_eq!(v.decision, Decision::Allow);
        assert_eq!(v.resolved_command.as_deref(), Some("echo A"));
    }

    #[test]
    fn locale_string_in_safe_command_resolves_to_literal() {
        let mut a = make_analyzer();
        let v = a.analyze("echo $\"hello\"").unwrap();
        assert_eq!(v.decision, Decision::Allow);
        assert_eq!(v.resolved_command.as_deref(), Some("echo hello"));
    }

    #[test]
    fn arithmetic_expansion_in_safe_command_resolves_to_literal() {
        let mut a = make_analyzer();
        let v = a.analyze("echo $((1+1))").unwrap();
        assert_eq!(v.decision, Decision::Allow);
        assert_eq!(v.resolved_command.as_deref(), Some("echo 2"));
    }

    #[test]
    fn brace_expansion_in_safe_command_resolves_to_literal() {
        let mut a = make_analyzer();
        let v = a.analyze("echo {a,b,c}").unwrap();
        assert_eq!(v.decision, Decision::Allow);
        assert_eq!(v.resolved_command.as_deref(), Some("echo a b c"));
    }

    // ---- Heredoc tests (resolution NOT in scope for heredocs in this PR) ----

    #[test]
    fn heredoc_with_param_expansion_asks() {
        let mut a = make_analyzer();
        let v = a.analyze("cat <<EOF\n${HOME}\nEOF").unwrap();
        assert_eq!(v.decision, Decision::Ask);
    }

    #[test]
    fn heredoc_quoted_with_param_expansion_allows() {
        let mut a = make_analyzer();
        let v = a.analyze("cat <<'EOF'\n${HOME}\nEOF").unwrap();
        assert_eq!(v.decision, Decision::Allow);
    }

    #[test]
    fn heredoc_bare_var_asks() {
        let mut a = make_analyzer();
        let v = a.analyze("cat <<EOF\n$HOME\nEOF").unwrap();
        assert_eq!(v.decision, Decision::Ask);
    }

    #[test]
    fn safe_command_without_expansion_allows() {
        let mut a = make_analyzer();
        let v = a.analyze("echo hello").unwrap();
        assert_eq!(v.decision, Decision::Allow);
        assert!(v.resolved_command.is_none());
    }

    // ---- Tests for unresolvable expansions (still Ask) ----

    #[test]
    fn param_length_in_safe_command_asks() {
        let mut a = make_analyzer();
        let v = a.analyze("echo ${#var}").unwrap();
        assert_eq!(v.decision, Decision::Ask);
    }

    #[test]
    fn param_indirect_in_safe_command_asks() {
        let mut a = make_analyzer();
        let v = a.analyze("echo ${!ref}").unwrap();
        assert_eq!(v.decision, Decision::Ask);
    }

    #[test]
    fn unset_var_asks_with_diagnostic_reason() {
        let mut a = make_analyzer();
        let v = a.analyze("echo $UNSET").unwrap();
        assert_eq!(v.decision, Decision::Ask);
        assert!(
            v.reason.contains("$UNSET is not set"),
            "expected diagnostic about unset var, got: {}",
            v.reason
        );
    }

    #[test]
    fn command_substitution_still_asks() {
        // Command substitution can never be resolved statically.
        let mut a = make_analyzer();
        let v = a.analyze("echo $(whoami)").unwrap();
        assert_eq!(v.decision, Decision::Ask);
    }

    #[test]
    fn arithmetic_division_by_zero_asks() {
        let mut a = make_analyzer();
        let v = a.analyze("echo $((1/0))").unwrap();
        assert_eq!(v.decision, Decision::Ask);
    }

    // ---- Resolution that triggers handler-side Ask ----

    #[test]
    fn rm_with_resolved_arg_still_asks_via_handler() {
        let mut a = make_analyzer_with(MockLookup::new().with("TARGET", "/tmp/file"));
        let v = a.analyze("rm $TARGET").unwrap();
        // rm always asks via the handler, regardless of arg
        assert_eq!(v.decision, Decision::Ask);
        // But the verdict carries the resolved form
        assert_eq!(v.resolved_command.as_deref(), Some("rm /tmp/file"));
    }

    // ---- Command-position protection ----

    #[test]
    fn dynamic_command_position_asks_even_when_resolved() {
        // `$cmd args` with cmd=ls would normally allow ls, but command-position
        // dynamic execution is always Ask regardless of resolution.
        let mut a = make_analyzer_with(MockLookup::new().with("cmd", "ls"));
        let v = a.analyze("$cmd args").unwrap();
        assert_eq!(v.decision, Decision::Ask);
        assert!(
            v.reason.contains("dynamic command"),
            "expected dynamic-command reason, got: {}",
            v.reason
        );
        assert_eq!(v.resolved_command.as_deref(), Some("ls args"));
    }

    // ---- Handler-path resolution ----

    #[test]
    fn handler_path_resolves_quoted_subcommand() {
        // `git $'status'` should resolve to `git status` and let the git handler
        // classify it normally (status is safe).
        let mut a = make_analyzer();
        let v = a.analyze("git $'status'").unwrap();
        assert_eq!(v.decision, Decision::Allow);
        assert_eq!(v.resolved_command.as_deref(), Some("git status"));
    }

    // ---- Default with literal ----

    #[test]
    fn param_default_resolves_when_unset() {
        let mut a = make_analyzer();
        let v = a.analyze("echo ${UNSET:-default}").unwrap();
        assert_eq!(v.decision, Decision::Allow);
        assert_eq!(v.resolved_command.as_deref(), Some("echo default"));
    }

    // ---- Safety: variable values containing shell metacharacters ----

    #[test]
    fn var_value_with_command_substitution_stays_literal() {
        // If a variable's value LOOKS like command substitution (`$(whoami)`),
        // shell_join_arg must single-quote it so the re-parsed command sees a
        // literal string, not an expansion. echo is safe regardless of arg
        // content, so this should Allow with the value treated as data.
        let mut a = make_analyzer_with(MockLookup::new().with("CMD_STR", "$(whoami)"));
        let v = a.analyze("echo $CMD_STR").unwrap();
        assert_eq!(
            v.decision,
            Decision::Allow,
            "echo with literal-looking command sub should allow, got: {v:?}"
        );
        // The resolved form quotes the value to keep it literal.
        assert_eq!(v.resolved_command.as_deref(), Some("echo '$(whoami)'"));
    }

    #[test]
    fn var_value_with_dangerous_command_string_still_safe_for_echo() {
        // The killer test for the "content drives the verdict" claim:
        // a variable holding what LOOKS like `rm -rf /` is just a string when
        // passed to echo. echo is safe; the value is data, not execution.
        let mut a = make_analyzer_with(MockLookup::new().with("CMD_STR", "rm -rf /"));
        let v = a.analyze("echo $CMD_STR").unwrap();
        assert_eq!(v.decision, Decision::Allow);
        // The dangerous-looking string is single-quoted in the resolved form
        // so it's parsed as a single literal arg.
        assert_eq!(v.resolved_command.as_deref(), Some("echo 'rm -rf /'"));
    }

    #[test]
    fn var_value_with_backticks_stays_literal() {
        // Similar to command sub: `\`whoami\`` in a variable value should
        // become a quoted literal arg, not a re-evaluated substitution.
        let mut a = make_analyzer_with(MockLookup::new().with("X", "`whoami`"));
        let v = a.analyze("echo $X").unwrap();
        assert_eq!(v.decision, Decision::Allow);
        assert_eq!(v.resolved_command.as_deref(), Some("echo '`whoami`'"));
    }

    // ---- Safety limits ----

    #[test]
    fn huge_brace_expansion_falls_back_to_ask() {
        // {1..100000} would produce 100k items; brace expansion is capped
        // at MAX_BRACE_EXPANSION (1024), so this returns Unresolvable → Ask.
        let mut a = make_analyzer();
        let v = a.analyze("echo {1..100000}").unwrap();
        assert_eq!(v.decision, Decision::Ask);
    }

    #[test]
    fn cartesian_brace_explosion_falls_back_to_ask() {
        // {1..32}{1..32}{1..32} = 32k items, well over the cap.
        let mut a = make_analyzer();
        let v = a.analyze("echo {1..32}{1..32}{1..32}").unwrap();
        assert_eq!(v.decision, Decision::Ask);
    }

    #[test]
    fn variable_value_containing_dollar_is_not_re_expanded() {
        // bash does NOT recursively expand variable values, and neither do we:
        // A="$B" stores the literal string "$B", not the expansion of $B.
        // When `echo $A` resolves, the result is `echo '$B'` — the value is
        // single-quoted in the resolved form so it stays literal, and the
        // re-parse sees a quoted string with no expansions to follow.
        let mut a = make_analyzer_with(MockLookup::new().with("A", "$B").with("B", "actual"));
        let v = a.analyze("echo $A").unwrap();
        assert_eq!(v.decision, Decision::Allow);
        // The literal `$B` ends up single-quoted to prevent re-expansion.
        assert_eq!(v.resolved_command.as_deref(), Some("echo '$B'"));
    }
}
