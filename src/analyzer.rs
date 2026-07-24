use std::path::{Path, PathBuf};

use rable::{Node, NodeKind};

use crate::allowlists;
use crate::ast;
use crate::cc_permissions::{self, CcRules};
use crate::condition::MatchContext;
use crate::config::Config;
use crate::environment::Environment;
use crate::error::RippyError;
use crate::handlers::{self, Classification, HandlerContext};
use crate::parser::BashParser;
use crate::resolve::{self, VarLookup};
use crate::verdict::{Decision, Verdict};

const MAX_DEPTH: usize = 256;

/// Maximum number of AST nodes walked per command. Bounds tree *breadth*
/// where `MAX_DEPTH` only bounds tree height: a pathological input that
/// produces thousands of sibling nodes at shallow depth would otherwise
/// slip through. Analysis that hits the cap returns Ask.
const MAX_NODES: usize = 10_000;

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
    /// Remaining AST-node budget for the current `analyze` call. Reset to
    /// `MAX_NODES` at the top of every public `analyze` call and decremented
    /// once per `analyze_node` entry. Returns Ask when exhausted.
    node_budget: usize,
}

impl Analyzer {
    /// Create a new analyzer from an [`Environment`] struct.
    ///
    /// This is the preferred constructor — it takes all external dependencies
    /// as an explicit struct, making tests deterministic without env-var hacks.
    ///
    /// # Errors
    ///
    /// Returns `RippyError::Parse` if the bash parser cannot be initialized.
    pub fn from_env(config: Config, env: Environment) -> Result<Self, RippyError> {
        let cc_rules = cc_permissions::load_cc_rules_with_home(&env.working_directory, env.home);
        let git_branch = crate::condition::detect_git_branch(&env.working_directory);
        Ok(Self {
            parser: BashParser::new()?,
            config,
            remote: env.remote,
            working_directory: env.working_directory,
            verbose: env.verbose,
            cc_rules,
            git_branch,
            piped: false,
            var_lookup: env.var_lookup,
            resolution_depth: 0,
            node_budget: MAX_NODES,
        })
    }

    /// Create a new analyzer using the real process environment for variable lookups.
    ///
    /// Convenience wrapper around [`Analyzer::from_env`] that reads `$HOME`
    /// and process env vars automatically.
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
        let env = Environment::from_system(working_directory, remote, verbose);
        Self::from_env(config, env)
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
        let env = Environment::from_system(working_directory, remote, verbose)
            .with_var_lookup(var_lookup);
        Self::from_env(config, env)
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
        // Normalize a leading `NAME=VALUE` env prefix so the string-matching
        // config/CC layers see the real command (e.g. `cargo test`) instead of
        // the assignment token. Parse once and reuse the result below. On
        // unparseable input we fall back to the raw string and the real parse
        // error still surfaces at the `?` after the string checks.
        // `strip_env_prefix` keeps the rest of the command verbatim (redirects,
        // pipes, `&&` chains), refuses to strip when a value contains an
        // expansion, and refuses to strip code-influencing vars — so no ALLOW
        // rule can bypass the analyzer's redirect or assignment-expansion guards.
        let parsed = self.parser.parse(command);
        let stripped = parsed
            .as_ref()
            .ok()
            .and_then(|nodes| ast::strip_env_prefix(command, nodes));
        let match_str = stripped.as_deref().unwrap_or(command);

        if let Some(decision) = self.cc_rules.check(match_str) {
            if self.verbose {
                eprintln!(
                    "[rippy] CC permission rule matched: {match_str} -> {}",
                    decision.as_str()
                );
            }
            return Ok(cc_decision_to_verdict(decision, match_str));
        }

        if let Some(verdict) = self
            .config
            .match_command(match_str, Some(&self.match_ctx()))
        {
            if self.verbose {
                eprintln!(
                    "[rippy] config rule matched: {match_str} -> {}",
                    verdict.decision.as_str()
                );
            }
            return Ok(verdict);
        }

        let nodes = parsed?;
        let cwd = self.working_directory.clone();
        self.node_budget = MAX_NODES;
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
        if self.node_budget == 0 {
            return Verdict::ask("ast node count exceeded");
        }
        self.node_budget -= 1;
        match &node.kind {
            NodeKind::Command { assignments, .. }
                if Self::assignment_has_expansion(assignments) =>
            {
                Verdict::ask("assignment with expansion")
            }
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
            NodeKind::CommandSubstitution { command, .. } => {
                let inner = self.analyze_node(command, cwd, depth + 1);
                if ast::is_safe_heredoc_substitution(command) {
                    inner
                } else {
                    most_restrictive(inner, Verdict::ask("command substitution"))
                }
            }
            NodeKind::ProcessSubstitution { command, .. } => {
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
                Verdict::combine(&self.analyze_redirects(redirects, cwd, depth))
            }
            _ if ast::is_expansion_node(&node.kind) => Verdict::ask("shell expansion"),
            _ => Verdict::ask("unrecognized shell construct"),
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

    /// Returns `true` if any `NAME=VALUE` assignment on a simple command has a
    /// shell expansion in its value (e.g. a command substitution or backticks).
    ///
    /// Assignment values are not otherwise inspected by the analyzer, so this
    /// guard — applied to every simple command, including those nested in
    /// pipelines and lists — forces such commands to Ask. Literal assignments
    /// (`FOO=bar ls`) contain no expansion and pass through unaffected.
    fn assignment_has_expansion(assignments: &[Node]) -> bool {
        assignments.iter().any(ast::has_expansions)
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
#[path = "analyzer_tests.rs"]
mod tests;
