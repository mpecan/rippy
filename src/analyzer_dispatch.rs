use std::path::{Path, PathBuf};

use rable::{Node, NodeKind};

use super::{
    Analyzer, EXPANSION_ASK, MAX_RESOLUTION_DEPTH, MAX_RESOLVED_LEN, annotate_with_resolution,
};
use crate::allowlists;
use crate::ask_rules;
use crate::ast;
use crate::handlers::{self, Classification, HandlerContext};
use crate::resolve::{self, VarLookup};
use crate::trace::{Stage, Trace};
use crate::verdict::UncertainKind::{DynamicExpansion, Unanalyzable};
use crate::verdict::{AllowReason, AskClass, Decision, Verdict};

impl Analyzer {
    pub(super) fn analyze_redirects(
        &mut self,
        redirects: &[Node],
        cwd: &Path,
        _depth: usize,
    ) -> Vec<Verdict> {
        let mut verdicts = Vec::new();
        for redir in redirects {
            match &redir.kind {
                NodeKind::Redirect { .. } => {
                    if let Some((op, target)) = ast::redirect_info(redir) {
                        verdicts.push(self.analyze_redirect(op, &target, cwd));
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

    pub(super) fn classify_with_handler(
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
                safe_scopes: &self.config.safe_scopes,
            };
            let classification = handler.classify(&ctx);
            self.trace(Stage::Handler, true, || {
                format!("{cmd_name} -> {classification:?}")
            });
            return self.apply_classification(classification, cwd, depth);
        }

        self.trace(Stage::Handler, false, || {
            format!("no handler registered for {cmd_name}")
        });
        self.default_verdict(cmd_name, args, cwd)
    }

    /// Match a single simple command (leaf) against the CC-permission and config
    /// string rules, returning the rule's verdict (with any redirects combined in)
    /// or `None` when no rule matches.
    ///
    /// The leaf is reconstructed from its own words only — the leading `NAME=VALUE`
    /// env prefix lives in the command's separate `assignments` and is never part
    /// of `words`, so `RUST_LOG=debug cargo test` matches as `cargo test`. Called
    /// per leaf (not on the raw chained string) so a trailing payload can never
    /// ride along on a leading allow-ruled command.
    pub(super) fn leaf_string_rule(
        &mut self,
        name: &str,
        args: &[String],
        redirects: &[Node],
        cwd: &Path,
    ) -> Option<Verdict> {
        let leaf = if args.is_empty() {
            name.to_owned()
        } else {
            format!("{name} {}", args.join(" "))
        };
        if let Some(decision) = self.cc_rules.check(&leaf) {
            self.trace(Stage::CcRule, true, || {
                format!("{}: {leaf}", decision.as_str())
            });
            let v = super::cc_decision_to_verdict(decision, &leaf);
            return Some(self.with_redirects(v, redirects, cwd));
        }
        let matched = {
            let ctx = self.match_ctx();
            self.config.match_command(&leaf, Some(&ctx))
        };
        let verdict = matched?;
        self.trace(Stage::ConfigRule, true, || {
            format!("{}: {}", verdict.decision.as_str(), verdict.reason)
        });
        Some(self.with_redirects(verdict, redirects, cwd))
    }

    /// Combine a command-level verdict with the verdicts of its redirects
    /// (most-restrictive wins), so an allow rule / safe command cannot bypass the
    /// redirect safety pipeline (self-protect, safe-dir, deny rules).
    pub(super) fn with_redirects(
        &mut self,
        verdict: Verdict,
        redirects: &[Node],
        cwd: &Path,
    ) -> Verdict {
        // `analyze_redirects` ignores the depth argument (redirect targets are leaf
        // paths, not recursively analyzed commands), so a fixed 0 is fine here.
        let redirect_verdicts = self.analyze_redirects(redirects, cwd, 0);
        if redirect_verdicts.is_empty() {
            return verdict;
        }
        let mut all = vec![verdict];
        all.extend(redirect_verdicts);
        Verdict::combine(&all)
    }

    /// Run one redirect target through the write pipeline, recording the gate's
    /// own verdict so the trace explains a decision the command word cannot.
    pub(super) fn analyze_redirect(
        &mut self,
        op: ast::RedirectOp,
        target: &str,
        cwd: &Path,
    ) -> Verdict {
        let verdict = self.redirect_verdict(op, target, cwd);
        self.trace(Stage::Redirect, true, || {
            format!("{}: {}", verdict.decision.as_str(), verdict.reason)
        });
        verdict
    }

    fn redirect_verdict(&self, op: ast::RedirectOp, target: &str, cwd: &Path) -> Verdict {
        // Before the read shortcut: `cat < "$(x)"` reads a file *named by* `x`.
        if ast::has_executing_substitution(target) {
            return Verdict::uncertain(Unanalyzable, EXPANSION_ASK);
        }
        if op == ast::RedirectOp::Read {
            return Verdict::allow(AllowReason::InputRedirect);
        }
        // `&>`/`>&` parse as `FdDup`; a path target is a real file write and must
        // run the write pipeline. see docs/security-invariants.md#fd-dup-remap
        let op = if op == ast::RedirectOp::FdDup {
            if ast::is_fd_dup_target(target) {
                return Verdict::allow(AllowReason::FdRedirect);
            }
            ast::RedirectOp::Write
        } else {
            op
        };
        if ast::is_safe_redirect_target(target) {
            return Verdict::allow(AllowReason::DeviceRedirect(target.to_owned()));
        }
        if self.config.self_protect && crate::self_protect::is_protected_path(target) {
            return Verdict::deny(crate::self_protect::PROTECTION_MESSAGE);
        }
        if let Some(verdict) = self.config.match_redirect(target, Some(&self.match_ctx())) {
            return verdict;
        }
        // Safe-dir writes auto-approve, but only after self_protect and user
        // rules so those stronger decisions win.
        if matches!(op, ast::RedirectOp::Write | ast::RedirectOp::Append)
            && self.is_safe_write_target(target, cwd)
        {
            return Verdict::allow(AllowReason::SafeDirWrite(target.to_owned()));
        }
        Verdict::ask(format!("redirect to {target}"))
    }

    /// Returns `true` only for statically-known write targets that resolve inside
    /// the trusted safe-dir set (declared scopes or default safe dirs). Relative
    /// targets resolve against `cwd`. Conservative by construction and guarded by
    /// a cwd exclusion and a symlink re-check for the world-writable defaults —
    /// see docs/security-invariants.md#tmp-symlink.
    pub(super) fn is_safe_write_target(&self, target: &str, cwd: &Path) -> bool {
        let target = resolve::strip_outer_quotes(target);
        if ast::has_shell_expansion_pattern(&target)
            || target.starts_with('~')
            || target.contains(['*', '?', '['])
        {
            return false;
        }
        let raw = Path::new(&target);
        let resolved = if raw.is_absolute() {
            handlers::normalize_path(raw)
        } else {
            handlers::normalize_path(&cwd.join(raw))
        };
        // Project files keep asking even when cwd lives under a safe dir.
        if resolved.starts_with(handlers::normalize_path(cwd)) {
            return false;
        }
        // Declared scopes are trusted opt-ins: logical match, no symlink re-check.
        let scopes = &self.config.safe_scopes;
        if scopes.iter().any(|d| resolved.starts_with(d)) {
            return true;
        }
        // Default dirs are world-writable: require both the logical target and its
        // symlink-resolved real path to stay inside the defaults.
        handlers::is_within_default_safe_dir(&resolved)
            && handlers::is_within_default_safe_dir(&canonicalize_existing_ancestor(&resolved))
    }

    /// Scope-aware unsafe-redirect check: a command has an unsafe write/append
    /// redirect only when its target is neither inherently safe (`/dev/null`)
    /// nor inside the trusted safe-dir set.
    pub(super) fn command_has_unsafe_redirect(&self, node: &Node, cwd: &Path) -> bool {
        let NodeKind::Command { redirects, .. } = &node.kind else {
            return false;
        };
        redirects.iter().any(|r| {
            let Some((op, target)) = ast::redirect_info(r) else {
                return false;
            };
            matches!(op, ast::RedirectOp::Write | ast::RedirectOp::Append)
                && !ast::is_safe_redirect_target(&target)
                && !self.is_safe_write_target(&target, cwd)
        })
    }

    pub(super) fn analyze_heredoc_node(quoted: bool, content: Option<&str>) -> Verdict {
        if quoted {
            return Verdict::allow(AllowReason::Heredoc);
        }
        if let Some(body) = content
            && ast::has_shell_expansion_pattern(body)
        {
            let kind = if ast::has_executing_substitution(body) {
                Unanalyzable
            } else {
                DynamicExpansion
            };
            return Verdict::uncertain(kind, "heredoc with expansion");
        }
        Verdict::allow(AllowReason::Heredoc)
    }

    /// A resolved command as the reason, trace and `resolved_command` show it,
    /// after recording the values it expanded so nothing shown later for this
    /// command repeats a secret one. see docs/security-invariants.md#history-redaction
    fn shown_resolution(&mut self, words: &[Node], resolved: &str) -> String {
        let values: Vec<(String, String)> = {
            let scoped = resolve::ScopedLookup::new(&self.locals, self.var_lookup.as_ref());
            words
                .iter()
                .flat_map(ast::expanded_names)
                .filter_map(|name| scoped.lookup(&name).map(|value| (name, value)))
                .collect()
        };
        for (name, value) in &values {
            self.revealed.record(name, value);
        }
        self.revealed.show(resolved.to_owned())
    }

    pub(super) fn analyze_inner_command(
        &mut self,
        inner: &str,
        cwd: &Path,
        depth: usize,
    ) -> Verdict {
        let Ok(nodes) = self.parser.parse(inner) else {
            return Verdict::uncertain(Unanalyzable, "unparseable inner command");
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
    pub(super) fn try_resolve(
        &mut self,
        words: &[Node],
        cwd: &Path,
        depth: usize,
    ) -> Option<Verdict> {
        if !ast::has_expansions_in_slices(words, &[]) {
            return None;
        }
        // Bail out on runaway resolution (also catches cycles like `A=$B; B=$A`).
        if self.resolution_depth >= MAX_RESOLUTION_DEPTH {
            self.trace(Stage::Expansion, false, || {
                format!("resolution depth exceeded ({MAX_RESOLUTION_DEPTH})")
            });
            return Some(Verdict::uncertain(
                Unanalyzable,
                "shell expansion (resolution depth exceeded)",
            ));
        }
        let resolved = {
            let scoped = resolve::ScopedLookup::new(&self.locals, self.var_lookup.as_ref());
            resolve::resolve_command_args(words, &scoped)
        };
        // Set-but-unknown value in argument position: never fabricated, and the
        // relaxed allow is gated on no other word being unresolvable.
        // see docs/security-invariants.md#dynamic-arg
        if resolved.arg_position_dynamic
            && !resolved.command_position_dynamic
            && resolved.failure_reason.is_none()
        {
            let v = self.dynamic_arg_verdict(words);
            return Some(self.unless_asks_anyway(v, words, cwd, depth));
        }
        let Some(args) = resolved.args else {
            let reason = resolved.failure_reason.map_or_else(
                || "shell expansion".to_string(),
                |r| format!("shell expansion ({r})"),
            );
            self.trace(Stage::Expansion, false, || reason.clone());
            let v = expansion_ask(words, reason);
            return Some(self.unless_asks_anyway(v, words, cwd, depth));
        };
        let resolved_command = resolve::shell_join(&args);
        // Refuse to materialize pathologically large resolved commands.
        if resolved_command.len() > MAX_RESOLVED_LEN {
            self.trace(Stage::Expansion, false, || {
                format!("resolved command exceeds {MAX_RESOLVED_LEN}-byte limit")
            });
            return Some(Verdict::uncertain(
                Unanalyzable,
                format!("shell expansion (resolved command exceeds {MAX_RESOLVED_LEN}-byte limit)"),
            ));
        }
        // Judged as resolved, shown redacted.
        let shown = self.shown_resolution(words, &resolved_command);
        self.trace(Stage::Expansion, true, || shown.clone());
        if resolved.command_position_dynamic {
            self.trace(Stage::Expansion, false, || {
                "command name comes from an expansion".to_owned()
            });
            return Some(
                Verdict::ask(format!("dynamic command (resolved: {shown})")).with_resolution(shown),
            );
        }
        // Track nesting around the recursive analyze_inner_command call.
        self.resolution_depth += 1;
        let inner = self.analyze_inner_command(&resolved_command, cwd, depth + 1);
        self.resolution_depth -= 1;
        Some(annotate_with_resolution(inner, &shown))
    }

    /// Raise a [`DynamicExpansion`] ask to the class the command has whatever
    /// the unknown value is. A value handed to a program that runs code is code,
    /// not data. Otherwise the command is classified again with each expansion
    /// resolved to an inert placeholder, keeping the literal text around it
    /// (`--output=$X`), and a class that probe asks with applies. Only the class
    /// can change, never the decision or reason; the probe is not traced and
    /// spends no node budget. See docs/jev.md#classification-rules.
    fn unless_asks_anyway(
        &mut self,
        v: Verdict,
        words: &[Node],
        cwd: &Path,
        depth: usize,
    ) -> Verdict {
        if v.ask_class() != Some(AskClass::Uncertain(DynamicExpansion)) {
            return v;
        }
        let Some(name) = ast::command_name_from_words(words) else {
            return v;
        };
        if ask_rules::runs_code(self.config.resolve_alias(name))
            || words.iter().skip(1).any(is_glued_expansion)
        {
            return v.into_approval();
        }
        let argv = placeholder_argv(words);
        let saved_trace = std::mem::replace(&mut self.trace, Trace::new(false));
        let saved_budget = self.node_budget;
        let probe = self.analyze_inner_command(&resolve::shell_join(&argv), cwd, depth + 1);
        self.trace = saved_trace;
        self.node_budget = saved_budget;
        match probe.decision {
            Decision::Allow => v,
            Decision::Ask => v.with_class_at_least(probe.ask_class().unwrap_or(AskClass::Approval)),
            Decision::Deny => v.into_approval(),
        }
    }

    /// Whether a config alias rewrites this command's name, so the program
    /// judged is not the one the text names.
    pub(super) fn is_aliased(&self, words: &[Node]) -> bool {
        ast::command_name_from_words(words).is_some_and(|n| self.config.resolve_alias(n) != n)
    }

    /// Verdict for a command with a dynamic-known argument (`$loopvar`, `$?`).
    ///
    /// SECURITY INVARIANT: this is the *only* place a dynamic argument relaxes
    /// the verdict, and it does so strictly for the pure-reader subset of
    /// `SIMPLE_SAFE` (see [`allowlists::is_dynamic_arg_safe`]), whose safety does
    /// not depend on argument values (`cat`/`echo`/`wc`/`ls`). Commands that can
    /// act on an argument value — pagers that spawn subshells (`less`/`man`),
    /// preview-executing finders (`fzf`), and state-changing commands
    /// (`mount`/`stty`) — are excluded, as is any handler command (`rm`,
    /// `git`, ...), because a set-but-unknown value could otherwise hide an
    /// injected dangerous flag or path.
    pub(super) fn dynamic_arg_verdict(&mut self, words: &[Node]) -> Verdict {
        let Some(raw_name) = ast::command_name_from_words(words) else {
            self.trace(Stage::Expansion, false, || {
                "ask: dynamic argument on a command with no name".to_owned()
            });
            return Verdict::uncertain(DynamicExpansion, "shell expansion ($VAR dynamic)");
        };
        let name = self.config.resolve_alias(raw_name).to_owned();
        if allowlists::is_dynamic_arg_safe(&name) {
            self.trace(Stage::Expansion, true, || {
                format!("allow: {name} is safe with a set-but-unknown argument")
            });
            Verdict::allow(AllowReason::DynamicArgSafe(name))
        } else {
            self.trace(Stage::Expansion, false, || {
                format!("ask: {name} is not safe with a set-but-unknown argument")
            });
            Verdict::uncertain(DynamicExpansion, "shell expansion ($VAR dynamic)")
        }
    }

    pub(super) fn apply_classification(
        &mut self,
        class: Classification,
        cwd: &Path,
        depth: usize,
    ) -> Verdict {
        match class {
            Classification::Allow(reason) => Verdict::allow(reason),
            Classification::Ask(desc) => Verdict::ask(desc),
            Classification::Uncertain(kind, desc) => Verdict::uncertain(kind, desc),
            Classification::Deny(desc) => Verdict::deny(desc),
            Classification::Recurse(inner) => {
                self.trace(Stage::Command, true, || format!("recurse: {inner}"));
                self.analyze_inner_command(&inner, cwd, depth)
                    .with_class_at_least(ask_rules::INDIRECT)
            }
            Classification::RecurseAtLeast(inner, outer) => {
                let outer = self.apply_classification(*outer, cwd, depth);
                self.trace(Stage::Command, true, || format!("recurse: {inner}"));
                let inner = self
                    .analyze_inner_command(&inner, cwd, depth)
                    .with_class_at_least(ask_rules::INDIRECT);
                // Outer last so an equal-decision tie reports its reason, which
                // names the flag that spawned the program.
                Verdict::combine(&[inner, outer])
            }
            Classification::RecurseRemote(inner) => {
                self.trace(Stage::Command, true, || {
                    format!("recurse (remote): {inner}")
                });
                let prev_remote = self.remote;
                self.remote = true;
                let v = self.analyze_inner_command(&inner, cwd, depth);
                self.remote = prev_remote;
                // Facts about a remote target cannot be computed locally.
                v.into_approval()
            }
            Classification::WithRedirects(reason, targets) => {
                let mut verdicts = vec![Verdict::allow(reason)];
                for target in &targets {
                    verdicts.push(self.analyze_redirect(ast::RedirectOp::Write, target, cwd));
                }
                Verdict::combine(&verdicts)
            }
        }
    }

    pub(super) fn default_verdict(
        &mut self,
        cmd_name: &str,
        args: &[String],
        cwd: &Path,
    ) -> Verdict {
        let action = self.config.default_action;
        self.trace(Stage::Default, true, || {
            action.map_or_else(
                || format!("{cmd_name} is an unknown command"),
                |a| format!("default action: {}", a.as_str()),
            )
        });
        let class = ask_rules::unknown_command(cmd_name, args, cwd);
        self.config.default_action.map_or_else(
            || Verdict::ask_as(class, format!("{cmd_name} (unknown command)")),
            |action| match action {
                Decision::Allow => Verdict::allow(AllowReason::DefaultAction {
                    cmd: cmd_name.to_owned(),
                    weakening: self.config.weakening_suffix().to_owned(),
                }),
                Decision::Ask => Verdict::ask_as(class, format!("{cmd_name} (default action)")),
                Decision::Deny => Verdict::deny(format!("{cmd_name} (default action)")),
            },
        )
    }
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

/// Class of an ask raised because `words` could not be resolved. Only an
/// unknown argument *value* is a [`DynamicExpansion`]: a command name hidden in
/// an expansion is approval-grade (`$cmd args` is an evasion shape), and a
/// substitution rippy did not vet is [`Unanalyzable`].
/// See docs/jev.md#two-kinds-of-ask.
pub(super) fn expansion_ask(words: &[Node], reason: impl Into<String>) -> Verdict {
    if words.first().is_some_and(ast::has_expansions) {
        Verdict::ask(reason)
    } else if words.iter().any(ast::word_executes_command) {
        Verdict::uncertain(Unanalyzable, reason)
    } else {
        Verdict::uncertain(DynamicExpansion, reason)
    }
}

/// Whether stdin comes from somewhere other than the terminal: a heredoc, a
/// here-string, or a `<` redirect. An interpreter reading it runs that input.
pub(super) fn stdin_redirected(redirects: &[Node]) -> bool {
    redirects.iter().any(|r| {
        matches!(r.kind, NodeKind::HereDoc { .. })
            || matches!(ast::redirect_info(r), Some((ast::RedirectOp::Read, _)))
    })
}

/// An expansion with literal text before it (`--output=$X`, `-o$X`, `of=$X`)
/// is part of a flag or operand, not a plain value: what the program does with
/// it depends on the value.
fn is_glued_expansion(word: &Node) -> bool {
    ast::has_expansions(word)
        && matches!(&word.kind, NodeKind::Word { value, .. }
            if !value.trim_start_matches(['"', '\'']).starts_with('$'))
}

/// The placeholder every unknown value resolves to in the class probe.
const PLACEHOLDER: &str = "rippy-placeholder";

struct PlaceholderLookup;

impl resolve::VarLookup for PlaceholderLookup {
    fn lookup(&self, _name: &str) -> Option<String> {
        Some(PLACEHOLDER.to_owned())
    }
}

/// `words` with every expansion replaced by [`PLACEHOLDER`]. The resolver keeps
/// literal text around an expansion; a word it cannot resolve at all (an
/// unsupported operator) is replaced whole.
fn placeholder_argv(words: &[Node]) -> Vec<String> {
    if let Some(args) = resolve::resolve_command_args(words, &PlaceholderLookup).args {
        return args;
    }
    let texts = words.iter().zip(
        ast::command_name_from_words(words)
            .map(str::to_owned)
            .into_iter()
            .chain(ast::command_args_from_words(words)),
    );
    texts
        .map(|(word, text)| {
            if ast::has_expansions(word) {
                PLACEHOLDER.to_owned()
            } else {
                text
            }
        })
        .collect()
}
