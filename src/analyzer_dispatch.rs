use std::path::Path;

use rable::{Node, NodeKind};

use super::{
    Analyzer, MAX_RESOLUTION_DEPTH, MAX_RESOLVED_LEN, annotate_with_resolution,
    canonicalize_existing_ancestor,
};
use crate::allowlists;
use crate::ast;
use crate::handlers::{self, Classification, HandlerContext};
use crate::resolve;
use crate::trace::Stage;
use crate::verdict::{AllowReason, Decision, Verdict};

impl Analyzer {
    pub(super) fn analyze_redirects(
        &self,
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
        self.default_verdict(cmd_name)
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
        &self,
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

    pub(super) fn analyze_redirect(
        &self,
        op: ast::RedirectOp,
        target: &str,
        cwd: &Path,
    ) -> Verdict {
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
            return Verdict::ask("heredoc with expansion");
        }
        Verdict::allow(AllowReason::Heredoc)
    }

    pub(super) fn analyze_inner_command(
        &mut self,
        inner: &str,
        cwd: &Path,
        depth: usize,
    ) -> Verdict {
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
            return Some(Verdict::ask("shell expansion (resolution depth exceeded)"));
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
            return Some(self.dynamic_arg_verdict(words));
        }
        let Some(args) = resolved.args else {
            let reason = resolved.failure_reason.map_or_else(
                || "shell expansion".to_string(),
                |r| format!("shell expansion ({r})"),
            );
            self.trace(Stage::Expansion, false, || reason.clone());
            return Some(Verdict::ask(reason));
        };
        let resolved_command = resolve::shell_join(&args);
        // Refuse to materialize pathologically large resolved commands.
        if resolved_command.len() > MAX_RESOLVED_LEN {
            self.trace(Stage::Expansion, false, || {
                format!("resolved command exceeds {MAX_RESOLVED_LEN}-byte limit")
            });
            return Some(Verdict::ask(format!(
                "shell expansion (resolved command exceeds {MAX_RESOLVED_LEN}-byte limit)"
            )));
        }
        self.trace(Stage::Expansion, true, || resolved_command.clone());
        if resolved.command_position_dynamic {
            self.trace(Stage::Expansion, false, || {
                "command name comes from an expansion".to_owned()
            });
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
    pub(super) fn dynamic_arg_verdict(&self, words: &[Node]) -> Verdict {
        let Some(raw_name) = ast::command_name_from_words(words) else {
            return Verdict::ask("shell expansion ($VAR dynamic)");
        };
        let name = self.config.resolve_alias(raw_name);
        if allowlists::is_dynamic_arg_safe(name) {
            Verdict::allow(AllowReason::DynamicArgSafe(name.to_owned()))
        } else {
            Verdict::ask("shell expansion ($VAR dynamic)")
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
            Classification::Deny(desc) => Verdict::deny(desc),
            Classification::Recurse(inner) => {
                self.trace(Stage::Command, true, || format!("recurse: {inner}"));
                self.analyze_inner_command(&inner, cwd, depth)
            }
            Classification::RecurseRemote(inner) => {
                self.trace(Stage::Command, true, || {
                    format!("recurse (remote): {inner}")
                });
                let prev_remote = self.remote;
                self.remote = true;
                let v = self.analyze_inner_command(&inner, cwd, depth);
                self.remote = prev_remote;
                v
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

    pub(super) fn default_verdict(&mut self, cmd_name: &str) -> Verdict {
        let action = self.config.default_action;
        self.trace(Stage::Default, true, || {
            action.map_or_else(
                || format!("{cmd_name} is an unknown command"),
                |a| format!("default action: {}", a.as_str()),
            )
        });
        self.config.default_action.map_or_else(
            || Verdict::ask(format!("{cmd_name} (unknown command)")),
            |action| match action {
                Decision::Allow => Verdict::allow(AllowReason::DefaultAction {
                    cmd: cmd_name.to_owned(),
                    weakening: self.config.weakening_suffix().to_owned(),
                }),
                Decision::Ask => Verdict::ask(format!("{cmd_name} (default action)")),
                Decision::Deny => Verdict::deny(format!("{cmd_name} (default action)")),
            },
        )
    }
}
