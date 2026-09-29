//! Simple commands: the env-prefix gate around the command's own verdict.
//! Split from `analyzer.rs` for the 700-line cap.

use std::path::Path;

use rable::{Node, NodeKind};

use super::{Analyzer, dispatch};
use crate::ask_rules;
use crate::ast;
use crate::trace::Stage;
use crate::verdict::UncertainKind::{DynamicExpansion, Unanalyzable};
use crate::verdict::{Decision, Verdict};

impl Analyzer {
    /// Analyze a simple `Command` node.
    ///
    /// Applies the assignment-expansion guard (`x=$(cmd)` → Ask), then binds any
    /// literal `VAR=val` prefix for the duration of this one command so
    /// `VAR=val cmd $VAR` resolves within it, and unwinds the binding afterward.
    ///
    /// An env prefix rippy cannot vouch for Asks, but only after the command
    /// itself is analyzed: the command may warrant Deny, and when it already
    /// Asks its own reason is the more useful one. Tracing the prefix last also
    /// keeps the deciding step last, which is what `rippy inspect` prints.
    /// see docs/security-invariants.md#dangerous-env-name
    pub(super) fn analyze_command(&mut self, node: &Node, cwd: &Path, depth: usize) -> Verdict {
        // Unreachable; fail closed so a dispatch change cannot approve blindly.
        let NodeKind::Command { assignments, .. } = &node.kind else {
            return Verdict::uncertain(
                Unanalyzable,
                "internal: non-command node in analyze_command",
            );
        };
        if ast::assignment_has_expansion(assignments) {
            return self.expansion_prefix(node, assignments, cwd, depth);
        }
        let Some(name) = ast::dangerous_assignment_name(assignments) else {
            return self.analyze_command_body(node, cwd, depth);
        };
        let prefix = Verdict::ask(format!("unrecognized env-var assignment ({name})"));
        let verdict = self.analyze_command_body(node, cwd, depth);
        if verdict.decision >= Decision::Ask {
            // The body's reason stands, but an unvetted prefix makes the ask an
            // approval: a reviewer judging the command alone never sees it.
            self.trace(Stage::EnvPrefix, true, || {
                format!("{name} is not a known-inert variable: the ask needs approval")
            });
            return Verdict::most_restrictive(verdict, prefix);
        }
        self.trace(Stage::EnvPrefix, true, || {
            format!("ask: {name} is not a known-inert variable")
        });
        prefix
    }

    /// An assignment whose value rippy cannot see asks, with the same decision
    /// and reason whatever follows. Its *class* also answers for the command:
    /// `CI=$X rm -rf build` still needs approval, and a body that is denied
    /// (a protected write) is never reviewable.
    fn expansion_prefix(
        &mut self,
        node: &Node,
        assignments: &[Node],
        cwd: &Path,
        depth: usize,
    ) -> Verdict {
        let kind = if assignments.iter().any(ast::word_executes_command) {
            Unanalyzable
        } else {
            DynamicExpansion
        };
        let v = Verdict::uncertain(kind, "assignment with expansion");
        let body = self.analyze_command_body(node, cwd, depth);
        self.trace(Stage::EnvPrefix, true, || {
            "ask: assignment value contains a shell expansion".to_owned()
        });
        // Bare or as a prefix: an exported name set here reaches every later
        // command's environment, as `LD_PRELOAD=$X; cmd` does.
        match body.decision {
            _ if ast::sets_unvetted_name(assignments) => v.into_approval(),
            Decision::Deny => v.into_approval(),
            Decision::Ask => Verdict::most_restrictive(v, body),
            Decision::Allow => v,
        }
    }

    /// The command's own verdict, ignoring any env prefix.
    fn analyze_command_body(&mut self, node: &Node, cwd: &Path, depth: usize) -> Verdict {
        let NodeKind::Command {
            words,
            redirects,
            assignments,
        } = &node.kind
        else {
            return Verdict::uncertain(
                Unanalyzable,
                "internal: non-command node in analyze_command_body",
            );
        };
        // Per-leaf string-rule match (expansions resolved downstream first).
        // see docs/security-invariants.md#string-rule-chokepoint
        if !ast::has_expansions_in_slices(words, &[])
            && let Some(name) = ast::command_name_from_words(words)
        {
            let args = ast::command_args_from_words(words);
            if let Some(v) = self.leaf_string_rule(name, &args, redirects, cwd) {
                return v;
            }
        }
        let checkpoint = self.locals.len();
        self.push_literal_bindings(assignments);
        let piped = self.piped || dispatch::stdin_redirected(redirects);
        let prev_piped = std::mem::replace(&mut self.piped, piped);
        let mut v = self.analyze_command_node(words, redirects, cwd, depth);
        self.piped = prev_piped;
        if self.is_aliased(words) {
            v = v.with_class_at_least(ask_rules::INDIRECT);
        }
        self.locals.truncate(checkpoint);
        v
    }
}
