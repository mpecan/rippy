//! The parts of a command Jev review needs, taken from rable's AST.
//!
//! Every simple command (including those nested in lists, loops, groups and
//! substitutions) and the byte spans of its words. From these come the
//! redacted, comment-free text that is sent, and the facts rippy computes.

use std::ops::Range;

use rable::{Node, NodeKind};

use super::redact;
use crate::ast;

const REDACTED: &str = "<redacted>";

/// One simple command.
pub struct Leaf<'a> {
    pub name: Option<String>,
    pub args: Vec<String>,
    pub words: &'a [Node],
    /// Whether it carries `NAME=value` prefixes, whose values are redacted.
    pub has_assignments: bool,
}

/// Everything collected from one parse.
pub struct Shape<'a> {
    source: &'a str,
    pub leaves: Vec<Leaf<'a>>,
    word_spans: Vec<Range<usize>>,
    assignment_spans: Vec<Range<usize>>,
    /// Texts of redirect targets (`< ~/.ssh/id_rsa`), labelled as paths.
    pub redirect_targets: Vec<String>,
    has_heredoc: bool,
    has_compound: bool,
    has_stdin_redirect: bool,
}

impl<'a> Shape<'a> {
    #[must_use]
    pub fn of(source: &'a str, nodes: &'a [Node]) -> Self {
        let mut shape = Self {
            source,
            leaves: Vec::new(),
            word_spans: Vec::new(),
            assignment_spans: Vec::new(),
            redirect_targets: Vec::new(),
            has_heredoc: false,
            has_compound: false,
            has_stdin_redirect: false,
        };
        for node in nodes {
            shape.visit(node);
        }
        shape
    }

    fn visit(&mut self, node: &'a Node) {
        self.has_compound |= is_compound(&node.kind);
        match &node.kind {
            NodeKind::Command {
                assignments,
                words,
                redirects,
            } => self.visit_command(assignments, words, redirects),
            NodeKind::Pipeline { commands, .. } => commands.iter().for_each(|c| self.visit(c)),
            NodeKind::List { items } => items.iter().for_each(|i| self.visit(&i.command)),
            NodeKind::If {
                condition,
                then_body,
                else_body,
                ..
            } => {
                self.visit(condition);
                self.visit(then_body);
                if let Some(e) = else_body {
                    self.visit(e);
                }
            }
            NodeKind::While {
                condition, body, ..
            }
            | NodeKind::Until {
                condition, body, ..
            } => {
                self.visit(condition);
                self.visit(body);
            }
            NodeKind::For { words, body, .. } | NodeKind::Select { words, body, .. } => {
                for w in words.iter().flatten() {
                    self.visit_word(w);
                }
                self.visit(body);
            }
            NodeKind::Case { word, patterns, .. } => {
                self.visit_word(word);
                for body in patterns.iter().filter_map(|p| p.body.as_ref()) {
                    self.visit(body);
                }
            }
            NodeKind::ForArith { body, .. }
            | NodeKind::Function { body, .. }
            | NodeKind::Subshell { body, .. }
            | NodeKind::BraceGroup { body, .. }
            | NodeKind::ConditionalExpr { body, .. } => self.visit(body),
            NodeKind::Coproc { command, .. }
            | NodeKind::CommandSubstitution { command, .. }
            | NodeKind::ProcessSubstitution { command, .. } => self.visit(command),
            NodeKind::Negation { pipeline } | NodeKind::Time { pipeline, .. } => {
                self.visit(pipeline);
            }
            NodeKind::HereDoc { .. } => self.has_heredoc = true,
            _ => {}
        }
    }

    fn visit_command(&mut self, assignments: &'a [Node], words: &'a [Node], redirects: &'a [Node]) {
        self.leaves.push(Leaf {
            name: ast::command_name_from_words(words).map(str::to_owned),
            args: ast::command_args_from_words(words),
            words,
            has_assignments: !assignments.is_empty(),
        });
        for a in assignments {
            self.assignment_spans.extend(self.span_of(a));
            self.visit_word(a);
        }
        for w in words {
            self.visit_word(w);
        }
        for r in redirects {
            match &r.kind {
                NodeKind::Redirect { target, op, fd } => {
                    self.has_stdin_redirect |= op.starts_with('<') || *fd == 0;
                    if let NodeKind::Word { value, .. } = &target.kind {
                        self.redirect_targets.push(value.clone());
                    }
                    self.visit_word(target);
                }
                NodeKind::HereDoc { .. } => self.has_heredoc = true,
                _ => {}
            }
        }
    }

    /// Whether any part is a compound construct (subshell, group, loop,
    /// conditional, function, substitution): only plain commands joined by
    /// pipes and lists are sent.
    #[must_use]
    pub const fn has_compound(&self) -> bool {
        self.has_compound
    }

    /// Whether anything reads stdin from a file, here-string or descriptor.
    #[must_use]
    pub const fn has_stdin_redirect(&self) -> bool {
        self.has_stdin_redirect
    }

    /// Whether the source is ASCII. rable's word spans drift after multibyte
    /// text, so spans are only trusted for ASCII input.
    #[must_use]
    pub const fn is_ascii(&self) -> bool {
        self.source.is_ascii()
    }

    /// Whether the command spans more than one line.
    #[must_use]
    pub fn is_multiline(&self) -> bool {
        self.source.trim_end().contains('\n')
    }

    #[must_use]
    pub const fn has_heredoc(&self) -> bool {
        self.has_heredoc
    }

    /// Record a word's span and descend into any substitution inside it.
    fn visit_word(&mut self, word: &'a Node) {
        self.word_spans.extend(self.span_of(word));
        if let NodeKind::Word { parts, .. } = &word.kind {
            for part in parts {
                self.visit(part);
            }
        }
    }

    fn span_of(&self, node: &Node) -> Option<Range<usize>> {
        let (start, end) = (node.span.start, node.span.end);
        let valid = start < end
            && end <= self.source.len()
            && self.source.is_char_boundary(start)
            && self.source.is_char_boundary(end);
        valid.then_some(start..end)
    }

    /// The command as sent to Jev: comments removed (they are the easiest
    /// steering channel) and secret-looking values replaced. Falls back to
    /// keeping comments when a heredoc body could contain a literal `#`.
    #[must_use]
    pub fn sanitized(&self) -> String {
        let mut edits = self.redactions();
        if !self.has_heredoc {
            edits.extend(
                self.comment_ranges()
                    .into_iter()
                    .map(|r| (r, String::new())),
            );
        }
        apply_edits(self.source, edits)
    }

    fn inside_word(&self, i: usize) -> bool {
        self.word_spans.iter().any(|r| r.contains(&i))
    }

    fn comment_ranges(&self) -> Vec<Range<usize>> {
        let bytes = self.source.as_bytes();
        let mut ranges = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            let starts_word = i == 0
                || matches!(
                    bytes[i - 1],
                    b' ' | b'\t' | b'\n' | b';' | b'&' | b'|' | b'(' | b')'
                );
            if bytes[i] == b'#' && starts_word && !self.inside_word(i) {
                let end = self.source[i..].find('\n').map_or(bytes.len(), |n| i + n);
                ranges.push(i..end);
                i = end;
            } else {
                i += 1;
            }
        }
        ranges
    }

    fn redactions(&self) -> Vec<(Range<usize>, String)> {
        let mut edits = Vec::new();
        for span in &self.assignment_spans {
            let text = &self.source[span.clone()];
            if let Some(eq) = text.find('=')
                && eq + 1 < text.len()
            {
                edits.push((span.start + eq + 1..span.end, REDACTED.to_owned()));
            }
        }
        let mut after_secret_flag = false;
        for span in &self.word_spans {
            if self.assignment_spans.contains(span) {
                continue;
            }
            let text = &self.source[span.clone()];
            for r in redact::secret_ranges(text, after_secret_flag) {
                edits.push((
                    span.start + r.start..span.start + r.end,
                    REDACTED.to_owned(),
                ));
            }
            after_secret_flag = redact::is_secret_flag(text);
        }
        edits
    }
}

/// Constructs other than plain commands joined by pipes and lists.
const fn is_compound(kind: &NodeKind) -> bool {
    matches!(
        kind,
        NodeKind::If { .. }
            | NodeKind::While { .. }
            | NodeKind::Until { .. }
            | NodeKind::For { .. }
            | NodeKind::ForArith { .. }
            | NodeKind::Select { .. }
            | NodeKind::Case { .. }
            | NodeKind::Function { .. }
            | NodeKind::Subshell { .. }
            | NodeKind::BraceGroup { .. }
            | NodeKind::ConditionalExpr { .. }
            | NodeKind::ArithmeticCommand { .. }
            | NodeKind::Coproc { .. }
            | NodeKind::CommandSubstitution { .. }
            | NodeKind::ProcessSubstitution { .. }
    )
}

fn apply_edits(source: &str, mut edits: Vec<(Range<usize>, String)>) -> String {
    edits.sort_by(|a, b| b.0.start.cmp(&a.0.start));
    let mut out = source.to_owned();
    let mut floor = usize::MAX;
    for (range, replacement) in edits {
        if range.end > floor {
            continue;
        }
        out.replace_range(range.clone(), &replacement);
        floor = range.start;
    }
    out.trim_end().to_owned()
}

#[cfg(test)]
#[path = "shape_tests.rs"]
mod tests;
