//! The parts of a command Jev review needs, taken from rable's AST.
//!
//! Every simple command (including those nested in lists, loops, groups and
//! substitutions) and the byte spans of its words. From these come the
//! redacted, comment-free text that is sent, and the facts rippy computes.

use std::ops::Range;

use rable::{Node, NodeKind};

use crate::ast;

const REDACTED: &str = "<redacted>";

/// One simple command.
pub struct Leaf<'a> {
    pub name: Option<String>,
    pub args: Vec<String>,
    pub words: &'a [Node],
}

/// Everything collected from one parse.
pub struct Shape<'a> {
    source: &'a str,
    pub leaves: Vec<Leaf<'a>>,
    word_spans: Vec<Range<usize>>,
    assignment_spans: Vec<Range<usize>>,
    has_heredoc: bool,
}

impl<'a> Shape<'a> {
    #[must_use]
    pub fn of(source: &'a str, nodes: &'a [Node]) -> Self {
        let mut shape = Self {
            source,
            leaves: Vec::new(),
            word_spans: Vec::new(),
            assignment_spans: Vec::new(),
            has_heredoc: false,
        };
        for node in nodes {
            shape.visit(node);
        }
        shape
    }

    fn visit(&mut self, node: &'a Node) {
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
                NodeKind::Redirect { target, .. } => self.visit_word(target),
                NodeKind::HereDoc { .. } => self.has_heredoc = true,
                _ => {}
            }
        }
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
        let mut previous_was_secret_flag = false;
        for span in &self.word_spans {
            if self.assignment_spans.contains(span) {
                continue;
            }
            let text = &self.source[span.clone()];
            if previous_was_secret_flag && !text.starts_with('-') {
                edits.push((span.clone(), REDACTED.to_owned()));
            } else if let Some(eq) = secret_flag_value_start(text) {
                edits.push((span.start + eq..span.end, REDACTED.to_owned()));
            } else if looks_like_secret(text.trim_matches(['"', '\''])) {
                edits.push((span.clone(), REDACTED.to_owned()));
            } else if let Some(userinfo) = url_userinfo(text) {
                edits.push((
                    span.start + userinfo.start..span.start + userinfo.end,
                    REDACTED.to_owned(),
                ));
            }
            previous_was_secret_flag = is_secret_flag(text);
        }
        edits
    }
}

fn is_secret_flag(word: &str) -> bool {
    if !word.starts_with('-') || word.contains('=') {
        return false;
    }
    let lower = word.to_ascii_lowercase();
    [
        "token", "secret", "password", "passwd", "api-key", "apikey", "auth",
    ]
    .iter()
    .any(|k| lower.contains(k))
}

/// `--token=VALUE` → offset of `VALUE`.
fn secret_flag_value_start(word: &str) -> Option<usize> {
    let eq = word.find('=')?;
    (is_secret_flag(&word[..eq]) && eq + 1 < word.len()).then_some(eq + 1)
}

/// Token shapes from common providers, and long opaque base64/hex runs.
fn looks_like_secret(word: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "ghp_",
        "gho_",
        "ghu_",
        "ghs_",
        "ghr_",
        "github_pat_",
        "glpat-",
        "sk-",
        "sk_live_",
        "rk_live_",
        "xoxb-",
        "xoxp-",
        "xoxa-",
        "AKIA",
        "ASIA",
        "npm_",
        "hf_",
    ];
    if word.len() >= 16 && PREFIXES.iter().any(|p| word.starts_with(p)) {
        return true;
    }
    let opaque = word
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_' | '-'));
    let mixed =
        word.chars().any(|c| c.is_ascii_digit()) && word.chars().any(|c| c.is_ascii_alphabetic());
    word.len() >= 32
        && opaque
        && mixed
        && !word.starts_with(['/', '.', '-'])
        && !word.contains("//")
}

/// `https://user:pass@host` → the range of `user:pass`.
fn url_userinfo(word: &str) -> Option<Range<usize>> {
    let scheme_end = word.find("://")? + 3;
    let rest = &word[scheme_end..];
    let at = rest.find('@')?;
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    (at < authority_end && at > 0).then(|| scheme_end..scheme_end + at)
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
    let trimmed = out.trim_end();
    trimmed.to_owned()
}

#[cfg(test)]
#[path = "shape_tests.rs"]
mod tests;
