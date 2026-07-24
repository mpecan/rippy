use rable::{Node, NodeKind};

use crate::allowlists;

/// The operator used in a file redirect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectOp {
    /// `>` — write (truncate)
    Write,
    /// `>>` — append
    Append,
    /// `<` — read
    Read,
    /// `>&` or `&>` — file descriptor duplication
    FdDup,
    /// Anything else
    Other,
}

/// Extract the command name from a word slice.
#[must_use]
pub fn command_name_from_words(words: &[Node]) -> Option<&str> {
    words.first().and_then(word_value)
}

/// Extract the command name from a `Command` node.
#[must_use]
pub fn command_name(node: &Node) -> Option<&str> {
    let NodeKind::Command { words, .. } = &node.kind else {
        return None;
    };
    command_name_from_words(words)
}

/// Extract command arguments from a word slice (all words after the name).
#[must_use]
pub fn command_args_from_words(words: &[Node]) -> Vec<String> {
    words.iter().skip(1).map(node_text).collect()
}

/// Extract command arguments from a `Command` node.
#[must_use]
pub fn command_args(node: &Node) -> Vec<String> {
    let NodeKind::Command { words, .. } = &node.kind else {
        return Vec::new();
    };
    command_args_from_words(words)
}

/// Extract the redirect operator and target from a `Redirect` node.
#[must_use]
pub fn redirect_info(node: &Node) -> Option<(RedirectOp, String)> {
    let NodeKind::Redirect { op, target, .. } = &node.kind else {
        return None;
    };
    let redirect_op = match op.as_str() {
        ">" => RedirectOp::Write,
        ">>" => RedirectOp::Append,
        "<" | "<<<" => RedirectOp::Read,
        "&>" | ">&" => RedirectOp::FdDup,
        _ => RedirectOp::Other,
    };
    Some((redirect_op, node_text(target)))
}

/// Check whether a node contains command or process substitutions.
///
/// Rable keeps `$(...)` and backtick substitutions as literal text in word
/// values, so we check word values for expansion patterns.
#[must_use]
pub fn has_expansions(node: &Node) -> bool {
    has_expansions_kind(&node.kind)
}

/// Check for expansions in word and redirect slices.
#[must_use]
pub fn has_expansions_in_slices(words: &[Node], redirects: &[Node]) -> bool {
    words.iter().any(has_expansions) || redirects.iter().any(has_expansions)
}

/// Returns `true` if the node kind is itself a shell expansion.
///
/// This is the single source of truth for which `NodeKind` variants
/// represent expansions. Used by both `has_expansions_kind` (AST walking)
/// and `analyze_node` (verdict generation).
#[must_use]
pub const fn is_expansion_node(kind: &NodeKind) -> bool {
    matches!(
        kind,
        NodeKind::CommandSubstitution { .. }
            | NodeKind::ProcessSubstitution { .. }
            | NodeKind::ParamExpansion { .. }
            | NodeKind::ParamIndirect { .. }
            | NodeKind::ParamLength { .. }
            | NodeKind::AnsiCQuote { .. }
            | NodeKind::LocaleString { .. }
            | NodeKind::ArithmeticExpansion { .. }
            | NodeKind::BraceExpansion { .. }
    )
}

fn has_expansions_kind(kind: &NodeKind) -> bool {
    if is_expansion_node(kind) {
        return true;
    }
    match kind {
        NodeKind::Word { value, parts, .. } => {
            // Trust parsed parts; textual scan is only a fallback for synthetic
            // words. see docs/security-invariants.md#word-parts-trust
            if parts.is_empty() {
                has_shell_expansion_pattern(value)
            } else {
                parts.iter().any(has_expansions)
            }
        }
        NodeKind::Command {
            words, redirects, ..
        } => has_expansions_in_slices(words, redirects),
        NodeKind::Pipeline { commands, .. } => commands.iter().any(has_expansions),
        NodeKind::List { items } => items.iter().any(|item| has_expansions(&item.command)),
        NodeKind::Redirect { target, .. } => has_expansions(target),
        NodeKind::If {
            condition,
            then_body,
            else_body,
            ..
        } => {
            has_expansions(condition)
                || has_expansions(then_body)
                || else_body.as_deref().is_some_and(has_expansions)
        }
        NodeKind::Subshell { body, .. } | NodeKind::BraceGroup { body, .. } => has_expansions(body),
        NodeKind::HereDoc {
            content, quoted, ..
        } => !quoted && has_shell_expansion_pattern(content),
        _ => false,
    }
}

/// Check if a string contains shell expansion patterns (`$(`, `` ` ``, `${`, or `$` + identifier).
///
/// Used for heredoc content and other string-level expansion detection where
/// structured AST nodes are not available.
#[must_use]
pub fn has_shell_expansion_pattern(s: &str) -> bool {
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'`' {
            return true;
        }
        if b == b'$'
            && let Some(&next) = bytes.get(i + 1)
            && (next == b'('
                || next == b'{'
                || next == b'\''
                || next == b'"'
                || next.is_ascii_alphabetic()
                || next == b'_')
        {
            return true;
        }
    }
    false
}

/// Drop a leading `NAME=VALUE` env prefix, returning the rest of the command
/// verbatim (words, pipes, `&&`/`||`/`;` chains, and redirects all preserved).
///
/// This lets the config/permission string matchers see the real command name
/// (`cargo`) rather than the assignment token (`INSTA_UPDATE=always`), while the
/// result stays byte-for-byte identical to the same command written without the
/// prefix — so an env-prefixed command is treated exactly like its bare form and
/// no new redirect/pipeline path is introduced.
///
/// The prefix is located on the *leftmost* simple command, so pipelines and
/// lists are handled too: `RUST_LOG=debug cargo test | grep foo` becomes
/// `cargo test | grep foo`, and `A=1 cargo test && cargo build` becomes
/// `cargo test && cargo build`. The tail is kept by slicing the original string
/// from the first word's own source span, never a hand-rolled tokenizer.
///
/// Returns `None` (caller keeps the original string) when:
/// - the input is not a single top-level statement, or its leftmost node is not
///   a simple command carrying at least one assignment and one word;
/// - any assignment value contains a shell expansion — a deliberate coupling, so
///   an ALLOW rule cannot mask `FOO=$(rm -rf /) cargo test`; those are forced to
///   Ask by the analyzer's assignment-expansion guard instead;
/// - any assignment sets a code-influencing variable (see
///   [`is_dangerous_env_name`]), so a literal `LD_PRELOAD=./evil.so cargo test`
///   is not masked by a bare-command allow rule and instead reaches the analyzer.
#[must_use]
pub fn strip_env_prefix(command: &str, nodes: &[Node]) -> Option<String> {
    let [node] = nodes else {
        return None;
    };
    let (assignments, words) = leftmost_simple_command(node)?;
    if assignments.is_empty() || words.is_empty() {
        return None;
    }
    if assignments.iter().any(has_expansions) {
        return None;
    }
    if assignments
        .iter()
        .filter_map(|a| assignment_name(a, command))
        .any(is_dangerous_env_name)
    {
        return None;
    }
    let char_start = words.first()?.span.start;
    let byte_start = command.char_indices().nth(char_start).map(|(i, _)| i)?;
    command.get(byte_start..).map(str::to_owned)
}

/// Find the leftmost simple command, descending through the first branch of a
/// pipeline or list, and return its `(assignments, words)`.
fn leftmost_simple_command(node: &Node) -> Option<(&[Node], &[Node])> {
    match &node.kind {
        NodeKind::Command {
            assignments, words, ..
        } => Some((assignments, words)),
        NodeKind::Pipeline { commands, .. } => commands.first().and_then(leftmost_simple_command),
        NodeKind::List { items } => items
            .first()
            .and_then(|item| leftmost_simple_command(&item.command)),
        _ => None,
    }
}

/// Extract the `(name, value)` of a *literal* `NAME=VALUE` assignment node —
/// i.e. one whose value contains no shell expansion.
///
/// Reads the name and value directly from the assignment `Word`'s `value`
/// (`"NAME=VALUE"`), so no source string needs threading into the deep walk.
/// Returns `None` when the node is not a word, the value contains an expansion
/// (command substitution, parameter expansion, ...), or the name is empty.
///
/// A `NAME+=VALUE` compound assignment is deliberately *not* bound: bash
/// concatenates `VALUE` onto the variable's existing value, so binding it to the
/// right-hand side alone would be wrong. We return `None` (the variable stays
/// unresolved and the referencing command falls back to Ask) rather than
/// fabricate a truncated value.
///
/// The value has any outer quotes stripped, matching how the analyzer treats
/// argument words, so `FOO='a b'` yields `("FOO", "a b")`.
#[must_use]
pub fn literal_assignment(assignment: &Node) -> Option<(String, String)> {
    let NodeKind::Word { value, parts, .. } = &assignment.kind else {
        return None;
    };
    // A non-literal value (`x=$(cmd)`, `x=$y`) must never be bound.
    if parts.iter().any(has_expansions) {
        return None;
    }
    let (name, val) = value.split_once('=')?;
    // `NAME+=VALUE` appends to the prior value we cannot reconstruct; refuse.
    if name.ends_with('+') {
        return None;
    }
    if name.is_empty() {
        return None;
    }
    Some((name.to_string(), strip_quotes(val)))
}

/// Return the variable name of a `NAME+=VALUE` compound (append) assignment
/// node, or `None` if the node is not an append assignment (`NAME=VALUE`) or
/// not a word.
///
/// An append combines the variable's *prior* value (which may not be statically
/// known, or may live in a shadowed binding) with the right-hand side, so no
/// concrete value can be bound soundly. The analyzer uses this to shadow the
/// variable as set-but-unknown — keeping safe-list commands allowed while
/// forcing handlers to Ask, and never resolving a stale prior literal.
#[must_use]
pub fn append_assignment_name(assignment: &Node) -> Option<String> {
    let NodeKind::Word { value, .. } = &assignment.kind else {
        return None;
    };
    let (name, _) = value.split_once('=')?;
    // `strip_suffix('+')` yields `None` unless the name ends with `+`, so this
    // matches `NAME+=...` only, never a plain `NAME=...`.
    let base = name.strip_suffix('+')?;
    if base.is_empty() {
        return None;
    }
    Some(base.to_string())
}

/// Extract the variable name of a `NAME=VALUE` (or `NAME+=VALUE`) assignment node.
fn assignment_name<'a>(assignment: &Node, source: &'a str) -> Option<&'a str> {
    let text = assignment.source_text(source);
    let (name, _) = text.split_once('=')?;
    Some(name.strip_suffix('+').unwrap_or(name))
}

/// Environment variable names whose values can change how a following command
/// loads or resolves code, letting a *literal* assignment turn an otherwise-safe
/// command into arbitrary code execution (e.g. `LD_PRELOAD`, `BASH_ENV`,
/// `GIT_SSH_COMMAND`). When a leading env prefix sets any of these,
/// [`strip_env_prefix`] refuses to strip so the command is not masked by a
/// string-layer allow rule and instead falls through to the analyzer.
#[must_use]
fn is_dangerous_env_name(name: &str) -> bool {
    // Dynamic-linker families: Linux `LD_*` (LD_PRELOAD, LD_LIBRARY_PATH,
    // LD_AUDIT, ...) and macOS `DYLD_*` (DYLD_INSERT_LIBRARIES, ...).
    if name.starts_with("LD_") || name.starts_with("DYLD_") {
        return true;
    }
    matches!(
        name,
        "BASH_ENV"
            | "ENV"
            | "SHELLOPTS"
            | "BASHOPTS"
            | "IFS"
            | "PS4"
            | "GIT_SSH"
            | "GIT_SSH_COMMAND"
            | "GIT_EXTERNAL_DIFF"
            | "GIT_PAGER"
            | "PAGER"
            | "EDITOR"
            | "VISUAL"
            | "PERL5OPT"
            | "PERL5LIB"
            | "PYTHONSTARTUP"
            | "PYTHONPATH"
            | "NODE_OPTIONS"
            | "RUBYOPT"
    )
}

/// Check if a redirect target is inherently safe (e.g., /dev/null).
#[must_use]
pub fn is_safe_redirect_target(target: &str) -> bool {
    matches!(target, "/dev/null" | "/dev/stdout" | "/dev/stderr")
}

/// Whether a `Command` node carries any redirects at all.
///
/// Used to route a single simple command that has redirects (e.g.
/// `echo x > .env`) through the full analyzer, since the redirect target may be
/// protected and cannot be judged safe on the command name alone.
#[must_use]
pub const fn command_has_redirects(node: &Node) -> bool {
    matches!(&node.kind, NodeKind::Command { redirects, .. } if !redirects.is_empty())
}

/// Whether the parsed tree is one plain simple command (no redirects, no word
/// expansions) — the only shape a whole-string allow rule may be trusted on.
///
/// A chain (`a && b`), pipeline (`a | b`), redirect (`a > f`), or command
/// substitution (`` a `b` ``) parses to a `List`/`Pipeline` or a `Command` that
/// carries redirects/expansions, none of which match here. Those fall through to
/// the AST walk so a trailing payload cannot ride along on a leading allow-ruled
/// command. see docs/security-invariants.md#string-rule-chokepoint
#[must_use]
pub fn is_single_plain_command(nodes: &[Node]) -> bool {
    let [node] = nodes else {
        return false;
    };
    matches!(
        &node.kind,
        NodeKind::Command { words, redirects, .. }
            if redirects.is_empty() && !words.iter().any(has_expansions)
    )
}

/// Returns `true` when a [`RedirectOp::FdDup`] target denotes a file
/// descriptor operation rather than a file write.
///
/// `&>`/`>&` are parsed as `FdDup`, but they mean two different things
/// depending on the target: a bare descriptor (`2>&1`, `>&2`) or a close
/// (`>&-`) is a real fd duplication, whereas a path (`&> out.log`) is a file
/// write and must be treated like `>`. Only the descriptor forms are matched
/// here: an optional leading `&`, then either `-` (close) or all-ASCII digits.
#[must_use]
pub fn is_fd_dup_target(target: &str) -> bool {
    let t = target.strip_prefix('&').unwrap_or(target);
    t == "-" || (!t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()))
}

/// Check if a node is a harmless fallback command (for `|| true` patterns).
#[must_use]
pub fn is_harmless_fallback(node: &Node) -> bool {
    let Some(name) = command_name(node) else {
        return false;
    };
    matches!(name, "true" | "false" | ":" | "echo" | "printf")
}

/// Extract text from a node, stripping quotes.
fn node_text(node: &Node) -> String {
    if let NodeKind::Word { value, .. } = &node.kind {
        strip_quotes(value)
    } else {
        String::new()
    }
}

/// Get the string value of a word node.
const fn word_value(node: &Node) -> Option<&str> {
    if let NodeKind::Word { value, .. } = &node.kind {
        Some(value.as_str())
    } else {
        None
    }
}

/// Strip surrounding quotes from a string token.
fn strip_quotes(s: &str) -> String {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        s[1..s.len() - 1].to_owned()
    } else if s.len() >= 3
        && ((s.starts_with("$'") && s.ends_with('\''))
            || (s.starts_with("$\"") && s.ends_with('"')))
    {
        s[2..s.len() - 1].to_owned()
    } else {
        s.to_owned()
    }
}

/// Returns `true` when a node is a safe heredoc data-passing idiom:
/// a single `SIMPLE_SAFE` command whose only redirects are quoted heredocs,
/// with no word-level expansions.
///
/// Example: `cat <<'EOF' ... EOF` — `cat` is safe, heredoc is quoted,
/// no pipes, no lists.
///
/// Reliability note: the structural guarantees here assume rable produces
/// a faithful AST for heredocs inside `$(...)`. That held unreliably before
/// rable 0.1.14 (see rable issue #26) — an unmatched `(` in a heredoc body
/// could corrupt paren tracking and drop the `HereDoc` node. Pin `rable >=
/// 0.1.14` when touching this helper.
///
/// Scope note: the checks here are intentionally not tightened further
/// (e.g., restricting to literally `cat` or `words.len() == 1`). `SIMPLE_SAFE`
/// is a read-only-viewer allowlist (`cat`, `head`, `grep`, `xxd`, …) with no
/// command-execution primitives, so a non-`cat` entry with flags and a
/// quoted heredoc is still safe data-passing. The existing conditions
/// (`SIMPLE_SAFE` + all-redirects-quoted-heredocs + no word-expansions) are
/// already structurally tight; the rable 0.1.14 fix makes them *reliable*.
#[must_use]
pub fn is_safe_heredoc_substitution(command: &Node) -> bool {
    let NodeKind::Command {
        words, redirects, ..
    } = &command.kind
    else {
        return false;
    };
    let Some(name) = command_name_from_words(words) else {
        return false;
    };
    if !allowlists::is_simple_safe(name) {
        return false;
    }
    if redirects.is_empty() {
        return false;
    }
    let all_quoted_heredocs = redirects
        .iter()
        .all(|r| matches!(&r.kind, NodeKind::HereDoc { quoted, .. } if *quoted));
    if !all_quoted_heredocs {
        return false;
    }
    !words.iter().any(has_expansions)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[path = "ast_tests.rs"]
mod tests;
