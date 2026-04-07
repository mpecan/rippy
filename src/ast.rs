use rable::{Node, NodeKind};

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
            has_shell_expansion_pattern(value) || parts.iter().any(has_expansions)
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

/// Check if a redirect target is inherently safe (e.g., /dev/null).
#[must_use]
pub fn is_safe_redirect_target(target: &str) -> bool {
    matches!(target, "/dev/null" | "/dev/stdout" | "/dev/stderr")
}

/// Check if a command node has file output redirects (>, >>)
/// to targets other than safe ones.
#[must_use]
pub fn has_unsafe_file_redirect(node: &Node) -> bool {
    let NodeKind::Command { redirects, .. } = &node.kind else {
        return false;
    };
    redirects.iter().any(|r| {
        let Some((op, target)) = redirect_info(r) else {
            return false;
        };
        matches!(op, RedirectOp::Write | RedirectOp::Append) && !is_safe_redirect_target(&target)
    })
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::parser::BashParser;

    use super::*;

    fn parse_first(source: &str) -> Vec<Node> {
        let mut parser = BashParser::new().unwrap();
        parser.parse(source).unwrap()
    }

    fn find_command(nodes: &[Node]) -> Option<&Node> {
        for node in nodes {
            match &node.kind {
                NodeKind::Command { .. } => return Some(node),
                NodeKind::Pipeline { commands, .. } => {
                    if let Some(cmd) = find_command(commands) {
                        return Some(cmd);
                    }
                }
                NodeKind::List { items } => {
                    let nodes: Vec<&Node> = items.iter().map(|i| &i.command).collect();
                    if let Some(cmd) = find_command_refs(&nodes) {
                        return Some(cmd);
                    }
                }
                _ => {}
            }
        }
        None
    }

    fn find_command_refs<'a>(nodes: &[&'a Node]) -> Option<&'a Node> {
        for node in nodes {
            if matches!(node.kind, NodeKind::Command { .. }) {
                return Some(node);
            }
        }
        None
    }

    #[test]
    fn extract_command_name() {
        let nodes = parse_first("git status");
        let cmd = find_command(&nodes).unwrap();
        assert_eq!(command_name(cmd), Some("git"));
    }

    #[test]
    fn extract_command_args() {
        let nodes = parse_first("git commit -m 'hello world'");
        let cmd = find_command(&nodes).unwrap();
        let args = command_args(cmd);
        assert!(args.contains(&"commit".to_owned()));
        assert!(args.contains(&"-m".to_owned()));
    }

    #[test]
    fn detect_command_substitution() {
        let nodes = parse_first("echo $(whoami)");
        assert!(has_expansions(&nodes[0]));
    }

    #[test]
    fn no_expansions_in_literal() {
        let nodes = parse_first("echo hello");
        let cmd = find_command(&nodes).unwrap();
        assert!(!has_expansions(cmd));
    }

    #[test]
    fn redirect_write() {
        let nodes = parse_first("echo foo > output.txt");
        let NodeKind::Command { redirects, .. } = &nodes[0].kind else {
            unreachable!("expected Command node");
        };
        let (op, target) = redirect_info(&redirects[0]).unwrap();
        assert_eq!(op, RedirectOp::Write);
        assert_eq!(target, "output.txt");
    }

    #[test]
    fn redirect_append() {
        let nodes = parse_first("echo foo >> log.txt");
        let NodeKind::Command { redirects, .. } = &nodes[0].kind else {
            unreachable!("expected Command node");
        };
        let (op, target) = redirect_info(&redirects[0]).unwrap();
        assert_eq!(op, RedirectOp::Append);
        assert_eq!(target, "log.txt");
    }

    // ---- Expansion detection for hardened node types ----

    #[test]
    fn detect_param_expansion() {
        let nodes = parse_first("echo ${HOME}");
        assert!(has_expansions(&nodes[0]));
    }

    #[test]
    fn detect_simple_var_expansion() {
        let nodes = parse_first("echo $HOME");
        assert!(has_expansions(&nodes[0]));
    }

    #[test]
    fn detect_param_length() {
        let nodes = parse_first("echo ${#var}");
        assert!(has_expansions(&nodes[0]));
    }

    #[test]
    fn detect_param_indirect() {
        let nodes = parse_first("echo ${!ref}");
        assert!(has_expansions(&nodes[0]));
    }

    #[test]
    fn detect_ansi_c_quote() {
        let nodes = parse_first("echo $'\\x41'");
        assert!(has_expansions(&nodes[0]));
    }

    #[test]
    fn detect_locale_string() {
        let nodes = parse_first("echo $\"hello\"");
        assert!(has_expansions(&nodes[0]));
    }

    #[test]
    fn detect_arithmetic_expansion_inline() {
        let nodes = parse_first("echo $((1+1))");
        assert!(has_expansions(&nodes[0]));
    }

    #[test]
    fn detect_brace_expansion() {
        let nodes = parse_first("echo {a,b,c}");
        assert!(has_expansions(&nodes[0]));
    }

    #[test]
    fn detect_brace_expansion_range() {
        let nodes = parse_first("echo {1..10}");
        assert!(has_expansions(&nodes[0]));
    }

    // ---- Quote stripping for ANSI-C and locale ----

    #[test]
    fn strip_ansi_c_quotes() {
        assert_eq!(strip_quotes("$'hello'"), "hello");
    }

    #[test]
    fn strip_locale_quotes() {
        assert_eq!(strip_quotes("$\"hello\""), "hello");
    }

    #[test]
    fn strip_regular_quotes_unchanged() {
        assert_eq!(strip_quotes("'hello'"), "hello");
        assert_eq!(strip_quotes("\"hello\""), "hello");
        assert_eq!(strip_quotes("hello"), "hello");
    }

    // ---- Shell expansion pattern detection ----

    #[test]
    fn expansion_pattern_detects_dollar_var() {
        assert!(has_shell_expansion_pattern("$HOME"));
        assert!(has_shell_expansion_pattern("hello $USER world"));
        assert!(has_shell_expansion_pattern("$_private"));
    }

    #[test]
    fn expansion_pattern_detects_braced() {
        assert!(has_shell_expansion_pattern("${HOME}"));
    }

    #[test]
    fn expansion_pattern_detects_command_sub() {
        assert!(has_shell_expansion_pattern("$(whoami)"));
        assert!(has_shell_expansion_pattern("`whoami`"));
    }

    #[test]
    fn expansion_pattern_detects_ansi_c() {
        assert!(has_shell_expansion_pattern("$'hello'"));
    }

    #[test]
    fn expansion_pattern_no_false_positive() {
        assert!(!has_shell_expansion_pattern("hello world"));
        assert!(!has_shell_expansion_pattern("price is $5"));
        assert!(!has_shell_expansion_pattern(""));
    }
}
