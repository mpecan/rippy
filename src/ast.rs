use rable::ast::Node;

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

/// Extract the command name (first word) from a `Command` node.
#[must_use]
pub fn command_name(node: &Node) -> Option<&str> {
    let Node::Command { words, .. } = node else {
        return None;
    };
    words.first().and_then(word_value)
}

/// Extract command arguments (all words after the command name) from a command node.
#[must_use]
pub fn command_args(node: &Node) -> Vec<String> {
    let Node::Command { words, .. } = node else {
        return Vec::new();
    };
    words
        .iter()
        .skip(1) // skip command name
        .map(node_text)
        .collect()
}

/// Extract the redirect operator and target from a `Redirect` node.
#[must_use]
pub fn redirect_info(node: &Node) -> Option<(RedirectOp, String)> {
    let Node::Redirect { op, target, .. } = node else {
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

/// Check whether a node's subtree contains command or process substitutions.
///
/// Rable keeps `$(...)` and backtick substitutions as literal text in word values,
/// so we check word values for expansion patterns rather than looking for
/// `CommandSubstitution` AST nodes.
#[must_use]
pub fn has_expansions(node: &Node) -> bool {
    match node {
        Node::CommandSubstitution { .. } | Node::ProcessSubstitution { .. } => true,
        Node::Word { value, parts, .. } => {
            value.contains("$(") || value.contains('`') || parts.iter().any(has_expansions)
        }
        Node::Command { words, redirects } => {
            words.iter().any(has_expansions) || redirects.iter().any(has_expansions)
        }
        Node::Pipeline { commands } => commands.iter().any(has_expansions),
        Node::List { parts } => parts.iter().any(has_expansions),
        Node::Redirect { target, .. } => has_expansions(target),
        Node::If {
            condition,
            then_body,
            else_body,
            ..
        } => {
            has_expansions(condition)
                || has_expansions(then_body)
                || else_body.as_deref().is_some_and(has_expansions)
        }
        Node::Subshell { body, .. } | Node::BraceGroup { body, .. } => has_expansions(body),
        Node::HereDoc {
            content, quoted, ..
        } => !quoted && (content.contains("$(") || content.contains('`')),
        _ => false,
    }
}

/// Extract text from a node, stripping quotes.
fn node_text(node: &Node) -> String {
    if let Node::Word { value, .. } = node {
        strip_quotes(value)
    } else {
        let s = format!("{node}");
        strip_quotes(&s)
    }
}

/// Get the string value of a word node.
const fn word_value(node: &Node) -> Option<&str> {
    match node {
        Node::Word { value, .. } => Some(value.as_str()),
        _ => None,
    }
}

/// Strip surrounding quotes from a string token.
fn strip_quotes(s: &str) -> String {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        s[1..s.len() - 1].to_owned()
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
            match node {
                Node::Command { .. } => return Some(node),
                Node::Pipeline { commands } => {
                    if let Some(cmd) = find_command(commands) {
                        return Some(cmd);
                    }
                }
                Node::List { parts } => {
                    if let Some(cmd) = find_command(parts) {
                        return Some(cmd);
                    }
                }
                _ => {}
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
        let Node::Command { redirects, .. } = &nodes[0] else {
            unreachable!("expected Command node");
        };
        let (op, target) = redirect_info(&redirects[0]).unwrap();
        assert_eq!(op, RedirectOp::Write);
        assert_eq!(target, "output.txt");
    }

    #[test]
    fn redirect_append() {
        let nodes = parse_first("echo foo >> log.txt");
        let Node::Command { redirects, .. } = &nodes[0] else {
            unreachable!("expected Command node");
        };
        let (op, target) = redirect_info(&redirects[0]).unwrap();
        assert_eq!(op, RedirectOp::Append);
        assert_eq!(target, "log.txt");
    }
}
