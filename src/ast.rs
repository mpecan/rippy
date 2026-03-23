use tree_sitter::Node;

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

/// Extract the command name (first word) from a `command` or `simple_command` node.
#[must_use]
pub fn command_name<'a>(node: Node<'a>, source: &'a str) -> Option<&'a str> {
    // tree-sitter-bash uses "command_name" as a field name
    node.child_by_field_name("name")
        .map(|n| n.utf8_text(source.as_bytes()).unwrap_or_default())
        .or_else(|| {
            // Fallback: first named child that is a "word" or "command_name"
            let mut cursor = node.walk();
            node.named_children(&mut cursor).find_map(|child| {
                if child.kind() == "command_name" || child.kind() == "word" {
                    Some(child.utf8_text(source.as_bytes()).unwrap_or_default())
                } else {
                    None
                }
            })
        })
}

/// Extract command arguments (all words after the command name) from a command node.
#[must_use]
pub fn command_args(node: Node, source: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut found_name = false;
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "command_name" => {
                found_name = true;
            }
            "word" | "string" | "raw_string" | "concatenation" | "number" if found_name => {
                if let Ok(text) = child.utf8_text(source.as_bytes()) {
                    args.push(strip_quotes(text));
                }
            }
            _ => {
                if found_name
                    && child.kind() != "file_redirect"
                    && let Ok(text) = child.utf8_text(source.as_bytes())
                {
                    args.push(strip_quotes(text));
                }
            }
        }
    }
    args
}

/// Extract the redirect operator and target from a `file_redirect` node.
#[must_use]
pub fn redirect_info(node: Node, source: &str) -> Option<(RedirectOp, String)> {
    if node.kind() != "file_redirect" {
        return None;
    }

    let mut op = RedirectOp::Other;
    let mut target = None;

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let text = child.utf8_text(source.as_bytes()).unwrap_or_default();
        match child.kind() {
            ">" => op = RedirectOp::Write,
            ">>" => op = RedirectOp::Append,
            "<" => op = RedirectOp::Read,
            "&>" | ">&" => op = RedirectOp::FdDup,
            "word" | "string" | "raw_string" | "concatenation" | "number" => {
                target = Some(strip_quotes(text));
            }
            _ => {
                // The operator might be embedded in a different node kind
                if text == ">" {
                    op = RedirectOp::Write;
                } else if text == ">>" {
                    op = RedirectOp::Append;
                } else if text == "<" {
                    op = RedirectOp::Read;
                } else if target.is_none()
                    && !text.is_empty()
                    && !["file_redirect"].contains(&child.kind())
                {
                    target = Some(strip_quotes(text));
                }
            }
        }
    }

    target.map(|t| (op, t))
}

/// Check whether a node's subtree contains command substitutions or process substitutions.
#[must_use]
pub fn has_expansions(node: Node) -> bool {
    if matches!(node.kind(), "command_substitution" | "process_substitution") {
        return true;
    }
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|child| has_expansions(child))
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

    fn parse_first_command(source: &str) -> (tree_sitter::Tree, String) {
        let mut parser = BashParser::new().unwrap();
        let tree = parser.parse(source).unwrap();
        (tree, source.to_owned())
    }

    fn find_node<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
        if node.kind() == kind {
            return Some(node);
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if let Some(found) = find_node(child, kind) {
                return Some(found);
            }
        }
        None
    }

    #[test]
    fn extract_command_name() {
        let (tree, source) = parse_first_command("git status");
        let cmd = find_node(tree.root_node(), "command").unwrap();
        assert_eq!(command_name(cmd, &source), Some("git"));
    }

    #[test]
    fn extract_command_args() {
        let (tree, source) = parse_first_command("git commit -m 'hello world'");
        let cmd = find_node(tree.root_node(), "command").unwrap();
        let args = command_args(cmd, &source);
        assert!(args.contains(&"commit".to_owned()));
        assert!(args.contains(&"-m".to_owned()));
    }

    #[test]
    fn detect_command_substitution() {
        let (tree, _source) = parse_first_command("echo $(whoami)");
        let cmd_sub = find_node(tree.root_node(), "command_substitution");
        assert!(cmd_sub.is_some());
        assert!(has_expansions(tree.root_node()));
    }

    #[test]
    fn no_expansions_in_literal() {
        let (tree, _source) = parse_first_command("echo hello");
        let cmd = find_node(tree.root_node(), "command").unwrap();
        assert!(!has_expansions(cmd));
    }

    #[test]
    fn redirect_write() {
        let (tree, source) = parse_first_command("echo foo > output.txt");
        let redir = find_node(tree.root_node(), "file_redirect").unwrap();
        let (op, target) = redirect_info(redir, &source).unwrap();
        assert_eq!(op, RedirectOp::Write);
        assert_eq!(target, "output.txt");
    }

    #[test]
    fn redirect_append() {
        let (tree, source) = parse_first_command("echo foo >> log.txt");
        let redir = find_node(tree.root_node(), "file_redirect").unwrap();
        let (op, target) = redirect_info(redir, &source).unwrap();
        assert_eq!(op, RedirectOp::Append);
        assert_eq!(target, "log.txt");
    }
}
