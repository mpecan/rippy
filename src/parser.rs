use crate::error::RippyError;

/// Wrapper around tree-sitter with the bash grammar.
pub struct BashParser {
    parser: tree_sitter::Parser,
}

impl BashParser {
    /// Create a new parser initialized with the bash grammar.
    ///
    /// # Errors
    ///
    /// Returns `RippyError::Parse` if the language fails to load.
    pub fn new() -> Result<Self, RippyError> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_bash::LANGUAGE.into())
            .map_err(|e| RippyError::Parse(format!("failed to load bash grammar: {e}")))?;
        Ok(Self { parser })
    }

    /// Parse a bash command string into a tree-sitter tree.
    ///
    /// # Errors
    ///
    /// Returns `RippyError::Parse` if tree-sitter fails to produce a tree.
    pub fn parse(&mut self, source: &str) -> Result<tree_sitter::Tree, RippyError> {
        self.parser
            .parse(source, None)
            .ok_or_else(|| RippyError::Parse("tree-sitter returned no tree".into()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_command() {
        let mut parser = BashParser::new().unwrap();
        let tree = parser.parse("echo hello").unwrap();
        let root = tree.root_node();
        assert_eq!(root.kind(), "program");
        assert!(root.child_count() > 0);
    }

    #[test]
    fn parse_pipeline() {
        let mut parser = BashParser::new().unwrap();
        let tree = parser.parse("cat file | grep pattern").unwrap();
        let root = tree.root_node();
        // Should contain a pipeline node
        let child = root.child(0).unwrap();
        assert_eq!(child.kind(), "pipeline");
    }

    #[test]
    fn parse_list() {
        let mut parser = BashParser::new().unwrap();
        let tree = parser.parse("cd /tmp && ls").unwrap();
        let root = tree.root_node();
        let child = root.child(0).unwrap();
        assert_eq!(child.kind(), "list");
    }

    #[test]
    fn parse_redirect() {
        let mut parser = BashParser::new().unwrap();
        let tree = parser.parse("echo foo > output.txt").unwrap();
        let root = tree.root_node();
        let cmd = root.child(0).unwrap();
        // The redirected_statement or simple_command should contain a redirect
        assert!(
            cmd.kind() == "redirected_statement" || cmd.kind() == "command",
            "got: {}",
            cmd.kind()
        );
    }

    #[test]
    fn parse_command_substitution() {
        let mut parser = BashParser::new().unwrap();
        let tree = parser.parse("echo $(whoami)").unwrap();
        let root = tree.root_node();
        // Verify the tree has a command_substitution somewhere
        let source = "echo $(whoami)";
        let mut found = false;
        walk_tree(root, &mut |node| {
            if node.kind() == "command_substitution" {
                found = true;
            }
        });
        assert!(found, "expected command_substitution node in: {source}");
    }

    #[test]
    fn parse_if_statement() {
        let mut parser = BashParser::new().unwrap();
        let tree = parser.parse("if true; then echo yes; fi").unwrap();
        let root = tree.root_node();
        let child = root.child(0).unwrap();
        assert_eq!(child.kind(), "if_statement");
    }

    #[test]
    fn parse_for_loop() {
        let mut parser = BashParser::new().unwrap();
        let tree = parser.parse("for i in 1 2 3; do echo $i; done").unwrap();
        let root = tree.root_node();
        let child = root.child(0).unwrap();
        assert_eq!(child.kind(), "for_statement");
    }

    #[test]
    fn parse_subshell() {
        let mut parser = BashParser::new().unwrap();
        let tree = parser.parse("(echo hello)").unwrap();
        let root = tree.root_node();
        let child = root.child(0).unwrap();
        assert_eq!(child.kind(), "subshell");
    }

    /// Walk all nodes in a tree, calling `f` for each.
    fn walk_tree(node: tree_sitter::Node, f: &mut impl FnMut(tree_sitter::Node)) {
        f(node);
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            walk_tree(child, f);
        }
    }

    #[test]
    fn dump_node_kinds() {
        // Diagnostic test: prints all node kinds for a complex command.
        // Useful for discovering tree-sitter-bash node type names.
        let mut parser = BashParser::new().unwrap();
        let source = "echo hello | grep h && cd /tmp; rm -rf * > /dev/null 2>&1";
        let tree = parser.parse(source).unwrap();
        let mut kinds = Vec::new();
        walk_tree(tree.root_node(), &mut |node| {
            kinds.push(node.kind().to_owned());
        });
        // Just verify we got a reasonable set of node kinds
        assert!(kinds.contains(&"program".to_owned()));
        assert!(kinds.contains(&"command_name".to_owned()));
    }
}
