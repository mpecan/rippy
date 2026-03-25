use rable::Node;

use crate::error::RippyError;

/// Wrapper around rable bash parser.
pub struct BashParser;

impl BashParser {
    /// Create a new parser.
    ///
    /// # Errors
    ///
    /// Always succeeds — rable is stateless.
    pub const fn new() -> Result<Self, RippyError> {
        Ok(Self)
    }

    /// Parse a bash command string into a list of AST nodes.
    ///
    /// # Errors
    ///
    /// Returns `RippyError::Parse` if the source cannot be parsed.
    pub fn parse(&mut self, source: &str) -> Result<Vec<Node>, RippyError> {
        rable::parse(source, false).map_err(|e| RippyError::Parse(format!("parse error: {e}")))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use rable::NodeKind;

    use super::*;

    #[test]
    fn parse_simple_command() {
        let mut parser = BashParser::new().unwrap();
        let nodes = parser.parse("echo hello").unwrap();
        assert!(!nodes.is_empty());
        assert!(matches!(nodes[0].kind, NodeKind::Command { .. }));
    }

    #[test]
    fn parse_pipeline() {
        let mut parser = BashParser::new().unwrap();
        let nodes = parser.parse("cat file | grep pattern").unwrap();
        assert!(matches!(nodes[0].kind, NodeKind::Pipeline { .. }));
    }

    #[test]
    fn parse_list() {
        let mut parser = BashParser::new().unwrap();
        let nodes = parser.parse("cd /tmp && ls").unwrap();
        assert!(matches!(nodes[0].kind, NodeKind::List { .. }));
    }

    #[test]
    fn parse_redirect() {
        let mut parser = BashParser::new().unwrap();
        let nodes = parser.parse("echo foo > output.txt").unwrap();
        assert!(
            matches!(&nodes[0].kind, NodeKind::Command { redirects, .. } if !redirects.is_empty())
        );
    }

    #[test]
    fn parse_command_substitution() {
        let mut parser = BashParser::new().unwrap();
        let nodes = parser.parse("echo $(whoami)").unwrap();
        assert!(!nodes.is_empty());
        assert!(crate::ast::has_expansions(&nodes[0]));
    }

    #[test]
    fn parse_if_statement() {
        let mut parser = BashParser::new().unwrap();
        let nodes = parser.parse("if true; then echo yes; fi").unwrap();
        assert!(matches!(nodes[0].kind, NodeKind::If { .. }));
    }

    #[test]
    fn parse_for_loop() {
        let mut parser = BashParser::new().unwrap();
        let nodes = parser.parse("for i in 1 2 3; do echo $i; done").unwrap();
        assert!(matches!(nodes[0].kind, NodeKind::For { .. }));
    }

    #[test]
    fn parse_subshell() {
        let mut parser = BashParser::new().unwrap();
        let nodes = parser.parse("(echo hello)").unwrap();
        assert!(matches!(nodes[0].kind, NodeKind::Subshell { .. }));
    }
}
