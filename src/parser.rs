use rable::Node;

use crate::error::RippyError;
use crate::nesting::Shape;

/// Stack for the parse thread. rable caps its own parser recursion at 1 000
/// frames, which the worst construct (`case`) needs ~16 MB for; `nesting` caps
/// the lexer recursion rable does not. 256 MB leaves every one of those bounds
/// a margin of 16x or better, and the mapping is only ever committed as it is
/// touched. see docs/security-invariants.md#parser-stack-bound
const PARSE_STACK: usize = 256 * 1024 * 1024;

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
    /// Returns `RippyError::TooComplex` for input whose shape rable could only
    /// answer with a stack overflow (#195), and `RippyError::Parse` if the
    /// source cannot be parsed.
    pub fn parse(&mut self, source: &str) -> Result<Vec<Node>, RippyError> {
        let shape = Shape::of(source);
        if let Some(detail) = shape.violation() {
            return Err(RippyError::TooComplex(detail));
        }
        if shape.is_flat() {
            return rable::parse(source, false).map_err(|e| RippyError::Parse(format!("{e}")));
        }
        parse_on_a_deep_stack(source).map_err(RippyError::Parse)
    }
}

/// Parse on a thread sized for the bounds in `nesting`. A stack overflow aborts
/// the process rather than unwinding, so the hook's fail-closed net would never
/// see it and the agent would read the empty stdout as an approval (#195).
fn parse_on_a_deep_stack(source: &str) -> Result<Vec<Node>, String> {
    std::thread::scope(|scope| {
        let spawned = std::thread::Builder::new()
            .stack_size(PARSE_STACK)
            .spawn_scoped(scope, || {
                rable::parse(source, false).map_err(|e| format!("{e}"))
            });
        match spawned {
            Ok(handle) => handle
                .join()
                .unwrap_or_else(|_| Err("the parser panicked".to_owned())),
            Err(e) => Err(format!("could not start a parser thread: {e}")),
        }
    })
}

#[cfg(test)]
#[expect(clippy::unwrap_used)]
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

    #[test]
    fn parse_error_prefix_not_doubled() {
        let mut parser = BashParser::new().unwrap();
        let err = parser.parse("echo $( ( unbalanced").unwrap_err();
        let msg = err.to_string();
        // Display prepends exactly one "parse error: "; the closure must not double it.
        assert_eq!(msg.matches("parse error:").count(), 1, "message: {msg}");
    }
}
