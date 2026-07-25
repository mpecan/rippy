//! Crate-internal surfaces exposed to the `fuzz/` targets.
//!
//! Metamorphic invariant 8 (issue #168) is stated over `resolve::WordResolution`,
//! which is `pub(crate)` and therefore unreachable from `fuzz/`. This module is
//! the minimum plain-typed shim that lets the libfuzzer `metamorphic` target
//! assert it. It is compiled only under `feature = "fuzzing"` (and under `cfg(test)`
//! so the shim itself is covered by `cargo test`), and is not public API.

use crate::ast;
use crate::parser::BashParser;
use crate::resolve::{VarLookup, WordResolution, has_process_substitution, resolve_word};

struct UnsetLookup;

impl VarLookup for UnsetLookup {
    fn lookup(&self, _name: &str) -> Option<String> {
        None
    }
}

/// True when resolving `word_source` as an argument yields a `Literal` that
/// still carries a shell expansion or a process substitution — the fail-open
/// invariant 8 forbids.
///
/// Unparseable input and every non-`Literal` outcome return `false`: those are
/// the outcomes the invariant does not constrain.
#[must_use]
pub fn resolution_leaks_expansion(word_source: &str) -> bool {
    let Ok(mut parser) = BashParser::new() else {
        return false;
    };
    let Ok(nodes) = parser.parse(&format!("cat {word_source}")) else {
        return false;
    };
    let Some(node) = nodes.first() else {
        return false;
    };
    let rable::NodeKind::Command { words, .. } = &node.kind else {
        return false;
    };
    let Some(arg) = words.get(1) else {
        return false;
    };
    match resolve_word(arg, &UnsetLookup) {
        WordResolution::Literal(s) => {
            ast::has_shell_expansion_pattern(&s) || has_process_substitution(&s)
        }
        _ => false,
    }
}

#[cfg(test)]
#[expect(clippy::literal_string_with_formatting_args)]
mod tests {
    use super::*;

    #[test]
    fn inert_and_expansion_words_do_not_leak() {
        for src in [
            "safe",
            "${U:-safe}",
            "${U:-$(id)}",
            "$\"$(id)\"",
            "${U:-<(id)}",
        ] {
            assert!(!resolution_leaks_expansion(src), "{src} leaked");
        }
    }

    #[test]
    fn malformed_input_is_not_a_leak() {
        assert!(!resolution_leaks_expansion("'"));
        assert!(!resolution_leaks_expansion(""));
    }
}
