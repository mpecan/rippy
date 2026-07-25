//! Metamorphic invariant 8 (issue #168): resolution never hands back a
//! `Literal` that still carries an expansion.
//!
//! A resolved `Literal` is re-analyzed as a plain string, so an expansion
//! surviving into one would be evaluated by the shell but never seen by the
//! analyzer — the whole #156 class of fail-opens. This generalizes the
//! fixed-list `no_unset_default_resolves_to_expansion_bearing_literal` test to
//! unbounded nesting. Scoped to an all-unset lookup, because a *set* variable's
//! value is deliberately kept verbatim (see
//! `set_var_value_containing_expansion_stays_verbatim`).

use proptest::prelude::*;
use rable::NodeKind;

use super::tests::MockLookup;
use super::{WordResolution, has_process_substitution, resolve_word};
use crate::ast;
use crate::parser::BashParser;

/// Expansion forms that must never survive into a resolved literal.
const PAYLOADS: &[&str] = &[
    "$(id)", "`id`", "<(id)", ">(id)", "$HOME", "$1", "$@", "$*", "${V}", "$((1+1))",
];

const INERT: &[&str] = &["safe", "a.b", "x-1", "0"];

fn arb_word() -> impl Strategy<Value = String> {
    let leaf = prop_oneof![prop::sample::select(PAYLOADS), prop::sample::select(INERT),]
        .prop_map(str::to_string);

    leaf.prop_recursive(3, 16, 2, |inner| {
        prop_oneof![
            inner.clone().prop_map(|p| format!("${{U:-{p}}}")),
            inner.clone().prop_map(|p| format!("${{U-{p}}}")),
            inner.clone().prop_map(|p| format!("${{U:+{p}}}")),
            // A `"` in the payload would terminate the translated string early
            // and generate a malformed word rather than a nested expansion.
            inner.clone().prop_map(|p| if p.contains('"') {
                format!("${{U:-{p}}}")
            } else {
                format!("$\"{p}\"")
            }),
            (inner.clone(), inner).prop_map(|(a, b)| format!("{a}{b}")),
        ]
    })
}

fn resolve_first_arg(source: &str) -> Option<WordResolution> {
    let mut parser = BashParser::new().ok()?;
    let nodes = parser.parse(source).ok()?;
    let NodeKind::Command { words, .. } = &nodes.first()?.kind else {
        return None;
    };
    let node = words.get(1)?;
    Some(resolve_word(node, &MockLookup::new()))
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 512,
        max_shrink_iters: 512,
        .. ProptestConfig::default()
    })]

    #[test]
    fn resolved_literal_never_carries_expansion(word in arb_word()) {
        let source = format!("cat {word}");
        let Some(WordResolution::Literal(s)) = resolve_first_arg(&source) else {
            return Ok(());
        };
        prop_assert!(
            !ast::has_shell_expansion_pattern(&s),
            "{source:?} resolved to expansion-bearing literal {s:?}"
        );
    }

    #[test]
    fn resolved_literal_never_carries_process_substitution(word in arb_word()) {
        let source = format!("cat {word}");
        let Some(WordResolution::Literal(s)) = resolve_first_arg(&source) else {
            return Ok(());
        };
        prop_assert!(
            !has_process_substitution(&s),
            "{source:?} resolved to process-substitution literal {s:?}"
        );
    }
}
