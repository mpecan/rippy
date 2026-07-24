use super::*;

/// #152 item 1: `combine_parts`'s `Unresolvable`/`DynamicKnown` arm is normally
/// unreachable (both are filtered by `resolve_word_node` before this is called).
/// Calling it directly with such a part must fail closed (`Unresolvable`, which
/// forces Ask), never `panic!` — a security hook must not be one refactor away
/// from crashing.
#[test]
fn combine_parts_fails_closed_on_unexpected_variant() {
    for part in [
        WordResolution::DynamicKnown,
        WordResolution::Unresolvable {
            reason: "seed".to_string(),
        },
    ] {
        let result = combine_parts(&[WordResolution::Literal("a".to_string()), part]);
        assert!(
            matches!(result, WordResolution::Unresolvable { .. }),
            "expected fail-closed Unresolvable, got {result:?}"
        );
    }
}
