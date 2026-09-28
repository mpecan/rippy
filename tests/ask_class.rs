//! Ask-class behavior a catalog case cannot express. The classes themselves
//! are pinned by `tests/data/catalog/ask_class.toml`.

#![allow(clippy::unwrap_used)]

mod common;

use common::isolated_analyzer;
use rippy_cli::verdict::AskClass;

// The placeholder re-classification that keeps `rm $f` approval runs a second
// analysis; it must not surface in `rippy inspect`'s trace.
#[test]
fn placeholder_probe_is_not_traced() {
    let mut analyzer = isolated_analyzer();
    analyzer.record_trace();
    let verdict = analyzer.analyze("for f in *; do rm $f; done").unwrap();
    assert_eq!(verdict.ask_class(), Some(AskClass::Approval));
    let trace = analyzer.take_trace();
    assert!(!trace.is_empty());
    assert!(
        trace
            .iter()
            .all(|e| !e.detail.contains("rippy-placeholder")),
        "{trace:#?}"
    );
}
