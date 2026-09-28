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

// Verification finding: a config alias makes rippy judge one program while the
// text names another (`python3` judged as `kubectl`). The class records that
// the judgement was indirect, so the ask is never sent for review.
#[test]
fn an_alias_rewrite_is_indirect() {
    use rippy_cli::config::{Config, ConfigFormat};
    use rippy_cli::environment::Environment;
    use rippy_cli::verdict::UncertainKind;

    let toml = "[[aliases]]\nsource = \"python3\"\ntarget = \"kubectl\"\n";
    let config = Config::load_from_str(toml, ConfigFormat::Toml).unwrap();
    let env = Environment::for_test(std::path::PathBuf::from("/nonexistent-rippy-alias-dir"));
    let mut analyzer = rippy_cli::analyzer::Analyzer::from_env(config, env).unwrap();
    let aliased = analyzer
        .analyze("python3 get pods -n $RIPPY_T_UNSET_NS")
        .unwrap();
    assert_eq!(
        aliased.ask_class(),
        Some(AskClass::Uncertain(UncertainKind::Indirect))
    );
    let direct = analyzer
        .analyze("kubectl get pods -n $RIPPY_T_UNSET_NS")
        .unwrap();
    assert_eq!(
        direct.ask_class(),
        Some(AskClass::Uncertain(UncertainKind::DynamicExpansion))
    );
}
