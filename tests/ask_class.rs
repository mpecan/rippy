//! Ask-class behavior a catalog case cannot express. The classes themselves
//! are pinned by `tests/data/catalog/ask_class.toml`.

#![allow(clippy::unwrap_used)]

mod common;

use common::isolated_analyzer;
use rippy_cli::verdict::{AskClass, Decision};

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

/// Prefixes that set a name outside the inert list, literal and not.
const UNVETTED_PREFIXES: &[&str] = &[
    "FOO=1",
    "LD_PRELOAD=./x.so",
    "PATH=./bin",
    "FOO=$HOME",
    "LD_PRELOAD=$HOME/x.so",
    "FOO=$(id)",
];

// Review of the rebase onto #210: an expansion prefix downgraded an approval
// ask (`FOO=$HOME rm -rf build`) to a reviewable class.
#[test]
fn an_unvetted_env_prefix_never_leaves_an_ask_reviewable() {
    let mut analyzer = isolated_analyzer();
    let mut checked = 0;
    for case in common::catalog::load() {
        for prefix in UNVETTED_PREFIXES {
            let prefixed = format!("{prefix} {}", case.command);
            let Ok(v) = analyzer.analyze(&prefixed) else {
                continue;
            };
            if v.decision != Decision::Ask {
                continue;
            }
            checked += 1;
            assert!(
                !v.ask_class().is_some_and(AskClass::is_reviewable),
                "{prefixed}: {:?}",
                v.ask_class()
            );
        }
    }
    assert!(checked > 1000, "only {checked} prefixed asks");
}

// An inert name with a value rippy cannot see asks as `dynamic-expansion`, but
// that class must not stand in for what the command itself needs.
#[test]
fn an_expansion_prefix_never_lowers_the_class() {
    let mut analyzer = isolated_analyzer();
    let mut checked = 0;
    for case in common::catalog::load() {
        let Ok(own) = analyzer.analyze(&case.command) else {
            continue;
        };
        let needs_approval =
            own.decision == Decision::Deny || own.ask_class() == Some(AskClass::Approval);
        if !needs_approval {
            continue;
        }
        let prefixed = format!("CI=$X {}", case.command);
        let Ok(v) = analyzer.analyze(&prefixed) else {
            continue;
        };
        checked += 1;
        assert!(
            v.decision == Decision::Deny || !v.ask_class().is_some_and(AskClass::is_reviewable),
            "{prefixed}: {:?}",
            v.ask_class()
        );
    }
    assert!(checked > 300, "only {checked} commands");
}
