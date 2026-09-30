//! Redaction never panics, and an expanded secret-named value never reaches
//! what rippy shows (docs/security-invariants.md#history-redaction).

use std::path::PathBuf;

use proptest::prelude::*;

use super::secrets;
use crate::analyzer::Analyzer;
use crate::config::Config;
use crate::resolve::tests::MockLookup;

/// Where an expansion lands; `{}` is the `$NAME` reference.
const TEMPLATES: &[&str] = &[
    "echo {}",
    "somecli {}",
    "somecli --flag={}",
    "cat /tmp/{}",
    "git push {} main",
    "kubectl get pods -n {}",
    "curl -H \"Authorization: Bearer {}\" https://x.example",
    "psql -c \"{}\"",
    "{} status",
    "git {}",
    "env {}",
    "bash -c \"{}\"",
];

const REFS: &[&str] = &["$N", "${N}", "\"$N\"", "${N:-dflt}", "x$N"];

const SUFFIXES: &[&str] = &["TOKEN", "PASSWORD", "KEY", "SECRET", "PAT", "AUTH"];

fn secret_case() -> impl Strategy<Value = (String, String, String)> {
    (
        prop::sample::select(TEMPLATES),
        prop::sample::select(REFS),
        "[A-Z]{1,6}",
        prop::sample::select(SUFFIXES),
        "[a-z0-9]{2,20}",
    )
        .prop_map(|(tpl, r, prefix, suffix, tail)| {
            let name = format!("{prefix}_{suffix}");
            // A fixed stem keeps the value from occurring by chance in a reason.
            let value = format!("Zq9{tail}");
            (tpl.replace("{}", &r.replace('N', &name)), name, value)
        })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn secrets_never_panics(text in "[\\s\\S]{0,512}") {
        let _ = secrets(&text);
    }

    #[test]
    fn a_secret_named_value_is_never_shown((command, name, value) in secret_case()) {
        let mut analyzer = Analyzer::new_with_var_lookup(
            Config::empty(),
            false,
            PathBuf::from("/project"),
            false,
            Box::new(MockLookup::new().with(&name, &value)),
        )
        .unwrap();
        analyzer.record_trace();
        let verdict = analyzer.analyze(&command).unwrap();
        let mut shown = vec![verdict.reason.clone()];
        shown.extend(verdict.resolved_command);
        shown.extend(analyzer.take_trace().into_iter().map(|e| e.detail));
        for text in &shown {
            prop_assert!(!text.contains(&value), "{command} [{name}={value}] -> {text}");
        }
    }
}
