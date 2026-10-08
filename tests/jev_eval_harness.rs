//! `scripts/jev-eval/sweep.py` replays rippy's Jev policy offline to fit
//! thresholds, so its copies of the policy constants and threshold defaults
//! must match `src/jev/policy.rs` and `JevSettings::default()`. A drift would
//! make the sweep recommend thresholds for a policy rippy does not run.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use rippy_cli::jev_settings::JevSettings;

fn read(relative: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// The value of `const NAME: f64 = <value>;` in Rust source.
fn rust_const(source: &str, name: &str) -> f64 {
    let prefix = format!("const {name}: f64 = ");
    let line = source
        .lines()
        .find_map(|l| l.trim().strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("policy.rs has no `{prefix}…`"));
    line.trim_end_matches(';').trim().parse().unwrap()
}

/// The value of a top-level `NAME = <value>` assignment in Python source.
fn py_assignment<'a>(source: &'a str, name: &str) -> &'a str {
    let prefix = format!("{name} = ");
    source
        .lines()
        .find_map(|l| l.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("sweep.py has no `{prefix}…`"))
        .trim()
}

fn py_float(source: &str, name: &str) -> f64 {
    py_assignment(source, name).parse().unwrap()
}

/// The `key=value` pairs of sweep.py's `DEFAULTS = dict(...)`.
fn py_defaults(source: &str) -> Vec<(String, f64)> {
    let body = py_assignment(source, "DEFAULTS")
        .strip_prefix("dict(")
        .and_then(|b| b.strip_suffix(')'))
        .expect("DEFAULTS is a one-line dict(...)");
    body.split(',')
        .map(|pair| {
            let (key, value) = pair.split_once('=').expect("key=value");
            (key.trim().to_string(), value.trim().parse().unwrap())
        })
        .collect()
}

#[test]
fn sweep_policy_constants_match_policy_rs() {
    let policy = read("src/jev/policy.rs");
    let sweep = read("scripts/jev-eval/sweep.py");
    for name in ["NETWORK_EFFECT_THRESHOLD", "MAX_DESTRUCTIVE"] {
        assert!(
            (rust_const(&policy, name) - py_float(&sweep, name)).abs() < f64::EPSILON,
            "{name} differs between src/jev/policy.rs and scripts/jev-eval/sweep.py"
        );
    }
}

#[test]
fn sweep_defaults_match_jev_settings_default() {
    let s = JevSettings::default();
    let expected = [
        ("exfil", s.exfiltration_threshold),
        ("steer", s.steer_threshold),
        ("secrets", s.max_reads_secrets),
        ("project", s.max_project_code),
    ];
    let actual = py_defaults(&read("scripts/jev-eval/sweep.py"));
    assert_eq!(
        actual.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(),
        expected.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
        "sweep.py DEFAULTS keys changed; update this test with the new mapping"
    );
    for ((key, got), (_, want)) in actual.iter().zip(expected) {
        assert!(
            (got - want).abs() < f64::EPSILON,
            "sweep.py DEFAULTS[{key}] = {got}, but JevSettings::default() has {want}"
        );
    }
}
