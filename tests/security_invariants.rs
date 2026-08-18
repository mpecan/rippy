//! Behavioral locks for the invariants named in `docs/security-invariants.md`.
//!
//! Each test here is cited from that document's traceability table. They fill
//! the gaps the table exposed — most notably the `#env-prefix-strip`
//! fall-through, whose absence let #157 contradict the documented intent.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use rippy_cli::analyzer::Analyzer;
use rippy_cli::config::{Config, ConfigDirective, ConfigFormat};
use rippy_cli::environment::Environment;
use rippy_cli::verdict::{Decision, Verdict};

/// Allow `foo`, deny `baz`. Deliberately tiny: `load_from_str` consults no
/// stdlib rules, so a verdict here comes from these two rules plus the analyzer.
const RULES: &str = "\
[[rules]]
action = \"allow\"
command = \"foo\"

[[rules]]
action = \"deny\"
command = \"baz\"
message = \"nope\"
";

fn ruled_analyzer() -> Analyzer {
    let config = Config::load_from_str(RULES, ConfigFormat::Toml).expect("config parses");
    let env = Environment::for_test(PathBuf::from("/project"));
    Analyzer::from_env(config, env).expect("analyzer builds")
}

fn analyzer_with_scopes(scopes: Vec<PathBuf>) -> Analyzer {
    let directives = scopes.into_iter().map(ConfigDirective::SafeScope).collect();
    let env = Environment::for_test(PathBuf::from("/project"));
    Analyzer::from_env(Config::from_directives(directives), env).expect("analyzer builds")
}

fn verdict(analyzer: &mut Analyzer, command: &str) -> Verdict {
    analyzer.analyze(command).expect("analyze succeeds")
}

fn decide(analyzer: &mut Analyzer, command: &str) -> Decision {
    verdict(analyzer, command).decision
}

#[test]
fn env_prefix_dangerous_var_asks_even_when_command_is_allow_ruled() {
    let mut a = ruled_analyzer();
    let v = verdict(&mut a, "LD_PRELOAD=/tmp/e.so foo");
    assert_eq!(v.decision, Decision::Ask, "reason: {}", v.reason);
    assert!(
        v.reason.contains("unrecognized env-var assignment"),
        "reason: {}",
        v.reason
    );
    assert_eq!(decide(&mut a, "LANG=x foo"), Decision::Allow);
}

#[test]
fn env_prefix_with_expansion_asks_even_when_command_is_allow_ruled() {
    let mut a = ruled_analyzer();
    let v = verdict(&mut a, "FOO=$(rm -rf /) foo");
    assert_eq!(v.decision, Decision::Ask, "reason: {}", v.reason);
    assert!(
        v.reason.contains("assignment with expansion"),
        "reason: {}",
        v.reason
    );
}

#[test]
fn env_prefix_does_not_launder_redirect_past_self_protect() {
    let mut a = ruled_analyzer();
    assert_eq!(decide(&mut a, "LANG=x foo"), Decision::Allow);
    assert_eq!(decide(&mut a, "LANG=x foo > .rippy"), Decision::Deny);
}

#[test]
fn deny_rule_still_matches_unparseable_command() {
    let mut a = ruled_analyzer();
    let unmatched = verdict(&mut a, "foo $( ( bar");
    assert_eq!(unmatched.decision, Decision::Ask);
    assert!(
        unmatched.reason.contains("could not parse"),
        "reason: {}",
        unmatched.reason
    );
    assert_eq!(decide(&mut a, "baz $( ( bar"), Decision::Deny);
}

#[test]
fn allow_rule_does_not_short_circuit_chained_payload() {
    let mut a = ruled_analyzer();
    assert_eq!(decide(&mut a, "foo && rm -rf /"), Decision::Ask);
}

#[test]
fn allow_ruled_leaves_combine_to_allow() {
    let mut a = ruled_analyzer();
    assert_eq!(decide(&mut a, "foo && foo"), Decision::Allow);
    assert_eq!(decide(&mut a, "foo | foo"), Decision::Allow);
}

#[test]
fn allow_rule_leaf_with_redirect_still_self_protects() {
    let mut a = ruled_analyzer();
    assert_eq!(decide(&mut a, "foo > .rippy"), Decision::Deny);
    assert_eq!(decide(&mut a, "foo > /tmp/x.txt"), Decision::Allow);
}

#[test]
fn deny_rule_matches_non_leading_leaf() {
    let mut a = ruled_analyzer();
    assert_eq!(decide(&mut a, "foo; baz"), Decision::Deny);
}

/// A declared scope is a trusted opt-in that skips the world-writable-dir
/// symlink re-check — see docs/security-invariants.md#tmp-symlink. The
/// undeclared half of the pair is the guard that re-check provides.
#[cfg(unix)]
#[test]
fn declared_scope_skips_symlink_recheck() {
    let base = std::path::Path::new("/tmp").join(format!(
        "rippy_scope_symlink_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&base).unwrap();
    std::os::unix::fs::symlink("/etc", base.join("escape")).unwrap();
    let command = format!("echo x > {}/escape/out.txt", base.display());

    let undeclared = decide(&mut analyzer_with_scopes(vec![]), &command);
    let declared = decide(&mut analyzer_with_scopes(vec![base.clone()]), &command);
    std::fs::remove_dir_all(&base).ok();

    assert_eq!(undeclared, Decision::Ask, "{command}");
    assert_eq!(declared, Decision::Allow, "{command}");
}
