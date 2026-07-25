//! Whole-catalog reason snapshot.
//!
//! Every catalog command is analyzed with a fully deterministic analyzer and the
//! resulting `decision` + `reason` are compared line-for-line against
//! `tests/data/reason_snapshot.txt`. It exists to prove that refactors of the
//! verdict-reason machinery (e.g. the typed [`crate::verdict::AllowReason`])
//! leave the user-visible wire strings byte-identical.
//!
//! The snapshot is a self-consistent before/after artifact, not a second source
//! of truth about which commands are safe: it deliberately runs with no `$HOME`,
//! stdlib rules only, an empty variable environment and a fixed literal cwd, so
//! its decisions for `$VAR` cases may differ from the catalog runner's (which
//! uses the real process environment). Catalog expectations stay the authority
//! on decisions; this file only pins reason strings.
//!
//! Regenerate with `RIPPY_UPDATE_REASON_SNAPSHOT=1 cargo test reason_snapshot`.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::analyzer::Analyzer;
use crate::config::Config;
use crate::environment::Environment;
use crate::resolve::tests::MockLookup;

/// Fixed, non-existent cwd: keeps safe-dir and path resolution decisions
/// identical on every machine and keeps developer paths out of the snapshot.
const SNAPSHOT_CWD: &str = "/tmp/rippy-reason-snapshot";

#[derive(Deserialize)]
struct Catalog {
    #[serde(default)]
    case: Vec<Case>,
    #[serde(default)]
    contrast: Vec<ContrastGroup>,
}

#[derive(Deserialize)]
struct Case {
    command: String,
}

#[derive(Deserialize)]
struct ContrastGroup {
    template: String,
    #[serde(default)]
    safe: Vec<ContrastCase>,
    #[serde(default)]
    dangerous: Vec<ContrastCase>,
}

#[derive(Deserialize)]
struct ContrastCase {
    inner: String,
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn snapshot_analyzer() -> Analyzer {
    let cwd = PathBuf::from(SNAPSHOT_CWD);
    let config = Config::load_with_home(&cwd, None, None).unwrap();
    let env = Environment::for_test(cwd).with_var_lookup(Box::new(MockLookup::new()));
    Analyzer::from_env(config, env).unwrap()
}

/// Collect every command the catalog exercises, in a stable order.
fn catalog_commands(catalog_dir: &Path) -> Vec<String> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(catalog_dir)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "toml"))
        .collect();
    paths.sort();

    let mut commands = Vec::new();
    for path in &paths {
        let content = std::fs::read_to_string(path).unwrap();
        let catalog: Catalog = toml::from_str(&content).unwrap();
        commands.extend(catalog.case.into_iter().map(|c| c.command));
        for group in catalog.contrast {
            let inners = group.safe.into_iter().chain(group.dangerous);
            commands.extend(inners.map(|c| group.template.replace("{CMD}", &c.inner)));
        }
    }
    commands
}

fn render_snapshot() -> String {
    use std::fmt::Write as _;

    let mut analyzer = snapshot_analyzer();
    let mut out = String::new();
    for command in catalog_commands(&repo_root().join("tests/data/catalog")) {
        let verdict = analyzer.analyze(&command).unwrap();
        let _ = writeln!(
            out,
            "{}\t{}\t{}",
            command.replace(['\t', '\n'], " "),
            verdict.decision.as_str(),
            verdict.reason.replace(['\t', '\n'], " "),
        );
    }
    out
}

#[test]
fn reason_snapshot_matches() {
    let path = repo_root().join("tests/data/reason_snapshot.txt");
    let actual = render_snapshot();

    if std::env::var_os("RIPPY_UPDATE_REASON_SNAPSHOT").is_some() {
        std::fs::write(&path, &actual).unwrap();
        return;
    }

    let expected = std::fs::read_to_string(&path).unwrap();
    if expected == actual {
        return;
    }
    let diff: Vec<String> = expected
        .lines()
        .zip(actual.lines())
        .filter(|(e, a)| e != a)
        .take(10)
        .map(|(e, a)| format!("\n  expected: {e}\n  actual:   {a}"))
        .collect();
    panic!(
        "reason snapshot drifted ({} expected lines vs {} actual).{}\n\
         Reasons are part of the JSON wire output — regenerate with \
         RIPPY_UPDATE_REASON_SNAPSHOT=1 only when the change is intended.",
        expected.lines().count(),
        actual.lines().count(),
        diff.join("")
    );
}

/// Two renders in the same process must agree; a reason that varied with
/// machine state would silently invalidate the before/after proof.
#[test]
fn reason_snapshot_is_deterministic() {
    assert_eq!(render_snapshot(), render_snapshot());
}
