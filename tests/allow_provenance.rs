//! Provenance of approvals, asserted by category rather than by reason substring.
//!
//! Every pair below was recorded from observed analyzer output before being
//! written down; several are not what a naive reading of the code suggests, and
//! carry a comment saying why.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::PathBuf;

use common::isolated_analyzer;
use rippy_cli::analyzer::Analyzer;
use rippy_cli::config::Config;
use rippy_cli::environment::Environment;
use rippy_cli::verdict::{AllowReason, Decision, RuleSource};

fn provenance(command: &str) -> AllowReason {
    let mut analyzer = isolated_analyzer();
    let verdict = analyzer.analyze(command).unwrap();
    assert_eq!(
        verdict.decision,
        Decision::Allow,
        "{command:?} did not allow: {}",
        verdict.reason
    );
    verdict
        .allow_reason()
        .unwrap_or_else(|| panic!("{command:?} allowed without provenance"))
        .clone()
}

fn analyzer_in(dir: PathBuf, home: Option<PathBuf>) -> Analyzer {
    let config = Config::load_with_home(&dir, None, home.clone()).unwrap();
    Analyzer::from_env(config, Environment::for_test(dir).with_home(home)).unwrap()
}

/// A tempdir home whose global config waives the project-config trust prompt,
/// so a project rule written by the test is actually loaded.
fn trusting_home() -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join(".rippy")).unwrap();
    std::fs::write(
        home.path().join(".rippy/config.toml"),
        "[settings]\ntrust-project-configs = true\n",
    )
    .unwrap();
    home
}

#[test]
fn allowlist_and_wrapper_provenance() {
    assert_eq!(provenance("ls -la"), AllowReason::SimpleSafe("ls".into()));
    assert_eq!(
        provenance("nohup"),
        AllowReason::Wrapper("nohup".into()),
        "a wrapper with no inner command has nothing to recurse into"
    );
    assert_eq!(
        provenance("tar --help"),
        AllowReason::HelpFlag("tar".into())
    );
    assert_eq!(
        provenance("for f in *.txt; do cat $f; done"),
        AllowReason::DynamicArgSafe("cat".into())
    );
}

#[test]
fn redirect_provenance() {
    assert_eq!(provenance("cat < /etc/hosts"), AllowReason::InputRedirect);
    // `Verdict::combine` picks the LAST maximum on a tie, so the redirect
    // verdict — not `ls is safe` — is the one that survives.
    assert_eq!(provenance("ls 2>&1"), AllowReason::FdRedirect);
    assert_eq!(
        provenance("echo hi > /dev/null"),
        AllowReason::DeviceRedirect("/dev/null".into())
    );
    assert_eq!(
        provenance("echo hi > /tmp/rippy-provenance-out"),
        AllowReason::SafeDirWrite("/tmp/rippy-provenance-out".into())
    );
}

#[test]
fn structural_provenance() {
    assert_eq!(provenance("cat <<'EOF'\nhello\nEOF"), AllowReason::Heredoc);
    assert_eq!(
        provenance("FOO=bar"),
        AllowReason::EmptyCommand,
        "a bare assignment parses to a command node with no command name"
    );
    assert_eq!(
        provenance("case x in y) ;; esac"),
        AllowReason::Empty,
        "a case with only empty bodies produces nothing to report"
    );
}

#[test]
fn handler_provenance() {
    assert_eq!(provenance("git status"), AllowReason::handler("git status"));
    assert_eq!(
        provenance("kubectl get pods"),
        AllowReason::handler("kubectl get")
    );
}

#[test]
fn baseline_config_rule_provenance() {
    // `cargo` is driven by stdlib rules, not by a handler or the allowlist.
    let AllowReason::ConfigRule { source, detail } = provenance("cargo build") else {
        panic!("cargo build is not rule-driven");
    };
    assert_eq!(source, RuleSource::Baseline);
    assert!(
        detail.starts_with("matched rule: command=cargo"),
        "{detail}"
    );
}

#[test]
fn project_config_rule_provenance() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(".rippy.toml"),
        "[[rules]]\naction = \"allow\"\ncommand = \"frobnicate\"\n",
    )
    .unwrap();

    let home = trusting_home();
    let verdict = analyzer_in(dir.path().to_path_buf(), Some(home.path().to_path_buf()))
        .analyze("frobnicate --now")
        .unwrap();
    assert_eq!(verdict.decision, Decision::Allow);
    let Some(AllowReason::ConfigRule { source, .. }) = verdict.allow_reason() else {
        panic!("expected a rule allow, got {:?}", verdict.allow_reason());
    };
    assert_eq!(*source, RuleSource::Project);
}

#[test]
fn default_action_provenance() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(".rippy.toml"),
        "[settings]\ndefault = \"allow\"\n",
    )
    .unwrap();

    let home = trusting_home();
    let verdict = analyzer_in(dir.path().to_path_buf(), Some(home.path().to_path_buf()))
        .analyze("frobnicate --now")
        .unwrap();
    assert_eq!(verdict.decision, Decision::Allow);
    let Some(AllowReason::DefaultAction { cmd, .. }) = verdict.allow_reason() else {
        panic!(
            "expected a default-action allow, got {:?}",
            verdict.allow_reason()
        );
    };
    assert_eq!(cmd, "frobnicate");
}

#[test]
fn cc_permission_provenance() {
    let home = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join(".claude")).unwrap();
    std::fs::write(
        home.path().join(".claude/settings.json"),
        r#"{"permissions":{"allow":["Bash(frobnicate:*)"]}}"#,
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();

    let verdict = analyzer_in(dir.path().to_path_buf(), Some(home.path().to_path_buf()))
        .analyze("frobnicate --now")
        .unwrap();
    assert_eq!(verdict.decision, Decision::Allow);
    assert_eq!(
        verdict.allow_reason(),
        Some(&AllowReason::CcPermission("frobnicate --now".into()))
    );
}

/// `AllowReason::AfterRule` is minted in the `PostToolUse` path, which only the
/// binary exercises, and provenance is deliberately not serialized — so this
/// asserts the wire string the variant has to keep producing.
#[test]
fn after_rule_message_reaches_additional_context() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(".rippy.toml"),
        "[[rules]]\naction = \"after\"\npattern = \"ls*\"\nmessage = \"ran a listing\"\n",
    )
    .unwrap();
    let home = trusting_home();

    let json = concat!(
        r#"{"tool_name":"Bash","tool_input":{"command":"ls"},"#,
        r#""tool_result":{"output":"file.txt"},"hook_event_name":"PostToolUse"}"#
    );
    let output = std::process::Command::new(common::rippy_binary())
        .args(["--mode", "claude"])
        .current_dir(dir.path())
        .env("HOME", home.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write as _;
            child.stdin.as_mut().unwrap().write_all(json.as_bytes())?;
            child.wait_with_output()
        })
        .unwrap();

    let v: serde_json::Value = serde_json::from_slice(&output.stdout).expect("hook emits JSON");
    assert_eq!(
        v["hookSpecificOutput"]["additionalContext"],
        "ran a listing"
    );
}
