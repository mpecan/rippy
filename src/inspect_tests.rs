use crate::config::RuleTarget;
use crate::environment::Environment;
use crate::verdict::Decision;

use super::*;

/// Fixed, non-existent cwd so safe-dir and path decisions are machine-independent.
const TRACE_CWD: &str = "/tmp/rippy-inspect-trace";

/// Commands whose traced decision must equal the analyzer's, spanning every
/// routing shape the old parallel implementation got wrong: compound forms
/// (#137), redirects, env prefixes and each `AllowReason` provenance (#163).
const SPREAD: &[&str] = &[
    "ls -la",
    "git status",
    "git push origin main",
    "some_unknown_tool --flag",
    "cargo build",
    "ls -la | head",
    "git log --oneline && git status",
    "git log --oneline || echo fail",
    "ls; echo done",
    "ls && rm -rf /",
    "echo secret > .env",
    "echo x > /etc/passwd",
    "ls | tee /etc/hosts",
    "echo hi > /dev/null",
    "echo hi > /tmp/rippy-inspect-out",
    "cat < /etc/hosts",
    "ls 2>&1",
    "LANG=x echo hi",
    "LD_PRELOAD=/tmp/x ls",
    "FOO=$(id) ls",
    "x=$(ls); echo $x",
    "for i in 1 2 3; do echo $i; done",
    "for f in *.txt; do cat $f; done",
    "cat <<'EOF'\nhello\nEOF",
    "nohup",
    "env ls",
    "tar --help",
    "case x in y) ;; esac",
    "FOO=bar",
    "if",
];

/// An analyzer isolated from the developer's `~/.rippy` and `~/.claude`, so the
/// spread below is deterministic on every machine.
fn trace_test_analyzer() -> crate::analyzer::Analyzer {
    let cwd = PathBuf::from(TRACE_CWD);
    let config = Config::load_with_home(&cwd, None, None).unwrap();
    crate::analyzer::Analyzer::from_env(config, Environment::for_test(cwd)).unwrap()
}

fn analyzer_at(dir: &Path, config_path: &Path) -> crate::analyzer::Analyzer {
    let config = Config::load_with_home(dir, Some(config_path), None).unwrap();
    crate::analyzer::Analyzer::from_env(config, Environment::for_test(dir.to_path_buf())).unwrap()
}

#[test]
fn rule_to_display_command() {
    let rule = Rule::new(RuleTarget::Command, Decision::Allow, "git status");
    let d = rule_to_display(&rule);
    assert_eq!(d.action, "allow");
    assert_eq!(d.pattern, "git status");
    assert!(d.message.is_none());
}

#[test]
fn rule_to_display_with_message() {
    let rule = Rule::new(RuleTarget::Command, Decision::Deny, "rm -rf *").with_message("use trash");
    let d = rule_to_display(&rule);
    assert_eq!(d.action, "deny");
    assert_eq!(d.message.as_deref(), Some("use trash"));
}

#[test]
fn rule_to_display_redirect() {
    let rule =
        Rule::new(RuleTarget::Redirect, Decision::Deny, "**/.env*").with_message("protected");
    let d = rule_to_display(&rule);
    assert_eq!(d.action, "deny-redirect");
}

#[test]
fn rule_to_display_mcp() {
    let rule = Rule::new(RuleTarget::Mcp, Decision::Allow, "mcp__github__*");
    let d = rule_to_display(&rule);
    assert_eq!(d.action, "allow-mcp");
    assert_eq!(d.pattern, "mcp__github__*");
}

#[test]
fn rule_to_display_after() {
    let rule = Rule::new(RuleTarget::After, Decision::Allow, "git commit")
        .with_message("don't forget to push");
    let d = rule_to_display(&rule);
    assert_eq!(d.action, "after");
    assert_eq!(d.message.as_deref(), Some("don't forget to push"));
}

#[test]
fn directive_to_display_skips_set() {
    let d = ConfigDirective::Set {
        key: "default".to_string(),
        value: "ask".to_string(),
    };
    assert!(directive_to_display(&d).is_none());
}

#[test]
fn trace_handler_command() {
    let cwd = std::env::current_dir().unwrap();
    let output = collect_trace_data("git push origin main", &cwd, None).unwrap();
    assert_eq!(output.decision, "ask");
    assert!(
        output
            .steps
            .iter()
            .any(|s| s.stage == "Handler" && s.matched)
    );
}

#[test]
fn trace_safe_command() {
    let cwd = std::env::current_dir().unwrap();
    let output = collect_trace_data("cat /tmp/file", &cwd, None).unwrap();
    assert_eq!(output.decision, "allow");
    assert!(
        output
            .steps
            .iter()
            .any(|s| s.stage == "Allowlist" && s.matched)
    );
}

#[test]
fn trace_with_config_rule() {
    let dir = tempfile::TempDir::new().unwrap();
    let config_path = dir.path().join("test.toml");
    std::fs::write(
        &config_path,
        "[[rules]]\naction = \"deny\"\npattern = \"echo evil\"\nmessage = \"no evil\"\n",
    )
    .unwrap();

    let output = collect_trace_data("echo evil", dir.path(), Some(&config_path)).unwrap();
    assert_eq!(output.decision, "deny");
    assert_eq!(output.reason, "no evil");
    assert!(
        output
            .steps
            .iter()
            .any(|s| s.stage == "Config rules" && s.matched)
    );
}

#[test]
fn trace_env_prefix_matches_config_rule() {
    // #133: an env-prefixed command should trace against the stripped form
    // and match a bare-command rule, disclosing the normalization step.
    let dir = tempfile::TempDir::new().unwrap();
    let config_path = dir.path().join("test.toml");
    std::fs::write(
        &config_path,
        "[[rules]]\naction = \"deny\"\npattern = \"echo evil\"\nmessage = \"no evil\"\n",
    )
    .unwrap();

    let output = collect_trace_data("LANG=x echo evil", dir.path(), Some(&config_path)).unwrap();
    assert_eq!(output.decision, "deny");
    assert_eq!(output.reason, "no evil");
    assert!(
        output
            .steps
            .iter()
            .any(|s| s.stage == "Config rules" && s.matched)
    );
    // Transparency: the normalization is disclosed.
    assert!(
        output
            .steps
            .iter()
            .any(|s| s.stage == "Env prefix" && s.matched)
    );
}

/// #133 (env prefix on the first command of a pipeline strips correctly) crossed
/// with #155: the stripped form is what the whole-string rule sees, but a
/// pipeline is not a single plain command, so the matching ALLOW is *withheld* —
/// the approval comes from the per-leaf allowlist instead. The trace must say so
/// rather than credit the rule.
#[test]
fn trace_env_prefix_pipeline_records_withheld_allow_rule() {
    let dir = tempfile::TempDir::new().unwrap();
    let config_path = dir.path().join("test.toml");
    std::fs::write(
        &config_path,
        "[[rules]]\naction = \"allow\"\npattern = \"echo hi | cat\"\n",
    )
    .unwrap();

    let output =
        collect_trace_data("LANG=x echo hi | cat", dir.path(), Some(&config_path)).unwrap();
    assert_eq!(output.decision, "allow");
    assert!(
        output
            .steps
            .iter()
            .any(|s| s.stage == "Env prefix" && s.matched),
        "the stripped form was not disclosed"
    );
    let rule_step = output
        .steps
        .iter()
        .find(|s| s.stage == "Config rules")
        .unwrap();
    assert!(
        rule_step.detail.contains("echo hi | cat"),
        "the rule was matched against the un-stripped command: {}",
        rule_step.detail
    );
    assert!(
        !rule_step.matched,
        "a withheld allow rule must not be recorded as the deciding layer"
    );
    assert!(rule_step.detail.contains("not applied"));
    assert_eq!(output.provenance.as_deref(), Some("simple-safe"));
}

#[test]
fn trace_unknown_command_asks() {
    let dir = tempfile::TempDir::new().unwrap();
    let output = collect_trace_data("some_unknown_tool --flag", dir.path(), None).unwrap();
    // Unknown commands should result in ask (default).
    assert_eq!(output.decision, "ask");
}

#[test]
fn list_rules_from_config_file() {
    let dir = tempfile::TempDir::new().unwrap();
    let config = dir.path().join("test.toml");
    std::fs::write(&config, "[[rules]]\naction = \"allow\"\npattern = \"ls\"\n").unwrap();

    let source = load_source_rules(&config).unwrap();
    assert_eq!(source.rules.len(), 1);
    assert_eq!(source.rules[0].action, "allow");
    assert_eq!(source.rules[0].pattern, "ls");
}

#[test]
fn collect_list_with_config_override() {
    let dir = tempfile::TempDir::new().unwrap();
    let config = dir.path().join("test.toml");
    std::fs::write(
        &config,
        "[settings]\ndefault = \"deny\"\n\n[[rules]]\n\
         action = \"allow\"\npattern = \"git *\"\n",
    )
    .unwrap();

    let output = collect_list_data(dir.path(), Some(&config)).unwrap();
    assert!(!output.config_sources.is_empty());
    assert_eq!(output.default_action.as_deref(), Some("deny"));
    assert!(output.handler_count > 0);
    assert!(output.simple_safe_count > 0);
}

#[test]
fn json_output_parses() {
    let output = ListOutput {
        config_sources: vec![SourceRules {
            path: "test.toml".to_string(),
            rules: vec![RuleDisplay {
                action: "allow".to_string(),
                pattern: "git status".to_string(),
                message: None,
            }],
        }],
        cc_sources: vec![],
        active_package: Some("develop".to_string()),
        default_action: Some("ask".to_string()),
        handler_count: 43,
        simple_safe_count: 165,
        wrapper_count: 8,
    };
    let json = serde_json::to_string(&output).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["handler_count"], 43);
}

#[test]
fn trace_pipe_command_parses() {
    let cwd = std::env::current_dir().unwrap();
    let output = collect_trace_data("ls -la | head", &cwd, None).unwrap();
    assert_ne!(output.reason, "could not parse command");
    // Pin the decision to the analyzer's own verdict rather than a hard-coded
    // "allow" so this test cannot flap on a developer's global config or CC
    // permissions.
    let config = Config::load(&cwd, None).unwrap();
    let mut analyzer = crate::analyzer::Analyzer::new(config, false, cwd, false).unwrap();
    let verdict = analyzer.analyze("ls -la | head").unwrap();
    assert_eq!(output.decision, verdict.decision.as_str());
    assert!(output.steps.iter().any(|s| s.stage == "Parse" && s.matched));
}

#[test]
fn trace_and_operator_parses() {
    let cwd = std::env::current_dir().unwrap();
    let output = collect_trace_data("git log --oneline && git status", &cwd, None).unwrap();
    assert_ne!(output.reason, "could not parse command");
}

#[test]
fn trace_compound_never_unparseable() {
    let cwd = std::env::current_dir().unwrap();
    let commands = [
        "ls -la | head",
        "git log --oneline && git status",
        "git log --oneline || echo fail",
        "ls; echo done",
        "for i in 1 2 3; do echo $i; done",
        "x=$(ls); echo $x",
    ];
    for command in commands {
        let output = collect_trace_data(command, &cwd, None).unwrap();
        assert_ne!(
            output.reason, "could not parse command",
            "command was wrongly reported unparseable: {command}"
        );
    }
}

#[test]
fn trace_safe_command_with_redirect_not_short_circuited() {
    // Regression for #137: a lone safe command with a redirect must route
    // through the analyzer, not auto-approve on the command name.
    let cwd = std::env::current_dir().unwrap();
    let output = collect_trace_data("echo secret > .env", &cwd, None).unwrap();

    let config = Config::load(&cwd, None).unwrap();
    let mut analyzer = crate::analyzer::Analyzer::new(config, false, cwd, false).unwrap();
    let verdict = analyzer.analyze("echo secret > .env").unwrap();
    assert_eq!(output.decision, verdict.decision.as_str());
    assert_ne!(output.decision, "allow");
}

#[test]
fn trace_semicolon_list_not_judged_on_first_cmd() {
    let cwd = std::env::current_dir().unwrap();
    let output = collect_trace_data("ls; echo done", &cwd, None).unwrap();

    // Trace decision must equal the analyzer's verdict, proving the list is
    // routed recursively rather than judged on its safe first word `ls`.
    let config = Config::load(&cwd, None).unwrap();
    let mut analyzer = crate::analyzer::Analyzer::new(config, false, cwd, false).unwrap();
    let verdict = analyzer.analyze("ls; echo done").unwrap();
    assert_eq!(output.decision, verdict.decision.as_str());
}

#[test]
fn trace_unsafe_compound_not_allowed() {
    let cwd = std::env::current_dir().unwrap();
    let output = collect_trace_data("ls && rm -rf /", &cwd, None).unwrap();
    // An unsafe compound must never auto-approve on the strength of `ls`.
    assert_ne!(output.decision, "allow");
}

#[test]
fn trace_truly_unparseable_still_asks() {
    let cwd = std::env::current_dir().unwrap();
    // A bare `if` keyword is an incomplete construct rable rejects with Err.
    let output = collect_trace_data("if", &cwd, None).unwrap();
    assert_eq!(output.decision, "ask");
    assert_eq!(
        output.reason,
        "rippy could not parse this command; approve manually"
    );
}

#[test]
fn trace_json_output_parses() {
    let output = TraceOutput {
        command: "git status".to_string(),
        decision: "allow".to_string(),
        reason: "git is safe".to_string(),
        resolved: None,
        provenance: Some("handler".to_string()),
        steps: vec![TraceStep {
            stage: "Allowlist".to_string(),
            matched: true,
            detail: "git is safe".to_string(),
        }],
    };
    let json = serde_json::to_string(&output).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["decision"], "allow");
    assert_eq!(parsed["provenance"], "handler");
}

/// The core anti-regression test for #167: the explain path reports exactly what
/// the hook path decided, for every routing shape.
#[test]
fn trace_decision_matches_analyzer_across_spread() {
    for command in SPREAD {
        let output = trace_with_analyzer(&mut trace_test_analyzer(), command).unwrap();
        let verdict = trace_test_analyzer().analyze(command).unwrap();
        assert_eq!(
            output.decision,
            verdict.decision.as_str(),
            "decision diverged for {command:?}"
        );
        assert_eq!(
            output.reason, verdict.reason,
            "reason diverged for {command:?}"
        );
        assert_eq!(
            output.resolved, verdict.resolved_command,
            "resolution diverged for {command:?}"
        );
    }
}

#[test]
fn trace_provenance_matches_allow_reason() {
    for command in SPREAD {
        let output = trace_with_analyzer(&mut trace_test_analyzer(), command).unwrap();
        let verdict = trace_test_analyzer().analyze(command).unwrap();
        let expected = verdict
            .allow_reason()
            .map(|r| AllowReason::variant_name(r).to_string());
        assert_eq!(output.provenance, expected, "provenance for {command:?}");
        if output.decision != "allow" {
            assert!(
                output.provenance.is_none(),
                "{command:?} reported provenance without allowing"
            );
        }
    }
}

/// Pins the provenance label per approval route, so a future refactor that
/// re-routes an approval (say, allowlist → handler) is visible in the trace.
#[test]
fn trace_provenance_names_the_approval_route() {
    let cases: &[(&str, &str)] = &[
        ("ls -la", "simple-safe"),
        ("nohup", "wrapper"),
        ("tar --help", "help-flag"),
        ("for f in *.txt; do cat $f; done", "dynamic-arg-safe"),
        ("cat < /etc/hosts", "input-redirect"),
        ("ls 2>&1", "fd-redirect"),
        ("echo hi > /dev/null", "device-redirect"),
        ("echo hi > /tmp/rippy-inspect-out", "safe-dir-write"),
        ("cat <<'EOF'\nhello\nEOF", "heredoc"),
        ("git status", "handler"),
        ("cargo build", "config-rule"),
        ("CI=bar", "empty-command"),
        ("case x in y) ;; esac", "empty"),
    ];
    for (command, expected) in cases {
        let output = trace_with_analyzer(&mut trace_test_analyzer(), command).unwrap();
        assert_eq!(output.decision, "allow", "{command:?}: {}", output.reason);
        assert_eq!(output.provenance.as_deref(), Some(*expected), "{command:?}");
    }
}

/// Regression: a dangerous env prefix used to be invisible to the explain path,
/// which short-circuited on the allowlisted command name alone.
#[test]
fn trace_dangerous_env_prefix_is_not_allowed() {
    let output = trace_with_analyzer(&mut trace_test_analyzer(), "LD_PRELOAD=/tmp/x ls").unwrap();
    let verdict = trace_test_analyzer()
        .analyze("LD_PRELOAD=/tmp/x ls")
        .unwrap();
    assert_eq!(output.decision, verdict.decision.as_str());
    assert_ne!(output.decision, "allow");
}

/// Regression for #155: a whole-string allow rule only covers a single plain
/// command, and the explain path must apply the same gate.
#[test]
fn trace_whole_string_allow_does_not_cover_compound() {
    let dir = tempfile::TempDir::new().unwrap();
    let config_path = dir.path().join("allow-ls.toml");
    std::fs::write(
        &config_path,
        "[[rules]]\naction = \"allow\"\npattern = \"ls*\"\n",
    )
    .unwrap();

    let mut analyzer = analyzer_at(dir.path(), &config_path);
    let output = trace_with_analyzer(&mut analyzer, "ls && rm -rf /").unwrap();
    let verdict = analyzer_at(dir.path(), &config_path)
        .analyze("ls && rm -rf /")
        .unwrap();
    assert_eq!(output.decision, verdict.decision.as_str());
    assert_ne!(output.decision, "allow");
}

/// Regression: the explain path used to match rules with a null `MatchContext`,
/// so every conditional rule silently failed to fire.
#[test]
fn trace_evaluates_rule_conditions() {
    let dir = tempfile::TempDir::new().unwrap();
    let config_path = dir.path().join("conditional.toml");
    std::fs::write(
        &config_path,
        "[[rules]]\naction = \"deny\"\npattern = \"ls*\"\nmessage = \"denied here\"\n\n\
         [rules.when.cwd]\nunder = \"/\"\n",
    )
    .unwrap();

    let mut analyzer = analyzer_at(dir.path(), &config_path);
    let output = trace_with_analyzer(&mut analyzer, "ls -la").unwrap();
    assert_eq!(output.decision, "deny");
    assert_eq!(output.reason, "denied here");
}

/// Guards against a future refactor silently dropping the events and leaving
/// `rippy inspect` showing a bare verdict with no explanation.
#[test]
fn trace_records_stage_events() {
    for command in SPREAD {
        let output = trace_with_analyzer(&mut trace_test_analyzer(), command).unwrap();
        assert!(
            output.steps.iter().any(|s| s.stage == "CC permissions"),
            "trace for {command:?} omits the first layer consulted"
        );
        // A whole-string rule decides before the parser runs; everything else
        // must show the parse step.
        let short_circuited = output
            .steps
            .iter()
            .any(|s| s.matched && matches!(s.stage.as_str(), "CC permissions" | "Config rules"));
        assert!(
            short_circuited || output.steps.iter().any(|s| s.stage == "Parse"),
            "no Parse step for {command:?}"
        );
    }
}

/// Regression for the three gates that decided without leaving a trace event:
/// the redirect pipeline, the dangerous/expanding env prefix, and the
/// dynamic-argument allow. Each used to terminate on an affirmative
/// `Allowlist ✓ <cmd> is in the simple-safe list` that contradicted the verdict.
/// Details transcribed from observed `trace_test_analyzer` output.
#[test]
fn trace_records_the_deciding_gate() {
    let cases: &[(&str, &str, &str)] = &[
        (
            "echo x > /etc/passwd",
            "Redirect",
            "ask: redirect to /etc/passwd",
        ),
        ("echo secret > .env", "Redirect", "ask: redirect to .env"),
        (
            "ls | tee /etc/hosts",
            "Redirect",
            "ask: redirect to /etc/hosts",
        ),
        (
            "echo hi > /dev/null",
            "Redirect",
            "allow: redirect to /dev/null",
        ),
        (
            "LD_PRELOAD=/tmp/x ls",
            "Env prefix",
            "ask: LD_PRELOAD is not a known-inert variable",
        ),
        (
            "FOO=$(id) ls",
            "Env prefix",
            "ask: assignment value contains a shell expansion",
        ),
        (
            "for f in *.txt; do cat $f; done",
            "Expansion",
            "allow: cat is safe with a set-but-unknown argument",
        ),
    ];
    for (command, stage, detail) in cases {
        let output = trace_with_analyzer(&mut trace_test_analyzer(), command).unwrap();
        let last = output.steps.last().unwrap();
        assert_eq!(&last.stage, stage, "{command:?} ends on the wrong stage");
        assert_eq!(&last.detail, detail, "{command:?}");
        assert!(
            last.detail.starts_with(&format!("{}: ", output.decision)),
            "{command:?}: deciding step claims {:?} but the verdict is {:?}",
            last.detail,
            output.decision
        );
    }
}

/// A step whose detail opens with a decision word claims that decision.
fn claimed_decision(step: &TraceStep) -> Option<&'static str> {
    ["allow", "ask", "deny"]
        .into_iter()
        .find(|d| step.detail.starts_with(&format!("{d}: ")))
}

/// Every non-approving verdict must be explained by a step, so `rippy inspect`
/// never prints a decision the trace does not account for. "Explains" means a
/// step that claims the reached decision, or a miss at a stage that can decide
/// on its own (a parse failure, an unresolvable expansion, an allowlist/handler
/// miss). The CC- and config-rule misses every command records are deliberately
/// not enough — before the redirect/env/dynamic-arg gates were instrumented,
/// `echo x > /etc/passwd` and `LD_PRELOAD=/tmp/x ls` had nothing else.
#[test]
fn trace_explains_every_non_allow_verdict() {
    const DECIDING_ON_MISS: [&str; 4] = ["Parse", "Expansion", "Allowlist", "Handler"];
    for command in SPREAD {
        let output = trace_with_analyzer(&mut trace_test_analyzer(), command).unwrap();
        if output.decision == "allow" {
            continue;
        }
        assert!(
            output.steps.iter().any(|s| {
                claimed_decision(s) == Some(output.decision.as_str())
                    || (!s.matched && DECIDING_ON_MISS.contains(&s.stage.as_str()))
            }),
            "no step explains the {:?} verdict for {command:?}: {:#?}",
            output.decision,
            output.steps
        );
    }
}
