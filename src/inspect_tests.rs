use crate::config::RuleTarget;

use super::*;

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

    let output = collect_trace_data("VAR=x echo evil", dir.path(), Some(&config_path)).unwrap();
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
            .any(|s| s.stage == "Normalize env prefix" && s.matched)
    );
}

#[test]
fn trace_env_prefix_pipeline_matches_config_rule() {
    // #133: env prefix on the first command of a pipeline strips correctly.
    let dir = tempfile::TempDir::new().unwrap();
    let config_path = dir.path().join("test.toml");
    std::fs::write(
        &config_path,
        "[[rules]]\naction = \"allow\"\npattern = \"echo hi | cat\"\n",
    )
    .unwrap();

    let output = collect_trace_data("VAR=x echo hi | cat", dir.path(), Some(&config_path)).unwrap();
    assert_eq!(output.decision, "allow");
    assert!(
        output
            .steps
            .iter()
            .any(|s| s.stage == "Config rules" && s.matched)
    );
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
    assert_eq!(output.reason, "could not parse command");
}

#[test]
fn trace_json_output_parses() {
    let output = TraceOutput {
        command: "git status".to_string(),
        decision: "allow".to_string(),
        reason: "git is safe".to_string(),
        resolved: None,
        steps: vec![TraceStep {
            stage: "Allowlist".to_string(),
            matched: true,
            detail: "git is safe".to_string(),
        }],
    };
    let json = serde_json::to_string(&output).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["decision"], "allow");
}
