use super::*;
use crate::condition::Condition;

#[test]
fn last_match_wins() {
    let config = Config::from_directives(vec![
        ConfigDirective::Rule(
            Rule::new(RuleTarget::Command, Decision::Deny, "rm").with_message("blocked"),
        ),
        ConfigDirective::Rule(
            Rule::new(RuleTarget::Command, Decision::Allow, "rm --help")
                .with_message("help is fine"),
        ),
    ]);
    let v = config.match_command("rm --help", None).unwrap();
    assert_eq!(v.decision, Decision::Allow);
    assert_eq!(v.reason, "help is fine");
}

#[test]
fn alias_resolution() {
    let config = Config {
        aliases: vec![("~/custom-git".into(), "git".into())],
        ..Config::default()
    };
    assert_eq!(config.resolve_alias("~/custom-git"), "git");
    assert_eq!(config.resolve_alias("npm"), "npm");
}

#[test]
fn match_redirect_last_wins() {
    let config = Config::from_directives(vec![
        ConfigDirective::Rule(
            Rule::new(RuleTarget::Redirect, Decision::Deny, "/etc/*")
                .with_message("no writes to /etc"),
        ),
        ConfigDirective::Rule(
            Rule::new(RuleTarget::Redirect, Decision::Allow, "/etc/hosts").with_message("hosts ok"),
        ),
    ]);
    let v = config.match_redirect("/etc/hosts", None).unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn settings_extracted() {
    let config = Config::from_directives(vec![
        ConfigDirective::Set {
            key: "default".into(),
            value: "deny".into(),
        },
        ConfigDirective::Set {
            key: "log".into(),
            value: "~/.rippy/audit.log".into(),
        },
        ConfigDirective::Set {
            key: "log-full".into(),
            value: String::new(),
        },
    ]);
    assert_eq!(config.default_action, Some(Decision::Deny));
    assert!(config.log_file.is_some());
    assert!(config.log_full);
}

#[test]
fn match_mcp_rule() {
    let config = Config::from_directives(vec![ConfigDirective::Rule(Rule::new(
        RuleTarget::Mcp,
        Decision::Deny,
        "dangerous*",
    ))]);
    let v = config.match_mcp("dangerous_tool").unwrap();
    assert_eq!(v.decision, Decision::Deny);
    assert!(config.match_mcp("safe_tool").is_none());
}

#[test]
fn match_after_rule() {
    let config = Config::from_directives(vec![ConfigDirective::Rule(
        Rule::new(RuleTarget::After, Decision::Allow, "git commit").with_message("committed!"),
    )]);
    assert_eq!(
        config.match_after("git commit -m foo"),
        Some("committed!".into())
    );
    assert!(config.match_after("ls").is_none());
}

#[test]
fn allow_uv_run_python_c() {
    let config = Config::from_directives(vec![
        ConfigDirective::Rule(
            Rule::new(RuleTarget::Command, Decision::Deny, "python")
                .with_message("Use uv run python"),
        ),
        ConfigDirective::Rule(Rule::new(
            RuleTarget::Command,
            Decision::Allow,
            "uv run python -c",
        )),
    ]);
    let v = config.match_command("python foo.py", None).unwrap();
    assert_eq!(v.decision, Decision::Deny);
    let v = config
        .match_command("uv run python -c 'print(1)'", None)
        .unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn match_file_read_rules() {
    let config = Config::from_directives(vec![
        ConfigDirective::Rule(
            Rule::new(RuleTarget::FileRead, Decision::Deny, "**/.env*").with_message("no env"),
        ),
        ConfigDirective::Rule(Rule::new(RuleTarget::FileRead, Decision::Allow, "/tmp/**")),
    ]);
    let v = config.match_file_read(".env.local", None).unwrap();
    assert_eq!(v.decision, Decision::Deny);
    assert_eq!(v.reason, "no env");

    let v = config.match_file_read("/tmp/safe.txt", None).unwrap();
    assert_eq!(v.decision, Decision::Allow);

    assert!(config.match_file_read("main.rs", None).is_none());
}

#[test]
fn match_file_write_rules() {
    let config = Config::from_directives(vec![ConfigDirective::Rule(
        Rule::new(RuleTarget::FileWrite, Decision::Deny, "**/.rippy*")
            .with_message("config protected"),
    )]);
    let v = config.match_file_write(".rippy.toml", None).unwrap();
    assert_eq!(v.decision, Decision::Deny);
    assert!(config.match_file_write("other.txt", None).is_none());
}

#[test]
fn match_file_edit_rules() {
    let config = Config::from_directives(vec![ConfigDirective::Rule(
        Rule::new(RuleTarget::FileEdit, Decision::Ask, "**/node_modules/**").with_message("vendor"),
    )]);
    let v = config
        .match_file_edit("node_modules/pkg/index.js", None)
        .unwrap();
    assert_eq!(v.decision, Decision::Ask);
    assert!(config.match_file_edit("src/main.rs", None).is_none());
}

#[test]
fn file_rules_last_match_wins() {
    let config = Config::from_directives(vec![
        ConfigDirective::Rule(Rule::new(RuleTarget::FileRead, Decision::Allow, "**")),
        ConfigDirective::Rule(
            Rule::new(RuleTarget::FileRead, Decision::Deny, "**/.env*").with_message("blocked"),
        ),
    ]);
    let v = config.match_file_read(".env", None).unwrap();
    assert_eq!(v.decision, Decision::Deny);
    let v = config.match_file_read("main.rs", None).unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn conditional_rule_skipped_when_condition_fails() {
    let config = Config::from_directives(vec![ConfigDirective::Rule(
        Rule::new(RuleTarget::Command, Decision::Deny, "echo *")
            .with_message("blocked on main")
            .with_conditions(vec![Condition::BranchEq("main".into())]),
    )]);
    let ctx = MatchContext {
        branch: Some("develop"),
        cwd: std::path::Path::new("/tmp"),
    };
    assert!(config.match_command("echo hello", Some(&ctx)).is_none());
}

#[test]
fn conditional_rule_applies_when_condition_passes() {
    let config = Config::from_directives(vec![ConfigDirective::Rule(
        Rule::new(RuleTarget::Command, Decision::Deny, "echo *")
            .with_message("blocked on main")
            .with_conditions(vec![Condition::BranchEq("main".into())]),
    )]);
    let ctx = MatchContext {
        branch: Some("main"),
        cwd: std::path::Path::new("/tmp"),
    };
    let v = config.match_command("echo hello", Some(&ctx)).unwrap();
    assert_eq!(v.decision, Decision::Deny);
    assert_eq!(v.reason, "blocked on main");
}

#[test]
fn conditional_rule_skipped_without_context() {
    let config = Config::from_directives(vec![ConfigDirective::Rule(
        Rule::new(RuleTarget::Command, Decision::Deny, "echo *")
            .with_conditions(vec![Condition::BranchEq("main".into())]),
    )]);
    assert!(config.match_command("echo hello", None).is_none());
}

#[test]
fn structured_rule_in_config() {
    let mut rule = Rule::new(RuleTarget::Command, Decision::Deny, "*");
    rule.pattern = crate::pattern::Pattern::any();
    rule.command = Some("git".into());
    rule.subcommand = Some("push".into());
    let config = Config::from_directives(vec![ConfigDirective::Rule(rule)]);
    let v = config.match_command("git push origin main", None);
    assert!(v.is_some());
    assert_eq!(v.unwrap().decision, Decision::Deny);
    assert!(config.match_command("git status", None).is_none());
}

#[test]
fn structured_rule_with_when_condition() {
    let mut rule = Rule::new(RuleTarget::Command, Decision::Deny, "*");
    rule.pattern = crate::pattern::Pattern::any();
    rule.command = Some("git".into());
    rule.subcommand = Some("push".into());
    let rule = rule.with_conditions(vec![Condition::BranchEq("main".into())]);
    let config = Config::from_directives(vec![ConfigDirective::Rule(rule)]);
    let ctx_main = MatchContext {
        branch: Some("main"),
        cwd: std::path::Path::new("/tmp"),
    };
    let ctx_feat = MatchContext {
        branch: Some("feature"),
        cwd: std::path::Path::new("/tmp"),
    };
    assert!(
        config
            .match_command("git push origin", Some(&ctx_main))
            .is_some()
    );
    assert!(
        config
            .match_command("git push origin", Some(&ctx_feat))
            .is_none()
    );
}

#[test]
fn project_rule_override_annotated() {
    let directives = vec![
        ConfigDirective::Rule(Rule::new(RuleTarget::Command, Decision::Deny, "rm -rf *")),
        ConfigDirective::ProjectBoundary,
        ConfigDirective::Rule(Rule::new(RuleTarget::Command, Decision::Allow, "rm -rf *")),
    ];
    let config = Config::from_directives(directives);
    let v = config.match_command("rm -rf /tmp", None).unwrap();
    assert_eq!(v.decision, Decision::Allow);
    assert!(
        v.reason.contains("overrides deny"),
        "reason should mention override, got: {}",
        v.reason
    );
}

#[test]
fn project_rule_no_override_not_annotated() {
    let directives = vec![
        ConfigDirective::ProjectBoundary,
        ConfigDirective::Rule(Rule::new(RuleTarget::Command, Decision::Allow, "echo *")),
    ];
    let config = Config::from_directives(directives);
    let v = config.match_command("echo hello", None).unwrap();
    assert_eq!(v.decision, Decision::Allow);
    assert!(
        !v.reason.contains("overrides"),
        "no baseline deny → should not mention override, got: {}",
        v.reason
    );
}

#[test]
fn baseline_rule_not_annotated() {
    let directives = vec![
        ConfigDirective::Rule(Rule::new(RuleTarget::Command, Decision::Deny, "rm *")),
        ConfigDirective::ProjectBoundary,
    ];
    let config = Config::from_directives(directives);
    let v = config.match_command("rm -rf /", None).unwrap();
    assert_eq!(v.decision, Decision::Deny);
    assert!(!v.reason.contains("overrides"));
}

#[test]
fn project_ask_overriding_deny_not_annotated() {
    let directives = vec![
        ConfigDirective::Rule(Rule::new(RuleTarget::Command, Decision::Deny, "rm *")),
        ConfigDirective::ProjectBoundary,
        ConfigDirective::Rule(Rule::new(RuleTarget::Command, Decision::Ask, "rm *")),
    ];
    let config = Config::from_directives(directives);
    let v = config.match_command("rm -rf /", None).unwrap();
    assert_eq!(v.decision, Decision::Ask);
    assert!(!v.reason.contains("overrides"));
}

#[test]
fn project_allow_overriding_ask_annotated() {
    let directives = vec![
        ConfigDirective::Rule(Rule::new(
            RuleTarget::Command,
            Decision::Ask,
            "docker run *",
        )),
        ConfigDirective::ProjectBoundary,
        ConfigDirective::Rule(Rule::new(
            RuleTarget::Command,
            Decision::Allow,
            "docker run *",
        )),
    ];
    let config = Config::from_directives(directives);
    let v = config.match_command("docker run nginx", None).unwrap();
    assert_eq!(v.decision, Decision::Allow);
    assert!(v.reason.contains("overrides ask"));
}

#[test]
fn project_rules_range_set_correctly() {
    let directives = vec![
        ConfigDirective::Rule(Rule::new(RuleTarget::Command, Decision::Deny, "a")),
        ConfigDirective::ProjectBoundary,
        ConfigDirective::Rule(Rule::new(RuleTarget::Command, Decision::Allow, "b")),
        ConfigDirective::ProjectBoundary,
        ConfigDirective::Rule(Rule::new(RuleTarget::Command, Decision::Allow, "c")),
    ];
    let config = Config::from_directives(directives);
    assert_eq!(config.project_rules_range, Some(1..2));
}

#[test]
fn env_override_allow_not_annotated_as_project() {
    let directives = vec![
        ConfigDirective::Rule(Rule::new(RuleTarget::Command, Decision::Deny, "rm *")),
        ConfigDirective::ProjectBoundary,
        ConfigDirective::ProjectBoundary,
        ConfigDirective::Rule(Rule::new(RuleTarget::Command, Decision::Allow, "rm *")),
    ];
    let config = Config::from_directives(directives);
    let v = config.match_command("rm -rf /", None).unwrap();
    assert_eq!(v.decision, Decision::Allow);
    assert!(!v.reason.contains("overrides"));
}

#[test]
fn project_default_allow_detected() {
    let directives = vec![
        ConfigDirective::ProjectBoundary,
        ConfigDirective::Set {
            key: "default".to_string(),
            value: "allow".to_string(),
        },
        ConfigDirective::ProjectBoundary,
    ];
    let config = Config::from_directives(directives);
    assert!(
        config
            .weakening_suffix()
            .contains("default action to allow")
    );
}

#[test]
fn project_self_protect_off_detected() {
    let directives = vec![
        ConfigDirective::ProjectBoundary,
        ConfigDirective::Set {
            key: "self-protect".to_string(),
            value: "off".to_string(),
        },
        ConfigDirective::ProjectBoundary,
    ];
    let config = Config::from_directives(directives);
    assert!(config.weakening_suffix().contains("self-protection"));
}
