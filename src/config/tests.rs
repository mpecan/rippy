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

#[test]
fn project_broad_allow_detected() {
    let directives = vec![
        ConfigDirective::ProjectBoundary,
        ConfigDirective::Rule(Rule::new(RuleTarget::Command, Decision::Allow, "*")),
        ConfigDirective::ProjectBoundary,
    ];
    let config = Config::from_directives(directives);
    assert!(config.weakening_suffix().contains("allows all commands"));
}

#[test]
fn project_deny_only_no_weakening_notes() {
    let directives = vec![
        ConfigDirective::ProjectBoundary,
        ConfigDirective::Rule(Rule::new(RuleTarget::Command, Decision::Deny, "rm *")),
        ConfigDirective::Set {
            key: "default".to_string(),
            value: "ask".to_string(),
        },
        ConfigDirective::ProjectBoundary,
    ];
    let config = Config::from_directives(directives);
    assert!(config.weakening_suffix().is_empty());
}

#[test]
fn weakening_notes_appended_to_project_allow_verdict() {
    let directives = vec![
        ConfigDirective::ProjectBoundary,
        ConfigDirective::Set {
            key: "default".to_string(),
            value: "allow".to_string(),
        },
        ConfigDirective::Rule(Rule::new(RuleTarget::Command, Decision::Allow, "echo *")),
        ConfigDirective::ProjectBoundary,
    ];
    let config = Config::from_directives(directives);
    let v = config.match_command("echo hello", None).unwrap();
    assert_eq!(v.decision, Decision::Allow);
    assert!(v.reason.contains("NOTE: project config"));
    assert!(v.reason.contains("default action to allow"));
}

#[test]
fn package_setting_loads_develop_rules() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.toml");
    std::fs::write(&config_path, "[settings]\npackage = \"develop\"\n").unwrap();

    let mut directives = Vec::new();
    loader::load_file(&config_path, &mut directives).unwrap();

    // The config should contain a Set directive for package
    let has_package = directives
            .iter()
            .any(|d| matches!(d, ConfigDirective::Set { key, value } if key == "package" && value == "develop"));
    assert!(has_package, "should emit package setting directive");
}

#[test]
fn package_loads_via_config_pipeline() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(home.join(".rippy")).unwrap();
    std::fs::write(
        home.join(".rippy/config.toml"),
        "[settings]\npackage = \"develop\"\n",
    )
    .unwrap();

    let config = Config::load_with_home(dir.path(), None, Some(home)).unwrap();
    assert_eq!(
        config.active_package,
        Some(crate::packages::Package::Develop)
    );
    // Develop package allows cargo test
    let v = config.match_command("cargo test", None);
    assert!(v.is_some(), "develop package should match cargo test");
    assert_eq!(v.unwrap().decision, Decision::Allow);
}

#[test]
fn project_package_overrides_global() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(home.join(".rippy")).unwrap();
    std::fs::write(
        home.join(".rippy/config.toml"),
        "[settings]\npackage = \"develop\"\n",
    )
    .unwrap();

    let project = dir.path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(
        project.join(".rippy.toml"),
        "[settings]\npackage = \"review\"\n",
    )
    .unwrap();

    let config = Config::load_with_home(&project, None, Some(home)).unwrap();
    assert_eq!(
        config.active_package,
        Some(crate::packages::Package::Review)
    );
}

#[test]
fn no_package_setting_backward_compatible() {
    let dir = tempfile::tempdir().unwrap();
    let config = Config::load_with_home(dir.path(), None, None).unwrap();
    assert_eq!(config.active_package, None);
}

#[test]
fn user_rules_override_package_rules() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(home.join(".rippy")).unwrap();
    // develop package allows rm, but user config overrides to deny
    std::fs::write(
        home.join(".rippy/config.toml"),
        "[settings]\npackage = \"develop\"\n\n\
             [[rules]]\naction = \"deny\"\ncommand = \"rm\"\nmessage = \"no rm\"\n",
    )
    .unwrap();

    let config = Config::load_with_home(dir.path(), None, Some(home)).unwrap();
    let v = config.match_command("rm foo", None);
    assert!(v.is_some());
    assert_eq!(v.unwrap().decision, Decision::Deny);
}

#[test]
fn line_based_config_package_setting() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(home.join(".rippy")).unwrap();
    // Line-based format (no .toml extension)
    std::fs::write(home.join(".rippy/config"), "set package develop\n").unwrap();

    let config = Config::load_with_home(dir.path(), None, Some(home)).unwrap();
    assert_eq!(
        config.active_package,
        Some(crate::packages::Package::Develop)
    );
}

#[test]
fn invalid_package_name_produces_none() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(home.join(".rippy")).unwrap();
    std::fs::write(
        home.join(".rippy/config.toml"),
        "[settings]\npackage = \"yolo\"\n",
    )
    .unwrap();

    let config = Config::load_with_home(dir.path(), None, Some(home)).unwrap();
    // Invalid package name is gracefully ignored (with stderr warning)
    assert_eq!(config.active_package, None);
}

#[test]
fn custom_package_loads_via_config_pipeline() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir_all(home.join(".rippy/packages")).unwrap();

    // Custom package extending develop adds a deny rule for `npm publish`.
    std::fs::write(
        home.join(".rippy/packages/team.toml"),
        r#"
[meta]
name = "team"
extends = "develop"

[[rules]]
action = "deny"
pattern = "npm publish"
message = "team policy"
"#,
    )
    .unwrap();

    // Global config activates the custom package.
    std::fs::create_dir_all(home.join(".rippy")).unwrap();
    std::fs::write(
        home.join(".rippy/config.toml"),
        "[settings]\npackage = \"team\"\n",
    )
    .unwrap();

    let config = Config::load_with_home(dir.path(), None, Some(home)).unwrap();

    // Active package is the custom one.
    match &config.active_package {
        Some(crate::packages::Package::Custom(c)) => assert_eq!(c.name, "team"),
        other => panic!("expected Custom(team), got {other:?}"),
    }

    // Inherited from develop:
    let v = config.match_command("cargo test", None);
    assert!(v.is_some());
    assert_eq!(v.unwrap().decision, Decision::Allow);

    // Added by custom team package:
    let v = config.match_command("npm publish", None);
    assert!(v.is_some());
    assert_eq!(v.unwrap().decision, Decision::Deny);
}

// ---------------------------------------------------------------------------
// Safe scope expansion
// ---------------------------------------------------------------------------

#[test]
fn expand_scope_expands_leading_tilde() {
    let home = std::path::Path::new("/home/alice");
    let got = expand_scope_path(std::path::Path::new("~/src"), Some(home)).unwrap();
    assert_eq!(got, std::path::PathBuf::from("/home/alice/src"));
}

#[test]
fn expand_scope_bare_tilde_rejected_as_home() {
    // A bare `~` expands to the home directory itself, which is too broad to
    // trust — the load path drops it (parity with `rippy scope add ~`).
    let home = std::path::Path::new("/home/alice");
    assert!(expand_scope_path(std::path::Path::new("~"), Some(home)).is_none());
}

#[test]
fn expand_scope_home_env_form_rejected() {
    // `$HOME`-style expansion that lands on the home dir is also rejected.
    let home = std::path::Path::new("/home/alice");
    assert!(expand_scope_path(std::path::Path::new("/home/alice/"), Some(home)).is_none());
}

#[test]
fn expand_scope_expands_env_var() {
    // `CARGO_PKG_NAME` is set to "rippy-cli" in the test process environment.
    let got = expand_scope_path(std::path::Path::new("/opt/$CARGO_PKG_NAME/x"), None).unwrap();
    assert_eq!(got, std::path::PathBuf::from("/opt/rippy-cli/x"));
}

#[test]
fn expand_scope_expands_braced_env_var() {
    let got = expand_scope_path(std::path::Path::new("/opt/${CARGO_PKG_NAME}/x"), None).unwrap();
    assert_eq!(got, std::path::PathBuf::from("/opt/rippy-cli/x"));
}

#[test]
fn expand_scope_unknown_braced_env_var_stays_literal() {
    let got = expand_scope_path(
        std::path::Path::new("/opt/${RIPPY_NO_SUCH_VAR_XYZ}/x"),
        None,
    )
    .unwrap();
    assert_eq!(
        got,
        std::path::PathBuf::from("/opt/${RIPPY_NO_SUCH_VAR_XYZ}/x")
    );
}

#[test]
fn expand_scope_normalizes_dotdot() {
    let got = expand_scope_path(std::path::Path::new("/opt/repos/../work"), None).unwrap();
    assert_eq!(got, std::path::PathBuf::from("/opt/work"));
}

#[test]
fn expand_scope_rejects_root() {
    assert!(expand_scope_path(std::path::Path::new("/"), None).is_none());
    // Tilde escaping up to root is rejected too.
    let home = std::path::Path::new("/home");
    assert!(expand_scope_path(std::path::Path::new("~/.."), Some(home)).is_none());
}

#[test]
fn expand_scope_unknown_env_var_stays_literal() {
    // A variable that is (almost certainly) undefined must not expand to empty
    // and thereby collapse the path — it stays literal.
    let got = expand_scope_path(
        std::path::Path::new("/opt/$RIPPY_NO_SUCH_VAR_XYZ/repos"),
        None,
    )
    .unwrap();
    assert_eq!(
        got,
        std::path::PathBuf::from("/opt/$RIPPY_NO_SUCH_VAR_XYZ/repos")
    );
}

#[test]
fn safe_scope_directive_expands_and_populates() {
    let home = std::path::PathBuf::from("/home/bob");
    let config = Config::from_directives_with_home(
        vec![ConfigDirective::SafeScope(std::path::PathBuf::from(
            "~/src/other",
        ))],
        Some(home.as_path()),
    );
    assert_eq!(
        config.safe_scopes,
        vec![std::path::PathBuf::from("/home/bob/src/other")]
    );
}

#[test]
fn safe_scope_root_entry_dropped() {
    let config = Config::from_directives(vec![ConfigDirective::SafeScope(
        std::path::PathBuf::from("/"),
    )]);
    assert!(config.safe_scopes.is_empty());
}

#[test]
fn safe_scope_home_entry_dropped_at_load() {
    // A trusted/hand-edited `[scopes] safe = ["~"]` must not widen auto-approval
    // to the whole home directory — the load path drops it, matching the CLI.
    let home = std::path::PathBuf::from("/home/carol");
    let config = Config::from_directives_with_home(
        vec![
            ConfigDirective::SafeScope(std::path::PathBuf::from("~")),
            ConfigDirective::SafeScope(std::path::PathBuf::from("/home/carol")),
        ],
        Some(home.as_path()),
    );
    assert!(
        config.safe_scopes.is_empty(),
        "home-dir scopes must be dropped, got {:?}",
        config.safe_scopes
    );
}

#[test]
fn project_safe_scope_weakening_note_in_verdict() {
    // A project config declaring a safe scope must disclose that it widens
    // auto-approval — both in the suffix and in an actual allow verdict reason.
    let home = std::path::PathBuf::from("/home/dave");
    let directives = vec![
        ConfigDirective::ProjectBoundary,
        ConfigDirective::SafeScope(std::path::PathBuf::from("/opt/repos")),
        ConfigDirective::Rule(Rule::new(RuleTarget::Command, Decision::Allow, "echo *")),
        ConfigDirective::ProjectBoundary,
    ];
    let config = Config::from_directives_with_home(directives, Some(home.as_path()));
    assert!(config.weakening_suffix().contains("declares safe scope"));
    assert!(config.weakening_suffix().contains("widens auto-approval"));

    let v = config.match_command("echo hi", None).unwrap();
    assert_eq!(v.decision, Decision::Allow);
    assert!(
        v.reason.contains("declares safe scope"),
        "verdict reason must surface the scope disclosure, got: {}",
        v.reason
    );
}
