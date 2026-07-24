use super::*;

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
    let has_package = directives.iter().any(|d| {
        matches!(d, ConfigDirective::Set { key, value }
            if key == "package" && value == "develop")
    });
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

// Safe scope expansion

#[test]
fn expand_scope_expands_leading_tilde() {
    let home = std::path::Path::new("/home/alice");
    let got = expand_scope_path(std::path::Path::new("~/src"), Some(home)).unwrap();
    assert_eq!(got, std::path::PathBuf::from("/home/alice/src"));
}

#[test]
fn expand_scope_bare_tilde_rejected_as_home() {
    // A bare `~` is too broad to trust, so the load path drops it.
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
