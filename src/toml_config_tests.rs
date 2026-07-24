use super::*;
use crate::config::Config;

#[test]
fn parse_settings() {
    let toml = r#"
[settings]
default = "deny"
log = "/tmp/rippy.log"
log-full = true
"#;
    let directives = parse_toml_config(toml, Path::new("test.toml")).unwrap();
    let config = Config::from_directives(directives);
    assert_eq!(config.default_action, Some(Decision::Deny));
    assert!(config.log_file.is_some());
    assert!(config.log_full);
}

#[test]
fn auto_mode_defaults_to_defer() {
    let config = Config::from_directives(vec![]);
    assert_eq!(config.auto_mode, crate::verdict::AutoMode::Defer);
}

#[test]
fn parse_auto_mode_ask() {
    let toml = "[settings]\nauto-mode = \"ask\"\n";
    let directives = parse_toml_config(toml, Path::new("test.toml")).unwrap();
    let config = Config::from_directives(directives);
    assert_eq!(config.auto_mode, crate::verdict::AutoMode::Ask);
}

#[test]
fn parse_command_rules() {
    let toml = r#"
[[rules]]
action = "allow"
pattern = "git status"

[[rules]]
action = "deny"
pattern = "rm -rf *"
message = "Use trash instead"
"#;
    let directives = parse_toml_config(toml, Path::new("test.toml")).unwrap();
    assert_eq!(directives.len(), 2);

    let config = Config::from_directives(directives);
    let v = config.match_command("git status", None).unwrap();
    assert_eq!(v.decision, Decision::Allow);

    let v = config.match_command("rm -rf /tmp", None).unwrap();
    assert_eq!(v.decision, Decision::Deny);
    assert_eq!(v.reason, "Use trash instead");
}

#[test]
fn parse_redirect_rules() {
    let toml = r#"
[[rules]]
action = "deny-redirect"
pattern = "**/.env*"
message = "Do not write to env files"
"#;
    let directives = parse_toml_config(toml, Path::new("test.toml")).unwrap();
    let config = Config::from_directives(directives);
    let v = config.match_redirect(".env", None).unwrap();
    assert_eq!(v.decision, Decision::Deny);
    assert_eq!(v.reason, "Do not write to env files");
}

#[test]
fn parse_mcp_rules() {
    let toml = r#"
[[rules]]
action = "allow-mcp"
pattern = "mcp__github__*"
"#;
    let directives = parse_toml_config(toml, Path::new("test.toml")).unwrap();
    let config = Config::from_directives(directives);
    let v = config.match_mcp("mcp__github__create_issue").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn parse_after_rule() {
    let toml = r#"
[[rules]]
action = "after"
pattern = "git commit"
message = "Don't forget to push"
"#;
    let directives = parse_toml_config(toml, Path::new("test.toml")).unwrap();
    let config = Config::from_directives(directives);
    let msg = config.match_after("git commit -m test").unwrap();
    assert_eq!(msg, "Don't forget to push");
}

#[test]
fn after_requires_message() {
    let toml = r#"
[[rules]]
action = "after"
pattern = "git commit"
"#;
    let result = parse_toml_config(toml, Path::new("test.toml"));
    assert!(result.is_err());
}

#[test]
fn unknown_action_errors() {
    let toml = r#"
[[rules]]
action = "yolo"
pattern = "rm -rf /"
"#;
    let result = parse_toml_config(toml, Path::new("test.toml"));
    assert!(result.is_err());
}

#[test]
fn parse_aliases() {
    let toml = r#"
[[aliases]]
source = "~/custom-git"
target = "git"
"#;
    let directives = parse_toml_config(toml, Path::new("test.toml")).unwrap();
    let config = Config::from_directives(directives);
    assert_eq!(config.resolve_alias("~/custom-git"), "git");
}

#[test]
fn when_clause_parsed_into_conditions() {
    let toml = r#"
[[rules]]
action = "ask"
pattern = "docker run *"
message = "Container execution"

[rules.when]
branch = { not = "main" }
"#;
    let directives = parse_toml_config(toml, Path::new("test.toml")).unwrap();
    // Should parse without error and have 1 rule with 1 condition
    assert_eq!(directives.len(), 1);
    match &directives[0] {
        ConfigDirective::Rule(r) => {
            assert_eq!(r.conditions.len(), 1);
        }
        _ => panic!("expected Rule"),
    }
}

#[test]
fn malformed_toml_errors() {
    let result = parse_toml_config("not valid [[[ toml", Path::new("bad.toml"));
    assert!(result.is_err());
}

#[test]
fn roundtrip_rules() {
    let toml_input = r#"
[settings]
default = "ask"

[[rules]]
action = "allow"
pattern = "git status"

[[rules]]
action = "deny"
pattern = "rm -rf *"
message = "Use trash instead"

[[rules]]
action = "deny-redirect"
pattern = "**/.env*"
message = "protected"

[[rules]]
action = "after"
pattern = "git commit"
message = "push please"

[[aliases]]
source = "~/bin/git"
target = "git"
"#;
    let directives = parse_toml_config(toml_input, Path::new("test.toml")).unwrap();
    let serialized = rules_to_toml(&directives);
    let re_parsed = parse_toml_config(&serialized, Path::new("test.toml")).unwrap();

    let config1 = Config::from_directives(directives);
    let config2 = Config::from_directives(re_parsed);

    assert_eq!(
        config1.match_command("git status", None).unwrap().decision,
        config2.match_command("git status", None).unwrap().decision,
    );
    assert_eq!(
        config1.match_command("rm -rf /tmp", None).unwrap().decision,
        config2.match_command("rm -rf /tmp", None).unwrap().decision,
    );
    assert_eq!(config1.default_action, config2.default_action);
    assert_eq!(
        config1.resolve_alias("~/bin/git"),
        config2.resolve_alias("~/bin/git"),
    );
}

#[test]
fn roundtrip_mcp_rules() {
    let toml_input = r#"
[[rules]]
action = "allow-mcp"
pattern = "mcp__github__*"

[[rules]]
action = "deny-mcp"
pattern = "mcp__dangerous__*"
"#;
    let directives = parse_toml_config(toml_input, Path::new("test.toml")).unwrap();
    let serialized = rules_to_toml(&directives);
    let re_parsed = parse_toml_config(&serialized, Path::new("test.toml")).unwrap();

    let config = Config::from_directives(re_parsed);
    assert_eq!(
        config
            .match_mcp("mcp__github__create_issue")
            .unwrap()
            .decision,
        Decision::Allow,
    );
    assert_eq!(
        config.match_mcp("mcp__dangerous__exec").unwrap().decision,
        Decision::Deny,
    );
}

#[test]
fn roundtrip_file_rules() {
    let toml_input = r#"
[[rules]]
action = "deny-read"
pattern = "**/.env*"
message = "no env"

[[rules]]
action = "allow-write"
pattern = "/tmp/**"

[[rules]]
action = "ask-edit"
pattern = "**/vendor/**"
message = "vendor files"
"#;
    let directives = parse_toml_config(toml_input, Path::new("test.toml")).unwrap();
    let serialized = rules_to_toml(&directives);
    let re_parsed = parse_toml_config(&serialized, Path::new("test.toml")).unwrap();

    let config = Config::from_directives(re_parsed);
    assert_eq!(
        config.match_file_read(".env", None).unwrap().decision,
        Decision::Deny,
    );
    assert_eq!(
        config
            .match_file_write("/tmp/out.txt", None)
            .unwrap()
            .decision,
        Decision::Allow,
    );
    assert_eq!(
        config
            .match_file_edit("vendor/pkg/lib.rs", None)
            .unwrap()
            .decision,
        Decision::Ask,
    );
}

#[test]
fn all_action_variants() {
    let toml_input = r#"
[[rules]]
action = "ask"
pattern = "docker *"
message = "confirm container"

[[rules]]
action = "allow-redirect"
pattern = "/tmp/**"

[[rules]]
action = "ask-redirect"
pattern = "/var/**"

[[rules]]
action = "ask-mcp"
pattern = "mcp__unknown__*"
"#;
    let directives = parse_toml_config(toml_input, Path::new("test.toml")).unwrap();
    let config = Config::from_directives(directives);

    let v = config.match_command("docker run -it ubuntu", None).unwrap();
    assert_eq!(v.decision, Decision::Ask);
    assert_eq!(v.reason, "confirm container");

    assert_eq!(
        config
            .match_redirect("/tmp/out.txt", None)
            .unwrap()
            .decision,
        Decision::Allow,
    );
    assert_eq!(
        config
            .match_redirect("/var/log/out", None)
            .unwrap()
            .decision,
        Decision::Ask,
    );
    assert_eq!(
        config.match_mcp("mcp__unknown__tool").unwrap().decision,
        Decision::Ask,
    );
}

#[test]
fn empty_toml_produces_empty_config() {
    let directives = parse_toml_config("", Path::new("test.toml")).unwrap();
    assert!(directives.is_empty());
    let config = Config::from_directives(directives);
    assert!(config.match_command("anything", None).is_none());
}

#[test]
fn log_full_false_not_emitted() {
    let toml = "[settings]\nlog-full = false\n";
    let directives = parse_toml_config(toml, Path::new("test.toml")).unwrap();
    let config = Config::from_directives(directives);
    assert!(!config.log_full);
}

// ── Structured matching TOML tests ─────────────────────────────

const STRUCTURED_DENY_FORCE: &str = "\
[[rules]]\naction = \"deny\"\ncommand = \"git\"\nsubcommand = \"push\"\n\
flags = [\"--force\", \"-f\"]\nmessage = \"No force push\"\n";

#[test]
fn parse_structured_command_with_flags() {
    let directives = parse_toml_config(STRUCTURED_DENY_FORCE, Path::new("t")).unwrap();
    let config = Config::from_directives(directives);
    assert_eq!(
        config
            .match_command("git push --force origin main", None)
            .unwrap()
            .decision,
        Decision::Deny
    );
    assert!(config.match_command("git push origin main", None).is_none());
}

#[test]
fn parse_structured_subcommands_and_no_pattern() {
    let toml = "[[rules]]\naction = \"allow\"\ncommand = \"git\"\n\
                     subcommands = [\"status\", \"log\", \"diff\"]\n";
    let config = Config::from_directives(parse_toml_config(toml, Path::new("t")).unwrap());
    assert!(config.match_command("git status", None).is_some());
    assert!(config.match_command("git log --oneline", None).is_some());
    assert!(config.match_command("git push", None).is_none());

    // No-pattern structured rule (docker)
    let toml2 = "[[rules]]\naction = \"ask\"\ncommand = \"docker\"\nsubcommand = \"run\"\n";
    let config2 = Config::from_directives(parse_toml_config(toml2, Path::new("t")).unwrap());
    assert!(config2.match_command("docker run ubuntu", None).is_some());
    assert!(config2.match_command("docker ps", None).is_none());
}

#[test]
fn structured_rule_round_trips() {
    let directives = parse_toml_config(STRUCTURED_DENY_FORCE, Path::new("t")).unwrap();
    let serialized = rules_to_toml(&directives);
    assert!(serialized.contains("command = \"git\""));
    assert!(serialized.contains("subcommand = \"push\""));
    assert!(serialized.contains("flags = "));
    assert!(!serialized.contains("pattern = ")); // structured-only
}

#[test]
fn rule_with_risk_field_errors() {
    // Regression: the `risk` field was accepted silently (#117). It is now
    // rejected as an unknown field so users don't write no-op configs.
    let toml = r#"
[[rules]]
action = "ask"
pattern = "docker run *"
risk = "high"
message = "Verify the image"
"#;
    let result = parse_toml_config(toml, Path::new("test.toml"));
    assert!(result.is_err(), "risk field should now be rejected");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("risk"),
        "error should mention the rejected field, got: {err_msg}"
    );
}

#[test]
fn rule_with_typo_field_errors() {
    // `deny_unknown_fields` also catches typos in known field names, not
    // just orphaned fields like `risk`. Pins the broader contract.
    let toml = "[[rules]]\nactoin = \"ask\"\npattern = \"git status\"\n";
    let result = parse_toml_config(toml, Path::new("test.toml"));
    assert!(result.is_err(), "typo'd field should be rejected");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("actoin"),
        "error should mention the typo'd field, got: {err_msg}"
    );
}

#[test]
fn rule_without_pattern_or_structured_fails() {
    let toml = "[[rules]]\naction = \"deny\"\nmessage = \"missing\"\n";
    assert!(parse_toml_config(toml, Path::new("t")).is_err());
}

#[test]
fn parse_scopes_safe_table() {
    let toml = "[scopes]\nsafe = [\"/opt/repos\", \"/srv/work\"]\n";
    let directives = parse_toml_config(toml, Path::new("test.toml")).unwrap();
    let config = Config::from_directives(directives);
    assert_eq!(
        config.safe_scopes,
        vec![
            std::path::PathBuf::from("/opt/repos"),
            std::path::PathBuf::from("/srv/work"),
        ]
    );
}

#[test]
fn parse_cd_allowed_dirs_back_compat() {
    let toml = "[cd]\nallowed-dirs = [\"/opt/legacy\"]\n";
    let directives = parse_toml_config(toml, Path::new("test.toml")).unwrap();
    let config = Config::from_directives(directives);
    assert_eq!(
        config.safe_scopes,
        vec![std::path::PathBuf::from("/opt/legacy")]
    );
}

#[test]
fn scopes_and_cd_merge_into_one_list() {
    let toml = "[scopes]\nsafe = [\"/opt/a\"]\n[cd]\nallowed-dirs = [\"/opt/b\"]\n";
    let directives = parse_toml_config(toml, Path::new("test.toml")).unwrap();
    let config = Config::from_directives(directives);
    assert_eq!(
        config.safe_scopes,
        vec![
            std::path::PathBuf::from("/opt/a"),
            std::path::PathBuf::from("/opt/b"),
        ]
    );
}
