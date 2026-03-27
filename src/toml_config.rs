//! TOML-based config parser for `.rippy.toml` files.
//!
//! Parses structured TOML config into `Vec<Rule>` that feeds into the same
//! `Config::from_rules()` path as the legacy line-based parser.

use std::fmt::Write as _;
use std::path::Path;

use serde::Deserialize;

use crate::config::Rule;
use crate::error::RippyError;
use crate::pattern::Pattern;
use crate::verdict::Decision;

// ---------------------------------------------------------------------------
// Deserialization structs
// ---------------------------------------------------------------------------

/// Top-level structure of a `.rippy.toml` file.
#[derive(Debug, Deserialize)]
pub struct TomlConfig {
    pub settings: Option<TomlSettings>,
    #[serde(default)]
    pub rules: Vec<TomlRule>,
    #[serde(default)]
    pub aliases: Vec<TomlAlias>,
}

/// Global settings section.
#[derive(Debug, Deserialize)]
pub struct TomlSettings {
    pub default: Option<String>,
    pub log: Option<String>,
    #[serde(rename = "log-full")]
    pub log_full: Option<bool>,
}

/// A single rule entry from the `[[rules]]` array.
#[derive(Debug, Deserialize)]
pub struct TomlRule {
    pub action: String,
    pub pattern: String,
    pub message: Option<String>,
    /// Risk annotation — stored for future use by `rippy suggest` (#48).
    pub risk: Option<String>,
    /// Condition clause — stored for future use by conditional rules (#46).
    pub when: Option<toml::Value>,
}

/// An alias entry from the `[[aliases]]` array.
#[derive(Debug, Deserialize)]
pub struct TomlAlias {
    pub source: String,
    pub target: String,
}

// ---------------------------------------------------------------------------
// TOML → Vec<Rule> conversion
// ---------------------------------------------------------------------------

/// Parse a TOML config string into a list of rules.
///
/// # Errors
///
/// Returns `RippyError::Config` if the TOML is malformed or contains
/// invalid rule definitions.
pub fn parse_toml_config(content: &str, path: &Path) -> Result<Vec<Rule>, RippyError> {
    let config: TomlConfig = toml::from_str(content).map_err(|e| RippyError::Config {
        path: path.to_owned(),
        line: 0,
        message: e.to_string(),
    })?;

    toml_to_rules(&config).map_err(|msg| RippyError::Config {
        path: path.to_owned(),
        line: 0,
        message: msg,
    })
}

/// Convert parsed TOML structs into the internal `Rule` enum list.
fn toml_to_rules(config: &TomlConfig) -> Result<Vec<Rule>, String> {
    let mut rules = Vec::new();

    if let Some(settings) = &config.settings {
        settings_to_rules(settings, &mut rules);
    }

    for rule in &config.rules {
        rules.push(convert_rule(rule)?);
    }

    for alias in &config.aliases {
        rules.push(Rule::Alias {
            source: alias.source.clone(),
            target: alias.target.clone(),
        });
    }

    Ok(rules)
}

/// Convert settings into `Rule::Set` entries.
fn settings_to_rules(settings: &TomlSettings, rules: &mut Vec<Rule>) {
    if let Some(default) = &settings.default {
        rules.push(Rule::Set {
            key: "default".to_string(),
            value: default.clone(),
        });
    }
    if let Some(log) = &settings.log {
        rules.push(Rule::Set {
            key: "log".to_string(),
            value: log.clone(),
        });
    }
    if settings.log_full == Some(true) {
        rules.push(Rule::Set {
            key: "log-full".to_string(),
            value: String::new(),
        });
    }
}

/// Convert a single TOML rule into the internal `Rule` enum.
fn convert_rule(rule: &TomlRule) -> Result<Rule, String> {
    let pattern = Pattern::new(&rule.pattern);

    match rule.action.as_str() {
        "allow" => Ok(Rule::Command {
            kind: Decision::Allow,
            pattern,
            message: rule.message.clone(),
        }),
        "ask" => Ok(Rule::Command {
            kind: Decision::Ask,
            pattern,
            message: rule.message.clone(),
        }),
        "deny" => Ok(Rule::Command {
            kind: Decision::Deny,
            pattern,
            message: rule.message.clone(),
        }),
        "allow-redirect" => Ok(Rule::Redirect {
            kind: Decision::Allow,
            pattern,
            message: rule.message.clone(),
        }),
        "ask-redirect" => Ok(Rule::Redirect {
            kind: Decision::Ask,
            pattern,
            message: rule.message.clone(),
        }),
        "deny-redirect" => Ok(Rule::Redirect {
            kind: Decision::Deny,
            pattern,
            message: rule.message.clone(),
        }),
        "allow-mcp" => Ok(Rule::Mcp {
            kind: Decision::Allow,
            pattern,
        }),
        "ask-mcp" => Ok(Rule::Mcp {
            kind: Decision::Ask,
            pattern,
        }),
        "deny-mcp" => Ok(Rule::Mcp {
            kind: Decision::Deny,
            pattern,
        }),
        "after" => {
            let message = rule
                .message
                .clone()
                .ok_or("'after' rules require a message field")?;
            Ok(Rule::After { pattern, message })
        }
        other => Err(format!("unknown action: {other}")),
    }
}

// ---------------------------------------------------------------------------
// Vec<Rule> → TOML serialization (for `rippy migrate`)
// ---------------------------------------------------------------------------

/// Serialize a list of rules into TOML format.
#[must_use]
pub fn rules_to_toml(rules: &[Rule]) -> String {
    let mut out = String::new();
    emit_settings(rules, &mut out);
    emit_rules(rules, &mut out);
    emit_aliases(rules, &mut out);
    out
}

fn emit_settings(rules: &[Rule], out: &mut String) {
    let mut has_header = false;
    for rule in rules {
        if let Rule::Set { key, value } = rule {
            if !has_header {
                let _ = writeln!(out, "[settings]");
                has_header = true;
            }
            if key == "log-full" {
                let _ = writeln!(out, "log-full = true");
            } else {
                let _ = writeln!(out, "{key} = {value:?}");
            }
        }
    }
    if has_header {
        out.push('\n');
    }
}

fn emit_rules(rules: &[Rule], out: &mut String) {
    for rule in rules {
        match rule {
            Rule::Command {
                kind,
                pattern,
                message,
            } => emit_rule_entry(out, decision_str(*kind), pattern.raw(), message.as_deref()),
            Rule::Redirect {
                kind,
                pattern,
                message,
            } => {
                let action = format!("{}-redirect", decision_str(*kind));
                emit_rule_entry(out, &action, pattern.raw(), message.as_deref());
            }
            Rule::Mcp { kind, pattern } => {
                let action = format!("{}-mcp", decision_str(*kind));
                emit_rule_entry(out, &action, pattern.raw(), None);
            }
            Rule::After { pattern, message } => {
                emit_rule_entry(out, "after", pattern.raw(), Some(message));
            }
            Rule::Alias { .. } | Rule::Set { .. } => {}
        }
    }
}

fn emit_rule_entry(out: &mut String, action: &str, pattern: &str, message: Option<&str>) {
    let _ = writeln!(out, "[[rules]]");
    let _ = writeln!(out, "action = {action:?}");
    let _ = writeln!(out, "pattern = {pattern:?}");
    if let Some(msg) = message {
        let _ = writeln!(out, "message = {msg:?}");
    }
    out.push('\n');
}

fn emit_aliases(rules: &[Rule], out: &mut String) {
    for rule in rules {
        if let Rule::Alias { source, target } = rule {
            let _ = writeln!(out, "[[aliases]]");
            let _ = writeln!(out, "source = {source:?}");
            let _ = writeln!(out, "target = {target:?}");
            out.push('\n');
        }
    }
}

const fn decision_str(d: Decision) -> &'static str {
    match d {
        Decision::Allow => "allow",
        Decision::Ask => "ask",
        Decision::Deny => "deny",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
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
        let rules = parse_toml_config(toml, Path::new("test.toml")).unwrap();
        let config = Config::from_rules(rules);
        assert_eq!(config.default_action, Some(Decision::Deny));
        assert!(config.log_file.is_some());
        assert!(config.log_full);
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
        let rules = parse_toml_config(toml, Path::new("test.toml")).unwrap();
        assert_eq!(rules.len(), 2);

        let config = Config::from_rules(rules);
        let v = config.match_command("git status").unwrap();
        assert_eq!(v.decision, Decision::Allow);

        let v = config.match_command("rm -rf /tmp").unwrap();
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
        let rules = parse_toml_config(toml, Path::new("test.toml")).unwrap();
        let config = Config::from_rules(rules);
        let v = config.match_redirect(".env").unwrap();
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
        let rules = parse_toml_config(toml, Path::new("test.toml")).unwrap();
        let config = Config::from_rules(rules);
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
        let rules = parse_toml_config(toml, Path::new("test.toml")).unwrap();
        let config = Config::from_rules(rules);
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
        let rules = parse_toml_config(toml, Path::new("test.toml")).unwrap();
        let config = Config::from_rules(rules);
        assert_eq!(config.resolve_alias("~/custom-git"), "git");
    }

    #[test]
    fn risk_and_when_stored_without_error() {
        let toml = r#"
[[rules]]
action = "ask"
pattern = "docker run *"
risk = "high"
message = "Container execution"

[rules.when]
branch = { not = "main" }
"#;
        let rules = parse_toml_config(toml, Path::new("test.toml")).unwrap();
        assert_eq!(rules.len(), 1);
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
        let rules = parse_toml_config(toml_input, Path::new("test.toml")).unwrap();
        let serialized = rules_to_toml(&rules);
        let re_parsed = parse_toml_config(&serialized, Path::new("test.toml")).unwrap();

        let config1 = Config::from_rules(rules);
        let config2 = Config::from_rules(re_parsed);

        // Verify behavior is equivalent.
        assert_eq!(
            config1.match_command("git status").unwrap().decision,
            config2.match_command("git status").unwrap().decision,
        );
        assert_eq!(
            config1.match_command("rm -rf /tmp").unwrap().decision,
            config2.match_command("rm -rf /tmp").unwrap().decision,
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
        let rules = parse_toml_config(toml_input, Path::new("test.toml")).unwrap();
        let serialized = rules_to_toml(&rules);
        let re_parsed = parse_toml_config(&serialized, Path::new("test.toml")).unwrap();

        let config = Config::from_rules(re_parsed);
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
        let rules = parse_toml_config(toml_input, Path::new("test.toml")).unwrap();
        let config = Config::from_rules(rules);

        let v = config.match_command("docker run -it ubuntu").unwrap();
        assert_eq!(v.decision, Decision::Ask);
        assert_eq!(v.reason, "confirm container");

        assert_eq!(
            config.match_redirect("/tmp/out.txt").unwrap().decision,
            Decision::Allow,
        );
        assert_eq!(
            config.match_redirect("/var/log/out").unwrap().decision,
            Decision::Ask,
        );
        assert_eq!(
            config.match_mcp("mcp__unknown__tool").unwrap().decision,
            Decision::Ask,
        );
    }

    #[test]
    fn empty_toml_produces_empty_config() {
        let rules = parse_toml_config("", Path::new("test.toml")).unwrap();
        assert!(rules.is_empty());
        let config = Config::from_rules(rules);
        assert!(config.match_command("anything").is_none());
    }

    #[test]
    fn log_full_false_not_emitted() {
        let toml = "[settings]\nlog-full = false\n";
        let rules = parse_toml_config(toml, Path::new("test.toml")).unwrap();
        let config = Config::from_rules(rules);
        assert!(!config.log_full);
    }
}
