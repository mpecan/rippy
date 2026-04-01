//! TOML-based config parser for `.rippy.toml` files.
//!
//! Parses structured TOML config into `Vec<ConfigDirective>` that feeds into the same
//! `Config::from_directives()` path as the legacy line-based parser.

use std::fmt::Write as _;
use std::path::Path;

use serde::Deserialize;

use crate::config::{ConfigDirective, Rule, RuleTarget};
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
    pub cd: Option<TomlCd>,
    #[serde(default)]
    pub rules: Vec<TomlRule>,
    #[serde(default)]
    pub aliases: Vec<TomlAlias>,
}

/// Configuration for `cd` directory navigation.
#[derive(Debug, Deserialize)]
pub struct TomlCd {
    /// Additional directories that `cd` is allowed to navigate to.
    #[serde(default, rename = "allowed-dirs")]
    pub allowed_dirs: Vec<String>,
}

/// Global settings section.
#[derive(Debug, Deserialize)]
pub struct TomlSettings {
    pub default: Option<String>,
    pub log: Option<String>,
    #[serde(rename = "log-full")]
    pub log_full: Option<bool>,
    pub tracking: Option<String>,
    #[serde(rename = "self-protect")]
    pub self_protect: Option<bool>,
}

/// A single rule entry from the `[[rules]]` array.
#[derive(Debug, Deserialize)]
pub struct TomlRule {
    pub action: String,
    /// Glob pattern (optional if structured fields are present).
    pub pattern: Option<String>,
    pub message: Option<String>,
    /// Risk annotation — stored for future use by `rippy suggest` (#48).
    pub risk: Option<String>,
    /// Condition clause — parsed into `Condition` list for conditional rules (#46).
    pub when: Option<toml::Value>,
    // Structured matching fields (all optional, combined with AND).
    pub command: Option<String>,
    pub subcommand: Option<String>,
    pub subcommands: Option<Vec<String>>,
    pub flags: Option<Vec<String>>,
    #[serde(rename = "args-contain")]
    pub args_contain: Option<String>,
}

/// An alias entry from the `[[aliases]]` array.
#[derive(Debug, Deserialize)]
pub struct TomlAlias {
    pub source: String,
    pub target: String,
}

// ---------------------------------------------------------------------------
// TOML → Vec<ConfigDirective> conversion
// ---------------------------------------------------------------------------

/// Parse a TOML config string into a list of directives.
///
/// # Errors
///
/// Returns `RippyError::Config` if the TOML is malformed or contains
/// invalid rule definitions.
pub fn parse_toml_config(content: &str, path: &Path) -> Result<Vec<ConfigDirective>, RippyError> {
    let config: TomlConfig = toml::from_str(content).map_err(|e| RippyError::Config {
        path: path.to_owned(),
        line: 0,
        message: e.to_string(),
    })?;

    toml_to_directives(&config).map_err(|msg| RippyError::Config {
        path: path.to_owned(),
        line: 0,
        message: msg,
    })
}

/// Convert parsed TOML structs into the internal directive list.
fn toml_to_directives(config: &TomlConfig) -> Result<Vec<ConfigDirective>, String> {
    let mut directives = Vec::new();

    if let Some(settings) = &config.settings {
        settings_to_directives(settings, &mut directives);
    }

    if let Some(cd) = &config.cd {
        for dir in &cd.allowed_dirs {
            directives.push(ConfigDirective::CdAllow(std::path::PathBuf::from(dir)));
        }
    }

    for rule in &config.rules {
        directives.push(convert_rule(rule)?);
    }

    for alias in &config.aliases {
        directives.push(ConfigDirective::Alias {
            source: alias.source.clone(),
            target: alias.target.clone(),
        });
    }

    Ok(directives)
}

/// Convert settings into `ConfigDirective::Set` entries.
fn settings_to_directives(settings: &TomlSettings, out: &mut Vec<ConfigDirective>) {
    if let Some(default) = &settings.default {
        out.push(ConfigDirective::Set {
            key: "default".to_string(),
            value: default.clone(),
        });
    }
    if let Some(log) = &settings.log {
        out.push(ConfigDirective::Set {
            key: "log".to_string(),
            value: log.clone(),
        });
    }
    if settings.log_full == Some(true) {
        out.push(ConfigDirective::Set {
            key: "log-full".to_string(),
            value: String::new(),
        });
    }
    if let Some(tracking) = &settings.tracking {
        out.push(ConfigDirective::Set {
            key: "tracking".to_string(),
            value: tracking.clone(),
        });
    }
    if settings.self_protect == Some(false) {
        out.push(ConfigDirective::Set {
            key: "self-protect".to_string(),
            value: "off".to_string(),
        });
    }
}

/// Convert a single TOML rule into a `ConfigDirective::Rule`.
fn convert_rule(toml_rule: &TomlRule) -> Result<ConfigDirective, String> {
    let action = toml_rule.action.as_str();
    let (target, decision) = parse_action_to_target(action)?;

    let has_structured = toml_rule.command.is_some()
        || toml_rule.subcommand.is_some()
        || toml_rule.subcommands.is_some()
        || toml_rule.flags.is_some()
        || toml_rule.args_contain.is_some();

    // Pattern is optional when structured fields are present.
    let mut rule = match &toml_rule.pattern {
        Some(p) => Rule::new(target, decision, p),
        None if has_structured => {
            let mut r = Rule::new(target, decision, "*");
            r.pattern = Pattern::any();
            r
        }
        None => return Err("rule must have 'pattern' or structured fields".to_string()),
    };

    if let Some(msg) = &toml_rule.message {
        rule = rule.with_message(msg.clone());
    }

    // After rules require a message.
    if target == RuleTarget::After && rule.message.is_none() {
        return Err("'after' rules require a message field".to_string());
    }

    // Parse conditions from the `when` clause.
    if let Some(when_value) = &toml_rule.when {
        let conditions = crate::condition::parse_conditions(when_value)?;
        rule = rule.with_conditions(conditions);
    }

    // Copy structured fields.
    rule.command.clone_from(&toml_rule.command);
    rule.subcommand.clone_from(&toml_rule.subcommand);
    rule.subcommands.clone_from(&toml_rule.subcommands);
    rule.flags.clone_from(&toml_rule.flags);
    rule.args_contain.clone_from(&toml_rule.args_contain);

    Ok(ConfigDirective::Rule(rule))
}

/// Map an action string (e.g. "deny-redirect") to `(RuleTarget, Decision)`.
fn parse_action_to_target(action: &str) -> Result<(RuleTarget, Decision), String> {
    match action {
        "allow" | "ask" | "deny" => Ok((RuleTarget::Command, parse_decision(action))),
        "after" => Ok((RuleTarget::After, Decision::Allow)),
        _ => parse_compound_action(action),
    }
}

fn parse_compound_action(action: &str) -> Result<(RuleTarget, Decision), String> {
    let suffix = action.rsplit('-').next().unwrap_or("");
    let target = match suffix {
        "redirect" => RuleTarget::Redirect,
        "mcp" => RuleTarget::Mcp,
        "read" => RuleTarget::FileRead,
        "write" => RuleTarget::FileWrite,
        "edit" => RuleTarget::FileEdit,
        _ => return Err(format!("unknown action: {action}")),
    };
    let base = action.split('-').next().unwrap_or("ask");
    Ok((target, parse_decision(base)))
}

fn parse_decision(word: &str) -> Decision {
    match word {
        "allow" => Decision::Allow,
        "deny" => Decision::Deny,
        _ => Decision::Ask,
    }
}

// ---------------------------------------------------------------------------
// Vec<ConfigDirective> → TOML serialization (for `rippy migrate`)
// ---------------------------------------------------------------------------

/// Serialize a list of directives into TOML format.
#[must_use]
pub fn rules_to_toml(directives: &[ConfigDirective]) -> String {
    let mut out = String::new();
    emit_settings(directives, &mut out);
    emit_rules(directives, &mut out);
    emit_aliases(directives, &mut out);
    out
}

fn emit_settings(directives: &[ConfigDirective], out: &mut String) {
    let mut has_header = false;
    for d in directives {
        if let ConfigDirective::Set { key, value } = d {
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

fn emit_rules(directives: &[ConfigDirective], out: &mut String) {
    for d in directives {
        if let ConfigDirective::Rule(rule) = d {
            emit_rule_entry(out, rule);
        }
    }
}

fn emit_rule_entry(out: &mut String, rule: &Rule) {
    let _ = writeln!(out, "[[rules]]");
    let _ = writeln!(out, "action = {:?}", rule.action_str());
    // Only emit pattern if it's not the wildcard placeholder for structured-only rules.
    if !rule.pattern.is_any() || !rule.has_structured_fields() {
        let _ = writeln!(out, "pattern = {:?}", rule.pattern.raw());
    }
    if let Some(cmd) = &rule.command {
        let _ = writeln!(out, "command = {cmd:?}");
    }
    if let Some(sub) = &rule.subcommand {
        let _ = writeln!(out, "subcommand = {sub:?}");
    }
    if let Some(subs) = &rule.subcommands {
        let _ = writeln!(out, "subcommands = {subs:?}");
    }
    if let Some(flags) = &rule.flags {
        let _ = writeln!(out, "flags = {flags:?}");
    }
    if let Some(ac) = &rule.args_contain {
        let _ = writeln!(out, "args-contain = {ac:?}");
    }
    if let Some(msg) = &rule.message {
        let _ = writeln!(out, "message = {msg:?}");
    }
    out.push('\n');
}

fn emit_aliases(directives: &[ConfigDirective], out: &mut String) {
    for d in directives {
        if let ConfigDirective::Alias { source, target } = d {
            let _ = writeln!(out, "[[aliases]]");
            let _ = writeln!(out, "source = {source:?}");
            let _ = writeln!(out, "target = {target:?}");
            out.push('\n');
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
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
        let directives = parse_toml_config(toml, Path::new("test.toml")).unwrap();
        let config = Config::from_directives(directives);
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
risk = "high"
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
    fn rule_without_pattern_or_structured_fails() {
        let toml = "[[rules]]\naction = \"deny\"\nmessage = \"missing\"\n";
        assert!(parse_toml_config(toml, Path::new("t")).is_err());
    }
}
