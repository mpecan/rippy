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
    /// Optional metadata section — used by packages for display purposes,
    /// ignored during directive generation.
    pub meta: Option<TomlMeta>,
    pub settings: Option<TomlSettings>,
    pub cd: Option<TomlCd>,
    pub scopes: Option<TomlScopes>,
    pub git: Option<TomlGit>,
    #[serde(default)]
    pub rules: Vec<TomlRule>,
    #[serde(default)]
    pub aliases: Vec<TomlAlias>,
}

/// Metadata section for packages and config files.
///
/// This is purely informational — it is not converted to config directives.
/// For custom packages, `extends` names a built-in package whose rules are
/// inherited before the custom package's own rules are layered on top.
#[derive(Debug, Deserialize)]
pub struct TomlMeta {
    pub name: Option<String>,
    pub tagline: Option<String>,
    pub shield: Option<String>,
    pub description: Option<String>,
    pub extends: Option<String>,
}

/// Configuration for `cd` directory navigation.
///
/// Legacy back-compat alias for `[scopes] safe`; new configs should prefer
/// `[scopes]`. Both feed the same internal safe-scope list.
#[derive(Debug, Deserialize)]
pub struct TomlCd {
    /// Additional directories that `cd` is allowed to navigate to.
    #[serde(default, rename = "allowed-dirs")]
    pub allowed_dirs: Vec<String>,
}

/// First-class safe-scope configuration (`[scopes] safe = ["~/src"]`).
///
/// Directories the user explicitly trusts for cross-repo work: reads within
/// them are auto-approved, writes still ask.
#[derive(Debug, Deserialize)]
pub struct TomlScopes {
    #[serde(default)]
    pub safe: Vec<String>,
}

/// Git workflow style configuration.
#[derive(Debug, Deserialize)]
pub struct TomlGit {
    /// Default git workflow style for the project.
    pub style: Option<String>,
    /// Branch-specific style overrides.
    #[serde(default)]
    pub branches: Vec<TomlGitBranch>,
}

/// A branch-specific git style override.
#[derive(Debug, Deserialize)]
pub struct TomlGitBranch {
    /// Branch glob pattern (e.g., "agent/*", "main").
    pub pattern: String,
    /// Style name for branches matching this pattern.
    pub style: String,
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
    /// `"defer"` (default) or `"ask"` — how uncertain verdicts behave in
    /// Claude's auto permission modes.
    #[serde(rename = "auto-mode")]
    pub auto_mode: Option<String>,
    /// Whether to auto-trust all project configs without checking the trust DB.
    #[serde(rename = "trust-project-configs")]
    pub trust_project_configs: Option<bool>,
    /// Safety package to activate (e.g., "review", "develop", "autopilot").
    pub package: Option<String>,
}

/// A single rule entry from the `[[rules]]` array.
///
/// `deny_unknown_fields` is set here (and only here among the `Toml*` structs)
/// so typos or stale fields in user rules surface as a clear error instead of
/// being silently ignored — see #117 for the `risk` field regression.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TomlRule {
    pub action: String,
    /// Glob pattern (optional if structured fields are present).
    pub pattern: Option<String>,
    pub message: Option<String>,
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

    // First-class `[scopes] safe` and the legacy `[cd] allowed-dirs` alias both
    // feed the same internal safe-scope list.
    if let Some(scopes) = &config.scopes {
        for dir in &scopes.safe {
            directives.push(ConfigDirective::SafeScope(std::path::PathBuf::from(dir)));
        }
    }
    if let Some(cd) = &config.cd {
        for dir in &cd.allowed_dirs {
            directives.push(ConfigDirective::SafeScope(std::path::PathBuf::from(dir)));
        }
    }

    // Expand git style rules BEFORE user rules so users can override.
    if let Some(git) = &config.git {
        directives.extend(crate::git_styles::expand_git_config(git)?);
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
    if let Some(auto_mode) = &settings.auto_mode {
        out.push(ConfigDirective::Set {
            key: "auto-mode".to_string(),
            value: auto_mode.clone(),
        });
    }
    if settings.self_protect == Some(false) {
        out.push(ConfigDirective::Set {
            key: "self-protect".to_string(),
            value: "off".to_string(),
        });
    }
    if let Some(trust) = settings.trust_project_configs {
        out.push(ConfigDirective::Set {
            key: "trust-project-configs".to_string(),
            value: if trust { "on" } else { "off" }.to_string(),
        });
    }
    if let Some(package) = &settings.package {
        out.push(ConfigDirective::Set {
            key: "package".to_string(),
            value: package.clone(),
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
    emit_scopes(directives, &mut out);
    emit_rules(directives, &mut out);
    emit_aliases(directives, &mut out);
    out
}

/// Emit a `[scopes] safe = [...]` block for any declared safe scopes so
/// `rippy migrate` round-trips legacy `scope` / `cd-allow` directives instead
/// of silently dropping them.
fn emit_scopes(directives: &[ConfigDirective], out: &mut String) {
    let scopes: Vec<String> = directives
        .iter()
        .filter_map(|d| match d {
            ConfigDirective::SafeScope(p) => Some(format!("{:?}", p.display().to_string())),
            _ => None,
        })
        .collect();
    if scopes.is_empty() {
        return;
    }
    let _ = writeln!(out, "[scopes]");
    let _ = writeln!(out, "safe = [{}]", scopes.join(", "));
    out.push('\n');
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
#[path = "toml_config_tests.rs"]
mod tests;
