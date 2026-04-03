use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::condition::{Condition, MatchContext, evaluate_all};
use crate::discover::FlagCache;
use crate::error::RippyError;
use crate::pattern::Pattern;
use crate::verdict::{Decision, Verdict};

/// Lazily loaded flag alias cache for structured matching.
static FLAG_CACHE: OnceLock<FlagCache> = OnceLock::new();

fn flag_cache() -> &'static FlagCache {
    FLAG_CACHE.get_or_init(crate::discover::load_cache)
}

// ---------------------------------------------------------------------------
// New Rule types
// ---------------------------------------------------------------------------

/// What kind of entity a rule targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleTarget {
    Command,
    Redirect,
    Mcp,
    FileRead,
    FileWrite,
    FileEdit,
    After,
}

/// A single rule: target + decision + pattern + optional message + conditions.
///
/// Rules can use glob-pattern matching (the `pattern` field), structured matching
/// (command/subcommand/flags fields), or both. When both are present, all must match (AND).
#[derive(Debug, Clone)]
pub struct Rule {
    pub target: RuleTarget,
    pub decision: Decision,
    pub pattern: Pattern,
    pub message: Option<String>,
    pub conditions: Vec<Condition>,
    // Structured matching fields (all optional, combined with AND).
    pub command: Option<String>,
    pub subcommand: Option<String>,
    pub subcommands: Option<Vec<String>>,
    pub flags: Option<Vec<String>>,
    pub args_contain: Option<String>,
}

impl Rule {
    #[must_use]
    pub fn new(target: RuleTarget, decision: Decision, pattern: &str) -> Self {
        Self {
            target,
            decision,
            pattern: Pattern::new(pattern),
            message: None,
            conditions: vec![],
            command: None,
            subcommand: None,
            subcommands: None,
            flags: None,
            args_contain: None,
        }
    }

    #[must_use]
    pub fn with_message(mut self, msg: impl Into<String>) -> Self {
        self.message = Some(msg.into());
        self
    }

    #[must_use]
    pub fn with_conditions(mut self, c: Vec<Condition>) -> Self {
        self.conditions = c;
        self
    }

    /// Format structured fields as a human-readable description.
    #[must_use]
    pub fn structured_description(&self) -> String {
        let mut parts = Vec::new();
        if let Some(c) = &self.command {
            parts.push(format!("command={c}"));
        }
        if let Some(s) = &self.subcommand {
            parts.push(format!("subcommand={s}"));
        }
        if let Some(list) = &self.subcommands {
            parts.push(format!("subcommands=[{}]", list.join(",")));
        }
        if let Some(f) = &self.flags {
            parts.push(format!("flags=[{}]", f.join(",")));
        }
        if let Some(a) = &self.args_contain {
            parts.push(format!("args-contain={a}"));
        }
        parts.join(" ")
    }

    /// Returns `true` if this rule has any structured matching fields set.
    #[must_use]
    pub const fn has_structured_fields(&self) -> bool {
        self.command.is_some()
            || self.subcommand.is_some()
            || self.subcommands.is_some()
            || self.flags.is_some()
            || self.args_contain.is_some()
    }

    /// Return the action string for this rule (e.g. "allow", "deny-redirect", "ask-read").
    #[must_use]
    pub fn action_str(&self) -> String {
        let base = self.decision.as_str();
        match self.target {
            RuleTarget::Command => base.to_string(),
            RuleTarget::Redirect => format!("{base}-redirect"),
            RuleTarget::Mcp => format!("{base}-mcp"),
            RuleTarget::FileRead => format!("{base}-read"),
            RuleTarget::FileWrite => format!("{base}-write"),
            RuleTarget::FileEdit => format!("{base}-edit"),
            RuleTarget::After => "after".to_string(),
        }
    }
}

/// A parsed config directive — either a Rule, a Set key/value, or an Alias.
#[derive(Debug, Clone)]
pub enum ConfigDirective {
    Rule(Rule),
    Set {
        key: String,
        value: String,
    },
    Alias {
        source: String,
        target: String,
    },
    CdAllow(PathBuf),
    /// Marker separating baseline (stdlib + global) from project rules.
    ProjectBoundary,
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Loaded and merged configuration with rules partitioned by type.
#[derive(Debug, Clone, Default)]
pub struct Config {
    rules: Vec<Rule>,
    after_rules: Vec<(Pattern, String)>,
    pub default_action: Option<Decision>,
    pub log_file: Option<PathBuf>,
    pub log_full: bool,
    pub tracking_db: Option<PathBuf>,
    pub self_protect: bool,
    /// Whether to auto-trust all project configs without checking the trust DB.
    pub trust_project_configs: bool,
    aliases: Vec<(String, String)>,
    /// Extra directories that `cd` is allowed to navigate to (beyond the project root).
    pub cd_allowed_dirs: Vec<PathBuf>,
    /// Index range in `rules` containing project-config rules.
    /// `None` when no project config was loaded. Rules outside this range
    /// are baseline (stdlib + global) or env override.
    project_rules_range: Option<std::ops::Range<usize>>,
    /// Pre-formatted suffix appended to verdict reasons when project allow rules fire.
    /// Empty string when the project config doesn't weaken protections.
    project_weakening_suffix: String,
}

impl Config {
    /// Load config from the three-tier system: global, project, env override.
    ///
    /// # Errors
    ///
    /// Returns `RippyError::Config` if a config file exists but contains invalid syntax.
    pub fn load(cwd: &Path, env_config: Option<&Path>) -> Result<Self, RippyError> {
        // Stdlib first (lowest priority — user config overrides via last-match-wins).
        let mut directives = crate::stdlib::stdlib_directives()?;

        if let Some(home) = home_dir() {
            load_first_existing(
                &[
                    home.join(".rippy/config.toml"),
                    home.join(".rippy/config"),
                    home.join(".dippy/config"),
                ],
                &mut directives,
            )?;
        }

        directives.push(ConfigDirective::ProjectBoundary);

        if let Some(project_config) = find_project_config(cwd) {
            let trust_all = has_trust_setting(&directives);
            load_project_config_if_trusted(&project_config, trust_all, &mut directives)?;
        }

        directives.push(ConfigDirective::ProjectBoundary);

        if let Some(env_path) = env_config {
            load_file(env_path, &mut directives)?;
        }

        Ok(Self::from_directives(directives))
    }

    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Return the pre-formatted weakening suffix for verdict annotation.
    #[must_use]
    pub fn weakening_suffix(&self) -> &str {
        &self.project_weakening_suffix
    }

    /// Match a command string against command rules (last-match-wins).
    #[must_use]
    pub fn match_command(&self, command: &str, ctx: Option<&MatchContext>) -> Option<Verdict> {
        self.match_rules(RuleTarget::Command, command, "matched rule", ctx)
    }

    /// Match a redirect target path against redirect rules.
    #[must_use]
    pub fn match_redirect(&self, path: &str, ctx: Option<&MatchContext>) -> Option<Verdict> {
        self.match_rules(RuleTarget::Redirect, path, "redirect rule", ctx)
    }

    /// Match an MCP tool name against MCP rules.
    #[must_use]
    pub fn match_mcp(&self, tool_name: &str) -> Option<Verdict> {
        self.match_rules(RuleTarget::Mcp, tool_name, "MCP rule", None)
    }

    /// Match a file path against file-read rules.
    #[must_use]
    pub fn match_file_read(&self, path: &str, ctx: Option<&MatchContext>) -> Option<Verdict> {
        self.match_rules(RuleTarget::FileRead, path, "file-read rule", ctx)
    }

    /// Match a file path against file-write rules.
    #[must_use]
    pub fn match_file_write(&self, path: &str, ctx: Option<&MatchContext>) -> Option<Verdict> {
        self.match_rules(RuleTarget::FileWrite, path, "file-write rule", ctx)
    }

    /// Match a file path against file-edit rules.
    #[must_use]
    pub fn match_file_edit(&self, path: &str, ctx: Option<&MatchContext>) -> Option<Verdict> {
        self.match_rules(RuleTarget::FileEdit, path, "file-edit rule", ctx)
    }

    /// Match a command for `after` rules (post-execution feedback).
    #[must_use]
    pub fn match_after(&self, command: &str) -> Option<String> {
        let mut result = None;
        for (pattern, message) in &self.after_rules {
            if pattern.matches(command) {
                result = Some(message.clone());
            }
        }
        result
    }

    /// Resolve aliases for a command name. Returns the target if aliased.
    #[must_use]
    pub fn resolve_alias<'a>(&'a self, command: &'a str) -> &'a str {
        for (source, target) in &self.aliases {
            if command == source
                || command
                    .strip_prefix(source.as_str())
                    .is_some_and(|rest| rest.starts_with('/'))
            {
                return target;
            }
        }
        command
    }

    /// Shared matching logic for all rule targets (last-match-wins).
    ///
    /// Supports both glob-pattern and structured matching. For structured rules,
    /// the input is parsed into command name + args on demand.
    fn match_rules(
        &self,
        target: RuleTarget,
        input: &str,
        label: &str,
        ctx: Option<&MatchContext>,
    ) -> Option<Verdict> {
        let mut result = None;
        let mut baseline_decision: Option<Decision> = None;
        let project_range = self.project_rules_range.as_ref();

        for (i, rule) in self.rules.iter().enumerate() {
            if rule.target != target {
                continue;
            }
            if !rule.pattern.matches(input) {
                continue;
            }
            if rule.has_structured_fields() && !matches_structured(rule, input) {
                continue;
            }
            if !rule.conditions.is_empty() {
                match ctx {
                    Some(c) if evaluate_all(&rule.conditions, c) => {}
                    _ => continue,
                }
            }

            let is_project_rule = project_range.is_some_and(|r| r.contains(&i));
            if !is_project_rule {
                baseline_decision = Some(rule.decision);
            }

            let mut reason = if is_project_rule
                && rule.decision == Decision::Allow
                && baseline_decision.is_some_and(|d| d != Decision::Allow)
            {
                let overridden = baseline_decision.map_or("ask", Decision::as_str);
                format!(
                    "matched project rule (overrides {overridden}: {})",
                    rule.pattern.raw()
                )
            } else {
                rule.message
                    .as_deref()
                    .map_or_else(|| format_rule_reason(rule, label), String::from)
            };

            if is_project_rule && rule.decision == Decision::Allow {
                reason.push_str(&self.project_weakening_suffix);
            }

            result = Some(Verdict {
                decision: rule.decision,
                reason,
            });
        }
        result
    }

    /// Build a `Config` from a list of directives.
    pub fn from_directives(directives: Vec<ConfigDirective>) -> Self {
        let mut config = Self {
            self_protect: true,
            ..Self::default()
        };
        let mut in_project_section = false;
        let mut project_start: Option<usize> = None;
        let mut weakening_notes: Vec<String> = Vec::new();

        for directive in directives {
            match directive {
                ConfigDirective::Rule(r) => {
                    if r.target == RuleTarget::After {
                        if let Some(msg) = &r.message {
                            config.after_rules.push((r.pattern, msg.clone()));
                        }
                    } else {
                        if in_project_section {
                            detect_broad_allow(&r, &mut weakening_notes);
                        }
                        config.rules.push(r);
                    }
                }
                ConfigDirective::Set { key, value } => {
                    if in_project_section {
                        detect_dangerous_setting(&key, &value, &mut weakening_notes);
                    }
                    apply_setting(&mut config, &key, &value);
                }
                ConfigDirective::Alias { source, target } => {
                    config.aliases.push((source, target));
                }
                ConfigDirective::ProjectBoundary => {
                    if in_project_section {
                        if let Some(start) = project_start {
                            config.project_rules_range = Some(start..config.rules.len());
                        }
                        in_project_section = false;
                    } else {
                        project_start = Some(config.rules.len());
                        in_project_section = true;
                    }
                }
                ConfigDirective::CdAllow(path) => {
                    config.cd_allowed_dirs.push(normalize_path(&path));
                }
            }
        }

        if in_project_section && project_start.is_some() {
            config.project_rules_range = project_start.map(|start| start..config.rules.len());
        }

        config.project_weakening_suffix = build_weakening_suffix(&weakening_notes);
        config
    }
}

/// Normalize a path by removing `.` and resolving `..` components.
fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for c in path.components() {
        match c {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other),
        }
    }
    normalized
}

fn apply_setting(config: &mut Config, key: &str, value: &str) {
    match key {
        "default" => config.default_action = parse_action_word(value),
        "log" => config.log_file = Some(PathBuf::from(value)),
        "log-full" => config.log_full = true,
        "tracking" => {
            config.tracking_db = Some(if value == "on" || value.is_empty() {
                home_dir().map_or_else(
                    || PathBuf::from(".rippy/tracking.db"),
                    |h| h.join(".rippy/tracking.db"),
                )
            } else {
                PathBuf::from(value)
            });
        }
        "trust-project-configs" => {
            config.trust_project_configs = value != "off" && value != "false";
        }
        "self-protect" => {
            config.self_protect = value != "off";
        }
        _ => {}
    }
}

/// Detect dangerous settings in project config directives.
fn detect_dangerous_setting(key: &str, value: &str, notes: &mut Vec<String>) {
    if key == "default" && value == "allow" {
        notes.push("sets default action to allow (all unknown commands auto-approved)".to_string());
    }
    if key == "self-protect" && value == "off" {
        notes.push("disables self-protection (AI tools can modify rippy config)".to_string());
    }
}

/// Detect overly broad allow rules in project config directives.
fn detect_broad_allow(rule: &Rule, notes: &mut Vec<String>) {
    if rule.decision != Decision::Allow {
        return;
    }
    let raw = rule.pattern.raw();
    if raw == "*" || raw == "**" || raw == "*|" {
        notes.push(format!("allows all commands with pattern \"{raw}\""));
    }
}

/// Pre-format the weakening notes into a suffix string for verdict annotation.
///
/// Returns an empty string if there are no notes.
pub(crate) fn build_weakening_suffix(notes: &[String]) -> String {
    if notes.is_empty() {
        return String::new();
    }
    let mut suffix = String::from(" | NOTE: project config ");
    for (i, note) in notes.iter().enumerate() {
        if i > 0 {
            suffix.push_str(", ");
        }
        suffix.push_str(note);
    }
    suffix
}

// ---------------------------------------------------------------------------
// File loading
// ---------------------------------------------------------------------------

/// Load the first file that exists from a list of candidates.
fn load_first_existing(
    paths: &[PathBuf],
    directives: &mut Vec<ConfigDirective>,
) -> Result<(), RippyError> {
    for path in paths {
        if path.is_file() {
            return load_file(path, directives);
        }
    }
    Ok(())
}

/// Parse a single config file and append directives to the list.
pub(crate) fn load_file(
    path: &Path,
    directives: &mut Vec<ConfigDirective>,
) -> Result<(), RippyError> {
    let content = std::fs::read_to_string(path).map_err(|e| RippyError::Config {
        path: path.to_owned(),
        line: 0,
        message: format!("could not read: {e}"),
    })?;

    load_file_from_content(&content, path, directives)
}

/// Parse config content (already read from disk) and append directives.
pub(crate) fn load_file_from_content(
    content: &str,
    path: &Path,
    directives: &mut Vec<ConfigDirective>,
) -> Result<(), RippyError> {
    if path.extension().is_some_and(|ext| ext == "toml") {
        let parsed = crate::toml_config::parse_toml_config(content, path)?;
        directives.extend(parsed);
        return Ok(());
    }

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let directive = parse_rule(line).map_err(|msg| RippyError::Config {
            path: path.to_owned(),
            line: line_num + 1,
            message: msg,
        })?;
        directives.push(directive);
    }

    Ok(())
}

/// Check whether already-loaded directives contain `trust-project-configs = on/true`.
fn has_trust_setting(directives: &[ConfigDirective]) -> bool {
    directives.iter().rev().any(|d| {
        matches!(
            d,
            ConfigDirective::Set { key, value }
            if key == "trust-project-configs"
                && value != "off"
                && value != "false"
        )
    })
}

/// Load a project config file only if it is trusted.
///
/// If `trust_all` is true (from `trust-project-configs = on` in global config),
/// the file is loaded unconditionally. Otherwise, the trust database is consulted
/// and untrusted/modified configs are skipped with a stderr warning.
fn load_project_config_if_trusted(
    path: &Path,
    trust_all: bool,
    directives: &mut Vec<ConfigDirective>,
) -> Result<(), RippyError> {
    let content = std::fs::read_to_string(path).map_err(|e| RippyError::Config {
        path: path.to_owned(),
        line: 0,
        message: format!("could not read: {e}"),
    })?;

    if trust_all {
        return load_file_from_content(&content, path, directives);
    }

    let db = crate::trust::TrustDb::load();
    match db.check(path, &content) {
        crate::trust::TrustStatus::Trusted => load_file_from_content(&content, path, directives),
        crate::trust::TrustStatus::Untrusted => {
            eprintln!(
                "[rippy] untrusted project config: {} — run `rippy trust` to review and enable",
                path.display()
            );
            Ok(())
        }
        crate::trust::TrustStatus::Modified { .. } => {
            eprintln!(
                "[rippy] project config modified since last trust: {} — \
                 run `rippy trust` to re-approve",
                path.display()
            );
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Legacy line parser
// ---------------------------------------------------------------------------

/// A token from a config line, tagged as quoted or unquoted.
#[derive(Debug)]
enum Token {
    Bare(String),
    Quoted(String),
}

/// Tokenize a config line, respecting quoted strings.
/// Returns tagged tokens so callers can distinguish patterns from messages.
fn tokenize_config_line(line: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = line.chars().peekable();

    while let Some(&ch) = chars.peek() {
        if ch.is_whitespace() {
            chars.next();
            continue;
        }
        if ch == '"' {
            chars.next();
            let mut s = String::new();
            loop {
                match chars.next() {
                    None | Some('"') => break,
                    Some('\\') => {
                        if let Some(escaped) = chars.next() {
                            s.push(escaped);
                        }
                    }
                    Some(c) => s.push(c),
                }
            }
            tokens.push(Token::Quoted(s));
        } else {
            let mut s = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() {
                    break;
                }
                s.push(c);
                chars.next();
            }
            tokens.push(Token::Bare(s));
        }
    }
    tokens
}

/// From a token list (after the keyword), extract the pattern (all bare tokens
/// joined by spaces) and the optional message (first quoted token).
fn extract_pattern_and_message(tokens: &[Token]) -> (String, Option<String>) {
    let mut bare_parts = Vec::new();
    let mut message = None;
    for token in tokens {
        match token {
            Token::Bare(s) => bare_parts.push(s.as_str()),
            Token::Quoted(s) => {
                if message.is_none() {
                    message = Some(s.clone());
                }
            }
        }
    }
    (bare_parts.join(" "), message)
}

/// Parse a single config line into a `ConfigDirective`.
///
/// # Errors
///
/// Returns an error string if the line contains an unknown directive or
/// invalid syntax.
pub fn parse_rule(line: &str) -> Result<ConfigDirective, String> {
    let tokens = tokenize_config_line(line);
    let keyword = match tokens.first() {
        Some(Token::Bare(k)) => k.as_str(),
        Some(Token::Quoted(_)) => return Err("directive cannot be quoted".into()),
        None => return Err("empty rule".into()),
    };
    let rest = &tokens[1..];

    match keyword {
        "allow" | "ask" | "deny" => parse_command_rule(keyword, rest),
        "allow-redirect" | "ask-redirect" | "deny-redirect" => parse_redirect_rule(keyword, rest),
        "after" => parse_after_rule(rest),
        "allow-mcp" | "ask-mcp" | "deny-mcp" => parse_mcp_rule(keyword, rest),
        "allow-read" | "ask-read" | "deny-read" => parse_file_rule(keyword, rest, "read"),
        "allow-write" | "ask-write" | "deny-write" => parse_file_rule(keyword, rest, "write"),
        "allow-edit" | "ask-edit" | "deny-edit" => parse_file_rule(keyword, rest, "edit"),
        "set" => parse_set_directive(rest),
        "alias" => parse_alias_directive(rest),
        "cd-allow" => parse_cd_allow_directive(rest),
        _ => Err(format!("unknown directive: {keyword}")),
    }
}

fn parse_command_rule(keyword: &str, rest: &[Token]) -> Result<ConfigDirective, String> {
    let (pattern_str, message) = extract_pattern_and_message(rest);
    if pattern_str.is_empty() {
        return Err(format!("{keyword} requires a pattern"));
    }
    let mut rule = Rule::new(RuleTarget::Command, parse_rule_kind(keyword), &pattern_str);
    if let Some(msg) = message {
        rule = rule.with_message(msg);
    }
    Ok(ConfigDirective::Rule(rule))
}

fn parse_redirect_rule(keyword: &str, rest: &[Token]) -> Result<ConfigDirective, String> {
    let (pattern_str, message) = extract_pattern_and_message(rest);
    if pattern_str.is_empty() {
        return Err(format!("{keyword} requires a path pattern"));
    }
    let base_kind = keyword.split('-').next().unwrap_or("ask");
    let mut rule = Rule::new(
        RuleTarget::Redirect,
        parse_rule_kind(base_kind),
        &pattern_str,
    );
    if let Some(msg) = message {
        rule = rule.with_message(msg);
    }
    Ok(ConfigDirective::Rule(rule))
}

fn parse_after_rule(rest: &[Token]) -> Result<ConfigDirective, String> {
    let (pattern_str, message) = extract_pattern_and_message(rest);
    let message = message.ok_or("after requires a pattern and quoted message")?;
    if pattern_str.is_empty() {
        return Err("after requires a pattern".into());
    }
    let rule = Rule::new(RuleTarget::After, Decision::Allow, &pattern_str).with_message(message);
    Ok(ConfigDirective::Rule(rule))
}

fn parse_mcp_rule(keyword: &str, rest: &[Token]) -> Result<ConfigDirective, String> {
    let (pattern_str, _) = extract_pattern_and_message(rest);
    if pattern_str.is_empty() {
        return Err(format!("{keyword} requires a tool pattern"));
    }
    let base_kind = keyword.split('-').next().unwrap_or("ask");
    let rule = Rule::new(RuleTarget::Mcp, parse_rule_kind(base_kind), &pattern_str);
    Ok(ConfigDirective::Rule(rule))
}

fn parse_file_rule(keyword: &str, rest: &[Token], op: &str) -> Result<ConfigDirective, String> {
    let (pattern_str, message) = extract_pattern_and_message(rest);
    if pattern_str.is_empty() {
        return Err(format!("{keyword} requires a file path pattern"));
    }
    let base_kind = keyword.split('-').next().unwrap_or("ask");
    let target = match op {
        "read" => RuleTarget::FileRead,
        "write" => RuleTarget::FileWrite,
        "edit" => RuleTarget::FileEdit,
        _ => return Err(format!("unknown file operation: {op}")),
    };
    let mut rule = Rule::new(target, parse_rule_kind(base_kind), &pattern_str);
    if let Some(msg) = message {
        rule = rule.with_message(msg);
    }
    Ok(ConfigDirective::Rule(rule))
}

fn parse_set_directive(rest: &[Token]) -> Result<ConfigDirective, String> {
    let bare: Vec<&str> = rest
        .iter()
        .filter_map(|t| match t {
            Token::Bare(s) => Some(s.as_str()),
            Token::Quoted(_) => None,
        })
        .collect();
    if bare.is_empty() {
        return Err("set requires a key".into());
    }
    Ok(ConfigDirective::Set {
        key: bare[0].to_owned(),
        value: bare.get(1).copied().unwrap_or_default().to_owned(),
    })
}

fn parse_alias_directive(rest: &[Token]) -> Result<ConfigDirective, String> {
    let bare: Vec<&str> = rest
        .iter()
        .filter_map(|t| match t {
            Token::Bare(s) => Some(s.as_str()),
            Token::Quoted(_) => None,
        })
        .collect();
    if bare.len() < 2 {
        return Err("alias requires source and target".into());
    }
    Ok(ConfigDirective::Alias {
        source: bare[0].to_owned(),
        target: bare[1].to_owned(),
    })
}

fn parse_cd_allow_directive(rest: &[Token]) -> Result<ConfigDirective, String> {
    let (path_str, _) = extract_pattern_and_message(rest);
    if path_str.is_empty() {
        return Err("cd-allow requires a directory path".into());
    }
    Ok(ConfigDirective::CdAllow(PathBuf::from(path_str)))
}

fn parse_rule_kind(word: &str) -> Decision {
    match word {
        "allow" => Decision::Allow,
        "deny" => Decision::Deny,
        _ => Decision::Ask,
    }
}

fn parse_action_word(word: &str) -> Option<Decision> {
    match word {
        "allow" => Some(Decision::Allow),
        "ask" => Some(Decision::Ask),
        "deny" => Some(Decision::Deny),
        _ => None,
    }
}

/// Walk up from `start` looking for `.rippy` or `.dippy` config files.
pub fn find_project_config(start: &Path) -> Option<PathBuf> {
    let mut dir = start;
    loop {
        let toml = dir.join(".rippy.toml");
        if toml.is_file() {
            return Some(toml);
        }
        let rippy = dir.join(".rippy");
        if rippy.is_file() {
            return Some(rippy);
        }
        let dippy = dir.join(".dippy");
        if dippy.is_file() {
            return Some(dippy);
        }
        dir = dir.parent()?;
    }
}

/// Check structured rule fields against the parsed command tokens.
///
/// All present fields must match (AND logic). Returns `true` if every
/// field that is `Some` matches the given input.
fn matches_structured(rule: &Rule, input: &str) -> bool {
    let mut tokens = input.split_whitespace();
    let Some(cmd_name) = tokens.next() else {
        return false;
    };
    let args: Vec<&str> = tokens.collect();

    if let Some(expected) = &rule.command
        && cmd_name != expected.as_str()
    {
        return false;
    }

    let first_positional = args.iter().find(|a| !a.starts_with('-')).copied();

    if let Some(expected) = &rule.subcommand
        && first_positional != Some(expected.as_str())
    {
        return false;
    }

    if let Some(list) = &rule.subcommands {
        match first_positional {
            Some(sub) if list.iter().any(|s| s == sub) => {}
            _ => return false,
        }
    }

    if let Some(required_flags) = &rule.flags {
        // Expand flags with aliases from discovery cache.
        let cache_key = rule.command.as_ref().map(|cmd| {
            rule.subcommand
                .as_ref()
                .map_or_else(|| cmd.clone(), |sub| format!("{cmd} {sub}"))
        });
        let expanded =
            crate::discover::expand_flags(required_flags, flag_cache(), cache_key.as_deref());
        if !has_required_flag(&args, &expanded) {
            return false;
        }
    }

    if let Some(needle) = &rule.args_contain
        && !args.iter().any(|a| a.contains(needle.as_str()))
    {
        return false;
    }

    true
}

/// Check if any required flag matches any arg, handling combined short flags.
fn has_required_flag(args: &[&str], required_flags: &[String]) -> bool {
    for arg in args {
        // Direct match (e.g. "--force" == "--force", "-f" == "-f").
        if required_flags.iter().any(|f| f == arg) {
            return true;
        }
        // Combined short flag expansion: "-fv" contains "-f" and "-v".
        if arg.starts_with('-')
            && !arg.starts_with("--")
            && arg.len() > 2
            && arg.as_bytes().iter().skip(1).all(u8::is_ascii_alphabetic)
        {
            for ch in arg.chars().skip(1) {
                let short = format!("-{ch}");
                if required_flags.iter().any(|f| f == &short) {
                    return true;
                }
            }
        }
    }
    false
}

/// Format a human-readable reason for a matched rule.
fn format_rule_reason(rule: &Rule, label: &str) -> String {
    if rule.has_structured_fields() {
        format!("{label}: {}", rule.structured_description())
    } else {
        format!("{label}: {}", rule.pattern.as_str())
    }
}

pub(crate) fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parse_allow_rule() {
        let d = parse_rule("allow git status").unwrap();
        match d {
            ConfigDirective::Rule(r) => {
                assert_eq!(r.target, RuleTarget::Command);
                assert_eq!(r.decision, Decision::Allow);
                assert_eq!(r.pattern.as_str(), "git status");
                assert!(r.message.is_none());
            }
            _ => panic!("expected Rule"),
        }
    }

    #[test]
    fn parse_deny_with_message() {
        let d = parse_rule(r#"deny python "Use uv run python""#).unwrap();
        match d {
            ConfigDirective::Rule(r) => {
                assert_eq!(r.target, RuleTarget::Command);
                assert_eq!(r.decision, Decision::Deny);
                assert_eq!(r.pattern.as_str(), "python");
                assert_eq!(r.message.as_deref(), Some("Use uv run python"));
            }
            _ => panic!("expected Rule"),
        }
    }

    #[test]
    fn parse_deny_multi_word_pattern_with_message() {
        let d = parse_rule(r#"deny rm -rf "use trash instead""#).unwrap();
        match d {
            ConfigDirective::Rule(r) => {
                assert_eq!(r.target, RuleTarget::Command);
                assert_eq!(r.decision, Decision::Deny);
                assert_eq!(r.pattern.as_str(), "rm -rf");
                assert_eq!(r.message.as_deref(), Some("use trash instead"));
            }
            _ => panic!("expected Rule"),
        }
    }

    #[test]
    fn parse_redirect_rule() {
        let d = parse_rule("deny-redirect **/.env*").unwrap();
        match d {
            ConfigDirective::Rule(r) => {
                assert_eq!(r.target, RuleTarget::Redirect);
                assert_eq!(r.decision, Decision::Deny);
                assert_eq!(r.pattern.as_str(), "**/.env*");
            }
            _ => panic!("expected Rule"),
        }
    }

    #[test]
    fn parse_after_rule() {
        let d = parse_rule(r#"after git "committed successfully""#).unwrap();
        match d {
            ConfigDirective::Rule(r) => {
                assert_eq!(r.target, RuleTarget::After);
                assert_eq!(r.pattern.as_str(), "git");
                assert_eq!(r.message.as_deref(), Some("committed successfully"));
            }
            _ => panic!("expected Rule"),
        }
    }

    #[test]
    fn parse_set_rule() {
        let d = parse_rule("set default ask").unwrap();
        match d {
            ConfigDirective::Set { key, value } => {
                assert_eq!(key, "default");
                assert_eq!(value, "ask");
            }
            _ => panic!("expected Set"),
        }
    }

    #[test]
    fn parse_alias_rule() {
        let d = parse_rule("alias ~/custom-git git").unwrap();
        match d {
            ConfigDirective::Alias { source, target } => {
                assert_eq!(source, "~/custom-git");
                assert_eq!(target, "git");
            }
            _ => panic!("expected Alias"),
        }
    }

    #[test]
    fn parse_mcp_rule() {
        let d = parse_rule("deny-mcp dangerous_tool").unwrap();
        match d {
            ConfigDirective::Rule(r) => {
                assert_eq!(r.target, RuleTarget::Mcp);
                assert_eq!(r.decision, Decision::Deny);
                assert_eq!(r.pattern.as_str(), "dangerous_tool");
            }
            _ => panic!("expected Rule"),
        }
    }

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
    fn tokenize_quoted_strings() {
        let tokens = tokenize_config_line(r#"deny python "Use uv run python""#);
        assert_eq!(tokens.len(), 3);
        assert!(matches!(&tokens[0], Token::Bare(s) if s == "deny"));
        assert!(matches!(&tokens[1], Token::Bare(s) if s == "python"));
        assert!(matches!(&tokens[2], Token::Quoted(s) if s == "Use uv run python"));
    }

    #[test]
    fn tokenize_escaped_quote() {
        let tokens = tokenize_config_line(r#"deny test "say \"hello\"""#);
        assert_eq!(tokens.len(), 3);
        assert!(matches!(&tokens[2], Token::Quoted(s) if s == r#"say "hello""#));
    }

    #[test]
    fn unknown_directive_errors() {
        assert!(parse_rule("foobar something").is_err());
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
                Rule::new(RuleTarget::Redirect, Decision::Allow, "/etc/hosts")
                    .with_message("hosts ok"),
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
            Rule::new(RuleTarget::FileEdit, Decision::Ask, "**/node_modules/**")
                .with_message("vendor"),
        )]);
        let v = config
            .match_file_edit("node_modules/pkg/index.js", None)
            .unwrap();
        assert_eq!(v.decision, Decision::Ask);
        assert!(config.match_file_edit("src/main.rs", None).is_none());
    }

    #[test]
    fn parse_file_read_rule() {
        let d = parse_rule(r#"deny-read **/.env* "no env files""#).unwrap();
        match d {
            ConfigDirective::Rule(r) => {
                assert_eq!(r.target, RuleTarget::FileRead);
                assert_eq!(r.decision, Decision::Deny);
                assert!(r.pattern.matches(".env"));
                assert!(r.pattern.matches("foo/.env.local"));
                assert_eq!(r.message.as_deref(), Some("no env files"));
            }
            _ => panic!("expected Rule"),
        }
    }

    #[test]
    fn parse_file_write_rule() {
        let d = parse_rule("allow-write /tmp/**").unwrap();
        match d {
            ConfigDirective::Rule(r) => {
                assert_eq!(r.target, RuleTarget::FileWrite);
                assert_eq!(r.decision, Decision::Allow);
            }
            _ => panic!("expected Rule"),
        }
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
        // Provide a context where branch is NOT main
        let ctx = MatchContext {
            branch: Some("develop"),
            cwd: std::path::Path::new("/tmp"),
        };
        // Rule should be skipped
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
        // No context provided — rule should be skipped
        assert!(config.match_command("echo hello", None).is_none());
    }

    // ── Structured matching tests ──────────────────────────────────

    fn structured_rule(
        decision: Decision,
        command: Option<&str>,
        subcommand: Option<&str>,
        flags: Option<Vec<&str>>,
    ) -> Rule {
        let mut r = Rule::new(RuleTarget::Command, decision, "*");
        r.pattern = Pattern::any();
        r.command = command.map(String::from);
        r.subcommand = subcommand.map(String::from);
        r.flags = flags.map(|f| f.into_iter().map(String::from).collect());
        r
    }

    #[test]
    fn structured_command_matches() {
        let rule = structured_rule(Decision::Deny, Some("git"), None, None);
        assert!(matches_structured(&rule, "git push origin main"));
        assert!(matches_structured(&rule, "git status"));
        assert!(!matches_structured(&rule, "docker ps"));
    }

    #[test]
    fn structured_subcommand_matches() {
        let rule = structured_rule(Decision::Deny, Some("git"), Some("push"), None);
        assert!(matches_structured(&rule, "git push origin main"));
        assert!(!matches_structured(&rule, "git status"));
        // --no-pager is a flag, so "push" is still the first positional → matches
        assert!(matches_structured(&rule, "git --no-pager push"));
    }

    #[test]
    fn structured_flags_matches() {
        let rule = structured_rule(
            Decision::Deny,
            Some("git"),
            Some("push"),
            Some(vec!["--force", "-f"]),
        );
        assert!(matches_structured(&rule, "git push --force origin main"));
        assert!(matches_structured(&rule, "git push origin main --force"));
        assert!(matches_structured(&rule, "git push -f origin main"));
        assert!(!matches_structured(&rule, "git push origin main"));
    }

    #[test]
    fn structured_combined_short_flags() {
        let rule = structured_rule(
            Decision::Deny,
            Some("curl"),
            None,
            Some(vec!["-k", "--insecure"]),
        );
        let flags = rule.flags.as_ref().unwrap();
        assert!(has_required_flag(&["-kv", "http://example.com"], flags));
        assert!(has_required_flag(
            &["--insecure", "http://example.com"],
            flags
        ));
        assert!(!has_required_flag(&["-v", "http://example.com"], flags));
    }

    #[test]
    fn structured_subcommands_list() {
        let mut rule = structured_rule(Decision::Allow, Some("git"), None, None);
        rule.subcommands = Some(vec!["status".into(), "log".into(), "diff".into()]);
        assert!(matches_structured(&rule, "git status"));
        assert!(matches_structured(&rule, "git log --oneline"));
        assert!(!matches_structured(&rule, "git push origin"));
    }

    #[test]
    fn structured_args_contain() {
        let mut rule = structured_rule(Decision::Deny, Some("curl"), None, None);
        rule.args_contain = Some("password".into());
        assert!(matches_structured(
            &rule,
            "curl http://example.com?password=123"
        ));
        assert!(!matches_structured(&rule, "curl http://example.com"));
    }

    #[test]
    fn structured_rule_in_config() {
        let rule = structured_rule(Decision::Deny, Some("git"), Some("push"), None);
        let config = Config::from_directives(vec![ConfigDirective::Rule(rule)]);
        let v = config.match_command("git push origin main", None);
        assert!(v.is_some());
        assert_eq!(v.unwrap().decision, Decision::Deny);

        // Non-matching command
        assert!(config.match_command("git status", None).is_none());
    }

    #[test]
    fn structured_empty_input_no_match() {
        let rule = structured_rule(Decision::Deny, Some("git"), None, None);
        assert!(!matches_structured(&rule, ""));
    }

    #[test]
    fn structured_rule_with_when_condition() {
        let rule = structured_rule(Decision::Deny, Some("git"), Some("push"), None)
            .with_conditions(vec![Condition::BranchEq("main".into())]);
        let config = Config::from_directives(vec![ConfigDirective::Rule(rule)]);
        let ctx_main = MatchContext {
            branch: Some("main"),
            cwd: std::path::Path::new("/tmp"),
        };
        let ctx_feat = MatchContext {
            branch: Some("feature"),
            cwd: std::path::Path::new("/tmp"),
        };
        // Matches on main branch
        assert!(
            config
                .match_command("git push origin", Some(&ctx_main))
                .is_some()
        );
        // Does NOT match on feature branch
        assert!(
            config
                .match_command("git push origin", Some(&ctx_feat))
                .is_none()
        );
    }

    #[test]
    fn has_structured_fields_detects_fields() {
        let plain = Rule::new(RuleTarget::Command, Decision::Allow, "git *");
        assert!(!plain.has_structured_fields());

        let structured = structured_rule(Decision::Deny, Some("git"), None, None);
        assert!(structured.has_structured_fields());
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
        assert!(
            !v.reason.contains("overrides"),
            "baseline rule should not be annotated, got: {}",
            v.reason
        );
    }

    #[test]
    fn project_ask_overriding_deny_not_annotated() {
        // ask overriding deny is not weakening — it's still restrictive.
        let directives = vec![
            ConfigDirective::Rule(Rule::new(RuleTarget::Command, Decision::Deny, "rm *")),
            ConfigDirective::ProjectBoundary,
            ConfigDirective::Rule(Rule::new(RuleTarget::Command, Decision::Ask, "rm *")),
        ];
        let config = Config::from_directives(directives);
        let v = config.match_command("rm -rf /", None).unwrap();
        assert_eq!(v.decision, Decision::Ask);
        assert!(
            !v.reason.contains("overrides"),
            "ask overriding deny is not weakening, got: {}",
            v.reason
        );
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
        assert!(
            v.reason.contains("overrides ask"),
            "allow overriding ask should be annotated, got: {}",
            v.reason
        );
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
        // --config rules (after second boundary) should NOT be annotated.
        let directives = vec![
            ConfigDirective::Rule(Rule::new(RuleTarget::Command, Decision::Deny, "rm *")),
            ConfigDirective::ProjectBoundary,
            ConfigDirective::ProjectBoundary,
            ConfigDirective::Rule(Rule::new(RuleTarget::Command, Decision::Allow, "rm *")),
        ];
        let config = Config::from_directives(directives);
        let v = config.match_command("rm -rf /", None).unwrap();
        assert_eq!(v.decision, Decision::Allow);
        assert!(
            !v.reason.contains("overrides"),
            "env override should not be annotated as project rule, got: {}",
            v.reason
        );
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
                .contains("default action to allow"),
            "should detect 'set default allow', got: {:?}",
            config.weakening_suffix()
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
        assert!(
            config.weakening_suffix().contains("self-protection"),
            "should detect self-protect off, got: {:?}",
            config.weakening_suffix()
        );
    }

    #[test]
    fn project_broad_allow_detected() {
        let directives = vec![
            ConfigDirective::ProjectBoundary,
            ConfigDirective::Rule(Rule::new(RuleTarget::Command, Decision::Allow, "*")),
            ConfigDirective::ProjectBoundary,
        ];
        let config = Config::from_directives(directives);
        assert!(
            config.weakening_suffix().contains("allows all commands"),
            "should detect broad allow *, got: {:?}",
            config.weakening_suffix()
        );
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
        assert!(
            config.weakening_suffix().is_empty(),
            "deny-only config should have no weakening suffix, got: {:?}",
            config.weakening_suffix()
        );
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
        assert!(
            v.reason.contains("NOTE: project config"),
            "verdict should include weakening notes, got: {}",
            v.reason
        );
        assert!(
            v.reason.contains("default action to allow"),
            "should mention default allow, got: {}",
            v.reason
        );
    }
}
