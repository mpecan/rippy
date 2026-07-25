use std::path::PathBuf;

mod loader;
mod matching;
mod parser;
mod sources;
mod string_loader;
mod types;

pub use loader::{home_dir, load_file};
pub use parser::{parse_action_word, parse_rule};
pub use sources::{ConfigSourceInfo, enumerate_config_sources, find_project_config};
pub use string_loader::ConfigFormat;
pub use types::{ConfigDirective, Rule, RuleTarget};

use loader::{
    apply_setting, build_weakening_suffix, detect_broad_allow, detect_dangerous_setting,
    has_trust_setting, load_first_existing, load_project_config_if_trusted,
};
use matching::{format_rule_reason, matches_structured};

use std::path::Path;

use crate::condition::{MatchContext, evaluate_all};
use crate::error::RippyError;
use crate::pattern::Pattern;
use crate::verdict::{AutoMode, Decision, RuleSource, Verdict};

// Config

/// Loaded and merged configuration with rules partitioned by type.
#[derive(Debug, Clone, Default)]
pub struct Config {
    rules: Vec<Rule>,
    after_rules: Vec<(Pattern, String)>,
    pub default_action: Option<Decision>,
    pub log_file: Option<std::path::PathBuf>,
    pub log_full: bool,
    pub tracking_db: Option<std::path::PathBuf>,
    pub self_protect: bool,
    /// How an uncertain `Ask` behaves in Claude's auto permission modes
    /// (config knob `auto-mode`; defaults to [`AutoMode::Defer`]).
    pub auto_mode: AutoMode,
    /// Whether to auto-trust all project configs without checking the trust DB.
    pub trust_project_configs: bool,
    aliases: Vec<(String, String)>,
    /// User-declared safe scopes (beyond the project root). Path-based handlers
    /// (`cd`, `mkdir`, `git -C`) treat these as in-scope: reads within them are
    /// allowed, writes still ask. Paths are tilde/env-expanded and normalized at
    /// load time; entries that would resolve to the filesystem root are dropped.
    pub safe_scopes: Vec<std::path::PathBuf>,
    /// Index range in `rules` containing project-config rules.
    /// `None` when no project config was loaded. Rules outside this range
    /// are baseline (stdlib + global) or env override.
    project_rules_range: Option<std::ops::Range<usize>>,
    /// Pre-formatted suffix appended to verdict reasons when project allow rules fire.
    /// Empty string when the project config doesn't weaken protections.
    project_weakening_suffix: String,
    /// The active safety package (if any).
    pub active_package: Option<crate::packages::Package>,
}

impl Config {
    /// Load config from the three-tier system: global, project, env override.
    ///
    /// # Errors
    ///
    /// Returns `RippyError::Config` if a config file exists but contains invalid syntax.
    pub fn load(cwd: &Path, env_config: Option<&Path>) -> Result<Self, RippyError> {
        Self::load_with_home(cwd, env_config, home_dir())
    }

    /// Load config with an explicit home directory instead of reading `$HOME`.
    ///
    /// Pass `None` to skip global config loading (useful for tests).
    ///
    /// # Errors
    ///
    /// Returns `RippyError::Config` if a config file exists but contains invalid syntax.
    pub fn load_with_home(
        cwd: &Path,
        env_config: Option<&Path>,
        home: Option<PathBuf>,
    ) -> Result<Self, RippyError> {
        // Stdlib first (lowest priority — user config overrides via last-match-wins).
        let mut directives = crate::stdlib::stdlib_directives()?;

        // Pre-scan config files for the package setting. Project config
        // overrides global (last-match-wins). The package layer loads between
        // stdlib and user config so user rules can override package rules.
        let package = resolve_package(home.as_ref(), cwd);
        if let Some(pkg) = &package {
            directives.extend(crate::packages::package_directives(pkg)?);
        }

        if let Some(home) = home {
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

        let mut config = Self::from_directives(directives);
        config.active_package = package;
        Ok(config)
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

            let source = if is_project_rule {
                RuleSource::Project
            } else {
                RuleSource::Baseline
            };
            result = Some(Verdict::from_rule(rule.decision, reason, source));
        }
        result
    }

    /// Build a `Config` from a list of directives, reading `$HOME` for
    /// safe-scope tilde expansion.
    pub fn from_directives(directives: Vec<ConfigDirective>) -> Self {
        Self::from_directives_with_home(directives, home_dir().as_deref())
    }

    /// Build a `Config` from directives with an explicit home directory used
    /// for safe-scope tilde expansion (pass `None` to skip tilde expansion).
    pub fn from_directives_with_home(
        directives: Vec<ConfigDirective>,
        home: Option<&Path>,
    ) -> Self {
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
                ConfigDirective::SafeScope(path) => {
                    if in_project_section {
                        weakening_notes.push(format!(
                            "declares safe scope \"{}\" that widens auto-approval",
                            path.display()
                        ));
                    }
                    if let Some(scope) = expand_scope_path(&path, home) {
                        config.safe_scopes.push(scope);
                    }
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

/// Pre-scan global and project config files for the `package` setting.
///
/// Project config overrides global (last-match-wins). Returns `None` if
/// no config file specifies a package.
fn resolve_package(home: Option<&PathBuf>, cwd: &Path) -> Option<crate::packages::Package> {
    let mut package_name: Option<String> = None;

    // Check global config candidates.
    if let Some(home) = home {
        for path in &[
            home.join(".rippy/config.toml"),
            home.join(".rippy/config"),
            home.join(".dippy/config"),
        ] {
            if path.is_file() {
                package_name = loader::extract_package_setting(path);
                break; // Only the first existing global config matters
            }
        }
    }

    // Check project config (overrides global).
    if let Some(project_config) = find_project_config(cwd)
        && let Some(name) = loader::extract_package_setting(&project_config)
    {
        package_name = Some(name);
    }

    let name = package_name?;
    match crate::packages::Package::resolve(&name, home.map(PathBuf::as_path)) {
        Ok(pkg) => Some(pkg),
        Err(e) => {
            eprintln!("[rippy] {e}");
            None
        }
    }
}

/// Validate a user-supplied safe-scope directory for the `rippy scope` CLI.
///
/// Thin wrapper over [`expand_and_validate_scope`] so the CLI and the
/// config-load path apply exactly the same "too broad" rules. Returns the
/// expanded absolute path (the caller stores the original as-written string).
///
/// # Errors
///
/// Returns a human-readable message describing why the directory was rejected.
pub fn validate_safe_scope(dir: &str, home: Option<&Path>) -> Result<PathBuf, String> {
    expand_and_validate_scope(Path::new(dir), home)
}

/// Expand a declared safe-scope path and validate that it is safe to trust.
///
/// Expands a leading `~` (using `home`) and `$VAR`/`${VAR}` references, then
/// normalizes `.`/`..` components. Rejects paths that resolve to the filesystem
/// root, an empty path, a non-absolute path, or the home directory itself — all
/// of which would auto-approve far too much. Both the config-load path
/// ([`expand_scope_path`]) and the `rippy scope` CLI ([`validate_safe_scope`])
/// go through here so the two agree on what counts as "too broad".
///
/// # Errors
///
/// Returns a human-readable message describing why the directory was rejected.
fn expand_and_validate_scope(raw: &Path, home: Option<&Path>) -> Result<PathBuf, String> {
    let raw_str = raw
        .to_str()
        .ok_or_else(|| format!("'{}' is not valid UTF-8", raw.display()))?;
    let expanded = expand_scope_string(raw_str, home);
    let normalized = crate::handlers::normalize_path(Path::new(&expanded));
    if normalized.as_os_str().is_empty() || normalized == Path::new("/") {
        return Err(format!(
            "'{raw_str}' resolves to the filesystem root or is empty"
        ));
    }
    if !normalized.is_absolute() {
        return Err(format!(
            "'{raw_str}' must resolve to an absolute path (got '{}')",
            normalized.display()
        ));
    }
    if let Some(h) = home
        && normalized == crate::handlers::normalize_path(h)
    {
        return Err(format!(
            "'{raw_str}' is your home directory — too broad to be a safe scope"
        ));
    }
    Ok(normalized)
}

/// Expand and validate a declared safe-scope path for the config-load path.
///
/// Returns `None` for any path that is too broad to trust (filesystem root,
/// empty, non-absolute, or the home directory) — see
/// [`expand_and_validate_scope`]. Rejected entries are silently dropped rather
/// than disabling the hook. This keeps a hand-edited or trusted-project
/// `[scopes] safe = ["~"]` from widening auto-approval across the whole home
/// directory, matching what the `rippy scope` CLI refuses to add.
fn expand_scope_path(raw: &Path, home: Option<&Path>) -> Option<std::path::PathBuf> {
    expand_and_validate_scope(raw, home).ok()
}

/// Expand a leading tilde then any `$VAR`/`${VAR}` references in `raw`.
fn expand_scope_string(raw: &str, home: Option<&Path>) -> String {
    let tilde_expanded = expand_leading_tilde(raw, home);
    expand_env_vars(&tilde_expanded)
}

fn expand_leading_tilde(raw: &str, home: Option<&Path>) -> String {
    match home {
        Some(h) if raw == "~" => h.to_string_lossy().into_owned(),
        Some(h) => raw.strip_prefix("~/").map_or_else(
            || raw.to_string(),
            |rest| h.join(rest).to_string_lossy().into_owned(),
        ),
        None => raw.to_string(),
    }
}

/// Expand `$VAR` and `${VAR}` references using the process environment.
/// Unknown variables are kept literal so they cannot silently widen a scope.
fn expand_env_vars(input: &str) -> String {
    if !input.contains('$') {
        return input.to_string();
    }
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' {
            append_var_expansion(&mut out, &mut chars);
        } else {
            out.push(c);
        }
    }
    out
}

fn append_var_expansion(out: &mut String, chars: &mut std::iter::Peekable<std::str::Chars>) {
    let braced = chars.peek() == Some(&'{');
    if braced {
        chars.next();
    }
    let mut name = String::new();
    while let Some(&c) = chars.peek() {
        let is_name_char = if braced {
            c != '}'
        } else {
            c.is_ascii_alphanumeric() || c == '_'
        };
        if !is_name_char {
            break;
        }
        name.push(c);
        chars.next();
    }
    if braced && chars.peek() == Some(&'}') {
        chars.next();
    }
    match std::env::var_os(&name) {
        Some(val) if !name.is_empty() => out.push_str(&val.to_string_lossy()),
        _ => {
            out.push('$');
            if braced {
                out.push('{');
                out.push_str(&name);
                out.push('}');
            } else {
                out.push_str(&name);
            }
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used)]
mod tests;

#[cfg(test)]
#[expect(clippy::unwrap_used, clippy::panic)]
#[path = "tests_part2.rs"]
mod tests_part2;
