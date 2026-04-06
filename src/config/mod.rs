mod loader;
mod matching;
mod parser;
mod sources;
mod types;

pub use loader::{home_dir, load_file};
pub use parser::{parse_action_word, parse_rule};
pub use sources::{ConfigSourceInfo, enumerate_config_sources, find_project_config};
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
use crate::verdict::{Decision, Verdict};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

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
    /// Whether to auto-trust all project configs without checking the trust DB.
    pub trust_project_configs: bool,
    aliases: Vec<(String, String)>,
    /// Extra directories that `cd` is allowed to navigate to (beyond the project root).
    pub cd_allowed_dirs: Vec<std::path::PathBuf>,
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
                    config
                        .cd_allowed_dirs
                        .push(crate::handlers::normalize_path(&path));
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
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
}
