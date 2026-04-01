//! Git workflow styles — named rule bundles for git permissiveness.
//!
//! Styles are predefined sets of config rules that control how permissive
//! rippy is with git operations. They are expanded into `ConfigDirective`s
//! during config loading, slotting between stdlib and user rules.

use std::path::Path;

use crate::condition::Condition;
use crate::config::ConfigDirective;
use crate::toml_config::TomlGit;

const CAUTIOUS_TOML: &str = include_str!("stdlib/git_cautious.toml");
const STANDARD_TOML: &str = include_str!("stdlib/git_standard.toml");
const PERMISSIVE_TOML: &str = include_str!("stdlib/git_permissive.toml");

/// A named git workflow style.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitStyle {
    Cautious,
    Standard,
    Permissive,
}

impl GitStyle {
    /// Parse a style name from a string.
    ///
    /// # Errors
    ///
    /// Returns an error if the name is not recognized.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "cautious" => Ok(Self::Cautious),
            "standard" => Ok(Self::Standard),
            "permissive" => Ok(Self::Permissive),
            other => Err(format!(
                "unknown git style: {other} (expected cautious, standard, or permissive)"
            )),
        }
    }

    const fn toml_source(self) -> &'static str {
        match self {
            Self::Cautious => CAUTIOUS_TOML,
            Self::Standard => STANDARD_TOML,
            Self::Permissive => PERMISSIVE_TOML,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Cautious => "cautious",
            Self::Standard => "standard",
            Self::Permissive => "permissive",
        }
    }
}

/// Expand a `[git]` config section into directives.
///
/// The default style's rules are emitted first (unconditional), then
/// branch-specific overrides with `BranchMatch` conditions. This ensures
/// last-match-wins semantics: branch overrides beat the default style.
///
/// # Errors
///
/// Returns an error if a style name is unrecognized or a style TOML
/// fails to parse.
pub fn expand_git_config(git: &TomlGit) -> Result<Vec<ConfigDirective>, String> {
    let mut directives = Vec::new();

    if let Some(style_name) = &git.style {
        let style = GitStyle::parse(style_name)?;
        directives.extend(parse_style_rules(style)?);
    }

    for branch in &git.branches {
        if branch.pattern.is_empty() {
            return Err("git.branches entry has empty pattern".into());
        }
        let style = GitStyle::parse(&branch.style)?;
        let rules = parse_style_rules(style)?;
        directives.extend(add_branch_condition(rules, &branch.pattern));
    }

    Ok(directives)
}

/// Parse a style's embedded TOML into directives.
fn parse_style_rules(style: GitStyle) -> Result<Vec<ConfigDirective>, String> {
    let source = style.toml_source();
    let label = format!("(git-style:{style_name})", style_name = style.label());
    crate::toml_config::parse_toml_config(source, Path::new(&label))
        .map_err(|e| format!("error parsing git style {}: {e}", style.label()))
}

/// Append a `BranchMatch` condition to every rule in the directive list.
fn add_branch_condition(directives: Vec<ConfigDirective>, pattern: &str) -> Vec<ConfigDirective> {
    directives
        .into_iter()
        .map(|d| match d {
            ConfigDirective::Rule(mut rule) => {
                rule.conditions
                    .push(Condition::BranchMatch(pattern.to_string()));
                ConfigDirective::Rule(rule)
            }
            other => other,
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn cautious_toml_parses() {
        let rules = parse_style_rules(GitStyle::Cautious).unwrap();
        assert!(!rules.is_empty());
    }

    #[test]
    fn standard_toml_parses() {
        let rules = parse_style_rules(GitStyle::Standard).unwrap();
        assert!(!rules.is_empty());
    }

    #[test]
    fn permissive_toml_parses() {
        let rules = parse_style_rules(GitStyle::Permissive).unwrap();
        assert!(!rules.is_empty());
    }

    #[test]
    fn unknown_style_errors() {
        assert!(GitStyle::parse("yolo").is_err());
    }

    #[test]
    fn expand_default_style_only() {
        let git = TomlGit {
            style: Some("standard".into()),
            branches: vec![],
        };
        let directives = expand_git_config(&git).unwrap();
        assert!(!directives.is_empty());
        // No branch conditions on default style rules
        for d in &directives {
            if let ConfigDirective::Rule(r) = d {
                assert!(r.conditions.is_empty());
            }
        }
    }

    #[test]
    fn expand_branch_override_adds_conditions() {
        let git = TomlGit {
            style: None,
            branches: vec![crate::toml_config::TomlGitBranch {
                pattern: "agent/*".into(),
                style: "permissive".into(),
            }],
        };
        let directives = expand_git_config(&git).unwrap();
        assert!(!directives.is_empty());
        for d in &directives {
            if let ConfigDirective::Rule(r) = d {
                assert!(
                    r.conditions
                        .iter()
                        .any(|c| matches!(c, Condition::BranchMatch(p) if p == "agent/*")),
                    "expected BranchMatch condition on rule"
                );
            }
        }
    }

    #[test]
    fn expand_default_plus_branch_override() {
        let git = TomlGit {
            style: Some("standard".into()),
            branches: vec![crate::toml_config::TomlGitBranch {
                pattern: "main".into(),
                style: "cautious".into(),
            }],
        };
        let directives = expand_git_config(&git).unwrap();
        // Should have both unconditional (standard) and conditioned (cautious) rules
        let unconditional = directives
            .iter()
            .filter(|d| matches!(d, ConfigDirective::Rule(r) if r.conditions.is_empty()))
            .count();
        let conditioned = directives
            .iter()
            .filter(|d| matches!(d, ConfigDirective::Rule(r) if !r.conditions.is_empty()))
            .count();
        assert!(unconditional > 0, "expected unconditional standard rules");
        assert!(conditioned > 0, "expected conditioned cautious rules");
    }

    #[test]
    fn empty_git_section_produces_no_directives() {
        let git = TomlGit {
            style: None,
            branches: vec![],
        };
        let directives = expand_git_config(&git).unwrap();
        assert!(directives.is_empty());
    }

    #[test]
    fn empty_branch_pattern_errors() {
        let git = TomlGit {
            style: None,
            branches: vec![crate::toml_config::TomlGitBranch {
                pattern: String::new(),
                style: "standard".into(),
            }],
        };
        assert!(expand_git_config(&git).is_err());
    }
}
