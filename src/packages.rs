//! Preconfigured safety packages — named rule bundles for different workflows.
//!
//! Packages are embedded TOML files that slot between stdlib and user config.
//! They provide sensible defaults for common development scenarios so users
//! can get started with a single `package = "develop"` setting.
//!
//! Three packages are available:
//!
//! - `review`    — full supervision, every command asks
//! - `develop`   — auto-approves builds, tests, VCS; asks for destructive ops
//! - `autopilot` — maximum AI autonomy, only catastrophic ops blocked

use std::path::Path;

use crate::config::ConfigDirective;
use crate::error::RippyError;

const REVIEW_TOML: &str = include_str!("packages/review.toml");
const DEVELOP_TOML: &str = include_str!("packages/develop.toml");
const AUTOPILOT_TOML: &str = include_str!("packages/autopilot.toml");

/// A preconfigured safety profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Package {
    /// Full supervision. Every command asks.
    Review,
    /// Auto-approves builds, tests, VCS. Asks for destructive ops.
    Develop,
    /// Maximum AI autonomy. Only catastrophic ops blocked.
    Autopilot,
}

/// All available packages in display order (most restrictive first).
const ALL_PACKAGES: &[Package] = &[Package::Review, Package::Develop, Package::Autopilot];

impl Package {
    /// Parse a package name from a string.
    ///
    /// # Errors
    ///
    /// Returns an error if the name is not recognized.
    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "review" => Ok(Self::Review),
            "develop" => Ok(Self::Develop),
            "autopilot" => Ok(Self::Autopilot),
            other => Err(format!(
                "unknown package: {other} (expected review, develop, or autopilot)"
            )),
        }
    }

    /// The short name used in config files.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Review => "review",
            Self::Develop => "develop",
            Self::Autopilot => "autopilot",
        }
    }

    /// One-line description shown in `rippy profile list`.
    #[must_use]
    pub const fn tagline(self) -> &'static str {
        match self {
            Self::Review => "Full supervision. Every command asks.",
            Self::Develop => "Let me code. Ask when it matters.",
            Self::Autopilot => "Maximum AI autonomy. Only catastrophic ops are blocked.",
        }
    }

    /// Shield bar for terminal display (e.g., `===`, `==.`, `=..`).
    #[must_use]
    pub const fn shield(self) -> &'static str {
        match self {
            Self::Review => "===",
            Self::Develop => "==.",
            Self::Autopilot => "=..",
        }
    }

    /// All available packages in display order (most restrictive first).
    #[must_use]
    pub const fn all() -> &'static [Self] {
        ALL_PACKAGES
    }

    const fn toml_source(self) -> &'static str {
        match self {
            Self::Review => REVIEW_TOML,
            Self::Develop => DEVELOP_TOML,
            Self::Autopilot => AUTOPILOT_TOML,
        }
    }
}

/// Parse a package's embedded TOML into config directives.
///
/// # Errors
///
/// Returns `RippyError::Config` if the embedded TOML is malformed (a build bug).
pub fn package_directives(package: Package) -> Result<Vec<ConfigDirective>, RippyError> {
    let source = package.toml_source();
    let label = format!("(package:{})", package.name());
    crate::toml_config::parse_toml_config(source, Path::new(&label))
}

/// Get the raw TOML source for a package.
#[must_use]
pub const fn package_toml(package: Package) -> &'static str {
    package.toml_source()
}

impl std::fmt::Display for Package {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::verdict::Decision;

    #[test]
    fn review_toml_parses() {
        let directives = package_directives(Package::Review).unwrap();
        assert!(
            !directives.is_empty(),
            "review package should produce directives"
        );
    }

    #[test]
    fn develop_toml_parses() {
        let directives = package_directives(Package::Develop).unwrap();
        assert!(
            !directives.is_empty(),
            "develop package should produce directives"
        );
    }

    #[test]
    fn autopilot_toml_parses() {
        let directives = package_directives(Package::Autopilot).unwrap();
        assert!(
            !directives.is_empty(),
            "autopilot package should produce directives"
        );
    }

    #[test]
    fn parse_valid_names() {
        assert_eq!(Package::parse("review").unwrap(), Package::Review);
        assert_eq!(Package::parse("develop").unwrap(), Package::Develop);
        assert_eq!(Package::parse("autopilot").unwrap(), Package::Autopilot);
    }

    #[test]
    fn parse_invalid_name_errors() {
        let err = Package::parse("yolo").unwrap_err();
        assert!(err.contains("unknown package"));
        assert!(err.contains("yolo"));
    }

    #[test]
    fn all_returns_three_packages() {
        assert_eq!(Package::all().len(), 3);
    }

    #[test]
    fn develop_allows_cargo_test() {
        let config = Config::from_directives(package_directives(Package::Develop).unwrap());
        let v = config.match_command("cargo test", None);
        assert!(v.is_some(), "develop package should match cargo test");
        assert_eq!(v.unwrap().decision, Decision::Allow);
    }

    #[test]
    fn develop_allows_file_ops() {
        let config = Config::from_directives(package_directives(Package::Develop).unwrap());
        for cmd in &["rm foo.txt", "mv a b", "cp a b", "touch new.txt"] {
            let v = config.match_command(cmd, None);
            assert!(v.is_some(), "develop should match {cmd}");
            assert_eq!(
                v.unwrap().decision,
                Decision::Allow,
                "develop should allow {cmd}"
            );
        }
    }

    #[test]
    fn autopilot_has_allow_default() {
        let directives = package_directives(Package::Autopilot).unwrap();
        let has_default_allow = directives
            .iter()
            .any(|d| matches!(d, ConfigDirective::Set { key, value } if key == "default" && value == "allow"));
        assert!(has_default_allow, "autopilot should set default = allow");
    }

    #[test]
    fn review_has_no_extra_allow_rules() {
        let directives = package_directives(Package::Review).unwrap();
        // Review should only have git style rules (from cautious), no explicit allow commands
        let allow_command_rules = directives.iter().filter(|d| {
            matches!(d, ConfigDirective::Rule(r) if r.decision == Decision::Allow
                && !r.pattern.raw().starts_with("git"))
        });
        assert_eq!(
            allow_command_rules.count(),
            0,
            "review should not add non-git allow rules"
        );
    }

    #[test]
    fn package_toml_not_empty() {
        for pkg in Package::all() {
            let toml = package_toml(*pkg);
            assert!(!toml.is_empty(), "{pkg} TOML should not be empty");
            assert!(toml.contains("[meta]"), "{pkg} should have [meta] section");
        }
    }

    #[test]
    fn display_shows_name() {
        assert_eq!(format!("{}", Package::Review), "review");
        assert_eq!(format!("{}", Package::Develop), "develop");
        assert_eq!(format!("{}", Package::Autopilot), "autopilot");
    }

    #[test]
    fn shield_values_are_three_chars() {
        for pkg in Package::all() {
            assert_eq!(pkg.shield().len(), 3, "{pkg} shield should be 3 chars");
        }
    }
}
