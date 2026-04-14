//! Preconfigured safety packages — named rule bundles for different workflows.
//!
//! Packages are embedded TOML files that slot between stdlib and user config.
//! They provide sensible defaults for common development scenarios so users
//! can get started with a single `package = "develop"` setting.
//!
//! Three built-in packages are available:
//!
//! - `review`    — full supervision, every command asks
//! - `develop`   — auto-approves builds, tests, VCS; asks for destructive ops
//! - `autopilot` — maximum AI autonomy, only catastrophic ops blocked
//!
//! Users may also define custom packages in `~/.rippy/packages/<name>.toml`.
//! Custom packages can `extends = "<builtin>"` to inherit from a built-in
//! package and layer extra rules on top.

mod custom;
mod meta;

pub use custom::{CustomPackage, discover_custom_packages, load_custom_package};

use std::path::Path;
use std::sync::Arc;

use crate::config::ConfigDirective;
use crate::error::RippyError;
use meta::builtin_meta;

const REVIEW_TOML: &str = include_str!("packages/review.toml");
const DEVELOP_TOML: &str = include_str!("packages/develop.toml");
const AUTOPILOT_TOML: &str = include_str!("packages/autopilot.toml");

/// A preconfigured safety profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Package {
    /// Full supervision. Every command asks.
    Review,
    /// Auto-approves builds, tests, VCS. Asks for destructive ops.
    Develop,
    /// Maximum AI autonomy. Only catastrophic ops blocked.
    Autopilot,
    /// User-defined custom package loaded from `~/.rippy/packages/<name>.toml`.
    Custom(Arc<CustomPackage>),
}

/// All built-in packages in display order (most restrictive first).
const ALL_BUILTIN: &[Package] = &[Package::Review, Package::Develop, Package::Autopilot];

impl Package {
    /// Parse a built-in package name from a string.
    ///
    /// For custom packages use [`Package::resolve`], which checks built-ins
    /// first and then `~/.rippy/packages/<name>.toml`.
    ///
    /// # Errors
    ///
    /// Returns an error if the name does not match a built-in package.
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

    /// Resolve a package name to a built-in or custom package.
    ///
    /// Built-in names (`review`, `develop`, `autopilot`) always take priority.
    /// If a custom file in `~/.rippy/packages/` has the same name as a built-in,
    /// a warning is printed to stderr and the built-in is used.
    ///
    /// Pass `None` for `home` to skip custom package resolution.
    ///
    /// # Errors
    ///
    /// Returns `RippyError::Config` if a custom package file exists but is
    /// malformed. Returns `RippyError::Setup` if the name is unknown.
    pub fn resolve(name: &str, home: Option<&Path>) -> Result<Self, RippyError> {
        // Built-ins always take priority.
        if let Ok(builtin) = Self::parse(name) {
            if let Some(home) = home
                && home
                    .join(".rippy/packages")
                    .join(format!("{name}.toml"))
                    .is_file()
            {
                eprintln!(
                    "[rippy] custom package \"{name}\" is shadowed by the built-in package with the same name"
                );
            }
            return Ok(builtin);
        }

        // Try custom packages.
        if let Some(home) = home
            && let Some(pkg) = load_custom_package(home, name)?
        {
            return Ok(Self::Custom(pkg));
        }

        let known = known_package_names(home);
        Err(RippyError::Setup(format!(
            "unknown package: {name} (known: {})",
            known.join(", ")
        )))
    }

    /// The short name used in config files.
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Review => "review",
            Self::Develop => "develop",
            Self::Autopilot => "autopilot",
            Self::Custom(c) => &c.name,
        }
    }

    /// One-line description shown in `rippy profile list`.
    ///
    /// For built-ins, sourced from the `[meta] tagline` field of the
    /// package's embedded TOML (parsed once, cached). For custom packages,
    /// read from the `CustomPackage` loaded at discovery time.
    #[must_use]
    pub fn tagline(&self) -> &str {
        match self {
            Self::Custom(c) => &c.tagline,
            _ => &builtin_meta(self).tagline,
        }
    }

    /// Shield bar for terminal display (e.g., `===`, `==.`, `=..`).
    ///
    /// Sourced from `[meta] shield` in the package's TOML.
    #[must_use]
    pub fn shield(&self) -> &str {
        match self {
            Self::Custom(c) => &c.shield,
            _ => &builtin_meta(self).shield,
        }
    }

    /// All built-in packages in display order (most restrictive first).
    #[must_use]
    pub const fn all() -> &'static [Self] {
        ALL_BUILTIN
    }

    /// All built-in packages as an owned array.
    #[must_use]
    pub const fn all_builtin() -> [Self; 3] {
        [Self::Review, Self::Develop, Self::Autopilot]
    }

    /// All packages available: built-ins followed by discovered custom packages.
    ///
    /// Pass `None` for `home` to return only built-ins.
    #[must_use]
    pub fn all_available(home: Option<&Path>) -> Vec<Self> {
        let mut packages: Vec<Self> = ALL_BUILTIN.to_vec();
        if let Some(home) = home {
            for custom in discover_custom_packages(home) {
                // Skip custom packages that shadow built-ins — they're unreachable.
                if Self::parse(&custom.name).is_ok() {
                    continue;
                }
                packages.push(Self::Custom(custom));
            }
        }
        packages
    }

    /// Whether this package is user-defined (loaded from `~/.rippy/packages/`).
    #[must_use]
    pub const fn is_custom(&self) -> bool {
        matches!(self, Self::Custom(_))
    }

    /// Raw TOML source for the package's rules.
    #[must_use]
    pub fn toml_source(&self) -> &str {
        match self {
            Self::Review => REVIEW_TOML,
            Self::Develop => DEVELOP_TOML,
            Self::Autopilot => AUTOPILOT_TOML,
            Self::Custom(c) => &c.toml_source,
        }
    }
}

fn known_package_names(home: Option<&Path>) -> Vec<String> {
    let mut names: Vec<String> = ALL_BUILTIN.iter().map(|p| p.name().to_string()).collect();
    if let Some(home) = home {
        for custom in discover_custom_packages(home) {
            if !names.contains(&custom.name) {
                names.push(custom.name.clone());
            }
        }
    }
    names
}

/// Parse a package's TOML into config directives.
///
/// For built-ins, parses the embedded TOML. For custom packages with
/// `extends = "<builtin>"`, first generates the base package's directives,
/// then appends the custom package's directives (last-match-wins lets custom
/// rules override base rules).
///
/// # Errors
///
/// Returns `RippyError::Config` if the TOML is malformed, or
/// `RippyError::Setup` if `extends` references an unknown or non-built-in
/// package.
pub fn package_directives(package: &Package) -> Result<Vec<ConfigDirective>, RippyError> {
    if let Package::Custom(c) = package {
        return custom_package_directives(c);
    }
    let source = package.toml_source();
    let label = format!("(package:{})", package.name());
    crate::toml_config::parse_toml_config(source, Path::new(&label))
}

fn custom_package_directives(pkg: &CustomPackage) -> Result<Vec<ConfigDirective>, RippyError> {
    let mut directives = Vec::new();

    if let Some(base_name) = &pkg.extends {
        let base = Package::parse(base_name).map_err(|_| {
            RippyError::Setup(format!(
                "custom package \"{}\" extends unknown package \"{base_name}\" \
                 (only built-ins review, develop, autopilot may be extended)",
                pkg.name
            ))
        })?;
        let base_source = base.toml_source();
        let base_label = format!("(package:{})", base.name());
        directives.extend(crate::toml_config::parse_toml_config(
            base_source,
            Path::new(&base_label),
        )?);
    }

    directives.extend(crate::toml_config::parse_toml_config(
        &pkg.toml_source,
        &pkg.path,
    )?);
    Ok(directives)
}

/// Get the raw TOML source for a package.
#[must_use]
pub fn package_toml(package: &Package) -> &str {
    package.toml_source()
}

impl std::fmt::Display for Package {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::verdict::Decision;

    #[test]
    fn review_toml_parses() {
        let directives = package_directives(&Package::Review).unwrap();
        assert!(
            !directives.is_empty(),
            "review package should produce directives"
        );
    }

    #[test]
    fn develop_toml_parses() {
        let directives = package_directives(&Package::Develop).unwrap();
        assert!(
            !directives.is_empty(),
            "develop package should produce directives"
        );
    }

    #[test]
    fn autopilot_toml_parses() {
        let directives = package_directives(&Package::Autopilot).unwrap();
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
        let config = Config::from_directives(package_directives(&Package::Develop).unwrap());
        let v = config.match_command("cargo test", None);
        assert!(v.is_some(), "develop package should match cargo test");
        assert_eq!(v.unwrap().decision, Decision::Allow);
    }

    #[test]
    fn develop_allows_file_ops() {
        let config = Config::from_directives(package_directives(&Package::Develop).unwrap());
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
        let directives = package_directives(&Package::Autopilot).unwrap();
        let has_default_allow = directives
            .iter()
            .any(|d| matches!(d, ConfigDirective::Set { key, value } if key == "default" && value == "allow"));
        assert!(has_default_allow, "autopilot should set default = allow");
    }

    #[test]
    fn review_has_no_extra_allow_rules() {
        let directives = package_directives(&Package::Review).unwrap();
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
            let toml = package_toml(pkg);
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
    fn shield_values_match_expected() {
        assert_eq!(Package::Review.shield(), "===");
        assert_eq!(Package::Develop.shield(), "==.");
        assert_eq!(Package::Autopilot.shield(), "=..");
    }

    #[test]
    fn tagline_values_not_empty() {
        for pkg in Package::all() {
            assert!(
                !pkg.tagline().is_empty(),
                "{pkg} tagline should not be empty"
            );
        }
    }

    #[test]
    fn autopilot_denies_catastrophic_rm() {
        let config = Config::from_directives(package_directives(&Package::Autopilot).unwrap());
        for cmd in &["rm -rf /", "rm -rf ~"] {
            let v = config.match_command(cmd, None);
            assert!(v.is_some(), "autopilot should match {cmd}");
            assert_eq!(
                v.unwrap().decision,
                Decision::Deny,
                "autopilot should deny {cmd}"
            );
        }
    }

    // --- Custom package and resolution tests ---

    use tempfile::tempdir;

    fn write_custom(home: &Path, name: &str, body: &str) {
        let dir = home.join(".rippy/packages");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{name}.toml")), body).unwrap();
    }

    #[test]
    fn resolve_builtin_without_home() {
        let pkg = Package::resolve("develop", None).unwrap();
        assert_eq!(pkg, Package::Develop);
    }

    #[test]
    fn resolve_builtin_takes_priority_over_custom_with_same_name() {
        let home = tempdir().unwrap();
        write_custom(home.path(), "develop", "[meta]\ntagline = \"shadowed\"\n");
        let pkg = Package::resolve("develop", Some(home.path())).unwrap();
        // Built-in wins
        assert_eq!(pkg, Package::Develop);
    }

    #[test]
    fn resolve_custom_package_by_name() {
        let home = tempdir().unwrap();
        write_custom(
            home.path(),
            "corp",
            "[meta]\nname = \"corp\"\ntagline = \"Corporate\"\n",
        );
        let pkg = Package::resolve("corp", Some(home.path())).unwrap();
        match pkg {
            Package::Custom(c) => {
                assert_eq!(c.name, "corp");
                assert_eq!(c.tagline, "Corporate");
            }
            _ => panic!("expected Custom variant"),
        }
    }

    #[test]
    fn resolve_unknown_errors_lists_known() {
        let err = Package::resolve("bogus", None).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("bogus"), "error should mention name: {msg}");
        assert!(
            msg.contains("develop"),
            "error should list built-ins: {msg}"
        );
    }

    #[test]
    fn resolve_unknown_errors_includes_custom() {
        let home = tempdir().unwrap();
        write_custom(home.path(), "extra", "[meta]\nname = \"extra\"\n");
        let err = Package::resolve("bogus", Some(home.path())).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("extra"),
            "error should list custom packages: {msg}"
        );
    }

    #[test]
    fn all_available_includes_custom_from_home() {
        let home = tempdir().unwrap();
        write_custom(home.path(), "corp", "[meta]\nname = \"corp\"\n");
        write_custom(home.path(), "team", "[meta]\nname = \"team\"\n");

        let all = Package::all_available(Some(home.path()));
        let names: Vec<&str> = all.iter().map(Package::name).collect();
        assert!(names.contains(&"review"));
        assert!(names.contains(&"develop"));
        assert!(names.contains(&"autopilot"));
        assert!(names.contains(&"corp"));
        assert!(names.contains(&"team"));
    }

    #[test]
    fn all_available_filters_shadowed_custom() {
        let home = tempdir().unwrap();
        // Custom file with a built-in name should not appear in the list.
        write_custom(home.path(), "develop", "[meta]\ntagline = \"shadowed\"\n");
        let all = Package::all_available(Some(home.path()));
        let develop_entries: Vec<&Package> = all.iter().filter(|p| p.name() == "develop").collect();
        assert_eq!(develop_entries.len(), 1);
        assert_eq!(develop_entries[0], &Package::Develop);
    }

    #[test]
    fn all_builtin_returns_three() {
        let all = Package::all_builtin();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0], Package::Review);
        assert_eq!(all[1], Package::Develop);
        assert_eq!(all[2], Package::Autopilot);
    }

    #[test]
    fn custom_extends_develop_inherits_directives() {
        let home = tempdir().unwrap();
        write_custom(
            home.path(),
            "team",
            r#"
[meta]
name = "team"
extends = "develop"

[[rules]]
action = "deny"
pattern = "npm publish"
message = "team rule: no publishing"
"#,
        );
        let pkg = Package::resolve("team", Some(home.path())).unwrap();
        let directives = package_directives(&pkg).unwrap();

        let config = Config::from_directives(directives);

        // Inherited from develop:
        let v = config.match_command("cargo test", None);
        assert!(v.is_some());
        assert_eq!(v.unwrap().decision, Decision::Allow);

        // Added by custom team package:
        let v = config.match_command("npm publish", None);
        assert!(v.is_some());
        assert_eq!(v.unwrap().decision, Decision::Deny);
    }

    #[test]
    fn custom_extends_unknown_package_errors() {
        let home = tempdir().unwrap();
        write_custom(
            home.path(),
            "bad",
            "[meta]\nname = \"bad\"\nextends = \"nope\"\n",
        );
        let pkg = Package::resolve("bad", Some(home.path())).unwrap();
        let err = package_directives(&pkg).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("nope"),
            "error should mention extends target: {msg}"
        );
    }

    #[test]
    fn custom_extends_custom_rejected() {
        // extends = "team" is not a built-in, so it's rejected even if a custom
        // package named "team" exists.
        let home = tempdir().unwrap();
        write_custom(home.path(), "team", "[meta]\nname = \"team\"\n");
        write_custom(
            home.path(),
            "derived",
            "[meta]\nname = \"derived\"\nextends = \"team\"\n",
        );
        let pkg = Package::resolve("derived", Some(home.path())).unwrap();
        let err = package_directives(&pkg).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("team"),
            "error should mention the rejected base: {msg}"
        );
    }

    #[test]
    fn custom_without_extends_has_only_own_rules() {
        let home = tempdir().unwrap();
        write_custom(
            home.path(),
            "solo",
            r#"
[meta]
name = "solo"

[[rules]]
action = "deny"
pattern = "rm -rf /"
"#,
        );
        let pkg = Package::resolve("solo", Some(home.path())).unwrap();
        let directives = package_directives(&pkg).unwrap();
        let config = Config::from_directives(directives);

        // The solo package does NOT inherit from develop, so `cargo test`
        // has no matching rule.
        let v = config.match_command("cargo test", None);
        assert!(v.is_none(), "solo should not inherit develop's rules");

        // Own rule still applies.
        let v = config.match_command("rm -rf /", None);
        assert!(v.is_some());
        assert_eq!(v.unwrap().decision, Decision::Deny);
    }
}
