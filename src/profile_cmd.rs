//! CLI commands for managing safety packages.
//!
//! Provides `rippy profile list`, `rippy profile show`, and `rippy profile set`.

use std::fmt::Write as _;
use std::path::Path;
use std::process::ExitCode;

use serde::Serialize;

use crate::cli::{ProfileArgs, ProfileTarget};
use crate::config::{self, ConfigDirective};
use crate::error::RippyError;
use crate::packages::{self, Package};

/// Run the profile subcommand.
///
/// # Errors
///
/// Returns `RippyError` on config I/O failures or invalid package names.
pub fn run(args: &ProfileArgs) -> Result<ExitCode, RippyError> {
    match &args.target {
        ProfileTarget::List { json } => list_profiles(*json),
        ProfileTarget::Show { name, json } => show_profile(name, *json),
        ProfileTarget::Set { name, project } => set_profile(name, *project),
    }
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct ProfileListEntry {
    name: String,
    shield: String,
    tagline: String,
    active: bool,
    #[serde(rename = "custom")]
    is_custom: bool,
}

fn list_profiles(json: bool) -> Result<ExitCode, RippyError> {
    let active = active_package_name();
    let home = config::home_dir();
    let packages = Package::all_available(home.as_deref());

    if json {
        let entries: Vec<ProfileListEntry> = packages
            .iter()
            .map(|p| ProfileListEntry {
                name: p.name().to_string(),
                shield: p.shield().to_string(),
                tagline: p.tagline().to_string(),
                active: active.as_deref() == Some(p.name()),
                is_custom: p.is_custom(),
            })
            .collect();
        let out = serde_json::to_string_pretty(&entries)
            .map_err(|e| RippyError::Setup(format!("JSON error: {e}")))?;
        println!("{out}");
        return Ok(ExitCode::SUCCESS);
    }

    let (builtins, customs): (Vec<&Package>, Vec<&Package>) =
        packages.iter().partition(|p| !p.is_custom());

    for pkg in &builtins {
        print_profile_line(pkg, active.as_deref());
    }
    if !customs.is_empty() {
        println!();
        println!("Custom packages:");
        for pkg in &customs {
            print_profile_line(pkg, active.as_deref());
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn print_profile_line(pkg: &Package, active: Option<&str>) {
    let marker = if active == Some(pkg.name()) {
        "  (active)"
    } else {
        ""
    };
    println!(
        "  {:<12}[{}]     {}{marker}",
        pkg.name(),
        pkg.shield(),
        pkg.tagline(),
    );
}

/// Read the currently active package from the merged config.
fn active_package_name() -> Option<String> {
    let cwd = std::env::current_dir().unwrap_or_default();
    let config = config::Config::load(&cwd, None).ok()?;
    config.active_package.map(|p| p.name().to_string())
}

// ---------------------------------------------------------------------------
// Show
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct ProfileShowOutput {
    name: String,
    shield: String,
    tagline: String,
    rules: Vec<RuleDisplay>,
    git_style: Option<String>,
    git_branches: Vec<BranchDisplay>,
}

#[derive(Debug, Serialize)]
struct RuleDisplay {
    action: String,
    description: String,
}

#[derive(Debug, Serialize)]
struct BranchDisplay {
    pattern: String,
    style: String,
}

fn show_profile(name: &str, json: bool) -> Result<ExitCode, RippyError> {
    let home = config::home_dir();
    let package = Package::resolve(name, home.as_deref())?;
    let directives = packages::package_directives(&package)?;

    let rules = extract_rule_displays(&directives);
    let (git_style, git_branches) = extract_git_info(&package);

    if json {
        let output = ProfileShowOutput {
            name: package.name().to_string(),
            shield: package.shield().to_string(),
            tagline: package.tagline().to_string(),
            rules,
            git_style,
            git_branches,
        };
        let out = serde_json::to_string_pretty(&output)
            .map_err(|e| RippyError::Setup(format!("JSON error: {e}")))?;
        println!("{out}");
        return Ok(ExitCode::SUCCESS);
    }

    println!("Package: {} [{}]", package.name(), package.shield());
    println!("  \"{}\"", package.tagline());
    println!();

    if !rules.is_empty() {
        println!("  Rules:");
        for rule in &rules {
            println!("    {:<6} {}", rule.action, rule.description);
        }
        println!();
    }

    if let Some(style) = &git_style {
        let mut git_line = format!("  Git: {style}");
        if !git_branches.is_empty() {
            let _ = write!(git_line, " (");
            for (i, b) in git_branches.iter().enumerate() {
                if i > 0 {
                    let _ = write!(git_line, ", ");
                }
                let _ = write!(git_line, "{} on {}", b.style, b.pattern);
            }
            let _ = write!(git_line, ")");
        }
        println!("{git_line}");
    }

    Ok(ExitCode::SUCCESS)
}

fn extract_rule_displays(directives: &[ConfigDirective]) -> Vec<RuleDisplay> {
    directives
        .iter()
        .filter_map(|d| {
            if let ConfigDirective::Rule(r) = d {
                Some(RuleDisplay {
                    action: r.decision.as_str().to_string(),
                    description: format_rule_description(r),
                })
            } else {
                None
            }
        })
        .collect()
}

fn format_rule_description(r: &crate::config::Rule) -> String {
    // Prefer structured matching fields over raw pattern.
    if let Some(cmd) = &r.command {
        let mut desc = cmd.clone();
        if let Some(sub) = &r.subcommand {
            desc = format!("{desc} {sub}");
        } else if let Some(subs) = &r.subcommands {
            desc = format!("{desc} {}", subs.join(", "));
        }
        if let Some(flags) = &r.flags {
            desc = format!("{desc} [{}]", flags.join(", "));
        }
        if let Some(ac) = &r.args_contain {
            desc = format!("{desc} (args contain \"{ac}\")");
        }
        if let Some(msg) = &r.message {
            desc = format!("{desc}  \"{msg}\"");
        }
        return desc;
    }

    let raw = r.pattern.raw();
    r.message
        .as_ref()
        .map_or_else(|| raw.to_string(), |msg| format!("{raw}  \"{msg}\""))
}

fn extract_git_info(package: &Package) -> (Option<String>, Vec<BranchDisplay>) {
    let source = packages::package_toml(package);
    let config: crate::toml_config::TomlConfig = match toml::from_str(source) {
        Ok(c) => c,
        Err(_) => return (None, Vec::new()),
    };
    let Some(git) = config.git else {
        return (None, Vec::new());
    };
    let branches = git
        .branches
        .iter()
        .map(|b| BranchDisplay {
            pattern: b.pattern.clone(),
            style: b.style.clone(),
        })
        .collect();
    (git.style, branches)
}

// ---------------------------------------------------------------------------
// Set
// ---------------------------------------------------------------------------

fn set_profile(name: &str, project: bool) -> Result<ExitCode, RippyError> {
    let home = config::home_dir();
    let _ = Package::resolve(name, home.as_deref())?;

    let path = resolve_config_path(project)?;
    write_package_setting(&path, name)?;

    if project {
        crate::trust::TrustGuard::before_write(&path).commit();
    }
    eprintln!("[rippy] Package set to \"{name}\" in {}", path.display());

    Ok(ExitCode::SUCCESS)
}

fn resolve_config_path(project: bool) -> Result<std::path::PathBuf, RippyError> {
    if project {
        Ok(std::path::PathBuf::from(".rippy.toml"))
    } else {
        config::home_dir()
            .map(|h| h.join(".rippy/config.toml"))
            .ok_or_else(|| RippyError::Setup("could not determine home directory".into()))
    }
}

/// Write `package = "<name>"` to a TOML config file.
///
/// If the file has an existing `package = ` line, it is replaced.
/// If the file has a `[settings]` section but no package, the line is inserted.
/// Otherwise, `[settings]\npackage = "<name>"` is prepended.
///
/// # Errors
///
/// Returns `RippyError::Setup` if the file cannot be read or written.
pub fn write_package_setting(path: &Path, package_name: &str) -> Result<(), RippyError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| {
            RippyError::Setup(format!("could not create {}: {e}", parent.display()))
        })?;
    }

    let existing = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(RippyError::Setup(format!(
                "could not read {}: {e}",
                path.display()
            )));
        }
    };

    let new_line = format!("package = \"{package_name}\"");
    let content = update_package_in_content(&existing, &new_line);

    std::fs::write(path, content)
        .map_err(|e| RippyError::Setup(format!("could not write {}: {e}", path.display())))
}

fn is_package_setting_line(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.starts_with("package =") || trimmed.starts_with("package=")
}

fn update_package_in_content(existing: &str, new_line: &str) -> String {
    // Case 1: Replace existing package line.
    if existing.lines().any(is_package_setting_line) {
        return existing
            .lines()
            .map(|l| {
                if is_package_setting_line(l) {
                    new_line.to_string()
                } else {
                    l.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + if existing.ends_with('\n') { "\n" } else { "" };
    }

    // Case 2: Has [settings] section — insert after it.
    if existing.contains("[settings]") {
        return existing
            .lines()
            .flat_map(|l| {
                if l.trim() == "[settings]" {
                    vec![l.to_string(), new_line.to_string()]
                } else {
                    vec![l.to_string()]
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
            + if existing.ends_with('\n') { "\n" } else { "" };
    }

    // Case 3: No settings section — prepend one.
    if existing.is_empty() {
        format!("[settings]\n{new_line}\n")
    } else {
        format!("[settings]\n{new_line}\n\n{existing}")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn update_empty_file() {
        let result = update_package_in_content("", "package = \"develop\"");
        assert_eq!(result, "[settings]\npackage = \"develop\"\n");
    }

    #[test]
    fn update_existing_package_line() {
        let existing = "[settings]\npackage = \"review\"\n";
        let result = update_package_in_content(existing, "package = \"develop\"");
        assert!(result.contains("package = \"develop\""));
        assert!(!result.contains("review"));
    }

    #[test]
    fn update_settings_section_no_package() {
        let existing = "[settings]\ndefault = \"ask\"\n";
        let result = update_package_in_content(existing, "package = \"develop\"");
        assert!(result.contains("[settings]"));
        assert!(result.contains("package = \"develop\""));
        assert!(result.contains("default = \"ask\""));
    }

    #[test]
    fn update_no_settings_section() {
        let existing = "[[rules]]\naction = \"allow\"\ncommand = \"ls\"\n";
        let result = update_package_in_content(existing, "package = \"develop\"");
        assert!(result.starts_with("[settings]\npackage = \"develop\""));
        assert!(result.contains("[[rules]]"));
    }

    #[test]
    fn update_does_not_clobber_similar_keys() {
        // Keys like package_version should not be matched by the package replacement.
        let existing = "[settings]\npackage_version = \"1.0\"\ndefault = \"ask\"\n";
        let result = update_package_in_content(existing, "package = \"develop\"");
        assert!(
            result.contains("package_version = \"1.0\""),
            "package_version should be preserved, got: {result}"
        );
        assert!(result.contains("package = \"develop\""));
    }

    #[test]
    fn update_handles_no_space_before_equals() {
        let existing = "[settings]\npackage=\"review\"\n";
        let result = update_package_in_content(existing, "package = \"develop\"");
        assert!(result.contains("package = \"develop\""));
        assert!(!result.contains("review"));
    }

    #[test]
    fn write_package_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write_package_setting(&path, "develop").unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("package = \"develop\""));
        assert!(content.contains("[settings]"));
    }

    #[test]
    fn write_package_updates_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[settings]\npackage = \"review\"\n").unwrap();

        write_package_setting(&path, "autopilot").unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("package = \"autopilot\""));
        assert!(!content.contains("review"));
    }
}
