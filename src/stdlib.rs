//! Embedded stdlib rules — default safety rules shipped with the binary.
//!
//! These are loaded as the lowest-priority tier in the config system.
//! User and project config override stdlib rules via last-match-wins.

use std::io::Write as _;
use std::path::Path;
use std::process::ExitCode;

use crate::cli::InitArgs;
use crate::config::{self, ConfigDirective};
use crate::error::RippyError;
use crate::packages::Package;

// Simple tool rules (split from simple.toml)
const CARGO_TOML: &str = include_str!("stdlib/cargo.toml");
const BREW_TOML: &str = include_str!("stdlib/brew.toml");
const PIP_TOML: &str = include_str!("stdlib/pip.toml");
const TERRAFORM_TOML: &str = include_str!("stdlib/terraform.toml");
const PYTEST_TOML: &str = include_str!("stdlib/pytest.toml");
const MAKE_TOML: &str = include_str!("stdlib/make.toml");
const RUSTUP_TOML: &str = include_str!("stdlib/rustup.toml");
const OPENSSL_TOML: &str = include_str!("stdlib/openssl.toml");

// File operations
const FILE_OPS_TOML: &str = include_str!("stdlib/file_ops.toml");

// Dangerous command rules (split from dangerous.toml)
const BUILTINS_TOML: &str = include_str!("stdlib/builtins.toml");
const SUDO_TOML: &str = include_str!("stdlib/sudo.toml");
const SSH_TOML: &str = include_str!("stdlib/ssh.toml");
const INTERPRETERS_TOML: &str = include_str!("stdlib/interpreters.toml");
const PACKAGE_MANAGERS_TOML: &str = include_str!("stdlib/package_managers.toml");

/// All embedded stdlib TOML sources in loading order.
const STDLIB_SOURCES: &[(&str, &str)] = &[
    // Simple tools
    ("(stdlib:cargo)", CARGO_TOML),
    ("(stdlib:brew)", BREW_TOML),
    ("(stdlib:pip)", PIP_TOML),
    ("(stdlib:terraform)", TERRAFORM_TOML),
    ("(stdlib:pytest)", PYTEST_TOML),
    ("(stdlib:make)", MAKE_TOML),
    ("(stdlib:rustup)", RUSTUP_TOML),
    ("(stdlib:openssl)", OPENSSL_TOML),
    // File operations
    ("(stdlib:file_ops)", FILE_OPS_TOML),
    // Dangerous commands
    ("(stdlib:builtins)", BUILTINS_TOML),
    ("(stdlib:sudo)", SUDO_TOML),
    ("(stdlib:ssh)", SSH_TOML),
    ("(stdlib:interpreters)", INTERPRETERS_TOML),
    ("(stdlib:package_managers)", PACKAGE_MANAGERS_TOML),
];

/// Parse all embedded stdlib TOML into config directives.
///
/// # Errors
///
/// Returns `RippyError::Config` if any embedded TOML is malformed (a build bug).
pub fn stdlib_directives() -> Result<Vec<ConfigDirective>, RippyError> {
    let mut directives = Vec::new();
    for (label, source) in STDLIB_SOURCES {
        let parsed = crate::toml_config::parse_toml_config(source, Path::new(label))?;
        directives.extend(parsed);
    }
    Ok(directives)
}

/// Return the concatenated raw TOML for all stdlib files.
#[must_use]
pub fn stdlib_toml() -> String {
    let mut out = String::new();
    for (_, source) in STDLIB_SOURCES {
        out.push_str(source);
        out.push('\n');
    }
    out
}

/// Run the `rippy init` command — create config with a safety package.
///
/// # Errors
///
/// Returns `RippyError::Setup` if the file cannot be written.
pub fn run_init(args: &InitArgs) -> Result<ExitCode, RippyError> {
    if args.stdout {
        print!("{}", stdlib_toml());
        return Ok(ExitCode::SUCCESS);
    }

    let package = resolve_init_package(args)?;

    let path = if args.global {
        config::home_dir()
            .map(|h| h.join(".rippy/config.toml"))
            .ok_or_else(|| RippyError::Setup("could not determine home directory".into()))?
    } else {
        std::path::PathBuf::from(".rippy.toml")
    };

    if path.exists() {
        return Err(RippyError::Setup(format!(
            "{} already exists. Remove it first or edit manually.",
            path.display()
        )));
    }

    crate::profile_cmd::write_package_setting(&path, package.name())?;

    if !args.global {
        crate::trust::TrustGuard::for_new_file(&path).commit();
    }

    eprintln!(
        "[rippy] Created {} with package \"{}\"\n  \
         \"{}\"\n  \
         Run `rippy profile show {}` for details, or edit {} to customize.",
        path.display(),
        package.name(),
        package.tagline(),
        package.name(),
        path.display(),
    );
    Ok(ExitCode::SUCCESS)
}

/// Determine which package to use: from `--package` flag, interactive prompt,
/// or default to `develop` when stdin is not a terminal.
fn resolve_init_package(args: &InitArgs) -> Result<Package, RippyError> {
    if let Some(name) = &args.package {
        return Package::parse(name).map_err(RippyError::Setup);
    }

    if is_interactive() {
        return prompt_package_selection();
    }

    // Non-interactive: default to develop.
    Ok(Package::Develop)
}

fn is_interactive() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal()
}

fn prompt_package_selection() -> Result<Package, RippyError> {
    eprintln!("\nWhich package fits your workflow?\n");
    for (i, pkg) in Package::all().iter().enumerate() {
        let recommended = if *pkg == Package::Develop {
            "  (recommended)"
        } else {
            ""
        };
        eprintln!(
            "  [{}] {:<12}[{}]  {}{recommended}",
            i + 1,
            pkg.name(),
            pkg.shield(),
            pkg.tagline(),
        );
    }
    eprint!("\nSelect [1-3] (default: 2): ");
    let _ = std::io::stderr().flush();

    let mut input = String::new();
    if std::io::stdin().read_line(&mut input).is_err() {
        return Ok(Package::Develop);
    }

    match input.trim() {
        "" | "2" => Ok(Package::Develop),
        "1" => Ok(Package::Review),
        "3" => Ok(Package::Autopilot),
        other => Package::parse(other).map_err(RippyError::Setup),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::verdict::Decision;

    #[test]
    fn stdlib_parses_without_error() {
        let directives = stdlib_directives().unwrap();
        assert!(!directives.is_empty());
    }

    #[test]
    fn stdlib_cargo_safe_subcommands() {
        let config = Config::from_directives(stdlib_directives().unwrap());
        let v = config.match_command("cargo test --release", None);
        assert!(v.is_some());
        assert_eq!(v.unwrap().decision, Decision::Allow);
    }

    #[test]
    fn stdlib_cargo_ask_subcommands() {
        let config = Config::from_directives(stdlib_directives().unwrap());
        let v = config.match_command("cargo run", None);
        assert!(v.is_some());
        assert_eq!(v.unwrap().decision, Decision::Ask);
    }

    #[test]
    fn stdlib_cargo_unknown_defaults_to_ask() {
        let config = Config::from_directives(stdlib_directives().unwrap());
        let v = config.match_command("cargo some-unknown-subcommand", None);
        assert!(v.is_some());
        assert_eq!(v.unwrap().decision, Decision::Ask);
    }

    #[test]
    fn stdlib_file_ops_ask() {
        let config = Config::from_directives(stdlib_directives().unwrap());
        for cmd in &["rm -rf /tmp/test", "mv a b", "chmod 755 file"] {
            let v = config.match_command(cmd, None);
            assert!(v.is_some(), "expected match for {cmd}");
            assert_eq!(v.unwrap().decision, Decision::Ask, "expected ask for {cmd}");
        }
    }

    #[test]
    fn stdlib_dangerous_commands_ask() {
        let config = Config::from_directives(stdlib_directives().unwrap());
        for cmd in &["sudo apt install foo", "ssh user@host", "eval echo hi"] {
            let v = config.match_command(cmd, None);
            assert!(v.is_some(), "expected match for {cmd}");
            assert_eq!(v.unwrap().decision, Decision::Ask, "expected ask for {cmd}");
        }
    }

    #[test]
    fn stdlib_toml_not_empty() {
        let toml = stdlib_toml();
        assert!(toml.contains("[[rules]]"));
        assert!(toml.contains("cargo"));
    }

    #[test]
    fn init_refuses_existing_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join(".rippy.toml");
        std::fs::write(&path, "existing").unwrap();

        let original = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        let result = run_init(&InitArgs {
            global: false,
            stdout: false,
            package: Some("develop".into()),
        });
        std::env::set_current_dir(original).unwrap();

        assert!(result.is_err());
    }
}
