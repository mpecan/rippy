//! Convert legacy `.rippy` config files to TOML format.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::cli::MigrateArgs;
use crate::config::ConfigDirective;
use crate::error::RippyError;
use crate::toml_config::rules_to_toml;

/// Run the `rippy migrate` subcommand.
///
/// # Errors
///
/// Returns `RippyError` if the input config cannot be read/parsed
/// or the output cannot be written.
pub fn run(args: &MigrateArgs) -> Result<ExitCode, RippyError> {
    let input_path = resolve_input_path(args)?;
    let rules = parse_legacy_file(&input_path)?;
    let toml_output = rules_to_toml(&rules);

    if args.stdout {
        print!("{toml_output}");
    } else {
        let output_path = derive_output_path(&input_path);
        std::fs::write(&output_path, &toml_output).map_err(|e| {
            RippyError::Setup(format!("could not write {}: {e}", output_path.display()))
        })?;
        crate::trust::TrustGuard::for_new_file(&output_path).commit();
        eprintln!(
            "[rippy] Converted {} -> {}",
            input_path.display(),
            output_path.display()
        );
    }

    Ok(ExitCode::SUCCESS)
}

/// Resolve the input config file path.
fn resolve_input_path(args: &MigrateArgs) -> Result<PathBuf, RippyError> {
    if let Some(path) = &args.path {
        return Ok(path.clone());
    }

    // Walk up from cwd looking for .rippy or .dippy (legacy formats only).
    let cwd = std::env::current_dir().map_err(|e| RippyError::Setup(format!("no cwd: {e}")))?;
    let mut dir = cwd.as_path();
    loop {
        let rippy = dir.join(".rippy");
        if rippy.is_file() {
            return Ok(rippy);
        }
        let dippy = dir.join(".dippy");
        if dippy.is_file() {
            return Ok(dippy);
        }
        dir = dir
            .parent()
            .ok_or_else(|| RippyError::Setup("no .rippy or .dippy config found".to_string()))?;
    }
}

/// Derive the output `.rippy.toml` path from the input path.
fn derive_output_path(input: &Path) -> PathBuf {
    input
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(".rippy.toml")
}

/// Parse a legacy line-based config file into directives.
fn parse_legacy_file(path: &Path) -> Result<Vec<ConfigDirective>, RippyError> {
    let content = std::fs::read_to_string(path).map_err(|e| RippyError::Config {
        path: path.to_owned(),
        line: 0,
        message: format!("could not read: {e}"),
    })?;

    let mut directives = Vec::new();
    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let directive = crate::config::parse_rule(line).map_err(|msg| RippyError::Config {
            path: path.to_owned(),
            line: line_num + 1,
            message: msg,
        })?;
        directives.push(directive);
    }

    Ok(directives)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn migrate_basic_config() {
        let dir = tempfile::TempDir::new().unwrap();
        let input = dir.path().join(".rippy");
        std::fs::write(
            &input,
            "allow git status\ndeny rm -rf \"use trash instead\"\nset default ask\n",
        )
        .unwrap();

        let directives = parse_legacy_file(&input).unwrap();
        let toml = rules_to_toml(&directives);

        // Verify the TOML is valid and round-trips.
        let re_parsed =
            crate::toml_config::parse_toml_config(&toml, Path::new("test.toml")).unwrap();
        let config = crate::config::Config::from_directives(re_parsed);
        assert_eq!(
            config.match_command("git status", None).unwrap().decision,
            crate::verdict::Decision::Allow,
        );
        assert_eq!(
            config.match_command("rm -rf /tmp", None).unwrap().decision,
            crate::verdict::Decision::Deny,
        );
        assert_eq!(config.default_action, Some(crate::verdict::Decision::Ask));
    }

    #[test]
    fn derive_output_path_sibling() {
        let out = derive_output_path(Path::new("/home/user/project/.rippy"));
        assert_eq!(out, PathBuf::from("/home/user/project/.rippy.toml"));
    }

    #[test]
    fn derive_output_path_bare() {
        let out = derive_output_path(Path::new(".rippy"));
        assert_eq!(out, PathBuf::from(".rippy.toml"));
    }
}
