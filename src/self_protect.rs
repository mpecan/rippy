//! Self-protection: prevent AI tools from modifying rippy's own config files.
//!
//! These checks run **before** any user-configurable rules and cannot be
//! overridden by config. The only escape hatch is `set self-protect off`
//! (which requires manual editing of the config file).

use std::path::Path;

/// Filenames that are always protected (matched against basename).
const PROTECTED_BASENAMES: &[&str] = &[".rippy", ".rippy.toml", ".dippy"];

/// Subdirectory paths that are always protected (matched against suffix).
const PROTECTED_SUFFIXES: &[&str] = &[".rippy/config", ".rippy/config.toml", ".dippy/config"];

/// Message returned when a protected file is denied.
pub const PROTECTION_MESSAGE: &str = "rippy configuration files are protected from modification. To disable self-protection, manually add `set self-protect off` to your config.";

/// Check if a file path targets a protected rippy configuration file.
///
/// Matches against:
/// - Exact basename: `.rippy`, `.rippy.toml`, `.dippy`
/// - Path suffixes: `.rippy/config`, `.rippy/config.toml`, `.dippy/config`
#[must_use]
pub fn is_protected_path(path: &str) -> bool {
    let path = Path::new(path);

    if path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|name| PROTECTED_BASENAMES.contains(&name))
    {
        return true;
    }

    // Check if the path ends with a protected suffix.
    let path_str = path.to_string_lossy();
    PROTECTED_SUFFIXES
        .iter()
        .any(|suffix| path_str.ends_with(suffix))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn protects_rippy_config() {
        assert!(is_protected_path(".rippy"));
        assert!(is_protected_path(".rippy.toml"));
        assert!(is_protected_path(".dippy"));
    }

    #[test]
    fn protects_with_directory_prefix() {
        assert!(is_protected_path("/home/user/project/.rippy"));
        assert!(is_protected_path("some/path/.rippy.toml"));
        assert!(is_protected_path("/tmp/.dippy"));
    }

    #[test]
    fn protects_global_config() {
        assert!(is_protected_path("/home/user/.rippy/config"));
        assert!(is_protected_path("/home/user/.rippy/config.toml"));
        assert!(is_protected_path("/home/user/.dippy/config"));
    }

    #[test]
    fn does_not_protect_unrelated_files() {
        assert!(!is_protected_path("main.rs"));
        assert!(!is_protected_path("/tmp/output.txt"));
        assert!(!is_protected_path(".env"));
        assert!(!is_protected_path("config.toml"));
        assert!(!is_protected_path("rippy.rs"));
    }

    #[test]
    fn does_not_protect_partial_matches() {
        assert!(!is_protected_path(".rippy_backup"));
        assert!(!is_protected_path("not.rippy"));
        // .rippy.toml is protected (exact basename match)
        assert!(is_protected_path(".rippy.toml"));
    }
}
