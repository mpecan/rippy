//! Self-protection: prevent AI tools from modifying rippy's own config files.
//!
//! These checks run **before** any user-configurable rules and cannot be
//! overridden by config. The only escape hatch is `set self-protect off`
//! (which requires manual editing of the config file).

/// Filenames that are always protected (matched against the last component).
const PROTECTED_BASENAMES: &[&str] = &[".rippy", ".rippy.toml", ".dippy"];

/// Directories whose contents are rippy config: a custom package carries rules
/// and settings, and the active one is chosen by config.
const PROTECTED_DIRS: &[&str] = &[".rippy/packages"];

/// Config files matched against the path's trailing components.
const PROTECTED_SUFFIXES: &[&str] = &[
    ".rippy/config",
    ".rippy/config.toml",
    ".rippy/trusted.json",
    ".dippy/config",
];

/// Message returned when a protected file is denied.
pub const PROTECTION_MESSAGE: &str = "rippy configuration files are protected from \
     modification. To disable self-protection, manually add `set self-protect off` to \
     your config.";

/// Check if a file path targets a protected rippy configuration file.
///
/// The path is normalised lexically first (`.`, `..` and repeated `/` are
/// resolved, and case is folded because macOS and Windows file systems ignore
/// it), then matched by whole components against:
/// - basenames: `.rippy`, `.rippy.toml`, `.dippy`
/// - trailing components: `.rippy/config`, `.rippy/config.toml`, `.rippy/trusted.json`,
///   `.dippy/config`
/// - directories: anything in or naming `.rippy/packages`
#[must_use]
pub fn is_protected_path(path: &str) -> bool {
    let parts = normalized_components(path);
    let parts: Vec<&str> = parts.iter().map(String::as_str).collect();
    if parts
        .last()
        .is_some_and(|name| PROTECTED_BASENAMES.contains(name))
    {
        return true;
    }
    PROTECTED_DIRS
        .iter()
        .any(|dir| parts.windows(pattern(dir).len()).any(|w| w == pattern(dir)))
        || PROTECTED_SUFFIXES
            .iter()
            .any(|suffix| parts.ends_with(&pattern(suffix)))
}

fn pattern(p: &str) -> Vec<&str> {
    p.split('/').collect()
}

/// Lower-cased path components with `.`, `..` and empty segments resolved.
fn normalized_components(path: &str) -> Vec<String> {
    let mut parts: Vec<String> = Vec::new();
    for part in path.split(['/', '\\']) {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(part.to_lowercase()),
        }
    }
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_packages_are_protected() {
        assert!(is_protected_path("/home/u/.rippy/packages/evil.toml"));
        assert!(is_protected_path("~/.rippy/packages/x.toml"));
        assert!(is_protected_path("/home/u/.rippy/packages"));
        assert!(!is_protected_path("/home/u/project/packages/x.toml"));
    }

    #[test]
    fn spelling_variants_are_normalised() {
        assert!(is_protected_path("/home/u/.rippy//config.toml"));
        assert!(is_protected_path("/home/u/.rippy/./config.toml"));
        assert!(is_protected_path("/home/u/.rippy/x/../config.toml"));
        assert!(is_protected_path("/home/u/.rippy/packages/./evil.toml"));
        assert!(is_protected_path("/home/u/.RIPPY/Config.toml"));
        assert!(is_protected_path("/home/u/.rippy/packages/"));
        assert!(is_protected_path("proj/.Rippy.TOML"));
    }

    #[test]
    fn only_whole_components_match() {
        assert!(!is_protected_path("/home/u/not.rippy/config.toml"));
        assert!(!is_protected_path("/home/u/x.rippy/packages/a.toml"));
        assert!(!is_protected_path("/home/u/.rippy/config.toml.bak"));
        assert!(!is_protected_path("/home/u/.rippy/packages-old/a.toml"));
    }

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
    fn protects_trust_database() {
        assert!(is_protected_path("/home/user/.rippy/trusted.json"));
        assert!(is_protected_path(".rippy/trusted.json"));
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
