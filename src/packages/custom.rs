//! Discovery and loading of user-defined custom packages from `~/.rippy/packages/`.
//!
//! Custom packages are ordinary `.rippy.toml` files with a `[meta]` section.
//! The filename (minus `.toml`) is the authoritative package name — the `[meta] name`
//! field in the file is informational and triggers a warning if it disagrees.
//!
//! Custom packages may `extends = "<builtin>"` to inherit from a built-in package.
//! Cycles are prevented structurally: custom packages can only extend built-ins,
//! never other custom packages.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::error::RippyError;
use crate::toml_config::TomlConfig;

/// A user-defined package loaded from `~/.rippy/packages/<name>.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomPackage {
    /// Package name (derived from the filename, not `[meta] name`).
    pub name: String,
    /// One-line description from `[meta] tagline`, or a default.
    pub tagline: String,
    /// Shield bar from `[meta] shield`, or a default.
    pub shield: String,
    /// Path the package was loaded from.
    pub path: PathBuf,
    /// Raw TOML contents, cached for directive generation.
    pub toml_source: String,
    /// Optional built-in package name to inherit rules from.
    pub extends: Option<String>,
}

/// The directory where custom packages live, relative to `$HOME`.
fn custom_packages_dir(home: &Path) -> PathBuf {
    home.join(".rippy/packages")
}

/// Scan `~/.rippy/packages/*.toml` and return metadata-loaded custom packages.
///
/// Malformed files are skipped with a stderr warning so callers like
/// `rippy profile list` stay robust in the presence of a single bad file.
#[must_use]
pub fn discover_custom_packages(home: &Path) -> Vec<Arc<CustomPackage>> {
    let dir = custom_packages_dir(home);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };

    let mut packages: Vec<Arc<CustomPackage>> = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !is_toml_file(&path) {
            continue;
        }
        let Some(name) = package_name_from_path(&path) else {
            continue;
        };
        match load_custom_package_from_path(&path, &name) {
            Ok(pkg) => packages.push(Arc::new(pkg)),
            Err(e) => eprintln!("[rippy] skipping custom package {}: {e}", path.display()),
        }
    }
    packages.sort_by(|a, b| a.name.cmp(&b.name));
    packages
}

/// Load a single custom package by name from `~/.rippy/packages/<name>.toml`.
///
/// Returns `Ok(None)` if no such file exists. Returns `Err` when the file
/// exists but cannot be read or contains malformed TOML.
///
/// # Errors
///
/// Returns `RippyError::Config` if the file is malformed or unreadable.
pub fn load_custom_package(
    home: &Path,
    name: &str,
) -> Result<Option<Arc<CustomPackage>>, RippyError> {
    let path = custom_packages_dir(home).join(format!("{name}.toml"));
    if !path.is_file() {
        return Ok(None);
    }
    let pkg = load_custom_package_from_path(&path, name)?;
    Ok(Some(Arc::new(pkg)))
}

fn load_custom_package_from_path(path: &Path, name: &str) -> Result<CustomPackage, RippyError> {
    let toml_source = std::fs::read_to_string(path).map_err(|e| RippyError::Config {
        path: path.to_path_buf(),
        line: 0,
        message: format!("could not read: {e}"),
    })?;
    let config: TomlConfig = toml::from_str(&toml_source).map_err(|e| RippyError::Config {
        path: path.to_path_buf(),
        line: 0,
        message: format!("{e}"),
    })?;

    let meta = config.meta.unwrap_or(crate::toml_config::TomlMeta {
        name: None,
        tagline: None,
        shield: None,
        description: None,
        extends: None,
    });

    if let Some(meta_name) = meta.name.as_deref()
        && meta_name != name
    {
        eprintln!(
            "[rippy] custom package {}: [meta] name=\"{meta_name}\" does not match filename \"{name}\" (filename wins)",
            path.display(),
        );
    }

    let tagline = meta
        .tagline
        .unwrap_or_else(|| format!("Custom package: {name}"));
    let shield = meta.shield.unwrap_or_else(|| "===".to_string());
    let extends = meta.extends;

    Ok(CustomPackage {
        name: name.to_string(),
        tagline,
        shield,
        path: path.to_path_buf(),
        toml_source,
        extends,
    })
}

fn is_toml_file(path: &Path) -> bool {
    path.extension().is_some_and(|ext| ext == "toml") && path.is_file()
}

fn package_name_from_path(path: &Path) -> Option<String> {
    path.file_stem()
        .and_then(|s| s.to_str())
        .map(std::string::ToString::to_string)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_file(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn discover_empty_dir_returns_empty() {
        let home = tempdir().unwrap();
        let packages = discover_custom_packages(home.path());
        assert!(packages.is_empty());
    }

    #[test]
    fn discover_missing_dir_returns_empty() {
        let home = tempdir().unwrap();
        // Do not create .rippy/packages/
        let packages = discover_custom_packages(home.path());
        assert!(packages.is_empty());
    }

    #[test]
    fn discover_finds_toml_files() {
        let home = tempdir().unwrap();
        let pkg_dir = home.path().join(".rippy/packages");
        write_file(
            &pkg_dir.join("corp.toml"),
            r#"
[meta]
name = "corp"
tagline = "Corporate standard"
shield = "===."

[[rules]]
action = "deny"
pattern = "rm -rf"
"#,
        );

        let packages = discover_custom_packages(home.path());
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "corp");
        assert_eq!(packages[0].tagline, "Corporate standard");
        assert_eq!(packages[0].shield, "===.");
        assert!(packages[0].extends.is_none());
    }

    #[test]
    fn discover_ignores_non_toml_files() {
        let home = tempdir().unwrap();
        let pkg_dir = home.path().join(".rippy/packages");
        write_file(&pkg_dir.join("notes.txt"), "some text");
        write_file(&pkg_dir.join("README"), "read me");

        let packages = discover_custom_packages(home.path());
        assert!(packages.is_empty());
    }

    #[test]
    fn discover_skips_malformed_returns_valid_only() {
        let home = tempdir().unwrap();
        let pkg_dir = home.path().join(".rippy/packages");
        write_file(&pkg_dir.join("good.toml"), "[meta]\nname = \"good\"\n");
        write_file(&pkg_dir.join("bad.toml"), "this is not valid toml [[");

        let packages = discover_custom_packages(home.path());
        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].name, "good");
    }

    #[test]
    fn discover_returns_sorted() {
        let home = tempdir().unwrap();
        let pkg_dir = home.path().join(".rippy/packages");
        write_file(&pkg_dir.join("zeta.toml"), "[meta]\nname = \"zeta\"\n");
        write_file(&pkg_dir.join("alpha.toml"), "[meta]\nname = \"alpha\"\n");
        write_file(&pkg_dir.join("mango.toml"), "[meta]\nname = \"mango\"\n");

        let packages = discover_custom_packages(home.path());
        let names: Vec<&str> = packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "mango", "zeta"]);
    }

    #[test]
    fn load_by_name_happy_path() {
        let home = tempdir().unwrap();
        let pkg_dir = home.path().join(".rippy/packages");
        write_file(
            &pkg_dir.join("team.toml"),
            r#"
[meta]
name = "team"
tagline = "Team package"
extends = "develop"
"#,
        );

        let pkg = load_custom_package(home.path(), "team").unwrap().unwrap();
        assert_eq!(pkg.name, "team");
        assert_eq!(pkg.tagline, "Team package");
        assert_eq!(pkg.extends.as_deref(), Some("develop"));
    }

    #[test]
    fn load_by_name_not_found_returns_none() {
        let home = tempdir().unwrap();
        let result = load_custom_package(home.path(), "missing").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn load_by_name_malformed_errors_with_path() {
        let home = tempdir().unwrap();
        let pkg_dir = home.path().join(".rippy/packages");
        write_file(&pkg_dir.join("broken.toml"), "not valid [[");

        let err = load_custom_package(home.path(), "broken").unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            msg.contains("broken.toml"),
            "error should mention path: {msg}"
        );
    }

    #[test]
    fn load_defaults_tagline_when_missing() {
        let home = tempdir().unwrap();
        let pkg_dir = home.path().join(".rippy/packages");
        write_file(
            &pkg_dir.join("plain.toml"),
            "[[rules]]\naction = \"ask\"\npattern = \"foo\"\n",
        );

        let pkg = load_custom_package(home.path(), "plain").unwrap().unwrap();
        assert!(pkg.tagline.contains("plain"));
        assert_eq!(pkg.shield, "===");
    }

    #[test]
    fn load_warns_when_meta_name_mismatch() {
        let home = tempdir().unwrap();
        let pkg_dir = home.path().join(".rippy/packages");
        // filename is "filename.toml", but [meta] name says "metaname"
        write_file(
            &pkg_dir.join("filename.toml"),
            "[meta]\nname = \"metaname\"\ntagline = \"Mismatch\"\n",
        );

        let pkg = load_custom_package(home.path(), "filename")
            .unwrap()
            .unwrap();
        // Filename wins
        assert_eq!(pkg.name, "filename");
    }
}
