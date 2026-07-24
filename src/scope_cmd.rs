//! CLI handler for `rippy scope` — manage safe scope directories.
//!
//! Safe scopes are directories the user explicitly trusts for cross-repo work.
//! Within a declared scope, path-based reads (`cd`, `git -C … log`) stop
//! prompting; writes still ask. Scopes are opt-in and, when declared in a
//! project config, require `rippy trust` before they take effect.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::cli::{ScopeArgs, ScopeTarget};
use crate::config;
use crate::error::RippyError;

/// Run the `rippy scope` subcommand.
///
/// # Errors
///
/// Returns `RippyError::Setup` if the config file cannot be read or written, or
/// if the supplied directory fails validation.
pub fn run(args: &ScopeArgs) -> Result<ExitCode, RippyError> {
    match &args.target {
        ScopeTarget::Add { dir, global } => add(dir, *global),
        ScopeTarget::Remove { dir, global } => remove(dir, *global),
        ScopeTarget::List { global } => list(*global),
    }
}

fn resolve_config_path(global: bool) -> Result<PathBuf, RippyError> {
    if global {
        config::home_dir()
            .map(|h| h.join(".rippy/config.toml"))
            .ok_or_else(|| RippyError::Setup("could not determine home directory".into()))
    } else {
        Ok(PathBuf::from(".rippy.toml"))
    }
}

fn add(dir: &str, global: bool) -> Result<ExitCode, RippyError> {
    let expanded = config::validate_safe_scope(dir, config::home_dir().as_deref())
        .map_err(RippyError::Setup)?;
    let path = resolve_config_path(global)?;

    let guard = (!global).then(|| crate::trust::TrustGuard::before_write(&path));
    let added = add_to_file(&path, dir)?;
    if let Some(g) = guard {
        g.commit();
    }

    if added {
        eprintln!(
            "[rippy] added safe scope to {}:\n  {dir}  (expands to {})",
            path.display(),
            expanded.display()
        );
        if !global {
            eprintln!("[rippy] note: project scopes take effect only after `rippy trust`");
        }
    } else {
        eprintln!(
            "[rippy] {dir} is already a declared safe scope in {}",
            path.display()
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn remove(dir: &str, global: bool) -> Result<ExitCode, RippyError> {
    let path = resolve_config_path(global)?;
    let guard = (!global).then(|| crate::trust::TrustGuard::before_write(&path));
    let removed = remove_from_file(&path, dir)?;
    if let Some(g) = guard {
        g.commit();
    }

    if removed {
        eprintln!("[rippy] removed safe scope {dir} from {}", path.display());
        Ok(ExitCode::SUCCESS)
    } else {
        eprintln!(
            "[rippy] {dir} is not a declared safe scope in {}",
            path.display()
        );
        Ok(ExitCode::from(1))
    }
}

fn list(global: bool) -> Result<ExitCode, RippyError> {
    let path = resolve_config_path(global)?;
    let scopes = list_from_file(&path)?;
    if scopes.is_empty() {
        eprintln!("[rippy] no safe scopes declared in {}", path.display());
    } else {
        eprintln!("[rippy] safe scopes in {}:", path.display());
        for s in &scopes {
            eprintln!("  {s}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// File operations (path-explicit for testability)
// ---------------------------------------------------------------------------

/// Read the `[scopes] safe` array from a config file. Returns an empty list if
/// the file or section is absent.
///
/// # Errors
///
/// Returns `RippyError::Setup` if the file exists but is not valid TOML.
pub fn list_from_file(path: &Path) -> Result<Vec<String>, RippyError> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(RippyError::Setup(format!(
                "could not read {}: {e}",
                path.display()
            )));
        }
    };
    read_scopes(&content, path)
}

fn read_scopes(content: &str, path: &Path) -> Result<Vec<String>, RippyError> {
    if content.trim().is_empty() {
        return Ok(Vec::new());
    }
    let value: toml::Value = toml::from_str(content)
        .map_err(|e| RippyError::Setup(format!("could not parse {}: {e}", path.display())))?;
    let scopes = value
        .get("scopes")
        .and_then(|s| s.get("safe"))
        .and_then(toml::Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Ok(scopes)
}

/// Add a directory to the `[scopes] safe` array. Returns `true` if it was added,
/// `false` if it was already present.
///
/// # Errors
///
/// Returns `RippyError::Setup` on read/parse/write failure.
pub fn add_to_file(path: &Path, dir: &str) -> Result<bool, RippyError> {
    let existing = read_content(path)?;
    let mut scopes = read_scopes(&existing, path)?;
    if scopes.iter().any(|s| s == dir) {
        return Ok(false);
    }
    scopes.push(dir.to_string());
    write_scopes(path, &existing, &scopes)?;
    Ok(true)
}

/// Remove a directory from the `[scopes] safe` array. Returns `true` if an entry
/// was removed.
///
/// # Errors
///
/// Returns `RippyError::Setup` on read/parse/write failure.
pub fn remove_from_file(path: &Path, dir: &str) -> Result<bool, RippyError> {
    let existing = read_content(path)?;
    let mut scopes = read_scopes(&existing, path)?;
    let before = scopes.len();
    scopes.retain(|s| s != dir);
    if scopes.len() == before {
        return Ok(false);
    }
    write_scopes(path, &existing, &scopes)?;
    Ok(true)
}

fn read_content(path: &Path) -> Result<String, RippyError> {
    match std::fs::read_to_string(path) {
        Ok(c) => Ok(c),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(RippyError::Setup(format!(
            "could not read {}: {e}",
            path.display()
        ))),
    }
}

fn write_scopes(path: &Path, existing: &str, scopes: &[String]) -> Result<(), RippyError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| {
            RippyError::Setup(format!("could not create {}: {e}", parent.display()))
        })?;
    }
    let content = build_content(existing, scopes);
    std::fs::write(path, content)
        .map_err(|e| RippyError::Setup(format!("could not write {}: {e}", path.display())))
}

/// Rebuild file content: strip any existing `[scopes]` section and re-append a
/// fresh one carrying `scopes`. Other sections and content are preserved.
fn build_content(existing: &str, scopes: &[String]) -> String {
    let base = strip_scopes_section(existing);
    let base = base.trim_end();
    if scopes.is_empty() {
        return if base.is_empty() {
            String::new()
        } else {
            format!("{base}\n")
        };
    }
    let block = render_scopes_block(scopes);
    if base.is_empty() {
        block
    } else {
        format!("{base}\n\n{block}")
    }
}

fn render_scopes_block(scopes: &[String]) -> String {
    let items = scopes
        .iter()
        .map(|s| format!("{s:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[scopes]\nsafe = [{items}]\n")
}

/// Drop any existing scopes declaration from `content` so a fresh one can be
/// appended without producing a duplicate (invalid) `scopes` table.
///
/// Handles the canonical `[scopes]` header form (this is what the CLI writes)
/// and a root-level dotted `scopes.safe = [...]` key. Both feed `read_scopes`
/// via the real TOML parser, so both must be stripped here for the rewrite to
/// stay consistent with the read path.
fn strip_scopes_section(content: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    let mut skipping = false;
    let mut at_root = true;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed == "[scopes]" {
            skipping = true;
            at_root = false;
            continue;
        }
        if trimmed.starts_with('[') {
            skipping = false;
            at_root = false;
            out.push(line);
            continue;
        }
        if skipping || (at_root && is_root_scopes_dotted_key(trimmed)) {
            continue;
        }
        out.push(line);
    }
    out.join("\n")
}

/// Whether `trimmed` is a root-level dotted `scopes.<key> = …` assignment,
/// which declares the same table as a `[scopes]` header.
fn is_root_scopes_dotted_key(trimmed: &str) -> bool {
    trimmed.starts_with("scopes.") && trimmed.contains('=')
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn tmp() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join(".rippy.toml");
        (dir, path)
    }

    #[test]
    fn add_then_list() {
        let (_d, path) = tmp();
        assert!(add_to_file(&path, "/opt/repos").unwrap());
        let scopes = list_from_file(&path).unwrap();
        assert_eq!(scopes, vec!["/opt/repos".to_string()]);
    }

    #[test]
    fn add_is_idempotent() {
        let (_d, path) = tmp();
        assert!(add_to_file(&path, "/opt/repos").unwrap());
        assert!(!add_to_file(&path, "/opt/repos").unwrap());
        assert_eq!(list_from_file(&path).unwrap().len(), 1);
    }

    #[test]
    fn add_appends_second() {
        let (_d, path) = tmp();
        add_to_file(&path, "/opt/a").unwrap();
        add_to_file(&path, "/opt/b").unwrap();
        assert_eq!(
            list_from_file(&path).unwrap(),
            vec!["/opt/a".to_string(), "/opt/b".to_string()]
        );
    }

    #[test]
    fn remove_deletes_entry() {
        let (_d, path) = tmp();
        add_to_file(&path, "/opt/a").unwrap();
        add_to_file(&path, "/opt/b").unwrap();
        assert!(remove_from_file(&path, "/opt/a").unwrap());
        assert_eq!(list_from_file(&path).unwrap(), vec!["/opt/b".to_string()]);
    }

    #[test]
    fn remove_absent_returns_false() {
        let (_d, path) = tmp();
        add_to_file(&path, "/opt/a").unwrap();
        assert!(!remove_from_file(&path, "/opt/missing").unwrap());
    }

    #[test]
    fn add_preserves_other_sections() {
        let (_d, path) = tmp();
        std::fs::write(&path, "[settings]\ndefault = \"ask\"\n\n[[rules]]\naction = \"deny\"\npattern = \"rm -rf *\"\n").unwrap();
        add_to_file(&path, "/opt/repos").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        // Still valid TOML with the rule intact and the scope present.
        let parsed: toml::Value = toml::from_str(&content).unwrap();
        assert!(parsed.get("settings").is_some());
        assert_eq!(parsed["rules"].as_array().unwrap().len(), 1);
        assert_eq!(
            list_from_file(&path).unwrap(),
            vec!["/opt/repos".to_string()]
        );
    }

    #[test]
    fn add_updates_existing_scopes_section() {
        let (_d, path) = tmp();
        std::fs::write(&path, "[scopes]\nsafe = [\"/opt/a\"]\n").unwrap();
        add_to_file(&path, "/opt/b").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        // No duplicate [scopes] header.
        assert_eq!(content.matches("[scopes]").count(), 1);
        assert_eq!(
            list_from_file(&path).unwrap(),
            vec!["/opt/a".to_string(), "/opt/b".to_string()]
        );
    }

    #[test]
    fn remove_last_leaves_empty_array() {
        let (_d, path) = tmp();
        add_to_file(&path, "/opt/a").unwrap();
        remove_from_file(&path, "/opt/a").unwrap();
        assert!(list_from_file(&path).unwrap().is_empty());
        // File must remain valid TOML.
        let content = std::fs::read_to_string(&path).unwrap();
        let _parsed: toml::Value = toml::from_str(&content).unwrap();
    }

    #[test]
    fn validate_rejects_root_and_empty() {
        assert!(config::validate_safe_scope("/", None).is_err());
        assert!(config::validate_safe_scope("", None).is_err());
    }

    #[test]
    fn validate_rejects_relative() {
        assert!(config::validate_safe_scope("relative/dir", None).is_err());
    }

    #[test]
    fn validate_rejects_home_root() {
        let home = Path::new("/home/alice");
        assert!(config::validate_safe_scope("~", Some(home)).is_err());
    }

    #[test]
    fn validate_accepts_expanded_tilde() {
        let home = Path::new("/home/alice");
        let got = config::validate_safe_scope("~/src", Some(home)).unwrap();
        assert_eq!(got, PathBuf::from("/home/alice/src"));
    }

    #[test]
    fn resolve_config_path_project_is_local() {
        assert_eq!(
            resolve_config_path(false).unwrap(),
            PathBuf::from(".rippy.toml")
        );
    }

    #[test]
    fn resolve_config_path_global_under_home() {
        // Home resolution reads $HOME, which the test process has set.
        if let Ok(path) = resolve_config_path(true) {
            assert!(
                path.ends_with(".rippy/config.toml"),
                "unexpected global path: {}",
                path.display()
            );
        }
    }

    #[test]
    fn add_replaces_root_dotted_scopes_key() {
        // A hand-edited root-level `scopes.safe = [...]` (dotted-key form) must be
        // stripped on rewrite so we don't emit a duplicate scopes declaration.
        let (_d, path) = tmp();
        std::fs::write(&path, "scopes.safe = [\"/opt/a\"]\n").unwrap();
        add_to_file(&path, "/opt/b").unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        // Still valid TOML (a duplicate scopes table would fail to parse).
        let _parsed: toml::Value = toml::from_str(&content).unwrap();
        assert_eq!(
            list_from_file(&path).unwrap(),
            vec!["/opt/a".to_string(), "/opt/b".to_string()]
        );
    }

    #[test]
    fn remove_cli_absent_exits_nonzero() {
        // `scope remove` of an undeclared entry reports failure (ExitCode 1).
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join(".rippy.toml");
        std::fs::write(&path, "[scopes]\nsafe = [\"/opt/a\"]\n").unwrap();
        assert!(!remove_from_file(&path, "/opt/never").unwrap());
    }
}
