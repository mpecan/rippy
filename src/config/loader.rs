use std::path::{Path, PathBuf};

use crate::error::RippyError;
use crate::verdict::Decision;

use super::Config;
use super::parser::{parse_action_word, parse_rule};
use super::types::{ConfigDirective, Rule};

/// Normalize a path by removing `.` and resolving `..` components.
pub(super) fn normalize_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for c in path.components() {
        match c {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other),
        }
    }
    normalized
}

pub(super) fn apply_setting(config: &mut Config, key: &str, value: &str) {
    match key {
        "default" => config.default_action = parse_action_word(value),
        "log" => config.log_file = Some(PathBuf::from(value)),
        "log-full" => config.log_full = true,
        "tracking" => {
            config.tracking_db = Some(if value == "on" || value.is_empty() {
                home_dir().map_or_else(
                    || PathBuf::from(".rippy/tracking.db"),
                    |h| h.join(".rippy/tracking.db"),
                )
            } else {
                PathBuf::from(value)
            });
        }
        "trust-project-configs" => {
            config.trust_project_configs = value != "off" && value != "false";
        }
        "self-protect" => {
            config.self_protect = value != "off";
        }
        _ => {}
    }
}

/// Detect dangerous settings in project config directives.
pub(super) fn detect_dangerous_setting(key: &str, value: &str, notes: &mut Vec<String>) {
    if key == "default" && value == "allow" {
        notes.push("sets default action to allow (all unknown commands auto-approved)".to_string());
    }
    if key == "self-protect" && value == "off" {
        notes.push("disables self-protection (AI tools can modify rippy config)".to_string());
    }
}

/// Detect overly broad allow rules in project config directives.
pub(super) fn detect_broad_allow(rule: &Rule, notes: &mut Vec<String>) {
    if rule.decision != Decision::Allow {
        return;
    }
    let raw = rule.pattern.raw();
    if raw == "*" || raw == "**" || raw == "*|" {
        notes.push(format!("allows all commands with pattern \"{raw}\""));
    }
}

/// Pre-format the weakening notes into a suffix string for verdict annotation.
///
/// Returns an empty string if there are no notes.
pub(super) fn build_weakening_suffix(notes: &[String]) -> String {
    if notes.is_empty() {
        return String::new();
    }
    let mut suffix = String::from(" | NOTE: project config ");
    for (i, note) in notes.iter().enumerate() {
        if i > 0 {
            suffix.push_str(", ");
        }
        suffix.push_str(note);
    }
    suffix
}

// ---------------------------------------------------------------------------
// File loading
// ---------------------------------------------------------------------------

/// Load the first file that exists from a list of candidates.
pub(super) fn load_first_existing(
    paths: &[PathBuf],
    directives: &mut Vec<ConfigDirective>,
) -> Result<(), RippyError> {
    for path in paths {
        if path.is_file() {
            return load_file(path, directives);
        }
    }
    Ok(())
}

/// Parse a single config file and append directives to the list.
///
/// # Errors
///
/// Returns `RippyError::Config` if the file cannot be read or contains invalid syntax.
pub fn load_file(path: &Path, directives: &mut Vec<ConfigDirective>) -> Result<(), RippyError> {
    let content = std::fs::read_to_string(path).map_err(|e| RippyError::Config {
        path: path.to_owned(),
        line: 0,
        message: format!("could not read: {e}"),
    })?;

    load_file_from_content(&content, path, directives)
}

/// Parse config content (already read from disk) and append directives.
pub(super) fn load_file_from_content(
    content: &str,
    path: &Path,
    directives: &mut Vec<ConfigDirective>,
) -> Result<(), RippyError> {
    if path.extension().is_some_and(|ext| ext == "toml") {
        let parsed = crate::toml_config::parse_toml_config(content, path)?;
        directives.extend(parsed);
        return Ok(());
    }

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let directive = parse_rule(line).map_err(|msg| RippyError::Config {
            path: path.to_owned(),
            line: line_num + 1,
            message: msg,
        })?;
        directives.push(directive);
    }

    Ok(())
}

/// Check whether already-loaded directives contain `trust-project-configs = on/true`.
pub(super) fn has_trust_setting(directives: &[ConfigDirective]) -> bool {
    directives.iter().rev().any(|d| {
        matches!(
            d,
            ConfigDirective::Set { key, value }
            if key == "trust-project-configs"
                && value != "off"
                && value != "false"
        )
    })
}

/// Load a project config file only if it is trusted.
///
/// If `trust_all` is true (from `trust-project-configs = on` in global config),
/// the file is loaded unconditionally. Otherwise, the trust database is consulted
/// and untrusted/modified configs are skipped with a stderr warning.
pub(super) fn load_project_config_if_trusted(
    path: &Path,
    trust_all: bool,
    directives: &mut Vec<ConfigDirective>,
) -> Result<(), RippyError> {
    let content = std::fs::read_to_string(path).map_err(|e| RippyError::Config {
        path: path.to_owned(),
        line: 0,
        message: format!("could not read: {e}"),
    })?;

    if trust_all {
        return load_file_from_content(&content, path, directives);
    }

    let db = crate::trust::TrustDb::load();
    match db.check(path, &content) {
        crate::trust::TrustStatus::Trusted => load_file_from_content(&content, path, directives),
        crate::trust::TrustStatus::Untrusted => {
            eprintln!(
                "[rippy] untrusted project config: {} — run `rippy trust` to review and enable",
                path.display()
            );
            Ok(())
        }
        crate::trust::TrustStatus::Modified { .. } => {
            eprintln!(
                "[rippy] project config modified since last trust: {} — \
                 run `rippy trust` to re-approve",
                path.display()
            );
            Ok(())
        }
    }
}

pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}
