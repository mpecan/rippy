//! CLI commands for adding rules: rippy allow/deny/ask

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::cli::RuleArgs;
use crate::config;
use crate::error::RippyError;
use crate::verdict::Decision;

/// Run the allow/deny/ask subcommand.
///
/// # Errors
///
/// Returns `RippyError::Setup` if the config file cannot be read or written.
pub fn run(decision: Decision, args: &RuleArgs) -> Result<ExitCode, RippyError> {
    let path = resolve_config_path(args.global)?;
    append_rule_to_toml(&path, decision, &args.pattern, args.message.as_deref())?;

    eprintln!(
        "[rippy] Added to {}:\n  {} {}{}",
        path.display(),
        decision.as_str(),
        args.pattern,
        args.message
            .as_ref()
            .map_or(String::new(), |m| format!(" \"{m}\""))
    );
    Ok(ExitCode::SUCCESS)
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

/// Append a rule to a TOML config file, creating it if necessary.
///
/// # Errors
///
/// Returns `RippyError::Setup` if the file cannot be read, created, or written.
pub fn append_rule_to_toml(
    path: &Path,
    decision: Decision,
    pattern: &str,
    message: Option<&str>,
) -> Result<(), RippyError> {
    // Create parent directories if needed
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|e| {
            RippyError::Setup(format!("could not create {}: {e}", parent.display()))
        })?;
    }

    // Read existing content
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

    // Build the rule block
    let mut block = String::new();
    // Add separator if file is non-empty and doesn't end with newline
    if !existing.is_empty() && !existing.ends_with('\n') {
        block.push('\n');
    }
    let _ = writeln!(block, "\n[[rules]]");
    let _ = writeln!(block, "action = {:?}", decision.as_str());
    let _ = writeln!(block, "pattern = {pattern:?}");
    if let Some(msg) = message {
        let _ = writeln!(block, "message = {msg:?}");
    }

    // Append
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| RippyError::Setup(format!("could not open {}: {e}", path.display())))?;
    std::io::Write::write_all(&mut file, block.as_bytes())
        .map_err(|e| RippyError::Setup(format!("could not write {}: {e}", path.display())))?;

    Ok(())
}

/// Generate pattern suggestions from most specific to most general.
#[must_use]
pub fn suggest_patterns(command: &str) -> Vec<String> {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    if tokens.is_empty() {
        return vec![];
    }
    if tokens.len() == 1 {
        return vec![tokens[0].to_string()];
    }

    let mut suggestions = Vec::new();

    // 1. Exact command (normalized whitespace)
    suggestions.push(tokens.join(" "));

    // 2. Wildcard last arg (if >2 tokens)
    if tokens.len() > 2 {
        let prefix: Vec<&str> = tokens[..tokens.len() - 1].to_vec();
        suggestions.push(format!("{} *", prefix.join(" ")));
    }

    // 3. Wildcard after first two tokens (command + subcommand)
    if tokens.len() > 2 {
        suggestions.push(format!("{} {} *", tokens[0], tokens[1]));
    } else {
        // 2 tokens: command + arg, wildcard the arg
        suggestions.push(format!("{} *", tokens[0]));
    }

    // 4. Wildcard entire command (only if >2 tokens, otherwise redundant)
    if tokens.len() > 2 {
        suggestions.push(format!("{} *", tokens[0]));
    }

    // Deduplicate while preserving order
    let mut seen = std::collections::HashSet::new();
    suggestions.retain(|s| seen.insert(s.clone()));
    suggestions
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn suggest_single_command() {
        let s = suggest_patterns("ls");
        assert_eq!(s, vec!["ls"]);
    }

    #[test]
    fn suggest_two_tokens() {
        let s = suggest_patterns("git status");
        assert_eq!(s, vec!["git status", "git *"]);
    }

    #[test]
    fn suggest_three_tokens() {
        let s = suggest_patterns("git push origin");
        assert_eq!(s, vec!["git push origin", "git push *", "git *"]);
    }

    #[test]
    fn suggest_four_tokens() {
        let s = suggest_patterns("git push origin main");
        assert_eq!(
            s,
            vec![
                "git push origin main",
                "git push origin *",
                "git push *",
                "git *",
            ]
        );
    }

    #[test]
    fn suggest_empty() {
        assert!(suggest_patterns("").is_empty());
    }

    #[test]
    fn suggest_normalizes_whitespace() {
        let s = suggest_patterns("git  push   origin");
        assert_eq!(s, vec!["git push origin", "git push *", "git *"]);
    }

    #[test]
    fn append_creates_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join(".rippy.toml");
        append_rule_to_toml(&path, Decision::Allow, "git status", None).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("action = \"allow\""));
        assert!(content.contains("pattern = \"git status\""));
    }

    #[test]
    fn append_with_message() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join(".rippy.toml");
        append_rule_to_toml(&path, Decision::Deny, "rm -rf *", Some("use trash")).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("action = \"deny\""));
        assert!(content.contains("message = \"use trash\""));
    }

    #[test]
    fn append_preserves_existing() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join(".rippy.toml");
        std::fs::write(&path, "[settings]\ndefault = \"ask\"\n").unwrap();

        append_rule_to_toml(&path, Decision::Allow, "git status", None).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.starts_with("[settings]"));
        assert!(content.contains("action = \"allow\""));
    }

    #[test]
    fn append_twice_no_duplicates_in_format() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join(".rippy.toml");
        append_rule_to_toml(&path, Decision::Allow, "git status", None).unwrap();
        append_rule_to_toml(&path, Decision::Deny, "rm -rf *", None).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        // Both rules should parse as valid TOML
        let parsed: toml::Value = toml::from_str(&content).unwrap();
        let rules = parsed["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn appended_rule_is_loadable() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join(".rippy.toml");
        append_rule_to_toml(&path, Decision::Deny, "rm -rf *", Some("no")).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let directives = crate::toml_config::parse_toml_config(&content, &path).unwrap();
        let config = crate::config::Config::from_directives(directives);
        let v = config.match_command("rm -rf /tmp", None).unwrap();
        assert_eq!(v.decision, Decision::Deny);
    }
}
