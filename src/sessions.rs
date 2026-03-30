//! Parse Claude Code session files (JSONL) for Bash command history.
//!
//! Extracts tool calls and user decisions (allow/deny) from session transcripts,
//! producing `CommandBreakdown` data compatible with the suggestion engine.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::config;
use crate::error::RippyError;
use crate::tracking::CommandBreakdown;
use crate::verdict::Decision;

/// A single Bash command extracted from a session with the user's decision.
#[derive(Debug, Clone)]
pub struct SessionCommand {
    pub command: String,
    pub allowed: bool,
}

/// Parse a single JSONL session file for Bash tool commands.
///
/// Extracts `tool_use` entries with `name == "Bash"` and correlates them with
/// `tool_result` entries to determine if the user allowed or denied each command.
///
/// # Errors
///
/// Returns `RippyError::Parse` if the file cannot be read.
pub fn parse_session_file(path: &Path) -> Result<Vec<SessionCommand>, RippyError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| RippyError::Parse(format!("could not read {}: {e}", path.display())))?;
    Ok(parse_session_content(&content))
}

/// Parse JSONL content for Bash tool commands.
fn parse_session_content(content: &str) -> Vec<SessionCommand> {
    let mut pending: HashMap<String, String> = HashMap::new();
    let mut commands = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };

        match entry.get("type").and_then(serde_json::Value::as_str) {
            Some("assistant") => extract_tool_uses(&entry, &mut pending),
            Some("user") => extract_tool_results(&entry, &mut pending, &mut commands),
            _ => {}
        }
    }

    commands
}

fn extract_tool_uses(entry: &serde_json::Value, pending: &mut HashMap<String, String>) {
    let Some(content) = entry
        .get("message")
        .and_then(|m| m.get("content"))
        .and_then(serde_json::Value::as_array)
    else {
        return;
    };

    for item in content {
        if item.get("type").and_then(serde_json::Value::as_str) != Some("tool_use") {
            continue;
        }
        if item.get("name").and_then(serde_json::Value::as_str) != Some("Bash") {
            continue;
        }
        if let (Some(id), Some(command)) = (
            item.get("id").and_then(serde_json::Value::as_str),
            item.get("input")
                .and_then(|i| i.get("command"))
                .and_then(serde_json::Value::as_str),
        ) && !command.is_empty()
        {
            pending.insert(id.to_string(), command.to_string());
        }
    }
}

fn extract_tool_results(
    entry: &serde_json::Value,
    pending: &mut HashMap<String, String>,
    commands: &mut Vec<SessionCommand>,
) {
    let Some(content) = entry
        .get("message")
        .and_then(|m| m.get("content"))
        .and_then(serde_json::Value::as_array)
    else {
        return;
    };

    for item in content {
        if item.get("type").and_then(serde_json::Value::as_str) != Some("tool_result") {
            continue;
        }
        let Some(tool_use_id) = item.get("tool_use_id").and_then(serde_json::Value::as_str) else {
            continue;
        };
        if let Some(command) = pending.remove(tool_use_id) {
            let is_error = item.get("is_error").and_then(serde_json::Value::as_bool);
            commands.push(SessionCommand {
                command,
                allowed: is_error != Some(true),
            });
        }
    }
}

// ── Project directory discovery ────────────────────────────────────────

/// Find and parse all session files for the current project.
///
/// # Errors
///
/// Returns `RippyError::Parse` if session files cannot be read.
pub fn parse_project_sessions(cwd: &Path) -> Result<Vec<SessionCommand>, RippyError> {
    let Some(project_dir) = find_project_dir(cwd) else {
        return Err(RippyError::Parse(
            "no Claude Code session directory found for this project".to_string(),
        ));
    };

    let mut all_commands = Vec::new();
    let entries = std::fs::read_dir(&project_dir)
        .map_err(|e| RippyError::Parse(format!("could not read {}: {e}", project_dir.display())))?;

    for entry in entries {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "jsonl") {
            match parse_session_file(&path) {
                Ok(cmds) => all_commands.extend(cmds),
                Err(e) => eprintln!("[rippy] warning: {}: {e}", path.display()),
            }
        }
    }

    Ok(all_commands)
}

/// Find the Claude Code project directory for a given working directory.
fn find_project_dir(cwd: &Path) -> Option<PathBuf> {
    let home = config::home_dir()?;
    let projects_dir = home.join(".claude/projects");
    if !projects_dir.is_dir() {
        return None;
    }

    // Claude Code uses cwd path with '/' replaced by '-'.
    let cwd_str = cwd.to_str()?;
    let normalized = cwd_str.trim_start_matches('/').replace(['/', '.'], "-");
    let project_name = format!("-{normalized}");
    let candidate = projects_dir.join(&project_name);

    if candidate.is_dir() {
        Some(candidate)
    } else {
        None
    }
}

// ── Conversion to CommandBreakdown ─────────────────────────────────────

/// Convert session commands to `CommandBreakdown` format for the suggest engine.
#[must_use]
pub fn to_breakdowns(commands: &[SessionCommand]) -> Vec<CommandBreakdown> {
    let mut map: HashMap<String, CommandBreakdown> = HashMap::new();

    for cmd in commands {
        let entry = map
            .entry(cmd.command.clone())
            .or_insert_with(|| CommandBreakdown {
                command: cmd.command.clone(),
                allow_count: 0,
                ask_count: 0,
                deny_count: 0,
            });
        if cmd.allowed {
            entry.allow_count += 1;
        } else {
            entry.deny_count += 1;
        }
    }

    let mut result: Vec<CommandBreakdown> = map.into_values().collect();
    result.sort_by(|a, b| {
        let total_b = b.allow_count + b.ask_count + b.deny_count;
        let total_a = a.allow_count + a.ask_count + a.deny_count;
        total_b
            .cmp(&total_a)
            .then_with(|| a.command.cmp(&b.command))
    });
    result
}

// ── Audit classification ───────────────────────────────────────────────

/// Audit results: classify commands against current rippy config.
#[derive(Debug)]
pub struct AuditResult {
    pub auto_allowed: Vec<(String, i64)>,
    pub user_allowed: Vec<(String, i64)>,
    pub user_denied: Vec<(String, i64)>,
    pub total: i64,
}

/// Classify session commands against the current rippy config.
///
/// # Errors
///
/// Returns `RippyError` if the config cannot be loaded.
pub fn audit_commands(commands: &[SessionCommand], cwd: &Path) -> Result<AuditResult, RippyError> {
    let config = crate::config::Config::load(cwd, None)?;

    let mut auto_allowed: HashMap<String, i64> = HashMap::new();
    let mut user_allowed: HashMap<String, i64> = HashMap::new();
    let mut user_denied: HashMap<String, i64> = HashMap::new();

    for cmd in commands {
        let verdict = config.match_command(&cmd.command, None);
        let rippy_would_allow = verdict
            .as_ref()
            .is_some_and(|v| v.decision == Decision::Allow);

        if rippy_would_allow {
            *auto_allowed.entry(cmd.command.clone()).or_default() += 1;
        } else if cmd.allowed {
            *user_allowed.entry(cmd.command.clone()).or_default() += 1;
        } else {
            *user_denied.entry(cmd.command.clone()).or_default() += 1;
        }
    }

    #[allow(clippy::cast_possible_wrap)]
    let total = commands.len() as i64;

    Ok(AuditResult {
        auto_allowed: sorted_counts(auto_allowed),
        user_allowed: sorted_counts(user_allowed),
        user_denied: sorted_counts(user_denied),
        total,
    })
}

fn sorted_counts(map: HashMap<String, i64>) -> Vec<(String, i64)> {
    let mut v: Vec<_> = map.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v
}

/// Print audit results to stdout.
pub fn print_audit(result: &AuditResult) {
    let auto_count: i64 = result.auto_allowed.iter().map(|(_, c)| c).sum();
    let user_count: i64 = result.user_allowed.iter().map(|(_, c)| c).sum();
    let deny_count: i64 = result.user_denied.iter().map(|(_, c)| c).sum();

    println!("Analyzed {} commands\n", result.total);

    #[allow(clippy::cast_precision_loss)]
    let pct = |n: i64| {
        if result.total > 0 {
            (n as f64 / result.total as f64) * 100.0
        } else {
            0.0
        }
    };

    println!(
        "  Auto-allowed (no action needed):     {:>4} ({:.1}%)",
        auto_count,
        pct(auto_count)
    );
    println!(
        "  User-allowed (consider allow rules): {:>4} ({:.1}%)",
        user_count,
        pct(user_count)
    );
    println!(
        "  User-denied  (consider deny rules):  {:>4} ({:.1}%)",
        deny_count,
        pct(deny_count)
    );

    if !result.user_allowed.is_empty() {
        println!("\n  Top user-allowed commands:");
        for (cmd, count) in result.user_allowed.iter().take(10) {
            println!("    {cmd:<50} {count}x");
        }
    }

    if !result.user_denied.is_empty() {
        println!("\n  User-denied commands:");
        for (cmd, count) in &result.user_denied {
            println!("    {cmd:<50} {count}x");
        }
    }
    println!();
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const SAMPLE_JSONL: &str = r#"
{"type":"assistant","message":{"content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"git status"}}]}}
{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"t1","content":"ok"}]}}
{"type":"assistant","message":{"content":[{"type":"tool_use","id":"t2","name":"Bash","input":{"command":"rm -rf /"}}]}}
{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"t2","is_error":true,"content":"denied"}]}}
{"type":"assistant","message":{"content":[{"type":"tool_use","id":"t3","name":"Bash","input":{"command":"git status"}}]}}
{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"t3","content":"ok"}]}}
{"type":"assistant","message":{"content":[{"type":"tool_use","id":"t4","name":"Read","input":{"path":"foo.rs"}}]}}
{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"t4","content":"file contents"}]}}
"#;

    #[test]
    fn parse_extracts_bash_commands() {
        let commands = parse_session_content(SAMPLE_JSONL);
        assert_eq!(commands.len(), 3); // 2x git status + 1x rm -rf /
    }

    #[test]
    fn parse_detects_allowed_and_denied() {
        let commands = parse_session_content(SAMPLE_JSONL);
        let allowed_count = commands.iter().filter(|c| c.allowed).count();
        let denied: Vec<_> = commands.iter().filter(|c| !c.allowed).collect();
        assert_eq!(allowed_count, 2);
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0].command, "rm -rf /");
    }

    #[test]
    fn parse_ignores_non_bash_tools() {
        let commands = parse_session_content(SAMPLE_JSONL);
        // Read tool (t4) should not appear
        assert!(!commands.iter().any(|c| c.command.contains("foo.rs")));
    }

    #[test]
    fn parse_handles_empty_input() {
        let commands = parse_session_content("");
        assert!(commands.is_empty());
    }

    #[test]
    fn parse_handles_malformed_lines() {
        let input = "not json\n{\"type\":\"unknown\"}\n";
        let commands = parse_session_content(input);
        assert!(commands.is_empty());
    }

    #[test]
    fn to_breakdowns_aggregates() {
        let commands = parse_session_content(SAMPLE_JSONL);
        let breakdowns = to_breakdowns(&commands);

        assert_eq!(breakdowns.len(), 2); // git status, rm -rf /

        let git = breakdowns
            .iter()
            .find(|b| b.command == "git status")
            .unwrap();
        assert_eq!(git.allow_count, 2);
        assert_eq!(git.deny_count, 0);

        let rm = breakdowns.iter().find(|b| b.command == "rm -rf /").unwrap();
        assert_eq!(rm.allow_count, 0);
        assert_eq!(rm.deny_count, 1);
    }

    #[test]
    fn to_breakdowns_empty() {
        let breakdowns = to_breakdowns(&[]);
        assert!(breakdowns.is_empty());
    }

    #[test]
    fn project_dir_mapping() {
        let cwd = Path::new("/Users/mdp/src/github.com/mpecan/rippy");
        let cwd_str = cwd.to_str().unwrap();
        let normalized = cwd_str
            .trim_start_matches('/')
            .replace(['/', '.'], "-");
        let name = format!("-{normalized}");
        assert_eq!(name, "-Users-mdp-src-github-com-mpecan-rippy");
    }

    #[test]
    fn parse_session_file_from_disk() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        std::fs::write(&path, SAMPLE_JSONL).unwrap();

        let commands = parse_session_file(&path).unwrap();
        assert_eq!(commands.len(), 3);
    }
}
