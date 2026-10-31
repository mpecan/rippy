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
pub(crate) struct SessionCommand {
    pub command: String,
    pub allowed: bool,
    /// When the user decided: the `tool_result` entry's timestamp, else the `tool_use` one's.
    pub timestamp: Option<String>,
}

/// A `tool_use` awaiting its `tool_result`: the command and the entry's timestamp.
type Pending = HashMap<String, (String, Option<String>)>;

/// Parse a single JSONL session file for Bash tool commands.
///
/// Extracts `tool_use` entries with `name == "Bash"` and correlates them with
/// `tool_result` entries to determine if the user allowed or denied each command.
///
/// # Errors
///
/// Returns `RippyError::Parse` if the file cannot be read.
pub(crate) fn parse_session_file(path: &Path) -> Result<Vec<SessionCommand>, RippyError> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| RippyError::Parse(format!("could not read {}: {e}", path.display())))?;
    Ok(parse_session_content(&content))
}

/// Parse JSONL content for Bash tool commands.
fn parse_session_content(content: &str) -> Vec<SessionCommand> {
    let mut pending = Pending::new();
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

fn entry_timestamp(entry: &serde_json::Value) -> Option<String> {
    entry
        .get("timestamp")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

fn extract_tool_uses(entry: &serde_json::Value, pending: &mut Pending) {
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
            pending.insert(
                id.to_string(),
                (command.to_string(), entry_timestamp(entry)),
            );
        }
    }
}

fn extract_tool_results(
    entry: &serde_json::Value,
    pending: &mut Pending,
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
        if let Some((command, use_timestamp)) = pending.remove(tool_use_id) {
            let is_error = item.get("is_error").and_then(serde_json::Value::as_bool);
            commands.push(SessionCommand {
                command,
                allowed: is_error != Some(true),
                timestamp: entry_timestamp(entry).or(use_timestamp),
            });
        }
    }
}

// Project directory discovery

/// Find and parse all session files for the current project.
///
/// # Errors
///
/// Returns `RippyError::Parse` if session files cannot be read.
pub(crate) fn parse_project_sessions(cwd: &Path) -> Result<Vec<SessionCommand>, RippyError> {
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

// Filtering

/// Filter out commands that CC permissions or rippy config already auto-allow.
///
/// Only returns commands that would actually need new rules (user-allowed or user-denied).
///
/// # Errors
///
/// Returns `RippyError` if the config cannot be loaded.
pub(crate) fn filter_auto_allowed(
    commands: &[SessionCommand],
    cwd: &Path,
) -> Result<Vec<SessionCommand>, RippyError> {
    let config = crate::config::Config::load(cwd, None)?;
    let cc_rules = crate::cc_permissions::load_cc_rules(cwd);

    let filtered = commands
        .iter()
        .filter(|cmd| {
            let cc = cc_rules.check(&cmd.command);
            let rippy = config.match_command(&cmd.command, None);
            let auto_allowed = cc == Some(Decision::Allow)
                || rippy
                    .as_ref()
                    .is_some_and(|v| v.decision == Decision::Allow);
            !auto_allowed
        })
        .cloned()
        .collect();

    Ok(filtered)
}

/// Keep only commands decided inside a `--since` window; also returns how many were dropped
/// for lacking a usable timestamp, so the caller can say so rather than shrink counts silently.
///
/// `duration` is a [`crate::tracking::parse_since_window`] result (e.g. `"7 days"`). `SQLite`
/// does the date math, as it does for the tracking DB, so both sources share one meaning of
/// "since" and any timestamp form `SQLite` understands (fractional seconds, `Z`, `+02:00`)
/// compares as an instant.
///
/// # Errors
///
/// Returns `RippyError::Tracking` if the in-memory `SQLite` evaluation fails or the window is out
/// of range.
pub(crate) fn retain_since(
    commands: Vec<SessionCommand>,
    duration: &str,
) -> Result<(Vec<SessionCommand>, usize), RippyError> {
    let conn = rusqlite::Connection::open_in_memory().map_err(|e| since_err(&e))?;
    let cutoff: Option<f64> = conn
        .query_row(
            "SELECT julianday('now', ?1)",
            [format!("-{duration}")],
            |r| r.get(0),
        )
        .map_err(|e| since_err(&e))?;
    let Some(cutoff) = cutoff else {
        return Err(RippyError::Tracking(format!(
            "invalid --since window: {duration}"
        )));
    };
    retain_from(&conn, commands, cutoff)
}

/// Keep commands at or after `cutoff` (a Julian day number); count the untimed ones dropped.
fn retain_from(
    conn: &rusqlite::Connection,
    commands: Vec<SessionCommand>,
    cutoff: f64,
) -> Result<(Vec<SessionCommand>, usize), RippyError> {
    let mut stmt = conn
        .prepare("SELECT julianday(?1)")
        .map_err(|e| since_err(&e))?;
    let mut kept = Vec::with_capacity(commands.len());
    let mut untimed = 0;
    for cmd in commands {
        let at: Option<f64> = match cmd.timestamp.as_deref() {
            Some(ts) => stmt
                .query_row([ts], |r| r.get(0))
                .map_err(|e| since_err(&e))?,
            None => None,
        };
        match at {
            Some(at) if at >= cutoff => kept.push(cmd),
            Some(_) => {}
            None => untimed += 1,
        }
    }
    Ok((kept, untimed))
}

fn since_err(e: &rusqlite::Error) -> RippyError {
    RippyError::Tracking(format!("--since evaluation failed: {e}"))
}

// Conversion to CommandBreakdown

/// Convert session commands to `CommandBreakdown` format for the suggest engine.
#[must_use]
pub(crate) fn to_breakdowns(commands: &[SessionCommand]) -> Vec<CommandBreakdown> {
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

// Audit classification

/// Audit results: classify commands against current rippy config.
#[derive(Debug)]
pub(crate) struct AuditResult {
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
pub(crate) fn audit_commands(
    commands: &[SessionCommand],
    cwd: &Path,
) -> Result<AuditResult, RippyError> {
    let config = crate::config::Config::load(cwd, None)?;
    let cc_rules = crate::cc_permissions::load_cc_rules(cwd);

    let mut auto_allowed: HashMap<String, i64> = HashMap::new();
    let mut user_allowed: HashMap<String, i64> = HashMap::new();
    let mut user_denied: HashMap<String, i64> = HashMap::new();

    for cmd in commands {
        // Check CC permissions first (same priority as analyzer).
        let cc_decision = cc_rules.check(&cmd.command);
        let rippy_verdict = config.match_command(&cmd.command, None);
        let would_allow = cc_decision == Some(Decision::Allow)
            || rippy_verdict
                .as_ref()
                .is_some_and(|v| v.decision == Decision::Allow);

        if would_allow {
            *auto_allowed.entry(cmd.command.clone()).or_default() += 1;
        } else if cmd.allowed {
            *user_allowed.entry(cmd.command.clone()).or_default() += 1;
        } else {
            *user_denied.entry(cmd.command.clone()).or_default() += 1;
        }
    }

    #[expect(clippy::cast_possible_wrap)]
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
pub(crate) fn print_audit(result: &AuditResult) {
    let auto_count: i64 = result.auto_allowed.iter().map(|(_, c)| c).sum();
    let user_count: i64 = result.user_allowed.iter().map(|(_, c)| c).sum();
    let deny_count: i64 = result.user_denied.iter().map(|(_, c)| c).sum();

    println!("Analyzed {} commands\n", result.total);

    #[expect(clippy::cast_precision_loss)]
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

// Tests

#[cfg(test)]
#[expect(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn tool_use_line(id: &str, name: &str, input: &str) -> String {
        format!(
            concat!(
                r#"{{"type":"assistant","message":{{"content":[{{"#,
                r#""type":"tool_use","id":"{id}","name":"{name}","input":{input}}}]}}}}"#,
            ),
            id = id,
            name = name,
            input = input,
        )
    }

    fn tool_result_line(id: &str, extra: &str, content: &str) -> String {
        format!(
            concat!(
                r#"{{"type":"user","message":{{"content":[{{"#,
                r#""type":"tool_result","tool_use_id":"{id}",{extra}"content":"{content}"}}]}}}}"#,
            ),
            id = id,
            extra = extra,
            content = content,
        )
    }

    fn sample_jsonl() -> String {
        [
            tool_use_line("t1", "Bash", r#"{"command":"git status"}"#),
            tool_result_line("t1", "", "ok"),
            tool_use_line("t2", "Bash", r#"{"command":"rm -rf /"}"#),
            tool_result_line("t2", r#""is_error":true,"#, "denied"),
            tool_use_line("t3", "Bash", r#"{"command":"git status"}"#),
            tool_result_line("t3", "", "ok"),
            tool_use_line("t4", "Read", r#"{"path":"foo.rs"}"#),
            tool_result_line("t4", "", "file contents"),
        ]
        .join("\n")
    }

    #[test]
    fn parse_extracts_bash_commands() {
        let commands = parse_session_content(&sample_jsonl());
        assert_eq!(commands.len(), 3); // 2x git status + 1x rm -rf /
    }

    #[test]
    fn parse_detects_allowed_and_denied() {
        let commands = parse_session_content(&sample_jsonl());
        let allowed_count = commands.iter().filter(|c| c.allowed).count();
        let denied: Vec<_> = commands.iter().filter(|c| !c.allowed).collect();
        assert_eq!(allowed_count, 2);
        assert_eq!(denied.len(), 1);
        assert_eq!(denied[0].command, "rm -rf /");
    }

    #[test]
    fn parse_ignores_non_bash_tools() {
        let commands = parse_session_content(&sample_jsonl());
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
        let commands = parse_session_content(&sample_jsonl());
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
        let normalized = cwd_str.trim_start_matches('/').replace(['/', '.'], "-");
        let name = format!("-{normalized}");
        assert_eq!(name, "-Users-mdp-src-github-com-mpecan-rippy");
    }

    fn with_ts(line: &str, ts: &str) -> String {
        line.replacen('{', &format!(r#"{{"timestamp":"{ts}","#), 1)
    }

    /// A timestamp `offset` from now (an `SQLite` modifier such as `"-2 hours"`), in Claude Code's
    /// own format.
    fn ts_from_now(offset: &str) -> String {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.query_row(
            "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?1)",
            [offset],
            |r| r.get(0),
        )
        .unwrap()
    }

    fn cmd(command: &str, timestamp: Option<String>) -> SessionCommand {
        SessionCommand {
            command: command.to_string(),
            allowed: true,
            timestamp,
        }
    }

    #[test]
    fn parse_takes_timestamp_from_tool_result() {
        let content = [
            with_ts(
                &tool_use_line("t1", "Bash", r#"{"command":"ls"}"#),
                "2026-01-01T00:00:00Z",
            ),
            with_ts(&tool_result_line("t1", "", "ok"), "2026-01-02T00:00:00Z"),
        ]
        .join("\n");
        let commands = parse_session_content(&content);
        assert_eq!(
            commands[0].timestamp.as_deref(),
            Some("2026-01-02T00:00:00Z")
        );
    }

    #[test]
    fn parse_falls_back_to_tool_use_timestamp() {
        let content = [
            with_ts(
                &tool_use_line("t1", "Bash", r#"{"command":"ls"}"#),
                "2026-01-01T00:00:00Z",
            ),
            tool_result_line("t1", "", "ok"),
        ]
        .join("\n");
        let commands = parse_session_content(&content);
        assert_eq!(
            commands[0].timestamp.as_deref(),
            Some("2026-01-01T00:00:00Z")
        );
    }

    #[test]
    fn parse_without_timestamps_leaves_none() {
        let commands = parse_session_content(&sample_jsonl());
        assert!(commands.iter().all(|c| c.timestamp.is_none()));
    }

    #[test]
    fn retain_since_keeps_only_the_window() {
        let commands = vec![
            cmd("recent", Some(ts_from_now("-30 minutes"))),
            cmd("old", Some(ts_from_now("-3 hours"))),
            cmd("ancient", Some("2000-01-01T00:00:00.000Z".to_string())),
            cmd("no-timestamp", None),
            cmd("garbage-timestamp", Some("yesterday-ish".to_string())),
        ];
        let (kept, untimed) = retain_since(commands, "1 hours").unwrap();
        let names: Vec<_> = kept.iter().map(|c| c.command.as_str()).collect();
        assert_eq!(names, ["recent"]);
        assert_eq!(
            untimed, 2,
            "no-timestamp and garbage-timestamp are counted, not just lost"
        );
    }

    #[test]
    fn retain_since_wide_window_keeps_all_timestamped() {
        let commands = vec![
            cmd("recent", Some(ts_from_now("-30 minutes"))),
            cmd("old", Some(ts_from_now("-3 hours"))),
        ];
        let (kept, untimed) = retain_since(commands, "1 days").unwrap();
        assert_eq!((kept.len(), untimed), (2, 0));
    }

    #[test]
    fn retain_since_honours_utc_offsets() {
        // 30 minutes ago, written as -05:00 local time. Compared as text against a UTC
        // cutoff it would look 5h old and be dropped; as an instant it is in the window.
        let utc_ago = ts_from_now("-30 minutes");
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let shifted: String = conn
            .query_row(
                "SELECT strftime('%Y-%m-%dT%H:%M:%f', ?1, '-5 hours') || '-05:00'",
                [&utc_ago],
                |r| r.get(0),
            )
            .unwrap();
        let (kept, _) = retain_since(vec![cmd("shifted", Some(shifted))], "1 hours").unwrap();
        assert_eq!(kept.len(), 1);
    }

    #[test]
    fn retain_from_keeps_a_command_exactly_at_the_cutoff() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let ts = "2026-06-01T12:00:00.000Z";
        let cutoff: f64 = conn
            .query_row("SELECT julianday(?1)", [ts], |r| r.get(0))
            .unwrap();
        let (kept, _) =
            retain_from(&conn, vec![cmd("edge", Some(ts.to_string()))], cutoff).unwrap();
        assert_eq!(
            kept.len(),
            1,
            "the window is inclusive, like the tracking DB's >="
        );
    }

    #[test]
    fn retain_since_rejects_out_of_range_window() {
        let commands = vec![cmd("x", Some(ts_from_now("-1 minutes")))];
        assert!(retain_since(commands, "99999999999 days").is_err());
    }

    #[test]
    fn parse_session_file_from_disk() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl");
        std::fs::write(&path, sample_jsonl()).unwrap();

        let commands = parse_session_file(&path).unwrap();
        assert_eq!(commands.len(), 3);
    }
}
