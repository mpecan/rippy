//! The `rippy suggest` command — analyze tracking data and suggest config rules.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

use serde::Serialize;

use crate::cli::SuggestArgs;
use crate::config;
use crate::error::RippyError;
use crate::risk::{self, RiskLevel};
use crate::rule_cmd;
use crate::tracking;
use crate::verdict::Decision;

/// Confidence that a suggestion is correct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

impl Confidence {
    const fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

/// A single rule suggestion with supporting evidence.
#[derive(Debug, Clone, Serialize)]
pub struct Suggestion {
    pub pattern: String,
    pub action: String,
    pub risk: RiskLevel,
    pub confidence: Confidence,
    pub evidence: Evidence,
}

/// Supporting evidence from the tracking DB.
#[derive(Debug, Clone, Serialize)]
pub struct Evidence {
    pub total: i64,
    pub allow_count: i64,
    pub ask_count: i64,
    pub deny_count: i64,
    pub example_commands: Vec<String>,
}

/// Internal: a group of commands sharing a common prefix.
struct CommandGroup {
    key: String,
    evidence: Evidence,
}

// ── Entry point ────────────────────────────────────────────────────────

/// Run the `rippy suggest` command.
///
/// # Errors
///
/// Returns `RippyError` if the database cannot be opened or queried,
/// or if applying suggestions fails.
pub fn run(args: &SuggestArgs) -> Result<ExitCode, RippyError> {
    if let Some(command) = &args.from_command {
        print_command_suggestions(command);
        return Ok(ExitCode::SUCCESS);
    }

    let breakdowns = load_breakdowns(args)?;
    let suggestions = analyze_breakdowns(&breakdowns, args.min_count);

    if suggestions.is_empty() {
        eprintln!("[rippy] No suggestions — not enough data yet.");
        return Ok(ExitCode::SUCCESS);
    }

    if args.json {
        let json = serde_json::to_string_pretty(&suggestions)
            .map_err(|e| RippyError::Tracking(format!("JSON serialization failed: {e}")))?;
        println!("{json}");
    } else {
        print_text(&suggestions);
    }

    if args.apply {
        apply_suggestions(&suggestions, args.global)?;
    }

    Ok(ExitCode::SUCCESS)
}

/// Load command breakdowns from the appropriate source.
///
/// Priority: explicit `--session-file` > explicit `--db` > auto-detect sessions > tracking DB.
/// Sessions are the default for Claude Code users (always available, no setup needed).
fn load_breakdowns(args: &SuggestArgs) -> Result<Vec<tracking::CommandBreakdown>, RippyError> {
    // Explicit session file always wins.
    if let Some(file) = &args.session_file {
        return load_from_sessions(args, || crate::sessions::parse_session_file(file));
    }

    // Explicit --db flag uses tracking DB.
    if args.db.is_some() {
        return load_from_db(args);
    }

    // Default: try sessions first, fall back to tracking DB.
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    match crate::sessions::parse_project_sessions(&cwd) {
        Ok(ref commands) if !commands.is_empty() => {
            load_from_session_commands(args, commands, &cwd)
        }
        _ => load_from_db(args),
    }
}

fn load_from_sessions(
    args: &SuggestArgs,
    parse: impl FnOnce() -> Result<Vec<crate::sessions::SessionCommand>, RippyError>,
) -> Result<Vec<tracking::CommandBreakdown>, RippyError> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let commands = parse()?;
    load_from_session_commands(args, &commands, &cwd)
}

fn load_from_session_commands(
    args: &SuggestArgs,
    commands: &[crate::sessions::SessionCommand],
    cwd: &std::path::Path,
) -> Result<Vec<tracking::CommandBreakdown>, RippyError> {
    if args.audit {
        let audit = crate::sessions::audit_commands(commands, cwd)?;
        crate::sessions::print_audit(&audit);
    }

    // Filter out commands already handled by CC permissions or rippy config.
    let filtered = crate::sessions::filter_auto_allowed(commands, cwd)?;
    Ok(crate::sessions::to_breakdowns(&filtered))
}

fn load_from_db(args: &SuggestArgs) -> Result<Vec<tracking::CommandBreakdown>, RippyError> {
    let db_path = resolve_db_path(args)?;
    let conn = tracking::open_db(&db_path)?;
    let since_modifier = parse_since(args.since.as_deref())?;
    tracking::query_command_breakdown(&conn, since_modifier.as_deref())
}

fn print_command_suggestions(command: &str) {
    let patterns = rule_cmd::suggest_patterns(command);
    if patterns.is_empty() {
        eprintln!("[rippy] No patterns to suggest for empty command");
        return;
    }
    println!("Suggested patterns for: {command}\n");
    for (i, pattern) in patterns.iter().enumerate() {
        println!("  {}. {pattern}", i + 1);
    }
    let last = patterns.last().map_or("", String::as_str);
    let first = patterns.first().map_or("", String::as_str);
    println!("\nUsage: rippy allow \"{last}\"\n       rippy deny \"{first}\"");
}

fn resolve_db_path(args: &SuggestArgs) -> Result<PathBuf, RippyError> {
    tracking::resolve_db_path(args.db.as_deref())
}

fn parse_since(since: Option<&str>) -> Result<Option<String>, RippyError> {
    since.map_or(Ok(None), |s| {
        tracking::parse_duration(s)
            .ok_or_else(|| {
                RippyError::Tracking(format!(
                    "invalid duration: {s}. Use format like 7d, 1h, 30m"
                ))
            })
            .map(Some)
    })
}

// ── Analysis engine ────────────────────────────────────────────────────

/// Analyze command breakdowns and produce rule suggestions.
#[must_use]
pub fn analyze_breakdowns(
    breakdowns: &[tracking::CommandBreakdown],
    min_count: i64,
) -> Vec<Suggestion> {
    let groups = group_commands(breakdowns);

    let mut suggestions: Vec<Suggestion> = groups
        .into_iter()
        .filter(|g| g.evidence.total >= min_count)
        .map(|g| {
            let risk = risk::classify(&g.key);
            let confidence = compute_confidence(&g.evidence);
            let action = suggest_action(&g.evidence, risk);
            let pattern = generalize_pattern(&g.key, &g.evidence.example_commands);
            Suggestion {
                pattern,
                action: action.as_str().to_string(),
                risk,
                confidence,
                evidence: g.evidence,
            }
        })
        .collect();

    // Sort: critical first, then by total descending.
    suggestions.sort_by(|a, b| {
        b.risk
            .cmp(&a.risk)
            .then_with(|| b.evidence.total.cmp(&a.evidence.total))
    });

    suggestions
}

// ── Grouping ───────────────────────────────────────────────────────────

/// Tools whose subcommand (second token) should be part of the group key.
const SUBCOMMAND_TOOLS: &[&str] = &[
    "git", "docker", "cargo", "npm", "yarn", "pnpm", "kubectl", "helm", "pip", "pip3",
];

fn group_key(command: &str) -> String {
    let mut tokens = command.split_whitespace();
    let Some(first) = tokens.next() else {
        return command.to_string();
    };
    if SUBCOMMAND_TOOLS.contains(&first)
        && let Some(second) = tokens.next()
    {
        return format!("{first} {second}");
    }
    first.to_string()
}

fn group_commands(breakdowns: &[tracking::CommandBreakdown]) -> Vec<CommandGroup> {
    let mut map: HashMap<String, CommandGroup> = HashMap::new();

    for bd in breakdowns {
        let key = group_key(&bd.command);
        let total = bd.allow_count + bd.ask_count + bd.deny_count;
        let group = map.entry(key.clone()).or_insert_with(|| CommandGroup {
            key,
            evidence: Evidence {
                total: 0,
                allow_count: 0,
                ask_count: 0,
                deny_count: 0,
                example_commands: Vec::new(),
            },
        });
        group.evidence.total += total;
        group.evidence.allow_count += bd.allow_count;
        group.evidence.ask_count += bd.ask_count;
        group.evidence.deny_count += bd.deny_count;
        if group.evidence.example_commands.len() < 3 {
            group.evidence.example_commands.push(bd.command.clone());
        }
    }

    map.into_values().collect()
}

// ── Confidence ─────────────────────────────────────────────────────────

/// Compute confidence from the evidence ratios.
#[must_use]
pub fn compute_confidence(evidence: &Evidence) -> Confidence {
    if evidence.total == 0 {
        return Confidence::Low;
    }

    #[allow(clippy::cast_precision_loss)]
    let max_ratio = [
        evidence.allow_count,
        evidence.ask_count,
        evidence.deny_count,
    ]
    .into_iter()
    .max()
    .unwrap_or(0) as f64
        / evidence.total as f64;

    if max_ratio >= 0.8 && evidence.total >= 10 {
        Confidence::High
    } else if max_ratio >= 0.6 && evidence.total >= 5 {
        Confidence::Medium
    } else {
        Confidence::Low
    }
}

// ── Action suggestion ──────────────────────────────────────────────────

/// Suggest an action based on evidence and risk.
#[must_use]
pub fn suggest_action(evidence: &Evidence, risk: RiskLevel) -> Decision {
    if evidence.total == 0 {
        return Decision::Ask;
    }

    #[allow(clippy::cast_precision_loss)]
    let allow_ratio = evidence.allow_count as f64 / evidence.total as f64;

    // Mostly denied → deny.
    #[allow(clippy::cast_precision_loss)]
    let deny_ratio = evidence.deny_count as f64 / evidence.total as f64;

    if deny_ratio >= 0.5 {
        return Decision::Deny;
    }

    // Mostly allowed: action depends on risk level.
    if allow_ratio >= 0.8 {
        return match risk {
            RiskLevel::Low | RiskLevel::Medium => Decision::Allow,
            RiskLevel::High | RiskLevel::Critical => Decision::Ask,
        };
    }

    // Mixed signals → ask.
    Decision::Ask
}

// ── Pattern generalization ─────────────────────────────────────────────

/// Produce a glob pattern from a group key and example commands.
fn generalize_pattern(group_key: &str, examples: &[String]) -> String {
    // If all examples are the same command, use exact match.
    if examples.len() == 1 {
        return examples[0].clone();
    }

    // If examples all share the group key as prefix, use "group_key *".
    let all_start_with_key = examples.iter().all(|e| {
        e == group_key
            || (e.starts_with(group_key) && e.as_bytes().get(group_key.len()) == Some(&b' '))
    });

    if all_start_with_key && examples.iter().any(|e| e != group_key) {
        return format!("{group_key} *");
    }

    // Fallback: use the group key as a prefix pattern.
    group_key.to_string()
}

// ── Output ─────────────────────────────────────────────────────────────

fn print_text(suggestions: &[Suggestion]) {
    let mut current_confidence: Option<Confidence> = None;

    for s in suggestions {
        if current_confidence != Some(s.confidence) {
            current_confidence = Some(s.confidence);
            println!("\n  {} confidence:", s.confidence.as_str().to_uppercase());
        }
        let mut line = format!(
            "    {} {:<30} # {} {} times (risk: {})",
            s.action,
            s.pattern,
            s.action,
            s.evidence.total,
            s.risk.as_str(),
        );
        if !s.evidence.example_commands.is_empty() && s.evidence.example_commands[0] != s.pattern {
            let _ = write!(line, ", e.g. {}", s.evidence.example_commands[0]);
        }
        println!("{line}");
    }
    println!();
}

fn apply_suggestions(suggestions: &[Suggestion], global: bool) -> Result<(), RippyError> {
    let path = if global {
        config::home_dir()
            .map(|h| h.join(".rippy/config.toml"))
            .ok_or_else(|| RippyError::Setup("could not determine home directory".into()))?
    } else {
        PathBuf::from(".rippy.toml")
    };

    for s in suggestions {
        let decision = match s.action.as_str() {
            "allow" => Decision::Allow,
            "deny" => Decision::Deny,
            _ => Decision::Ask,
        };
        rule_cmd::append_rule_to_toml(&path, decision, &s.pattern, None)?;
    }

    eprintln!(
        "[rippy] Applied {} suggestion(s) to {}",
        suggestions.len(),
        path.display()
    );
    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::mode::Mode;

    fn make_evidence(allow: i64, ask: i64, deny: i64) -> Evidence {
        Evidence {
            total: allow + ask + deny,
            allow_count: allow,
            ask_count: ask,
            deny_count: deny,
            example_commands: vec![],
        }
    }

    // ── Confidence ─────────────────────────────────────────────────

    #[test]
    fn confidence_high() {
        let e = make_evidence(20, 0, 0);
        assert_eq!(compute_confidence(&e), Confidence::High);
    }

    #[test]
    fn confidence_medium() {
        let e = make_evidence(5, 2, 0);
        assert_eq!(compute_confidence(&e), Confidence::Medium);
    }

    #[test]
    fn confidence_low_small_sample() {
        let e = make_evidence(3, 0, 0);
        assert_eq!(compute_confidence(&e), Confidence::Low);
    }

    #[test]
    fn confidence_low_mixed() {
        let e = make_evidence(5, 4, 3);
        assert_eq!(compute_confidence(&e), Confidence::Low);
    }

    #[test]
    fn confidence_empty() {
        let e = make_evidence(0, 0, 0);
        assert_eq!(compute_confidence(&e), Confidence::Low);
    }

    // ── Action suggestion ──────────────────────────────────────────

    #[test]
    fn action_mostly_allowed_low_risk() {
        let e = make_evidence(20, 1, 0);
        assert_eq!(suggest_action(&e, RiskLevel::Low), Decision::Allow);
    }

    #[test]
    fn action_mostly_allowed_high_risk() {
        let e = make_evidence(20, 1, 0);
        assert_eq!(suggest_action(&e, RiskLevel::High), Decision::Ask);
    }

    #[test]
    fn action_mostly_denied() {
        let e = make_evidence(2, 1, 10);
        assert_eq!(suggest_action(&e, RiskLevel::Low), Decision::Deny);
    }

    #[test]
    fn action_mixed_signals() {
        let e = make_evidence(5, 5, 0);
        assert_eq!(suggest_action(&e, RiskLevel::Medium), Decision::Ask);
    }

    // ── Grouping ───────────────────────────────────────────────────

    #[test]
    fn group_key_subcommand_tools() {
        assert_eq!(group_key("git push origin main"), "git push");
        assert_eq!(group_key("docker run -it ubuntu"), "docker run");
        assert_eq!(group_key("cargo test --release"), "cargo test");
    }

    #[test]
    fn group_key_simple_commands() {
        assert_eq!(group_key("ls -la"), "ls");
        assert_eq!(group_key("rm -rf /tmp"), "rm");
        assert_eq!(group_key("make"), "make");
    }

    #[test]
    fn group_commands_aggregates() {
        let breakdowns = vec![
            tracking::CommandBreakdown {
                command: "git push origin main".into(),
                allow_count: 5,
                ask_count: 2,
                deny_count: 0,
            },
            tracking::CommandBreakdown {
                command: "git push origin dev".into(),
                allow_count: 3,
                ask_count: 1,
                deny_count: 0,
            },
        ];
        let groups = group_commands(&breakdowns);
        assert_eq!(groups.len(), 1);
        let g = &groups[0];
        assert_eq!(g.key, "git push");
        assert_eq!(g.evidence.allow_count, 8);
        assert_eq!(g.evidence.ask_count, 3);
        assert_eq!(g.evidence.total, 11);
        assert_eq!(g.evidence.example_commands.len(), 2);
    }

    // ── Pattern generalization ─────────────────────────────────────

    #[test]
    fn generalize_single_example() {
        let p = generalize_pattern("git push", &["git push origin main".into()]);
        assert_eq!(p, "git push origin main");
    }

    #[test]
    fn generalize_multiple_examples() {
        let p = generalize_pattern(
            "git push",
            &["git push origin main".into(), "git push origin dev".into()],
        );
        assert_eq!(p, "git push *");
    }

    #[test]
    fn generalize_exact_key_only() {
        let p = generalize_pattern("ls", &["ls".into(), "ls".into()]);
        assert_eq!(p, "ls");
    }

    // ── End-to-end with in-memory DB ───────────────────────────────

    fn populate_test_db(conn: &rusqlite::Connection) {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS decisions (
                id INTEGER PRIMARY KEY,
                timestamp TEXT NOT NULL DEFAULT (datetime('now')),
                session_id TEXT, mode TEXT, tool_name TEXT NOT NULL,
                command TEXT, decision TEXT NOT NULL, reason TEXT, payload_json TEXT
            );",
        )
        .unwrap();

        let entry = tracking::TrackingEntry {
            session_id: None,
            mode: Mode::Claude,
            tool_name: "Bash",
            command: Some("git status"),
            decision: Decision::Allow,
            reason: "safe",
            payload_json: None,
        };

        for _ in 0..15 {
            tracking::record_decision(conn, &entry).unwrap();
        }
        for _ in 0..10 {
            tracking::record_decision(
                conn,
                &tracking::TrackingEntry {
                    decision: Decision::Ask,
                    command: Some("git push origin main"),
                    reason: "review",
                    ..entry
                },
            )
            .unwrap();
        }
        for _ in 0..5 {
            tracking::record_decision(
                conn,
                &tracking::TrackingEntry {
                    decision: Decision::Deny,
                    command: Some("rm -rf /"),
                    reason: "dangerous",
                    ..entry
                },
            )
            .unwrap();
        }
    }

    #[test]
    fn analyze_produces_suggestions() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
        populate_test_db(&conn);

        let breakdowns = tracking::query_command_breakdown(&conn, None).unwrap();
        let suggestions = analyze_breakdowns(&breakdowns, 3);
        assert!(!suggestions.is_empty());
        assert!(suggestions.len() >= 3);
    }

    #[test]
    fn analyze_risk_and_action_correct() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL;").unwrap();
        populate_test_db(&conn);

        let breakdowns = tracking::query_command_breakdown(&conn, None).unwrap();
        let suggestions = analyze_breakdowns(&breakdowns, 3);

        let rm = suggestions
            .iter()
            .find(|s| s.pattern.contains("rm"))
            .unwrap();
        assert_eq!(rm.risk, RiskLevel::High);
        assert_eq!(rm.action, "deny");

        let status = suggestions
            .iter()
            .find(|s| s.pattern.contains("status"))
            .unwrap();
        assert_eq!(status.risk, RiskLevel::Low);
        assert_eq!(status.action, "allow");

        let push = suggestions
            .iter()
            .find(|s| s.pattern.contains("push"))
            .unwrap();
        assert_eq!(push.risk, RiskLevel::Medium);
    }

    #[test]
    fn apply_suggestions_writes_rules() {
        let dir = tempfile::TempDir::new().unwrap();
        let config_path = dir.path().join(".rippy.toml");

        let suggestions = vec![
            Suggestion {
                pattern: "git status".into(),
                action: "allow".into(),
                risk: RiskLevel::Low,
                confidence: Confidence::High,
                evidence: make_evidence(20, 0, 0),
            },
            Suggestion {
                pattern: "rm -rf *".into(),
                action: "deny".into(),
                risk: RiskLevel::High,
                confidence: Confidence::High,
                evidence: make_evidence(0, 0, 10),
            },
        ];

        // We need to run in the tmpdir so .rippy.toml lands there.
        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();
        apply_suggestions(&suggestions, false).unwrap();
        std::env::set_current_dir(original_dir).unwrap();

        let content = std::fs::read_to_string(&config_path).unwrap();
        assert!(content.contains("action = \"allow\""));
        assert!(content.contains("pattern = \"git status\""));
        assert!(content.contains("action = \"deny\""));
        assert!(content.contains("pattern = \"rm -rf *\""));
    }
}
