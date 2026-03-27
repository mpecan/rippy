//! The `rippy stats` command — query decision tracking data.

use std::path::PathBuf;
use std::process::ExitCode;

use serde::Serialize;

use crate::cli::StatsArgs;
use crate::config;
use crate::error::RippyError;
use crate::tracking;

/// Run the `rippy stats` command.
///
/// # Errors
///
/// Returns `RippyError::Tracking` if the database cannot be opened or queried.
pub fn run(args: &StatsArgs) -> Result<ExitCode, RippyError> {
    let db_path = resolve_db_path(args)?;
    let conn = tracking::open_db(&db_path)?;

    let since_modifier = if let Some(since_str) = &args.since {
        Some(tracking::parse_duration(since_str).ok_or_else(|| {
            RippyError::Tracking(format!(
                "invalid duration: {since_str}. Use format like 7d, 1h, 30m"
            ))
        })?)
    } else {
        None
    };

    let counts = tracking::query_counts(&conn, since_modifier.as_deref())?;
    let top_asked = tracking::query_top_commands(&conn, "ask", since_modifier.as_deref(), 5)?;
    let top_denied = tracking::query_top_commands(&conn, "deny", since_modifier.as_deref(), 5)?;

    let output = StatsOutput {
        db_path: db_path.display().to_string(),
        since: args.since.clone(),
        counts,
        top_asked,
        top_denied,
    };

    if args.json {
        let json = serde_json::to_string_pretty(&output)
            .map_err(|e| RippyError::Tracking(format!("JSON serialization failed: {e}")))?;
        println!("{json}");
    } else {
        print_stats_text(&output);
    }

    Ok(ExitCode::SUCCESS)
}

fn resolve_db_path(args: &StatsArgs) -> Result<PathBuf, RippyError> {
    if let Some(db) = &args.db {
        return Ok(db.clone());
    }

    // Try loading config to find tracking_db path.
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let cfg = config::Config::load(&cwd, None)?;
    cfg.tracking_db.ok_or_else(|| {
        RippyError::Tracking(
            "no tracking database configured. Enable with `set tracking on` in \
             .rippy config, or use --db <path>"
                .to_string(),
        )
    })
}

fn print_stats_text(output: &StatsOutput) {
    println!("Tracking: {}", output.db_path);
    if let Some(since) = &output.since {
        println!("Period: last {since}");
    }
    println!();
    println!("Decisions: {} total", output.counts.total);
    print_count_line("  Allow", output.counts.allow, output.counts.total);
    print_count_line("  Ask", output.counts.ask, output.counts.total);
    print_count_line("  Deny", output.counts.deny, output.counts.total);

    if !output.top_asked.is_empty() {
        println!("\nTop asked commands:");
        for (cmd, count) in &output.top_asked {
            println!("  {cmd:<40} {count} times");
        }
    }

    if !output.top_denied.is_empty() {
        println!("\nTop denied commands:");
        for (cmd, count) in &output.top_denied {
            println!("  {cmd:<40} {count} times");
        }
    }
}

fn print_count_line(label: &str, count: i64, total: i64) {
    if total > 0 {
        #[allow(clippy::cast_precision_loss)]
        let pct = (count as f64 / total as f64) * 100.0;
        println!("{label:<8} {count:>6} ({pct:.1}%)");
    } else {
        println!("{label:<8} {count:>6}");
    }
}

#[derive(Debug, Serialize)]
struct StatsOutput {
    db_path: String,
    since: Option<String>,
    counts: tracking::DecisionCounts,
    top_asked: Vec<(String, i64)>,
    top_denied: Vec<(String, i64)>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::mode::Mode;
    use crate::verdict::Decision;

    fn populate_db(conn: &rusqlite::Connection) {
        let entry = tracking::TrackingEntry {
            session_id: None,
            mode: Mode::Claude,
            tool_name: "Bash",
            command: Some("git status"),
            decision: Decision::Allow,
            reason: "safe",
            payload_json: None,
        };
        for _ in 0..10 {
            tracking::record_decision(conn, &entry).unwrap();
        }
        for _ in 0..5 {
            tracking::record_decision(
                conn,
                &tracking::TrackingEntry {
                    decision: Decision::Ask,
                    command: Some("git push"),
                    reason: "review",
                    ..entry
                },
            )
            .unwrap();
        }
        for _ in 0..2 {
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
    fn stats_output_from_populated_db() {
        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("test.db");
        let conn = tracking::open_db(&db_path).unwrap();
        populate_db(&conn);

        let counts = tracking::query_counts(&conn, None).unwrap();
        assert_eq!(counts.total, 17);
        assert_eq!(counts.allow, 10);
        assert_eq!(counts.ask, 5);
        assert_eq!(counts.deny, 2);

        let top_asked = tracking::query_top_commands(&conn, "ask", None, 5).unwrap();
        assert_eq!(top_asked.len(), 1);
        assert_eq!(top_asked[0].0, "git push");

        let top_denied = tracking::query_top_commands(&conn, "deny", None, 5).unwrap();
        assert_eq!(top_denied.len(), 1);
        assert_eq!(top_denied[0].0, "rm -rf /");
    }

    #[test]
    fn stats_json_serializes() {
        let output = StatsOutput {
            db_path: "/tmp/test.db".to_string(),
            since: Some("7d".to_string()),
            counts: tracking::DecisionCounts {
                total: 100,
                allow: 70,
                ask: 25,
                deny: 5,
            },
            top_asked: vec![("git push".to_string(), 20)],
            top_denied: vec![("rm -rf /".to_string(), 3)],
        };
        let json = serde_json::to_string(&output).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["counts"]["total"], 100);
    }
}
