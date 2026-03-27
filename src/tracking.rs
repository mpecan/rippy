//! SQLite-based decision tracking for auditing and analysis.

use std::path::Path;

use rusqlite::Connection;

use crate::error::RippyError;
use crate::mode::Mode;
use crate::verdict::Decision;

/// A decision entry to record in the tracking database.
pub struct TrackingEntry<'a> {
    pub session_id: Option<&'a str>,
    pub mode: Mode,
    pub tool_name: &'a str,
    pub command: Option<&'a str>,
    pub decision: Decision,
    pub reason: &'a str,
    pub payload_json: Option<&'a str>,
}

/// Open (or create) the tracking database and ensure the schema exists.
///
/// # Errors
///
/// Returns `RippyError::Tracking` if the database cannot be opened or
/// the schema cannot be created.
pub fn open_db(path: &Path) -> Result<Connection, RippyError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            RippyError::Tracking(format!(
                "could not create directory {}: {e}",
                parent.display()
            ))
        })?;
    }

    let conn = Connection::open(path)
        .map_err(|e| RippyError::Tracking(format!("could not open {}: {e}", path.display())))?;

    // WAL mode for concurrent reads during writes, NORMAL sync for speed.
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
        .map_err(|e| RippyError::Tracking(format!("could not set pragmas: {e}")))?;

    ensure_schema(&conn)?;
    Ok(conn)
}

fn ensure_schema(conn: &Connection) -> Result<(), RippyError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS decisions (
            id INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL DEFAULT (datetime('now')),
            session_id TEXT,
            mode TEXT,
            tool_name TEXT NOT NULL,
            command TEXT,
            decision TEXT NOT NULL,
            reason TEXT,
            payload_json TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_decisions_timestamp ON decisions(timestamp);
        CREATE INDEX IF NOT EXISTS idx_decisions_decision ON decisions(decision);
        CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
        INSERT OR IGNORE INTO schema_version (rowid, version) VALUES (1, 1);",
    )
    .map_err(|e| RippyError::Tracking(format!("could not create schema: {e}")))
}

/// Record a single decision in the tracking database.
///
/// # Errors
///
/// Returns `RippyError::Tracking` if the insert fails.
pub fn record_decision(conn: &Connection, entry: &TrackingEntry) -> Result<(), RippyError> {
    conn.execute(
        "INSERT INTO decisions (session_id, mode, tool_name, command, decision, reason, payload_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            entry.session_id,
            mode_str(entry.mode),
            entry.tool_name,
            entry.command,
            entry.decision.as_str(),
            entry.reason,
            entry.payload_json,
        ],
    )
    .map_err(|e| RippyError::Tracking(format!("could not insert decision: {e}")))?;
    Ok(())
}

/// Record a decision, logging errors to stderr instead of propagating.
///
/// This is the hook-path entry point — it must never block or fail the hook.
pub fn record(db_path: &Path, entry: &TrackingEntry) {
    if let Err(e) = try_record(db_path, entry) {
        eprintln!("[rippy] tracking error: {e}");
    }
}

fn try_record(db_path: &Path, entry: &TrackingEntry) -> Result<(), RippyError> {
    let conn = open_db(db_path)?;
    record_decision(&conn, entry)
}

const fn mode_str(mode: Mode) -> &'static str {
    match mode {
        Mode::Claude => "claude",
        Mode::Gemini => "gemini",
        Mode::Cursor => "cursor",
        Mode::Codex => "codex",
    }
}

/// Query aggregate decision counts from the tracking database.
///
/// # Errors
///
/// Returns `RippyError::Tracking` if the database cannot be queried.
pub fn query_counts(conn: &Connection, since: Option<&str>) -> Result<DecisionCounts, RippyError> {
    let (where_clause, params) = build_since_filter(since);

    let mut stmt = conn
        .prepare(&format!(
            "SELECT decision, COUNT(*) FROM decisions {where_clause} GROUP BY decision"
        ))
        .map_err(|e| RippyError::Tracking(format!("query failed: {e}")))?;

    let mut counts = DecisionCounts::default();
    let rows = stmt
        .query_map(rusqlite::params_from_iter(&params), |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .map_err(|e| RippyError::Tracking(format!("query failed: {e}")))?;

    for row in rows {
        let (decision, count) = row.map_err(|e| RippyError::Tracking(format!("{e}")))?;
        match decision.as_str() {
            "allow" => counts.allow = count,
            "ask" => counts.ask = count,
            "deny" => counts.deny = count,
            _ => {}
        }
    }
    counts.total = counts.allow + counts.ask + counts.deny;
    Ok(counts)
}

/// Query top commands by decision type.
///
/// # Errors
///
/// Returns `RippyError::Tracking` if the database cannot be queried.
pub fn query_top_commands(
    conn: &Connection,
    decision_filter: &str,
    since: Option<&str>,
    limit: usize,
) -> Result<Vec<(String, i64)>, RippyError> {
    let (where_clause, params) = build_since_filter(since);

    let decision_clause = if where_clause.is_empty() {
        format!("WHERE decision = '{decision_filter}'")
    } else {
        format!("{where_clause} AND decision = '{decision_filter}'")
    };

    let mut stmt = conn
        .prepare(&format!(
            "SELECT command, COUNT(*) as cnt FROM decisions \
             {decision_clause} AND command IS NOT NULL \
             GROUP BY command ORDER BY cnt DESC LIMIT {limit}"
        ))
        .map_err(|e| RippyError::Tracking(format!("query failed: {e}")))?;

    let rows = stmt
        .query_map(rusqlite::params_from_iter(&params), |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .map_err(|e| RippyError::Tracking(format!("query failed: {e}")))?;

    rows.map(|r| r.map_err(|e| RippyError::Tracking(format!("{e}"))))
        .collect()
}

fn build_since_filter(since: Option<&str>) -> (String, Vec<String>) {
    since.map_or_else(
        || (String::new(), vec![]),
        |duration| {
            (
                format!("WHERE timestamp >= datetime('now', '-{duration}')"),
                vec![],
            )
        },
    )
}

/// Parse a duration string like `7d`, `30d`, `1h`, `30m` into a `SQLite` modifier format.
///
/// Returns `None` if the format is invalid.
#[must_use]
pub fn parse_duration(input: &str) -> Option<String> {
    let input = input.trim();
    if input.len() < 2 {
        return None;
    }
    let (num_str, unit) = input.split_at(input.len() - 1);
    let num: u64 = num_str.parse().ok()?;
    let sqlite_unit = match unit {
        "s" => "seconds",
        "m" => "minutes",
        "h" => "hours",
        "d" => "days",
        _ => return None,
    };
    Some(format!("{num} {sqlite_unit}"))
}

/// Aggregate decision counts.
#[derive(Debug, Default, serde::Serialize)]
pub struct DecisionCounts {
    pub total: i64,
    pub allow: i64,
    pub ask: i64,
    pub deny: i64,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn in_memory_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            .unwrap();
        ensure_schema(&conn).unwrap();
        conn
    }

    fn sample_entry() -> TrackingEntry<'static> {
        TrackingEntry {
            session_id: Some("test-session"),
            mode: Mode::Claude,
            tool_name: "Bash",
            command: Some("git status"),
            decision: Decision::Allow,
            reason: "safe command",
            payload_json: None,
        }
    }

    #[test]
    fn record_and_query_counts() {
        let conn = in_memory_db();
        record_decision(&conn, &sample_entry()).unwrap();
        record_decision(
            &conn,
            &TrackingEntry {
                decision: Decision::Ask,
                command: Some("git push"),
                reason: "needs review",
                ..sample_entry()
            },
        )
        .unwrap();
        record_decision(
            &conn,
            &TrackingEntry {
                decision: Decision::Deny,
                command: Some("rm -rf /"),
                reason: "dangerous",
                ..sample_entry()
            },
        )
        .unwrap();

        let counts = query_counts(&conn, None).unwrap();
        assert_eq!(counts.total, 3);
        assert_eq!(counts.allow, 1);
        assert_eq!(counts.ask, 1);
        assert_eq!(counts.deny, 1);
    }

    #[test]
    fn query_top_commands() {
        let conn = in_memory_db();
        for _ in 0..5 {
            record_decision(
                &conn,
                &TrackingEntry {
                    decision: Decision::Ask,
                    command: Some("git push"),
                    reason: "review",
                    ..sample_entry()
                },
            )
            .unwrap();
        }
        for _ in 0..3 {
            record_decision(
                &conn,
                &TrackingEntry {
                    decision: Decision::Ask,
                    command: Some("npm install"),
                    reason: "review",
                    ..sample_entry()
                },
            )
            .unwrap();
        }

        let top = super::query_top_commands(&conn, "ask", None, 5).unwrap();
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].0, "git push");
        assert_eq!(top[0].1, 5);
        assert_eq!(top[1].0, "npm install");
        assert_eq!(top[1].1, 3);
    }

    #[test]
    fn open_db_creates_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("sub").join("tracking.db");
        let conn = open_db(&db_path).unwrap();
        record_decision(&conn, &sample_entry()).unwrap();
        assert!(db_path.exists());
    }

    #[test]
    fn parse_duration_valid() {
        assert_eq!(parse_duration("7d"), Some("7 days".to_string()));
        assert_eq!(parse_duration("1h"), Some("1 hours".to_string()));
        assert_eq!(parse_duration("30m"), Some("30 minutes".to_string()));
        assert_eq!(parse_duration("60s"), Some("60 seconds".to_string()));
    }

    #[test]
    fn parse_duration_invalid() {
        assert_eq!(parse_duration(""), None);
        assert_eq!(parse_duration("d"), None);
        assert_eq!(parse_duration("abc"), None);
        assert_eq!(parse_duration("7x"), None);
    }

    #[test]
    fn schema_version_recorded() {
        let conn = in_memory_db();
        let version: i32 = conn
            .query_row("SELECT version FROM schema_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 1);
    }

    #[test]
    fn null_fields_handled() {
        let conn = in_memory_db();
        record_decision(
            &conn,
            &TrackingEntry {
                session_id: None,
                command: None,
                payload_json: None,
                ..sample_entry()
            },
        )
        .unwrap();
        let counts = query_counts(&conn, None).unwrap();
        assert_eq!(counts.total, 1);
    }

    #[test]
    fn idempotent_schema() {
        let conn = in_memory_db();
        // Second call should not error.
        ensure_schema(&conn).unwrap();
        record_decision(&conn, &sample_entry()).unwrap();
    }
}
