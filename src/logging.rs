use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::time::SystemTime;

use crate::mode::Mode;
use crate::verdict::Verdict;

/// Parameters for a log entry.
pub struct LogEntry<'a> {
    pub log_file: &'a Path,
    pub log_full: bool,
    pub command: Option<&'a str>,
    pub verdict: &'a Verdict,
    pub mode: Mode,
    pub raw_payload: Option<&'a serde_json::Value>,
}

/// Write a JSON log line to the configured log file.
/// Errors are printed to stderr but never block the hook.
pub fn write_log_entry(entry: &LogEntry<'_>) {
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut json = serde_json::json!({
        "timestamp": timestamp,
        "decision": entry.verdict.decision.as_str(),
        "reason": entry.verdict.reason,
    });

    if let Some(cmd) = entry.command {
        json["command"] = serde_json::Value::String(cmd.to_owned());
    }

    if entry.log_full {
        json["mode"] = serde_json::Value::String(format!("{:?}", entry.mode));
        if let Some(payload) = entry.raw_payload {
            json["payload"] = payload.clone();
        }
    }

    let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(entry.log_file)
    else {
        eprintln!(
            "[rppy] warning: could not open log file: {}",
            entry.log_file.display()
        );
        return;
    };

    if let Ok(line) = serde_json::to_string(&json)
        && writeln!(file, "{line}").is_err()
    {
        eprintln!(
            "[rppy] warning: could not write to log: {}",
            entry.log_file.display()
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::verdict::Decision;

    fn entry_to<'a>(
        log_path: &'a Path,
        log_full: bool,
        command: Option<&'a str>,
        verdict: &'a Verdict,
        raw_payload: Option<&'a serde_json::Value>,
    ) -> LogEntry<'a> {
        LogEntry {
            log_file: log_path,
            log_full,
            command,
            verdict,
            mode: Mode::Claude,
            raw_payload,
        }
    }

    #[test]
    fn writes_json_line() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("test.log");
        let verdict = Verdict::allow("test reason");

        write_log_entry(&entry_to(&log_path, false, Some("ls"), &verdict, None));

        let content = std::fs::read_to_string(&log_path).unwrap();
        let e: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(e["decision"], "allow");
        assert_eq!(e["reason"], "test reason");
        assert_eq!(e["command"], "ls");
        assert!(e["timestamp"].is_u64());
    }

    #[test]
    fn log_full_includes_payload() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("test.log");
        let verdict = Verdict::ask("needs review");
        let payload = serde_json::json!({"tool_name": "Bash"});

        write_log_entry(&entry_to(
            &log_path,
            true,
            Some("rm -rf /"),
            &verdict,
            Some(&payload),
        ));

        let content = std::fs::read_to_string(&log_path).unwrap();
        let e: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(e["decision"], "ask");
        assert_eq!(e["mode"], "Claude");
        assert_eq!(e["payload"]["tool_name"], "Bash");
    }

    #[test]
    fn bad_path_does_not_panic() {
        let verdict = Verdict::allow("ok");
        write_log_entry(&entry_to(
            Path::new("/nonexistent/dir/file.log"),
            false,
            Some("ls"),
            &verdict,
            None,
        ));
    }

    #[test]
    fn no_command_field_when_none() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("test.log");
        let verdict = Verdict::allow("no command");

        write_log_entry(&entry_to(&log_path, false, None, &verdict, None));

        let content = std::fs::read_to_string(&log_path).unwrap();
        let e: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert!(e.get("command").is_none());
        assert_eq!(e["decision"], "allow");
    }

    #[test]
    fn appends_multiple_entries() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("test.log");
        let v1 = Verdict::allow("safe");
        let v2 = Verdict {
            decision: Decision::Ask,
            reason: "dangerous".into(),
        };

        write_log_entry(&entry_to(&log_path, false, Some("ls"), &v1, None));
        write_log_entry(&entry_to(&log_path, false, Some("rm"), &v2, None));

        let content = std::fs::read_to_string(&log_path).unwrap();
        let line_count = content.trim().lines().count();
        assert_eq!(line_count, 2);
    }
}
