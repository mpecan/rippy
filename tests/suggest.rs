//! `rippy suggest` end to end: rule suggestions from `--from-command`, the tracking DB and
//! Claude Code session files, including the `--since` window on every source (#221).
#![allow(clippy::unwrap_used)]

mod common;

#[test]
fn suggest_from_command_output() {
    let dir = tempfile::TempDir::new().unwrap();
    let output = common::rippy_command()
        .args(["suggest", "--from-command", "git push origin main"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("git push origin main"));
    assert!(stdout.contains("git push *"));
    assert!(stdout.contains("git *"));

    // Suggest should NOT create a config file
    assert!(!dir.path().join(".rippy.toml").exists());
}

#[test]
fn suggest_from_db_json() {
    let dir = tempfile::TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");

    // Populate a tracking DB directly using rusqlite.
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         CREATE TABLE decisions (
             id INTEGER PRIMARY KEY,
             timestamp TEXT NOT NULL DEFAULT (datetime('now')),
             session_id TEXT, mode TEXT, tool_name TEXT NOT NULL,
             command TEXT, decision TEXT NOT NULL, reason TEXT, payload_json TEXT
         );",
    )
    .unwrap();
    // 15x allow git status
    for _ in 0..15 {
        conn.execute(
            "INSERT INTO decisions (tool_name, command, decision, reason) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params!["Bash", "git status", "allow", "safe"],
        )
        .unwrap();
    }
    // 8x deny rm -rf /
    for _ in 0..8 {
        conn.execute(
            "INSERT INTO decisions (tool_name, command, decision, reason) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params!["Bash", "rm -rf /", "deny", "dangerous"],
        )
        .unwrap();
    }
    drop(conn);

    let output = common::rippy_command()
        .args([
            "suggest",
            "--db",
            db_path.to_str().unwrap(),
            "--json",
            "--min-count",
            "3",
        ])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let suggestions: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let arr = suggestions.as_array().unwrap();
    assert!(arr.len() >= 2);

    // Should have a suggestion with allow action and one with deny
    let actions: Vec<&str> = arr.iter().filter_map(|s| s["action"].as_str()).collect();
    assert!(actions.contains(&"allow"));
    assert!(actions.contains(&"deny"));
}

/// A Claude Code session line pair: one `Bash` `tool_use` and its allowed `tool_result`.
fn session_lines(id: &str, command: &str, ts: &str) -> String {
    format!(
        concat!(
            r#"{{"type":"assistant","timestamp":"{ts}","message":{{"content":[{{"#,
            r#""type":"tool_use","id":"{id}","name":"Bash","#,
            r#""input":{{"command":"{command}"}}}}]}}}}"#,
            "\n",
            r#"{{"type":"user","timestamp":"{ts}","message":{{"content":[{{"type":"tool_result","#,
            r#""tool_use_id":"{id}","content":"ok"}}]}}}}"#,
            "\n",
        ),
        id = id,
        command = command,
        ts = ts,
    )
}

/// Write a session file: 4x `recent-tool run` from 10 minutes ago, 6x `old-tool run` from 2020.
fn write_mixed_age_session(dir: &std::path::Path) -> std::path::PathBuf {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let recent: String = conn
        .query_row(
            "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-10 minutes')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let mut content = String::new();
    for i in 0..4 {
        content.push_str(&session_lines(&format!("r{i}"), "recent-tool run", &recent));
    }
    for i in 0..6 {
        content.push_str(&session_lines(
            &format!("o{i}"),
            "old-tool run",
            "2020-01-01T00:00:00.000Z",
        ));
    }
    let path = dir.join("session.jsonl");
    std::fs::write(&path, content).unwrap();
    path
}

/// `(first example, evidence.total)` per suggestion in `rippy suggest --json` output.
fn suggestion_totals(stdout: &[u8]) -> Vec<(String, i64)> {
    let v: serde_json::Value = serde_json::from_slice(stdout).unwrap();
    let mut totals: Vec<(String, i64)> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            let example = s["evidence"]["example_commands"][0]
                .as_str()
                .unwrap()
                .to_string();
            (example, s["evidence"]["total"].as_i64().unwrap())
        })
        .collect();
    totals.sort();
    totals
}

/// Run `rippy suggest` with an isolated HOME and cwd of `dir`, returning the raw output.
fn suggest_in(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    common::rippy_command()
        .arg("suggest")
        .args(args)
        .env("HOME", dir)
        .current_dir(dir)
        .output()
        .unwrap()
}

fn suggest_session_totals(dir: &std::path::Path, extra: &[&str]) -> Vec<(String, i64)> {
    let session = write_mixed_age_session(dir);
    let mut args = vec!["--session-file", session.to_str().unwrap(), "--json"];
    args.extend(["--min-count", "1"]);
    args.extend(extra);
    let output = suggest_in(dir, &args);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    suggestion_totals(&output.stdout)
}

fn output_text(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&[output.stdout.as_slice(), &output.stderr].concat()).into_owned()
}

#[test]
fn suggest_session_file_honours_since() {
    let dir = tempfile::TempDir::new().unwrap();
    let all = suggest_session_totals(dir.path(), &[]);
    assert_eq!(
        all,
        [
            ("old-tool run".to_string(), 6),
            ("recent-tool run".to_string(), 4)
        ]
    );

    let recent = suggest_session_totals(dir.path(), &["--since", "1h"]);
    assert_eq!(recent, [("recent-tool run".to_string(), 4)]);
}

/// Put the mixed-age session where auto-detection looks for `dir`'s project, and return `dir`
/// canonicalized (the child's cwd resolves `/var` to `/private/var` on macOS).
fn install_project_session(dir: &std::path::Path) -> std::path::PathBuf {
    let cwd = dir.canonicalize().unwrap();
    let encoded = cwd
        .to_str()
        .unwrap()
        .trim_start_matches('/')
        .replace(['/', '.'], "-");
    let project = cwd.join(".claude/projects").join(format!("-{encoded}"));
    std::fs::create_dir_all(&project).unwrap();
    write_mixed_age_session(&project);
    cwd
}

#[test]
fn suggest_autodetected_sessions_honour_since() {
    let dir = tempfile::TempDir::new().unwrap();
    let cwd = install_project_session(dir.path());
    let all = suggest_in(&cwd, &["--json", "--min-count", "1"]);
    assert!(all.status.success(), "{}", output_text(&all));
    assert_eq!(
        suggestion_totals(&all.stdout).len(),
        2,
        "both commands without a window"
    );

    let recent = suggest_in(&cwd, &["--json", "--min-count", "1", "--since", "1h"]);
    assert!(recent.status.success(), "{}", output_text(&recent));
    assert_eq!(
        suggestion_totals(&recent.stdout),
        [("recent-tool run".to_string(), 4)]
    );
}

#[test]
fn suggest_audit_respects_since() {
    let dir = tempfile::TempDir::new().unwrap();
    let session = write_mixed_age_session(dir.path());
    let path = session.to_str().unwrap();
    let all = suggest_in(dir.path(), &["--session-file", path, "--audit"]);
    assert!(
        output_text(&all).contains("Analyzed 10 commands"),
        "{}",
        output_text(&all)
    );
    let windowed = suggest_in(
        dir.path(),
        &["--session-file", path, "--audit", "--since", "1h"],
    );
    assert!(
        output_text(&windowed).contains("Analyzed 4 commands"),
        "{}",
        output_text(&windowed)
    );
}

#[test]
fn suggest_since_warns_about_untimed_session_commands() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("untimed.jsonl");
    let lines = session_lines("u", "untimed-tool run", "x").replace(r#""timestamp":"x","#, "");
    std::fs::write(&path, lines).unwrap();
    let args = [
        "--session-file",
        path.to_str().unwrap(),
        "--since",
        "365d",
        "--min-count",
        "1",
    ];
    let output = suggest_in(dir.path(), &args);
    assert!(output.status.success());
    let text = output_text(&output);
    assert!(
        text.contains("skipped 1 command(s) with no timestamp"),
        "{text}"
    );
    assert!(text.contains("No suggestions from the last 365d"), "{text}");
}

/// Write a tracking DB with 4x `recent-tool run` from 10 minutes ago and 4x `old-tool run`
/// from 10 days ago.
fn write_mixed_age_db(dir: &std::path::Path) -> std::path::PathBuf {
    let db_path = dir.join("mixed.db");
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute_batch(
        "CREATE TABLE decisions (
             id INTEGER PRIMARY KEY,
             timestamp TEXT NOT NULL DEFAULT (datetime('now')),
             session_id TEXT, mode TEXT, tool_name TEXT NOT NULL,
             command TEXT, decision TEXT NOT NULL, reason TEXT, payload_json TEXT
         );",
    )
    .unwrap();
    for (command, age) in [
        ("recent-tool run", "-10 minutes"),
        ("old-tool run", "-10 days"),
    ] {
        for _ in 0..4 {
            conn.execute(
                "INSERT INTO decisions (timestamp, tool_name, command, decision, reason) \
                 VALUES (datetime('now', ?1), 'Bash', ?2, 'allow', 'user')",
                rusqlite::params![age, command],
            )
            .unwrap();
        }
    }
    db_path
}

#[test]
fn suggest_db_honours_since() {
    let dir = tempfile::TempDir::new().unwrap();
    let db = write_mixed_age_db(dir.path());
    let args = [
        "--db",
        db.to_str().unwrap(),
        "--json",
        "--min-count",
        "1",
        "--since",
        "1d",
    ];
    let output = suggest_in(dir.path(), &args);
    assert!(output.status.success(), "{}", output_text(&output));
    assert_eq!(
        suggestion_totals(&output.stdout),
        [("recent-tool run".to_string(), 4)]
    );
}

#[test]
fn suggest_rejects_invalid_since_on_every_source() {
    let dir = tempfile::TempDir::new().unwrap();
    let session = write_mixed_age_session(dir.path());
    let db = write_mixed_age_db(dir.path());
    let cwd = install_project_session(dir.path());
    let sources: [&[&str]; 3] = [
        &["--session-file", session.to_str().unwrap()],
        &["--db", db.to_str().unwrap()],
        &[],
    ];
    for source in sources {
        for (since, expect) in [
            ("garbage", "invalid duration: garbage"),
            ("999999999d", "--since 999999999d reaches back"),
        ] {
            let mut args = source.to_vec();
            args.extend(["--since", since]);
            let output = suggest_in(&cwd, &args);
            assert!(!output.status.success(), "{args:?} should fail");
            assert!(
                output_text(&output).contains(expect),
                "{args:?}: {}",
                output_text(&output)
            );
        }
    }
}
