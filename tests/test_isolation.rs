//! A test run must never read or write the developer's own `~/.rippy`: with
//! `tracking = "on"` there, every spawned hook used to append a row to the real
//! tracking database (hundreds of MB of test commands), and `trust --yes` filled
//! the real `trusted.json` with temp-dir entries.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::Path;

const TRACKING_ON: &str = "[settings]\ntracking = \"on\"\n";

/// Ways a test could spawn rippy with the caller's real home. Clearing or
/// emptying `HOME` is as bad as a bare spawn: `dirs::home_dir()` (trust db,
/// jev, setup) then falls back to the passwd entry, i.e. the real `~`.
const ESCAPES: &[&str] = &[
    "CARGO_BIN_EXE_",
    "target/debug/rippy",
    "target/release/rippy",
    "Command::new(\"rippy\"",
    ".env_clear()",
    ".env_remove(\"HOME\")",
    ".env(\"HOME\", \"\")",
];

fn tracked_commands(home: &Path) -> Vec<String> {
    let conn = rusqlite::Connection::open(home.join(".rippy/tracking.db")).unwrap();
    let mut stmt = conn.prepare("SELECT command FROM decisions").unwrap();
    stmt.query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[test]
fn spawned_rippy_never_sees_the_callers_home() {
    let home = common::isolated_home();
    assert!(home.starts_with(env!("CARGO_TARGET_TMPDIR")), "{home:?}");
    if let Some(real) = std::env::var_os("HOME") {
        assert_ne!(home, Path::new(&real));
    }
}

#[test]
fn a_default_hook_run_tracks_into_the_isolated_home() {
    // The one deliberate write to the shared isolated home: no other test in
    // this binary relies on its tracking setting.
    let home = common::isolated_home();
    std::fs::create_dir_all(home.join(".rippy")).unwrap();
    std::fs::write(home.join(".rippy/config.toml"), TRACKING_ON).unwrap();

    let marker = "echo test-isolation-marker";
    let payload = serde_json::json!({"tool_name": "Bash", "tool_input": {"command": marker}});
    let (_, code) = common::run_rippy(&payload.to_string(), "claude", &[]);
    assert_eq!(code, 0);

    assert!(tracked_commands(home).iter().any(|c| c == marker));
}

#[test]
fn trust_yes_writes_the_trust_db_under_the_given_home() {
    let project = tempfile::TempDir::new().unwrap();
    let config = project.path().join(".rippy.toml");
    std::fs::write(
        &config,
        "[[rules]]\naction = \"deny\"\npattern = \"echo\"\n",
    )
    .unwrap();
    let home = tempfile::TempDir::new().unwrap();

    let output = common::rippy_command()
        .args(["trust", "--yes"])
        .current_dir(project.path())
        .env("HOME", home.path())
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");

    let db = std::fs::read_to_string(home.path().join(".rippy/trusted.json")).unwrap();
    let canonical = config.canonicalize().unwrap();
    assert!(
        db.contains(&*canonical.to_string_lossy()),
        "{canonical:?} not in {db}"
    );
}

#[test]
fn no_test_spawns_rippy_around_the_isolating_helper() {
    let tests = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let helper = tests.join("common/mod.rs");
    let mut offenders = Vec::new();
    let mut stack = vec![tests];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs")
                && path != helper
                && !path.ends_with(file!())
            {
                let text = std::fs::read_to_string(&path).unwrap();
                offenders.extend(
                    ESCAPES
                        .iter()
                        .filter(|needle| text.contains(**needle))
                        .map(|needle| format!("{}: {needle}", path.display())),
                );
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "spawn rippy with common::rippy_command() and a real HOME: {offenders:?}"
    );
}
