//! A test run must never read or write the developer's own `~/.rippy`: with
//! `tracking = "on"` there, every spawned hook used to append a row to the real
//! tracking database (hundreds of MB of test commands), and `trust --yes` filled
//! the real `trusted.json` with temp-dir entries.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::path::Path;

const TRACKING_ON: &str = "[settings]\ntracking = \"on\"\n";

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
    let cmd = common::rippy_command();
    let envs: Vec<_> = cmd.get_envs().collect();
    assert!(envs.contains(&("HOME".as_ref(), Some(home.as_os_str()))));
    assert!(envs.contains(&("RIPPY_CONFIG".as_ref(), None)));
    assert!(envs.contains(&("DIPPY_CONFIG".as_ref(), None)));
}

#[test]
fn a_default_hook_run_tracks_into_the_isolated_home() {
    // This binary's isolated home is used by no other test, so the config
    // written here cannot leak into another test.
    let home = common::isolated_home();
    std::fs::create_dir_all(home.join(".rippy")).unwrap();
    std::fs::write(home.join(".rippy/config.toml"), TRACKING_ON).unwrap();

    let marker = "echo test-isolation-marker";
    let payload = serde_json::json!({"tool_name": "Bash", "tool_input": {"command": marker}});
    let (_, code) = common::run_rippy(&payload.to_string(), "claude", &[]);
    assert_eq!(code, 0);

    assert_eq!(tracked_commands(home), [marker]);
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
                let direct = [
                    "CARGO_BIN_EXE_",
                    "target/debug/rippy",
                    "target/release/rippy",
                ];
                if direct.iter().any(|needle| text.contains(needle)) {
                    offenders.push(path);
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "spawn rippy with common::rippy_command() so it gets an isolated HOME: {offenders:?}"
    );
}
