//! Secrets never reach anything rippy shows or keeps: the hook's reason, the
//! tracking database or the log (docs/security-invariants.md#history-redaction).
//! Each command is run through the real binary with the secret in its
//! environment, as it would be under Claude Code.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::io::Write;
use std::path::Path;
use std::process::Stdio;

/// Marks a case whose secret is typed into the command, not in the environment.
const LITERAL: &str = "RIPPY_TEST_UNUSED";

/// `(command, env var, its value)`: the value is what must never appear.
const CASES: &[(&str, &str, &str)] = &[
    // A provider-shaped value, expanded.
    (
        "echo $GH_TOKEN",
        "GH_TOKEN",
        "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
    ),
    // A value with no secret shape, behind a secret name.
    (
        "somecli --dbname app $DB_PASSWORD",
        "DB_PASSWORD",
        "hunter2x",
    ),
    // Inside a quoted header.
    (
        "curl -H \"Authorization: Bearer $API_TOKEN\" https://api.example.com/x",
        "API_TOKEN",
        "tok3n-v4lue-abc",
    ),
    // In URL userinfo.
    (
        "git push https://x:$GL_PAT@gitlab.com/o/r",
        "GL_PAT",
        concat!("glp", "at-xxxxYYYYzzzz1111AAAA"),
    ),
    // Typed literally into the command.
    (
        "curl -u admin:hunt3r-pw https://x.example",
        LITERAL,
        "hunt3r-pw",
    ),
    // Review: reasons built from the resolved command quote its arguments.
    ("tee $MY_TOKEN", "MY_TOKEN", "plainvalue77"),
    ("git $DB_PASSWORD", "DB_PASSWORD", "hunter2secret"),
    ("gh $DB_PASSWORD", "DB_PASSWORD", "hunter2secret"),
    (
        "curl https://x.io -o $DB_PASSWORD",
        "DB_PASSWORD",
        "hunter2secret",
    ),
    ("bash -c \"echo $GH_TOKEN\"", "GH_TOKEN", "hunter2fakeplain"),
    (
        "git -c core.x=$GH_TOKEN log",
        "GH_TOKEN",
        "hunter2fakeplain",
    ),
    ("mkdir -p /etc/$GH_TOKEN", "GH_TOKEN", "hunter2fakeplain"),
    ("cd /$GH_TOKEN", "GH_TOKEN", "hunter2fakeplain"),
    ("env echo $GH_TOKEN", "GH_TOKEN", "hunter2fakeplain"),
    (
        "find . -exec echo $GH_TOKEN \\;",
        "GH_TOKEN",
        "hunter2fakeplain",
    ),
    ("echo $PGPASSWORD", "PGPASSWORD", "pgvalue1234"),
    ("systemctl $GH_TOKEN", "GH_TOKEN", "fa'kevalue99"),
    // Second review round: a trace line renders values with `{:?}`, which
    // escapes backslashes, quotes and newlines.
    ("git $MY_TOKEN", "MY_TOKEN", "p\\ssw0rdXYZ12"),
    ("bash -c \"echo $Q_TOKEN\"", "Q_TOKEN", "sec\"ret\"part99"),
    (
        "git $NL_TOKEN",
        "NL_TOKEN",
        "firstsecretline\nsecondsecretline",
    ),
    // A value re-parsed as shell leaks word by word unless scrubbed so.
    (
        "sh -c $X_TOKEN",
        "X_TOKEN",
        "echo hi > /etc/hunter2secretpart",
    ),
    // A Claude Code permission rule quotes the matched command.
    ("echo $DB_PASSWORD", "DB_PASSWORD", "hunter2ccrule"),
];

/// Whether `text` holds `value`, or any part of it the shell's quoting would
/// leave intact (`fa'kevalue` is shown as `'fa'\''kevalue'`).
fn leaks(text: &str, value: &str) -> bool {
    text.contains(value)
        || value
            .split(['\'', '"', '\\', '\n', ' '])
            .filter(|part| part.len() >= 8)
            .any(|part| text.contains(part))
}

/// The hook's stdout and its `-v` trace on stderr.
fn run_hook(command: &str, var: &str, value: &str, config: &Path, home: &Path) -> String {
    let payload = serde_json::json!({
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "hook_event_name": "PreToolUse",
    });
    let mut child = common::rippy_command()
        .args(["--mode", "claude", "-v"])
        .env("HOME", home)
        .env("RIPPY_CONFIG", config)
        .env(var, value)
        .current_dir(home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.to_string().as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// `rippy inspect --json` for `command`, with `var` set.
fn inspect(command: &str, var: &str, value: &str, home: &Path) -> String {
    let out = common::rippy_command()
        .args(["inspect", "--json", command])
        .env("HOME", home)
        .env(var, value)
        .current_dir(home)
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn no_secret_reaches_the_reason_the_database_or_the_log() {
    let dir = tempfile::tempdir().unwrap();
    let (db, log, config) = (
        dir.path().join("tracking.db"),
        dir.path().join("rippy.log"),
        dir.path().join("config"),
    );
    std::fs::write(
        &config,
        format!(
            "set tracking {}\nset log {}\nset log-full\n",
            db.display(),
            log.display()
        ),
    )
    .unwrap();
    std::fs::create_dir_all(dir.path().join(".claude")).unwrap();
    std::fs::write(
        dir.path().join(".claude/settings.json"),
        r#"{"permissions": {"allow": ["Bash(echo:*)"]}}"#,
    )
    .unwrap();
    for (command, var, value) in CASES {
        let reply = run_hook(command, var, value, &config, dir.path());
        assert!(reply.contains("permissionDecision"), "{command}: {reply}");
        // A secret typed into the command is the AI's own text: only what is
        // kept (database, log) must hide it. An environment value must never
        // be shown at all.
        if *var == LITERAL {
            continue;
        }
        assert!(
            !leaks(&reply, value),
            "{command}: reason or trace leaks {value}: {reply}"
        );
        let inspected = inspect(command, var, value, dir.path());
        assert!(
            !leaks(&inspected, value),
            "{command}: inspect leaks {value}: {inspected}"
        );
    }
    // Byte-level, so no copy survives anywhere in the files.
    let db_bytes = std::fs::read(&db).unwrap();
    let log_text = std::fs::read_to_string(&log).unwrap();
    for (command, _, value) in CASES {
        let found = db_bytes.windows(value.len()).any(|w| w == value.as_bytes());
        assert!(!found, "{command}: tracking db keeps {value}");
        assert!(!log_text.contains(value), "{command}: log keeps {value}");
    }
    assert!(log_text.contains("<redacted>"), "{log_text}");
}

// The resolution itself still happens: only its display is redacted, so a
// value that makes the command dangerous still decides the verdict.
#[test]
fn a_redacted_value_still_decides_the_verdict() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config");
    std::fs::write(&config, "").unwrap();
    let reply = run_hook("$DEPLOY_TOKEN", "DEPLOY_TOKEN", "rm", &config, dir.path());
    assert!(reply.contains("\"ask\""), "{reply}");
    let reply = run_hook(
        "echo $DEPLOY_TOKEN",
        "DEPLOY_TOKEN",
        "harmless-value",
        &config,
        dir.path(),
    );
    assert!(reply.contains("\"allow\""), "{reply}");
    assert!(!reply.contains("harmless-value"), "{reply}");
}

// A secret-named value that changes the subcommand changes the verdict,
// though both replies show only `git <redacted>`.
#[test]
fn the_hidden_value_picks_the_verdict() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config");
    std::fs::write(&config, "").unwrap();
    let reply = run_hook("git $GIT_TOKEN", "GIT_TOKEN", "status", &config, dir.path());
    assert!(reply.contains("\"allow\""), "{reply}");
    let reply = run_hook("git $GIT_TOKEN", "GIT_TOKEN", "push", &config, dir.path());
    assert!(reply.contains("\"ask\""), "{reply}");
    assert!(reply.contains("(resolved: git <redacted>)"), "{reply}");
}

// Only secret-named values are scrubbed by name; the rest of a resolution
// stays readable.
#[test]
fn an_ordinary_value_stays_visible() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config");
    std::fs::write(&config, "").unwrap();
    let reply = run_hook(
        "kubectl get pods -n $NS",
        "NS",
        "production",
        &config,
        dir.path(),
    );
    assert!(
        reply.contains("(resolved: kubectl get pods -n production)"),
        "{reply}"
    );
}

// A value bound on the command itself is scrubbed like one from the environment.
#[test]
fn a_command_local_secret_is_scrubbed() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config");
    std::fs::write(&config, "").unwrap();
    let reply = run_hook(
        "MY_TOKEN=hunter2x somecli $MY_TOKEN",
        "UNUSED",
        "x",
        &config,
        dir.path(),
    );
    // The hook's answer only: `-v` echoes the command as the AI typed it.
    let answer = reply.lines().next().unwrap_or_default();
    assert!(answer.contains("(resolved: somecli <redacted>)"), "{reply}");
    assert!(!answer.contains("hunter2x"), "{reply}");
}
