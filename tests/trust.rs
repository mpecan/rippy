#![allow(clippy::unwrap_used)]

mod common;
use common::run_rippy;

// ---- Trust model integration tests ----

#[test]
fn trust_untrusted_project_config_ignored() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        dir.path().join(".rippy.toml"),
        "[[rules]]\naction = \"deny\"\npattern = \"echo *\"\nmessage = \"blocked\"\n",
    )
    .unwrap();

    // Without trust, the project config should be ignored.
    // echo is simple_safe → allowed despite the deny rule.
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"echo hello"}}"#;
    let (stdout, code) = common::run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 0, "untrusted project config should be ignored");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn trust_untrusted_config_emits_stderr_warning() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        dir.path().join(".rippy.toml"),
        "[[rules]]\naction = \"deny\"\npattern = \"echo *\"\n",
    )
    .unwrap();

    let json = r#"{"tool_name":"Bash","tool_input":{"command":"echo hello"}}"#;
    let mut cmd = std::process::Command::new(common::rippy_binary());
    cmd.arg("--mode")
        .arg("claude")
        .current_dir(dir.path())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().unwrap();
    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().unwrap();
        let _ = stdin.write_all(json.as_bytes());
    }
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("untrusted project config"),
        "stderr should warn about untrusted config, got: {stderr}"
    );
}

#[test]
fn trust_trusted_project_config_applied() {
    let dir = tempfile::TempDir::new().unwrap();
    let config_path = dir.path().join(".rippy.toml");
    std::fs::write(
        &config_path,
        "[[rules]]\naction = \"deny\"\npattern = \"echo *\"\nmessage = \"blocked\"\n",
    )
    .unwrap();

    // Trust the config by writing a trust DB entry at HOME/.rippy/trusted.json.
    let content = std::fs::read_to_string(&config_path).unwrap();
    let fake_home = dir.path().join("fakehome");
    let rippy_dir = fake_home.join(".rippy");
    std::fs::create_dir_all(&rippy_dir).unwrap();
    let trust_db_path = rippy_dir.join("trusted.json");
    let mut db = rippy_cli::trust::TrustDb::load_from(&trust_db_path);
    db.trust(&config_path, &content);
    db.save().unwrap();

    // Run rippy with HOME pointing to our fake home.
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"echo hello"}}"#;
    let mut cmd = std::process::Command::new(common::rippy_binary());
    cmd.arg("--mode")
        .arg("claude")
        .current_dir(dir.path())
        .env("HOME", &fake_home)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().unwrap();
    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().unwrap();
        let _ = stdin.write_all(json.as_bytes());
    }
    let output = child.wait_with_output().unwrap();
    let code = output.status.code().unwrap_or(-1);
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        code, 2,
        "trusted deny rule should block echo, stdout: {stdout_str}"
    );
}

#[test]
fn trust_global_setting_bypasses_check() {
    let dir = tempfile::TempDir::new().unwrap();
    // Project config denies echo.
    std::fs::write(
        dir.path().join(".rippy.toml"),
        "[[rules]]\naction = \"deny\"\npattern = \"echo *\"\nmessage = \"blocked\"\n",
    )
    .unwrap();

    // Global config enables trust-project-configs.
    let home = dir.path().join("fakehome");
    let rippy_dir = home.join(".rippy");
    std::fs::create_dir_all(&rippy_dir).unwrap();
    std::fs::write(
        rippy_dir.join("config.toml"),
        "[settings]\ntrust-project-configs = true\n",
    )
    .unwrap();

    let json = r#"{"tool_name":"Bash","tool_input":{"command":"echo hello"}}"#;
    let mut cmd = std::process::Command::new(common::rippy_binary());
    cmd.arg("--mode")
        .arg("claude")
        .current_dir(dir.path())
        .env("HOME", &home)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().unwrap();
    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().unwrap();
        let _ = stdin.write_all(json.as_bytes());
    }
    let output = child.wait_with_output().unwrap();
    let code = output.status.code().unwrap_or(-1);
    // With trust-project-configs=true, the deny rule should apply.
    assert_eq!(code, 2, "global trust setting should load project config");
}

#[test]
fn trust_command_status_untrusted() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(dir.path().join(".rippy"), "allow git status\n").unwrap();

    let output = std::process::Command::new(common::rippy_binary())
        .args(["trust", "--status"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("untrusted"),
        "should show untrusted status, got: {stderr}"
    );
    assert_eq!(output.status.code().unwrap_or(-1), 2);
}

#[test]
fn trust_command_revoke() {
    let dir = tempfile::TempDir::new().unwrap();
    let config_path = dir.path().join(".rippy");
    std::fs::write(&config_path, "allow git status\n").unwrap();

    // Trust it first via the trust DB.
    let content = std::fs::read_to_string(&config_path).unwrap();
    let trust_dir = dir.path().join(".rippy_home");
    let rippy_dir = trust_dir.join(".rippy");
    std::fs::create_dir_all(&rippy_dir).unwrap();
    let trust_db_path = rippy_dir.join("trusted.json");
    let mut db = rippy_cli::trust::TrustDb::load_from(&trust_db_path);
    db.trust(&config_path, &content);
    db.save().unwrap();

    // Revoke it.
    let output = std::process::Command::new(common::rippy_binary())
        .args(["trust", "--revoke"])
        .current_dir(dir.path())
        .env("HOME", &trust_dir)
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("revoked"),
        "should confirm revocation, got: {stderr}"
    );
    assert_eq!(output.status.code().unwrap_or(-1), 0);

    // Verify it's now untrusted.
    let db2 = rippy_cli::trust::TrustDb::load_from(&trust_db_path);
    assert_eq!(
        db2.check(&config_path, &content),
        rippy_cli::trust::TrustStatus::Untrusted
    );
}

#[test]
fn trust_modified_config_is_ignored() {
    let dir = tempfile::TempDir::new().unwrap();
    let config_path = dir.path().join(".rippy.toml");
    let original = "[[rules]]\naction = \"deny\"\npattern = \"echo *\"\nmessage = \"blocked\"\n";
    std::fs::write(&config_path, original).unwrap();

    // Trust the original content.
    let fake_home = dir.path().join("fakehome");
    let rippy_dir = fake_home.join(".rippy");
    std::fs::create_dir_all(&rippy_dir).unwrap();
    let trust_db_path = rippy_dir.join("trusted.json");
    let mut db = rippy_cli::trust::TrustDb::load_from(&trust_db_path);
    db.trust(&config_path, original);
    db.save().unwrap();

    // Modify the config after trusting.
    std::fs::write(
        &config_path,
        "[[rules]]\naction = \"allow\"\npattern = \"*\"\n",
    )
    .unwrap();

    // Run rippy — modified config should be ignored.
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"echo hello"}}"#;
    let mut cmd = std::process::Command::new(common::rippy_binary());
    cmd.arg("--mode")
        .arg("claude")
        .current_dir(dir.path())
        .env("HOME", &fake_home)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().unwrap();
    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().unwrap();
        let _ = stdin.write_all(json.as_bytes());
    }
    let output = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("modified since last trust"),
        "should warn about modified config, got: {stderr}"
    );
    // echo should be allowed (config was ignored).
    assert_eq!(output.status.code().unwrap_or(-1), 0);
}

#[test]
fn trust_command_yes_trusts_without_stdin() {
    let dir = tempfile::TempDir::new().unwrap();
    let config_path = dir.path().join(".rippy");
    std::fs::write(&config_path, "deny echo\n").unwrap();

    let output = std::process::Command::new(common::rippy_binary())
        .args(["trust", "--yes"])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("trusted"),
        "should confirm trust, got: {stderr}"
    );
    assert_eq!(output.status.code().unwrap_or(-1), 0);
}

#[test]
fn trust_command_list_empty() {
    let dir = tempfile::TempDir::new().unwrap();
    let output = std::process::Command::new(common::rippy_binary())
        .args(["trust", "--list"])
        .current_dir(dir.path())
        .env("HOME", dir.path())
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no trusted project configs"),
        "should report empty, got: {stderr}"
    );
    assert_eq!(output.status.code().unwrap_or(-1), 0);
}

#[test]
fn trust_command_status_when_trusted() {
    let dir = tempfile::TempDir::new().unwrap();
    let config_path = dir.path().join(".rippy");
    std::fs::write(&config_path, "allow git status\n").unwrap();

    let content = std::fs::read_to_string(&config_path).unwrap();
    let fake_home = dir.path().join("fakehome");
    let rippy_dir = fake_home.join(".rippy");
    std::fs::create_dir_all(&rippy_dir).unwrap();
    let trust_db_path = rippy_dir.join("trusted.json");
    let mut db = rippy_cli::trust::TrustDb::load_from(&trust_db_path);
    db.trust(&config_path, &content);
    db.save().unwrap();

    let output = std::process::Command::new(common::rippy_binary())
        .args(["trust", "--status"])
        .current_dir(dir.path())
        .env("HOME", &fake_home)
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("trusted:"),
        "should show trusted status, got: {stderr}"
    );
    assert_eq!(output.status.code().unwrap_or(-1), 0);
}

#[test]
fn self_protect_blocks_trust_db_write() {
    let json = r#"{"tool_name":"Write","tool_input":{"file_path":"/home/user/.rippy/trusted.json","content":"{}"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 2, "self-protect should block trust DB writes");
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn trust_repo_level_survives_config_change() {
    // Trust a config in a git repo, then change the file — should still be trusted
    // because repo_id matches.
    let dir = tempfile::TempDir::new().unwrap();
    std::process::Command::new("git")
        .args(["init"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    std::process::Command::new("git")
        .args([
            "remote",
            "add",
            "origin",
            "git@github.com:test/trust-repo.git",
        ])
        .current_dir(dir.path())
        .output()
        .unwrap();

    let config_path = dir.path().join(".rippy.toml");
    let original = "[[rules]]\naction = \"deny\"\npattern = \"echo *\"\nmessage = \"blocked\"\n";
    std::fs::write(&config_path, original).unwrap();

    // Trust it (which stores repo_id).
    let fake_home = dir.path().join("fakehome");
    let rippy_dir = fake_home.join(".rippy");
    std::fs::create_dir_all(&rippy_dir).unwrap();
    let trust_db_path = rippy_dir.join("trusted.json");
    let mut db = rippy_cli::trust::TrustDb::load_from(&trust_db_path);
    db.trust(&config_path, original);
    db.save().unwrap();

    // Modify the config (simulates git pull changing the file).
    let updated =
        "[[rules]]\naction = \"deny\"\npattern = \"echo *\"\nmessage = \"updated block\"\n";
    std::fs::write(&config_path, updated).unwrap();

    // Run rippy — should still trust because repo_id matches.
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"echo hello"}}"#;
    let mut cmd = std::process::Command::new(common::rippy_binary());
    cmd.arg("--mode")
        .arg("claude")
        .current_dir(dir.path())
        .env("HOME", &fake_home)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn().unwrap();
    {
        use std::io::Write;
        let stdin = child.stdin.as_mut().unwrap();
        let _ = stdin.write_all(json.as_bytes());
    }
    let output = child.wait_with_output().unwrap();
    let code = output.status.code().unwrap_or(-1);
    // The deny rule should apply — config is trusted via repo_id.
    assert_eq!(code, 2, "repo-level trust should survive config change");
}

#[test]
fn trust_guard_preserves_trust_after_allow() {
    // Verify TrustGuard works: trust a config, write to it via guard, verify still trusted.
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("trusted.json");
    let config_path = dir.path().join(".rippy.toml");

    let original = "[[rules]]\naction = \"deny\"\npattern = \"rm *\"\n";
    std::fs::write(&config_path, original).unwrap();

    // Trust the original.
    let mut db = rippy_cli::trust::TrustDb::load_from(&db_path);
    db.trust(&config_path, original);
    db.save().unwrap();

    // Verify trusted.
    assert_eq!(
        db.check(&config_path, original),
        rippy_cli::trust::TrustStatus::Trusted
    );

    // Simulate a write that changes the content.
    let updated = format!("{original}\n[[rules]]\naction = \"allow\"\npattern = \"git status\"\n");
    std::fs::write(&config_path, &updated).unwrap();

    // Without guard, hash mismatch → modified. But check() also considers repo_id,
    // and there's no git repo here, so it falls back to hash → Modified.
    let status = db.check(&config_path, &updated);
    assert!(
        matches!(status, rippy_cli::trust::TrustStatus::Modified { .. }),
        "without guard, changed hash should be Modified"
    );

    // Now simulate the guard flow: re-trust after write.
    db.trust(&config_path, &updated);
    db.save().unwrap();

    let db2 = rippy_cli::trust::TrustDb::load_from(&db_path);
    assert_eq!(
        db2.check(&config_path, &updated),
        rippy_cli::trust::TrustStatus::Trusted,
        "after guard commit, should be trusted with new hash"
    );
}

#[test]
fn trust_guard_does_not_grant_trust_to_untrusted_file() {
    // If a file was never trusted, TrustGuard::before_write should not
    // grant trust after the write.
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("trusted.json");
    let config_path = dir.path().join(".rippy.toml");

    let malicious = "[[rules]]\naction = \"allow\"\npattern = \"*\"\n";
    std::fs::write(&config_path, malicious).unwrap();

    // File is untrusted (no DB entry).
    let db = rippy_cli::trust::TrustDb::load_from(&db_path);
    assert_eq!(
        db.check(&config_path, malicious),
        rippy_cli::trust::TrustStatus::Untrusted
    );

    // TrustGuard::before_write sees untrusted → was_trusted = false.
    let guard = rippy_cli::trust::TrustGuard::before_write(&config_path);

    // Append a rule (simulating `rippy allow`).
    let updated = format!("{malicious}\n[[rules]]\naction = \"deny\"\npattern = \"rm *\"\n");
    std::fs::write(&config_path, &updated).unwrap();

    // Commit should be a no-op since file was not trusted before.
    guard.commit();

    // Verify still untrusted.
    let db2 = rippy_cli::trust::TrustDb::load_from(&db_path);
    assert_eq!(
        db2.check(&config_path, &updated),
        rippy_cli::trust::TrustStatus::Untrusted,
        "guard should not grant trust to previously untrusted file"
    );
}
