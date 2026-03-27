#![allow(clippy::unwrap_used)]

mod common;
use common::{run_rippy, run_rippy_in_dir, run_rippy_with_stderr};

// ---- Claude mode tests ----

#[test]
fn claude_allow_safe_command() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn claude_ask_dangerous_command() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
}

#[test]
fn claude_pipeline_safe() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"cat file | grep pattern | sort"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn claude_git_push_asks() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"git push origin main"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
}

// ---- Gemini mode tests ----

#[test]
fn gemini_allow_safe() {
    let json = r#"{"tool_name":"bash","tool_input":"ls -la"}"#;
    let (stdout, code) = run_rippy(json, "gemini", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["decision"], "allow");
}

#[test]
fn gemini_deny_dangerous() {
    let json = r#"{"tool_name":"bash","tool_input":"rm -rf /"}"#;
    let (stdout, code) = run_rippy(json, "gemini", &[]);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    // Gemini maps Ask to deny
    assert_eq!(v["decision"], "deny");
}

// ---- Cursor mode tests ----

#[test]
fn cursor_allow_safe() {
    let json = r#"{"tool_name":"bash","command":"echo hello"}"#;
    let (stdout, code) = run_rippy(json, "cursor", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["permission"], "allow");
}

// ---- Config tests ----

#[test]
fn config_deny_overrides() {
    let config_path = format!("{}/tests/fixtures/test.rippy", env!("CARGO_MANIFEST_DIR"));
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/stuff"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &["--config", &config_path]);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(
        v["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("use trash instead")
    );
}

#[test]
fn config_allow_overrides() {
    let config_path = format!("{}/tests/fixtures/test.rippy", env!("CARGO_MANIFEST_DIR"));
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &["--config", &config_path]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

// ---- MCP tests ----

#[test]
fn mcp_tool_asks_by_default() {
    let json = r#"{"tool_name":"mcp__server__tool","tool_input":{}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
}

// ---- Error handling ----

#[test]
fn malformed_json_returns_error() {
    let (stdout, code) = run_rippy("not json", "claude", &[]);
    assert_eq!(code, 1);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(v["error"].as_str().is_some());
}

// ---- Complex commands ----

#[test]
fn bash_c_recurses() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"bash -c 'ls -la'"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn wrapper_time_git_status() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"time git status"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn redirect_to_dev_null_safe() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"echo foo > /dev/null"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn redirect_to_file_asks() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"echo foo > /tmp/output.txt"}}"#;
    let (_stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 2);
}

// ---- Verbose mode tests ----

#[test]
fn verbose_traces_to_stderr() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#;
    let (stdout, stderr, code) = run_rippy_with_stderr(json, "claude", &["--verbose"]);
    assert_eq!(code, 0);
    // stdout is still valid JSON
    let _v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    // stderr contains trace lines
    assert!(
        stderr.contains("[rippy]"),
        "stderr should contain [rippy] trace lines"
    );
    assert!(
        stderr.contains("command:"),
        "stderr should trace the command"
    );
}

#[test]
fn verbose_handler_trace() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"git push origin main"}}"#;
    let (_stdout, stderr, code) = run_rippy_with_stderr(json, "claude", &["--verbose"]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("[rippy] handler:"),
        "stderr should show handler decision"
    );
}

// ---- Handler fix tests (Issue #4) ----

#[test]
fn bash_c_with_positional_args_asks() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"bash -c '$0 $1' rm '-rf /'"}}"#;
    let (_stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 2);
}

#[test]
fn bash_c_without_positional_args_recurses() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"bash -c 'git status'"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn xargs_with_value_flags_finds_inner_command() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"xargs -n 5 -P 4 grep pattern"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

// ---- Resource limit tests (Issue #3) ----

#[test]
fn oversized_input_returns_error() {
    // Send > 1MB of input
    let big_json = format!(
        r#"{{"tool_name":"Bash","tool_input":{{"command":"echo {}"}}}}"#,
        "x".repeat(1_100_000)
    );
    let (stdout, code) = run_rippy(&big_json, "claude", &[]);
    assert_eq!(code, 1);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(v["error"].as_str().unwrap().contains("limit"));
}

// ---- Logging integration test (Issue #2) ----

#[test]
fn log_file_receives_entry() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("rippy.log");
    let config_path = dir.path().join("config");
    std::fs::write(&config_path, format!("set log {}", log_path.display())).unwrap();

    let json = r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#;
    let (_stdout, code) = run_rippy(json, "claude", &["--config", config_path.to_str().unwrap()]);
    assert_eq!(code, 0);

    let content = std::fs::read_to_string(&log_path).unwrap();
    let entry: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
    assert_eq!(entry["decision"], "allow");
    assert_eq!(entry["command"], "ls");
}

// ---- Heredoc tests ----

#[test]
fn heredoc_safe_allows() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"cat <<EOF\nhello\nEOF"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

// ---- Handler integration tests ----

#[test]
fn docker_exec_ls_allows() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"docker exec container ls"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn find_exec_grep_allows() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"find . -exec grep pattern {} ;"}}"#;
    let (_stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
}

#[test]
fn fd_search_allows() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"fd -e rs"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn fd_exec_rm_asks() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"fd -x rm"}}"#;
    let (_stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 2);
}

#[test]
fn fd_exec_batch_grep_allows() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"fd -X grep pattern"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn env_inner_command_analyzed() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"env FOO=bar ls"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

// ---- Ansible handler tests ----

#[test]
fn ansible_doc_allows() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"ansible-doc module_name"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn ansible_playbook_check_allows() {
    let json =
        r#"{"tool_name":"Bash","tool_input":{"command":"ansible-playbook site.yml --check"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn ansible_playbook_asks() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"ansible-playbook site.yml"}}"#;
    let (_stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 2);
}

#[test]
fn ansible_vault_view_allows() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"ansible-vault view secrets.yml"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn ansible_vault_encrypt_asks() {
    let json =
        r#"{"tool_name":"Bash","tool_input":{"command":"ansible-vault encrypt secrets.yml"}}"#;
    let (_stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 2);
}

#[test]
fn ansible_lint_allows() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"ansible-lint playbook.yml"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn ansible_galaxy_list_allows() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"ansible-galaxy list"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn ansible_galaxy_install_asks() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"ansible-galaxy install geerlingguy.docker"}}"#;
    let (_stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 2);
}

#[test]
fn ansible_config_dump_allows() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"ansible-config dump"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn ansible_inventory_list_allows() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"ansible-inventory --list"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

// ---- Python -c safety analysis tests ----

#[test]
fn python_c_print_allows() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"python -c 'print(1)'"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn python_c_import_os_asks() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"python -c 'import os; os.system(\"rm -rf /\")'"}}"#;
    let (_stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 2);
}

#[test]
fn python_c_import_json_allows() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"python -c 'import json; print(json.dumps({}))'"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn python_script_asks() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"python script.py"}}"#;
    let (_stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 2);
}

// ---- CC permission rules tests ----

#[test]
fn cc_allow_rule_auto_approves() {
    let dir = tempfile::tempdir().unwrap();
    let claude_dir = dir.path().join(".claude");
    std::fs::create_dir(&claude_dir).unwrap();
    std::fs::write(
        claude_dir.join("settings.local.json"),
        r#"{"permissions": {"allow": ["Bash(git push)"]}}"#,
    )
    .unwrap();
    // git push normally asks, but CC allow rule should auto-approve
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"git push origin main"}}"#;
    let (stdout, code) = common::run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn cc_deny_rule_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let claude_dir = dir.path().join(".claude");
    std::fs::create_dir(&claude_dir).unwrap();
    std::fs::write(
        claude_dir.join("settings.json"),
        r#"{"permissions": {"deny": ["Bash(ls)"]}}"#,
    )
    .unwrap();
    // ls is normally safe, but CC deny rule should block it
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#;
    let (stdout, code) = common::run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn cc_ask_rule_prompts() {
    let dir = tempfile::tempdir().unwrap();
    let claude_dir = dir.path().join(".claude");
    std::fs::create_dir(&claude_dir).unwrap();
    std::fs::write(
        claude_dir.join("settings.json"),
        r#"{"permissions": {"ask": ["Bash(git status)"]}}"#,
    )
    .unwrap();
    // git status is normally safe, but CC ask rule should prompt
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#;
    let (_stdout, code) = common::run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 2);
}

// ---- Cargo handler tests ----

#[test]
fn cargo_test_allows() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"cargo test --all"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn cargo_build_allows() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"cargo build --release"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn cargo_nextest_allows() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"cargo nextest run"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn cargo_audit_allows() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"cargo audit"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn cargo_bench_allows() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"cargo bench"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn cargo_deny_allows() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"cargo deny check"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn cargo_rm_asks() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".claude")).unwrap();
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"cargo rm serde"}}"#;
    let (_stdout, code) = common::run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 2);
}

#[test]
fn cargo_run_asks() {
    // Use isolated dir to avoid CC permission rules from ~/.claude/
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".claude")).unwrap();
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"cargo run"}}"#;
    let (_stdout, code) = common::run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 2);
}

#[test]
fn cargo_publish_asks() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".claude")).unwrap();
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"cargo publish"}}"#;
    let (_stdout, code) = common::run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 2);
}

#[test]
fn cargo_fix_asks() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".claude")).unwrap();
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"cargo fix"}}"#;
    let (_stdout, code) = common::run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 2);
}

#[test]
fn cargo_add_asks() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".claude")).unwrap();
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"cargo add serde"}}"#;
    let (_stdout, code) = common::run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 2);
}

// ---- PostToolUse ----

#[test]
fn post_tool_use_returns_allow() {
    let json =
        r#"{"tool_name":"Bash","tool_input":{"command":"ls"},"tool_result":{"output":"file.txt"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

// ---- Codex mode ----

#[test]
fn codex_mode_safe_command() {
    let json = r#"{"tool_name":"bash","tool_input":"ls -la"}"#;
    let (stdout, code) = run_rippy(json, "codex", &[]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["decision"], "allow");
}

#[test]
fn codex_mode_dangerous_command() {
    let json = r#"{"tool_name":"bash","tool_input":"rm -rf /"}"#;
    let (stdout, code) = run_rippy(json, "codex", &[]);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["decision"], "deny");
}

// ---- Dippy backward compat ----

#[test]
fn dippy_config_file_loaded() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join(".dippy");
    std::fs::write(&config_path, "deny rm -rf \"blocked by dippy config\"").unwrap();
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &["--config", config_path.to_str().unwrap()]);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
}

// ---- Empty command ----

#[test]
fn empty_command_in_payload() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":""}}"#;
    let (_stdout, code) = run_rippy(json, "claude", &[]);
    assert_eq!(code, 0);
}

// ---- Recommended config tests (#16) ----

fn recommended_config_path() -> String {
    format!("{}/examples/recommended.rippy", env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn recommended_config_allows_defaults_read() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"defaults read com.apple.finder"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &["--config", &recommended_config_path()]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn recommended_config_asks_defaults_write() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"defaults write com.apple.finder key val"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &["--config", &recommended_config_path()]);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
}

#[test]
fn recommended_config_asks_kill() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"kill -9 1234"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &["--config", &recommended_config_path()]);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
}

#[test]
fn recommended_config_asks_dd() {
    let json =
        r#"{"tool_name":"Bash","tool_input":{"command":"dd if=/dev/zero of=/dev/sda bs=1M"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &["--config", &recommended_config_path()]);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
}

#[test]
fn recommended_config_allows_xattr_bare() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"xattr"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &["--config", &recommended_config_path()]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn recommended_config_asks_xattr_write() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"xattr -w attr val file.txt"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &["--config", &recommended_config_path()]);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
}

#[test]
fn recommended_config_allows_ansible_doc() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"ansible-doc copy"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &["--config", &recommended_config_path()]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn recommended_config_allows_diskutil_list() {
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"diskutil list"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &["--config", &recommended_config_path()]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn recommended_config_exact_match_dmesg_allows_bare() {
    // dmesg| uses exact match — bare `dmesg` is allowed
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"dmesg"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &["--config", &recommended_config_path()]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn recommended_config_exact_match_dmesg_asks_clear() {
    // dmesg -c needs approval even though bare dmesg is allowed
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"dmesg -c"}}"#;
    let (stdout, code) = run_rippy(json, "claude", &["--config", &recommended_config_path()]);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
}

// ---- TOML config integration tests ----

#[test]
fn toml_config_allows_command() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        dir.path().join(".rippy.toml"),
        "[[rules]]\naction = \"allow\"\npattern = \"echo hello\"\n",
    )
    .unwrap();

    let json = r#"{"tool_name":"Bash","tool_input":{"command":"echo hello"}}"#;
    let (stdout, code) = run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn toml_config_denies_with_message() {
    let dir = tempfile::TempDir::new().unwrap();
    std::fs::write(
        dir.path().join(".rippy.toml"),
        r#"
[[rules]]
action = "deny"
pattern = "rm -rf *"
message = "Use trash-cli instead of rm -rf"
"#,
    )
    .unwrap();

    let json = r#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp"}}"#;
    let (stdout, code) = run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(
        v["hookSpecificOutput"]["permissionDecisionReason"],
        "Use trash-cli instead of rm -rf"
    );
}

#[test]
fn toml_config_takes_precedence_over_legacy() {
    let dir = tempfile::TempDir::new().unwrap();
    // Legacy config denies git status.
    std::fs::write(dir.path().join(".rippy"), "deny git status\n").unwrap();
    // TOML config allows it — should win.
    std::fs::write(
        dir.path().join(".rippy.toml"),
        "[[rules]]\naction = \"allow\"\npattern = \"git status\"\n",
    )
    .unwrap();

    let json = r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#;
    let (stdout, code) = run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn toml_config_via_config_flag() {
    let dir = tempfile::TempDir::new().unwrap();
    let config_path = dir.path().join("custom.toml");
    std::fs::write(
        &config_path,
        "[[rules]]\naction = \"deny\"\npattern = \"echo *\"\nmessage = \"no echo\"\n",
    )
    .unwrap();

    let json = r#"{"tool_name":"Bash","tool_input":{"command":"echo test"}}"#;
    let config_str = config_path.to_str().unwrap();
    let (stdout, code) = run_rippy(json, "claude", &["--config", config_str]);
    assert_eq!(code, 2);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(
        v["hookSpecificOutput"]["permissionDecisionReason"],
        "no echo"
    );
}

#[test]
fn migrate_stdout_produces_valid_toml() {
    let dir = tempfile::TempDir::new().unwrap();
    let config = dir.path().join(".rippy");
    std::fs::write(&config, "allow git status\ndeny rm -rf \"use trash\"\n").unwrap();

    let output = std::process::Command::new(common::rippy_binary())
        .args(["migrate", "--stdout"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "migrate failed: {:?}",
        output.status
    );

    let toml_str = String::from_utf8(output.stdout).unwrap();
    assert!(toml_str.contains("action = \"allow\""));
    assert!(toml_str.contains("pattern = \"git status\""));
    assert!(toml_str.contains("action = \"deny\""));
    assert!(toml_str.contains("message = \"use trash\""));
}

// ---- Inspect integration tests ----

#[test]
fn inspect_list_with_config() {
    let dir = tempfile::TempDir::new().unwrap();
    let config = dir.path().join("test.toml");
    std::fs::write(
        &config,
        "[[rules]]\naction = \"deny\"\npattern = \"rm -rf *\"\nmessage = \"use trash\"\n",
    )
    .unwrap();

    let output = std::process::Command::new(common::rippy_binary())
        .args(["inspect", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("deny"));
    assert!(stdout.contains("rm -rf *"));
    assert!(stdout.contains("Handlers:"));
    assert!(stdout.contains("Simple safe:"));
}

#[test]
fn inspect_trace_safe_command() {
    let output = std::process::Command::new(common::rippy_binary())
        .args(["inspect", "cat /tmp/file"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("ALLOW"));
    assert!(stdout.contains("Allowlist"));
}

#[test]
fn inspect_trace_with_config_rule() {
    let dir = tempfile::TempDir::new().unwrap();
    let config = dir.path().join("test.toml");
    std::fs::write(
        &config,
        "[[rules]]\naction = \"deny\"\npattern = \"echo evil\"\nmessage = \"no evil allowed\"\n",
    )
    .unwrap();

    let output = std::process::Command::new(common::rippy_binary())
        .args(["inspect", "--config"])
        .arg(&config)
        .arg("echo evil")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("DENY"));
    assert!(stdout.contains("no evil allowed"));
}

#[test]
fn inspect_json_output() {
    let output = std::process::Command::new(common::rippy_binary())
        .args(["inspect", "--json", "cat /tmp/file"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(parsed["decision"], "allow");
    assert!(parsed["steps"].is_array());
}

#[test]
fn inspect_list_json_output() {
    let dir = tempfile::TempDir::new().unwrap();
    let config = dir.path().join("test.toml");
    std::fs::write(&config, "[[rules]]\naction = \"allow\"\npattern = \"ls\"\n").unwrap();

    let output = std::process::Command::new(common::rippy_binary())
        .args(["inspect", "--json", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(parsed["config_sources"].is_array());
    assert!(parsed["handler_count"].is_number());
    assert!(parsed["simple_safe_count"].is_number());
}
