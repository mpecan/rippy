#![allow(clippy::unwrap_used)]

mod common;
use common::run_rippy;

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
