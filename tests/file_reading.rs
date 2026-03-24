#![allow(clippy::unwrap_used)]

mod common;
use common::run_rippy_in_dir;

// ---- Python script file reading ----

#[test]
fn python_script_safe_file_allows() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("safe.py"),
        "import json\nprint(json.dumps({}))",
    )
    .unwrap();
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"python safe.py"}}"#;
    let (stdout, code) = run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn python_script_dangerous_file_asks() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("evil.py"), "import os\nos.system('ls')").unwrap();
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"python evil.py"}}"#;
    let (_stdout, code) = run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 2);
}

// ---- SQL file reading ----

#[test]
fn psql_f_readonly_file_allows() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("query.sql"), "SELECT * FROM users;").unwrap();
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"psql -f query.sql"}}"#;
    let (stdout, code) = run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn psql_f_write_file_asks() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("migrate.sql"), "DROP TABLE users;").unwrap();
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"psql -f migrate.sql"}}"#;
    let (_stdout, code) = run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 2);
}

// ---- Shell script file reading ----

#[test]
fn bash_script_safe_file_allows() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("test.sh"), "ls -la").unwrap();
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"bash test.sh"}}"#;
    let (stdout, code) = run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn bash_script_dangerous_file_asks() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("danger.sh"), "rm -rf /").unwrap();
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"bash danger.sh"}}"#;
    let (_stdout, code) = run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 2);
}

// ---- GH API --input file reading ----

#[test]
fn gh_api_input_query_file_allows() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("query.graphql"),
        "{ repository(owner: \"o\", name: \"r\") { name } }",
    )
    .unwrap();
    let json =
        r#"{"tool_name":"Bash","tool_input":{"command":"gh api graphql --input query.graphql"}}"#;
    let (stdout, code) = run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn gh_api_input_mutation_file_asks() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("mutate.graphql"),
        "mutation { addStar(input: {}) { clientMutationId } }",
    )
    .unwrap();
    let json =
        r#"{"tool_name":"Bash","tool_input":{"command":"gh api graphql --input mutate.graphql"}}"#;
    let (_stdout, code) = run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 2);
}

// ---- AWK -f file reading ----

#[test]
fn awk_f_safe_file_allows() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("safe.awk"), "{print $1}").unwrap();
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"awk -f safe.awk data.txt"}}"#;
    let (stdout, code) = run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "allow");
}

#[test]
fn awk_f_system_file_asks() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("evil.awk"), r#"{system("rm -rf /")}"#).unwrap();
    let json = r#"{"tool_name":"Bash","tool_input":{"command":"awk -f evil.awk"}}"#;
    let (_stdout, code) = run_rippy_in_dir(json, "claude", dir.path());
    assert_eq!(code, 2);
}
