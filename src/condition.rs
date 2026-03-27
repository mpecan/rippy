//! Conditional rule evaluation — `when` clauses for context-aware rules.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use toml::Value;

/// Runtime context for evaluating rule conditions.
pub struct MatchContext<'a> {
    /// Current git branch (cached), or `None` if not in a git repo.
    pub branch: Option<&'a str>,
    /// Working directory for cwd-relative checks.
    pub cwd: &'a Path,
}

/// A single condition that must be true for a rule to apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    /// Branch name equals value.
    BranchEq(String),
    /// Branch name does not equal value.
    BranchNot(String),
    /// Branch name matches glob pattern.
    BranchMatch(String),
    /// Working directory is under the given path.
    CwdUnder(String),
    /// File exists at the given path.
    FileExists(String),
    /// Environment variable equals value.
    EnvEq { name: String, value: String },
    /// External command exits with code 0.
    Exec(String),
}

/// Evaluate all conditions (AND). Returns true if all pass or list is empty.
pub fn evaluate_all(conditions: &[Condition], ctx: &MatchContext) -> bool {
    conditions.iter().all(|c| evaluate_one(c, ctx))
}

fn evaluate_one(cond: &Condition, ctx: &MatchContext) -> bool {
    match cond {
        Condition::BranchEq(expected) => ctx.branch == Some(expected.as_str()),
        Condition::BranchNot(excluded) => ctx.branch != Some(excluded.as_str()),
        Condition::BranchMatch(pattern) => ctx
            .branch
            .is_some_and(|b| crate::pattern::Pattern::new(pattern).matches(b)),
        Condition::CwdUnder(base) => {
            let base_path = if base == "." {
                ctx.cwd.to_path_buf()
            } else {
                ctx.cwd.join(base)
            };
            ctx.cwd.starts_with(&base_path)
        }
        Condition::FileExists(path) => Path::new(path).exists(),
        Condition::EnvEq { name, value } => {
            std::env::var(name).ok().as_deref() == Some(value.as_str())
        }
        Condition::Exec(cmd) => evaluate_exec(cmd),
    }
}

/// Run an external command with a 1-second timeout.
fn evaluate_exec(cmd: &str) -> bool {
    let child = Command::new("sh")
        .args(["-c", cmd])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();

    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[rippy] condition exec failed: {e}");
            return false;
        }
    };

    // Poll with timeout.
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    eprintln!("[rippy] condition exec timed out: {cmd}");
                    return false;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                eprintln!("[rippy] condition exec failed: {e}");
                return false;
            }
        }
    }
}

/// Parse a TOML `when` value into a list of conditions.
///
/// # Errors
///
/// Returns an error string if the TOML structure is unrecognized.
pub fn parse_conditions(value: &Value) -> Result<Vec<Condition>, String> {
    let table = value.as_table().ok_or("'when' must be a TOML table")?;

    let mut conditions = Vec::new();

    for (key, val) in table {
        match key.as_str() {
            "branch" => conditions.push(parse_branch_condition(val)?),
            "cwd" => conditions.push(parse_cwd_condition(val)?),
            "file-exists" => {
                let path = val.as_str().ok_or("'file-exists' must be a string")?;
                conditions.push(Condition::FileExists(path.to_string()));
            }
            "env" => conditions.push(parse_env_condition(val)?),
            "exec" => {
                let cmd = val.as_str().ok_or("'exec' must be a string")?;
                conditions.push(Condition::Exec(cmd.to_string()));
            }
            other => return Err(format!("unknown condition type: {other}")),
        }
    }

    Ok(conditions)
}

fn parse_branch_condition(val: &Value) -> Result<Condition, String> {
    let table = val.as_table().ok_or("'branch' must be a table")?;

    if let Some(v) = table.get("eq") {
        return Ok(Condition::BranchEq(
            v.as_str().ok_or("branch.eq must be a string")?.to_string(),
        ));
    }
    if let Some(v) = table.get("not") {
        return Ok(Condition::BranchNot(
            v.as_str().ok_or("branch.not must be a string")?.to_string(),
        ));
    }
    if let Some(v) = table.get("match") {
        return Ok(Condition::BranchMatch(
            v.as_str()
                .ok_or("branch.match must be a string")?
                .to_string(),
        ));
    }

    Err("branch condition must have 'eq', 'not', or 'match' key".into())
}

fn parse_cwd_condition(val: &Value) -> Result<Condition, String> {
    let table = val.as_table().ok_or("'cwd' must be a table")?;
    if let Some(v) = table.get("under") {
        return Ok(Condition::CwdUnder(
            v.as_str().ok_or("cwd.under must be a string")?.to_string(),
        ));
    }
    Err("cwd condition must have 'under' key".into())
}

fn parse_env_condition(val: &Value) -> Result<Condition, String> {
    let table = val.as_table().ok_or("'env' must be a table")?;
    let name = table
        .get("name")
        .and_then(Value::as_str)
        .ok_or("env.name must be a string")?;
    let value = table
        .get("eq")
        .and_then(Value::as_str)
        .ok_or("env.eq must be a string")?;
    Ok(Condition::EnvEq {
        name: name.to_string(),
        value: value.to_string(),
    })
}

/// Detect the current git branch from a working directory.
///
/// Returns `None` if not in a git repository or git is not available.
#[must_use]
pub fn detect_git_branch(cwd: &Path) -> Option<String> {
    let output = Command::new("git")
        .args(["symbolic-ref", "--short", "HEAD"])
        .current_dir(cwd)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    String::from_utf8(output.stdout)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn ctx_with_branch<'a>(branch: Option<&'a str>, cwd: &'a Path) -> MatchContext<'a> {
        MatchContext { branch, cwd }
    }

    #[test]
    fn branch_eq_matches() {
        let ctx = ctx_with_branch(Some("main"), Path::new("/tmp"));
        assert!(evaluate_one(&Condition::BranchEq("main".into()), &ctx));
        assert!(!evaluate_one(&Condition::BranchEq("develop".into()), &ctx));
    }

    #[test]
    fn branch_not_matches() {
        let ctx = ctx_with_branch(Some("feature/foo"), Path::new("/tmp"));
        assert!(evaluate_one(&Condition::BranchNot("main".into()), &ctx));
        assert!(!evaluate_one(
            &Condition::BranchNot("feature/foo".into()),
            &ctx
        ));
    }

    #[test]
    fn branch_match_glob() {
        let ctx = ctx_with_branch(Some("feat/my-feature"), Path::new("/tmp"));
        assert!(evaluate_one(&Condition::BranchMatch("feat/*".into()), &ctx));
        assert!(!evaluate_one(&Condition::BranchMatch("fix/*".into()), &ctx));
    }

    #[test]
    fn branch_none_fails_all() {
        let ctx = ctx_with_branch(None, Path::new("/tmp"));
        assert!(!evaluate_one(&Condition::BranchEq("main".into()), &ctx));
        assert!(evaluate_one(&Condition::BranchNot("main".into()), &ctx));
    }

    #[test]
    fn cwd_under_self() {
        let cwd = std::env::current_dir().unwrap();
        let ctx = ctx_with_branch(None, &cwd);
        assert!(evaluate_one(&Condition::CwdUnder(".".into()), &ctx));
    }

    #[test]
    fn file_exists_condition() {
        assert!(evaluate_one(
            &Condition::FileExists("Cargo.toml".into()),
            &MatchContext {
                branch: None,
                cwd: Path::new(".")
            }
        ));
        assert!(!evaluate_one(
            &Condition::FileExists("nonexistent_file_xyz".into()),
            &MatchContext {
                branch: None,
                cwd: Path::new(".")
            }
        ));
    }

    #[test]
    fn env_eq_condition() {
        // SAFETY: test runs single-threaded via cargo test.
        unsafe { std::env::set_var("RIPPY_TEST_VAR", "hello") };
        let ctx = MatchContext {
            branch: None,
            cwd: Path::new("."),
        };
        assert!(evaluate_one(
            &Condition::EnvEq {
                name: "RIPPY_TEST_VAR".into(),
                value: "hello".into()
            },
            &ctx
        ));
        assert!(!evaluate_one(
            &Condition::EnvEq {
                name: "RIPPY_TEST_VAR".into(),
                value: "world".into()
            },
            &ctx
        ));
        unsafe { std::env::remove_var("RIPPY_TEST_VAR") };
    }

    #[test]
    fn evaluate_all_empty_is_true() {
        let ctx = ctx_with_branch(None, Path::new("/tmp"));
        assert!(evaluate_all(&[], &ctx));
    }

    #[test]
    fn evaluate_all_and_logic() {
        let ctx = ctx_with_branch(Some("main"), Path::new("/tmp"));
        let conditions = vec![
            Condition::BranchEq("main".into()),
            Condition::BranchNot("develop".into()),
        ];
        assert!(evaluate_all(&conditions, &ctx));

        let conditions_fail = vec![
            Condition::BranchEq("main".into()),
            Condition::BranchEq("develop".into()), // fails
        ];
        assert!(!evaluate_all(&conditions_fail, &ctx));
    }

    #[test]
    fn parse_branch_eq() {
        let toml: Value = toml::from_str(r#"branch = { eq = "main" }"#).unwrap();
        let conds = parse_conditions(&toml).unwrap();
        assert_eq!(conds, vec![Condition::BranchEq("main".into())]);
    }

    #[test]
    fn parse_branch_not() {
        let toml: Value = toml::from_str(r#"branch = { not = "main" }"#).unwrap();
        let conds = parse_conditions(&toml).unwrap();
        assert_eq!(conds, vec![Condition::BranchNot("main".into())]);
    }

    #[test]
    fn parse_branch_match() {
        let toml: Value = toml::from_str(r#"branch = { match = "feat/*" }"#).unwrap();
        let conds = parse_conditions(&toml).unwrap();
        assert_eq!(conds, vec![Condition::BranchMatch("feat/*".into())]);
    }

    #[test]
    fn parse_cwd_under() {
        let toml: Value = toml::from_str(r#"cwd = { under = "." }"#).unwrap();
        let conds = parse_conditions(&toml).unwrap();
        assert_eq!(conds, vec![Condition::CwdUnder(".".into())]);
    }

    #[test]
    fn parse_file_exists() {
        let toml: Value = toml::from_str(r#"file-exists = "Cargo.toml""#).unwrap();
        let conds = parse_conditions(&toml).unwrap();
        assert_eq!(conds, vec![Condition::FileExists("Cargo.toml".into())]);
    }

    #[test]
    fn parse_env_eq() {
        let toml: Value = toml::from_str(r#"env = { name = "HOME", eq = "/home/user" }"#).unwrap();
        let conds = parse_conditions(&toml).unwrap();
        assert_eq!(
            conds,
            vec![Condition::EnvEq {
                name: "HOME".into(),
                value: "/home/user".into()
            }]
        );
    }

    #[test]
    fn parse_exec() {
        let toml: Value = toml::from_str(r#"exec = "true""#).unwrap();
        let conds = parse_conditions(&toml).unwrap();
        assert_eq!(conds, vec![Condition::Exec("true".into())]);
    }

    #[test]
    fn parse_unknown_condition_errors() {
        let toml: Value = toml::from_str(r#"unknown = "value""#).unwrap();
        assert!(parse_conditions(&toml).is_err());
    }

    #[test]
    fn exec_true_succeeds() {
        assert!(evaluate_exec("true"));
    }

    #[test]
    fn exec_false_fails() {
        assert!(!evaluate_exec("false"));
    }

    #[test]
    fn detect_git_branch_in_fresh_repo() {
        let dir = tempfile::TempDir::new().unwrap();
        // Initialize a git repo with a branch.
        std::process::Command::new("git")
            .args(["init", "-b", "test-branch"])
            .current_dir(dir.path())
            .output()
            .unwrap();
        // Need at least one commit for symbolic-ref to work.
        std::process::Command::new("git")
            .args(["commit", "--allow-empty", "-m", "init"])
            .current_dir(dir.path())
            .output()
            .unwrap();

        let branch = detect_git_branch(dir.path());
        assert_eq!(branch.as_deref(), Some("test-branch"));
    }

    #[test]
    fn detect_git_branch_not_a_repo() {
        let dir = tempfile::TempDir::new().unwrap();
        let branch = detect_git_branch(dir.path());
        assert!(branch.is_none());
    }
}
