//! Read and evaluate Claude Code's permission rules from settings files.
//!
//! Claude Code stores user-granted permissions in `settings.json` and
//! `settings.local.json` files. This module reads `permissions.allow`,
//! `permissions.deny`, and `permissions.ask` arrays, extracts `Bash(...)`
//! patterns, and checks commands against them with word-boundary matching.

use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::verdict::Decision;

/// Loaded Claude Code permission rules.
pub struct CcRules {
    allow: Vec<String>,
    deny: Vec<String>,
    ask: Vec<String>,
}

impl CcRules {
    /// Check a command against CC permission rules.
    ///
    /// Returns `Some(Decision)` if a rule matches, `None` if no rule matches
    /// (fall through to rippy's own analysis).
    ///
    /// Priority: deny > ask > allow.
    #[must_use]
    pub fn check(&self, command: &str) -> Option<Decision> {
        for pattern in &self.deny {
            if command_matches_pattern(command, pattern) {
                return Some(Decision::Deny);
            }
        }

        for pattern in &self.ask {
            if command_matches_pattern(command, pattern) {
                return Some(Decision::Ask);
            }
        }

        for pattern in &self.allow {
            if command_matches_pattern(command, pattern) {
                return Some(Decision::Allow);
            }
        }

        None
    }

    /// Returns true if no rules were loaded.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty() && self.ask.is_empty()
    }

    /// Return all rules as (decision, pattern) pairs for inspection.
    #[must_use]
    pub fn all_rules(&self) -> Vec<(Decision, &str)> {
        let mut rules = Vec::new();
        for p in &self.allow {
            rules.push((Decision::Allow, p.as_str()));
        }
        for p in &self.deny {
            rules.push((Decision::Deny, p.as_str()));
        }
        for p in &self.ask {
            rules.push((Decision::Ask, p.as_str()));
        }
        rules
    }
}

/// Load CC permission rules from all settings file paths.
///
/// Walks up from `working_dir` to find the nearest `.claude/` directory,
/// then reads (in order):
/// 1. `{project}/.claude/settings.json`
/// 2. `{project}/.claude/settings.local.json`
/// 3. `~/.claude/settings.json`
/// 4. `~/.claude/settings.local.json`
#[must_use]
pub fn load_cc_rules(working_dir: &Path) -> CcRules {
    load_cc_rules_with_home(working_dir, env_home_dir())
}

/// Load CC rules with an explicit home directory instead of reading `$HOME`.
///
/// Pass `None` to skip `~/.claude/` settings (useful for tests).
#[must_use]
pub fn load_cc_rules_with_home(working_dir: &Path, home: Option<PathBuf>) -> CcRules {
    load_rules_from_paths(&get_settings_paths_with_home(working_dir, home))
}

pub(crate) fn get_settings_paths(working_dir: &Path) -> Vec<PathBuf> {
    get_settings_paths_with_home(working_dir, env_home_dir())
}

pub(crate) fn get_settings_paths_with_home(
    working_dir: &Path,
    home: Option<PathBuf>,
) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // Walk up from working_dir to find .claude/ directory
    let mut dir = working_dir.to_path_buf();
    loop {
        if dir.join(".claude").is_dir() {
            paths.push(dir.join(".claude").join("settings.json"));
            paths.push(dir.join(".claude").join("settings.local.json"));
            break;
        }
        if !dir.pop() {
            break;
        }
    }

    if let Some(home) = home {
        paths.push(home.join(".claude").join("settings.json"));
        paths.push(home.join(".claude").join("settings.local.json"));
    }

    paths
}

fn env_home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

fn load_rules_from_paths(paths: &[PathBuf]) -> CcRules {
    let mut allow = Vec::new();
    let mut deny = Vec::new();
    let mut ask = Vec::new();

    for path in paths {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                eprintln!(
                    "[rippy] warning: could not read {}: {e} — failing closed",
                    path.display()
                );
                ask.push("*".to_string());
                continue;
            }
        };
        let json = match serde_json::from_str::<Value>(&content) {
            Ok(v) => v,
            Err(e) => {
                eprintln!(
                    "[rippy] warning: could not parse {}: {e} — failing closed",
                    path.display()
                );
                ask.push("*".to_string());
                continue;
            }
        };
        let Some(permissions) = json.get("permissions") else {
            continue;
        };

        append_bash_rules(permissions.get("allow"), &mut allow);
        append_bash_rules(permissions.get("deny"), &mut deny);
        append_bash_rules(permissions.get("ask"), &mut ask);
    }

    CcRules { allow, deny, ask }
}

fn append_bash_rules(rules_value: Option<&Value>, target: &mut Vec<String>) {
    let Some(arr) = rules_value.and_then(Value::as_array) else {
        return;
    };
    for rule in arr {
        if let Some(s) = rule.as_str()
            && let Some(pattern) = extract_bash_pattern(s)
        {
            target.push(pattern.to_string());
        }
    }
}

/// Extract the inner pattern from `Bash(pattern)`. Returns `None` for non-Bash rules.
fn extract_bash_pattern(rule: &str) -> Option<&str> {
    rule.strip_prefix("Bash(")
        .and_then(|inner| inner.strip_suffix(')'))
}

/// Check if `cmd` matches a CC permission pattern.
///
/// Supports `*` as a wildcard with word-boundary semantics.
fn command_matches_pattern(cmd: &str, pattern: &str) -> bool {
    if !pattern.contains('*') {
        return starts_with_word(cmd, pattern);
    }

    let ends_with_star = pattern.ends_with('*');
    let mut split = pattern.split('*').peekable();
    let mut pos = 0;
    let mut is_first = true;

    while let Some(segment) = split.next() {
        let is_last = split.peek().is_none();
        let seg = if is_first {
            segment.trim_end_matches(':').trim_end()
        } else {
            segment.trim()
        };

        if seg.is_empty() {
            is_first = false;
            continue;
        }

        if is_first {
            if !starts_with_word(cmd, seg) {
                return false;
            }
            pos = seg.len();
        } else if is_last && !ends_with_star {
            return ends_with_word(cmd, seg);
        } else {
            match find_word(cmd, pos, seg) {
                Some(end) => pos = end,
                None => return false,
            }
        }

        is_first = false;
    }

    true
}

/// Check if `cmd` equals `word` or starts with `word` followed by a space.
fn starts_with_word(cmd: &str, word: &str) -> bool {
    cmd == word
        || (cmd.len() > word.len() && cmd.as_bytes()[word.len()] == b' ' && cmd.starts_with(word))
}

/// Check if `cmd` ends with `word` preceded by a space (or equals `word`).
fn ends_with_word(cmd: &str, word: &str) -> bool {
    cmd == word
        || (cmd.len() > word.len()
            && cmd.as_bytes()[cmd.len() - word.len() - 1] == b' '
            && cmd.ends_with(word))
}

/// Find `needle` in `cmd[from..]` at a word boundary.
fn find_word(cmd: &str, from: usize, needle: &str) -> Option<usize> {
    let haystack = &cmd[from..];
    let mut search_from = 0;
    while let Some(idx) = haystack[search_from..].find(needle) {
        let abs_start = from + search_from + idx;
        let abs_end = abs_start + needle.len();
        let left_ok = abs_start == 0 || cmd.as_bytes()[abs_start - 1] == b' ';
        let right_ok = abs_end == cmd.len() || cmd.as_bytes()[abs_end] == b' ';
        if left_ok && right_ok {
            return Some(abs_end);
        }
        search_from += idx + 1;
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // ---- Pattern matching ----

    #[test]
    fn exact_match() {
        assert!(command_matches_pattern(
            "git push --force",
            "git push --force"
        ));
    }

    #[test]
    fn prefix_match_with_args() {
        assert!(command_matches_pattern(
            "git push --force origin",
            "git push --force"
        ));
    }

    #[test]
    fn no_partial_word_match() {
        assert!(!command_matches_pattern(
            "git push --forceful",
            "git push --force"
        ));
    }

    #[test]
    fn wildcard_all() {
        assert!(command_matches_pattern("anything", "*"));
        assert!(command_matches_pattern("", "*"));
    }

    #[test]
    fn wildcard_trailing() {
        assert!(command_matches_pattern(
            "git push origin main",
            "git push *"
        ));
    }

    #[test]
    fn wildcard_leading() {
        assert!(command_matches_pattern("git push --force", "* --force"));
    }

    #[test]
    fn wildcard_leading_no_partial() {
        assert!(!command_matches_pattern("git push --forceful", "* --force"));
    }

    #[test]
    fn wildcard_middle() {
        assert!(command_matches_pattern("git push main", "git * main"));
    }

    #[test]
    fn wildcard_middle_no_partial() {
        assert!(!command_matches_pattern("git push xmain", "git * main"));
    }

    #[test]
    fn wildcard_colon_prefix() {
        assert!(command_matches_pattern("sudo rm -rf /", "sudo:*"));
    }

    #[test]
    fn wildcard_colon_no_false_positive() {
        assert!(!command_matches_pattern("sudoedit /etc/hosts", "sudo:*"));
    }

    #[test]
    fn no_match() {
        assert!(!command_matches_pattern("git status", "git push --force"));
    }

    // ---- extract_bash_pattern ----

    #[test]
    fn extract_bash_valid() {
        assert_eq!(extract_bash_pattern("Bash(git push)"), Some("git push"));
        assert_eq!(extract_bash_pattern("Bash(*)"), Some("*"));
    }

    #[test]
    fn extract_non_bash_ignored() {
        assert_eq!(extract_bash_pattern("Read(**/.env*)"), None);
        assert_eq!(extract_bash_pattern("Write(*)"), None);
    }

    // ---- CcRules::check ----

    #[test]
    fn check_deny_trumps_all() {
        let rules = CcRules {
            allow: vec!["git push".into()],
            deny: vec!["git push --force".into()],
            ask: vec![],
        };
        assert_eq!(rules.check("git push --force"), Some(Decision::Deny));
    }

    #[test]
    fn check_ask_trumps_allow() {
        let rules = CcRules {
            allow: vec!["git push".into()],
            deny: vec![],
            ask: vec!["git push".into()],
        };
        assert_eq!(rules.check("git push origin"), Some(Decision::Ask));
    }

    #[test]
    fn check_allow_matches() {
        let rules = CcRules {
            allow: vec!["git push".into()],
            deny: vec![],
            ask: vec![],
        };
        assert_eq!(rules.check("git push origin"), Some(Decision::Allow));
    }

    #[test]
    fn check_no_match_returns_none() {
        let rules = CcRules {
            allow: vec!["git push".into()],
            deny: vec![],
            ask: vec![],
        };
        assert_eq!(rules.check("git status"), None);
    }

    // ---- Settings file loading ----

    #[test]
    fn load_from_settings_file() {
        let dir = tempfile::tempdir().unwrap();
        let claude_dir = dir.path().join(".claude");
        std::fs::create_dir(&claude_dir).unwrap();
        std::fs::write(
            claude_dir.join("settings.json"),
            r#"{
                "permissions": {
                    "allow": ["Bash(git status)", "Bash(cargo test *)"],
                    "deny": ["Bash(rm -rf /)"],
                    "ask": ["Bash(git push)"]
                }
            }"#,
        )
        .unwrap();

        let rules = load_rules_from_paths(&[claude_dir.join("settings.json")]);
        assert_eq!(rules.check("git status"), Some(Decision::Allow));
        assert_eq!(rules.check("cargo test --all"), Some(Decision::Allow));
        assert_eq!(rules.check("rm -rf /"), Some(Decision::Deny));
        assert_eq!(rules.check("git push origin"), Some(Decision::Ask));
        assert_eq!(rules.check("ls -la"), None);
    }

    #[test]
    fn missing_settings_no_rules() {
        let dir = tempfile::tempdir().unwrap();
        // Use explicit paths to avoid picking up real ~/.claude/settings.json
        let rules = load_rules_from_paths(&[dir.path().join("nonexistent.json")]);
        assert!(rules.is_empty());
        assert_eq!(rules.check("anything"), None);
    }

    #[test]
    fn malformed_json_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let claude_dir = dir.path().join(".claude");
        std::fs::create_dir(&claude_dir).unwrap();
        std::fs::write(claude_dir.join("settings.json"), "not valid json {{{").unwrap();

        let rules = load_rules_from_paths(&[claude_dir.join("settings.json")]);
        // Wildcard ask rule injected → everything matches as Ask
        assert_eq!(rules.check("git status"), Some(Decision::Ask));
    }

    #[test]
    fn non_bash_rules_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let claude_dir = dir.path().join(".claude");
        std::fs::create_dir(&claude_dir).unwrap();
        std::fs::write(
            claude_dir.join("settings.json"),
            r#"{
                "permissions": {
                    "deny": ["Read(**/.env*)", "Write(*)"]
                }
            }"#,
        )
        .unwrap();

        let rules = load_rules_from_paths(&[claude_dir.join("settings.json")]);
        assert!(rules.is_empty());
    }

    #[test]
    fn local_settings_merged() {
        let dir = tempfile::tempdir().unwrap();
        let claude_dir = dir.path().join(".claude");
        std::fs::create_dir(&claude_dir).unwrap();
        std::fs::write(
            claude_dir.join("settings.json"),
            r#"{"permissions": {"deny": ["Bash(rm -rf /)"]}}"#,
        )
        .unwrap();
        std::fs::write(
            claude_dir.join("settings.local.json"),
            r#"{"permissions": {"allow": ["Bash(git push)"]}}"#,
        )
        .unwrap();

        let rules = load_rules_from_paths(&[
            claude_dir.join("settings.json"),
            claude_dir.join("settings.local.json"),
        ]);
        assert_eq!(rules.check("rm -rf /"), Some(Decision::Deny));
        assert_eq!(rules.check("git push origin"), Some(Decision::Allow));
    }
}
