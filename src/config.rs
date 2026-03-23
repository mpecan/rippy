use std::path::{Path, PathBuf};

use crate::error::RippyError;
use crate::pattern::Pattern;
use crate::verdict::{Decision, Verdict};

/// A single rule parsed from a config file.
#[derive(Debug, Clone)]
pub enum Rule {
    Command {
        kind: Decision,
        pattern: Pattern,
        message: Option<String>,
    },
    Redirect {
        kind: Decision,
        pattern: Pattern,
        message: Option<String>,
    },
    After {
        pattern: Pattern,
        message: String,
    },
    Mcp {
        kind: Decision,
        pattern: Pattern,
    },
    Set {
        key: String,
        value: String,
    },
    Alias {
        source: String,
        target: String,
    },
}

/// Loaded and merged configuration.
#[derive(Debug, Clone, Default)]
pub struct Config {
    pub rules: Vec<Rule>,
    pub default_action: Option<Decision>,
    pub log_file: Option<PathBuf>,
    pub log_full: bool,
    aliases: Vec<(String, String)>,
}

impl Config {
    /// Load config from the three-tier system: global, project, env override.
    /// Missing files are silently ignored.
    ///
    /// # Errors
    ///
    /// Returns `RippyError::Config` if a config file exists but contains invalid syntax.
    pub fn load(cwd: &Path, env_config: Option<&Path>) -> Result<Self, RippyError> {
        let mut rules = Vec::new();

        // Tier 1: global config
        if let Some(home) = home_dir() {
            load_first_existing(
                &[home.join(".rippy/config"), home.join(".dippy/config")],
                &mut rules,
            )?;
        }

        // Tier 2: project config (walk up from cwd)
        if let Some(project_config) = find_project_config(cwd) {
            load_file(&project_config, &mut rules)?;
        }

        // Tier 3: env override (highest priority)
        if let Some(env_path) = env_config {
            load_file(env_path, &mut rules)?;
        }

        Ok(Self::from_rules(rules))
    }

    /// Create an empty config (for testing or when no config files exist).
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Match a command string against command rules (last-match-wins).
    #[must_use]
    pub fn match_command(&self, command: &str) -> Option<Verdict> {
        Self::last_match(&self.rules, command, |r| match r {
            Rule::Command {
                kind,
                pattern,
                message,
            } => Some((kind, pattern, message.as_deref())),
            _ => None,
        })
    }

    /// Match a redirect target path against redirect rules.
    #[must_use]
    pub fn match_redirect(&self, path: &str) -> Option<Verdict> {
        Self::last_match(&self.rules, path, |r| match r {
            Rule::Redirect {
                kind,
                pattern,
                message,
            } => Some((kind, pattern, message.as_deref())),
            _ => None,
        })
    }

    /// Match an MCP tool name against MCP rules.
    #[must_use]
    pub fn match_mcp(&self, tool_name: &str) -> Option<Verdict> {
        let mut result = None;
        for rule in &self.rules {
            if let Rule::Mcp { kind, pattern } = rule
                && pattern.matches(tool_name)
            {
                result = Some(Verdict {
                    decision: *kind,
                    reason: format!("MCP rule: {}", pattern.as_str()),
                });
            }
        }
        result
    }

    /// Match a command for `after` rules (post-execution feedback).
    #[must_use]
    pub fn match_after(&self, command: &str) -> Option<String> {
        let mut result = None;
        for rule in &self.rules {
            if let Rule::After { pattern, message } = rule
                && pattern.matches(command)
            {
                result = Some(message.clone());
            }
        }
        result
    }

    /// Resolve aliases for a command name. Returns the target if aliased.
    #[must_use]
    pub fn resolve_alias<'a>(&'a self, command: &'a str) -> &'a str {
        for (source, target) in &self.aliases {
            if command == source
                || command
                    .strip_prefix(source.as_str())
                    .is_some_and(|rest| rest.starts_with('/'))
            {
                return target;
            }
        }
        command
    }

    /// Build a `Config` from a list of rules (for testing and programmatic use).
    pub fn from_rules(rules: Vec<Rule>) -> Self {
        let mut default_action = None;
        let mut log_file = None;
        let mut log_full = false;
        let mut aliases = Vec::new();

        for rule in &rules {
            match rule {
                Rule::Set { key, value } => match key.as_str() {
                    "default" => default_action = parse_action_word(value),
                    "log" => log_file = Some(PathBuf::from(value)),
                    "log-full" => log_full = true,
                    _ => {}
                },
                Rule::Alias { source, target } => {
                    aliases.push((source.clone(), target.clone()));
                }
                _ => {}
            }
        }

        Self {
            rules,
            default_action,
            log_file,
            log_full,
            aliases,
        }
    }

    fn last_match(
        rules: &[Rule],
        input: &str,
        extract: impl Fn(&Rule) -> Option<(&Decision, &Pattern, Option<&str>)>,
    ) -> Option<Verdict> {
        let mut result = None;
        for rule in rules {
            if let Some((kind, pattern, message)) = extract(rule)
                && pattern.matches(input)
            {
                result = Some(Verdict {
                    decision: *kind,
                    reason: message.map_or_else(
                        || format!("matched rule: {}", pattern.as_str()),
                        String::from,
                    ),
                });
            }
        }
        result
    }
}

/// Load the first file that exists from a list of candidates.
fn load_first_existing(paths: &[PathBuf], rules: &mut Vec<Rule>) -> Result<(), RippyError> {
    for path in paths {
        if path.is_file() {
            return load_file(path, rules);
        }
    }
    Ok(())
}

/// Parse a single config file and append rules to the list.
fn load_file(path: &Path, rules: &mut Vec<Rule>) -> Result<(), RippyError> {
    let content = std::fs::read_to_string(path).map_err(|e| RippyError::Config {
        path: path.to_owned(),
        line: 0,
        message: format!("could not read: {e}"),
    })?;

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let rule = parse_rule(line).map_err(|msg| RippyError::Config {
            path: path.to_owned(),
            line: line_num + 1,
            message: msg,
        })?;
        rules.push(rule);
    }

    Ok(())
}

/// A token from a config line, tagged as quoted or unquoted.
#[derive(Debug)]
enum Token {
    Bare(String),
    Quoted(String),
}

/// Tokenize a config line, respecting quoted strings.
/// Returns tagged tokens so callers can distinguish patterns from messages.
fn tokenize_config_line(line: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut chars = line.chars().peekable();

    while let Some(&ch) = chars.peek() {
        if ch.is_whitespace() {
            chars.next();
            continue;
        }
        if ch == '"' {
            chars.next();
            let mut s = String::new();
            loop {
                match chars.next() {
                    None | Some('"') => break,
                    Some('\\') => {
                        if let Some(escaped) = chars.next() {
                            s.push(escaped);
                        }
                    }
                    Some(c) => s.push(c),
                }
            }
            tokens.push(Token::Quoted(s));
        } else {
            let mut s = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() {
                    break;
                }
                s.push(c);
                chars.next();
            }
            tokens.push(Token::Bare(s));
        }
    }
    tokens
}

/// From a token list (after the keyword), extract the pattern (all bare tokens
/// joined by spaces) and the optional message (first quoted token).
fn extract_pattern_and_message(tokens: &[Token]) -> (String, Option<String>) {
    let mut bare_parts = Vec::new();
    let mut message = None;
    for token in tokens {
        match token {
            Token::Bare(s) => bare_parts.push(s.as_str()),
            Token::Quoted(s) => {
                if message.is_none() {
                    message = Some(s.clone());
                }
            }
        }
    }
    (bare_parts.join(" "), message)
}

/// Parse a single config line into a Rule.
fn parse_rule(line: &str) -> Result<Rule, String> {
    let tokens = tokenize_config_line(line);
    let keyword = match tokens.first() {
        Some(Token::Bare(k)) => k.as_str(),
        Some(Token::Quoted(_)) => return Err("directive cannot be quoted".into()),
        None => return Err("empty rule".into()),
    };
    let rest = &tokens[1..];

    match keyword {
        "allow" | "ask" | "deny" => parse_command_rule(keyword, rest),
        "allow-redirect" | "ask-redirect" | "deny-redirect" => parse_redirect_rule(keyword, rest),
        "after" => parse_after_rule(rest),
        "allow-mcp" | "ask-mcp" | "deny-mcp" => parse_mcp_rule(keyword, rest),
        "set" => parse_set_rule(rest),
        "alias" => parse_alias_rule(rest),
        _ => Err(format!("unknown directive: {keyword}")),
    }
}

fn parse_command_rule(keyword: &str, rest: &[Token]) -> Result<Rule, String> {
    let (pattern_str, message) = extract_pattern_and_message(rest);
    if pattern_str.is_empty() {
        return Err(format!("{keyword} requires a pattern"));
    }
    Ok(Rule::Command {
        kind: parse_rule_kind(keyword),
        pattern: Pattern::new(&pattern_str),
        message,
    })
}

fn parse_redirect_rule(keyword: &str, rest: &[Token]) -> Result<Rule, String> {
    let (pattern_str, message) = extract_pattern_and_message(rest);
    if pattern_str.is_empty() {
        return Err(format!("{keyword} requires a path pattern"));
    }
    let base_kind = keyword.split('-').next().unwrap_or("ask");
    Ok(Rule::Redirect {
        kind: parse_rule_kind(base_kind),
        pattern: Pattern::new(&pattern_str),
        message,
    })
}

fn parse_after_rule(rest: &[Token]) -> Result<Rule, String> {
    let (pattern_str, message) = extract_pattern_and_message(rest);
    let message = message.ok_or("after requires a pattern and quoted message")?;
    if pattern_str.is_empty() {
        return Err("after requires a pattern".into());
    }
    Ok(Rule::After {
        pattern: Pattern::new(&pattern_str),
        message,
    })
}

fn parse_mcp_rule(keyword: &str, rest: &[Token]) -> Result<Rule, String> {
    let (pattern_str, _) = extract_pattern_and_message(rest);
    if pattern_str.is_empty() {
        return Err(format!("{keyword} requires a tool pattern"));
    }
    let base_kind = keyword.split('-').next().unwrap_or("ask");
    Ok(Rule::Mcp {
        kind: parse_rule_kind(base_kind),
        pattern: Pattern::new(&pattern_str),
    })
}

fn parse_set_rule(rest: &[Token]) -> Result<Rule, String> {
    let bare: Vec<&str> = rest
        .iter()
        .filter_map(|t| match t {
            Token::Bare(s) => Some(s.as_str()),
            Token::Quoted(_) => None,
        })
        .collect();
    if bare.is_empty() {
        return Err("set requires a key".into());
    }
    Ok(Rule::Set {
        key: bare[0].to_owned(),
        value: bare.get(1).copied().unwrap_or_default().to_owned(),
    })
}

fn parse_alias_rule(rest: &[Token]) -> Result<Rule, String> {
    let bare: Vec<&str> = rest
        .iter()
        .filter_map(|t| match t {
            Token::Bare(s) => Some(s.as_str()),
            Token::Quoted(_) => None,
        })
        .collect();
    if bare.len() < 2 {
        return Err("alias requires source and target".into());
    }
    Ok(Rule::Alias {
        source: bare[0].to_owned(),
        target: bare[1].to_owned(),
    })
}

fn parse_rule_kind(word: &str) -> Decision {
    match word {
        "allow" => Decision::Allow,
        "deny" => Decision::Deny,
        _ => Decision::Ask,
    }
}

fn parse_action_word(word: &str) -> Option<Decision> {
    match word {
        "allow" => Some(Decision::Allow),
        "ask" => Some(Decision::Ask),
        "deny" => Some(Decision::Deny),
        _ => None,
    }
}

/// Walk up from `start` looking for `.rippy` or `.dippy` config files.
fn find_project_config(start: &Path) -> Option<PathBuf> {
    let mut dir = start;
    loop {
        let rippy = dir.join(".rippy");
        if rippy.is_file() {
            return Some(rippy);
        }
        let dippy = dir.join(".dippy");
        if dippy.is_file() {
            return Some(dippy);
        }
        dir = dir.parent()?;
    }
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parse_allow_rule() {
        let rule = parse_rule("allow git status").unwrap();
        match rule {
            Rule::Command {
                kind: Decision::Allow,
                pattern,
                message,
            } => {
                assert_eq!(pattern.as_str(), "git status");
                assert!(message.is_none());
            }
            _ => panic!("expected Command rule"),
        }
    }

    #[test]
    fn parse_deny_with_message() {
        let rule = parse_rule(r#"deny python "Use uv run python""#).unwrap();
        match rule {
            Rule::Command {
                kind: Decision::Deny,
                pattern,
                message,
            } => {
                assert_eq!(pattern.as_str(), "python");
                assert_eq!(message.as_deref(), Some("Use uv run python"));
            }
            _ => panic!("expected Command rule"),
        }
    }

    #[test]
    fn parse_deny_multi_word_pattern_with_message() {
        let rule = parse_rule(r#"deny rm -rf "use trash instead""#).unwrap();
        match rule {
            Rule::Command {
                kind: Decision::Deny,
                pattern,
                message,
            } => {
                assert_eq!(pattern.as_str(), "rm -rf");
                assert_eq!(message.as_deref(), Some("use trash instead"));
            }
            _ => panic!("expected Command rule"),
        }
    }

    #[test]
    fn parse_redirect_rule() {
        let rule = parse_rule("deny-redirect **/.env*").unwrap();
        match rule {
            Rule::Redirect {
                kind: Decision::Deny,
                pattern,
                ..
            } => {
                assert_eq!(pattern.as_str(), "**/.env*");
            }
            _ => panic!("expected Redirect rule"),
        }
    }

    #[test]
    fn parse_after_rule() {
        let rule = parse_rule(r#"after git "committed successfully""#).unwrap();
        match rule {
            Rule::After { pattern, message } => {
                assert_eq!(pattern.as_str(), "git");
                assert_eq!(message, "committed successfully");
            }
            _ => panic!("expected After rule"),
        }
    }

    #[test]
    fn parse_set_rule() {
        let rule = parse_rule("set default ask").unwrap();
        match rule {
            Rule::Set { key, value } => {
                assert_eq!(key, "default");
                assert_eq!(value, "ask");
            }
            _ => panic!("expected Set rule"),
        }
    }

    #[test]
    fn parse_alias_rule() {
        let rule = parse_rule("alias ~/custom-git git").unwrap();
        match rule {
            Rule::Alias { source, target } => {
                assert_eq!(source, "~/custom-git");
                assert_eq!(target, "git");
            }
            _ => panic!("expected Alias rule"),
        }
    }

    #[test]
    fn parse_mcp_rule() {
        let rule = parse_rule("deny-mcp dangerous_tool").unwrap();
        match rule {
            Rule::Mcp {
                kind: Decision::Deny,
                pattern,
            } => {
                assert_eq!(pattern.as_str(), "dangerous_tool");
            }
            _ => panic!("expected Mcp rule"),
        }
    }

    #[test]
    fn last_match_wins() {
        let config = Config::from_rules(vec![
            Rule::Command {
                kind: Decision::Deny,
                pattern: Pattern::new("rm"),
                message: Some("blocked".into()),
            },
            Rule::Command {
                kind: Decision::Allow,
                pattern: Pattern::new("rm --help"),
                message: Some("help is fine".into()),
            },
        ]);
        let v = config.match_command("rm --help").unwrap();
        assert_eq!(v.decision, Decision::Allow);
        assert_eq!(v.reason, "help is fine");
    }

    #[test]
    fn tokenize_quoted_strings() {
        let tokens = tokenize_config_line(r#"deny python "Use uv run python""#);
        assert_eq!(tokens.len(), 3);
        assert!(matches!(&tokens[0], Token::Bare(s) if s == "deny"));
        assert!(matches!(&tokens[1], Token::Bare(s) if s == "python"));
        assert!(matches!(&tokens[2], Token::Quoted(s) if s == "Use uv run python"));
    }

    #[test]
    fn tokenize_escaped_quote() {
        let tokens = tokenize_config_line(r#"deny test "say \"hello\"""#);
        assert_eq!(tokens.len(), 3);
        assert!(matches!(&tokens[2], Token::Quoted(s) if s == r#"say "hello""#));
    }

    #[test]
    fn unknown_directive_errors() {
        assert!(parse_rule("foobar something").is_err());
    }

    #[test]
    fn alias_resolution() {
        let config = Config {
            aliases: vec![("~/custom-git".into(), "git".into())],
            ..Config::default()
        };
        assert_eq!(config.resolve_alias("~/custom-git"), "git");
        assert_eq!(config.resolve_alias("npm"), "npm");
    }

    #[test]
    fn match_redirect_last_wins() {
        let config = Config::from_rules(vec![
            Rule::Redirect {
                kind: Decision::Deny,
                pattern: Pattern::new("/etc/*"),
                message: Some("no writes to /etc".into()),
            },
            Rule::Redirect {
                kind: Decision::Allow,
                pattern: Pattern::new("/etc/hosts"),
                message: Some("hosts ok".into()),
            },
        ]);
        let v = config.match_redirect("/etc/hosts").unwrap();
        assert_eq!(v.decision, Decision::Allow);
    }

    #[test]
    fn settings_extracted() {
        let config = Config::from_rules(vec![
            Rule::Set {
                key: "default".into(),
                value: "deny".into(),
            },
            Rule::Set {
                key: "log".into(),
                value: "~/.rippy/audit.log".into(),
            },
            Rule::Set {
                key: "log-full".into(),
                value: String::new(),
            },
        ]);
        assert_eq!(config.default_action, Some(Decision::Deny));
        assert!(config.log_file.is_some());
        assert!(config.log_full);
    }

    #[test]
    fn match_mcp_rule() {
        let config = Config::from_rules(vec![Rule::Mcp {
            kind: Decision::Deny,
            pattern: Pattern::new("dangerous*"),
        }]);
        let v = config.match_mcp("dangerous_tool").unwrap();
        assert_eq!(v.decision, Decision::Deny);
        assert!(config.match_mcp("safe_tool").is_none());
    }

    #[test]
    fn match_after_rule() {
        let config = Config::from_rules(vec![Rule::After {
            pattern: Pattern::new("git commit"),
            message: "committed!".into(),
        }]);
        assert_eq!(
            config.match_after("git commit -m foo"),
            Some("committed!".into())
        );
        assert!(config.match_after("ls").is_none());
    }

    #[test]
    fn allow_uv_run_python_c() {
        let config = Config::from_rules(vec![
            Rule::Command {
                kind: Decision::Deny,
                pattern: Pattern::new("python"),
                message: Some("Use uv run python".into()),
            },
            Rule::Command {
                kind: Decision::Allow,
                pattern: Pattern::new("uv run python -c"),
                message: None,
            },
        ]);
        let v = config.match_command("python foo.py").unwrap();
        assert_eq!(v.decision, Decision::Deny);
        let v = config.match_command("uv run python -c 'print(1)'").unwrap();
        assert_eq!(v.decision, Decision::Allow);
    }
}
