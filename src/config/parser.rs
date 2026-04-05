use std::path::PathBuf;

use crate::verdict::Decision;

use super::types::{ConfigDirective, Rule, RuleTarget};

/// A token from a config line, tagged as quoted or unquoted.
#[derive(Debug)]
pub(super) enum Token {
    Bare(String),
    Quoted(String),
}

/// Tokenize a config line, respecting quoted strings.
/// Returns tagged tokens so callers can distinguish patterns from messages.
pub(super) fn tokenize_config_line(line: &str) -> Vec<Token> {
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

/// Parse a single config line into a `ConfigDirective`.
///
/// # Errors
///
/// Returns an error string if the line contains an unknown directive or
/// invalid syntax.
pub fn parse_rule(line: &str) -> Result<ConfigDirective, String> {
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
        "allow-read" | "ask-read" | "deny-read" => parse_file_rule(keyword, rest, "read"),
        "allow-write" | "ask-write" | "deny-write" => parse_file_rule(keyword, rest, "write"),
        "allow-edit" | "ask-edit" | "deny-edit" => parse_file_rule(keyword, rest, "edit"),
        "set" => parse_set_directive(rest),
        "alias" => parse_alias_directive(rest),
        "cd-allow" => parse_cd_allow_directive(rest),
        _ => Err(format!("unknown directive: {keyword}")),
    }
}

pub fn parse_action_word(word: &str) -> Option<Decision> {
    match word {
        "allow" => Some(Decision::Allow),
        "ask" => Some(Decision::Ask),
        "deny" => Some(Decision::Deny),
        _ => None,
    }
}

fn parse_command_rule(keyword: &str, rest: &[Token]) -> Result<ConfigDirective, String> {
    let (pattern_str, message) = extract_pattern_and_message(rest);
    if pattern_str.is_empty() {
        return Err(format!("{keyword} requires a pattern"));
    }
    let mut rule = Rule::new(RuleTarget::Command, parse_rule_kind(keyword), &pattern_str);
    if let Some(msg) = message {
        rule = rule.with_message(msg);
    }
    Ok(ConfigDirective::Rule(rule))
}

fn parse_redirect_rule(keyword: &str, rest: &[Token]) -> Result<ConfigDirective, String> {
    let (pattern_str, message) = extract_pattern_and_message(rest);
    if pattern_str.is_empty() {
        return Err(format!("{keyword} requires a path pattern"));
    }
    let base_kind = keyword.split('-').next().unwrap_or("ask");
    let mut rule = Rule::new(
        RuleTarget::Redirect,
        parse_rule_kind(base_kind),
        &pattern_str,
    );
    if let Some(msg) = message {
        rule = rule.with_message(msg);
    }
    Ok(ConfigDirective::Rule(rule))
}

fn parse_after_rule(rest: &[Token]) -> Result<ConfigDirective, String> {
    let (pattern_str, message) = extract_pattern_and_message(rest);
    let message = message.ok_or("after requires a pattern and quoted message")?;
    if pattern_str.is_empty() {
        return Err("after requires a pattern".into());
    }
    let rule = Rule::new(RuleTarget::After, Decision::Allow, &pattern_str).with_message(message);
    Ok(ConfigDirective::Rule(rule))
}

fn parse_mcp_rule(keyword: &str, rest: &[Token]) -> Result<ConfigDirective, String> {
    let (pattern_str, _) = extract_pattern_and_message(rest);
    if pattern_str.is_empty() {
        return Err(format!("{keyword} requires a tool pattern"));
    }
    let base_kind = keyword.split('-').next().unwrap_or("ask");
    let rule = Rule::new(RuleTarget::Mcp, parse_rule_kind(base_kind), &pattern_str);
    Ok(ConfigDirective::Rule(rule))
}

fn parse_file_rule(keyword: &str, rest: &[Token], op: &str) -> Result<ConfigDirective, String> {
    let (pattern_str, message) = extract_pattern_and_message(rest);
    if pattern_str.is_empty() {
        return Err(format!("{keyword} requires a file path pattern"));
    }
    let base_kind = keyword.split('-').next().unwrap_or("ask");
    let target = match op {
        "read" => RuleTarget::FileRead,
        "write" => RuleTarget::FileWrite,
        "edit" => RuleTarget::FileEdit,
        _ => return Err(format!("unknown file operation: {op}")),
    };
    let mut rule = Rule::new(target, parse_rule_kind(base_kind), &pattern_str);
    if let Some(msg) = message {
        rule = rule.with_message(msg);
    }
    Ok(ConfigDirective::Rule(rule))
}

fn parse_set_directive(rest: &[Token]) -> Result<ConfigDirective, String> {
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
    Ok(ConfigDirective::Set {
        key: bare[0].to_owned(),
        value: bare.get(1).copied().unwrap_or_default().to_owned(),
    })
}

fn parse_alias_directive(rest: &[Token]) -> Result<ConfigDirective, String> {
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
    Ok(ConfigDirective::Alias {
        source: bare[0].to_owned(),
        target: bare[1].to_owned(),
    })
}

fn parse_cd_allow_directive(rest: &[Token]) -> Result<ConfigDirective, String> {
    let (path_str, _) = extract_pattern_and_message(rest);
    if path_str.is_empty() {
        return Err("cd-allow requires a directory path".into());
    }
    Ok(ConfigDirective::CdAllow(PathBuf::from(path_str)))
}

fn parse_rule_kind(word: &str) -> Decision {
    match word {
        "allow" => Decision::Allow,
        "deny" => Decision::Deny,
        _ => Decision::Ask,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::config::{ConfigDirective, RuleTarget};
    use crate::verdict::Decision;

    #[test]
    fn parse_allow_rule() {
        let d = parse_rule("allow git status").unwrap();
        match d {
            ConfigDirective::Rule(r) => {
                assert_eq!(r.target, RuleTarget::Command);
                assert_eq!(r.decision, Decision::Allow);
                assert_eq!(r.pattern.as_str(), "git status");
                assert!(r.message.is_none());
            }
            _ => panic!("expected Rule"),
        }
    }

    #[test]
    fn parse_deny_with_message() {
        let d = parse_rule(r#"deny python "Use uv run python""#).unwrap();
        match d {
            ConfigDirective::Rule(r) => {
                assert_eq!(r.target, RuleTarget::Command);
                assert_eq!(r.decision, Decision::Deny);
                assert_eq!(r.pattern.as_str(), "python");
                assert_eq!(r.message.as_deref(), Some("Use uv run python"));
            }
            _ => panic!("expected Rule"),
        }
    }

    #[test]
    fn parse_deny_multi_word_pattern_with_message() {
        let d = parse_rule(r#"deny rm -rf "use trash instead""#).unwrap();
        match d {
            ConfigDirective::Rule(r) => {
                assert_eq!(r.target, RuleTarget::Command);
                assert_eq!(r.decision, Decision::Deny);
                assert_eq!(r.pattern.as_str(), "rm -rf");
                assert_eq!(r.message.as_deref(), Some("use trash instead"));
            }
            _ => panic!("expected Rule"),
        }
    }

    #[test]
    fn parse_redirect_rule() {
        let d = parse_rule("deny-redirect **/.env*").unwrap();
        match d {
            ConfigDirective::Rule(r) => {
                assert_eq!(r.target, RuleTarget::Redirect);
                assert_eq!(r.decision, Decision::Deny);
                assert_eq!(r.pattern.as_str(), "**/.env*");
            }
            _ => panic!("expected Rule"),
        }
    }

    #[test]
    fn parse_after_rule() {
        let d = parse_rule(r#"after git "committed successfully""#).unwrap();
        match d {
            ConfigDirective::Rule(r) => {
                assert_eq!(r.target, RuleTarget::After);
                assert_eq!(r.pattern.as_str(), "git");
                assert_eq!(r.message.as_deref(), Some("committed successfully"));
            }
            _ => panic!("expected Rule"),
        }
    }

    #[test]
    fn parse_set_rule() {
        let d = parse_rule("set default ask").unwrap();
        match d {
            ConfigDirective::Set { key, value } => {
                assert_eq!(key, "default");
                assert_eq!(value, "ask");
            }
            _ => panic!("expected Set"),
        }
    }

    #[test]
    fn parse_alias_rule() {
        let d = parse_rule("alias ~/custom-git git").unwrap();
        match d {
            ConfigDirective::Alias { source, target } => {
                assert_eq!(source, "~/custom-git");
                assert_eq!(target, "git");
            }
            _ => panic!("expected Alias"),
        }
    }

    #[test]
    fn parse_mcp_rule() {
        let d = parse_rule("deny-mcp dangerous_tool").unwrap();
        match d {
            ConfigDirective::Rule(r) => {
                assert_eq!(r.target, RuleTarget::Mcp);
                assert_eq!(r.decision, Decision::Deny);
                assert_eq!(r.pattern.as_str(), "dangerous_tool");
            }
            _ => panic!("expected Rule"),
        }
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
    fn parse_file_read_rule() {
        let d = parse_rule(r#"deny-read **/.env* "no env files""#).unwrap();
        match d {
            ConfigDirective::Rule(r) => {
                assert_eq!(r.target, RuleTarget::FileRead);
                assert_eq!(r.decision, Decision::Deny);
                assert!(r.pattern.matches(".env"));
                assert!(r.pattern.matches("foo/.env.local"));
                assert_eq!(r.message.as_deref(), Some("no env files"));
            }
            _ => panic!("expected Rule"),
        }
    }

    #[test]
    fn parse_file_write_rule() {
        let d = parse_rule("allow-write /tmp/**").unwrap();
        match d {
            ConfigDirective::Rule(r) => {
                assert_eq!(r.target, RuleTarget::FileWrite);
                assert_eq!(r.decision, Decision::Allow);
            }
            _ => panic!("expected Rule"),
        }
    }
}
