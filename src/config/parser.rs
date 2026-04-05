use std::path::PathBuf;

use crate::verdict::Decision;

use super::{ConfigDirective, Rule, RuleTarget};

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
