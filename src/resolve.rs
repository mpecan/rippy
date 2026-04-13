//! Static expansion resolution: turns `$HOME`, `$'hello'`, `$((1+1))`, `{a,b}`
//! into concrete strings using rable's AST and the host environment.
//!
//! The resolved command is then re-classified through the full analyzer
//! pipeline, so the variable's *content* (not its name) determines the verdict.

use rable::{Node, NodeKind};

use crate::ast;

/// Result of resolving a single word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WordResolution {
    /// All parts resolved to a single literal string.
    Literal(String),
    /// Brace expansion produced multiple words (changes argument count).
    Multiple(Vec<String>),
    /// At least one part is unresolvable.
    Unresolvable {
        /// Human-readable explanation of why resolution failed.
        reason: String,
    },
}

/// Outcome of resolving a full argument list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedArgs {
    /// Resolved argument list, or `None` if any word was unresolvable.
    pub args: Option<Vec<String>>,
    /// True if the first word (command position) contains a parameter expansion.
    /// Forces Ask even when resolution succeeds — `$cmd args` is always dangerous.
    pub command_position_dynamic: bool,
    /// Reason from the first unresolvable word (for Ask diagnostics).
    pub failure_reason: Option<String>,
}

/// Trait for looking up variable values. Allows test injection without
/// touching the real process environment.
pub trait VarLookup: Send + Sync {
    /// Returns `Some(value)` if the variable is set, `None` if unset.
    fn lookup(&self, name: &str) -> Option<String>;
}

/// Production env-based lookup. Reads `std::env::var` for any variable name.
///
/// No allowlist — the resolved value is re-classified through the full
/// analyzer pipeline, so the variable's content (not its name) determines
/// the verdict.
pub struct EnvLookup;

impl VarLookup for EnvLookup {
    fn lookup(&self, name: &str) -> Option<String> {
        std::env::var(name).ok()
    }
}

/// Attempt to resolve a single word node into literal text (or multiple words).
#[must_use]
pub fn resolve_word(node: &Node, vars: &dyn VarLookup) -> WordResolution {
    resolve_word_kind(&node.kind, vars)
}

fn resolve_word_kind(kind: &NodeKind, vars: &dyn VarLookup) -> WordResolution {
    match kind {
        NodeKind::Word { value, parts, .. } => resolve_word_node(value, parts, vars),
        NodeKind::WordLiteral { value } => WordResolution::Literal(value.clone()),
        NodeKind::AnsiCQuote { decoded, .. } => WordResolution::Literal(decoded.clone()),
        NodeKind::LocaleString { inner, .. } => WordResolution::Literal(inner.clone()),
        NodeKind::ParamExpansion { param, op, arg } => {
            resolve_param_expansion(param, op.as_deref(), arg.as_deref(), vars)
        }
        NodeKind::ParamLength { param } => WordResolution::Unresolvable {
            reason: format!("${{#{param}}} length expansion is not supported"),
        },
        NodeKind::ParamIndirect { param, .. } => WordResolution::Unresolvable {
            reason: format!("${{!{param}}} indirect expansion is not supported"),
        },
        NodeKind::ArithmeticExpansion { expression } => resolve_arithmetic(expression.as_deref()),
        NodeKind::BraceExpansion { content } => expand_brace(content).map_or_else(
            || WordResolution::Unresolvable {
                reason: format!("brace expansion {content} could not be expanded"),
            },
            WordResolution::Multiple,
        ),
        NodeKind::CommandSubstitution { command, .. }
            if ast::is_safe_heredoc_substitution(command) =>
        {
            resolve_safe_heredoc_content(command)
        }
        NodeKind::CommandSubstitution { .. } => WordResolution::Unresolvable {
            reason: "command substitution requires execution".to_string(),
        },
        NodeKind::ProcessSubstitution { .. } => WordResolution::Unresolvable {
            reason: "process substitution requires execution".to_string(),
        },
        _ => WordResolution::Unresolvable {
            reason: "non-word node".to_string(),
        },
    }
}

/// Extract the concatenated heredoc content from a safe heredoc command.
/// Caller must ensure `is_safe_heredoc_substitution(command)` is true.
fn resolve_safe_heredoc_content(command: &Node) -> WordResolution {
    let NodeKind::Command { redirects, .. } = &command.kind else {
        return WordResolution::Unresolvable {
            reason: "expected Command node".to_string(),
        };
    };
    let mut content = String::new();
    for redir in redirects {
        if let NodeKind::HereDoc {
            content: body,
            quoted,
            ..
        } = &redir.kind
        {
            if !quoted {
                return WordResolution::Unresolvable {
                    reason: "unquoted heredoc".to_string(),
                };
            }
            content.push_str(body);
        }
    }
    WordResolution::Literal(content)
}

fn resolve_word_node(value: &str, parts: &[Node], vars: &dyn VarLookup) -> WordResolution {
    if parts.is_empty() {
        return WordResolution::Literal(strip_outer_quotes(value));
    }
    let mut resolved_parts: Vec<WordResolution> = Vec::with_capacity(parts.len());
    for part in parts {
        let r = resolve_word(part, vars);
        if let WordResolution::Unresolvable { reason } = r {
            return WordResolution::Unresolvable { reason };
        }
        resolved_parts.push(r);
    }
    combine_parts(&resolved_parts)
}

/// Combine resolved parts. Mixing `Multiple` parts with literals produces a
/// cartesian expansion (`file.{a,b}` → `[file.a, file.b]`).
///
/// Refuses patterns whose cartesian product would exceed `MAX_BRACE_EXPANSION`
/// items, returning `Unresolvable` so the caller falls back to Ask. This
/// prevents `{1..32}{1..32}{1..32}` (32k items) from exhausting memory.
fn combine_parts(parts: &[WordResolution]) -> WordResolution {
    let mut variants: Vec<String> = vec![String::new()];
    for part in parts {
        match part {
            WordResolution::Literal(s) => {
                for v in &mut variants {
                    v.push_str(s);
                }
            }
            WordResolution::Multiple(items) => {
                let projected = variants.len().saturating_mul(items.len());
                if projected > MAX_BRACE_EXPANSION {
                    return WordResolution::Unresolvable {
                        reason: format!(
                            "brace expansion would produce {projected} items (cap: {MAX_BRACE_EXPANSION})"
                        ),
                    };
                }
                let mut next = Vec::with_capacity(projected);
                for v in &variants {
                    for item in items {
                        let mut combined = v.clone();
                        combined.push_str(item);
                        next.push(combined);
                    }
                }
                variants = next;
            }
            WordResolution::Unresolvable { .. } => unreachable!("filtered above"),
        }
    }
    if variants.len() == 1 {
        WordResolution::Literal(variants.into_iter().next().unwrap_or_default())
    } else {
        WordResolution::Multiple(variants)
    }
}

fn resolve_param_expansion(
    param: &str,
    op: Option<&str>,
    arg: Option<&str>,
    vars: &dyn VarLookup,
) -> WordResolution {
    let value = vars.lookup(param);
    match (op, arg, value) {
        // Plain ${VAR} or $VAR with set value, OR ${VAR:-default} / ${VAR-default} with set value.
        // (Default operators return the variable's value when set; otherwise the default.)
        (None | Some(":-" | "-"), _, Some(v)) => WordResolution::Literal(v),
        // Plain ${VAR} or $VAR with unset value → unresolvable.
        (None, _, None) => WordResolution::Unresolvable {
            reason: format!("${param} is not set"),
        },
        // ${VAR:-default} / ${VAR-default} with unset value → use the literal default.
        (Some(":-" | "-"), Some(default), None) => WordResolution::Literal(default.to_string()),
        // ${VAR:+value} → value if set, empty if unset.
        (Some(":+"), Some(value), Some(_)) => WordResolution::Literal(value.to_string()),
        (Some(":+"), _, None) => WordResolution::Literal(String::new()),
        // Unsupported operator → unresolvable.
        (Some(op), _, _) => WordResolution::Unresolvable {
            reason: format!("${{{param}{op}...}} operator not supported"),
        },
    }
}

fn resolve_arithmetic(expression: Option<&Node>) -> WordResolution {
    expression.and_then(eval_arithmetic).map_or_else(
        || WordResolution::Unresolvable {
            reason: "arithmetic expression could not be evaluated".to_string(),
        },
        |n| WordResolution::Literal(n.to_string()),
    )
}

/// Evaluate an arithmetic expression node if all leaves are constants.
fn eval_arithmetic(expr: &Node) -> Option<i64> {
    match &expr.kind {
        NodeKind::ArithNumber { value } => parse_arith_number(value),
        NodeKind::ArithBinaryOp { op, left, right } => {
            let l = eval_arithmetic(left)?;
            let r = eval_arithmetic(right)?;
            apply_binary(op, l, r)
        }
        NodeKind::ArithUnaryOp { op, operand } => {
            let v = eval_arithmetic(operand)?;
            apply_unary(op, v)
        }
        _ => None,
    }
}

fn parse_arith_number(value: &str) -> Option<i64> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        return i64::from_str_radix(hex, 16).ok();
    }
    if value.starts_with('0') && value.len() > 1 && !value.contains(|c: char| !c.is_ascii_digit()) {
        return i64::from_str_radix(&value[1..], 8).ok();
    }
    value.parse::<i64>().ok()
}

fn apply_binary(op: &str, l: i64, r: i64) -> Option<i64> {
    match op {
        "+" => l.checked_add(r),
        "-" => l.checked_sub(r),
        "*" => l.checked_mul(r),
        "/" if r != 0 => l.checked_div(r),
        "%" if r != 0 => l.checked_rem(r),
        "**" => {
            let exp = u32::try_from(r).ok()?;
            l.checked_pow(exp)
        }
        "<<" => {
            let shift = u32::try_from(r).ok()?;
            l.checked_shl(shift)
        }
        ">>" => {
            let shift = u32::try_from(r).ok()?;
            l.checked_shr(shift)
        }
        "&" => Some(l & r),
        "|" => Some(l | r),
        "^" => Some(l ^ r),
        _ => None,
    }
}

fn apply_unary(op: &str, v: i64) -> Option<i64> {
    match op {
        "+" => Some(v),
        "-" => v.checked_neg(),
        "~" => Some(!v),
        "!" => Some(i64::from(v == 0)),
        _ => None,
    }
}

/// Maximum number of items a single brace expansion may produce.
///
/// Bash has no built-in cap, but we refuse to materialize anything larger
/// to prevent `{1..1000000000}` from exhausting memory. Patterns that would
/// exceed this cap are treated as `Unresolvable` (caller falls back to Ask).
const MAX_BRACE_EXPANSION: usize = 1024;

/// Expand a brace pattern like `{a,b,c}` or `{1..10}`.
///
/// Returns `None` if the pattern is malformed, contains nested braces,
/// or would produce more than `MAX_BRACE_EXPANSION` items.
fn expand_brace(content: &str) -> Option<Vec<String>> {
    let bytes = content.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'{' || bytes[bytes.len() - 1] != b'}' {
        return None;
    }
    let inner = &content[1..content.len() - 1];
    if inner.contains('{') || inner.contains('}') {
        return None; // nested braces — defer to follow-up
    }
    if let Some(range) = parse_range(inner) {
        return if range.len() <= MAX_BRACE_EXPANSION {
            Some(range)
        } else {
            None
        };
    }
    let items: Vec<String> = inner.split(',').map(str::to_string).collect();
    if items.len() < 2 || items.len() > MAX_BRACE_EXPANSION {
        return None;
    }
    Some(items)
}

fn parse_range(inner: &str) -> Option<Vec<String>> {
    let parts: Vec<&str> = inner.splitn(3, "..").collect();
    if parts.len() < 2 {
        return None;
    }
    if let (Ok(start), Ok(end)) = (parts[0].parse::<i64>(), parts[1].parse::<i64>()) {
        return numeric_range(start, end);
    }
    if parts[0].len() == 1 && parts[1].len() == 1 {
        let start = parts[0].chars().next()?;
        let end = parts[1].chars().next()?;
        if start.is_ascii() && end.is_ascii() {
            return Some(char_range(start, end));
        }
    }
    None
}

/// Build a numeric range, refusing patterns that would exceed
/// `MAX_BRACE_EXPANSION` items (returns `None` so the caller falls back to Ask).
fn numeric_range(start: i64, end: i64) -> Option<Vec<String>> {
    let span = (end - start).unsigned_abs();
    if span >= MAX_BRACE_EXPANSION as u64 {
        return None;
    }
    Some(if start <= end {
        (start..=end).map(|n| n.to_string()).collect()
    } else {
        (end..=start).rev().map(|n| n.to_string()).collect()
    })
}

fn char_range(start: char, end: char) -> Vec<String> {
    // Character ranges are bounded by the ASCII range (max 128 items),
    // well under MAX_BRACE_EXPANSION, so no extra check needed.
    let s = start as u8;
    let e = end as u8;
    if s <= e {
        (s..=e).map(|b| (b as char).to_string()).collect()
    } else {
        (e..=s).rev().map(|b| (b as char).to_string()).collect()
    }
}

/// Strip surrounding `'...'` or `"..."` quotes from a literal word value.
fn strip_outer_quotes(s: &str) -> String {
    let bytes = s.as_bytes();
    if bytes.len() >= 2
        && ((bytes[0] == b'\'' && bytes[bytes.len() - 1] == b'\'')
            || (bytes[0] == b'"' && bytes[bytes.len() - 1] == b'"'))
    {
        return s[1..s.len() - 1].to_string();
    }
    s.to_string()
}

/// Resolve all words in a command's `words` slice.
///
/// Returns the resolved arg list (or `None` if any word is unresolvable),
/// plus a flag indicating whether the first word (command position) contains
/// a `ParamExpansion` — which forces Ask even when resolution succeeds.
#[must_use]
pub fn resolve_command_args(words: &[Node], vars: &dyn VarLookup) -> ResolvedArgs {
    let command_position_dynamic = words.first().is_some_and(word_has_param_expansion);
    let mut resolved: Vec<String> = Vec::with_capacity(words.len());
    let mut failure_reason: Option<String> = None;
    let mut all_ok = true;
    for word in words {
        match resolve_word(word, vars) {
            WordResolution::Literal(s) => resolved.push(s),
            WordResolution::Multiple(items) => resolved.extend(items),
            WordResolution::Unresolvable { reason } => {
                if failure_reason.is_none() {
                    failure_reason = Some(reason);
                }
                all_ok = false;
                break;
            }
        }
    }
    ResolvedArgs {
        args: if all_ok { Some(resolved) } else { None },
        command_position_dynamic,
        failure_reason,
    }
}

fn word_has_param_expansion(node: &Node) -> bool {
    match &node.kind {
        NodeKind::ParamExpansion { .. } | NodeKind::ParamIndirect { .. } => true,
        NodeKind::Word { parts, .. } => parts.iter().any(word_has_param_expansion),
        _ => false,
    }
}

/// Quote an argument for inclusion in a re-parsable shell command.
///
/// If the argument contains shell metacharacters or whitespace, it is
/// single-quoted with internal single quotes escaped as `'\''`.
#[must_use]
pub fn shell_join_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "''".to_string();
    }
    if arg.bytes().all(is_safe_unquoted) {
        return arg.to_string();
    }
    let escaped = arg.replace('\'', r"'\''");
    format!("'{escaped}'")
}

const fn is_safe_unquoted(b: u8) -> bool {
    matches!(
        b,
        b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'-' | b'/' | b'.' | b','
    )
}

/// Join resolved args into a single shell-safe command string.
#[must_use]
pub fn shell_join(args: &[String]) -> String {
    args.iter()
        .map(|a| shell_join_arg(a))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::literal_string_with_formatting_args
)]
pub(crate) mod tests {
    use super::*;
    use crate::parser::BashParser;
    use std::collections::HashMap;

    /// Test-only `VarLookup` impl backed by a `HashMap`.
    pub struct MockLookup {
        vars: HashMap<String, String>,
    }

    impl MockLookup {
        pub fn new() -> Self {
            Self {
                vars: HashMap::new(),
            }
        }
        pub fn with(mut self, name: &str, value: &str) -> Self {
            self.vars.insert(name.to_string(), value.to_string());
            self
        }
    }

    impl VarLookup for MockLookup {
        fn lookup(&self, name: &str) -> Option<String> {
            self.vars.get(name).cloned()
        }
    }

    fn parse_command(source: &str) -> Vec<Node> {
        let mut parser = BashParser::new().unwrap();
        parser.parse(source).unwrap()
    }

    fn extract_words(source: &str) -> Vec<Node> {
        let nodes = parse_command(source);
        let NodeKind::Command { words, .. } = &nodes[0].kind else {
            panic!("expected Command");
        };
        words.clone()
    }

    fn first_arg_node(source: &str) -> Node {
        // Returns the second word (first argument after command name).
        extract_words(source).into_iter().nth(1).unwrap()
    }

    // ---- Literal node resolution ----

    #[test]
    fn resolve_word_literal() {
        let node = first_arg_node("echo hello");
        let lookup = MockLookup::new();
        assert_eq!(
            resolve_word(&node, &lookup),
            WordResolution::Literal("hello".to_string())
        );
    }

    #[test]
    fn resolve_ansi_c_quote_decoded() {
        let node = first_arg_node("echo $'\\x41'");
        let lookup = MockLookup::new();
        assert_eq!(
            resolve_word(&node, &lookup),
            WordResolution::Literal("A".to_string())
        );
    }

    #[test]
    fn resolve_locale_string() {
        let node = first_arg_node("echo $\"hello\"");
        let lookup = MockLookup::new();
        assert_eq!(
            resolve_word(&node, &lookup),
            WordResolution::Literal("hello".to_string())
        );
    }

    // ---- Parameter expansion ----

    #[test]
    fn resolve_simple_var_set() {
        let node = first_arg_node("echo $HOME");
        let lookup = MockLookup::new().with("HOME", "/Users/test");
        assert_eq!(
            resolve_word(&node, &lookup),
            WordResolution::Literal("/Users/test".to_string())
        );
    }

    #[test]
    fn resolve_simple_var_unset() {
        let node = first_arg_node("echo $UNSET");
        let lookup = MockLookup::new();
        match resolve_word(&node, &lookup) {
            WordResolution::Unresolvable { reason } => {
                assert!(reason.contains("$UNSET is not set"));
            }
            other => panic!("expected Unresolvable, got {other:?}"),
        }
    }

    #[test]
    fn resolve_braced_var() {
        let node = first_arg_node("echo ${HOME}");
        let lookup = MockLookup::new().with("HOME", "/x");
        assert_eq!(
            resolve_word(&node, &lookup),
            WordResolution::Literal("/x".to_string())
        );
    }

    #[test]
    fn resolve_default_when_unset() {
        let node = first_arg_node("echo ${UNSET:-fallback}");
        let lookup = MockLookup::new();
        assert_eq!(
            resolve_word(&node, &lookup),
            WordResolution::Literal("fallback".to_string())
        );
    }

    #[test]
    fn resolve_default_when_set() {
        let node = first_arg_node("echo ${VAR:-fallback}");
        let lookup = MockLookup::new().with("VAR", "actual");
        assert_eq!(
            resolve_word(&node, &lookup),
            WordResolution::Literal("actual".to_string())
        );
    }

    #[test]
    fn resolve_alt_value_when_set() {
        let node = first_arg_node("echo ${VAR:+yes}");
        let lookup = MockLookup::new().with("VAR", "anything");
        assert_eq!(
            resolve_word(&node, &lookup),
            WordResolution::Literal("yes".to_string())
        );
    }

    #[test]
    fn resolve_alt_value_when_unset() {
        let node = first_arg_node("echo ${UNSET:+yes}");
        let lookup = MockLookup::new();
        assert_eq!(
            resolve_word(&node, &lookup),
            WordResolution::Literal(String::new())
        );
    }

    #[test]
    fn unsupported_param_op_unresolvable() {
        let node = first_arg_node("echo ${VAR##prefix}");
        let lookup = MockLookup::new().with("VAR", "x");
        assert!(matches!(
            resolve_word(&node, &lookup),
            WordResolution::Unresolvable { .. }
        ));
    }

    #[test]
    fn param_indirect_unresolvable() {
        let node = first_arg_node("echo ${!ref}");
        let lookup = MockLookup::new().with("ref", "HOME");
        assert!(matches!(
            resolve_word(&node, &lookup),
            WordResolution::Unresolvable { .. }
        ));
    }

    #[test]
    fn param_length_unresolvable() {
        let node = first_arg_node("echo ${#var}");
        let lookup = MockLookup::new().with("var", "abc");
        assert!(matches!(
            resolve_word(&node, &lookup),
            WordResolution::Unresolvable { .. }
        ));
    }

    // ---- Arithmetic expansion ----

    #[test]
    fn resolve_arithmetic_simple() {
        let node = first_arg_node("echo $((1+2))");
        let lookup = MockLookup::new();
        assert_eq!(
            resolve_word(&node, &lookup),
            WordResolution::Literal("3".to_string())
        );
    }

    #[test]
    fn resolve_arithmetic_complex() {
        let node = first_arg_node("echo $((2*3+4))");
        let lookup = MockLookup::new();
        assert_eq!(
            resolve_word(&node, &lookup),
            WordResolution::Literal("10".to_string())
        );
    }

    #[test]
    fn resolve_arithmetic_unary_negation() {
        let node = first_arg_node("echo $((-5))");
        let lookup = MockLookup::new();
        assert_eq!(
            resolve_word(&node, &lookup),
            WordResolution::Literal("-5".to_string())
        );
    }

    #[test]
    fn resolve_arithmetic_division_by_zero_unresolvable() {
        let node = first_arg_node("echo $((1/0))");
        let lookup = MockLookup::new();
        assert!(matches!(
            resolve_word(&node, &lookup),
            WordResolution::Unresolvable { .. }
        ));
    }

    #[test]
    fn resolve_arithmetic_with_var_unresolvable() {
        let node = first_arg_node("echo $((x+1))");
        let lookup = MockLookup::new();
        assert!(matches!(
            resolve_word(&node, &lookup),
            WordResolution::Unresolvable { .. }
        ));
    }

    // ---- Brace expansion ----

    #[test]
    fn resolve_brace_comma() {
        let node = first_arg_node("ls {a,b,c}");
        let lookup = MockLookup::new();
        assert_eq!(
            resolve_word(&node, &lookup),
            WordResolution::Multiple(vec!["a".into(), "b".into(), "c".into()])
        );
    }

    #[test]
    fn resolve_brace_numeric_range() {
        let node = first_arg_node("echo {1..3}");
        let lookup = MockLookup::new();
        assert_eq!(
            resolve_word(&node, &lookup),
            WordResolution::Multiple(vec!["1".into(), "2".into(), "3".into()])
        );
    }

    #[test]
    fn resolve_brace_char_range() {
        let node = first_arg_node("echo {a..c}");
        let lookup = MockLookup::new();
        assert_eq!(
            resolve_word(&node, &lookup),
            WordResolution::Multiple(vec!["a".into(), "b".into(), "c".into()])
        );
    }

    #[test]
    fn resolve_brace_with_prefix_and_suffix() {
        let node = first_arg_node("ls file.{txt,md}");
        let lookup = MockLookup::new();
        assert_eq!(
            resolve_word(&node, &lookup),
            WordResolution::Multiple(vec!["file.txt".into(), "file.md".into()])
        );
    }

    #[test]
    fn resolve_two_adjacent_brace_expansions() {
        // Two `Multiple` parts in the same word — exercises the cartesian
        // branch of `combine_parts` where `variants.len() > 1` AND a new
        // `Multiple` part is folded in.
        let node = first_arg_node("ls {a,b}{c,d}");
        let lookup = MockLookup::new();
        assert_eq!(
            resolve_word(&node, &lookup),
            WordResolution::Multiple(vec!["ac".into(), "ad".into(), "bc".into(), "bd".into(),])
        );
    }

    #[test]
    fn resolve_three_adjacent_brace_expansions() {
        // Three brace expansions: 2*2*2 = 8 variants. Exercises chained
        // cartesian products under the brace-cap limit.
        let node = first_arg_node("ls {a,b}{c,d}{e,f}");
        let lookup = MockLookup::new();
        let result = resolve_word(&node, &lookup);
        let WordResolution::Multiple(items) = result else {
            panic!("expected Multiple, got {result:?}");
        };
        assert_eq!(items.len(), 8);
        assert!(items.contains(&"ace".to_string()));
        assert!(items.contains(&"bdf".to_string()));
    }

    // ---- Command substitution: unresolvable ----

    #[test]
    fn command_substitution_unresolvable() {
        let node = first_arg_node("echo $(whoami)");
        let lookup = MockLookup::new();
        assert!(matches!(
            resolve_word(&node, &lookup),
            WordResolution::Unresolvable { .. }
        ));
    }

    // ---- resolve_command_args ----

    #[test]
    fn resolve_full_command_all_literal() {
        let words = extract_words("echo hello world");
        let lookup = MockLookup::new();
        let result = resolve_command_args(&words, &lookup);
        assert_eq!(
            result.args,
            Some(vec!["echo".into(), "hello".into(), "world".into()])
        );
        assert!(!result.command_position_dynamic);
    }

    #[test]
    fn resolve_full_command_with_var() {
        let words = extract_words("ls $HOME");
        let lookup = MockLookup::new().with("HOME", "/x");
        let result = resolve_command_args(&words, &lookup);
        assert_eq!(result.args, Some(vec!["ls".into(), "/x".into()]));
        assert!(!result.command_position_dynamic);
    }

    #[test]
    fn resolve_full_command_unresolvable_var() {
        let words = extract_words("ls $UNSET_XYZ");
        let lookup = MockLookup::new();
        let result = resolve_command_args(&words, &lookup);
        assert!(result.args.is_none());
        assert!(result.failure_reason.is_some());
    }

    #[test]
    fn command_position_dynamic_detected() {
        let words = extract_words("$cmd hello");
        let lookup = MockLookup::new().with("cmd", "ls");
        let result = resolve_command_args(&words, &lookup);
        assert!(result.command_position_dynamic);
        assert_eq!(result.args, Some(vec!["ls".into(), "hello".into()]));
    }

    #[test]
    fn brace_expansion_expands_args() {
        let words = extract_words("ls {a,b,c}");
        let lookup = MockLookup::new();
        let result = resolve_command_args(&words, &lookup);
        assert_eq!(
            result.args,
            Some(vec!["ls".into(), "a".into(), "b".into(), "c".into()])
        );
    }

    // ---- Shell joining ----

    #[test]
    fn shell_join_safe_args() {
        assert_eq!(shell_join_arg("hello"), "hello");
        assert_eq!(shell_join_arg("file.txt"), "file.txt");
        assert_eq!(shell_join_arg("/path/to/file"), "/path/to/file");
    }

    #[test]
    fn shell_join_with_spaces() {
        assert_eq!(shell_join_arg("hello world"), "'hello world'");
    }

    #[test]
    fn shell_join_with_inner_quote() {
        assert_eq!(shell_join_arg("it's"), r"'it'\''s'");
    }

    #[test]
    fn shell_join_empty() {
        assert_eq!(shell_join_arg(""), "''");
    }

    #[test]
    fn shell_join_args_list() {
        let args = vec![
            "echo".to_string(),
            "hello world".to_string(),
            "ok".to_string(),
        ];
        assert_eq!(shell_join(&args), "echo 'hello world' ok");
    }

    // ---- strip_outer_quotes ----

    #[test]
    fn strip_outer_quotes_double() {
        assert_eq!(strip_outer_quotes("\"hello\""), "hello");
    }

    #[test]
    fn strip_outer_quotes_single() {
        assert_eq!(strip_outer_quotes("'hello'"), "hello");
    }

    #[test]
    fn strip_outer_quotes_unquoted_unchanged() {
        assert_eq!(strip_outer_quotes("hello"), "hello");
    }

    #[test]
    fn strip_outer_quotes_mismatched_unchanged() {
        // Mismatched quote chars: only strips when both ends are the same.
        assert_eq!(strip_outer_quotes("'hello\""), "'hello\"");
        assert_eq!(strip_outer_quotes("\"hello'"), "\"hello'");
    }

    #[test]
    fn strip_outer_quotes_only_left_unchanged() {
        // A single quote at one end is not a pair — leave it alone.
        assert_eq!(strip_outer_quotes("'hello"), "'hello");
        assert_eq!(strip_outer_quotes("hello'"), "hello'");
    }

    #[test]
    fn strip_outer_quotes_empty_string() {
        assert_eq!(strip_outer_quotes(""), "");
    }

    #[test]
    fn strip_outer_quotes_single_char_unchanged() {
        // A single character can't be a quoted pair (need at least 2).
        assert_eq!(strip_outer_quotes("'"), "'");
        assert_eq!(strip_outer_quotes("\""), "\"");
    }

    #[test]
    fn strip_outer_quotes_just_quote_pair() {
        // Empty quoted string: both quotes get stripped → empty string.
        assert_eq!(strip_outer_quotes("''"), "");
        assert_eq!(strip_outer_quotes("\"\""), "");
    }

    // ---- EnvLookup ----

    #[test]
    fn env_lookup_returns_set_var() {
        // PATH is virtually always set; use it as a smoke test.
        let lookup = EnvLookup;
        assert!(lookup.lookup("PATH").is_some());
    }

    #[test]
    fn env_lookup_returns_none_for_unset() {
        let lookup = EnvLookup;
        assert!(
            lookup
                .lookup("__RIPPY_TEST_DEFINITELY_UNSET_42__")
                .is_none()
        );
    }
}
