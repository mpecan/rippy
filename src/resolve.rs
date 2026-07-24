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
    /// The word references a variable that is known to be *set* but whose
    /// value is not statically known (a for/select loop variable or a shell
    /// status/special var such as `$?`). We deliberately do NOT fabricate a
    /// value for it: substituting a placeholder and re-analyzing could hide an
    /// injected dangerous flag and flip a handler command from Ask to Allow.
    /// Callers gate on this outcome instead (see [`ResolvedArgs`]).
    DynamicKnown,
    /// At least one part is unresolvable.
    Unresolvable {
        /// Human-readable explanation of why resolution failed.
        reason: String,
    },
}

/// The static resolution state of a variable name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VarState {
    /// The variable is unset.
    Unset,
    /// The variable is set to a statically-known literal value.
    Value(String),
    /// The variable is known to be set, but its value is not statically known
    /// (loop-iteration variable, shell status/special variable, ...).
    DynamicSet,
}

/// A variable binding local to the command currently being analyzed.
///
/// Bindings are collected on the analyzer's `locals` stack and consulted by
/// [`ScopedLookup`] with a strict lexical-scope (checkpoint/truncate)
/// discipline, so they never satisfy a `$VAR` outside the scope that bound them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalBinding {
    /// Value fully known statically (literal `VAR=val` assignment / prefix).
    /// Substitutes its real value exactly like an env var and is re-analyzed —
    /// no injection surface beyond today's env path.
    Literal(String),
    /// Known to be set, value unknown (for/select loop variable). Resolves to
    /// [`WordResolution::DynamicKnown`], never a fabricated string.
    Dynamic,
}

/// Outcome of resolving a full argument list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedArgs {
    /// Resolved argument list, or `None` if any word was unresolvable
    /// or a `DynamicKnown` value landed in argument position.
    pub args: Option<Vec<String>>,
    /// True if the first word (command position) contains a parameter expansion.
    /// Forces Ask even when resolution succeeds — `$cmd args` is always dangerous.
    pub command_position_dynamic: bool,
    /// True if a *non-first* word resolved to [`WordResolution::DynamicKnown`]
    /// — a set-but-unknown value in argument position. The command is allowed
    /// only if its literal name is in `SIMPLE_SAFE` (safe regardless of
    /// argument values); every other command stays Ask.
    pub arg_position_dynamic: bool,
    /// Reason from the first unresolvable word (for Ask diagnostics).
    pub failure_reason: Option<String>,
}

/// Trait for looking up variable values. Allows test injection without
/// touching the real process environment.
pub trait VarLookup: Send + Sync {
    /// Returns `Some(value)` if the variable is set, `None` if unset.
    fn lookup(&self, name: &str) -> Option<String>;

    /// Returns the static resolution [`VarState`] of a variable name.
    ///
    /// The default implementation maps `lookup` onto `Value`/`Unset`, so
    /// existing implementors (`EnvLookup`, test mocks) work unchanged.
    /// [`ScopedLookup`] overrides this to surface local and status-var
    /// bindings.
    fn state(&self, name: &str) -> VarState {
        self.lookup(name).map_or(VarState::Unset, VarState::Value)
    }
}

/// Returns `true` if `name` is a shell status/special variable.
///
/// Such variables are always considered *set* with a dynamic value: `$?`, `$$`,
/// `$#`, `$!`, `$-`, `$*`, `$@`, numbered positional parameters, and named
/// specials such as `PIPESTATUS`, `RANDOM`, `SECONDS`, ... The base name is
/// matched *before* any `[` array subscript, so `${PIPESTATUS[0]}` is
/// recognized too.
#[must_use]
pub fn is_status_var(name: &str) -> bool {
    let base = name.split('[').next().unwrap_or(name);
    if base.is_empty() {
        return false;
    }
    if base.bytes().all(|b| b.is_ascii_digit()) {
        return true; // positional parameters ($0, $1, $2, ...)
    }
    matches!(
        base,
        "?" | "$"
            | "#"
            | "!"
            | "-"
            | "*"
            | "@"
            | "PIPESTATUS"
            | "RANDOM"
            | "SECONDS"
            | "LINENO"
            | "BASHPID"
            | "PPID"
            | "UID"
            | "EUID"
    )
}

/// A [`VarLookup`] that overlays command-local bindings and shell status
/// variables on top of an inner lookup (usually the process environment).
///
/// `state` consults `locals` (most-recent binding wins) and status-var names
/// first, then falls back to `inner`. Literal locals surface their value;
/// dynamic locals and status vars surface [`VarState::DynamicSet`].
pub struct ScopedLookup<'a> {
    locals: &'a [(String, LocalBinding)],
    inner: &'a dyn VarLookup,
}

impl<'a> ScopedLookup<'a> {
    /// Wrap `inner` with the given command-local bindings.
    #[must_use]
    pub const fn new(locals: &'a [(String, LocalBinding)], inner: &'a dyn VarLookup) -> Self {
        Self { locals, inner }
    }

    fn local(&self, name: &str) -> Option<&LocalBinding> {
        self.locals
            .iter()
            .rev()
            .find(|(n, _)| n == name)
            .map(|(_, b)| b)
    }
}

impl VarLookup for ScopedLookup<'_> {
    fn lookup(&self, name: &str) -> Option<String> {
        match self.local(name) {
            Some(LocalBinding::Literal(v)) => Some(v.clone()),
            Some(LocalBinding::Dynamic) => None,
            None => self.inner.lookup(name),
        }
    }

    fn state(&self, name: &str) -> VarState {
        match self.local(name) {
            Some(LocalBinding::Literal(v)) => VarState::Value(v.clone()),
            Some(LocalBinding::Dynamic) => VarState::DynamicSet,
            None if is_status_var(name) => VarState::DynamicSet,
            None => self.inner.state(name),
        }
    }
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
    let mut dynamic = false;
    for part in parts {
        match resolve_word(part, vars) {
            // Unresolvable is the most conservative outcome — it always forces
            // Ask — so it wins over a sibling DynamicKnown part.
            WordResolution::Unresolvable { reason } => {
                return WordResolution::Unresolvable { reason };
            }
            WordResolution::DynamicKnown => dynamic = true,
            r => resolved_parts.push(r),
        }
    }
    if dynamic {
        return WordResolution::DynamicKnown;
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
            WordResolution::Unresolvable { .. } | WordResolution::DynamicKnown => {
                unreachable!("filtered above")
            }
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
    let state = vars.state(param);
    match (op, arg, &state) {
        // Plain ${VAR}/$VAR or ${VAR:-def}/${VAR-def} with a known set value:
        // default operators return the variable's value when set.
        (None | Some(":-" | "-"), _, VarState::Value(v)) => WordResolution::Literal(v.clone()),
        // Same, but the value is dynamic (loop var / status var) → DynamicKnown.
        (None | Some(":-" | "-"), _, VarState::DynamicSet) => WordResolution::DynamicKnown,
        // Plain ${VAR} or $VAR with unset value → unresolvable.
        (None, _, VarState::Unset) => WordResolution::Unresolvable {
            reason: format!("${param} is not set"),
        },
        // ${VAR:-default} / ${VAR-default} with unset value → use the literal default.
        (Some(":-" | "-"), Some(default), VarState::Unset) => {
            WordResolution::Literal(default.to_string())
        }
        // ${VAR:+value} → the (literal) alternate when set (value or dynamic),
        // empty when unset. The alternate comes from source text, not the var
        // value, so a DynamicSet variable still yields a known literal.
        (Some(":+"), Some(value), VarState::Value(_) | VarState::DynamicSet) => {
            WordResolution::Literal(value.to_string())
        }
        (Some(":+"), _, VarState::Unset) => WordResolution::Literal(String::new()),
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
pub(crate) fn strip_outer_quotes(s: &str) -> String {
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
    let mut arg_position_dynamic = false;
    let mut all_ok = true;
    for (i, word) in words.iter().enumerate() {
        match resolve_word(word, vars) {
            WordResolution::Literal(s) => resolved.push(s),
            WordResolution::Multiple(items) => resolved.extend(items),
            // A set-but-unknown value. In command position it is already flagged
            // via `command_position_dynamic`; in argument position we never
            // fabricate a value — the caller gates on `arg_position_dynamic`.
            WordResolution::DynamicKnown => {
                if i > 0 {
                    arg_position_dynamic = true;
                }
                all_ok = false;
                break;
            }
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
        arg_position_dynamic,
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
#[path = "resolve_tests.rs"]
pub(crate) mod tests;
