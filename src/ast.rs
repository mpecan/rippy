use rable::{Node, NodeKind};

use crate::allowlists;

/// The operator used in a file redirect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectOp {
    /// `>` — write (truncate)
    Write,
    /// `>>` — append
    Append,
    /// `<` — read
    Read,
    /// `>&` or `&>` — file descriptor duplication
    FdDup,
    /// Anything else
    Other,
}

/// Extract the command name from a word slice.
#[must_use]
pub fn command_name_from_words(words: &[Node]) -> Option<&str> {
    words.first().and_then(word_value)
}

/// Extract the command name from a `Command` node.
#[must_use]
pub fn command_name(node: &Node) -> Option<&str> {
    let NodeKind::Command { words, .. } = &node.kind else {
        return None;
    };
    command_name_from_words(words)
}

/// Extract command arguments from a word slice (all words after the name).
#[must_use]
pub fn command_args_from_words(words: &[Node]) -> Vec<String> {
    words.iter().skip(1).map(node_text).collect()
}

/// Extract command arguments from a `Command` node.
#[must_use]
pub fn command_args(node: &Node) -> Vec<String> {
    let NodeKind::Command { words, .. } = &node.kind else {
        return Vec::new();
    };
    command_args_from_words(words)
}

/// Extract the redirect operator and target from a `Redirect` node.
#[must_use]
pub fn redirect_info(node: &Node) -> Option<(RedirectOp, String)> {
    let NodeKind::Redirect { op, target, .. } = &node.kind else {
        return None;
    };
    let redirect_op = match op.as_str() {
        ">" => RedirectOp::Write,
        ">>" => RedirectOp::Append,
        "<" | "<<<" => RedirectOp::Read,
        "&>" | ">&" => RedirectOp::FdDup,
        _ => RedirectOp::Other,
    };
    Some((redirect_op, node_text(target)))
}

/// Check whether a node contains command or process substitutions.
///
/// Rable keeps `$(...)` and backtick substitutions as literal text in word
/// values, so we check word values for expansion patterns.
#[must_use]
pub fn has_expansions(node: &Node) -> bool {
    has_expansions_kind(&node.kind)
}

/// Check for expansions in word and redirect slices.
#[must_use]
pub fn has_expansions_in_slices(words: &[Node], redirects: &[Node]) -> bool {
    words.iter().any(has_expansions) || redirects.iter().any(has_expansions)
}

/// Returns `true` if the node kind is itself a shell expansion.
///
/// This is the single source of truth for which `NodeKind` variants
/// represent expansions. Used by both `has_expansions_kind` (AST walking)
/// and `analyze_node` (verdict generation).
#[must_use]
pub const fn is_expansion_node(kind: &NodeKind) -> bool {
    matches!(
        kind,
        NodeKind::CommandSubstitution { .. }
            | NodeKind::ProcessSubstitution { .. }
            | NodeKind::ParamExpansion { .. }
            | NodeKind::ParamIndirect { .. }
            | NodeKind::ParamLength { .. }
            | NodeKind::AnsiCQuote { .. }
            | NodeKind::LocaleString { .. }
            | NodeKind::ArithmeticExpansion { .. }
            | NodeKind::BraceExpansion { .. }
    )
}

fn has_expansions_kind(kind: &NodeKind) -> bool {
    if is_expansion_node(kind) {
        return true;
    }
    match kind {
        NodeKind::Word { value, parts, .. } => {
            // Trust the parsed parts when present: rable decomposes words into
            // typed expansion nodes, so a `Word` whose parts are all literal
            // (e.g., `WordLiteral` for `'$(whoami)'`) contains no expansion
            // even though its raw value has metacharacters.
            //
            // Only fall back to the textual scan when parts are absent (e.g.,
            // synthetic words from heredoc content).
            if parts.is_empty() {
                has_shell_expansion_pattern(value)
            } else {
                parts.iter().any(has_expansions)
            }
        }
        NodeKind::Command {
            words, redirects, ..
        } => has_expansions_in_slices(words, redirects),
        NodeKind::Pipeline { commands, .. } => commands.iter().any(has_expansions),
        NodeKind::List { items } => items.iter().any(|item| has_expansions(&item.command)),
        NodeKind::Redirect { target, .. } => has_expansions(target),
        NodeKind::If {
            condition,
            then_body,
            else_body,
            ..
        } => {
            has_expansions(condition)
                || has_expansions(then_body)
                || else_body.as_deref().is_some_and(has_expansions)
        }
        NodeKind::Subshell { body, .. } | NodeKind::BraceGroup { body, .. } => has_expansions(body),
        NodeKind::HereDoc {
            content, quoted, ..
        } => !quoted && has_shell_expansion_pattern(content),
        _ => false,
    }
}

/// Check if a string contains shell expansion patterns (`$(`, `` ` ``, `${`, or `$` + identifier).
///
/// Used for heredoc content and other string-level expansion detection where
/// structured AST nodes are not available.
#[must_use]
pub fn has_shell_expansion_pattern(s: &str) -> bool {
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'`' {
            return true;
        }
        if b == b'$'
            && let Some(&next) = bytes.get(i + 1)
            && (next == b'('
                || next == b'{'
                || next == b'\''
                || next == b'"'
                || next.is_ascii_alphabetic()
                || next == b'_')
        {
            return true;
        }
    }
    false
}

/// Drop a leading `NAME=VALUE` env prefix, returning the rest of the command
/// verbatim (words, pipes, `&&`/`||`/`;` chains, and redirects all preserved).
///
/// This lets the config/permission string matchers see the real command name
/// (`cargo`) rather than the assignment token (`INSTA_UPDATE=always`), while the
/// result stays byte-for-byte identical to the same command written without the
/// prefix — so an env-prefixed command is treated exactly like its bare form and
/// no new redirect/pipeline path is introduced.
///
/// The prefix is located on the *leftmost* simple command, so pipelines and
/// lists are handled too: `RUST_LOG=debug cargo test | grep foo` becomes
/// `cargo test | grep foo`, and `A=1 cargo test && cargo build` becomes
/// `cargo test && cargo build`. The tail is kept by slicing the original string
/// from the first word's own source span, never a hand-rolled tokenizer.
///
/// Returns `None` (caller keeps the original string) when:
/// - the input is not a single top-level statement, or its leftmost node is not
///   a simple command carrying at least one assignment and one word;
/// - any assignment value contains a shell expansion — a deliberate coupling, so
///   an ALLOW rule cannot mask `FOO=$(rm -rf /) cargo test`; those are forced to
///   Ask by the analyzer's assignment-expansion guard instead;
/// - any assignment sets a code-influencing variable (see
///   [`is_dangerous_env_name`]), so a literal `LD_PRELOAD=./evil.so cargo test`
///   is not masked by a bare-command allow rule and instead reaches the analyzer.
#[must_use]
pub fn strip_env_prefix(command: &str, nodes: &[Node]) -> Option<String> {
    let [node] = nodes else {
        return None;
    };
    let (assignments, words) = leftmost_simple_command(node)?;
    if assignments.is_empty() || words.is_empty() {
        return None;
    }
    if assignments.iter().any(has_expansions) {
        return None;
    }
    if assignments
        .iter()
        .filter_map(|a| assignment_name(a, command))
        .any(is_dangerous_env_name)
    {
        return None;
    }
    let char_start = words.first()?.span.start;
    let byte_start = command.char_indices().nth(char_start).map(|(i, _)| i)?;
    command.get(byte_start..).map(str::to_owned)
}

/// Find the leftmost simple command, descending through the first branch of a
/// pipeline or list, and return its `(assignments, words)`.
fn leftmost_simple_command(node: &Node) -> Option<(&[Node], &[Node])> {
    match &node.kind {
        NodeKind::Command {
            assignments, words, ..
        } => Some((assignments, words)),
        NodeKind::Pipeline { commands, .. } => commands.first().and_then(leftmost_simple_command),
        NodeKind::List { items } => items
            .first()
            .and_then(|item| leftmost_simple_command(&item.command)),
        _ => None,
    }
}

/// Extract the `(name, value)` of a *literal* `NAME=VALUE` assignment node —
/// i.e. one whose value contains no shell expansion.
///
/// Reads the name and value directly from the assignment `Word`'s `value`
/// (`"NAME=VALUE"`), so no source string needs threading into the deep walk.
/// Returns `None` when the node is not a word, the value contains an expansion
/// (command substitution, parameter expansion, ...), or the name is empty.
///
/// A `NAME+=VALUE` compound assignment is deliberately *not* bound: bash
/// concatenates `VALUE` onto the variable's existing value, so binding it to the
/// right-hand side alone would be wrong. We return `None` (the variable stays
/// unresolved and the referencing command falls back to Ask) rather than
/// fabricate a truncated value.
///
/// The value has any outer quotes stripped, matching how the analyzer treats
/// argument words, so `FOO='a b'` yields `("FOO", "a b")`.
#[must_use]
pub fn literal_assignment(assignment: &Node) -> Option<(String, String)> {
    let NodeKind::Word { value, parts, .. } = &assignment.kind else {
        return None;
    };
    // A non-literal value (`x=$(cmd)`, `x=$y`) must never be bound — its real
    // value is unknown, so binding a fabricated one would be unsound.
    if parts.iter().any(has_expansions) {
        return None;
    }
    let (name, val) = value.split_once('=')?;
    // `NAME+=VALUE` appends to the existing binding; we cannot know the correct
    // result without the prior value, so refuse to bind it at all.
    if name.ends_with('+') {
        return None;
    }
    if name.is_empty() {
        return None;
    }
    Some((name.to_string(), strip_quotes(val)))
}

/// Return the variable name of a `NAME+=VALUE` compound (append) assignment
/// node, or `None` if the node is not an append assignment (`NAME=VALUE`) or
/// not a word.
///
/// An append combines the variable's *prior* value (which may not be statically
/// known, or may live in a shadowed binding) with the right-hand side, so no
/// concrete value can be bound soundly. The analyzer uses this to shadow the
/// variable as set-but-unknown — keeping safe-list commands allowed while
/// forcing handlers to Ask, and never resolving a stale prior literal.
#[must_use]
pub fn append_assignment_name(assignment: &Node) -> Option<String> {
    let NodeKind::Word { value, .. } = &assignment.kind else {
        return None;
    };
    let (name, _) = value.split_once('=')?;
    // `strip_suffix('+')` yields `None` unless the name ends with `+`, so this
    // matches `NAME+=...` only, never a plain `NAME=...`.
    let base = name.strip_suffix('+')?;
    if base.is_empty() {
        return None;
    }
    Some(base.to_string())
}

/// Extract the variable name of a `NAME=VALUE` (or `NAME+=VALUE`) assignment node.
fn assignment_name<'a>(assignment: &Node, source: &'a str) -> Option<&'a str> {
    let text = assignment.source_text(source);
    let (name, _) = text.split_once('=')?;
    Some(name.strip_suffix('+').unwrap_or(name))
}

/// Environment variable names whose values can change how a following command
/// loads or resolves code, letting a *literal* assignment turn an otherwise-safe
/// command into arbitrary code execution (e.g. `LD_PRELOAD`, `BASH_ENV`,
/// `GIT_SSH_COMMAND`). When a leading env prefix sets any of these,
/// [`strip_env_prefix`] refuses to strip so the command is not masked by a
/// string-layer allow rule and instead falls through to the analyzer.
#[must_use]
fn is_dangerous_env_name(name: &str) -> bool {
    // Dynamic-linker families: Linux `LD_*` (LD_PRELOAD, LD_LIBRARY_PATH,
    // LD_AUDIT, ...) and macOS `DYLD_*` (DYLD_INSERT_LIBRARIES, ...).
    if name.starts_with("LD_") || name.starts_with("DYLD_") {
        return true;
    }
    matches!(
        name,
        "BASH_ENV"
            | "ENV"
            | "SHELLOPTS"
            | "BASHOPTS"
            | "IFS"
            | "PS4"
            | "GIT_SSH"
            | "GIT_SSH_COMMAND"
            | "GIT_EXTERNAL_DIFF"
            | "GIT_PAGER"
            | "PAGER"
            | "EDITOR"
            | "VISUAL"
            | "PERL5OPT"
            | "PERL5LIB"
            | "PYTHONSTARTUP"
            | "PYTHONPATH"
            | "NODE_OPTIONS"
            | "RUBYOPT"
    )
}

/// Check if a redirect target is inherently safe (e.g., /dev/null).
#[must_use]
pub fn is_safe_redirect_target(target: &str) -> bool {
    matches!(target, "/dev/null" | "/dev/stdout" | "/dev/stderr")
}

/// Whether a `Command` node carries any redirects at all.
///
/// Used to route a single simple command that has redirects (e.g.
/// `echo x > .env`) through the full analyzer, since the redirect target may be
/// protected and cannot be judged safe on the command name alone.
#[must_use]
pub const fn command_has_redirects(node: &Node) -> bool {
    matches!(&node.kind, NodeKind::Command { redirects, .. } if !redirects.is_empty())
}

/// Returns `true` when a [`RedirectOp::FdDup`] target denotes a file
/// descriptor operation rather than a file write.
///
/// `&>`/`>&` are parsed as `FdDup`, but they mean two different things
/// depending on the target: a bare descriptor (`2>&1`, `>&2`) or a close
/// (`>&-`) is a real fd duplication, whereas a path (`&> out.log`) is a file
/// write and must be treated like `>`. Only the descriptor forms are matched
/// here: an optional leading `&`, then either `-` (close) or all-ASCII digits.
#[must_use]
pub fn is_fd_dup_target(target: &str) -> bool {
    let t = target.strip_prefix('&').unwrap_or(target);
    t == "-" || (!t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()))
}

/// Check if a node is a harmless fallback command (for `|| true` patterns).
#[must_use]
pub fn is_harmless_fallback(node: &Node) -> bool {
    let Some(name) = command_name(node) else {
        return false;
    };
    matches!(name, "true" | "false" | ":" | "echo" | "printf")
}

/// Extract text from a node, stripping quotes.
fn node_text(node: &Node) -> String {
    if let NodeKind::Word { value, .. } = &node.kind {
        strip_quotes(value)
    } else {
        String::new()
    }
}

/// Get the string value of a word node.
const fn word_value(node: &Node) -> Option<&str> {
    if let NodeKind::Word { value, .. } = &node.kind {
        Some(value.as_str())
    } else {
        None
    }
}

/// Strip surrounding quotes from a string token.
fn strip_quotes(s: &str) -> String {
    let s = s.trim();
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        s[1..s.len() - 1].to_owned()
    } else if s.len() >= 3
        && ((s.starts_with("$'") && s.ends_with('\''))
            || (s.starts_with("$\"") && s.ends_with('"')))
    {
        s[2..s.len() - 1].to_owned()
    } else {
        s.to_owned()
    }
}

/// Returns `true` when a node is a safe heredoc data-passing idiom:
/// a single `SIMPLE_SAFE` command whose only redirects are quoted heredocs,
/// with no word-level expansions.
///
/// Example: `cat <<'EOF' ... EOF` — `cat` is safe, heredoc is quoted,
/// no pipes, no lists.
///
/// Reliability note: the structural guarantees here assume rable produces
/// a faithful AST for heredocs inside `$(...)`. That held unreliably before
/// rable 0.1.14 (see rable issue #26) — an unmatched `(` in a heredoc body
/// could corrupt paren tracking and drop the `HereDoc` node. Pin `rable >=
/// 0.1.14` when touching this helper.
///
/// Scope note: the checks here are intentionally not tightened further
/// (e.g., restricting to literally `cat` or `words.len() == 1`). `SIMPLE_SAFE`
/// is a read-only-viewer allowlist (`cat`, `head`, `grep`, `xxd`, …) with no
/// command-execution primitives, so a non-`cat` entry with flags and a
/// quoted heredoc is still safe data-passing. The existing conditions
/// (`SIMPLE_SAFE` + all-redirects-quoted-heredocs + no word-expansions) are
/// already structurally tight; the rable 0.1.14 fix makes them *reliable*.
#[must_use]
pub fn is_safe_heredoc_substitution(command: &Node) -> bool {
    let NodeKind::Command {
        words, redirects, ..
    } = &command.kind
    else {
        return false;
    };
    let Some(name) = command_name_from_words(words) else {
        return false;
    };
    if !allowlists::is_simple_safe(name) {
        return false;
    }
    if redirects.is_empty() {
        return false;
    }
    let all_quoted_heredocs = redirects
        .iter()
        .all(|r| matches!(&r.kind, NodeKind::HereDoc { quoted, .. } if *quoted));
    if !all_quoted_heredocs {
        return false;
    }
    !words.iter().any(has_expansions)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use crate::parser::BashParser;

    use super::*;

    fn parse_first(source: &str) -> Vec<Node> {
        let mut parser = BashParser::new().unwrap();
        parser.parse(source).unwrap()
    }

    fn find_command(nodes: &[Node]) -> Option<&Node> {
        for node in nodes {
            match &node.kind {
                NodeKind::Command { .. } => return Some(node),
                NodeKind::Pipeline { commands, .. } => {
                    if let Some(cmd) = find_command(commands) {
                        return Some(cmd);
                    }
                }
                NodeKind::List { items } => {
                    let nodes: Vec<&Node> = items.iter().map(|i| &i.command).collect();
                    if let Some(cmd) = find_command_refs(&nodes) {
                        return Some(cmd);
                    }
                }
                _ => {}
            }
        }
        None
    }

    fn find_command_refs<'a>(nodes: &[&'a Node]) -> Option<&'a Node> {
        for node in nodes {
            if matches!(node.kind, NodeKind::Command { .. }) {
                return Some(node);
            }
        }
        None
    }

    #[test]
    fn extract_command_name() {
        let nodes = parse_first("git status");
        let cmd = find_command(&nodes).unwrap();
        assert_eq!(command_name(cmd), Some("git"));
    }

    #[test]
    fn extract_command_args() {
        let nodes = parse_first("git commit -m 'hello world'");
        let cmd = find_command(&nodes).unwrap();
        let args = command_args(cmd);
        assert!(args.contains(&"commit".to_owned()));
        assert!(args.contains(&"-m".to_owned()));
    }

    #[test]
    fn detect_command_substitution() {
        let nodes = parse_first("echo $(whoami)");
        assert!(has_expansions(&nodes[0]));
    }

    #[test]
    fn no_expansions_in_literal() {
        let nodes = parse_first("echo hello");
        let cmd = find_command(&nodes).unwrap();
        assert!(!has_expansions(cmd));
    }

    #[test]
    fn redirect_write() {
        let nodes = parse_first("echo foo > output.txt");
        let NodeKind::Command { redirects, .. } = &nodes[0].kind else {
            unreachable!("expected Command node");
        };
        let (op, target) = redirect_info(&redirects[0]).unwrap();
        assert_eq!(op, RedirectOp::Write);
        assert_eq!(target, "output.txt");
    }

    #[test]
    fn redirect_append() {
        let nodes = parse_first("echo foo >> log.txt");
        let NodeKind::Command { redirects, .. } = &nodes[0].kind else {
            unreachable!("expected Command node");
        };
        let (op, target) = redirect_info(&redirects[0]).unwrap();
        assert_eq!(op, RedirectOp::Append);
        assert_eq!(target, "log.txt");
    }

    #[test]
    fn fd_dup_target_recognizes_descriptors_but_not_paths() {
        // Bare descriptors and closes are fd operations.
        assert!(is_fd_dup_target("1"));
        assert!(is_fd_dup_target("2"));
        assert!(is_fd_dup_target("&1"));
        assert!(is_fd_dup_target("-"));
        assert!(is_fd_dup_target("&-"));
        // Paths (the `&> file` / `>& file` forms) are file writes, not fd dups.
        assert!(!is_fd_dup_target("/etc/passwd"));
        assert!(!is_fd_dup_target("out.log"));
        assert!(!is_fd_dup_target("/tmp/o"));
        assert!(!is_fd_dup_target(""));
        assert!(!is_fd_dup_target("1x"));
    }

    // ---- Expansion detection for hardened node types ----

    #[test]
    fn detect_param_expansion() {
        let nodes = parse_first("echo ${HOME}");
        assert!(has_expansions(&nodes[0]));
    }

    #[test]
    fn detect_simple_var_expansion() {
        let nodes = parse_first("echo $HOME");
        assert!(has_expansions(&nodes[0]));
    }

    #[test]
    fn detect_param_length() {
        let nodes = parse_first("echo ${#var}");
        assert!(has_expansions(&nodes[0]));
    }

    #[test]
    fn detect_param_indirect() {
        let nodes = parse_first("echo ${!ref}");
        assert!(has_expansions(&nodes[0]));
    }

    #[test]
    fn detect_ansi_c_quote() {
        let nodes = parse_first("echo $'\\x41'");
        assert!(has_expansions(&nodes[0]));
    }

    #[test]
    fn detect_locale_string() {
        let nodes = parse_first("echo $\"hello\"");
        assert!(has_expansions(&nodes[0]));
    }

    #[test]
    fn detect_arithmetic_expansion_inline() {
        let nodes = parse_first("echo $((1+1))");
        assert!(has_expansions(&nodes[0]));
    }

    #[test]
    fn detect_brace_expansion() {
        let nodes = parse_first("echo {a,b,c}");
        assert!(has_expansions(&nodes[0]));
    }

    #[test]
    fn detect_brace_expansion_range() {
        let nodes = parse_first("echo {1..10}");
        assert!(has_expansions(&nodes[0]));
    }

    // ---- Quote stripping for ANSI-C and locale ----

    #[test]
    fn strip_ansi_c_quotes() {
        assert_eq!(strip_quotes("$'hello'"), "hello");
    }

    #[test]
    fn strip_locale_quotes() {
        assert_eq!(strip_quotes("$\"hello\""), "hello");
    }

    #[test]
    fn strip_regular_quotes_unchanged() {
        assert_eq!(strip_quotes("'hello'"), "hello");
        assert_eq!(strip_quotes("\"hello\""), "hello");
        assert_eq!(strip_quotes("hello"), "hello");
    }

    // ---- Shell expansion pattern detection ----

    #[test]
    fn expansion_pattern_detects_dollar_var() {
        assert!(has_shell_expansion_pattern("$HOME"));
        assert!(has_shell_expansion_pattern("hello $USER world"));
        assert!(has_shell_expansion_pattern("$_private"));
    }

    #[test]
    fn expansion_pattern_detects_braced() {
        assert!(has_shell_expansion_pattern("${HOME}"));
    }

    #[test]
    fn expansion_pattern_detects_command_sub() {
        assert!(has_shell_expansion_pattern("$(whoami)"));
        assert!(has_shell_expansion_pattern("`whoami`"));
    }

    #[test]
    fn expansion_pattern_detects_ansi_c() {
        assert!(has_shell_expansion_pattern("$'hello'"));
    }

    #[test]
    fn expansion_pattern_no_false_positive() {
        assert!(!has_shell_expansion_pattern("hello world"));
        assert!(!has_shell_expansion_pattern("price is $5"));
        assert!(!has_shell_expansion_pattern(""));
    }

    // ---- Env-prefix stripping ----

    fn strip(command: &str) -> Option<String> {
        let nodes = parse_first(command);
        strip_env_prefix(command, &nodes)
    }

    #[test]
    fn strip_env_prefix_single_assignment() {
        assert_eq!(
            strip("INSTA_UPDATE=always cargo test"),
            Some("cargo test".to_owned())
        );
    }

    #[test]
    fn strip_env_prefix_multiple_assignments() {
        assert_eq!(strip("A=1 B=2 cargo test"), Some("cargo test".to_owned()));
    }

    #[test]
    fn strip_env_prefix_quoted_value() {
        assert_eq!(strip("FOO='a b' cargo test"), Some("cargo test".to_owned()));
    }

    #[test]
    fn strip_env_prefix_none_without_assignment() {
        assert_eq!(strip("cargo test"), None);
    }

    #[test]
    fn strip_env_prefix_none_for_assignment_only() {
        // No command word after the assignment.
        assert_eq!(strip("FOO=bar"), None);
    }

    #[test]
    fn strip_env_prefix_none_when_value_has_expansion() {
        // Coupling guard: never strip when the value could execute code.
        assert_eq!(strip("FOO=$(rm -rf /) cargo test"), None);
        assert_eq!(strip("FOO=`whoami` cargo test"), None);
        assert_eq!(strip("FOO=${HOME} cargo test"), None);
    }

    #[test]
    fn strip_env_prefix_pipeline_first_command() {
        // #133: an env prefix on the first command of a pipeline is stripped,
        // and the rest of the pipeline is preserved verbatim.
        assert_eq!(
            strip("RUST_LOG=debug cargo test | grep foo"),
            Some("cargo test | grep foo".to_owned())
        );
    }

    #[test]
    fn strip_env_prefix_list_first_command() {
        // #133: an env prefix on the first command of an `&&`/`;` list is
        // stripped, and the rest of the list is preserved verbatim.
        assert_eq!(
            strip("INSTA_UPDATE=always cargo test && cargo build"),
            Some("cargo test && cargo build".to_owned())
        );
        assert_eq!(
            strip("A=1 cargo test; echo done"),
            Some("cargo test; echo done".to_owned())
        );
    }

    #[test]
    fn strip_env_prefix_preserves_redirects() {
        // Redirects must survive stripping so the match string is identical to
        // the same command written without the prefix (no new bypass path).
        assert_eq!(
            strip("FOO=bar cargo build > out.log"),
            Some("cargo build > out.log".to_owned())
        );
    }

    #[test]
    fn strip_env_prefix_none_for_dangerous_var() {
        // Code-influencing env vars must not be masked by a bare-command allow
        // rule; refusing to strip forces them through the analyzer.
        assert_eq!(strip("LD_PRELOAD=./evil.so cargo test"), None);
        assert_eq!(strip("LD_LIBRARY_PATH=/tmp cargo test"), None);
        assert_eq!(strip("DYLD_INSERT_LIBRARIES=./e.dylib cargo test"), None);
        assert_eq!(strip("BASH_ENV=./e.sh cargo test"), None);
        assert_eq!(strip("GIT_SSH_COMMAND=./evil git fetch"), None);
        assert_eq!(strip("NODE_OPTIONS=--require=./e.js node app"), None);
        // A dangerous var anywhere in a multi-assignment prefix blocks stripping.
        assert_eq!(strip("SAFE=1 LD_PRELOAD=./e.so cargo test"), None);
    }

    #[test]
    fn strip_env_prefix_allows_ordinary_vars() {
        // Common, non-code-influencing vars still strip normally.
        assert_eq!(
            strip("RUST_LOG=debug cargo test"),
            Some("cargo test".to_owned())
        );
        assert_eq!(
            strip("CARGO_TERM_COLOR=always cargo build"),
            Some("cargo build".to_owned())
        );
    }

    // ---- Assignment binding extraction (issue #132 review) ----

    fn first_assignment(source: &str) -> Node {
        let nodes = parse_first(source);
        let NodeKind::Command { assignments, .. } = &nodes[0].kind else {
            unreachable!("expected Command node");
        };
        assignments.first().unwrap().clone()
    }

    #[test]
    fn literal_assignment_plain() {
        let a = first_assignment("FOO=bar echo hi");
        assert_eq!(
            literal_assignment(&a),
            Some(("FOO".to_string(), "bar".to_string()))
        );
    }

    #[test]
    fn literal_assignment_rejects_append() {
        // `NAME+=VALUE` must not bind to the RHS alone (bash concatenates onto
        // the prior value); returning None keeps the resolver conservative.
        let a = first_assignment("A+=/more echo hi");
        assert_eq!(literal_assignment(&a), None);
    }

    #[test]
    fn append_assignment_name_matches_append_only() {
        let append = first_assignment("A+=/more echo hi");
        assert_eq!(append_assignment_name(&append), Some("A".to_string()));

        let plain = first_assignment("A=/x echo hi");
        assert_eq!(append_assignment_name(&plain), None);
    }
}
