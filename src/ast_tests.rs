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

// Expansion detection for hardened node types

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

// Quote stripping for ANSI-C and locale

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

/// #198: a quote pair spliced into the middle of a token is invisible to the
/// command, so a handler must not see it either.
#[test]
fn strip_quotes_spliced_mid_token() {
    assert_eq!(strip_quotes("--to-com'mand'"), "--to-command");
    assert_eq!(strip_quotes("--to-command\"\""), "--to-command");
    assert_eq!(strip_quotes("--to-command=\"a b\""), "--to-command=a b");
    assert_eq!(strip_quotes("-x'f'"), "-xf");
    assert_eq!(strip_quotes(r"a\ b"), "a b");
    // Quoting is literal inside the other quote form.
    assert_eq!(strip_quotes("\"it's\""), "it's");
}

/// An unbalanced quote means rable's tokenizer and the shell disagree about
/// where the word ends, so the raw token is kept rather than a fabricated value.
#[test]
fn strip_quotes_keeps_unbalanced_token() {
    assert_eq!(strip_quotes("it's"), "it's");
}

/// A `$'…'`/`$"…"` away from the front keeps its sigil: downstream guards read
/// the resolved text to decide whether a value is statically known.
#[test]
fn strip_quotes_keeps_embedded_dollar_quote() {
    assert_eq!(strip_quotes("/tmp/foo$\"x\""), "/tmp/foo$\"x\"");
    assert_eq!(strip_quotes("/tmp/foo$'x'"), "/tmp/foo$'x'");
}

// Shell expansion pattern detection

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
    assert!(!has_shell_expansion_pattern(""));
}

// `$5` is a real positional-parameter expansion in bash, not plain text — see
// issue #162. `has_shell_expansion_pattern` must flag it (and the other
// positional/special parameters) rather than treat it as a literal.
#[test]
fn expansion_pattern_detects_positional_and_special_params() {
    assert!(has_shell_expansion_pattern("price is $5"));
    assert!(has_shell_expansion_pattern("$1"));
    assert!(has_shell_expansion_pattern("$9"));
    assert!(has_shell_expansion_pattern("$@"));
    assert!(has_shell_expansion_pattern("$*"));
    assert!(has_shell_expansion_pattern("$#"));
    assert!(has_shell_expansion_pattern("$?"));
    assert!(has_shell_expansion_pattern("$$"));
    assert!(has_shell_expansion_pattern("$!"));
    assert!(has_shell_expansion_pattern("$-"));
}

// Quote-aware backtick detection (#202). The catalog pins the end-to-end
// verdicts; these pin the scanner's quote bookkeeping directly, since a command
// string cannot isolate a single unbalanced or mixed-quoting token.

#[test]
fn backtick_substitution_detected_outside_single_quotes() {
    assert!(has_backtick_substitution("`id`"));
    assert!(has_backtick_substitution("\"`id`\""));
    assert!(has_backtick_substitution("\"pre`id`post\""));
    assert!(has_backtick_substitution("'inert'\"`id`\""));
    // An unterminated double quote must not be read as "still inside a string".
    assert!(has_backtick_substitution("\"`id`"));
}

#[test]
fn backtick_substitution_ignores_inert_backticks() {
    assert!(!has_backtick_substitution("'`id`'"));
    assert!(!has_backtick_substitution("\"a\\`b\""));
    assert!(!has_backtick_substitution("\\`"));
    assert!(!has_backtick_substitution("plain text"));
    assert!(!has_backtick_substitution(""));
    // A backslash is literal inside single quotes, so the closing quote still
    // closes and the following backtick is live.
    assert!(has_backtick_substitution("'a\\'`id`"));
}

// Executing-substitution detection (#193 follow-up). The catalog pins the
// `case` verdicts; these pin the distinction the narrowing rests on — a word
// that merely fails to resolve versus one that runs a command.

#[test]
fn executing_substitution_detected() {
    assert!(has_executing_substitution("$(id)"));
    assert!(has_executing_substitution("\"$(id)\""));
    assert!(has_executing_substitution("${x:-$(id)}"));
    assert!(has_executing_substitution("`id`"));
    assert!(has_executing_substitution("<(id)"));
    assert!(has_executing_substitution(">(tee f)"));
    assert!(has_executing_substitution("$((1+$(id)))"));
}

#[test]
fn inert_expansions_are_not_executing_substitutions() {
    for inert in [
        "$OSTYPE",
        "${VAR%%.*}",
        "${VAR#pre}",
        "${#x}",
        "${!x}",
        "*.tar.gz",
        // Single quotes and a backslash both defuse the substitution.
        "'$(id)'",
        "\\$(id)",
        // `<(` is literal text inside double quotes, unlike `$(`.
        "\"<(id)\"",
        // A lone `$` or `<` with nothing to open a substitution.
        "$",
        "a<b",
    ] {
        assert!(
            !has_executing_substitution(inert),
            "{inert} executes nothing"
        );
    }
}

/// Resolution-time re-analysis builds synthetic words whose `value` is empty
/// while the substitution lives in `parts`, so the walk cannot lean on the text
/// scan alone.
#[test]
fn word_executes_command_follows_parts_not_just_text() {
    let substitution = Node::empty(NodeKind::CommandSubstitution {
        command: Box::new(Node::empty(NodeKind::WordLiteral {
            value: "id".to_string(),
        })),
        brace: false,
    });
    let synthetic = Node::empty(NodeKind::Word {
        value: String::new(),
        parts: vec![substitution],
        spans: vec![],
    });

    assert!(word_executes_command(&synthetic));
}

// Env-prefix stripping

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
    // #133: prefix on a pipeline's first command strips, rest verbatim.
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
    // Redirects must survive stripping (no new bypass path).
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
    // `NAME+=VALUE` must not bind to the RHS alone (bash concatenates).
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

#[test]
fn is_dangerous_env_name_flags_git_config_and_bash_func_families() {
    for name in [
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_CONFIG_PARAMETERS",
        "BASH_FUNC_foo%%",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "GIT_SSH_COMMAND",
    ] {
        assert!(is_dangerous_env_name(name), "{name} should be dangerous");
    }
}

#[test]
fn is_dangerous_env_name_allows_ordinary_names() {
    for name in ["FOO", "PATH", "HOME", "NODE_ENV", "CI", "RUST_LOG"] {
        assert!(!is_dangerous_env_name(name), "{name} should be safe");
    }
}
