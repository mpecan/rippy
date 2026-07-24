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

// ---- Scoped lookup: local + status-var bindings (issue #132) ----

fn scoped_words<'a>(
    source: &str,
    locals: &'a [(String, LocalBinding)],
    inner: &'a dyn VarLookup,
) -> (Vec<Node>, ScopedLookup<'a>) {
    (extract_words(source), ScopedLookup::new(locals, inner))
}

#[test]
fn resolve_status_var_is_set() {
    // `$?` / `$PIPESTATUS` are known-set with a dynamic value → DynamicKnown,
    // never Unresolvable "not set".
    let inner = MockLookup::new();
    let locals: Vec<(String, LocalBinding)> = Vec::new();
    let scoped = ScopedLookup::new(&locals, &inner);
    assert_eq!(
        resolve_word(&first_arg_node("echo $?"), &scoped),
        WordResolution::DynamicKnown
    );
    assert_eq!(
        resolve_word(&first_arg_node("echo $PIPESTATUS"), &scoped),
        WordResolution::DynamicKnown
    );
    assert_eq!(
        resolve_word(&first_arg_node("echo ${PIPESTATUS[0]}"), &scoped),
        WordResolution::DynamicKnown
    );
    assert_eq!(
        resolve_word(&first_arg_node("echo $1"), &scoped),
        WordResolution::DynamicKnown
    );
}

#[test]
fn resolve_literal_local_substitutes() {
    let inner = MockLookup::new();
    let locals = vec![(
        "SCRATCH".to_string(),
        LocalBinding::Literal("/tmp/x".into()),
    )];
    let scoped = ScopedLookup::new(&locals, &inner);
    assert_eq!(
        resolve_word(&first_arg_node("ls $SCRATCH"), &scoped),
        WordResolution::Literal("/tmp/x".to_string())
    );
}

#[test]
fn resolve_dynamic_local_is_dynamic_known() {
    let inner = MockLookup::new();
    let locals = vec![("f".to_string(), LocalBinding::Dynamic)];
    let scoped = ScopedLookup::new(&locals, &inner);
    assert_eq!(
        resolve_word(&first_arg_node("echo $f"), &scoped),
        WordResolution::DynamicKnown
    );
}

#[test]
fn resolve_scoped_falls_back_to_env() {
    // An unbound name still consults the inner lookup.
    let inner = MockLookup::new().with("HOME", "/home/me");
    let locals: Vec<(String, LocalBinding)> = Vec::new();
    let scoped = ScopedLookup::new(&locals, &inner);
    assert_eq!(
        resolve_word(&first_arg_node("ls $HOME"), &scoped),
        WordResolution::Literal("/home/me".to_string())
    );
}

#[test]
fn resolve_dynamic_known_sets_arg_flag() {
    let inner = MockLookup::new();
    let locals = vec![("f".to_string(), LocalBinding::Dynamic)];
    let (words, scoped) = scoped_words("wc -l $f", &locals, &inner);
    let result = resolve_command_args(&words, &scoped);
    assert!(result.arg_position_dynamic);
    assert!(!result.command_position_dynamic);
    assert!(result.args.is_none());
}

#[test]
fn resolve_dynamic_in_command_position_flags_command_dynamic() {
    let inner = MockLookup::new();
    let locals = vec![("c".to_string(), LocalBinding::Dynamic)];
    let (words, scoped) = scoped_words("$c arg", &locals, &inner);
    let result = resolve_command_args(&words, &scoped);
    assert!(result.command_position_dynamic);
    // A command-position dynamic is not an argument-position dynamic.
    assert!(!result.arg_position_dynamic);
    assert!(result.args.is_none());
}

#[test]
fn resolve_combine_propagates_dynamic_known() {
    // `pre$dyn` — a literal prefix concatenated with a dynamic value stays
    // DynamicKnown (never a fabricated literal).
    let inner = MockLookup::new();
    let locals = vec![("dyn".to_string(), LocalBinding::Dynamic)];
    let scoped = ScopedLookup::new(&locals, &inner);
    assert_eq!(
        resolve_word(&first_arg_node("echo pre$dyn"), &scoped),
        WordResolution::DynamicKnown
    );
}

#[test]
fn resolve_default_op_on_dynamic_local_is_dynamic_known() {
    // `${f:-def}` where `f` is set-but-unknown (loop var): the default operator
    // returns the (dynamic) value, so the result is DynamicKnown, not the default.
    let inner = MockLookup::new();
    let locals = vec![("f".to_string(), LocalBinding::Dynamic)];
    let scoped = ScopedLookup::new(&locals, &inner);
    assert_eq!(
        resolve_word(&first_arg_node("echo ${f:-def}"), &scoped),
        WordResolution::DynamicKnown
    );
    assert_eq!(
        resolve_word(&first_arg_node("echo ${f-def}"), &scoped),
        WordResolution::DynamicKnown
    );
}

#[test]
fn resolve_alt_op_on_dynamic_local_is_literal_alternate() {
    // `${f:+yes}` where `f` is set-but-unknown: the alternate comes from source
    // text, not the variable value, so a set (even dynamic) var yields the
    // literal alternate.
    let inner = MockLookup::new();
    let locals = vec![("f".to_string(), LocalBinding::Dynamic)];
    let scoped = ScopedLookup::new(&locals, &inner);
    assert_eq!(
        resolve_word(&first_arg_node("echo ${f:+yes}"), &scoped),
        WordResolution::Literal("yes".to_string())
    );
}

#[test]
fn resolve_command_args_unresolvable_wins_over_later_dynamic() {
    // A DynamicKnown arg BEFORE an unresolvable substitution must not stop the
    // scan: the unresolvable word still records a failure_reason so the caller
    // does not take the relaxed dynamic-arg allow path (issue #132 review).
    let inner = MockLookup::new();
    let locals = vec![("f".to_string(), LocalBinding::Dynamic)];
    let (words, scoped) = scoped_words("cat $f $(rm -rf /)", &locals, &inner);
    let result = resolve_command_args(&words, &scoped);
    assert!(result.arg_position_dynamic);
    assert!(result.failure_reason.is_some());
    assert!(result.args.is_none());
}

#[test]
fn resolve_unresolvable_wins_over_dynamic_in_word() {
    // A word mixing a dynamic part with an unresolvable part resolves to the
    // more conservative Unresolvable (forces Ask for even simple-safe commands).
    let inner = MockLookup::new();
    let locals = vec![("dyn".to_string(), LocalBinding::Dynamic)];
    let scoped = ScopedLookup::new(&locals, &inner);
    assert!(matches!(
        resolve_word(&first_arg_node("echo $dyn$(whoami)"), &scoped),
        WordResolution::Unresolvable { .. }
    ));
}

#[test]
fn is_status_var_matches_specials_and_positionals() {
    for name in [
        "?",
        "$",
        "#",
        "!",
        "-",
        "*",
        "@",
        "0",
        "9",
        "42",
        "PIPESTATUS",
        "RANDOM",
    ] {
        assert!(is_status_var(name), "{name} should be a status var");
    }
    assert!(is_status_var("PIPESTATUS[0]"));
    for name in ["HOME", "PATH", "f", ""] {
        assert!(!is_status_var(name), "{name} should not be a status var");
    }
}
