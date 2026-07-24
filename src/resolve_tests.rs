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
    extract_words(source).into_iter().nth(1).unwrap()
}

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
    let node = first_arg_node("ls {a,b}{c,d}");
    let lookup = MockLookup::new();
    assert_eq!(
        resolve_word(&node, &lookup),
        WordResolution::Multiple(vec!["ac".into(), "ad".into(), "bc".into(), "bd".into(),])
    );
}

#[test]
fn resolve_three_adjacent_brace_expansions() {
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

#[test]
fn command_substitution_unresolvable() {
    let node = first_arg_node("echo $(whoami)");
    let lookup = MockLookup::new();
    assert!(matches!(
        resolve_word(&node, &lookup),
        WordResolution::Unresolvable { .. }
    ));
}

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
    assert_eq!(strip_outer_quotes("'hello\""), "'hello\"");
    assert_eq!(strip_outer_quotes("\"hello'"), "\"hello'");
}

#[test]
fn strip_outer_quotes_only_left_unchanged() {
    assert_eq!(strip_outer_quotes("'hello"), "'hello");
    assert_eq!(strip_outer_quotes("hello'"), "hello'");
}

#[test]
fn strip_outer_quotes_empty_string() {
    assert_eq!(strip_outer_quotes(""), "");
}

#[test]
fn strip_outer_quotes_single_char_unchanged() {
    assert_eq!(strip_outer_quotes("'"), "'");
    assert_eq!(strip_outer_quotes("\""), "\"");
}

#[test]
fn strip_outer_quotes_just_quote_pair() {
    assert_eq!(strip_outer_quotes("''"), "");
    assert_eq!(strip_outer_quotes("\"\""), "");
}

#[test]
fn env_lookup_returns_set_var() {
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

fn scoped_words<'a>(
    source: &str,
    locals: &'a [(String, LocalBinding)],
    inner: &'a dyn VarLookup,
) -> (Vec<Node>, ScopedLookup<'a>) {
    (extract_words(source), ScopedLookup::new(locals, inner))
}

#[test]
fn resolve_status_var_is_set() {
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
    assert!(!result.arg_position_dynamic);
    assert!(result.args.is_none());
}

#[test]
fn resolve_combine_propagates_dynamic_known() {
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

fn assert_expansion_unresolvable(src: &str, lookup: &MockLookup) {
    match resolve_word(&first_arg_node(src), lookup) {
        WordResolution::Unresolvable { reason } => {
            assert!(reason.contains("shell expansion"), "{src}: got {reason}");
        }
        other => panic!("{src}: expected Unresolvable, got {other:?}"),
    }
}

fn assert_literal(src: &str, lookup: &MockLookup, want: &str) {
    assert_eq!(
        resolve_word(&first_arg_node(src), lookup),
        WordResolution::Literal(want.to_string())
    );
}

// ${VAR:-x}/${VAR-x}/${VAR:+x} default/alternate text and $"..." locale inner are
// re-expanded by bash at runtime, so embedded $(...)/backtick must NOT resolve to
// an inert Literal (which would re-analyze as harmless) — they Ask instead (#156).
#[test]
fn reexpanded_text_with_substitution_is_unresolvable() {
    let unset = MockLookup::new();
    assert_expansion_unresolvable("cat ${U:-$(id)}", &unset);
    assert_expansion_unresolvable("cat ${U-$(id)}", &unset);
    assert_expansion_unresolvable("echo ${U:-`id`}", &unset);
    assert_expansion_unresolvable("echo $\"$(id)\"", &unset);
    assert_expansion_unresolvable("cat ${FOO:+$(id)}", &MockLookup::new().with("FOO", "1"));
}

#[test]
fn reexpanded_plain_text_stays_literal() {
    let unset = MockLookup::new();
    assert_literal("cat ${U:-safe}", &unset, "safe");
    assert_literal("echo $\"plain\"", &unset, "plain");
    assert_literal("cat ${FOO:+ok}", &MockLookup::new().with("FOO", "1"), "ok");
}

// A SET variable's value is NOT re-expanded by bash, so a Value(v) holding `$(id)`
// must stay a verbatim Literal — guards against an over-broad fix (#156).
#[test]
fn set_var_value_containing_expansion_stays_verbatim() {
    assert_literal(
        "cat ${V:-x}",
        &MockLookup::new().with("V", "$(id)"),
        "$(id)",
    );
}

// Scoped to all-unset so the legitimate Value(v)-verbatim path never fires (#156).
#[test]
fn no_unset_default_resolves_to_expansion_bearing_literal() {
    let lookup = MockLookup::new();
    for src in [
        "cat ${U:-$(id)}",
        "cat ${U-$(id)}",
        "echo ${U:-`id`}",
        "cat ${U:+$(id)}",
        "cat ${U:-${V:-$(id)}}",
        "echo $\"$(id)\"",
        "echo ${U:-$HOME}",
    ] {
        if let WordResolution::Literal(s) = resolve_word(&first_arg_node(src), &lookup) {
            assert!(
                !crate::ast::has_shell_expansion_pattern(&s),
                "{src} leaked expansion literal {s:?}"
            );
        }
    }
}
