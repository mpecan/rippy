use super::*;
use crate::resolve::tests::MockLookup;
use crate::verdict::Decision;

fn make_analyzer() -> Analyzer {
    // Use an empty MockLookup so default tests are deterministic regardless
    // of the host environment.
    make_analyzer_with(MockLookup::new())
}

fn make_analyzer_with(lookup: MockLookup) -> Analyzer {
    // cwd is /project (not a safe dir) so relative redirect targets resolve
    // into the project and keep asking, while /tmp etc. are auto-approved.
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
fn simple_safe_command() {
    let mut a = make_analyzer();
    let v = a.analyze("ls -la").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn git_status_safe() {
    let mut a = make_analyzer();
    let v = a.analyze("git status").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn git_push_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("git push").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn rm_rf_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("rm -rf /").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn pipeline_safe() {
    let mut a = make_analyzer();
    let v = a.analyze("cat file.txt | grep pattern").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn pipeline_mixed() {
    let mut a = make_analyzer();
    let v = a.analyze("cat file.txt | rm -rf /tmp").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn redirect_to_dev_null() {
    let mut a = make_analyzer();
    let v = a.analyze("echo foo > /dev/null").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn redirect_to_file_asks() {
    // Relative target resolves under the /project cwd (not a safe dir) → Ask.
    let mut a = make_analyzer();
    let v = a.analyze("echo foo > output.txt").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

// ---- Safe-dir write redirects (#136) ----

#[test]
fn redirect_to_tmp_write_allows() {
    let mut a = make_analyzer();
    let v = a.analyze("echo foo > /tmp/out.txt").unwrap();
    // echo is safe and the /tmp redirect is auto-approved → overall Allow.
    // (The reason surfaces the dominant `echo is safe` verdict.)
    assert_eq!(v.decision, Decision::Allow, "{}", v.reason);
}

#[test]
fn redirect_append_private_tmp_allows() {
    let mut a = make_analyzer();
    let v = a.analyze("echo foo >> /private/tmp/x/log").unwrap();
    assert_eq!(v.decision, Decision::Allow, "{}", v.reason);
}

#[test]
fn redirect_to_etc_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("echo foo > /etc/passwd").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn redirect_dotdot_escape_asks() {
    // Traversal that escapes /tmp collapses to /etc/passwd before the check.
    let mut a = make_analyzer();
    let v = a.analyze("echo foo > /tmp/../etc/passwd").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn redirect_dynamic_target_asks() {
    let mut a = make_analyzer_with(MockLookup::new().with("VAR", "/tmp/x"));
    for cmd in [
        "echo foo > $HOME/x",
        "echo foo > ~/x",
        "echo foo > \"$VAR\"",
    ] {
        let v = a.analyze(cmd).unwrap();
        assert_eq!(v.decision, Decision::Ask, "{cmd} -> {}", v.reason);
    }
}

#[test]
fn redirect_component_boundary_asks() {
    // /tmpevil shares a string prefix with /tmp but is a different component.
    let mut a = make_analyzer();
    let v = a.analyze("echo foo > /tmpevil/x").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn pipeline_redirect_to_tmp_allows() {
    let mut a = make_analyzer();
    let v = a.analyze("cat f | grep x > /tmp/out").unwrap();
    assert_eq!(v.decision, Decision::Allow, "{}", v.reason);
}

#[test]
fn unsafe_cmd_with_safe_redirect_still_asks() {
    // The redirect target is safe, but the left-hand command is not: combine
    // keeps the most-restrictive decision.
    let mut a = make_analyzer();
    let v = a.analyze("rm -rf / > /tmp/out").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

// ---- `&>` / `>&` (FdDup) redirects run the write-safety pipeline (#136) ----

#[test]
fn fd_dup_to_descriptor_allows() {
    // Real fd duplications / closes are harmless and stay allowed.
    let mut a = make_analyzer();
    for cmd in ["echo x 2>&1", "echo x >&2", "true 1>&2"] {
        let v = a.analyze(cmd).unwrap();
        assert_eq!(v.decision, Decision::Allow, "{cmd} -> {}", v.reason);
    }
}

#[test]
fn fd_dup_to_dev_null_allows() {
    let mut a = make_analyzer();
    let v = a.analyze("echo x &> /dev/null").unwrap();
    assert_eq!(v.decision, Decision::Allow, "{}", v.reason);
}

#[test]
fn fd_dup_to_unsafe_file_asks() {
    // `&> file` / `>& file` are *file writes*, not fd dups: they must not
    // bypass the safe-dir check just because rable parses them as FdDup.
    let mut a = make_analyzer();
    for cmd in ["echo x &> /etc/all.log", "echo secret >& /etc/passwd"] {
        let v = a.analyze(cmd).unwrap();
        assert_eq!(v.decision, Decision::Ask, "{cmd} -> {}", v.reason);
    }
}

#[test]
fn fd_dup_to_safe_dir_allows() {
    let mut a = make_analyzer();
    let v = a.analyze("echo x &> /tmp/all.log").unwrap();
    assert_eq!(v.decision, Decision::Allow, "{}", v.reason);
}

#[test]
fn fd_dup_to_self_protected_denies() {
    // `>& .rippy` must still hit self-protection, not the "fd redirect" allow.
    let mut a = Analyzer::new_with_var_lookup(
        Config::from_directives(vec![]),
        false,
        PathBuf::from("/project"),
        false,
        Box::new(MockLookup::new()),
    )
    .unwrap();
    assert!(a.config.self_protect);
    let v = a.analyze("echo x >& .rippy").unwrap();
    assert_eq!(v.decision, Decision::Deny, "{}", v.reason);
}

// ---- self-protection wins over safe-dir auto-approval (#136) ----

#[test]
fn self_protected_config_in_safe_dir_denies() {
    // A self-protected config file whose redirect target lands inside a safe
    // dir must still DENY: self_protect is checked before the safe-dir approve.
    let mut a = Analyzer::new_with_var_lookup(
        Config::from_directives(vec![]),
        false,
        PathBuf::from("/project"),
        false,
        Box::new(MockLookup::new()),
    )
    .unwrap();
    let v = a.analyze("echo x > /tmp/.rippy").unwrap();
    assert_eq!(v.decision, Decision::Deny, "{}", v.reason);
}

#[test]
fn self_protected_config_in_declared_scope_denies() {
    use crate::config::ConfigDirective;
    let config = Config::from_directives(vec![ConfigDirective::SafeScope(PathBuf::from(
        "/opt/repos",
    ))]);
    let mut a = Analyzer::new_with_var_lookup(
        config,
        false,
        PathBuf::from("/project"),
        false,
        Box::new(MockLookup::new()),
    )
    .unwrap();
    let v = a.analyze("echo x > /opt/repos/other/.rippy.toml").unwrap();
    assert_eq!(v.decision, Decision::Deny, "{}", v.reason);
}

// ---- glob-metacharacter targets keep asking (#136) ----

#[test]
fn redirect_glob_target_asks() {
    let mut a = make_analyzer();
    for cmd in [
        "echo foo > /tmp/*",
        "echo foo > /tmp/foo[1]",
        "echo foo > /tmp/foo?",
    ] {
        let v = a.analyze(cmd).unwrap();
        assert_eq!(v.decision, Decision::Ask, "{cmd} -> {}", v.reason);
    }
}

// ---- pipeline with an UNSAFE redirect still asks (#136) ----

#[test]
fn pipeline_redirect_to_unsafe_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("cat f | grep x > /etc/out").unwrap();
    assert_eq!(v.decision, Decision::Ask, "{}", v.reason);
}

// ---- project writes keep asking even when cwd lives under a safe dir (#136) ----

#[test]
fn redirect_into_cwd_under_safe_dir_asks() {
    // The checkout itself lives under /tmp; project-relative and absolute
    // writes into it must keep asking, not silently auto-approve.
    let mut a = Analyzer::new_with_var_lookup(
        Config::empty(),
        false,
        PathBuf::from("/tmp/checkout"),
        false,
        Box::new(MockLookup::new()),
    )
    .unwrap();
    for cmd in [
        "echo pwned > src/main.rs",
        "echo pwned > /tmp/checkout/src/main.rs",
    ] {
        let v = a.analyze(cmd).unwrap();
        assert_eq!(v.decision, Decision::Ask, "{cmd} -> {}", v.reason);
    }
    // A sibling target outside the checkout is still auto-approved.
    let v = a.analyze("echo x > /tmp/other.txt").unwrap();
    assert_eq!(v.decision, Decision::Allow, "{}", v.reason);
}

// ---- symlink planted in a world-writable safe dir cannot escape (#136) ----

#[cfg(unix)]
#[test]
fn redirect_through_symlink_out_of_safe_dir_asks() {
    use std::os::unix::fs::symlink;

    // A unique real directory directly under /tmp (a default safe dir).
    let uniq = format!(
        "rippy_symtest_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let base = std::path::Path::new("/tmp").join(&uniq);
    std::fs::create_dir_all(&base).unwrap();
    // A symlink inside the safe dir that points OUT of the safe set (/etc).
    let escape = base.join("escape");
    symlink("/etc", &escape).unwrap();
    // A plain (non-symlink) sibling dir that stays inside the safe dir.
    let inside = base.join("inside");
    std::fs::create_dir_all(&inside).unwrap();

    let mut a = make_analyzer();

    // Through the symlink the real target is /etc/hosts → must ask.
    let via_symlink = format!("echo pwned > {}/hosts", escape.display());
    let v = a.analyze(&via_symlink).unwrap();
    let escape_decision = v.decision;

    // A genuine write staying inside the safe dir is still auto-approved.
    let via_real = format!("echo ok > {}/out.txt", inside.display());
    let v2 = a.analyze(&via_real).unwrap();
    let inside_decision = v2.decision;

    // Best-effort cleanup before asserting.
    let _ = std::fs::remove_dir_all(&base);

    assert_eq!(escape_decision, Decision::Ask, "symlink escape must ask");
    assert_eq!(
        inside_decision,
        Decision::Allow,
        "genuine in-safe-dir write must allow"
    );
}

#[test]
fn wrapper_command_analyzes_inner() {
    let mut a = make_analyzer();
    let v = a.analyze("time git status").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn wrapper_command_unsafe_inner() {
    let mut a = make_analyzer();
    let v = a.analyze("time git push").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn command_substitution_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("echo $(rm -rf /)").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn shell_c_recurses() {
    let mut a = make_analyzer();
    let v = a.analyze("bash -c 'git status'").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn shell_c_unsafe() {
    let mut a = make_analyzer();
    let v = a.analyze("bash -c 'rm -rf /'").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn config_override_allows() {
    use crate::config::{ConfigDirective, Rule, RuleTarget};

    let config = Config::from_directives(vec![ConfigDirective::Rule(
        Rule::new(RuleTarget::Command, Decision::Allow, "rm -rf /tmp")
            .with_message("cleanup allowed"),
    )]);
    let mut a = Analyzer::new(config, false, PathBuf::from("/tmp"), false).unwrap();
    let v = a.analyze("rm -rf /tmp").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn help_flag_always_safe() {
    let mut a = make_analyzer();
    let v = a.analyze("npm --help").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn list_and() {
    let mut a = make_analyzer();
    let v = a.analyze("ls && echo done").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn unknown_command_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("some_unknown_tool --flag").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn depth_limit_exceeded() {
    let mut a = make_analyzer();
    let nodes = a.parser.parse("echo ok").unwrap();
    let v = a.analyze_node(&nodes[0], Path::new("/tmp"), MAX_DEPTH + 1);
    assert_eq!(v.decision, Decision::Ask);
    assert!(v.reason.contains("nesting depth exceeded"));
}

#[test]
fn depth_at_max_still_works() {
    let mut a = make_analyzer();
    let nodes = a.parser.parse("echo ok").unwrap();
    let v = a.analyze_node(&nodes[0], Path::new("/tmp"), MAX_DEPTH - 2);
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn subshell_safe_allows() {
    let mut a = make_analyzer();
    let v = a.analyze("(echo ok)").unwrap();
    assert_eq!(v.decision, Decision::Allow); // subshell is transparent
}

#[test]
fn heredoc_safe_allows() {
    let mut a = make_analyzer();
    let v = a.analyze("cat <<EOF\nhello world\nEOF").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn heredoc_quoted_delimiter_allows_even_with_expansion_syntax() {
    let mut a = make_analyzer();
    let v = a.analyze("cat <<'EOF'\n$(rm -rf /)\nEOF").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn nested_substitution_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("echo $(echo $(whoami))").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn complex_pipeline_all_safe() {
    let mut a = make_analyzer();
    let v = a.analyze("cat file | grep pattern | head -5").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn if_statement_safe() {
    let mut a = make_analyzer();
    let v = a.analyze("if true; then echo yes; fi").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn if_statement_unsafe_body() {
    let mut a = make_analyzer();
    let v = a.analyze("if true; then rm -rf /; fi").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn for_loop_unsafe() {
    let mut a = make_analyzer();
    let v = a.analyze("for i in 1 2 3; do rm -rf /; done").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn empty_command_allows() {
    let mut a = make_analyzer();
    let v = a.analyze("").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn case_statement() {
    let mut a = make_analyzer();
    let v = a.analyze("case x in a) echo yes;; esac").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn cc_allow_rule_overrides_handler() {
    let dir = tempfile::tempdir().unwrap();
    let claude_dir = dir.path().join(".claude");
    std::fs::create_dir(&claude_dir).unwrap();
    std::fs::write(
        claude_dir.join("settings.local.json"),
        r#"{"permissions": {"allow": ["Bash(git push)"]}}"#,
    )
    .unwrap();
    let mut a = Analyzer::new(Config::empty(), false, dir.path().to_path_buf(), false).unwrap();
    let v = a.analyze("git push origin main").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn cc_deny_rule_overrides_handler() {
    let dir = tempfile::tempdir().unwrap();
    let claude_dir = dir.path().join(".claude");
    std::fs::create_dir(&claude_dir).unwrap();
    std::fs::write(
        claude_dir.join("settings.json"),
        r#"{"permissions": {"deny": ["Bash(ls)"]}}"#,
    )
    .unwrap();
    let mut a = Analyzer::new(Config::empty(), false, dir.path().to_path_buf(), false).unwrap();
    let v = a.analyze("ls").unwrap();
    assert_eq!(v.decision, Decision::Deny);
}

#[test]
fn cc_rules_checked_before_rippy_config() {
    use crate::config::{ConfigDirective, Rule, RuleTarget};

    let dir = tempfile::tempdir().unwrap();
    let claude_dir = dir.path().join(".claude");
    std::fs::create_dir(&claude_dir).unwrap();
    std::fs::write(
        claude_dir.join("settings.local.json"),
        r#"{"permissions": {"allow": ["Bash(rm -rf /tmp)"]}}"#,
    )
    .unwrap();

    let config = Config::from_directives(vec![ConfigDirective::Rule(
        Rule::new(RuleTarget::Command, Decision::Ask, "rm -rf /tmp").with_message("dangerous"),
    )]);
    let mut a = Analyzer::new(config, false, dir.path().to_path_buf(), false).unwrap();
    let v = a.analyze("rm -rf /tmp").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn pipeline_with_file_redirect_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("cat file | grep pattern > out.txt").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn pipeline_with_dev_null_allows() {
    let mut a = make_analyzer();
    let v = a.analyze("ls | grep foo > /dev/null").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn pipeline_mid_redirect_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("echo hello > file.txt | cat").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn subshell_unsafe_propagates() {
    let mut a = make_analyzer();
    let v = a.analyze("(rm -rf /)").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn subshell_with_redirect_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("(echo ok) > file.txt").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn or_true_uses_cmd_verdict() {
    let mut a = make_analyzer();
    let v = a.analyze("git push || true").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn safe_cmd_or_true_allows() {
    let mut a = make_analyzer();
    let v = a.analyze("ls || true").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn or_colon_uses_cmd_verdict() {
    let mut a = make_analyzer();
    let v = a.analyze("ls || :").unwrap();
    assert_eq!(v.decision, Decision::Allow);
}

#[test]
fn or_with_unsafe_fallback_combines() {
    let mut a = make_analyzer();
    let v = a.analyze("ls || rm -rf /").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn and_combines_normally() {
    let mut a = make_analyzer();
    let v = a.analyze("ls && git push").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn command_substitution_floor_is_ask() {
    let mut a = make_analyzer();
    let v = a.analyze("echo $(ls)").unwrap();
    // Even though ls is safe, command substitution has an Ask floor
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn or_harmless_fallback_with_redirect_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("ls || echo fail > log.txt").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

// ---- Expansion resolution tests ----

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

// ---- Heredoc tests (resolution NOT in scope for heredocs in this PR) ----

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

// ---- Tests for unresolvable expansions (still Ask) ----

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
    // Command substitution can never be resolved statically.
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

// ---- Resolution that triggers handler-side Ask ----

#[test]
fn rm_with_resolved_arg_still_asks_via_handler() {
    let mut a = make_analyzer_with(MockLookup::new().with("TARGET", "/tmp/file"));
    let v = a.analyze("rm $TARGET").unwrap();
    // rm always asks via the handler, regardless of arg
    assert_eq!(v.decision, Decision::Ask);
    // But the verdict carries the resolved form
    assert_eq!(v.resolved_command.as_deref(), Some("rm /tmp/file"));
}

// ---- Command-position protection ----

#[test]
fn dynamic_command_position_asks_even_when_resolved() {
    // `$cmd args` with cmd=ls would normally allow ls, but command-position
    // dynamic execution is always Ask regardless of resolution.
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

// ---- Handler-path resolution ----

#[test]
fn handler_path_resolves_quoted_subcommand() {
    // `git $'status'` should resolve to `git status` and let the git handler
    // classify it normally (status is safe).
    let mut a = make_analyzer();
    let v = a.analyze("git $'status'").unwrap();
    assert_eq!(v.decision, Decision::Allow);
    assert_eq!(v.resolved_command.as_deref(), Some("git status"));
}

// ---- Default with literal ----

#[test]
fn param_default_resolves_when_unset() {
    let mut a = make_analyzer();
    let v = a.analyze("echo ${UNSET:-default}").unwrap();
    assert_eq!(v.decision, Decision::Allow);
    assert_eq!(v.resolved_command.as_deref(), Some("echo default"));
}

// ---- Safety: variable values containing shell metacharacters ----

#[test]
fn var_value_with_command_substitution_stays_literal() {
    // If a variable's value LOOKS like command substitution (`$(whoami)`),
    // shell_join_arg must single-quote it so the re-parsed command sees a
    // literal string, not an expansion. echo is safe regardless of arg
    // content, so this should Allow with the value treated as data.
    let mut a = make_analyzer_with(MockLookup::new().with("CMD_STR", "$(whoami)"));
    let v = a.analyze("echo $CMD_STR").unwrap();
    assert_eq!(
        v.decision,
        Decision::Allow,
        "echo with literal-looking command sub should allow, got: {v:?}"
    );
    // The resolved form quotes the value to keep it literal.
    assert_eq!(v.resolved_command.as_deref(), Some("echo '$(whoami)'"));
}

#[test]
fn var_value_with_dangerous_command_string_still_safe_for_echo() {
    // The killer test for the "content drives the verdict" claim:
    // a variable holding what LOOKS like `rm -rf /` is just a string when
    // passed to echo. echo is safe; the value is data, not execution.
    let mut a = make_analyzer_with(MockLookup::new().with("CMD_STR", "rm -rf /"));
    let v = a.analyze("echo $CMD_STR").unwrap();
    assert_eq!(v.decision, Decision::Allow);
    // The dangerous-looking string is single-quoted in the resolved form
    // so it's parsed as a single literal arg.
    assert_eq!(v.resolved_command.as_deref(), Some("echo 'rm -rf /'"));
}

#[test]
fn var_value_with_backticks_stays_literal() {
    // Similar to command sub: `\`whoami\`` in a variable value should
    // become a quoted literal arg, not a re-evaluated substitution.
    let mut a = make_analyzer_with(MockLookup::new().with("X", "`whoami`"));
    let v = a.analyze("echo $X").unwrap();
    assert_eq!(v.decision, Decision::Allow);
    assert_eq!(v.resolved_command.as_deref(), Some("echo '`whoami`'"));
}

// ---- Safety limits ----

#[test]
fn huge_brace_expansion_falls_back_to_ask() {
    // {1..100000} would produce 100k items; brace expansion is capped
    // at MAX_BRACE_EXPANSION (1024), so this returns Unresolvable → Ask.
    let mut a = make_analyzer();
    let v = a.analyze("echo {1..100000}").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn cartesian_brace_explosion_falls_back_to_ask() {
    // {1..32}{1..32}{1..32} = 32k items, well over the cap.
    let mut a = make_analyzer();
    let v = a.analyze("echo {1..32}{1..32}{1..32}").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn safe_heredoc_in_command_substitution_allows() {
    let mut a = make_analyzer();
    // $(cat <<'EOF' ... EOF) is a safe data-passing idiom — cat is SIMPLE_SAFE,
    // quoted delimiter prevents expansion, and echo is also safe.
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
    // git commit -m is Ask (git handler policy), but the heredoc substitution
    // should resolve rather than failing as "command substitution requires execution".
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
fn variable_value_containing_dollar_is_not_re_expanded() {
    // bash does NOT recursively expand variable values, and neither do we:
    // A="$B" stores the literal string "$B", not the expansion of $B.
    // When `echo $A` resolves, the result is `echo '$B'` — the value is
    // single-quoted in the resolved form so it stays literal, and the
    // re-parse sees a quoted string with no expansions to follow.
    let mut a = make_analyzer_with(MockLookup::new().with("A", "$B").with("B", "actual"));
    let v = a.analyze("echo $A").unwrap();
    assert_eq!(v.decision, Decision::Allow);
    // The literal `$B` ends up single-quoted to prevent re-expansion.
    assert_eq!(v.resolved_command.as_deref(), Some("echo '$B'"));
}
