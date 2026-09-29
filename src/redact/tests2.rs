//! Cases from the second coverage review: each kills a mutant the first test
//! file let through. Expected strings are observed output.

use super::words::{Rules, secret_ranges};
use super::*;

fn analyzer_with(vars: &[(&str, &str)]) -> crate::analyzer::Analyzer {
    let lookup = vars
        .iter()
        .fold(crate::resolve::tests::MockLookup::new(), |l, (n, v)| {
            l.with(n, v)
        });
    crate::analyzer::Analyzer::new_with_var_lookup(
        crate::config::Config::empty(),
        false,
        std::path::PathBuf::from("/project"),
        false,
        Box::new(lookup),
    )
    .unwrap()
}

#[test]
fn a_longer_value_is_scrubbed_before_one_it_contains() {
    let mut revealed = Revealed::default();
    revealed.record("A_TOKEN", "abcd");
    revealed.record("B_TOKEN", "abcdefgh");
    assert_eq!(
        revealed.show("echo abcdefgh abcd".to_owned()),
        format!("echo {REDACTED} {REDACTED}")
    );
}

#[test]
fn joined_fragments_and_plural_last_segments_mark_a_secret() {
    for name in ["AWS_ACCESS_KEY_ID", "SSH_PRIVATE_KEY_B64", "DEPLOY_KEYS"] {
        assert!(is_secret_name(name), "{name}");
    }
}

// `Revealed` is per command: a value one command revealed is not scrubbed
// from the next, and an unresolved command is shown as it was.
#[test]
fn a_new_command_forgets_what_the_last_one_revealed() {
    let mut analyzer = analyzer_with(&[("GH_TOKEN", "hunter2fakeplain"), ("NS", "prod")]);
    analyzer.analyze("somecli $GH_TOKEN").unwrap();
    assert_eq!(
        analyzer.analyze("tee $NS hunter2fakeplain").unwrap().reason,
        "redirect to hunter2fakeplain (resolved: tee prod hunter2fakeplain)"
    );
    analyzer.analyze("somecli $GH_TOKEN").unwrap();
    assert_eq!(
        analyzer.analyze("tee 'Bearer abcd1234'").unwrap().reason,
        "redirect to Bearer abcd1234"
    );
}

#[test]
fn a_phrase_inside_a_phrase_is_read_as_a_command_too() {
    assert_eq!(
        secrets("sh -c \"env -S 'TOKEN=abc12345 rm -rf /srv'\""),
        format!("sh -c \"env -S 'TOKEN={REDACTED} rm -rf /srv'\"")
    );
}

#[test]
fn every_auth_scheme_waits_for_its_credential() {
    for scheme in ["Basic", "Token", "Digest"] {
        assert_eq!(
            secrets(&format!(
                "curl -H 'Authorization: {scheme} s3cr3t-pw' https://x"
            )),
            format!("curl -H 'Authorization: {scheme} {REDACTED}' https://x")
        );
    }
}

#[test]
fn every_credential_program_row_is_read() {
    for (text, shown) in [
        ("sshpass -p s3cr3t-pw ssh host", "sshpass -p {R} ssh host"),
        ("sshpass -ps3cr3t-pw ssh host", "sshpass -p{R} ssh host"),
        ("curl -uadmin:s3cr3t-pw https://x", "curl -u{R} https://x"),
        ("mongosh -p s3cr3t-pw", "mongosh -p {R}"),
        ("mysql -p s3cr3t-pw", "mysql -p s3cr3t-pw"),
        (
            "docker login registry.example",
            "docker login registry.example",
        ),
    ] {
        assert_eq!(secrets(text), shown.replace("{R}", REDACTED), "{text}");
    }
}

#[test]
fn an_authorization_key_marks_the_next_word_in_every_spelling() {
    for text in [
        "curl -d '{\"Authorization\": \"s3cr3t-pw\"}' x",
        "curl -d '[\"Authorization:\", \"s3cr3t-pw\"]' x",
        "curl -H '\"Authorization\": \"Bearer\" s3cr3t-pw' https://x",
    ] {
        let out = secrets(text);
        assert!(!out.contains("s3cr3t-pw"), "{text}\n  -> {out}");
    }
}

#[test]
fn a_bare_secret_word_does_not_mark_the_next_one() {
    for text in [
        "gh secret list",
        "kubectl get secret app-tls",
        "npm token list",
    ] {
        assert_eq!(secrets(text), text);
    }
}

#[test]
fn hidden_keeps_the_shape_and_nulls() {
    let value = serde_json::json!({"password": [null, 1, {"a": "b"}]});
    assert_eq!(
        json(&value),
        serde_json::json!({"password": [null, REDACTED, {"a": REDACTED}]})
    );
}

#[test]
fn an_argv_array_hides_a_flag_value() {
    let value = serde_json::json!({"args": ["--password", "hunter2x", "--verbose", "x"]});
    assert_eq!(
        json(&value),
        serde_json::json!({"args": ["--password", REDACTED, "--verbose", "x"]})
    );
}

#[test]
fn an_open_quote_leaves_later_quoting_intact() {
    assert_eq!(
        secrets("echo it's; somecli \"--password hunter2x\""),
        format!("echo it's; somecli \"--password {REDACTED}\"")
    );
}

#[test]
fn history_reads_each_assignment_by_its_own_name() {
    for (text, shown) in [
        (
            "curl 'https://x.example/cb?client_secret=s3cr3t-pw&page=2'",
            "curl 'https://x.example/cb?client_secret={R}&page=2'",
        ),
        ("X_TOKEN=$'s3cr3t-pw' ./run", "X_TOKEN={R} ./run"),
        ("somecli --pw=s3cr3t-pw", "somecli --pw={R}"),
        (
            "somecli --password-file=./pw.txt",
            "somecli --password-file=./pw.txt",
        ),
        (
            "kubectl label pod web secrets.io/owner=team-a",
            "kubectl label pod web secrets.io/owner=team-a",
        ),
    ] {
        assert_eq!(secrets(text), shown.replace("{R}", REDACTED), "{text}");
    }
}

#[test]
fn single_dash_flags_count_by_a_strong_name_only() {
    for (text, shown) in [
        ("somecli -token s3cr3t-pw", "somecli -token {R}"),
        (
            "keytool -list -storepass s3cr3t-pw",
            "keytool -list -storepass {R}",
        ),
        ("somecli -password s3cr3t-pw", "somecli -password {R}"),
        ("find . -user root", "find . -user root"),
        (
            "openssl req -new -key server.key -out server.csr",
            "openssl req -new -key server.key -out server.csr",
        ),
    ] {
        assert_eq!(secrets(text), shown.replace("{R}", REDACTED), "{text}");
    }
}

#[test]
fn jev_strict_reads_openssl_pass_values_too() {
    let word = "pass:s3cr3t-pw";
    assert_eq!(
        secret_ranges(word, false, Rules::STRICT),
        vec![5..word.len()]
    );
}

#[test]
fn an_empty_quoted_value_is_left_alone() {
    for text in ["EMPTY_TOKEN='' ls", "X_TOKEN=\"\" y"] {
        assert_eq!(secrets(text), text);
    }
}

#[test]
fn a_path_tail_is_not_a_token_in_history() {
    let text = "ls /opt/builds/Release2026BuildArtifactsForWindowsX64";
    assert_eq!(secrets(text), text);
}
