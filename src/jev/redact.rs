//! The secret-looking parts of one word of a command, for redaction before it
//! is sent. Best effort by nature: it covers the common shapes, and
//! docs/jev.md#threat-model says so.

use std::ops::Range;

/// Flag names whose value is a credential. Long flags match by substring.
const SECRET_FLAG_PARTS: &[&str] = &[
    "token",
    "secret",
    "password",
    "passwd",
    "pass",
    "api-key",
    "apikey",
    "auth",
    "key",
    "credential",
    "cookie",
    "user",
    "pw",
];

/// Short flags whose value is commonly a credential (`-u user:pass`, `-p pw`).
const SECRET_SHORT_FLAGS: &[&str] = &["-u", "-p", "-P"];

/// Provider token prefixes.
const TOKEN_PREFIXES: &[&str] = &[
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "github_pat_",
    "glpat-",
    "sk-",
    "sk_live_",
    "rk_live_",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "AKIA",
    "ASIA",
    "npm_",
    "hf_",
];

/// Header or scheme markers after which the rest of the word is a credential.
const CREDENTIAL_MARKERS: &[&str] = &[
    "bearer ",
    "basic ",
    "token ",
    "authorization:",
    "api-key:",
    "x-api-key:",
    "cookie:",
    "token:",
];

/// Parts of an operand name (`api_key=…`, `token=…`) that mark a credential.
const SECRET_NAME_PARTS: &[&str] = &[
    "token",
    "secret",
    "password",
    "passwd",
    "api_key",
    "apikey",
    "api-key",
    "auth",
    "credential",
    "pw",
];

/// URL query parameters whose value is a credential.
const SECRET_PARAMS: &[&str] = &[
    "token",
    "access_token",
    "api_key",
    "apikey",
    "key",
    "secret",
    "password",
    "pass",
    "sig",
    "signature",
    "auth",
    "code",
];

/// Whether `word` is a flag whose next word is a credential.
pub(super) fn is_secret_flag(word: &str) -> bool {
    if !word.starts_with('-') || word.contains('=') {
        return false;
    }
    if SECRET_SHORT_FLAGS.contains(&word) {
        return true;
    }
    let lower = word.to_ascii_lowercase();
    word.starts_with("--") && SECRET_FLAG_PARTS.iter().any(|k| lower.contains(k))
}

/// Byte ranges of `word` to redact. `after_secret_flag` means the previous
/// word was a flag like `--token`, so this word is its value.
pub(super) fn secret_ranges(word: &str, after_secret_flag: bool) -> Vec<Range<usize>> {
    let whole = 0..word.len();
    if after_secret_flag && !word.starts_with('-') {
        return vec![whole];
    }
    // An expansion's value is never part of the text, and its operators
    // (`${X:-y}`) must not be mistaken for credential markers.
    if word.starts_with('$') && !word.starts_with("$'") {
        return Vec::new();
    }
    let lead = word.len() - word.trim_start_matches(['"', '\'']).len();
    let bare = word.trim_matches(['"', '\'']);
    if is_token(bare) || is_jwt(bare) || bare.rsplit('/').next().is_some_and(is_token) {
        return vec![whole];
    }
    let start = attached_short_value(bare)
        .or_else(|| spaced_flag_value(bare))
        .or_else(|| value_start(bare))
        .or_else(|| credential_marker_end(bare));
    if let Some(start) = start.map(|s| lead + s) {
        // A value that opens its own quoting runs to the end of the word.
        let end = if word[start..].starts_with(['\'', '"', '$']) {
            word.len()
        } else {
            unquoted_end(word)
        };
        let value = start..end;
        return vec![value];
    }
    let mut ranges: Vec<Range<usize>> = url_userinfo(word).into_iter().collect();
    ranges.extend(secret_url_params(word));
    ranges
}

/// `-pVALUE`, `-uVALUE` → where `VALUE` starts.
fn attached_short_value(word: &str) -> Option<usize> {
    SECRET_SHORT_FLAGS
        .iter()
        .find(|f| word.len() > f.len() && word.starts_with(**f) && !word.starts_with("--"))
        .map(|f| f.len())
}

/// A whole flag and value quoted as one word (`'--password abc'`).
fn spaced_flag_value(word: &str) -> Option<usize> {
    let (flag, rest) = word.split_once(' ')?;
    (is_secret_flag(flag) && !rest.trim().is_empty()).then(|| flag.len() + 1)
}

/// `--token=VALUE`, `API_TOKEN=VALUE` or `api_key=VALUE` → where `VALUE`
/// starts. Other lowercase `name=value` operands (`dd of=…`) are left alone:
/// their value tells a reviewer what the command touches.
fn value_start(word: &str) -> Option<usize> {
    let eq = word.find('=')?;
    let name = &word[..eq];
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
    {
        return None;
    }
    let env_style = name.starts_with(|c: char| c.is_ascii_uppercase() || c == '_')
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    let lower = name.to_ascii_lowercase();
    let secret_name = SECRET_NAME_PARTS.iter().any(|p| lower.contains(p));
    let secret = env_style || secret_name || is_secret_flag(name);
    (secret && eq + 1 < word.len()).then_some(eq + 1)
}

/// The end of a credential marker (`Bearer `, `Authorization:`) that starts at
/// a word boundary, so `${MY_TOKEN:-x}` is not read as `token:`.
fn credential_marker_end(word: &str) -> Option<usize> {
    let lower = word.to_ascii_lowercase();
    let at_boundary =
        |i: usize| i == 0 || !lower[..i].ends_with(|c: char| c.is_ascii_alphanumeric() || c == '_');
    let end = CREDENTIAL_MARKERS
        .iter()
        .flat_map(|m| lower.match_indices(m).map(move |(i, _)| (i, m.len())))
        .filter(|(i, _)| at_boundary(*i))
        .map(|(i, len)| i + len)
        .max()?;
    let end = end + word[end..].len() - word[end..].trim_start().len();
    (end < word.len()).then_some(end)
}
fn unquoted_end(word: &str) -> usize {
    word.trim_end_matches(['"', '\'']).len()
}

fn is_token(word: &str) -> bool {
    if word.len() >= 16 && TOKEN_PREFIXES.iter().any(|p| word.starts_with(p)) {
        return true;
    }
    let opaque = word
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_' | '-'));
    let mixed =
        word.chars().any(|c| c.is_ascii_digit()) && word.chars().any(|c| c.is_ascii_alphabetic());
    word.len() >= 32
        && opaque
        && mixed
        && !word.starts_with(['/', '.', '-'])
        && !word.contains("//")
}

/// A JSON Web Token: three base64url segments, the first a JSON header.
fn is_jwt(word: &str) -> bool {
    let parts: Vec<&str> = word.split('.').collect();
    parts.len() == 3
        && word.starts_with("eyJ")
        && parts.iter().all(|p| {
            p.len() >= 4
                && p.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        })
}

/// `https://user:pass@host` → the range of `user:pass`. The last `@` in the
/// authority ends the userinfo, since a password may itself contain `@`.
fn url_userinfo(word: &str) -> Option<Range<usize>> {
    let scheme_end = word.find("://")? + 3;
    let rest = &word[scheme_end..];
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let at = rest[..authority_end].rfind('@')?;
    (at > 0).then(|| scheme_end..scheme_end + at)
}

/// Values of credential-named parameters in a URL's query or fragment.
fn secret_url_params(word: &str) -> Vec<Range<usize>> {
    let Some(scheme) = word.find("://") else {
        return Vec::new();
    };
    let end = unquoted_end(word);
    let mut ranges = Vec::new();
    for marker in ['?', '#'] {
        let Some(start) = word[scheme..end].find(marker).map(|i| scheme + i + 1) else {
            continue;
        };
        let stop = word[start..end].find(['#', '?']).map_or(end, |i| start + i);
        let mut offset = start;
        for pair in word[start..stop].split('&') {
            if let Some((name, value)) = pair.split_once('=')
                && !value.is_empty()
                && SECRET_PARAMS.contains(&name.to_ascii_lowercase().as_str())
            {
                let value_start = offset + name.len() + 1;
                ranges.push(value_start..value_start + value.len());
            }
            offset += pair.len() + 1;
        }
    }
    ranges
}
#[cfg(test)]
mod tests {
    use super::*;

    fn redact(word: &str, after_flag: bool) -> String {
        let mut out = word.to_owned();
        let mut ranges = secret_ranges(word, after_flag);
        ranges.sort_by_key(|r| std::cmp::Reverse(r.start));
        for r in ranges {
            out.replace_range(r, "<r>");
        }
        out
    }

    #[test]
    fn flag_values_are_redacted() {
        assert_eq!(redact("--token=hunter2", false), "--token=<r>");
        assert_eq!(redact("--db-password=x", false), "--db-password=<r>");
        assert_eq!(redact("hunter2/x", true), "<r>");
        assert!(is_secret_flag("-u") && is_secret_flag("-p") && is_secret_flag("--api-key"));
        assert!(!is_secret_flag("-v") && !is_secret_flag("--format"));
    }

    #[test]
    fn environment_style_assignments_are_redacted_operands_are_not() {
        assert_eq!(redact("GITHUB_TOKEN=abc123", false), "GITHUB_TOKEN=<r>");
        assert_eq!(redact("API_KEY=\"a b\"", false), "API_KEY=<r>");
        assert_eq!(redact("of=/dev/sda", false), "of=/dev/sda");
        assert_eq!(redact("EMPTY=", false), "EMPTY=");
    }

    #[test]
    fn credential_headers_are_redacted() {
        assert_eq!(
            redact("\"Authorization: Bearer abcdef123\"", false),
            "\"Authorization: Bearer <r>\""
        );
        assert_eq!(
            redact("--header=X-Api-Key: k1", false),
            "--header=X-Api-Key: <r>"
        );
        assert_eq!(redact("Cookie:session=abc", false), "Cookie:<r>");
    }

    #[test]
    fn tokens_and_jwts_are_redacted_whole() {
        assert_eq!(
            redact("ghp_0123456789abcdefghijABCDEFGHIJ012345", false),
            "<r>"
        );
        assert_eq!(
            redact("./ghp_0123456789abcdefghijABCDEFGHIJ012345", false),
            "<r>"
        );
        assert_eq!(
            redact("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl", false),
            "<r>"
        );
        assert_eq!(
            redact("production-cluster-eu-west-1", false),
            "production-cluster-eu-west-1"
        );
    }

    // Verification-pass findings.
    #[test]
    fn more_credential_shapes_are_redacted() {
        assert_eq!(redact("-pabc123", false), "-p<r>");
        assert_eq!(redact("-upassword123", false), "-u<r>");
        assert_eq!(redact("--pw", false), "--pw");
        assert!(is_secret_flag("--pw"));
        assert_eq!(redact("token=abc123", false), "token=<r>");
        assert_eq!(redact("api_key=abc123", false), "api_key=<r>");
        assert_eq!(redact("'password=abc123'", false), "'password=<r>'");
        assert_eq!(redact("'--password abc123'", false), "'--password <r>'");
        assert_eq!(redact("\"--password=abc123\"", false), "\"--password=<r>\"");
        assert_eq!(redact("--password=$'abc123'", false), "--password=<r>");
        assert_eq!(
            redact("https://x.io/a#token=abc123", false),
            "https://x.io/a#token=<r>"
        );
    }

    #[test]
    fn expansions_are_left_intact() {
        assert_eq!(
            redact("${MY_SECRET_TOKEN:-x}", false),
            "${MY_SECRET_TOKEN:-x}"
        );
        assert_eq!(redact("$MY_TOKEN", false), "$MY_TOKEN");
        assert_eq!(redact("my_token:x", false), "my_token:x");
    }

    #[test]
    fn url_credentials_and_query_secrets_are_redacted() {
        assert_eq!(
            redact("https://user:p@ss@host/x", false),
            "https://<r>@host/x"
        );
        assert_eq!(
            redact("https://example.com/a@b", false),
            "https://example.com/a@b"
        );
        assert_eq!(
            redact("https://x.io/api?token=abc&page=2&sig=zz", false),
            "https://x.io/api?token=<r>&page=2&sig=<r>"
        );
    }
}
