//! Secret-looking values out of everything rippy shows or keeps: the reason it
//! returns, its trace, the tracking database and the log.
//!
//! Three layers, each catching what the others cannot:
//! - context: a credential flag's value, a secret-named assignment, an auth
//!   header, a URL's userinfo ([`words`]);
//! - shape: provider formats (GitHub, AWS, `OpenAI`, Stripe, Slack, Google,
//!   JWTs, private keys, …) from `leakguard`, with its PII detectors left off;
//! - name: the value of an expanded `$VAR` whose name marks a secret, whatever
//!   it looks like ([`Revealed`]).
//!
//! See docs/security-invariants.md#history-redaction.

use std::ops::Range;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::LazyLock;

use leakguard::{Kind, Mask, Redactor};
use serde_json::Value;

mod programs;
mod words;

#[cfg(feature = "jev")]
pub(crate) use words::Rules;
#[cfg(feature = "jev")]
pub(crate) use words::{secret_flag, secret_ranges};

/// What a redacted value is replaced with.
pub const REDACTED: &str = "<redacted>";

/// Name fragments that mark a secret wherever they appear (`PGPASSWORD`,
/// `apiToken`, `GITHUB_TOKENS`), compared with separators removed.
const SECRET_NAME_FRAGMENTS: &[&str] = &[
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "PASSPHRASE",
    "APIKEY",
    "CREDENTIAL",
    "PRIVATEKEY",
    "ACCESSKEY",
    "WEBHOOK",
    "AUTHCONFIG",
];

/// Short name parts that mark a secret only as the *last* segment
/// (`MYSQL_PWD`, `DEPLOY_KEY`, `GH_PAT`), so `SSH_AUTH_SOCK` or `SSH_KEY_PATH`
/// stay visible.
const SECRET_LAST_SEGMENTS: &[&str] = &[
    "KEY", "KEYS", "PASS", "PWD", "PW", "PAT", "AUTH", "DSN", "COOKIE", "SESSION",
];

/// Shorter values are not scrubbed by name: replacing every `1` in a line to
/// hide `DEBUG_TOKEN=1` would destroy the line and protect nothing.
const MIN_SCRUB_LEN: usize = 4;

/// A secret value re-parsed as shell (`sh -c $X_TOKEN`) is also scrubbed word
/// by word, for words at least this long; shorter ones (`echo`, `hi`) are too
/// likely to appear on their own.
const MIN_PIECE_LEN: usize = 8;

/// Quoted phrases are read as commands this many levels deep.
const MAX_PHRASE_DEPTH: usize = 4;

/// Open quotes re-read as literal before every quote is, which bounds
/// [`words_of`] to a few passes however the input is built.
const MAX_OPEN_QUOTES: usize = 16;

/// leakguard's secret detectors only. Email, IP, phone, card and IBAN
/// detectors would hide what a reviewer needs (`ssh deploy@10.0.0.12`), and its
/// high-entropy detector flags commit hashes.
static PROVIDER_SHAPES: LazyLock<Redactor> = LazyLock::new(|| {
    Redactor::only(&[
        Kind::PrivateKey,
        Kind::AzureConnectionString,
        Kind::TelegramToken,
        Kind::DiscordToken,
        Kind::Jwt,
        Kind::GitHubToken,
        Kind::SlackToken,
        Kind::StripeKey,
        Kind::OpenAiKey,
        Kind::GoogleApiKey,
        Kind::AwsAccessKey,
        Kind::UrlCredentials,
    ])
    .mask(Mask::fixed(REDACTED))
});

/// `text` (a command, or a reason quoting one) with every secret-looking value
/// replaced by [`REDACTED`].
#[must_use]
pub fn secrets(text: &str) -> String {
    let mut ranges = Vec::new();
    collect(text, 0, 0, &programs::Context::default(), &mut ranges);
    provider_shapes(&replace_ranges(text, ranges))
}

/// Provider-shaped secrets anywhere in `text`, replaced by [`REDACTED`].
///
/// leakguard 0.9.1 slices past the end of text ending in `://`; a trailing
/// newline keeps it in bounds, and any other panic redacts the whole text
/// rather than failing the hook (the binary's panic hook keeps its message,
/// which may quote the text, off stderr).
#[must_use]
pub fn provider_shapes(text: &str) -> String {
    let padded = format!("{text}\n");
    catch_unwind(AssertUnwindSafe(|| PROVIDER_SHAPES.clean(&padded))).map_or_else(
        |_| REDACTED.to_owned(),
        |out| {
            out.strip_suffix('\n')
                .map_or_else(|| out.clone(), str::to_owned)
        },
    )
}

/// A JSON value with every string redacted, and everything under a
/// secret-named key (`"password"`, `"api_key"`, `"credentials": {…}`) hidden.
#[must_use]
pub fn json(value: &Value) -> Value {
    match value {
        Value::String(s) => Value::String(secrets(s)),
        Value::Array(items) => argv(items),
        Value::Object(map) => map
            .iter()
            .map(|(k, v)| {
                let v = if is_secret_name(k) {
                    hidden(v)
                } else {
                    json(v)
                };
                (k.clone(), v)
            })
            .collect(),
        other => other.clone(),
    }
}

/// A JSON array, read like an argv: a string after a credential flag
/// (`["--password", "x"]`) is hidden whole.
fn argv(items: &[Value]) -> Value {
    let rules = programs::Context::default().rules();
    let mut after_flag = false;
    items
        .iter()
        .map(|item| {
            let out = match item {
                Value::String(_) if after_flag => Value::String(REDACTED.to_owned()),
                other => json(other),
            };
            after_flag = item.as_str().is_some_and(|s| words::secret_flag(s, rules));
            out
        })
        .collect()
}

/// `value` with every scalar in it replaced by [`REDACTED`], keeping its shape.
fn hidden(value: &Value) -> Value {
    match value {
        Value::Array(items) => items.iter().map(hidden).collect(),
        Value::Object(map) => map.iter().map(|(k, v)| (k.clone(), hidden(v))).collect(),
        Value::Null => Value::Null,
        _ => Value::String(REDACTED.to_owned()),
    }
}

/// Whether `name` marks a secret with no separator to anchor it.
///
/// A fragment match (`password`, `apitoken`) or a `pass` suffix (`storepass`)
/// counts; short ambiguous parts (`key`, `auth`) need a segment of their own.
#[must_use]
pub fn is_strong_secret_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    let joined: String = upper.chars().filter(char::is_ascii_alphanumeric).collect();
    let location = upper
        .rsplit(|c: char| !c.is_ascii_alphanumeric())
        .next()
        .is_some_and(|l| LOCATION_SEGMENTS.contains(&l));
    !location
        && (SECRET_NAME_FRAGMENTS.iter().any(|f| joined.contains(f)) || joined.ends_with("PASS"))
}

/// Last segments that say a name holds *where* a secret is, not the secret
/// (`--password-file`, `GITHUB_TOKEN_PATH`): the value is a path to show.
const LOCATION_SEGMENTS: &[&str] = &["FILE", "PATH", "DIR", "FD", "ENV", "CMD", "COMMAND"];

/// Whether `name` marks a variable, key or flag as holding a secret.
#[must_use]
pub fn is_secret_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    let last = upper.rsplit(|c: char| !c.is_ascii_alphanumeric()).next();
    if matches!(upper.as_str(), "PWD" | "OLDPWD")
        || last.is_some_and(|l| LOCATION_SEGMENTS.contains(&l))
    {
        return false;
    }
    let joined: String = upper.chars().filter(char::is_ascii_alphanumeric).collect();
    SECRET_NAME_FRAGMENTS.iter().any(|f| joined.contains(f))
        || last.is_some_and(|l| SECRET_LAST_SEGMENTS.contains(&l))
}

/// Values rippy learned while judging one command, which what it shows must
/// not repeat. Only an analysis that resolved a variable can reveal one, so
/// everything else is shown exactly as before.
#[derive(Default)]
pub struct Revealed {
    /// Values of secret-named variables, and their shell-quoted spellings.
    values: Vec<String>,
    /// A variable was resolved, so shown text may hold an environment value.
    resolved: bool,
}

impl Revealed {
    /// Note that `name` resolved to `value`.
    ///
    /// A secret-named value is kept in every spelling rippy may show it in:
    /// as is, shell-quoted (`'\''`), escaped by a trace's `{:?}` rendering, and,
    /// for a value that holds shell words, each long word on its own.
    pub fn record(&mut self, name: &str, value: &str) {
        self.resolved = true;
        if !is_secret_name(name) || value.len() < MIN_SCRUB_LEN {
            return;
        }
        let pieces = value
            .split(|c: char| {
                c.is_whitespace() || matches!(c, ';' | '|' | '&' | '<' | '>' | '(' | ')')
            })
            .filter(|p| p.len() >= MIN_PIECE_LEN && p.len() < value.len());
        for spelling in std::iter::once(value).chain(pieces) {
            let quoted = spelling.replace('\'', "'\\''");
            for form in [spelling.to_owned(), quoted] {
                let debug = format!("{form:?}");
                let escaped = &debug[1..debug.len() - 1];
                if escaped != form {
                    self.values.push(escaped.to_owned());
                }
                self.values.push(form);
            }
        }
        self.values.dedup();
    }

    /// Forget everything: a new command is being judged.
    pub fn clear(&mut self) {
        self.values.clear();
        self.resolved = false;
    }

    /// `text` as rippy may show it.
    #[must_use]
    pub fn show(&self, text: String) -> String {
        if !self.resolved {
            return text;
        }
        // Longest first, so a value containing another is scrubbed whole.
        let mut values: Vec<&String> = self.values.iter().collect();
        values.sort_by_key(|v| std::cmp::Reverse(v.len()));
        let scrubbed = values
            .into_iter()
            .fold(text, |out, v| out.replace(v.as_str(), REDACTED));
        secrets(&scrubbed)
    }
}

/// Byte ranges to redact in `text` (offset by `base`), word by word, with the
/// flag context carried from one word to the next and quoted phrases read as
/// commands of their own, so a value never swallows the rest of a phrase.
/// A phrase starts from its enclosing command's context (`curl '-u a:b'`), and
/// returns whether the word after it is a credential (`'… Bearer' TOKEN`).
fn collect(
    text: &str,
    base: usize,
    depth: usize,
    parent: &programs::Context,
    out: &mut Vec<Range<usize>>,
) -> bool {
    let mut ctx = parent.clone();
    let mut after_secret = false;
    for (n, word) in words_of(text).into_iter().enumerate() {
        let span = word.span;
        if word.starts_segment && n > 0 {
            ctx = programs::Context::default();
            after_secret = false;
        }
        let w = &text[span.clone()];
        let unquoted = w.trim_matches(['"', '\'']);
        if is_redacted_marker(text, &span) {
            after_secret = false;
            continue;
        }
        let at = |r: Range<usize>| base + span.start + r.start..base + span.start + r.end;
        let rules = ctx.rules();
        if after_secret && !is_auth_scheme(w) && !unquoted.starts_with('-') {
            out.extend(words::secret_ranges(w, true, rules).into_iter().map(at));
            after_secret = false;
            continue;
        }
        if after_secret && unquoted == "--" {
            continue;
        }
        if let Some(inner) = quoted_phrase(w).filter(|_| depth < MAX_PHRASE_DEPTH) {
            after_secret = collect(inner, base + span.start + 1, depth + 1, &ctx, out);
            continue;
        }
        ctx.see(unquoted);
        out.extend(words::secret_ranges(w, false, rules).into_iter().map(at));
        out.extend(json_values(w).into_iter().map(at));
        let rules = ctx.rules();
        // An auth scheme is a credential marker only after a header
        // (`Authorization: Bearer X`), not in prose (`rotate token daily`).
        let scheme = after_secret && is_auth_scheme(w);
        after_secret = scheme
            || words::secret_flag(unquoted, rules)
            || marks_next(w)
            || ctx.marks_next(unquoted);
    }
    after_secret
}

/// The values of secret-named keys in compact JSON inside one word
/// (`'{"user":"a","password":"x"}'`): a string up to its closing quote, or a
/// bare value up to the next `,`, `}` or `]`.
fn json_values(word: &str) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    for (colon, _) in word.match_indices("\":") {
        let key_start = word[..colon].rfind('"').map_or(0, |i| i + 1);
        if !is_secret_name(&word[key_start..colon]) {
            continue;
        }
        let rest = &word[colon + 2..];
        let skip = rest.len() - rest.trim_start().len();
        let start = colon + 2 + skip;
        let end = if word[start..].starts_with('"') {
            closing_quote(word, start + 1).map_or(word.len(), |q| q)
        } else {
            word[start..]
                .find([',', '}', ']'])
                .map_or(word.len(), |i| start + i)
        };
        let start = start + usize::from(word[start..].starts_with('"'));
        if start < end {
            ranges.push(start..end);
        }
    }
    ranges
}

/// The index of the `"` closing a JSON string that starts at `from`.
fn closing_quote(word: &str, from: usize) -> Option<usize> {
    let mut escaped = false;
    for (i, c) in word[from..].char_indices() {
        match c {
            _ if escaped => escaped = false,
            '\\' => escaped = true,
            '"' => return Some(from + i),
            _ => {}
        }
    }
    None
}

/// The inner text of a word that is one quoted multi-word phrase
/// (`"X=1 rm -rf /srv"`, `'{"password": "x"}'`).
fn quoted_phrase(word: &str) -> Option<&str> {
    let quote = word.chars().next().filter(|c| matches!(c, '\'' | '"'))?;
    let inner = word.strip_prefix(quote)?.strip_suffix(quote)?;
    inner.contains(char::is_whitespace).then_some(inner)
}

/// `Bearer`, `Basic`, `Token`: after an `Authorization:` header, the scheme
/// is skipped and the word after it is the credential.
fn is_auth_scheme(word: &str) -> bool {
    matches!(
        word.trim_matches(['"', '\'']).to_ascii_lowercase().as_str(),
        "bearer" | "basic" | "token" | "digest"
    )
}

/// A word after which the next one is a credential: a header name
/// (`Authorization:`), a JSON key (`"password":`) or a config key
/// (`user.password`, `aws_secret_access_key`).
fn marks_next(word: &str) -> bool {
    let bare = word.trim_matches(|c: char| matches!(c, '"' | '\'' | '{' | ',' | '['));
    if let Some(key) = bare.strip_suffix(':') {
        let key = key.trim_matches(['"', '\'']);
        return is_secret_name(key)
            || key.eq_ignore_ascii_case("authorization")
            || key.eq_ignore_ascii_case("proxy-authorization");
    }
    let config_key = bare.contains(['.', '_'])
        && bare
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_'));
    config_key && is_secret_name(bare)
}

/// The `redacted` inside an earlier pass's `<redacted>`: splitting at `<`
/// and `>` would otherwise redact it again into `<<redacted>>`.
fn is_redacted_marker(text: &str, span: &Range<usize>) -> bool {
    span.start > 0 && text.get(span.start - 1..span.end + 1) == Some(REDACTED)
}

/// `text` with every range replaced by [`REDACTED`], in one pass. Ranges that
/// overlap or touch are merged first, so each secret is covered whole.
fn replace_ranges(text: &str, mut ranges: Vec<Range<usize>>) -> String {
    ranges.sort_by_key(|r| r.start);
    let mut merged: Vec<Range<usize>> = Vec::new();
    for r in ranges.into_iter().filter(|r| r.start < r.end) {
        match merged.last_mut() {
            Some(last) if r.start <= last.end => last.end = last.end.max(r.end),
            _ => merged.push(r),
        }
    }
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    for r in merged {
        out.push_str(&text[at..r.start]);
        out.push_str(REDACTED);
        at = r.end;
    }
    out.push_str(&text[at..]);
    out
}

struct Word {
    span: Range<usize>,
    /// The word follows a `;`, `|`, `&`, `(`, `)` or newline: a new command.
    starts_segment: bool,
}

/// The shell words of `text`, split at unquoted whitespace and operators, with
/// quotes and backslash escapes kept inside the word. Not a parser: it never
/// fails, so unparseable text is still redacted. A quote left open (`it's`, a
/// comment) is read as a literal character, so the rest of the text is still
/// split into words. Splitting only at ASCII bytes keeps every range on a
/// UTF-8 boundary.
fn words_of(text: &str) -> Vec<Word> {
    let mut literal = Vec::new();
    while literal.len() < MAX_OPEN_QUOTES {
        match scan(text, &literal, false) {
            Ok(words) => return words,
            Err(open_quote) => literal.push(open_quote),
        }
    }
    scan(text, &literal, true).unwrap_or_default()
}

/// One pass of [`words_of`]: the words, or the position of a quote that never
/// closes. `literal` holds quotes an earlier pass found open; `no_quotes` reads
/// every quote as a literal character.
fn scan(text: &str, literal: &[usize], no_quotes: bool) -> Result<Vec<Word>, usize> {
    let mut words = Vec::new();
    let mut start: Option<usize> = None;
    let mut quote: Option<(u8, usize)> = None;
    let mut escaped = false;
    let mut new_segment = true;
    let mut continuation = false;
    let bytes = text.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if continuation {
            continuation = false;
            continue;
        }
        // `2>&1`, `>&2`: the `&` belongs to the redirect, not a new command.
        let redirect_amp = b == b'&'
            && (i
                .checked_sub(1)
                .is_some_and(|p| matches!(bytes[p], b'>' | b'<'))
                || bytes.get(i + 1) == Some(&b'>'));
        // A line continuation (`\` + newline) ends the word without ending
        // the command.
        let unquoted = quote.is_none() && !escaped;
        continuation = unquoted && b == b'\\' && bytes.get(i + 1) == Some(&b'\n');
        if continuation || (unquoted && is_delimiter(b) && !redirect_amp) {
            if let Some(s) = start.take() {
                words.push(Word {
                    span: s..i,
                    starts_segment: new_segment,
                });
                new_segment = false;
            }
            new_segment |= !continuation && is_separator(b);
            continue;
        }
        start.get_or_insert(i);
        if escaped {
            escaped = false;
        } else if let Some((q, _)) = quote {
            if b == q {
                quote = None;
            } else if q == b'"' && b == b'\\' {
                escaped = true;
            }
        } else if b == b'\\' {
            escaped = true;
        } else if matches!(b, b'\'' | b'"') && !no_quotes && !literal.contains(&i) {
            quote = Some((b, i));
        }
    }
    if let Some((_, at)) = quote {
        return Err(at);
    }
    if let Some(s) = start {
        words.push(Word {
            span: s..text.len(),
            starts_segment: new_segment,
        });
    }
    Ok(words)
}

const fn is_delimiter(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'<' | b'>') || is_separator(b)
}

const fn is_separator(b: u8) -> bool {
    matches!(b, b'\n' | b';' | b'|' | b'&' | b'(' | b')')
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

#[cfg(test)]
#[expect(clippy::unwrap_used)]
#[path = "tests2.rs"]
mod tests2;

#[cfg(test)]
#[expect(clippy::unwrap_used)]
#[path = "proptests.rs"]
mod proptests;
