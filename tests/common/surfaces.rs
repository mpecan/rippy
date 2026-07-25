//! Surface-pattern matching shared by `tests/allow_catalog.rs` and
//! `tests/allow_completeness.rs`, so the two cannot drift apart.
//!
//! Two matchers live here on purpose, and they disagree deliberately.
//! [`covers`] is lenient: the first placeholder makes every later word a
//! wildcard. It answers "has this shape already been declared?", where a
//! generous yes only removes a probe. [`exercises`] is strict: a placeholder
//! consumes words instead of swallowing the rest of the pattern. It answers
//! "is this surface really covered by a catalog case?", where a generous yes
//! would excuse a missing case and disarm the completeness gate.

/// One word of an `allow_surface()` pattern.
enum Word<'a> {
    /// A literal, possibly an alternation (`--help|-h`) or a glob (`list-*`).
    Literal(&'a str),
    /// `<operand>` — exactly one word.
    One,
    /// `<operand>...` — one or more words.
    OneOrMore,
    /// `[optional]` — zero or one word.
    ZeroOrOne,
    /// `[optional...]` — zero or more words.
    ZeroOrMore,
}

fn parse_word(word: &str) -> Word<'_> {
    if word.starts_with('[') {
        return if word.contains("...") {
            Word::ZeroOrMore
        } else {
            Word::ZeroOrOne
        };
    }
    if word.starts_with('<') {
        return if word.ends_with("...") {
            Word::OneOrMore
        } else {
            Word::One
        };
    }
    Word::Literal(word)
}

fn literal_matches(pattern: &str, actual: &str) -> bool {
    pattern.split('|').any(|alt| match alt.split_once('*') {
        Some((prefix, suffix)) => {
            actual.len() >= prefix.len() + suffix.len()
                && actual.starts_with(prefix)
                && actual.ends_with(suffix)
        }
        None => alt == actual,
    })
}

fn match_words(pattern: &[Word<'_>], probe: &[&str], exact: bool) -> bool {
    let Some((head, rest)) = pattern.split_first() else {
        return !exact || probe.is_empty();
    };
    match head {
        Word::Literal(lit) => {
            probe
                .first()
                .is_some_and(|actual| literal_matches(lit, actual))
                && match_words(rest, &probe[1..], exact)
        }
        Word::One => !probe.is_empty() && match_words(rest, &probe[1..], exact),
        Word::ZeroOrOne => {
            (0..=probe.len().min(1)).any(|taken| match_words(rest, &probe[taken..], exact))
        }
        Word::OneOrMore => (1..=probe.len()).any(|taken| match_words(rest, &probe[taken..], exact)),
        Word::ZeroOrMore => {
            (0..=probe.len()).any(|taken| match_words(rest, &probe[taken..], exact))
        }
    }
}

/// Does an observed invocation `probe` exercise the declared `surface`?
///
/// Trailing arguments are ignored (`git log --oneline` exercises `git log`),
/// but every declared word must be consumed by a real word of `probe`, so one
/// `aws s3 ls` case cannot vouch for `aws <service> wait`.
pub fn exercises(surface: &str, probe: &[&str]) -> bool {
    let words: Vec<Word<'_>> = surface.split_whitespace().map(parse_word).collect();
    !words.is_empty() && match_words(&words, probe, false)
}

/// Does `surface` cover `probe`, word by word?
///
/// `<operand>` and `[optional]` are open-ended — they and every later word
/// match anything. An alternation (`node|nodejs`, `--help|-h`) is a *closed*
/// choice: it covers the spelled alternatives only. Reading it as a wildcard
/// would let one `npm --help|-v` row silently vouch for the whole `npm`
/// namespace and disarm the check.
pub fn covers(surface: &str, probe: &[&str]) -> bool {
    let words: Vec<&str> = surface.split_whitespace().collect();
    for (i, word) in words.iter().enumerate() {
        if word.contains(['<', '[', '*']) {
            return i < probe.len();
        }
        if probe
            .get(i)
            .is_none_or(|actual| !word.split('|').any(|alt| alt == *actual))
        {
            return false;
        }
    }
    words.len() == probe.len()
}

pub fn is_declared(declared: &[String], probe: &[&str]) -> bool {
    declared.iter().any(|surface| covers(surface, probe))
}

/// Every command prefix a fully literal surface hangs a verb off, e.g.
/// `git lfs` from `git lfs status`. Probing these is what makes the catalog a
/// two-way check instead of a restatement of whatever the handler declared.
pub fn declared_namespaces(declared: &[String]) -> Vec<Vec<&str>> {
    let mut namespaces: Vec<Vec<&str>> = Vec::new();
    for surface in declared {
        let words: Vec<&str> = surface.split_whitespace().collect();
        if words.len() < 2 || words.iter().any(|w| w.contains(['<', '[', '*', '|'])) {
            continue;
        }
        let namespace = words[..words.len() - 1].to_vec();
        if !namespaces.contains(&namespace) {
            namespaces.push(namespace);
        }
    }
    namespaces
}

/// The literal words a guarded surface hangs its guard off, e.g. `npm run` from
/// `npm run <script>` or `deno eval` from `deno eval <code>`.
///
/// A placeholder swallows the verb, so these produce no namespace and
/// [`declared_namespaces`] never sees them — yet the guard is the whole
/// approval, and the neighbor is what shows the guard actually holds.
pub fn guarded_prefixes(declared: &[String]) -> Vec<Vec<&str>> {
    let mut prefixes: Vec<Vec<&str>> = Vec::new();
    for surface in declared {
        if !surface.contains(['<', '[', '*', '|']) {
            continue;
        }
        let prefix: Vec<&str> = surface
            .split_whitespace()
            .take_while(|w| !w.contains(['<', '[', '*', '|']))
            .collect();
        if !prefix.is_empty() && !prefixes.contains(&prefix) {
            prefixes.push(prefix);
        }
    }
    prefixes
}

/// Accumulating state for [`segments`].
#[derive(Default)]
struct Split {
    segments: Vec<Vec<String>>,
    words: Vec<String>,
    word: String,
}

impl Split {
    fn push(&mut self, ch: char) {
        self.word.push(ch);
    }

    fn end_word(&mut self) {
        if !self.word.is_empty() {
            self.words.push(std::mem::take(&mut self.word));
        }
    }

    fn end_segment(&mut self) {
        self.end_word();
        if !self.words.is_empty() {
            self.segments.push(std::mem::take(&mut self.words));
        }
    }

    fn finish(mut self) -> Vec<Vec<String>> {
        self.end_segment();
        self.segments
    }
}

/// Split a catalog command into the command segments it runs, quote-aware.
///
/// This is a deliberately small approximation of shell word splitting: no
/// expansion, no heredocs, and no descent into `$(...)`. It must only ever
/// under-claim — a missed segment costs one extra catalog case, a spurious one
/// would let an unrelated case vouch for a surface.
pub fn segments(command: &str) -> Vec<Vec<String>> {
    let mut split = Split::default();
    let mut quote: Option<char> = None;
    let mut escaped = false;

    for ch in command.chars() {
        match (escaped, quote) {
            (true, _) => {
                split.push(ch);
                escaped = false;
            }
            (false, Some(open)) if ch == open => quote = None,
            (false, Some(_)) => split.push(ch),
            (false, None) => match ch {
                '\\' => escaped = true,
                '\'' | '"' => quote = Some(ch),
                '|' | '&' | ';' | '\n' => split.end_segment(),
                c if c.is_whitespace() => split.end_word(),
                c => split.push(c),
            },
        }
    }
    split.finish()
}
