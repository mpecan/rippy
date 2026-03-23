/// A glob-style pattern compatible with Dippy's matching semantics.
///
/// Supports:
/// - `*` matches any sequence of characters
/// - `?` matches exactly one character
/// - `[abc]` and `[!abc]` character classes
/// - `**` matches any sequence (including across word boundaries)
/// - Trailing `|` means exact match only
/// - Default (no `|`): prefix match — pattern `git` matches `git add .`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    raw: String,
    exact: bool,
}

impl Pattern {
    /// Create a pattern from a raw string. A trailing `|` forces exact matching.
    #[must_use]
    pub fn new(raw: &str) -> Self {
        raw.strip_suffix('|').map_or_else(
            || Self {
                raw: raw.to_owned(),
                exact: false,
            },
            |stripped| Self {
                raw: stripped.to_owned(),
                exact: true,
            },
        )
    }

    /// Test whether `input` matches this pattern.
    #[must_use]
    pub fn matches(&self, input: &str) -> bool {
        if self.exact {
            glob_match(self.raw.as_bytes(), input.as_bytes())
        } else {
            // An empty pattern prefix-matches everything.
            if self.raw.is_empty() {
                return true;
            }
            if glob_match(self.raw.as_bytes(), input.as_bytes()) {
                return true;
            }
            // Try matching against the input truncated at each space boundary
            // (matching how Dippy does command prefix matching).
            for (i, _) in input.match_indices(' ') {
                if glob_match(
                    self.raw.as_bytes(),
                    input.as_bytes().get(..i).unwrap_or_default(),
                ) {
                    return true;
                }
            }
            false
        }
    }

    /// Return the raw pattern string (without trailing `|` if it was exact).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

/// Recursive glob matching of `pattern` against `text`.
fn glob_match(pattern: &[u8], text: &[u8]) -> bool {
    match (pattern, text) {
        ([], []) => true,
        // `*` or `**` — match zero-or-more characters (our `*` crosses `/` too).
        // `**/` skips 3 bytes, `**` at end matches everything, `*` skips 1.
        ([b'*', ..], _) => {
            if pattern == b"**" {
                return true;
            }
            let skip = if pattern.starts_with(b"**/") { 3 } else { 1 };
            let rest = &pattern[skip..];
            glob_match(rest, text) || (!text.is_empty() && glob_match(pattern, &text[1..]))
        }
        ([b'?', rest @ ..], [_, text_rest @ ..]) => glob_match(rest, text_rest),
        ([b'[', rest @ ..], [c, text_rest @ ..]) => {
            match_char_class(rest, *c).map_or_else(
                // Malformed bracket — treat `[` as literal
                || *c == b'[' && glob_match(rest, text_rest),
                |(matched, after_bracket)| matched && glob_match(after_bracket, text_rest),
            )
        }
        ([p, rest @ ..], [c, text_rest @ ..]) if *p == *c => glob_match(rest, text_rest),
        _ => false,
    }
}

/// Parse a character class after the opening `[`.
/// Returns `Some((matched, remaining_pattern_after_]))` or `None` if malformed.
fn match_char_class(pattern: &[u8], ch: u8) -> Option<(bool, &[u8])> {
    let (negated, mut pat) = if pattern.first() == Some(&b'!') {
        (true, &pattern[1..])
    } else {
        (false, pattern)
    };

    let mut matched = false;

    // Allow `]` as the first character in the class
    if pat.first() == Some(&b']') {
        if ch == b']' {
            matched = true;
        }
        pat = &pat[1..];
    }

    loop {
        match pat {
            [] => return None,
            [b']', rest @ ..] => return Some((matched ^ negated, rest)),
            [a, b'-', b, rest @ ..] if *b != b']' => {
                if ch >= *a && ch <= *b {
                    matched = true;
                }
                pat = rest;
            }
            [c, rest @ ..] => {
                if ch == *c {
                    matched = true;
                }
                pat = rest;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_exact() {
        let p = Pattern::new("git|");
        assert!(p.matches("git"));
        assert!(!p.matches("git status"));
        assert!(!p.matches("gi"));
    }

    #[test]
    fn literal_prefix() {
        let p = Pattern::new("git");
        assert!(p.matches("git"));
        assert!(p.matches("git status"));
        assert!(p.matches("git add ."));
        assert!(!p.matches("gitk"));
        assert!(!p.matches("g"));
    }

    #[test]
    fn wildcard_star() {
        let p = Pattern::new("git *|");
        assert!(p.matches("git status"));
        assert!(p.matches("git add"));
        assert!(!p.matches("git"));
    }

    #[test]
    fn wildcard_question() {
        let p = Pattern::new("ca?|");
        assert!(p.matches("cat"));
        assert!(p.matches("car"));
        assert!(!p.matches("ca"));
        assert!(!p.matches("cats"));
    }

    #[test]
    fn char_class() {
        let p = Pattern::new("[abc]at|");
        assert!(p.matches("cat"));
        assert!(p.matches("bat"));
        assert!(!p.matches("dat"));
    }

    #[test]
    fn negated_char_class() {
        let p = Pattern::new("[!abc]at|");
        assert!(!p.matches("cat"));
        assert!(p.matches("dat"));
    }

    #[test]
    fn char_class_range() {
        let p = Pattern::new("[a-z]|");
        assert!(p.matches("m"));
        assert!(!p.matches("M"));
        assert!(!p.matches("5"));
    }

    #[test]
    fn double_star() {
        let p = Pattern::new("**/.env*|");
        assert!(p.matches(".env"));
        assert!(p.matches("foo/.env"));
        assert!(p.matches("foo/bar/.env.local"));
    }

    #[test]
    fn prefix_matching_at_word_boundaries() {
        let p = Pattern::new("rm -rf");
        assert!(p.matches("rm -rf /"));
        assert!(p.matches("rm -rf /tmp"));
        assert!(p.matches("rm -rf"));
    }

    #[test]
    fn empty_pattern() {
        let p = Pattern::new("");
        assert!(p.matches(""));
        assert!(p.matches("anything"));
    }

    #[test]
    fn empty_exact_pattern() {
        let p = Pattern::new("|");
        assert!(p.matches(""));
        assert!(!p.matches("anything"));
    }

    #[test]
    fn double_star_at_end() {
        let p = Pattern::new("/tmp/**|");
        assert!(p.matches("/tmp/foo"));
        assert!(p.matches("/tmp/foo/bar"));
    }
}
