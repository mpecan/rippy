//! Pre-parse bound on the *shape* of a command string.
//!
//! rable parses by recursive descent, and a stack overflow *aborts* the process
//! instead of unwinding, which the hook's `catch_unwind` fail-closed net cannot
//! convert into an Ask (#195). Two things keep that from happening: the parse
//! runs on a deep stack (`parser::parse_on_a_deep_stack`), and the shapes that
//! recurse without any ceiling are counted here and refused.
//!
//! The scan is a genuine *over*-approximation: it never skips a span and never
//! cancels a count. Anything that tries to track quoting has to decide what a
//! `'` inside a comment, a heredoc body or `$'\''` means, and one wrong guess
//! desyncs the lexer into skipping the very nesting it is there to measure
//! (#195 again). Counting openers and never matching a closer needs no such
//! guess, so no input — however malformed — can make the count come out low.
//! see docs/security-invariants.md#parser-stack-bound

/// Maximum `$(`, `<(` and `>(` openers. rable's own `MAX_DEPTH` does not reach
/// the lexer's substitution recursion, so this is the one shape rippy has to
/// hold down: 16 384 nested `$(` overflow a 256 MB stack, and the parse is
/// super-linear in the nesting (128 takes 0.5 s, 256 takes 8.6 s, 384 takes
/// 37 s). 128 keeps the worst case sub-second and stays 128x under the floor.
const MAX_SUBSTITUTIONS: usize = 128;

/// Maximum `${` openers. Same unbounded lexer recursion, but far cheaper: it
/// overflows around 131 000 on a 256 MB stack and stays in milliseconds, so the
/// bound only has to sit clear of that while leaving room for a script full of
/// `${VAR}` references.
const MAX_PARAMETER_EXPANSIONS: usize = 4_096;

/// Maximum `{` openers. Brace *expansion* scans forward for the matching `}`,
/// so an input full of unclosed `{a,` costs roughly the brace count times the
/// input length: 8 192 takes 0.74 s, 20 000 takes 4 s, 50 000 takes 29 s — a
/// hang the calling agent would read as a failed hook. Balanced braces are far
/// cheaper (a 4 000-brace JSON document parses in 60 ms), so this only ever
/// bites input that is already malformed.
const MAX_BRACES: usize = 8_192;

/// Maximum runs of `;`, `&`, `|` or newline. rable recurses once per element of
/// a `;`/`&&` list; ~262 000 elements overflow a 256 MB stack. 16 384 leaves a
/// 16x margin and still passes a 10 000-line document written through a heredoc.
const MAX_SEPARATORS: usize = 16_384;

/// Separator budget for parsing on the caller's own stack. A source with no
/// construct opener at all can only recurse once per list element, and even a
/// 512 KB stack swallows this many.
const FLAT_SEPARATORS: usize = 64;

/// Words that make rable open a compound command or wrap one in another node.
/// Matched as runs of ASCII letters, so `verify` never looks like `if` — and a
/// run that only *resembles* a keyword (`if2`) counts, which is the safe
/// direction. `time`/`coproc`/`function` are here because they prefix a command
/// without any bracket to notice them by.
const KEYWORD_HEADS: [&[u8]; 12] = [
    b"if",
    b"elif",
    b"then",
    b"for",
    b"while",
    b"until",
    b"do",
    b"case",
    b"select",
    b"time",
    b"coproc",
    b"function",
];

/// Counts of the shapes that decide how deep rable can recurse. Every field is
/// an upper bound on the real thing, never an estimate of it.
#[derive(Default)]
pub(crate) struct Shape {
    /// `$(`, `<(`, `>(` — the lexer recursion rable does not bound itself.
    substitutions: usize,
    /// `${` — a second, much cheaper unbounded lexer recursion.
    parameter_expansions: usize,
    /// `{` — brace expansion, bounded for its cost rather than its depth.
    braces: usize,
    /// Runs of `;`, `&`, `|`, newline.
    separators: usize,
    /// Everything else that can make rable descend: `(`, `{`, backtick, `[`,
    /// `!` and `KEYWORD_HEADS`. Only ever compared against zero — rable's own
    /// `MAX_DEPTH` of 1000 caps how deep these recurse, so they need no
    /// ceiling of their own.
    heads: usize,
}

impl Shape {
    pub(crate) fn of(source: &str) -> Self {
        let bytes = source.as_bytes();
        let mut shape = Self::default();
        let mut word: Option<usize> = None;
        let mut after_separator = false;
        for (i, &b) in bytes.iter().enumerate() {
            if b.is_ascii_alphabetic() {
                word.get_or_insert(i);
                after_separator = false;
                continue;
            }
            if let Some(start) = word.take()
                && KEYWORD_HEADS.contains(&&bytes[start..i])
            {
                shape.heads += 1;
            }
            if matches!(b, b';' | b'&' | b'|' | b'\n') {
                shape.separators += usize::from(!after_separator);
                after_separator = true;
                continue;
            }
            after_separator = false;
            shape.count_opener(b, bytes.get(i + 1).copied());
        }
        if let Some(start) = word
            && KEYWORD_HEADS.contains(&&bytes[start..])
        {
            shape.heads += 1;
        }
        shape
    }

    const fn count_opener(&mut self, b: u8, next: Option<u8>) {
        match (b, next) {
            (b'$' | b'<' | b'>', Some(b'(')) => self.substitutions += 1,
            (b'$', Some(b'{')) => self.parameter_expansions += 1,
            _ => {}
        }
        if b == b'{' {
            self.braces += 1;
        }
        // `!` is here with the openers: it wraps the command in another node.
        if matches!(b, b'(' | b'{' | b'`' | b'[' | b'!') {
            self.heads += 1;
        }
    }

    /// Why this shape is too much for the parser, or `None` if it is within
    /// bounds.
    pub(crate) fn violation(&self) -> Option<String> {
        over(
            self.substitutions,
            MAX_SUBSTITUTIONS,
            "command substitutions",
        )
        .or_else(|| {
            over(
                self.parameter_expansions,
                MAX_PARAMETER_EXPANSIONS,
                "parameter expansions",
            )
        })
        .or_else(|| over(self.braces, MAX_BRACES, "brace expansions"))
        .or_else(|| over(self.separators, MAX_SEPARATORS, "statement separators"))
    }

    /// True when the source opens no construct at all, so rable cannot recurse
    /// past a handful of list elements and the parse is safe to run inline.
    pub(crate) const fn is_flat(&self) -> bool {
        self.heads == 0
            && self.substitutions == 0
            && self.parameter_expansions == 0
            && self.separators <= FLAT_SEPARATORS
    }
}

fn over(found: usize, limit: usize, noun: &str) -> Option<String> {
    (found > limit).then(|| format!("{found} {noun} exceed the limit of {limit}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shape(source: &str) -> Shape {
        Shape::of(source)
    }

    #[test]
    fn ordinary_commands_open_nothing() {
        for source in [
            "git status",
            "cat file | grep -c foo",
            "ls -la && echo done",
        ] {
            assert!(shape(source).is_flat(), "{source} was not flat");
            assert!(shape(source).violation().is_none());
        }
    }

    #[test]
    fn every_construct_opener_leaves_the_flat_path() {
        for source in [
            "if true; then ls; fi",
            "for f in *; do echo $f; done",
            "while read -r l; do echo $l; done",
            "until false; do ls; done",
            "case $x in a) ls ;; esac",
            "select i in a; do ls; done",
            "f() { ls; }",
            "(cd /tmp && ls)",
            "echo `date`",
            "[[ -f x ]] && ls",
            "echo $(pwd)",
            "echo ${HOME}",
            "diff <(ls) <(ls)",
            "! grep -q x file",
            "time cargo build",
            "coproc tail -f log",
        ] {
            assert!(!shape(source).is_flat(), "{source} took the inline path");
            assert!(shape(source).violation().is_none(), "{source} was refused");
        }
    }

    /// The whole point of the scan: a keyword must be a word, not a substring,
    /// or every `diff`/`verify`/`format` would leave the inline path.
    #[test]
    fn a_keyword_is_only_a_keyword_as_a_whole_word() {
        for source in ["diff a b", "verify --all", "cargo fmt", "forever --now"] {
            assert!(shape(source).is_flat(), "{source} was not flat");
        }
    }

    #[test]
    fn the_bounds_refuse_what_they_name() {
        for (source, noun) in [
            ("$(".repeat(MAX_SUBSTITUTIONS + 1), "command substitutions"),
            ("<(".repeat(MAX_SUBSTITUTIONS + 1), "command substitutions"),
            (">(".repeat(MAX_SUBSTITUTIONS + 1), "command substitutions"),
            (
                "${".repeat(MAX_PARAMETER_EXPANSIONS + 1),
                "parameter expansions",
            ),
            ("{a,".repeat(MAX_BRACES + 1), "brace expansions"),
            (
                vec!["a"; MAX_SEPARATORS + 2].join(";"),
                "statement separators",
            ),
        ] {
            let refused = shape(&source).violation();
            assert!(
                refused.is_some_and(|d| d.contains(noun)),
                "{noun} past the limit was not refused"
            );
        }
    }

    #[test]
    fn a_run_of_separators_is_one_statement_boundary() {
        assert_eq!(shape("a && b || c |& d").separators, 3);
        assert_eq!(shape("case x in a) ls ;; esac").separators, 1);
        assert_eq!(shape("a;\n\nb").separators, 1);
    }

    /// The desync family from #195: quoting that a lexer would have to
    /// interpret must not lower a single count.
    #[test]
    fn nothing_that_looks_like_quoting_hides_an_opener() {
        let tail = "$(".repeat(MAX_SUBSTITUTIONS + 1);
        for prefix in [
            "echo hi #'\n",
            "echo hi # \"\n",
            "# don't\n",
            "cat <<EOF\ndon't\nEOF\n",
            "cat <<'EOF'\nit's\nEOF\n",
            "echo $'\\'' ",
            "echo '",
            "echo \"",
        ] {
            let source = format!("{prefix}{tail}");
            assert!(
                shape(&source).substitutions > MAX_SUBSTITUTIONS,
                "{prefix:?} hid the openers behind it"
            );
        }
        // Re-balancing the stray quote must not help either.
        let rebalanced = format!("# '\n{tail} '");
        assert!(shape(&rebalanced).substitutions > MAX_SUBSTITUTIONS);
        // Nor does a comment hide a statement chain.
        let chain = format!("# '\n{}", vec!["a"; MAX_SEPARATORS + 2].join(";"));
        assert!(shape(&chain).separators > MAX_SEPARATORS);
    }

    /// Prose is the common case for a heredoc body, and it must survive the
    /// counters: apostrophes, unbalanced parens and English `if`/`for`/`while`.
    #[test]
    fn a_prose_document_stays_within_every_bound() {
        let line = "It's `foo` (see below) if you want, for each case while we wait\n";
        let body = line.repeat(1_200);
        let source = format!("cat > /tmp/notes.md <<'EOF'\n{body}EOF\n");
        assert!(shape(&source).violation().is_none());
    }

    #[test]
    fn a_long_script_stays_within_every_bound() {
        let script = (0..500)
            .map(|i| format!("if [ -f x{i} ]; then echo \"${{HOME}}/{i}\"; fi"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(shape(&script).violation().is_none());
    }

    /// Writing a config or fixture file through a heredoc is ordinary work, and
    /// its braces are balanced — the cheap case the `MAX_BRACES` bound is not
    /// aimed at.
    #[test]
    fn a_json_document_stays_within_every_bound() {
        let body = "{\"key\": {\"value\": 1}}\n".repeat(2_000);
        let source = format!("cat > /tmp/a.json <<'EOF'\n{body}EOF\n");
        assert!(shape(&source).violation().is_none());
    }

    #[test]
    fn a_long_chain_of_commands_stays_within_every_bound() {
        let chain = vec!["echo x"; 1_100].join(" && ");
        assert!(shape(&chain).violation().is_none());
    }
}
