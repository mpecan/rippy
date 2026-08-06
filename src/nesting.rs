//! Pre-parse bound on the *shape* of a command string.
//!
//! rable parses by recursive descent — one stack frame per open construct and
//! per list element — so deeply nested or endlessly chained input overflows the
//! stack. A stack overflow *aborts* the process instead of unwinding, which the
//! hook's `catch_unwind` fail-closed net cannot convert into an Ask, so the
//! shape has to be refused before rable ever sees it (#195).
//! see docs/security-invariants.md#parser-stack-bound

/// Maximum nesting of shell constructs handed to the parser. Measured overflow
/// floors for a debug build: ~50 nested `case`/`if` heads on a 2 MB thread
/// stack, ~250 on the 8 MB main thread. 32 stays clear of both while sitting
/// far above anything written by hand — real one-liners nest a few levels.
const MAX_NESTING: usize = 32;

/// Maximum number of statement separators (`;`, `&&`, `|`, newline, …). The
/// same recursion runs per list element: ~3 500 flat statements overflow a
/// 2 MB stack, ~15 000 the main thread. Past a thousand statements a "command"
/// is a program, and the analyzer's 10 000-node budget would cap it at Ask.
const MAX_STATEMENTS: usize = 1_000;

/// What an open construct is waiting for. Closers pop only their own frame, so
/// a `case` pattern's `)` is not mistaken for the end of a subshell.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Frame {
    Paren,
    Brace,
    Keyword,
    Backtick,
}

/// Why `source` is too complex to hand to the parser, or `None` if it is within
/// bounds. Deliberately approximate: the scan may over-count (a keyword inside
/// a heredoc body) because over-counting only costs an Ask, while under-counting
/// would cost the process.
pub(crate) fn violation(source: &str) -> Option<String> {
    let scan = Scan::run(source);
    if scan.max_depth > MAX_NESTING {
        return Some(format!(
            "nesting depth {} exceeds the {MAX_NESTING}-level limit",
            scan.max_depth
        ));
    }
    (scan.statements > MAX_STATEMENTS).then(|| {
        format!(
            "{} statements exceed the {MAX_STATEMENTS}-statement limit",
            scan.statements
        )
    })
}

#[derive(Default)]
struct Scan {
    stack: Vec<Frame>,
    max_depth: usize,
    statements: usize,
    after_separator: bool,
    word: String,
}

impl Scan {
    fn run(source: &str) -> Self {
        let mut scan = Self::default();
        let mut chars = source.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => {
                    chars.next();
                }
                '\'' => {
                    scan.end_word();
                    skip_single_quoted(&mut chars);
                }
                '"' => {
                    scan.end_word();
                    scan.double_quoted(&mut chars);
                }
                _ => scan.plain(c),
            }
        }
        scan.end_word();
        scan
    }

    fn plain(&mut self, c: char) {
        match c {
            '(' => self.open(Frame::Paren),
            '{' => self.open(Frame::Brace),
            ')' => self.close(Frame::Paren, 0),
            '}' => self.close(Frame::Brace, 0),
            '`' => {
                self.end_word();
                self.backtick(0);
            }
            ';' | '&' | '|' | '\n' => self.separator(),
            _ if c.is_whitespace() => self.end_word(),
            _ => self.word.push(c),
        }
    }

    /// Inside `"…"` only `$(…)` and backticks nest; every other character is
    /// literal text, so a quoted `(` is not a construct and a quoted `)` may
    /// not cancel one opened outside the span.
    fn double_quoted(&mut self, chars: &mut std::str::Chars<'_>) {
        let floor = self.stack.len();
        let mut dollar = false;
        while let Some(c) = chars.next() {
            match c {
                '\\' => {
                    chars.next();
                    dollar = false;
                }
                '"' => return,
                '(' if dollar => {
                    self.push(Frame::Paren);
                    dollar = false;
                }
                ')' => {
                    self.close(Frame::Paren, floor);
                    dollar = false;
                }
                '`' => self.backtick(floor),
                _ => dollar = c == '$',
            }
        }
    }

    fn open(&mut self, frame: Frame) {
        self.end_word();
        self.after_separator = false;
        self.push(frame);
    }

    fn close(&mut self, frame: Frame, floor: usize) {
        self.end_word();
        self.after_separator = false;
        if self.stack.len() > floor && self.stack.last() == Some(&frame) {
            self.stack.pop();
        }
    }

    fn backtick(&mut self, floor: usize) {
        if self.stack.len() > floor && self.stack.last() == Some(&Frame::Backtick) {
            self.stack.pop();
        } else {
            self.push(Frame::Backtick);
        }
    }

    fn push(&mut self, frame: Frame) {
        self.stack.push(frame);
        self.max_depth = self.max_depth.max(self.stack.len());
    }

    /// A run of separators (`;;`, `&&`, `|&`) opens one statement, not several.
    fn separator(&mut self) {
        self.end_word();
        if !self.after_separator {
            self.statements += 1;
            self.after_separator = true;
        }
    }

    fn end_word(&mut self) {
        if self.word.is_empty() {
            return;
        }
        let word = std::mem::take(&mut self.word);
        self.after_separator = false;
        match word.as_str() {
            "if" | "case" | "for" | "while" | "until" | "select" => self.push(Frame::Keyword),
            "fi" | "esac" | "done" => self.close(Frame::Keyword, 0),
            _ => {}
        }
    }
}

fn skip_single_quoted(chars: &mut std::str::Chars<'_>) {
    for c in chars.by_ref() {
        if c == '\'' {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn depth(source: &str) -> usize {
        Scan::run(source).max_depth
    }

    #[test]
    fn ordinary_commands_have_no_nesting() {
        assert_eq!(depth("git status"), 0);
        assert_eq!(depth("cat file | grep -c foo"), 0);
        assert_eq!(depth("ls -la && echo done"), 0);
    }

    #[test]
    fn balanced_constructs_unwind_to_zero() {
        for source in [
            "for f in *; do echo $f; done",
            "if true; then ls; fi",
            "case $x in a) ls ;; *) pwd ;; esac",
            "while read -r l; do echo $l; done",
            "f() { ls; }",
            "(cd /tmp && ls)",
            "echo ${HOME} $(pwd) `date`",
            "echo $((1 + 2))",
        ] {
            let scanned = depth(source);
            assert!(scanned <= 2, "{source} scanned as depth {scanned}");
            assert!(violation(source).is_none(), "{source} was refused");
        }
    }

    #[test]
    fn a_realistically_nested_script_stays_in_bounds() {
        let source = "for f in *.rs; do \
             if [ -f \"$f\" ]; then \
                 case \"$f\" in *_test.rs) echo test ;; *) echo src ;; esac; \
             fi; \
         done";
        assert!(violation(source).is_none());
    }

    #[test]
    fn each_construct_counts_toward_the_depth_limit() {
        for token in [
            "case x in a) ",
            "for i in a; do ",
            "if true; then ",
            "while true; do ",
            "until true; do ",
            "select i in a; do ",
            "{ ",
            "( ",
            "$( ",
            "f() { ",
        ] {
            let source = token.repeat(MAX_NESTING + 1);
            let refused = violation(&source);
            assert!(
                refused.is_some_and(|d| d.contains("nesting depth")),
                "{token:?} repeated past the limit was not refused"
            );
        }
    }

    #[test]
    fn a_case_pattern_paren_does_not_cancel_the_case() {
        assert!(depth(&"case x in a) ".repeat(40)) >= 40);
    }

    #[test]
    fn literal_parens_inside_double_quotes_are_text() {
        assert_eq!(depth("echo \"((((((((((\""), 0);
        assert_eq!(depth("python3 -c \"print(((1)))\""), 0);
    }

    /// A quoted `)` is literal to bash, so letting it pop would let an attacker
    /// hold the scanner at depth 0 while rable kept recursing.
    #[test]
    fn a_quoted_closer_cannot_cancel_an_unquoted_construct() {
        let source = "( echo \")\" ".repeat(MAX_NESTING + 1);
        assert!(violation(&source).is_some_and(|d| d.contains("nesting depth")));
    }

    #[test]
    fn command_substitution_inside_double_quotes_still_nests() {
        let source = "echo \"$( ".repeat(MAX_NESTING + 1);
        assert!(violation(&source).is_some_and(|d| d.contains("nesting depth")));
    }

    #[test]
    fn quoted_text_is_not_scanned_for_keywords_or_separators() {
        assert_eq!(depth("echo 'if case for while'"), 0);
        assert_eq!(Scan::run("echo 'a;b;c;d'").statements, 0);
        assert_eq!(Scan::run("echo \"a;b;c;d\"").statements, 0);
    }

    #[test]
    fn a_long_flat_chain_is_refused_by_the_statement_bound() {
        let flat = vec!["a"; MAX_STATEMENTS + 2].join(";");
        assert!(violation(&flat).is_some_and(|d| d.contains("statements")));
        let short = ["a"; 10].join(" && ");
        assert!(violation(&short).is_none());
    }

    #[test]
    fn multi_character_operators_count_as_one_statement() {
        assert_eq!(Scan::run("a && b || c |& d").statements, 3);
        assert_eq!(Scan::run("case x in a) ls ;; esac").statements, 1);
    }

    #[test]
    fn an_escaped_metacharacter_is_not_a_construct() {
        assert_eq!(depth("echo \\( \\( \\("), 0);
        assert_eq!(Scan::run("find . -type f -exec rm {} \\;").statements, 0);
    }
}
