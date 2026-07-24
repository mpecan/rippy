//! Heuristic safety analysis for inline Perl source code.
//!
//! Scans for dangerous system calls, file operations, evals, and network modules.
//! Returns `true` if no dangerous patterns are found.

const DANGEROUS_WORD_CALLS: &[&str] = &["system", "exec", "qx", "readpipe"];

const DANGEROUS_FILE_OP_WORDS: &[&str] = &[
    "unlink", "rename", "rmdir", "chmod", "chown", "truncate", "mkdir",
];

const DANGEROUS_EVALS: &[&str] = &["eval(", "eval {", "eval \"", "eval '", "eval $"];

const DANGEROUS_MODULES: &[&str] = &[
    "IO::Socket",
    "LWP::",
    "Net::",
    "HTTP::",
    "File::Copy",
    "File::Path",
    "File::Temp",
];

/// Check whether inline Perl source appears safe to execute.
///
/// This is a heuristic check — it may have false positives (blocking safe code)
/// but should not have false negatives (allowing dangerous code).
#[must_use]
pub fn is_perl_source_safe(source: &str) -> bool {
    !has_dangerous_calls(source)
        && !has_dangerous_file_ops(source)
        && !has_dangerous_evals(source)
        && !has_dangerous_modules(source)
        && !has_backtick_execution(source)
        && !has_dangerous_open(source)
        && !has_dangerous_s_flag(source)
}

fn has_dangerous_calls(source: &str) -> bool {
    DANGEROUS_WORD_CALLS
        .iter()
        .any(|c| contains_word(source, c))
}

fn has_dangerous_file_ops(source: &str) -> bool {
    DANGEROUS_FILE_OP_WORDS
        .iter()
        .any(|f| contains_word(source, f))
}

fn has_dangerous_evals(source: &str) -> bool {
    DANGEROUS_EVALS.iter().any(|e| source.contains(e))
}

fn has_dangerous_modules(source: &str) -> bool {
    DANGEROUS_MODULES.iter().any(|m| source.contains(m))
}

fn has_backtick_execution(source: &str) -> bool {
    source.contains('`')
}

/// Detect `open()` with write modes (`>`, `>>`, `|`).
fn has_dangerous_open(source: &str) -> bool {
    let Some(idx) = source.find("open(") else {
        return false;
    };
    let after = &source[idx + 5..];
    after.contains('>') || after.contains('|')
}

/// A byte is a Perl "word" character if it could be part of an identifier.
const fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Check whether `word` appears in `source` as a standalone token — not as a
/// prefix/substring of a longer identifier (e.g. `system` must not match
/// inside `$systematic`). Perl allows calling `system`/`exec`/`qx`/etc. with
/// or without parens/spaces (`system"id"`, `system(...)`, `system;`), so only
/// the boundary before and after the match is checked, not any particular
/// following delimiter.
fn contains_word(source: &str, word: &str) -> bool {
    let bytes = source.as_bytes();
    let wlen = word.len();
    if wlen == 0 || bytes.len() < wlen {
        return false;
    }
    for start in 0..=(bytes.len() - wlen) {
        if &source[start..start + wlen] != word {
            continue;
        }
        let before_ok = start == 0 || !is_word_byte(bytes[start - 1]);
        let after_ok = start + wlen == bytes.len() || !is_word_byte(bytes[start + wlen]);
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

/// Detect the `s///e` substitution execute flag: the flags segment after the
/// third occurrence of the chosen delimiter (following a whole-word `s`)
/// contains `e`, meaning the replacement is evaluated as Perl (and can shell
/// out) rather than treated as a literal string.
fn has_dangerous_s_flag(source: &str) -> bool {
    let bytes = source.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    while i < len {
        if bytes[i] == b's' {
            let before_ok = i == 0 || !is_word_byte(bytes[i - 1]);
            if before_ok && i + 1 < len {
                let delim = bytes[i + 1];
                if delim.is_ascii_alphanumeric() || delim == b'_' || delim.is_ascii_whitespace() {
                    i += 1;
                    continue;
                }
                if let Some(flags) = flags_after_third_delim(bytes, i + 1, delim)
                    && flags.contains(&b'e')
                {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

/// Starting at `start` (the position of the delimiter), find the byte range
/// after the third occurrence of `delim` and return it as the flags segment.
fn flags_after_third_delim(bytes: &[u8], start: usize, delim: u8) -> Option<&[u8]> {
    let mut count = 0u8;
    let mut j = start;
    while j < bytes.len() {
        if bytes[j] == delim {
            count += 1;
            if count == 3 {
                let flags_start = j + 1;
                let mut k = flags_start;
                while k < bytes.len() && bytes[k].is_ascii_alphabetic() {
                    k += 1;
                }
                return Some(&bytes[flags_start..k]);
            }
        }
        j += 1;
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn print_is_safe() {
        assert!(is_perl_source_safe("print 'hello\\n'"));
    }

    #[test]
    fn math_is_safe() {
        assert!(is_perl_source_safe("print 2 ** 10"));
    }

    #[test]
    fn empty_source_is_safe() {
        assert!(is_perl_source_safe(""));
    }

    #[test]
    fn regex_is_safe() {
        assert!(is_perl_source_safe("'hello' =~ /ell/"));
    }

    #[test]
    fn array_is_safe() {
        assert!(is_perl_source_safe("my @a = (1,2,3); print join(',', @a)"));
    }

    #[test]
    fn system_call_is_dangerous() {
        assert!(!is_perl_source_safe("system('rm -rf /')"));
    }

    #[test]
    fn system_bare_is_dangerous() {
        assert!(!is_perl_source_safe("system \"ls\""));
    }

    #[test]
    fn system_no_space_no_paren_is_dangerous() {
        assert!(!is_perl_source_safe("system\"id\""));
    }

    #[test]
    fn exec_is_dangerous() {
        assert!(!is_perl_source_safe("exec('ls')"));
    }

    #[test]
    fn exec_no_space_is_dangerous() {
        assert!(!is_perl_source_safe("exec\"id\""));
    }

    #[test]
    fn backtick_is_dangerous() {
        assert!(!is_perl_source_safe("`rm -rf /`"));
    }

    #[test]
    fn qx_is_dangerous() {
        assert!(!is_perl_source_safe("qx(rm -rf /)"));
    }

    #[test]
    fn qx_slash_delimiter_is_dangerous() {
        assert!(!is_perl_source_safe("qx/id/"));
    }

    #[test]
    fn qx_bang_delimiter_is_dangerous() {
        assert!(!is_perl_source_safe("qx!id!"));
    }

    #[test]
    fn unlink_is_dangerous() {
        assert!(!is_perl_source_safe("unlink '/tmp/x'"));
    }

    #[test]
    fn unlink_no_space_is_dangerous() {
        assert!(!is_perl_source_safe("unlink\"/tmp/x\""));
    }

    #[test]
    fn rename_is_dangerous() {
        assert!(!is_perl_source_safe("rename '/tmp/a', '/tmp/b'"));
    }

    #[test]
    fn eval_is_dangerous() {
        assert!(!is_perl_source_safe("eval('code')"));
    }

    #[test]
    fn eval_block_is_dangerous() {
        assert!(!is_perl_source_safe("eval { die 'err' }"));
    }

    #[test]
    fn io_socket_is_dangerous() {
        assert!(!is_perl_source_safe("use IO::Socket::INET"));
    }

    #[test]
    fn lwp_is_dangerous() {
        assert!(!is_perl_source_safe("use LWP::UserAgent"));
    }

    #[test]
    fn net_module_is_dangerous() {
        assert!(!is_perl_source_safe("use Net::FTP"));
    }

    #[test]
    fn open_write_is_dangerous() {
        assert!(!is_perl_source_safe("open(FH, '>/tmp/x')"));
    }

    #[test]
    fn open_pipe_is_dangerous() {
        assert!(!is_perl_source_safe("open(FH, '|cmd')"));
    }

    #[test]
    fn open_read_is_safe() {
        // open() for reading doesn't contain > or |
        assert!(is_perl_source_safe("open(FH, 'input.txt')"));
    }

    #[test]
    fn s_exec_flag_is_dangerous() {
        assert!(!is_perl_source_safe("s/x/id/e"));
    }

    #[test]
    fn s_plain_is_safe() {
        assert!(is_perl_source_safe("s/x/y/"));
    }

    #[test]
    fn identifier_prefix_is_not_dangerous() {
        // `system` as a substring of a longer identifier must not false-positive.
        assert!(is_perl_source_safe("my $systematic = 1; print $systematic"));
    }

    #[test]
    fn multi_e_concatenation_dangerous() {
        assert!(!is_perl_source_safe("1\nsystem(\"id\")"));
    }
}
