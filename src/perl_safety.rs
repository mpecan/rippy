//! Heuristic safety analysis for inline Perl source code.
//!
//! Scans for dangerous system calls, file operations, evals, and network modules.
//! Returns `true` if no dangerous patterns are found.

const DANGEROUS_CALLS: &[&str] = &[
    "system(",
    "system ",
    "exec(",
    "exec ",
    "qx(",
    "qx{",
    "qx[",
    "qx|",
    "readpipe(",
];

const DANGEROUS_FILE_OPS: &[&str] = &[
    "unlink(",
    "unlink ",
    "rename(",
    "rename ",
    "rmdir(",
    "rmdir ",
    "chmod(",
    "chmod ",
    "chown(",
    "chown ",
    "truncate(",
    "mkdir(",
    "mkdir ",
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
}

fn has_dangerous_calls(source: &str) -> bool {
    DANGEROUS_CALLS.iter().any(|c| source.contains(c))
}

fn has_dangerous_file_ops(source: &str) -> bool {
    DANGEROUS_FILE_OPS.iter().any(|f| source.contains(f))
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
    fn exec_is_dangerous() {
        assert!(!is_perl_source_safe("exec('ls')"));
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
    fn unlink_is_dangerous() {
        assert!(!is_perl_source_safe("unlink '/tmp/x'"));
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
}
