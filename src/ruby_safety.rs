//! Heuristic safety analysis for inline Ruby source code.
//!
//! Scans for dangerous system calls, file operations, requires, and evals.
//! Returns `true` if no dangerous patterns are found.

const DANGEROUS_WORD_CALLS: &[&str] = &["system", "exec", "spawn"];

// Ruby allows calling these with or without parens (`IO.popen "cmd"` runs a
// shell exactly like `IO.popen("cmd")`), so callers must use `contains_word`
// rather than a paren-anchored `source.contains`.
const DANGEROUS_WORD_SUBSTRING_CALLS: &[&str] =
    &["IO.popen", "Open3", "Kernel.system", "Kernel.exec"];

const DANGEROUS_SUBSTRING_CALLS: &[&str] = &["Kernel.`"];

// Exact method names — call with or without parens, so matched word-anchored.
const DANGEROUS_FILE_OPS: &[&str] = &[
    "File.delete",
    "File.unlink",
    "File.write",
    "File.open",
    "File.rename",
    "File.chmod",
    "File.chown",
    "Dir.rmdir",
    "Dir.delete",
];

// FileUtils methods have suffixed variants (`rm_rf`, `rm_r`, `cp_r`, ...), so
// these stay plain substrings rather than word-anchored.
const DANGEROUS_SUBSTRING_FILE_OPS: &[&str] = &[
    "FileUtils.rm",
    "FileUtils.mv",
    "FileUtils.cp",
    "FileUtils.chmod",
];

const DANGEROUS_REQUIRES: &[&str] = &[
    "open-uri",
    "net/http",
    "socket",
    "webrick",
    "open3",
    "fileutils",
];

const DANGEROUS_EVALS: &[&str] = &[
    "eval(",
    "instance_eval(",
    "class_eval(",
    "module_eval(",
    "binding.eval(",
];

/// Check whether inline Ruby source appears safe to execute.
///
/// This is a heuristic check — it may have false positives (blocking safe code)
/// but should not have false negatives (allowing dangerous code).
#[must_use]
pub(crate) fn is_ruby_source_safe(source: &str) -> bool {
    !has_dangerous_calls(source)
        && !has_dangerous_file_ops(source)
        && !has_dangerous_requires(source)
        && !has_dangerous_evals(source)
        && !has_backtick_execution(source)
        && !has_dangerous_percent_x(source)
}

fn has_dangerous_calls(source: &str) -> bool {
    DANGEROUS_WORD_CALLS
        .iter()
        .any(|c| contains_word(source, c))
        || DANGEROUS_WORD_SUBSTRING_CALLS
            .iter()
            .any(|c| contains_word(source, c))
        || DANGEROUS_SUBSTRING_CALLS.iter().any(|c| source.contains(c))
}

fn has_dangerous_file_ops(source: &str) -> bool {
    DANGEROUS_FILE_OPS.iter().any(|f| contains_word(source, f))
        || DANGEROUS_SUBSTRING_FILE_OPS
            .iter()
            .any(|f| source.contains(f))
}

fn has_dangerous_requires(source: &str) -> bool {
    for module in DANGEROUS_REQUIRES {
        if source.contains(&format!("require \"{module}\""))
            || source.contains(&format!("require '{module}'"))
            || source.contains(&format!("require(\"{module}\")"))
            || source.contains(&format!("require('{module}')"))
        {
            return true;
        }
    }
    false
}

fn has_dangerous_evals(source: &str) -> bool {
    DANGEROUS_EVALS.iter().any(|e| source.contains(e))
}

fn has_backtick_execution(source: &str) -> bool {
    source.contains('`')
}

/// A byte is a Ruby "word" character if it could be part of an identifier.
const fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Check whether `word` appears in `source` as a standalone token — not as a
/// prefix/substring of a longer identifier (e.g. `system` must not match
/// inside `spawn_count`). Ruby allows calling `system`/`exec`/`spawn` with or
/// without parens (`system "id"`, `system("id")`), so only the boundary
/// before and after the match is checked.
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

/// Detect Ruby's `%x` command-execution literal with any delimiter (not just
/// the commonly enumerated `( { [ |`) — `%x` accepts any non-alphanumeric
/// delimiter, e.g. `%x/id/`, `%x!id!`, `%x#id#`.
fn has_dangerous_percent_x(source: &str) -> bool {
    let bytes = source.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    while i + 1 < len {
        if bytes[i] == b'%' && bytes[i + 1] == b'x' {
            let before_ok = i == 0 || !is_word_byte(bytes[i - 1]);
            if before_ok
                && let Some(&delim) = bytes.get(i + 2)
                && !delim.is_ascii_alphanumeric()
                && delim != b'_'
                && !delim.is_ascii_whitespace()
            {
                return true;
            }
        }
        i += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn puts_is_safe() {
        assert!(is_ruby_source_safe("puts 'hello'"));
    }

    #[test]
    fn math_is_safe() {
        assert!(is_ruby_source_safe("puts 2 ** 10"));
    }

    #[test]
    fn array_is_safe() {
        assert!(is_ruby_source_safe("[1,2,3].map { |x| x * 2 }"));
    }

    #[test]
    fn empty_source_is_safe() {
        assert!(is_ruby_source_safe(""));
    }

    #[test]
    fn string_operations_safe() {
        assert!(is_ruby_source_safe("'hello'.upcase.reverse"));
    }

    #[test]
    fn word_literal_is_safe() {
        assert!(is_ruby_source_safe("puts %w[a b]"));
    }

    #[test]
    fn system_call_is_dangerous() {
        assert!(!is_ruby_source_safe("system('rm -rf /')"));
    }

    #[test]
    fn system_bare_is_dangerous() {
        assert!(!is_ruby_source_safe("system \"id\""));
    }

    #[test]
    fn exec_is_dangerous() {
        assert!(!is_ruby_source_safe("exec('ls')"));
    }

    #[test]
    fn exec_bare_is_dangerous() {
        assert!(!is_ruby_source_safe("exec \"id\""));
    }

    #[test]
    fn spawn_bare_is_dangerous() {
        assert!(!is_ruby_source_safe("spawn \"id\""));
    }

    #[test]
    fn backtick_is_dangerous() {
        assert!(!is_ruby_source_safe("`rm -rf /`"));
    }

    #[test]
    fn percent_x_is_dangerous() {
        assert!(!is_ruby_source_safe("%x(rm -rf /)"));
    }

    #[test]
    fn percent_x_slash_delimiter_is_dangerous() {
        assert!(!is_ruby_source_safe("%x/id/"));
    }

    #[test]
    fn io_popen_is_dangerous() {
        assert!(!is_ruby_source_safe("IO.popen('ls')"));
    }

    #[test]
    fn file_delete_is_dangerous() {
        assert!(!is_ruby_source_safe("File.delete('/tmp/x')"));
    }

    #[test]
    fn file_write_is_dangerous() {
        assert!(!is_ruby_source_safe("File.write('/tmp/x', 'data')"));
    }

    #[test]
    fn fileutils_rm_is_dangerous() {
        assert!(!is_ruby_source_safe("FileUtils.rm_rf('/')"));
    }

    #[test]
    fn require_net_http_is_dangerous() {
        assert!(!is_ruby_source_safe("require 'net/http'"));
    }

    #[test]
    fn require_socket_is_dangerous() {
        assert!(!is_ruby_source_safe("require 'socket'"));
    }

    #[test]
    fn eval_is_dangerous() {
        assert!(!is_ruby_source_safe("eval('code')"));
    }

    #[test]
    fn kernel_system_is_dangerous() {
        assert!(!is_ruby_source_safe("Kernel.system('ls')"));
    }

    #[test]
    fn spawn_is_dangerous() {
        assert!(!is_ruby_source_safe("spawn('ls')"));
    }

    #[test]
    fn open3_is_dangerous() {
        assert!(!is_ruby_source_safe("Open3.capture2('ls')"));
    }

    #[test]
    fn identifier_prefix_is_not_dangerous() {
        assert!(is_ruby_source_safe("spawn_count = 1; puts spawn_count"));
    }

    #[test]
    fn io_popen_bare_is_dangerous() {
        assert!(!is_ruby_source_safe("IO.popen \"id\""));
    }

    #[test]
    fn file_write_bare_is_dangerous() {
        assert!(!is_ruby_source_safe("File.write \"/tmp/x\", \"d\""));
    }

    #[test]
    fn file_open_bare_is_dangerous() {
        assert!(!is_ruby_source_safe("File.open \"/tmp/x\", \"w\""));
    }

    #[test]
    fn file_delete_bare_is_dangerous() {
        assert!(!is_ruby_source_safe("File.delete \"/tmp/x\""));
    }

    #[test]
    fn open3_identifier_prefix_is_not_dangerous() {
        assert!(is_ruby_source_safe("Open3ish = 1; puts Open3ish"));
    }
}
