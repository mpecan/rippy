//! Heuristic safety analysis for inline Ruby source code.
//!
//! Scans for dangerous system calls, file operations, requires, and evals.
//! Returns `true` if no dangerous patterns are found.

const DANGEROUS_CALLS: &[&str] = &[
    "system(",
    "exec(",
    "%x(",
    "%x{",
    "%x[",
    "%x|",
    "IO.popen(",
    "Open3.",
    "Kernel.system(",
    "Kernel.exec(",
    "Kernel.`",
    "spawn(",
];

const DANGEROUS_FILE_OPS: &[&str] = &[
    "File.delete(",
    "File.unlink(",
    "File.write(",
    "File.open(",
    "File.rename(",
    "File.chmod(",
    "File.chown(",
    "FileUtils.rm",
    "FileUtils.mv",
    "FileUtils.cp",
    "FileUtils.chmod",
    "Dir.rmdir(",
    "Dir.delete(",
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
pub fn is_ruby_source_safe(source: &str) -> bool {
    !has_dangerous_calls(source)
        && !has_dangerous_file_ops(source)
        && !has_dangerous_requires(source)
        && !has_dangerous_evals(source)
        && !has_backtick_execution(source)
}

fn has_dangerous_calls(source: &str) -> bool {
    DANGEROUS_CALLS.iter().any(|c| source.contains(c))
}

fn has_dangerous_file_ops(source: &str) -> bool {
    DANGEROUS_FILE_OPS.iter().any(|f| source.contains(f))
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
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
    fn system_is_dangerous() {
        assert!(!is_ruby_source_safe("system('rm -rf /')"));
    }

    #[test]
    fn exec_is_dangerous() {
        assert!(!is_ruby_source_safe("exec('ls')"));
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
}
