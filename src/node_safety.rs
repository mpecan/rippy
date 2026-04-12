//! Heuristic safety analysis for inline Node.js / JavaScript source code.
//!
//! Scans for dangerous `require()` calls, globals, and method calls.
//! Returns `true` if no dangerous patterns are found.

const DANGEROUS_REQUIRES: &[&str] = &[
    "child_process",
    "fs",
    "net",
    "dgram",
    "http",
    "https",
    "os",
    "cluster",
    "vm",
    "worker_threads",
];

const DANGEROUS_GLOBALS: &[&str] = &[
    "eval(",
    "Function(",
    "process.exit(",
    "process.kill(",
    "process.env",
    "child_process",
];

const DANGEROUS_METHODS: &[&str] = &[
    ".execSync(",
    ".spawnSync(",
    ".exec(",
    ".spawn(",
    ".fork(",
    ".writeFileSync(",
    ".writeFile(",
    ".unlinkSync(",
    ".unlink(",
    ".rmSync(",
    ".rmdirSync(",
    ".renameSync(",
    ".mkdirSync(",
    ".appendFileSync(",
    ".createWriteStream(",
];

/// Check whether inline Node.js source appears safe to execute.
///
/// This is a heuristic check — it may have false positives (blocking safe code)
/// but should not have false negatives (allowing dangerous code).
#[must_use]
pub fn is_node_source_safe(source: &str) -> bool {
    !has_dangerous_requires(source)
        && !has_dangerous_globals(source)
        && !has_dangerous_methods(source)
}

fn has_dangerous_requires(source: &str) -> bool {
    for module in DANGEROUS_REQUIRES {
        // require("module") or require('module')
        if source.contains(&format!("require(\"{module}\")"))
            || source.contains(&format!("require('{module}')"))
        {
            return true;
        }
        // import ... from "module" (ES modules)
        if source.contains(&format!("from \"{module}\""))
            || source.contains(&format!("from '{module}'"))
        {
            return true;
        }
    }
    false
}

fn has_dangerous_globals(source: &str) -> bool {
    DANGEROUS_GLOBALS.iter().any(|g| source.contains(g))
}

fn has_dangerous_methods(source: &str) -> bool {
    DANGEROUS_METHODS.iter().any(|m| source.contains(m))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn console_log_is_safe() {
        assert!(is_node_source_safe("console.log('hello')"));
    }

    #[test]
    fn math_is_safe() {
        assert!(is_node_source_safe("console.log(Math.sqrt(16))"));
    }

    #[test]
    fn json_parse_is_safe() {
        assert!(is_node_source_safe("JSON.parse('{\"a\":1}')"));
    }

    #[test]
    fn empty_source_is_safe() {
        assert!(is_node_source_safe(""));
    }

    #[test]
    fn array_operations_safe() {
        assert!(is_node_source_safe("[1,2,3].map(x => x * 2)"));
    }

    #[test]
    fn require_child_process_is_dangerous() {
        assert!(!is_node_source_safe(
            "require('child_process').execSync('ls')"
        ));
    }

    #[test]
    fn require_fs_is_dangerous() {
        assert!(!is_node_source_safe("require('fs').readFileSync('/')"));
    }

    #[test]
    fn require_net_is_dangerous() {
        assert!(!is_node_source_safe("require('net')"));
    }

    #[test]
    fn require_os_is_dangerous() {
        assert!(!is_node_source_safe("require('os').homedir()"));
    }

    #[test]
    fn require_double_quotes_is_dangerous() {
        assert!(!is_node_source_safe(
            "require(\"child_process\").exec('ls')"
        ));
    }

    #[test]
    fn import_from_fs_is_dangerous() {
        assert!(!is_node_source_safe("import { readFileSync } from 'fs'"));
    }

    #[test]
    fn eval_is_dangerous() {
        assert!(!is_node_source_safe("eval('code')"));
    }

    #[test]
    fn function_constructor_is_dangerous() {
        assert!(!is_node_source_safe("new Function('return 1')()"));
    }

    #[test]
    fn process_exit_is_dangerous() {
        assert!(!is_node_source_safe("process.exit(1)"));
    }

    #[test]
    fn process_env_is_dangerous() {
        assert!(!is_node_source_safe("console.log(process.env)"));
    }

    #[test]
    fn exec_sync_is_dangerous() {
        assert!(!is_node_source_safe("cp.execSync('rm -rf /')"));
    }

    #[test]
    fn write_file_sync_is_dangerous() {
        assert!(!is_node_source_safe("fs.writeFileSync('/tmp/x', 'data')"));
    }

    #[test]
    fn unlink_sync_is_dangerous() {
        assert!(!is_node_source_safe("fs.unlinkSync('/tmp/x')"));
    }

    #[test]
    fn rm_sync_is_dangerous() {
        assert!(!is_node_source_safe("fs.rmSync('/', { recursive: true })"));
    }

    #[test]
    fn require_vm_is_dangerous() {
        assert!(!is_node_source_safe("require('vm').runInNewContext('1')"));
    }
}
