//! Heuristic safety analysis for inline Python source code.
//!
//! Scans for dangerous imports, builtins, and attribute accesses.
//! Returns `true` if no dangerous patterns are found.

const DANGEROUS_IMPORTS: &[&str] = &[
    "os",
    "subprocess",
    "socket",
    "pickle",
    "shutil",
    "ctypes",
    "signal",
    "pty",
    "commands",
    "webbrowser",
    "tempfile",
    "pathlib",
    "io",
    "multiprocessing",
    "threading",
];

const DANGEROUS_BUILTINS: &[&str] = &[
    "eval(",
    "exec(",
    "open(",
    "__import__(",
    "compile(",
    "globals(",
    "locals(",
    "getattr(",
    "setattr(",
    "delattr(",
    "breakpoint(",
];

const DANGEROUS_ATTRIBUTES: &[&str] = &[
    ".system(",
    ".popen(",
    ".call(",
    ".run(",
    ".check_output(",
    ".check_call(",
    ".Popen(",
    ".connect(",
    ".write(",
    ".remove(",
    ".rmdir(",
    ".unlink(",
    ".rename(",
    ".mkdir(",
];

/// Check whether inline Python source appears safe to execute.
///
/// This is a heuristic check — it may have false positives (blocking safe code)
/// but should not have false negatives (allowing dangerous code).
#[must_use]
pub fn is_python_source_safe(source: &str) -> bool {
    !has_dangerous_imports(source)
        && !has_dangerous_builtins(source)
        && !has_dangerous_attributes(source)
}

fn has_dangerous_imports(source: &str) -> bool {
    for token in source.split([';', '\n']) {
        let trimmed = token.trim();
        // "import os" or "import os, subprocess"
        if let Some(rest) = trimmed.strip_prefix("import ") {
            for module in rest.split(',') {
                let name = module.split_whitespace().next().unwrap_or("");
                // Handle "import os.path" → check "os"
                let top_level = name.split('.').next().unwrap_or("");
                if DANGEROUS_IMPORTS.contains(&top_level) {
                    return true;
                }
            }
        }
        // "from os import system" or "from os.path import join"
        if let Some(rest) = trimmed.strip_prefix("from ")
            && let Some(module_part) = rest.split_whitespace().next()
        {
            let top_level = module_part.split('.').next().unwrap_or("");
            if DANGEROUS_IMPORTS.contains(&top_level) {
                return true;
            }
        }
    }
    false
}

fn has_dangerous_builtins(source: &str) -> bool {
    DANGEROUS_BUILTINS.iter().any(|b| source.contains(b))
}

fn has_dangerous_attributes(source: &str) -> bool {
    DANGEROUS_ATTRIBUTES.iter().any(|a| source.contains(a))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn print_is_safe() {
        assert!(is_python_source_safe("print(1)"));
    }

    #[test]
    fn simple_math_is_safe() {
        assert!(is_python_source_safe("x = 1 + 2; print(x)"));
    }

    #[test]
    fn json_import_is_safe() {
        assert!(is_python_source_safe("import json; print(json.dumps({}))"));
    }

    #[test]
    fn sys_import_is_safe() {
        assert!(is_python_source_safe("import sys; print(sys.version)"));
    }

    #[test]
    fn os_import_is_dangerous() {
        assert!(!is_python_source_safe("import os; os.system('rm -rf /')"));
    }

    #[test]
    fn subprocess_import_is_dangerous() {
        assert!(!is_python_source_safe("import subprocess"));
    }

    #[test]
    fn from_os_import_is_dangerous() {
        assert!(!is_python_source_safe("from os import system"));
    }

    #[test]
    fn from_os_path_import_is_dangerous() {
        assert!(!is_python_source_safe("from os.path import join"));
    }

    #[test]
    fn import_os_path_is_dangerous() {
        assert!(!is_python_source_safe("import os.path"));
    }

    #[test]
    fn eval_is_dangerous() {
        assert!(!is_python_source_safe("eval('code')"));
    }

    #[test]
    fn exec_is_dangerous() {
        assert!(!is_python_source_safe("exec('code')"));
    }

    #[test]
    fn open_is_dangerous() {
        assert!(!is_python_source_safe("open('file')"));
    }

    #[test]
    fn dunder_import_is_dangerous() {
        assert!(!is_python_source_safe("__import__('os')"));
    }

    #[test]
    fn compile_is_dangerous() {
        assert!(!is_python_source_safe("compile('code', '', 'exec')"));
    }

    #[test]
    fn attribute_system_is_dangerous() {
        assert!(!is_python_source_safe("foo.system('cmd')"));
    }

    #[test]
    fn attribute_popen_is_dangerous() {
        assert!(!is_python_source_safe("foo.popen('cmd')"));
    }

    #[test]
    fn attribute_connect_is_dangerous() {
        assert!(!is_python_source_safe("s.connect(('host', 80))"));
    }

    #[test]
    fn pickle_import_is_dangerous() {
        assert!(!is_python_source_safe("import pickle"));
    }

    #[test]
    fn socket_import_is_dangerous() {
        assert!(!is_python_source_safe("import socket"));
    }

    #[test]
    fn multiple_safe_imports() {
        assert!(is_python_source_safe(
            "import json, math, re; print(json.dumps({'a': math.pi}))"
        ));
    }

    #[test]
    fn mixed_safe_and_dangerous_imports() {
        assert!(!is_python_source_safe("import json, os"));
    }

    #[test]
    fn empty_source_is_safe() {
        assert!(is_python_source_safe(""));
    }

    #[test]
    fn string_operations_safe() {
        assert!(is_python_source_safe(
            "s = 'hello'; print(s.upper(), len(s))"
        ));
    }

    #[test]
    fn list_comprehension_safe() {
        assert!(is_python_source_safe("print([x**2 for x in range(10)])"));
    }

    #[test]
    fn breakpoint_is_dangerous() {
        assert!(!is_python_source_safe("breakpoint()"));
    }

    #[test]
    fn getattr_is_dangerous() {
        assert!(!is_python_source_safe("getattr(obj, 'method')"));
    }

    #[test]
    fn multiprocessing_is_dangerous() {
        assert!(!is_python_source_safe("import multiprocessing"));
    }
}
