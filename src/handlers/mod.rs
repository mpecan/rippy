mod ansible;
mod cd;
mod cloud;
mod curl;
mod database;
mod docker;
mod env_xargs;
mod find;
mod gh;
mod git;
mod helm;
mod mkdir;
mod npm;
mod packaging;
mod python;
mod shell;
mod system;
mod text_tools;
mod unix_utils;

use std::collections::HashMap;
use std::path::Path;
use std::sync::LazyLock;

use crate::verdict::Decision;

/// Context passed to handlers for classification.
pub struct HandlerContext<'a> {
    pub command_name: &'a str,
    pub args: &'a [String],
    pub working_directory: &'a Path,
    pub remote: bool,
    pub receives_piped_input: bool,
    /// Extra directories that `cd` is allowed to navigate to (from config).
    pub cd_allowed_dirs: &'a [std::path::PathBuf],
}

/// Maximum file size (64 KB) for `read_file` — prevents reading huge files.
const MAX_FILE_SIZE: u64 = 65_536;

impl HandlerContext<'_> {
    /// Get the first argument (typically a subcommand).
    pub fn subcommand(&self) -> &str {
        self.args.first().map_or("", String::as_str)
    }

    /// Get the Nth argument.
    pub fn arg(&self, n: usize) -> &str {
        self.args.get(n).map_or("", String::as_str)
    }

    /// Read a file's contents for informed classification.
    ///
    /// Returns `None` if the file can't be read (remote mode, missing,
    /// too large, binary, or outside the working directory).
    pub fn read_file(&self, path: &str) -> Option<String> {
        if self.remote {
            return None;
        }
        let file_path = self.working_directory.join(path);
        let canonical = file_path.canonicalize().ok()?;
        let cwd_canonical = self.working_directory.canonicalize().ok()?;
        if !canonical.starts_with(&cwd_canonical) {
            return None;
        }
        let metadata = std::fs::metadata(&canonical).ok()?;
        if metadata.len() > MAX_FILE_SIZE {
            return None;
        }
        std::fs::read_to_string(&canonical).ok()
    }
}

/// The result of classifying a command.
#[derive(Debug, Clone)]
pub enum Classification {
    /// Auto-approve with description.
    Allow(String),
    /// Needs user confirmation with description.
    Ask(String),
    /// Block with description.
    Deny(String),
    /// Re-parse and analyze this inner command string.
    Recurse(String),
    /// Re-parse inner command with remote=true (for docker exec, kubectl exec).
    RecurseRemote(String),
    /// Decision with redirect targets that need config rule checking.
    WithRedirects(Decision, String, Vec<String>),
}

/// Trait for command handlers.
pub trait Handler: Send + Sync {
    fn commands(&self) -> &[&str];
    fn classify(&self, ctx: &HandlerContext) -> Classification;
}

/// A data-driven handler for commands with simple subcommand-based classification.
pub struct SubcommandHandler {
    cmds: &'static [&'static str],
    safe: &'static [&'static str],
    ask: &'static [&'static str],
    desc_prefix: &'static str,
}

impl SubcommandHandler {
    #[must_use]
    pub const fn new(
        cmds: &'static [&'static str],
        safe: &'static [&'static str],
        ask: &'static [&'static str],
        desc_prefix: &'static str,
    ) -> Self {
        Self {
            cmds,
            safe,
            ask,
            desc_prefix,
        }
    }
}

impl Handler for SubcommandHandler {
    fn commands(&self) -> &[&str] {
        self.cmds
    }

    fn classify(&self, ctx: &HandlerContext) -> Classification {
        let sub = ctx.args.first().map_or("", String::as_str);
        let desc = format!("{} {sub}", self.desc_prefix);

        // Check --help/--version first
        if ctx
            .args
            .iter()
            .any(|a| a == "--help" || a == "-h" || a == "--version" || a == "-V")
        {
            return Classification::Allow(format!("{} help/version", self.desc_prefix));
        }

        if self.safe.contains(&sub) {
            Classification::Allow(desc)
        } else if self.ask.contains(&sub) {
            Classification::Ask(desc)
        } else if sub.is_empty() {
            Classification::Ask(format!("{} (no subcommand)", self.desc_prefix))
        } else {
            Classification::Ask(desc)
        }
    }
}

/// Look up a handler by command name.
#[must_use]
pub fn get_handler(command_name: &str) -> Option<&'static dyn Handler> {
    HANDLER_REGISTRY.get(command_name).copied()
}

/// Return the number of registered handler command names.
#[must_use]
pub fn handler_count() -> usize {
    HANDLER_REGISTRY.len()
}

static HANDLER_REGISTRY: LazyLock<HashMap<&'static str, &'static dyn Handler>> =
    LazyLock::new(build_registry);

fn build_registry() -> HashMap<&'static str, &'static dyn Handler> {
    // NOTE: Pure classification handlers (simple.rs, file_ops.rs, dangerous.rs) have been
    // migrated to stdlib config rules. Only behavioral handlers remain here.
    let handlers: Vec<&'static dyn Handler> = vec![
        &cd::CD_HANDLER,
        &mkdir::MKDIR_HANDLER,
        &git::GIT_HANDLER,
        &docker::DOCKER_HANDLER,
        &python::PYTHON_HANDLER,
        &shell::SHELL_HANDLER,
        &find::FIND_HANDLER,
        &curl::CURL_HANDLER,
        &npm::NPM_HANDLER,
        &helm::HELM_HANDLER,
        &gh::GH_HANDLER,
        &cloud::KUBECTL_HANDLER,
        &cloud::AWS_HANDLER,
        &cloud::GCLOUD_HANDLER,
        &cloud::AZ_HANDLER,
        &database::PSQL_HANDLER,
        &database::MYSQL_HANDLER,
        &database::SQLITE3_HANDLER,
        &text_tools::SED_HANDLER,
        &text_tools::AWK_HANDLER,
        &env_xargs::ENV_HANDLER,
        &env_xargs::XARGS_HANDLER,
        &unix_utils::TAR_HANDLER,
        &unix_utils::WGET_HANDLER,
        &packaging::UV_HANDLER,
        &unix_utils::GZIP_HANDLER,
        &unix_utils::UNZIP_HANDLER,
        &unix_utils::MKTEMP_HANDLER,
        &unix_utils::TEE_HANDLER,
        &unix_utils::SORT_HANDLER,
        &unix_utils::OPEN_HANDLER,
        &unix_utils::YQ_HANDLER,
        &packaging::RUFF_HANDLER,
        &packaging::BLACK_HANDLER,
        &system::FD_HANDLER,
        &system::DMESG_HANDLER,
        &system::IP_HANDLER,
        &system::IFCONFIG_HANDLER,
        &ansible::ANSIBLE_HANDLER,
    ];

    let mut map = HashMap::new();
    for handler in handlers {
        for cmd in handler.commands() {
            map.insert(*cmd, handler);
        }
    }
    map
}

/// Helper: check if any arg matches a set of flags.
pub fn has_flag(args: &[String], flags: &[&str]) -> bool {
    args.iter().any(|a| flags.contains(&a.as_str()))
}

/// Helper: get the first positional argument (non-flag).
pub fn first_positional(args: &[String]) -> Option<&str> {
    args.iter()
        .find(|a| !a.starts_with('-'))
        .map(String::as_str)
}

/// Helper: collect all positional (non-flag) arguments.
pub fn positional_args(args: &[String]) -> Vec<&str> {
    args.iter()
        .filter(|a| !a.starts_with('-'))
        .map(String::as_str)
        .collect()
}

/// Helper: get the value following a flag (e.g., `-o output.txt` → `Some("output.txt")`).
pub fn get_flag_value(args: &[String], flags: &[&str]) -> Option<String> {
    for (i, arg) in args.iter().enumerate() {
        if flags.contains(&arg.as_str()) {
            return args.get(i + 1).cloned();
        }
    }
    None
}

/// Default directories that are always considered safe for path-based handlers.
pub const SAFE_DIRECTORIES: &[&str] = &["/tmp", "/var/tmp"];

/// Logical path normalization: resolve `.` and `..` components without
/// filesystem access (the target directory may not exist yet).
pub fn normalize_path(path: &Path) -> std::path::PathBuf {
    let mut result = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                result.pop();
            }
            other => result.push(other),
        }
    }
    result
}

/// Check if a resolved, normalized path is within the working directory,
/// a config-allowed directory, or a default safe directory.
///
/// Both `path` and `normalized_cwd` must already be normalized.
/// `allowed_dirs` are normalized at config load time.
pub fn is_within_scope(
    path: &Path,
    normalized_cwd: &Path,
    allowed_dirs: &[std::path::PathBuf],
) -> bool {
    if path.starts_with(normalized_cwd) {
        return true;
    }

    if allowed_dirs.iter().any(|d| path.starts_with(d)) {
        return true;
    }

    SAFE_DIRECTORIES.iter().any(|safe| path.starts_with(safe))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn ctx_with_dir(dir: &Path, remote: bool) -> HandlerContext<'_> {
        HandlerContext {
            command_name: "test",
            args: &[],
            working_directory: dir,
            remote,
            receives_piped_input: false,
            cd_allowed_dirs: &[],
        }
    }

    #[test]
    fn read_file_returns_none_when_remote() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.txt");
        std::fs::write(&file, "hello").unwrap();
        let ctx = ctx_with_dir(dir.path(), true);
        assert!(ctx.read_file("test.txt").is_none());
    }

    #[test]
    fn read_file_returns_none_for_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_with_dir(dir.path(), false);
        assert!(ctx.read_file("nonexistent.txt").is_none());
    }

    #[test]
    fn read_file_reads_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.txt");
        std::fs::write(&file, "hello world").unwrap();
        let ctx = ctx_with_dir(dir.path(), false);
        assert_eq!(ctx.read_file("test.txt").unwrap(), "hello world");
    }

    #[test]
    fn read_file_rejects_path_outside_working_dir() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_with_dir(dir.path(), false);
        assert!(ctx.read_file("../../etc/passwd").is_none());
    }

    #[test]
    fn read_file_rejects_oversized_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("big.txt");
        #[allow(clippy::cast_possible_truncation)]
        let content = "x".repeat(MAX_FILE_SIZE as usize + 1);
        std::fs::write(&file, content).unwrap();
        let ctx = ctx_with_dir(dir.path(), false);
        assert!(ctx.read_file("big.txt").is_none());
    }
}
