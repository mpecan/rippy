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
mod git_subcommands;
mod helm;
mod mkdir;
mod node;
mod npm;
mod perl;
mod python;
mod python_tools;
mod ruby;
mod shell;
mod surface;
mod system;
mod task_runners;
mod text_tools;
mod unix_utils;

use std::collections::HashMap;
use std::path::Path;
use std::sync::LazyLock;

pub(crate) use surface::{AllowEntry, all_handler_surfaces};

use crate::verdict::AllowReason;

/// Context passed to handlers for classification.
pub(crate) struct HandlerContext<'a> {
    pub command_name: &'a str,
    pub args: &'a [String],
    pub working_directory: &'a Path,
    pub remote: bool,
    /// Whether this command receives piped stdin. Populated from the analyzer's
    /// pipeline state; reserved for handlers that need to gate on piped input
    /// (none read it yet).
    #[expect(dead_code, reason = "reserved: piped-input-aware handlers may read it")]
    pub receives_piped_input: bool,
    /// User-declared safe scopes: extra directories that path-based handlers
    /// (`cd`, `mkdir`, `git -C`) may enter/create in without prompting (from config).
    pub safe_scopes: &'a [std::path::PathBuf],
}

/// Maximum file size (64 KB) for `read_file` — prevents reading huge files.
const MAX_FILE_SIZE: u64 = 65_536;

impl HandlerContext<'_> {
    /// Get the first argument (typically a subcommand).
    pub(crate) fn subcommand(&self) -> &str {
        self.args.first().map_or("", String::as_str)
    }

    /// Get the Nth argument.
    pub(crate) fn arg(&self, n: usize) -> &str {
        self.args.get(n).map_or("", String::as_str)
    }

    /// Read a file's contents for informed classification.
    ///
    /// Returns `None` if the file can't be read (remote mode, missing,
    /// too large, binary, or outside the working directory).
    pub(crate) fn read_file(&self, path: &str) -> Option<String> {
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

    /// Construct a `HandlerContext` for unit tests with safe defaults.
    ///
    /// Defaults: `working_directory = /tmp`, `remote = false`,
    /// `receives_piped_input = false`, `safe_scopes = &[]`. Override any
    /// non-default field via struct-update syntax:
    /// `HandlerContext { remote: true, ..HandlerContext::test("cd", &args) }`.
    #[cfg(test)]
    pub(crate) fn test<'a>(command_name: &'a str, args: &'a [String]) -> HandlerContext<'a> {
        HandlerContext {
            command_name,
            args,
            working_directory: Path::new("/tmp"),
            remote: false,
            receives_piped_input: false,
            safe_scopes: &[],
        }
    }
}

/// The result of classifying a command.
#[derive(Debug, Clone)]
pub(crate) enum Classification {
    /// Auto-approve, carrying typed provenance (always
    /// [`AllowReason::Handler`] when minted by a handler).
    Allow(AllowReason),
    /// Needs user confirmation with description.
    Ask(String),
    /// Block with description. Wired to `Verdict::deny` in `apply_classification`;
    /// reserved for handlers that need to hard-block (none construct it yet).
    #[expect(
        dead_code,
        reason = "reserved: handlers may hard-deny; dispatch handles it"
    )]
    Deny(String),
    /// Re-parse and analyze this inner command string.
    Recurse(String),
    /// Analyze the inner command string, then take the most restrictive of that
    /// verdict and the outer command's own classification.
    ///
    /// For a wrapper that *delegates* (`sh -c`, `xargs`) plain [`Recurse`] is
    /// right: the wrapper adds no risk of its own. For a command that carries a
    /// second, independent risk alongside the program it spawns — `tar -xf`
    /// still unpacks a hostile archive whatever `--to-command` runs — replacing
    /// the outer verdict would let the extra flag *lower* the verdict (#198).
    RecurseAtLeast(String, Box<Self>),
    /// Re-parse inner command with remote=true (for docker exec, kubectl exec).
    RecurseRemote(String),
    /// Approve the command itself, but route these redirect targets through
    /// the redirect safety pipeline (self-protect, safe-dir, config rules).
    WithRedirects(AllowReason, Vec<String>),
}

/// Trait for command handlers.
pub(crate) trait Handler: Send + Sync {
    fn commands(&self) -> &[&str];
    fn classify(&self, ctx: &HandlerContext) -> Classification;

    /// Every invocation shape [`Handler::classify`] can approve
    /// (`Classification::Allow` or `WithRedirects`), as data.
    ///
    /// Rendered into `docs/allow-catalog.md`, so a widening of the approved set
    /// is visible as a documentation diff. Deliberately has no default
    /// implementation: a new handler must declare its surface to compile. A
    /// handler that only recurses or asks returns an empty vector.
    fn allow_surface(&self) -> Vec<AllowEntry>;
}

/// A data-driven handler for commands with simple subcommand-based classification.
pub(crate) struct SubcommandHandler {
    cmds: &'static [&'static str],
    safe: &'static [&'static str],
    ask: &'static [&'static str],
    desc_prefix: &'static str,
}

impl SubcommandHandler {
    #[must_use]
    pub(crate) const fn new(
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

        // Check --help/--version first (only when it is the sole argument).
        if is_sole_help_flag(ctx.args, &["--help", "-h", "--version", "-V"]) {
            return Classification::Allow(AllowReason::handler(format!(
                "{} help/version",
                self.desc_prefix
            )));
        }

        if self.safe.contains(&sub) {
            Classification::Allow(AllowReason::handler(desc))
        } else if self.ask.contains(&sub) {
            Classification::Ask(desc)
        } else if sub.is_empty() {
            Classification::Ask(format!("{} (no subcommand)", self.desc_prefix))
        } else {
            Classification::Ask(desc)
        }
    }

    fn allow_surface(&self) -> Vec<AllowEntry> {
        let cmd = self.cmds.first().copied().unwrap_or(self.desc_prefix);
        let mut entries = surface::subcommands(cmd, self.safe);
        entries.push(AllowEntry::guarded(
            format!("{cmd} --help|-h|--version|-V"),
            "sole argument",
        ));
        entries
    }
}

/// Look up a handler by command name.
#[must_use]
pub(crate) fn get_handler(command_name: &str) -> Option<&'static dyn Handler> {
    HANDLER_REGISTRY.get(command_name).copied()
}

/// Return the number of registered handler command names.
#[must_use]
pub(crate) fn handler_count() -> usize {
    HANDLER_REGISTRY.len()
}

/// Return all handler-registered command names, sorted alphabetically.
#[must_use]
pub(crate) fn all_handler_commands() -> Vec<&'static str> {
    let mut cmds: Vec<_> = HANDLER_REGISTRY.keys().copied().collect();
    cmds.sort_unstable();
    cmds
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
        &node::NODE_HANDLER,
        &perl::PERL_HANDLER,
        &python::PYTHON_HANDLER,
        &ruby::RUBY_HANDLER,
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
        &python_tools::UV_HANDLER,
        &unix_utils::GZIP_HANDLER,
        &unix_utils::UNZIP_HANDLER,
        &unix_utils::SEVENZIP_HANDLER,
        &unix_utils::MKTEMP_HANDLER,
        &unix_utils::TEE_HANDLER,
        &unix_utils::SORT_HANDLER,
        &unix_utils::OPEN_HANDLER,
        &unix_utils::YQ_HANDLER,
        &unix_utils::DOS2UNIX_HANDLER,
        &python_tools::RUFF_HANDLER,
        &python_tools::BLACK_HANDLER,
        &system::FD_HANDLER,
        &system::DMESG_HANDLER,
        &system::IP_HANDLER,
        &system::IFCONFIG_HANDLER,
        &ansible::ANSIBLE_HANDLER,
        &task_runners::JUST_HANDLER,
        &task_runners::MISE_HANDLER,
        &task_runners::TOKF_HANDLER,
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
pub(crate) fn has_flag(args: &[String], flags: &[&str]) -> bool {
    args.iter().any(|a| flags.contains(&a.as_str()))
}

/// Helper: true only when a help/version flag is the command's SOLE argument.
///
/// SECURITY: help/version flags must NOT be matched anywhere in argv. Many
/// commands overload short flags (`docker -h` is `--hostname`, not `--help`) or
/// consume the next token as a value (`git commit -m --version`), so scanning
/// argv for a help flag and short-circuiting to Allow lets a dangerous operand
/// ride along auto-approved (see #149). A lone help/version flag is genuinely
/// inert everywhere; combined with any other argument it must never pre-empt
/// evaluation of the rest of the command.
pub(crate) fn is_sole_help_flag(args: &[String], flags: &[&str]) -> bool {
    args.len() == 1 && flags.contains(&args[0].as_str())
}

/// Helper: get the first positional argument (non-flag).
pub(crate) fn first_positional(args: &[String]) -> Option<&str> {
    args.iter()
        .find(|a| !a.starts_with('-'))
        .map(String::as_str)
}

/// Helper: collect all positional (non-flag) arguments.
pub(crate) fn positional_args(args: &[String]) -> Vec<&str> {
    args.iter()
        .filter(|a| !a.starts_with('-'))
        .map(String::as_str)
        .collect()
}

/// Helper: get the value following a flag (e.g., `-o output.txt` → `Some("output.txt")`).
pub(crate) fn get_flag_value(args: &[String], flags: &[&str]) -> Option<String> {
    for (i, arg) in args.iter().enumerate() {
        if flags.contains(&arg.as_str()) {
            return args.get(i + 1).cloned();
        }
    }
    None
}

/// Helper: check if any arg matches a flag exactly OR as its `flag=value` form.
///
/// `has_flag`/`get_flag_value` only match space-separated tokens, so
/// `--use-compress-program=sh` or `--output=/tmp/x` slip past them. This
/// catches both forms without matching an unrelated longer flag name
/// (`--foo=bar` matches `--foo`, not `--foobar`).
pub(crate) fn has_flag_or_prefixed(args: &[String], flags: &[&str]) -> bool {
    args.iter().any(|a| {
        flags
            .iter()
            .any(|f| a == f || a.strip_prefix(f).is_some_and(|rest| rest.starts_with('=')))
    })
}

/// Helper: check if any arg matches a short (single-dash, two-char) flag glued
/// directly to its value with no separator (getopt's `-Ivalue`, e.g. tar's
/// `-Ish` for `--use-compress-program=sh`).
///
/// `has_flag_or_prefixed` only catches the `flag=value` form, so a glued short
/// option slips past it. This is restricted to two-char flags (`-I`, `-F`) —
/// long options never take a glued value without `=` — so it cannot swallow
/// an unrelated longer flag.
pub(crate) fn has_glued_short_flag(args: &[String], flags: &[&str]) -> bool {
    args.iter().any(|a| {
        flags
            .iter()
            .any(|f| f.len() == 2 && a.starts_with(f) && a.len() > f.len())
    })
}

/// Helper: collect the values following every occurrence of a flag.
///
/// Interpreters like Perl accept multiple `-e`/`-E` fragments and concatenate
/// them at runtime, so analyzing only the first occurrence (`get_flag_value`)
/// misses dangerous code hidden in a later fragment.
pub(crate) fn get_flag_values(args: &[String], flags: &[&str]) -> Vec<String> {
    let mut values = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if flags.contains(&args[i].as_str()) {
            if let Some(value) = args.get(i + 1) {
                values.push(value.clone());
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    values
}

/// Helper: collect the value of every occurrence of a flag, in the separated
/// (`-c sql`), `flag=value` and glued-short (`-csql`) spellings.
///
/// Cumulative value flags such as psql's `-c` and mysql's `-e` run every
/// occurrence, so reading only the first one (`get_flag_value`) lets a
/// read-only leading statement launder a write in a later one (#199). The
/// glued spellings have to be collected too, or the same laundering works
/// through `--command=…`.
pub(crate) fn get_all_flag_values(args: &[String], flags: &[&str]) -> Vec<String> {
    let mut values = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if flags.contains(&args[i].as_str()) {
            if let Some(value) = args.get(i + 1) {
                values.push(value.clone());
            }
            i += 2;
            continue;
        }
        if let Some(value) = glued_flag_value(&args[i], flags) {
            values.push(value.to_string());
        }
        i += 1;
    }
    values
}

/// The value glued to a flag inside a single argument, if any.
///
/// getopt lets a short option carry its value with no separator (`-cSQL`);
/// a long option only ever takes `=`, so the separator-less form is restricted
/// to two-char flags and cannot swallow an unrelated longer flag name.
fn glued_flag_value<'a>(arg: &'a str, flags: &[&str]) -> Option<&'a str> {
    flags.iter().find_map(|flag| {
        let rest = arg.strip_prefix(flag).filter(|rest| !rest.is_empty())?;
        rest.strip_prefix('=')
            .or_else(|| (flag.len() == 2 && !flag.starts_with("--")).then_some(rest))
    })
}

/// Default directories that are always considered safe for path-based handlers.
///
/// The `/private/...` entries are the macOS canonical locations for `/tmp` and
/// `/var/tmp`. rippy normalizes paths logically (no symlink resolution), so a
/// literal `/private/tmp/...` target — e.g. the session scratchpad — would not
/// otherwise match `/tmp`.
pub(crate) const SAFE_DIRECTORIES: &[&str] =
    &["/tmp", "/var/tmp", "/private/tmp", "/private/var/tmp"];

/// Logical path normalization: resolve `.` and `..` components without
/// filesystem access (the target directory may not exist yet).
pub(crate) fn normalize_path(path: &Path) -> std::path::PathBuf {
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
/// a user-declared safe scope, or a default safe directory.
///
/// Both `path` and `normalized_cwd` must already be normalized.
/// `safe_scopes` are expanded and normalized at config load time.
///
/// Matching uses `Path::starts_with`, which respects path-component
/// boundaries: a scope of `/opt/repos` matches `/opt/repos/x` but NOT the
/// sibling `/opt/repos-evil`. Do not replace this with string `starts_with`.
pub(crate) fn is_within_scope(
    path: &Path,
    normalized_cwd: &Path,
    safe_scopes: &[std::path::PathBuf],
) -> bool {
    path.starts_with(normalized_cwd) || is_within_safe_dir(path, safe_scopes)
}

/// Check if a resolved, normalized path is within a user-declared safe scope or
/// a default safe directory — but NOT the working directory.
///
/// This is the trusted-write set: unlike [`is_within_scope`], it deliberately
/// excludes the cwd so redirect targets (`>`, `>>`) inside the project keep
/// asking, while `/tmp`, `/var/tmp` (and their `/private` equivalents) plus any
/// declared scope are auto-approved.
///
/// Matching uses `Path::starts_with`, which respects path-component boundaries
/// (see [`is_within_scope`]). `safe_scopes` are expanded and normalized at
/// config load time.
pub(crate) fn is_within_safe_dir(path: &Path, safe_scopes: &[std::path::PathBuf]) -> bool {
    if safe_scopes.iter().any(|d| path.starts_with(d)) {
        return true;
    }

    is_within_default_safe_dir(path)
}

/// Check if a normalized path is within one of the built-in [`SAFE_DIRECTORIES`]
/// (`/tmp`, `/var/tmp`, …) — the world-writable defaults, ignoring any declared
/// scopes.
///
/// Callers that auto-approve writes use this to apply extra symlink hardening
/// to the world-writable defaults without subjecting user-declared scopes (which
/// are trusted opt-ins) to the same re-check.
#[must_use]
pub(crate) fn is_within_default_safe_dir(path: &Path) -> bool {
    SAFE_DIRECTORIES.iter().any(|safe| path.starts_with(safe))
}

#[cfg(test)]
#[expect(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn has_flag_or_prefixed_matches_bare_and_equals_form() {
        let flags = ["--foo"];
        let args = |s: &str| vec![s.to_string()];

        assert!(has_flag_or_prefixed(&args("--foo"), &flags));
        assert!(has_flag_or_prefixed(&args("--foo=bar"), &flags));
        assert!(!has_flag_or_prefixed(&args("--foobar"), &flags));
        assert!(!has_flag_or_prefixed(&args("--foobar=x"), &flags));
        assert!(!has_flag_or_prefixed(&args("--other"), &flags));
    }

    #[test]
    fn has_glued_short_flag_matches_attached_value_only() {
        let flags = ["-I", "-F"];
        let args = |s: &str| vec![s.to_string()];

        assert!(has_glued_short_flag(&args("-Ish"), &flags));
        assert!(has_glued_short_flag(&args("-I/bin/sh"), &flags));
        assert!(has_glued_short_flag(&args("-Fscript"), &flags));
        assert!(!has_glued_short_flag(&args("-I"), &flags));
        assert!(!has_glued_short_flag(&args("-i"), &flags));
        assert!(!has_glued_short_flag(&args("--info-script"), &flags));
    }

    #[test]
    fn is_within_scope_respects_component_boundary() {
        let cwd = Path::new("/project");
        let scopes = [std::path::PathBuf::from("/opt/repos")];
        // Sibling dir sharing a string prefix must NOT match.
        assert!(!is_within_scope(Path::new("/opt/repos-evil"), cwd, &scopes));
        assert!(!is_within_scope(
            Path::new("/opt/repos-evil/x"),
            cwd,
            &scopes
        ));
        // Exact scope and children DO match.
        assert!(is_within_scope(Path::new("/opt/repos"), cwd, &scopes));
        assert!(is_within_scope(Path::new("/opt/repos/x"), cwd, &scopes));
    }

    #[test]
    fn is_within_safe_dir_matches_default_and_scope_but_not_cwd() {
        let scopes = [std::path::PathBuf::from("/opt/repos")];
        // Default safe dirs (including macOS /private equivalents) and a scope.
        assert!(is_within_safe_dir(Path::new("/tmp/out.txt"), &scopes));
        assert!(is_within_safe_dir(Path::new("/private/tmp/x/log"), &scopes));
        assert!(is_within_safe_dir(Path::new("/var/tmp/y"), &scopes));
        assert!(is_within_safe_dir(Path::new("/opt/repos/other/f"), &scopes));
        // cwd is NOT safe, and a sibling sharing a string prefix must NOT match.
        assert!(!is_within_safe_dir(Path::new("/project/out.txt"), &scopes));
        assert!(!is_within_safe_dir(Path::new("/tmpevil/x"), &scopes));
        assert!(!is_within_safe_dir(Path::new("/opt/repos-evil/x"), &scopes));
    }

    #[test]
    fn is_sole_help_flag_only_fires_for_lone_flag() {
        let flags = &["--help", "-h", "--version"];
        // Sole help/version flag -> true.
        assert!(is_sole_help_flag(&["--help".into()], flags));
        assert!(is_sole_help_flag(&["--version".into()], flags));
        assert!(is_sole_help_flag(&["-h".into()], flags));
        // Help flag with any companion operand -> false (must not short-circuit).
        assert!(!is_sole_help_flag(
            &["--help".into(), "--danger".into()],
            flags
        ));
        assert!(!is_sole_help_flag(
            &["run".into(), "-h".into(), "host".into()],
            flags
        ));
        assert!(!is_sole_help_flag(
            &["--version".into(), "-e".into(), "code".into()],
            flags
        ));
        // No help flag at all, or empty -> false.
        assert!(!is_sole_help_flag(&["status".into()], flags));
        assert!(!is_sole_help_flag(&[], flags));
    }

    #[test]
    fn read_file_returns_none_when_remote() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.txt");
        std::fs::write(&file, "hello").unwrap();
        let ctx = HandlerContext {
            working_directory: dir.path(),
            remote: true,
            ..HandlerContext::test("test", &[])
        };
        assert!(ctx.read_file("test.txt").is_none());
    }

    #[test]
    fn read_file_returns_none_for_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = HandlerContext {
            working_directory: dir.path(),
            ..HandlerContext::test("test", &[])
        };
        assert!(ctx.read_file("nonexistent.txt").is_none());
    }

    #[test]
    fn read_file_reads_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.txt");
        std::fs::write(&file, "hello world").unwrap();
        let ctx = HandlerContext {
            working_directory: dir.path(),
            ..HandlerContext::test("test", &[])
        };
        assert_eq!(ctx.read_file("test.txt").unwrap(), "hello world");
    }

    #[test]
    fn read_file_rejects_path_outside_working_dir() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = HandlerContext {
            working_directory: dir.path(),
            ..HandlerContext::test("test", &[])
        };
        assert!(ctx.read_file("../../etc/passwd").is_none());
    }

    #[test]
    fn read_file_rejects_oversized_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("big.txt");
        #[expect(clippy::cast_possible_truncation)]
        let content = "x".repeat(MAX_FILE_SIZE as usize + 1);
        std::fs::write(&file, content).unwrap();
        let ctx = HandlerContext {
            working_directory: dir.path(),
            ..HandlerContext::test("test", &[])
        };
        assert!(ctx.read_file("big.txt").is_none());
    }
}
