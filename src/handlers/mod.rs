mod cloud;
mod curl;
mod dangerous;
mod database;
mod docker;
mod file_ops;
mod find;
mod gh;
mod git;
mod misc;
mod npm;
mod python;
mod shell;
mod simple;
mod system;
mod text_tools;

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
}

impl HandlerContext<'_> {
    /// Get the first argument (typically a subcommand).
    pub fn subcommand(&self) -> &str {
        self.args.first().map_or("", String::as_str)
    }

    /// Get the Nth argument.
    pub fn arg(&self, n: usize) -> &str {
        self.args.get(n).map_or("", String::as_str)
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

static HANDLER_REGISTRY: LazyLock<HashMap<&'static str, &'static dyn Handler>> =
    LazyLock::new(build_registry);

fn build_registry() -> HashMap<&'static str, &'static dyn Handler> {
    let handlers: Vec<&'static dyn Handler> = vec![
        &git::GIT_HANDLER,
        &docker::DOCKER_HANDLER,
        &python::PYTHON_HANDLER,
        &shell::SHELL_HANDLER,
        &find::FIND_HANDLER,
        &curl::CURL_HANDLER,
        &npm::NPM_HANDLER,
        &simple::CARGO_HANDLER,
        &simple::BREW_HANDLER,
        &simple::PIP_HANDLER,
        &simple::TERRAFORM_HANDLER,
        &simple::HELM_HANDLER,
        &simple::PYTEST_HANDLER,
        &gh::GH_HANDLER,
        &simple::MAKE_HANDLER,
        &simple::RUSTUP_HANDLER,
        &simple::OPENSSL_HANDLER,
        &cloud::KUBECTL_HANDLER,
        &cloud::AWS_HANDLER,
        &cloud::GCLOUD_HANDLER,
        &cloud::AZ_HANDLER,
        &database::PSQL_HANDLER,
        &database::MYSQL_HANDLER,
        &database::SQLITE3_HANDLER,
        &file_ops::FILE_OPS_HANDLER,
        &text_tools::SED_HANDLER,
        &text_tools::AWK_HANDLER,
        &misc::ENV_HANDLER,
        &misc::XARGS_HANDLER,
        &misc::TAR_HANDLER,
        &misc::WGET_HANDLER,
        &misc::UV_HANDLER,
        &misc::GZIP_HANDLER,
        &misc::UNZIP_HANDLER,
        &misc::MKTEMP_HANDLER,
        &misc::TEE_HANDLER,
        &misc::SORT_HANDLER,
        &misc::OPEN_HANDLER,
        &misc::YQ_HANDLER,
        &misc::RUFF_HANDLER,
        &misc::BLACK_HANDLER,
        &dangerous::DANGEROUS_BUILTINS_HANDLER,
        &dangerous::SUDO_HANDLER,
        &dangerous::SSH_HANDLER,
        &dangerous::INTERPRETER_HANDLER,
        &dangerous::PACKAGE_MANAGER_HANDLER,
        &system::FD_HANDLER,
        &system::DMESG_HANDLER,
        &system::IP_HANDLER,
        &system::IFCONFIG_HANDLER,
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
