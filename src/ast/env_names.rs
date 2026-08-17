//! Which environment variable names can change what a following command runs.
//!
//! Split from `ast.rs` for the 700-line cap; see
//! docs/security-invariants.md#dangerous-env-name.

/// Environment variable names whose values can change how a following command
/// loads or resolves code, letting a *literal* assignment turn an otherwise-safe
/// command into arbitrary code execution (e.g. `LD_PRELOAD`, `BASH_ENV`,
/// `GIT_SSH_COMMAND`). The analyzer's assignment-name gate Asks on any command
/// carrying such a prefix, and [`strip_env_prefix`] refuses to strip it so a
/// string-layer allow rule cannot mask it either.
///
/// Matching is by *capability family* rather than by member wherever a family
/// can be named: a flag guard always has an env twin, and enumerating twins one
/// at a time loses the race (#203). See
/// docs/security-invariants.md#dangerous-env-name for the rationale.
#[must_use]
pub(crate) fn is_dangerous_env_name(name: &str) -> bool {
    // Dynamic-linker families: Linux `LD_*` (LD_PRELOAD, LD_LIBRARY_PATH,
    // LD_AUDIT, ...) and macOS `DYLD_*` (DYLD_INSERT_LIBRARIES, ...).
    if name.starts_with("LD_") || name.starts_with("DYLD_") {
        return true;
    }
    // GIT_CONFIG* = env-based git-config injection; BASH_FUNC_* = exported
    // function injection. see docs/security-invariants.md#dangerous-env-name
    if name.starts_with("GIT_CONFIG") || name.starts_with("BASH_FUNC_") {
        return true;
    }
    // ANSIBLE_*_PLUGINS point ansible at an attacker-chosen directory it then
    // imports Python from — the env route to what `ansible-doc -M` does (#185).
    if name.starts_with("ANSIBLE_") && name.ends_with("_PLUGINS") {
        return true;
    }
    if redirects_lookup(name) || is_tool_hook(name) || is_active_git_var(name) {
        return true;
    }
    matches!(
        name,
        "BASH_ENV"
            | "ENV"
            | "SHELLOPTS"
            | "BASHOPTS"
            | "IFS"
            | "PS4"
            | "GIT_SSH"
            | "GIT_SSH_COMMAND"
            | "GIT_EXTERNAL_DIFF"
            | "GIT_PAGER"
            | "PAGER"
            | "EDITOR"
            | "VISUAL"
            | "PERL5OPT"
            | "PERL5LIB"
            | "PYTHONSTARTUP"
            | "PYTHONPATH"
            | "NODE_OPTIONS"
            | "RUBYOPT"
            | "ANSIBLE_CONFIG"
            | "ANSIBLE_LIBRARY"
            | "ANSIBLE_MODULE_UTILS"
    )
}

/// Names that decide *where a command's binary or configuration comes from*,
/// for every command rather than one tool. `PATH=/tmp/evil git status` runs an
/// attacker's `git`; `HOME`/`XDG_CONFIG_HOME` do the same one level down, by
/// choosing the config file that names a hook to run (`core.fsmonitor`).
fn redirects_lookup(name: &str) -> bool {
    matches!(
        name,
        "PATH"
            | "HOME"
            | "SHELL"
            | "XDG_CONFIG_HOME"
            | "XDG_CONFIG_DIRS"
            | "XDG_DATA_HOME"
            | "XDG_DATA_DIRS"
    )
}

/// Suffixes a tool uses to mean "run this program" or "add these flags".
///
/// A suffix rather than a list because the shape is a convention, not a set:
/// `TAR_OPTIONS` and `JAVA_TOOL_OPTIONS` inject argv into a tool that never
/// saw a flag guard, and the next tool to invent one will spell it the same
/// way. `GIT_PROXY_COMMAND` and `GIT_SSH_COMMAND` are the same idea for
/// programs.
fn is_tool_hook(name: &str) -> bool {
    const HOOK_SUFFIXES: &[&str] = &[
        "_COMMAND", "_OPTIONS", "_OPTS", "_EDITOR", "_PAGER", "_ASKPASS", "_WRAPPER",
    ];
    HOOK_SUFFIXES.iter().any(|s| name.ends_with(s))
}

/// Git owns the whole `GIT_*` namespace and nearly every member of it changes
/// what git reads or runs, so the polarity is inverted here: dangerous unless
/// the name is known inert. Enumerating the dangerous ones is what let
/// `GIT_DIR`, `GIT_EXEC_PATH` and `GIT_ALTERNATE_OBJECT_DIRECTORIES` through.
fn is_active_git_var(name: &str) -> bool {
    const INERT: &[&str] = &[
        "GIT_AUTHOR_NAME",
        "GIT_AUTHOR_EMAIL",
        "GIT_AUTHOR_DATE",
        "GIT_COMMITTER_NAME",
        "GIT_COMMITTER_EMAIL",
        "GIT_COMMITTER_DATE",
        "GIT_TERMINAL_PROMPT",
        "GIT_ADVICE",
        "GIT_MERGE_AUTOEDIT",
        "GIT_NOTES_REF",
        "GIT_REFLOG_ACTION",
    ];
    name.starts_with("GIT_") && !INERT.contains(&name)
}
