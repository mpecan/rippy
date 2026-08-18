//! Which environment variable names can change what a following command runs.
//!
//! Split from `ast.rs` for the 700-line cap; see
//! docs/security-invariants.md#dangerous-env-name.

use rable::Node;

use super::{append_assignment_name, has_expansions, literal_assignment};

/// Whether a literal `NAME=VALUE` prefix can change how the following command
/// loads or resolves code.
///
/// **The polarity is inverted: dangerous unless known inert.** Enumerating
/// dangerous names does not converge (#203). Every tool invents its own
/// variable for "where my config lives" or "which program to run", and each one
/// is a twin of a flag guard: `--exec-path`/`GIT_EXEC_PATH`,
/// `--use-compress-program`/`TAR_OPTIONS`, `--pager`/`MANPAGER`. Two rounds of
/// enumeration each shipped, and each was then shown to miss a dozen more —
/// `CARGO_HOME`, `RUSTC`, `RUSTFLAGS`, `KUBECONFIG`, `PSQLRC`, `PERLLIB`,
/// `PYTHONHOME`, `NODE_PATH`, `LESSOPEN`, `DOCKER_CONFIG`, and so on. The list
/// of names that are *harmless* is the one that can actually be closed, because
/// it is a property of the name rather than of every tool that might read it.
///
/// An unknown name therefore Asks. That is one prompt for a variable rippy has
/// not seen, against silent arbitrary code execution for every variable it has
/// not seen.
#[must_use]
pub(crate) fn is_dangerous_env_name(name: &str) -> bool {
    !is_inert(name)
}

/// Names that cannot select a program, a library path, or a config file that
/// names either. Everything here is data a command reads *about* its run —
/// locale, verbosity, identity, terminal geometry.
///
/// Adding a name is widening rippy's auto-approved surface, so it needs the
/// same bar as any other allow: it must be inert for *every* command, not just
/// the one that prompted it. `PAGER`, `EDITOR`, `TMPDIR`, `MAKEFLAGS` and the
/// proxy variables all look harmless and are not.
fn is_inert(name: &str) -> bool {
    // A closed POSIX set; `LOCPATH` (where locales *load from*) is not in it.
    if name.starts_with("LC_") {
        return true;
    }
    INERT_NAMES.contains(&name)
}

/// see [`is_inert`] for the bar a new entry has to clear.
const INERT_NAMES: &[&str] = &[
    // Locale and time.
    "LANG",
    "LANGUAGE",
    "TZ",
    // Terminal presentation. `TERMINFO`/`TERMCAP` — where terminal
    // descriptions load from — are dangerous and absent by design.
    "TERM",
    "COLUMNS",
    "LINES",
    "NO_COLOR",
    "FORCE_COLOR",
    "CLICOLOR",
    "CLICOLOR_FORCE",
    // Verbosity and diagnostics.
    "RUST_LOG",
    "RUST_BACKTRACE",
    "LOG_LEVEL",
    "VERBOSE",
    "DEBUG",
    "QUIET",
    // Environment markers a program branches on but does not execute.
    "CI",
    "CONTINUOUS_INTEGRATION",
    "DEBIAN_FRONTEND",
    "NODE_ENV",
    "RAILS_ENV",
    "RACK_ENV",
    "APP_ENV",
    "ENVIRONMENT",
    "SOURCE_DATE_EPOCH",
    "CARGO_TERM_COLOR",
    // Interpreter behaviour that adds no load path and runs no hook.
    "PYTHONDONTWRITEBYTECODE",
    "PYTHONUNBUFFERED",
    "PYTHONIOENCODING",
    "PYTHONHASHSEED",
    // Git identity and per-run behaviour. Every other GIT_* names a path, a
    // program, or a config source.
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
    "GIT_LFS_SKIP_SMUDGE",
    "GIT_OPTIONAL_LOCKS",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_CURL_VERBOSE",
    "GIT_ASK_YESNO",
    "GIT_CEILING_DIRECTORIES",
    "GIT_HTTP_LOW_SPEED_LIMIT",
    "GIT_HTTP_LOW_SPEED_TIME",
];

/// Whether any `NAME=VALUE` on a simple command has a shell expansion in its
/// value (a command substitution, backticks, ...).
///
/// Assignment values are not otherwise inspected, so this guard — applied to
/// every simple command, including those nested in pipelines and lists — forces
/// such commands to Ask. Literal assignments (`CI=1 ls`) pass through.
pub(crate) fn assignment_has_expansion(assignments: &[Node]) -> bool {
    assignments.iter().any(has_expansions)
}

/// The name of the first assignment on a simple command that rippy cannot vouch
/// for. Such a prefix can turn an otherwise-safe command into arbitrary code
/// execution, so the analyzer Asks before any handler can approve it.
pub(crate) fn dangerous_assignment_name(assignments: &[Node]) -> Option<String> {
    assignments.iter().find_map(|a| {
        literal_assignment(a)
            .map(|(n, _)| n)
            .or_else(|| append_assignment_name(a))
            .filter(|n| is_dangerous_env_name(n))
    })
}
