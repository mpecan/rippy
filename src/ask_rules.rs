//! Which [`AskClass`] an ask gets where rippy mints it.
//!
//! Classes are decided here, inside the analyzer's own recursion, so they
//! follow every wrapper, `-c` body and `-exec` the analyzer unwraps, and they
//! survive the merge of a compound command. None of this changes a decision or
//! a reason. See docs/jev.md#classification-rules.

use std::path::Path;

use rable::Node;

use crate::ast;
use crate::verdict::{AskClass, UncertainKind};

/// The class floor for anything judged indirectly: through a wrapper, a
/// handler's recursion, a script's contents or a config alias, so the text
/// rippy judged is not the command as written.
pub(crate) const INDIRECT: AskClass = AskClass::Uncertain(UncertainKind::Indirect);

/// Programs that change rippy's own rules or an agent's permissions. Asking
/// about them is always a human's call.
const SELF_TOOLS: &[&str] = &[
    "rippy",
    "dippy",
    "claude",
    "codex",
    "gemini",
    "cursor-agent",
    "opencode",
    "aider",
];

/// Builtins that change how later commands resolve or run.
const SHELL_STATE: &[&str] = &[
    ".", "source", "eval", "exec", "export", "declare", "typeset", "readonly", "local", "hash",
    "enable", "trap", "complete", "alias", "unalias", "set", "shopt", "ulimit", "umask",
];

/// Programs whose targets or subcommands are defined by files in the project.
pub(crate) const TASK_RUNNERS: &[&str] = &[
    "make",
    "gmake",
    "just",
    "task",
    "mise",
    "npm",
    "npx",
    "pnpm",
    "pnpx",
    "yarn",
    "bun",
    "bunx",
    "rake",
    "nox",
    "tox",
    "invoke",
    "poetry",
    "pipenv",
    "pdm",
    "hatch",
    "bundle",
    "composer",
    "gradle",
    "gradlew",
    "mvn",
    "mvnw",
    "sbt",
    "ant",
    "go",
    "deno",
    "cargo-make",
    "pipx",
    "uvx",
];

/// Programs that run code or other programs given as arguments. An unknown
/// value handed to one of these is code, not data. Programs whose own handler
/// already asks for an unknown subcommand (`git $X`, `kubectl $X`) are left to
/// the placeholder probe, so their ordinary arguments stay values.
const CODE_RUNNERS: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "python",
    "python3",
    "node",
    "nodejs",
    "deno",
    "bun",
    "ruby",
    "perl",
    "php",
    "lua",
    "awk",
    "gawk",
    "mawk",
    "nawk",
    "sed",
    "find",
    "xargs",
    "env",
    "eval",
    "exec",
    "source",
    ".",
    "sudo",
    "doas",
    "ssh",
    "watch",
    "parallel",
    "script",
    "strace",
    "ltrace",
    "gdb",
    "time",
    "nice",
    "nohup",
    "timeout",
    "stdbuf",
    "caffeinate",
    "command",
    "builtin",
    "chroot",
    "flock",
    "setsid",
    "unbuffer",
];

/// Variables that change which program a name resolves to, or what a shell
/// runs on start-up.
pub(crate) const LOOKUP_ENV: &[&str] = &[
    "PATH",
    "CDPATH",
    "BASH_ENV",
    "ENV",
    "PROMPT_COMMAND",
    "PYTHONPATH",
    "NODE_PATH",
    "RUBYLIB",
    "PERL5LIB",
    "GEM_PATH",
    "GEM_HOME",
];

const SCRIPT_EXTENSIONS: &[&str] = &[
    "sh", "bash", "zsh", "py", "js", "mjs", "cjs", "ts", "rb", "pl", "php", "lua", "ps1",
];

/// The class of an ask about a command no handler or rule knows.
pub(crate) fn unknown_command(name: &str, args: &[String], cwd: &Path) -> AskClass {
    if SELF_TOOLS.contains(&name) || SHELL_STATE.contains(&name) {
        return AskClass::Approval;
    }
    let first_operand = args.iter().find(|a| !a.starts_with('-'));
    let project_defined = is_script_like(name)
        || TASK_RUNNERS.contains(&name)
        || first_operand.is_some_and(|a| a.starts_with("./") || a.starts_with("../"))
        || args.iter().any(|a| is_runnable_arg(a, cwd));
    if project_defined {
        AskClass::Uncertain(UncertainKind::ProjectDefined)
    } else {
        AskClass::Uncertain(UncertainKind::UnknownCommand)
    }
}

/// A name that points at a file rather than a program on `PATH`.
pub(crate) fn is_script_like(name: &str) -> bool {
    name.contains('/') || has_script_extension(name)
}

/// An argument an unknown program may run: a script-named file, or a
/// path-like argument naming an executable file (`strace ./x`).
fn is_runnable_arg(arg: &str, cwd: &Path) -> bool {
    if arg.starts_with('-') || arg.contains("://") {
        return false;
    }
    has_script_extension(arg)
        || ((arg.contains('/') || arg.starts_with('.')) && is_executable(&cwd.join(arg)))
}

fn has_script_extension(arg: &str) -> bool {
    Path::new(arg)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| SCRIPT_EXTENSIONS.contains(&e))
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

/// Whether `name` runs code or programs taken from its arguments.
pub(crate) fn runs_code(name: &str) -> bool {
    CODE_RUNNERS.contains(&name) || is_script_like(name)
}

/// Whether a command's `NAME=value` prefix changes how names resolve.
pub(crate) fn sets_lookup_env(assignments: &[Node]) -> bool {
    assignments.iter().any(|a| {
        ast::literal_assignment(a)
            .map(|(n, _)| n)
            .or_else(|| ast::append_assignment_name(a))
            .or_else(|| assignment_name(a))
            .is_some_and(|n| LOOKUP_ENV.contains(&n.as_str()))
    })
}

/// The name of an assignment whose value is not literal (`PATH=./x:$PATH`).
fn assignment_name(assignment: &Node) -> Option<String> {
    let rable::NodeKind::Word { value, .. } = &assignment.kind else {
        return None;
    };
    value
        .split_once('=')
        .map(|(n, _)| n.trim_end_matches('+').to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PD: AskClass = AskClass::Uncertain(UncertainKind::ProjectDefined);
    const UC: AskClass = AskClass::Uncertain(UncertainKind::UnknownCommand);

    fn class(name: &str, args: &[&str]) -> AskClass {
        let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
        unknown_command(name, &args, Path::new("/nonexistent-rippy-dir"))
    }

    #[test]
    fn self_tools_and_shell_state_are_approval() {
        for name in ["rippy", "dippy", "claude", "export", "hash", "trap", "."] {
            assert_eq!(class(name, &[]), AskClass::Approval, "{name}");
        }
    }

    #[test]
    fn repository_defined_names_are_project_defined() {
        assert_eq!(class("./scripts/x.sh", &[]), PD);
        assert_eq!(class("bin/tool", &["list"]), PD);
        assert_eq!(class("deploy.py", &[]), PD);
        assert_eq!(class("poetry", &["run", "x"]), PD);
        assert_eq!(class("somecli", &["run", "task.sh"]), PD);
        assert_eq!(class("somecli", &["./x.py"]), PD);
        assert_eq!(class("watch", &["./x"]), PD);
        assert_eq!(class("stdbuf", &["-o0", "./x"]), PD);
    }

    #[test]
    fn ordinary_unknown_commands_stay_unknown() {
        assert_eq!(class("somecli", &["list", "--format", "json"]), UC);
        assert_eq!(class("somecli", &["sync", "./data"]), UC);
        assert_eq!(class("somecli", &["https://example.com/a.sh"]), UC);
    }

    #[cfg(unix)]
    #[test]
    fn an_executable_path_argument_is_project_defined() {
        use std::os::unix::fs::PermissionsExt;
        let Ok(dir) = tempfile::tempdir() else { return };
        let _ = std::fs::create_dir_all(dir.path().join("bin"));
        let tool = dir.path().join("bin/tool");
        let _ = std::fs::write(&tool, "#!/bin/sh\n");
        let _ = std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755));
        let _ = std::fs::write(dir.path().join("bin/notes"), "");
        let args = |a: &[&str]| a.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        // Not the first operand, so only the executable bit decides.
        let run = args(&["-e", "trace", "bin/tool"]);
        assert_eq!(unknown_command("strace", &run, dir.path()), PD);
        let data = args(&["-e", "trace", "bin/notes"]);
        assert_eq!(unknown_command("strace", &data, dir.path()), UC);
    }
}
