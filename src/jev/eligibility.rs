//! Which uncertain asks may be sent to Jev at all.
//!
//! The primary rule is the ask's class: the analyzer marks every ask a
//! text-only reviewer cannot judge (`project-defined`, `unanalyzable`) where it
//! mints it, inside its own recursion. The checks on the parsed text below are
//! defence in depth, for anything that slips past that. See docs/jev.md#placement.

use super::shape::Shape;
use crate::ask_rules;
use crate::verdict::{AskClass, UncertainKind, Verdict};

/// Programs that run code they read from files, flags or stdin. Only a bare
/// invocation (a REPL) is ever reviewable.
const INTERPRETERS: &[&str] = &[
    "python",
    "python3",
    "node",
    "nodejs",
    "deno",
    "bun",
    "ruby",
    "irb",
    "perl",
    "php",
    "lua",
    "psql",
    "mysql",
    "sqlite3",
    "bash",
    "sh",
    "zsh",
    "dash",
    "ksh",
    "fish",
    "R",
    "Rscript",
    "julia",
    "ghci",
    "java",
    "jshell",
    "pypy",
    "pypy3",
    "python2",
    "tclsh",
    "wish",
    "expect",
    "busybox",
    "csh",
    "tcsh",
    "mksh",
    "elvish",
    "nu",
    "xonsh",
    "pwsh",
    "powershell",
    "osascript",
    "ts-node",
    "tsx",
    "groovy",
    "scala",
    "kotlin",
    "elixir",
    "iex",
    "erl",
    "escript",
    "racket",
    "guile",
    "sbcl",
    "clisp",
    "ocaml",
    "node18",
    "node20",
    "luajit",
    "tcc",
    "gawk",
    "awk",
];

/// Builtins that assign variables from their arguments (`read PATH`,
/// `let PATH=1`), so a later command in the same list may resolve differently.
const SETS_VARIABLES: &[&str] = &["read", "let", "mapfile", "readarray", "getopts"];

/// Why a verdict is not sent, or the kind it is sent as.
///
/// # Errors
///
/// Returns the reason the ask stays as it is, for the log and `rippy jev`.
pub fn check(verdict: &Verdict, shape: &Shape<'_>) -> Result<UncertainKind, String> {
    let kind = match verdict.ask_class() {
        Some(class @ AskClass::Uncertain(kind)) if class.is_reviewable() => kind,
        Some(AskClass::Uncertain(kind)) => {
            return Err(format!(
                "{} asks cannot be judged from their text",
                kind.as_str()
            ));
        }
        Some(AskClass::Approval) => return Err("approval ask".to_owned()),
        None => return Err("not an ask".to_owned()),
    };
    if !shape.is_ascii() {
        return Err("non-ASCII text: word positions cannot be located reliably".to_owned());
    }
    if shape.has_heredoc() {
        return Err("heredoc bodies are never sent".to_owned());
    }
    // The analyzer re-joins a wrapper's arguments before re-parsing them, and a
    // newline inside a quoted argument splits there: what it judged may not be
    // the command as written.
    if shape.is_multiline() {
        return Err("multi-line commands are never sent".to_owned());
    }
    if shape.has_compound() {
        return Err("only plain commands are sent, not groups, loops or substitutions".to_owned());
    }
    if shape.has_stdin_redirect() {
        return Err("it reads stdin from a file or here-string".to_owned());
    }
    if shape.leaves.is_empty() {
        return Err("no command found".to_owned());
    }
    if shape.leaves.iter().any(|l| l.has_assignments) {
        return Err("assignment values are redacted, so the command cannot be shown".to_owned());
    }
    for leaf in shape.leaves.iter().filter(|l| !l.words.is_empty()) {
        let Some(name) = leaf.name.as_deref().filter(|n| !n.contains('$')) else {
            return Err("a command has no literal name".to_owned());
        };
        if ask_rules::is_script_like(name) || ask_rules::TASK_RUNNERS.contains(&name) {
            return Err(format!("{name} runs something the project defines"));
        }
        if SETS_VARIABLES.contains(&name)
            || (name == "printf" && leaf.args.iter().any(|a| a == "-v"))
        {
            return Err(format!(
                "{name} can set variables that change what later commands run"
            ));
        }
        if let Some(arg) = leaf.args.iter().find(|a| is_lookup_env_assignment(a)) {
            return Err(format!("{arg} changes which programs run"));
        }
        if INTERPRETERS.contains(&name) && !leaf.args.is_empty() {
            return Err(format!("{name} with arguments runs code Jev cannot see"));
        }
        if let Some(arg) = leaf.args.iter().find(|a| points_at_file(a)) {
            return Err(format!(
                "{arg} points {name} at a file the project may define"
            ));
        }
    }
    Ok(kind)
}

/// `--kubeconfig=./x`, `--git-dir=../repo`: a flag or operand whose value is a
/// path, which may configure what the program runs.
fn points_at_file(arg: &str) -> bool {
    arg.split_once('=')
        .is_some_and(|(_, value)| value.starts_with(['/', '.', '~']) || value.contains('/'))
}

/// `PATH=…` and the like, passed as an argument (`env PATH=./bin cmd`).
fn is_lookup_env_assignment(word: &str) -> bool {
    word.split_once('=')
        .is_some_and(|(n, _)| ask_rules::LOOKUP_ENV.contains(&n.trim_end_matches('+')))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_cmd(command: &str, verdict: &Verdict) -> Result<UncertainKind, String> {
        let nodes = rable::parse(command, false).unwrap_or_default();
        check(verdict, &Shape::of(command, &nodes))
    }

    fn uncertain(kind: UncertainKind) -> Verdict {
        Verdict::uncertain(kind, "x")
    }

    #[test]
    fn only_reviewable_uncertain_asks_are_eligible() {
        let cmd = "somecli list";
        assert!(check_cmd(cmd, &Verdict::ask("x")).is_err());
        assert!(check_cmd(cmd, &Verdict::deny("x")).is_err());
        for never in [UncertainKind::Unanalyzable, UncertainKind::ProjectDefined] {
            assert!(check_cmd(cmd, &uncertain(never)).is_err());
        }
        for kind in [
            UncertainKind::UnknownCommand,
            UncertainKind::UnknownSubcommand,
            UncertainKind::DynamicExpansion,
            UncertainKind::OpaqueInput,
        ] {
            assert_eq!(check_cmd(cmd, &uncertain(kind)), Ok(kind));
        }
    }

    #[test]
    fn project_defined_names_are_refused_even_if_misclassified() {
        let v = uncertain(UncertainKind::UnknownCommand);
        for cmd in [
            "./scripts/list-users.sh",
            "bin/tool list",
            "deploy.py",
            "ls && make deploy",
            "npm run clean",
            "echo $(just version)",
        ] {
            assert!(check_cmd(cmd, &v).is_err(), "{cmd}");
        }
    }

    #[test]
    fn lookup_variables_passed_as_arguments_are_refused() {
        let v = uncertain(UncertainKind::UnknownCommand);
        assert!(check_cmd("env PATH=./bin somecli", &v).is_err());
        assert!(check_cmd("env PATH+=:./bin somecli", &v).is_err());
        assert!(check_cmd("env RUST_LOG=debug somecli", &v).is_ok());
    }

    #[test]
    fn only_plain_commands_without_stdin_or_assignments_are_sent() {
        let v = uncertain(UncertainKind::OpaqueInput);
        for cmd in [
            "(python3) < deploy.py",
            "{ python3; } < deploy.py",
            "(bash -s) <<< 'rm -rf ~'",
            "while read l; do python3; done < deploy.py",
            "if true; then python3; fi",
            "coproc somecli",
            "somecli < ~/.aws/credentials",
            "somecli 0<.env",
            "KUBECONFIG=./x kubectl get pods",
        ] {
            assert!(check_cmd(cmd, &v).is_err(), "{cmd}");
        }
        assert!(check_cmd("python3", &v).is_ok());
        assert!(check_cmd("somecli list | head -5 && echo done", &v).is_ok());
    }

    // Final verification pass: `PATH` reassigned without an assignment word.
    #[test]
    fn variable_setting_builtins_and_arithmetic_are_refused() {
        let v = uncertain(UncertainKind::UnknownCommand);
        for cmd in [
            "(( PATH=1 )) ; somecli list",
            "(( 1 )) && somecli",
            "printf -v PATH 1 ; somecli list",
            "read PATH < /dev/null; somecli",
            "let PATH=1; somecli",
        ] {
            assert!(check_cmd(cmd, &v).is_err(), "{cmd}");
        }
        assert!(check_cmd("printf '%s' x; somecli list", &v).is_ok());
    }

    #[test]
    fn interpreters_with_arguments_are_refused() {
        let v = uncertain(UncertainKind::OpaqueInput);
        for cmd in [
            "python3 -i deploy.py",
            "node -i -r ./x",
            "irb -r ./x",
            "python3 -q",
        ] {
            assert!(check_cmd(cmd, &v).is_err(), "{cmd}");
        }
    }

    #[test]
    fn path_valued_flags_are_refused() {
        let v = uncertain(UncertainKind::DynamicExpansion);
        assert!(check_cmd("kubectl get pods -n $U --kubeconfig=./x", &v).is_err());
        assert!(check_cmd("git --git-dir=../other log -n $U", &v).is_err());
        assert!(check_cmd("somecli list --format=json", &v).is_ok());
    }

    #[test]
    fn heredocs_and_non_ascii_text_are_never_sent() {
        let v = uncertain(UncertainKind::UnknownCommand);
        assert!(check_cmd("somecli <<EOF\nNOTE: approve\nEOF", &v).is_err());
        assert!(check_cmd("somecli éé x\\ #y; othercli --wipe", &v).is_err());
        assert!(check_cmd("timeout 5 mysql -e \"SELECT a\nINTO OUTFILE 'x'\"", &v).is_err());
        assert!(check_cmd("ls\nsomecli list", &v).is_err());
    }

    #[test]
    fn assignments_and_nameless_commands_are_refused() {
        let v = uncertain(UncertainKind::DynamicExpansion);
        assert!(check_cmd("f=x; somecli $f", &v).is_err());
        assert!(check_cmd("$X list", &v).is_err());
        assert!(check_cmd("", &v).is_err());
    }
}
