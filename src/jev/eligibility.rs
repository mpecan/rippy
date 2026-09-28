//! Which uncertain asks may be sent to Jev at all.
//!
//! Jev sees only a command's text, so it judges by name: anything whose
//! behaviour the repository defines is excluded, because there the name proves
//! nothing. See docs/jev.md#placement.

use super::shape::Shape;
use crate::verdict::{AskClass, UncertainKind, Verdict};

/// Programs whose subcommands or targets are defined by files in the project.
const TASK_RUNNERS: &[&str] = &[
    "make", "gmake", "just", "task", "mise", "npm", "npx", "pnpm", "pnpx", "yarn", "bun", "bunx",
    "rake", "nox", "tox", "invoke",
];

/// Why a verdict is not sent, or the kind it is sent as.
///
/// # Errors
///
/// Returns the reason the ask stays as it is, for the log and `rippy jev`.
pub fn check(verdict: &Verdict, shape: &Shape<'_>) -> Result<UncertainKind, String> {
    let kind = match verdict.ask_class() {
        Some(AskClass::Uncertain(kind)) => kind,
        Some(AskClass::Approval) => return Err("approval ask".to_owned()),
        None => return Err("not an ask".to_owned()),
    };
    if kind == UncertainKind::Unanalyzable {
        return Err("rippy could not analyze the command".to_owned());
    }
    if shape.leaves.is_empty() {
        return Err("no command found".to_owned());
    }
    for leaf in &shape.leaves {
        let Some(name) = leaf.name.as_deref() else {
            return Err("a command has no literal name".to_owned());
        };
        if name.contains('/') {
            return Err(format!(
                "{name} is a path-qualified program the repository defines"
            ));
        }
        if TASK_RUNNERS.contains(&name) {
            return Err(format!("{name} runs tasks the repository defines"));
        }
        if name == "git" && kind == UncertainKind::UnknownSubcommand {
            return Err("an unknown git subcommand may be an alias".to_owned());
        }
        if kind == UncertainKind::OpaqueInput && leaf.args.iter().any(|a| !a.starts_with('-')) {
            return Err(format!("{name} runs a script or input Jev cannot see"));
        }
    }
    Ok(kind)
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
    fn only_non_unanalyzable_uncertain_asks_are_eligible() {
        let cmd = "somecli list";
        assert!(check_cmd(cmd, &Verdict::ask("x")).is_err());
        assert!(check_cmd(cmd, &Verdict::deny("x")).is_err());
        assert!(check_cmd(cmd, &uncertain(UncertainKind::Unanalyzable)).is_err());
        assert_eq!(
            check_cmd(cmd, &uncertain(UncertainKind::UnknownCommand)),
            Ok(UncertainKind::UnknownCommand)
        );
    }

    #[test]
    fn repository_defined_names_are_never_eligible() {
        let v = uncertain(UncertainKind::UnknownCommand);
        for cmd in [
            "./scripts/list-users.sh",
            "bin/tool list",
            "ls && make deploy",
            "npm run clean",
            "echo $(just version)",
        ] {
            assert!(check_cmd(cmd, &v).is_err(), "{cmd}");
        }
    }

    #[test]
    fn unknown_git_subcommands_may_be_aliases() {
        let v = uncertain(UncertainKind::UnknownSubcommand);
        assert!(check_cmd("git frobnicate --list", &v).is_err());
        assert!(check_cmd("7z q archive.7z", &v).is_ok());
        let dynamic = uncertain(UncertainKind::DynamicExpansion);
        assert!(check_cmd("git log -n $N", &dynamic).is_ok());
    }

    #[test]
    fn opaque_input_is_eligible_only_as_a_bare_repl() {
        let v = uncertain(UncertainKind::OpaqueInput);
        assert!(check_cmd("python3", &v).is_ok());
        assert!(check_cmd("python3 -q", &v).is_ok());
        assert!(check_cmd("python3 deploy.py", &v).is_err());
        assert!(check_cmd("psql -c '; SELECT 1'", &v).is_err());
    }
}
