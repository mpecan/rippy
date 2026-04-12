//! Implementation of `rippy list` subcommands.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::ExitCode;

use crate::cli::{ListArgs, ListTarget};
use crate::error::RippyError;
use crate::{allowlists, handlers, inspect};

/// Entry point for `rippy list`.
///
/// # Errors
///
/// Returns `RippyError` if config loading fails for the `rules` subcommand.
pub fn run(args: &ListArgs) -> Result<ExitCode, RippyError> {
    match &args.target {
        ListTarget::Safe => list_safe(),
        ListTarget::Handlers => list_handlers(),
        ListTarget::Rules(rules_args) => list_rules(rules_args.filter.as_deref())?,
    }
    Ok(ExitCode::SUCCESS)
}

fn list_safe() {
    let safe = allowlists::all_simple_safe();
    println!("Safe commands (auto-approved):");
    print_columns(&safe);
    println!("  ({} commands)\n", safe.len());

    let wrappers = allowlists::all_wrappers();
    println!("Wrapper commands (pass through to inner command):");
    print_columns(&wrappers);
    println!("  ({} commands)", wrappers.len());
}

fn list_handlers() {
    let all_cmds = handlers::all_handler_commands();
    let mut groups: BTreeSet<Vec<&str>> = BTreeSet::new();

    for cmd in &all_cmds {
        if let Some(handler) = handlers::get_handler(cmd) {
            groups.insert(handler.commands().to_vec());
        }
    }

    println!("Handler commands:");
    for cmds in &groups {
        let joined = cmds.join(", ");
        println!("  {joined}");
    }
    println!(
        "\n  ({} commands across {} handlers)",
        all_cmds.len(),
        groups.len()
    );
}

fn list_rules(filter: Option<&str>) -> Result<(), RippyError> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let output = inspect::collect_list_data(&cwd, None)?;

    println!("Rules:\n");

    for source in &output.config_sources {
        let rules: Vec<_> = source
            .rules
            .iter()
            .filter(|r| matches_filter(r, filter))
            .collect();
        if rules.is_empty() {
            continue;
        }
        println!("  {}:", source.path);
        for rule in &rules {
            let msg = rule
                .message
                .as_ref()
                .map_or(String::new(), |m| format!("  \"{m}\""));
            println!("    {:<6} {}{msg}", rule.action, rule.pattern);
        }
        println!();
    }

    for source in &output.cc_sources {
        let rules: Vec<_> = source
            .rules
            .iter()
            .filter(|r| matches_filter(r, filter))
            .collect();
        if rules.is_empty() {
            continue;
        }
        println!("  {}:", source.path);
        for rule in &rules {
            println!("    {:<6} {}", rule.action, rule.pattern);
        }
        println!();
    }
    Ok(())
}

fn matches_filter(rule: &inspect::RuleDisplay, filter: Option<&str>) -> bool {
    let Some(f) = filter else { return true };
    rule.pattern.contains(f) || rule.action.contains(f)
}

/// Print items in multi-column layout, 6 per row.
fn print_columns(items: &[&str]) {
    for chunk in items.chunks(6) {
        let row: Vec<String> = chunk.iter().map(|s| format!("{s:<14}")).collect();
        println!("  {}", row.join(""));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn safe_list_is_sorted_and_nonempty() {
        let safe = allowlists::all_simple_safe();
        assert!(!safe.is_empty());
        let mut sorted = safe.clone();
        sorted.sort_unstable();
        assert_eq!(safe, sorted);
    }

    #[test]
    fn wrapper_list_is_sorted_and_nonempty() {
        let wrappers = allowlists::all_wrappers();
        assert!(!wrappers.is_empty());
        let mut sorted = wrappers.clone();
        sorted.sort_unstable();
        assert_eq!(wrappers, sorted);
    }

    #[test]
    fn handler_commands_is_sorted_and_nonempty() {
        let cmds = handlers::all_handler_commands();
        assert!(!cmds.is_empty());
        let mut sorted = cmds.clone();
        sorted.sort_unstable();
        assert_eq!(cmds, sorted);
    }

    #[test]
    fn filter_matches_pattern() {
        let rule = inspect::RuleDisplay {
            action: "allow".into(),
            pattern: "git status".into(),
            message: None,
        };
        assert!(matches_filter(&rule, Some("git")));
        assert!(!matches_filter(&rule, Some("docker")));
        assert!(matches_filter(&rule, None));
    }

    #[test]
    fn filter_matches_action() {
        let rule = inspect::RuleDisplay {
            action: "deny".into(),
            pattern: "rm -rf".into(),
            message: None,
        };
        assert!(matches_filter(&rule, Some("deny")));
        assert!(!matches_filter(&rule, Some("allow")));
    }
}
