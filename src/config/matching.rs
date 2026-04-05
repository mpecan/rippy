use std::sync::OnceLock;

use crate::discover::FlagCache;

use super::Rule;

/// Lazily loaded flag alias cache for structured matching.
static FLAG_CACHE: OnceLock<FlagCache> = OnceLock::new();

fn flag_cache() -> &'static FlagCache {
    FLAG_CACHE.get_or_init(crate::discover::load_cache)
}

/// Check structured rule fields against the parsed command tokens.
///
/// All present fields must match (AND logic). Returns `true` if every
/// field that is `Some` matches the given input.
pub(super) fn matches_structured(rule: &Rule, input: &str) -> bool {
    let mut tokens = input.split_whitespace();
    let Some(cmd_name) = tokens.next() else {
        return false;
    };
    let args: Vec<&str> = tokens.collect();

    if let Some(expected) = &rule.command
        && cmd_name != expected.as_str()
    {
        return false;
    }

    let first_positional = args.iter().find(|a| !a.starts_with('-')).copied();

    if let Some(expected) = &rule.subcommand
        && first_positional != Some(expected.as_str())
    {
        return false;
    }

    if let Some(list) = &rule.subcommands {
        match first_positional {
            Some(sub) if list.iter().any(|s| s == sub) => {}
            _ => return false,
        }
    }

    if let Some(required_flags) = &rule.flags {
        // Expand flags with aliases from discovery cache.
        let cache_key = rule.command.as_ref().map(|cmd| {
            rule.subcommand
                .as_ref()
                .map_or_else(|| cmd.clone(), |sub| format!("{cmd} {sub}"))
        });
        let expanded =
            crate::discover::expand_flags(required_flags, flag_cache(), cache_key.as_deref());
        if !has_required_flag(&args, &expanded) {
            return false;
        }
    }

    if let Some(needle) = &rule.args_contain
        && !args.iter().any(|a| a.contains(needle.as_str()))
    {
        return false;
    }

    true
}

/// Check if any required flag matches any arg, handling combined short flags.
pub(super) fn has_required_flag(args: &[&str], required_flags: &[String]) -> bool {
    for arg in args {
        // Direct match (e.g. "--force" == "--force", "-f" == "-f").
        if required_flags.iter().any(|f| f == arg) {
            return true;
        }
        // Combined short flag expansion: "-fv" contains "-f" and "-v".
        if arg.starts_with('-')
            && !arg.starts_with("--")
            && arg.len() > 2
            && arg.as_bytes().iter().skip(1).all(u8::is_ascii_alphabetic)
        {
            for ch in arg.chars().skip(1) {
                let short = format!("-{ch}");
                if required_flags.iter().any(|f| f == &short) {
                    return true;
                }
            }
        }
    }
    false
}

/// Format a human-readable reason for a matched rule.
pub(super) fn format_rule_reason(rule: &Rule, label: &str) -> String {
    if rule.has_structured_fields() {
        format!("{label}: {}", rule.structured_description())
    } else {
        format!("{label}: {}", rule.pattern.as_str())
    }
}
