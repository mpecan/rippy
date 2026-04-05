use std::sync::OnceLock;

use crate::discover::FlagCache;

use super::types::Rule;

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
fn has_required_flag(args: &[&str], required_flags: &[String]) -> bool {
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::config::RuleTarget;
    use crate::pattern::Pattern;
    use crate::verdict::Decision;

    fn structured_rule(
        decision: Decision,
        command: Option<&str>,
        subcommand: Option<&str>,
        flags: Option<Vec<&str>>,
    ) -> Rule {
        let mut r = Rule::new(RuleTarget::Command, decision, "*");
        r.pattern = Pattern::any();
        r.command = command.map(String::from);
        r.subcommand = subcommand.map(String::from);
        r.flags = flags.map(|f| f.into_iter().map(String::from).collect());
        r
    }

    #[test]
    fn structured_command_matches() {
        let rule = structured_rule(Decision::Deny, Some("git"), None, None);
        assert!(matches_structured(&rule, "git push origin main"));
        assert!(matches_structured(&rule, "git status"));
        assert!(!matches_structured(&rule, "docker ps"));
    }

    #[test]
    fn structured_subcommand_matches() {
        let rule = structured_rule(Decision::Deny, Some("git"), Some("push"), None);
        assert!(matches_structured(&rule, "git push origin main"));
        assert!(!matches_structured(&rule, "git status"));
        assert!(matches_structured(&rule, "git --no-pager push"));
    }

    #[test]
    fn structured_flags_matches() {
        let rule = structured_rule(
            Decision::Deny,
            Some("git"),
            Some("push"),
            Some(vec!["--force", "-f"]),
        );
        assert!(matches_structured(&rule, "git push --force origin main"));
        assert!(matches_structured(&rule, "git push origin main --force"));
        assert!(matches_structured(&rule, "git push -f origin main"));
        assert!(!matches_structured(&rule, "git push origin main"));
    }

    #[test]
    fn structured_combined_short_flags() {
        let rule = structured_rule(
            Decision::Deny,
            Some("curl"),
            None,
            Some(vec!["-k", "--insecure"]),
        );
        let flags = rule.flags.as_ref().unwrap();
        assert!(has_required_flag(&["-kv", "http://example.com"], flags));
        assert!(has_required_flag(
            &["--insecure", "http://example.com"],
            flags
        ));
        assert!(!has_required_flag(&["-v", "http://example.com"], flags));
    }

    #[test]
    fn structured_subcommands_list() {
        let mut rule = structured_rule(Decision::Allow, Some("git"), None, None);
        rule.subcommands = Some(vec!["status".into(), "log".into(), "diff".into()]);
        assert!(matches_structured(&rule, "git status"));
        assert!(matches_structured(&rule, "git log --oneline"));
        assert!(!matches_structured(&rule, "git push origin"));
    }

    #[test]
    fn structured_args_contain() {
        let mut rule = structured_rule(Decision::Deny, Some("curl"), None, None);
        rule.args_contain = Some("password".into());
        assert!(matches_structured(
            &rule,
            "curl http://example.com?password=123"
        ));
        assert!(!matches_structured(&rule, "curl http://example.com"));
    }

    #[test]
    fn structured_empty_input_no_match() {
        let rule = structured_rule(Decision::Deny, Some("git"), None, None);
        assert!(!matches_structured(&rule, ""));
    }

    #[test]
    fn has_structured_fields_detects_fields() {
        let plain = Rule::new(RuleTarget::Command, Decision::Allow, "git *");
        assert!(!plain.has_structured_fields());

        let structured = structured_rule(Decision::Deny, Some("git"), None, None);
        assert!(structured.has_structured_fields());
    }
}
