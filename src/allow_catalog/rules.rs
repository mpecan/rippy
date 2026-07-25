//! Renders the allow rules carried by the embedded TOML bundles.
//!
//! Only `decision = allow` rules appear: an `ask`/`deny` rule cannot widen the
//! approved set, and listing them would bury the ones that can.

use std::fmt::Write as _;
use std::path::Path;

use crate::condition::Condition;
use crate::config::{ConfigDirective, Rule};
use crate::error::RippyError;
use crate::verdict::Decision;
use crate::{git_styles, packages, stdlib, toml_config};

pub(super) fn render_rule_bundles(out: &mut String) -> Result<(), RippyError> {
    let _ = writeln!(
        out,
        "### Stdlib — always active\n\nShipped with the binary and loaded as the lowest-priority \
         tier; your own config overrides them.\n"
    );
    for (label, source) in stdlib::stdlib_sources() {
        render_bundle(label, source, out)?;
    }

    let _ = writeln!(
        out,
        "### Packages — opt-in\n\nActive only when selected via `package = \"...\"` in your \
         config.\n"
    );
    for package in packages::Package::all() {
        render_bundle(package.name(), package.toml_source(), out)?;
    }

    let _ = writeln!(
        out,
        "### Git styles — opt-in\n\nActive only when selected via `[git] style = \"...\"`.\n"
    );
    for style in git_styles::ALL_STYLES {
        render_bundle(style.label(), style.toml_source(), out)?;
    }
    Ok(())
}

fn render_bundle(label: &str, source: &str, out: &mut String) -> Result<(), RippyError> {
    let directives = toml_config::parse_toml_config(source, Path::new(label))?;
    let allow_rules: Vec<&Rule> = directives
        .iter()
        .filter_map(|d| match d {
            ConfigDirective::Rule(rule) if rule.decision == Decision::Allow => Some(rule),
            _ => None,
        })
        .collect();

    if allow_rules.is_empty() {
        let _ = writeln!(out, "#### `{label}`\n\nNo allow rules.\n");
        return Ok(());
    }

    let _ = writeln!(out, "#### `{label}`\n");
    let _ = writeln!(out, "| Action | Matches | Message | Conditions |");
    let _ = writeln!(out, "| --- | --- | --- | --- |");
    for rule in allow_rules {
        let _ = writeln!(
            out,
            "| `{}` | `{}` | {} | {} |",
            rule.action_str(),
            rule_match(rule),
            rule.message.as_deref().unwrap_or("—"),
            conditions(&rule.conditions),
        );
    }
    out.push('\n');
    Ok(())
}

/// What the rule matches on, in the same shape `rippy inspect` prints.
fn rule_match(rule: &Rule) -> String {
    if !rule.has_structured_fields() {
        return rule.pattern.raw().to_owned();
    }
    if rule.pattern.is_any() {
        return rule.structured_description();
    }
    format!("{} + {}", rule.pattern.raw(), rule.structured_description())
}

fn conditions(conditions: &[Condition]) -> String {
    if conditions.is_empty() {
        return "—".to_owned();
    }
    conditions
        .iter()
        .map(|c| format!("`{}`", describe(c)))
        .collect::<Vec<_>>()
        .join(", ")
}

fn describe(condition: &Condition) -> String {
    match condition {
        Condition::BranchEq(v) => format!("branch = {v}"),
        Condition::BranchNot(v) => format!("branch != {v}"),
        Condition::BranchMatch(v) => format!("branch matches {v}"),
        Condition::CwdUnder(v) => format!("cwd under {v}"),
        Condition::FileExists(v) => format!("file exists {v}"),
        Condition::EnvEq { name, value } => format!("env {name} = {value}"),
        Condition::Exec(v) => format!("exec succeeds: {v}"),
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn every_bundle_gets_a_heading() {
        let mut out = String::new();
        render_rule_bundles(&mut out).unwrap();
        for (label, _) in stdlib::stdlib_sources() {
            assert!(out.contains(&format!("#### `{label}`")), "{label} missing");
        }
        for style in git_styles::ALL_STYLES {
            assert!(out.contains(&format!("#### `{}`", style.label())));
        }
    }

    /// The permissive git style is the loudest opt-in widening rippy ships; if
    /// it stopped rendering, the catalog would understate the surface.
    #[test]
    fn permissive_git_style_lists_allow_rules() {
        let mut out = String::new();
        render_rule_bundles(&mut out).unwrap();
        let permissive = out.split("#### `permissive`").nth(1).unwrap();
        assert!(permissive.contains("| `allow` |"));
    }
}
