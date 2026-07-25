//! Renders `docs/allow-catalog.md` — the single place that answers "what does
//! rippy auto-approve?".
//!
//! Everything here reads embedded constants and static registries only: no
//! filesystem, no environment, no working directory. Two renders on any two
//! machines must be byte-identical, because `tests/allow_catalog.rs` fails CI
//! when the committed file does not match this output.

use std::fmt::Write as _;

use crate::error::RippyError;
use crate::verdict::AllowCategory;
use crate::{allowlists, ast, handlers};

#[path = "allow_catalog/rules.rs"]
mod rules;

const BANNER: &str = "\
<!-- GENERATED FILE — do not edit by hand. -->
<!-- Regenerate with: RIPPY_UPDATE_ALLOW_CATALOG=1 cargo test --test allow_catalog -->

# rippy allow catalog

Every way rippy can decide `allow` without asking you, grouped by why.

**How far the guarantee goes.** The handler sections are what each handler
*declares* as its allow surface, not a proof about its code.
`tests/allow_catalog.rs` fails when this file drifts from those declarations,
and it checks both directions: every literal surface listed here must really be
approved by the analyzer, and each declared namespace is probed with a set of
mutation verbs so an approval a handler grants without declaring it also fails.
The probe vocabulary is finite, so treat a missing row as *not declared* rather
than as a proof that nothing else is approved.

**What this file is not.** Handlers that judge *content* — inline `python -c`
code, a `sed` script, the SQL behind `psql -c` — are listed by the invocation
shape that reaches the analyzer, not by which programs that analyzer accepts.
For those, the `Condition` column names the module that decides.

";

/// Render the whole catalog.
///
/// # Errors
///
/// Returns `RippyError::Config` if an embedded rule bundle fails to parse,
/// which would be a build-time bug in the shipped TOML.
pub fn render() -> Result<String, RippyError> {
    let mut out = String::from(BANNER);
    render_contents(&mut out);
    for category in AllowCategory::ALL {
        let _ = writeln!(out, "## {}\n\n{}\n", category.title(), category.summary());
        render_category(*category, &mut out)?;
    }
    Ok(out)
}

/// Every handler surface that names a complete, literal invocation: no operand
/// placeholder, no wildcard, no alternation, and no extra condition.
///
/// `tests/allow_catalog.rs` runs each one through the real analyzer, so the
/// catalog cannot claim an approval the pipeline does not actually grant.
#[must_use]
pub fn literal_surfaces() -> Vec<String> {
    handlers::all_handler_surfaces()
        .into_iter()
        .flat_map(|(_, entries)| entries)
        .filter(|e| {
            e.guard.is_empty() && !e.surface.contains(['<', '*', '|', '[']) && !e.surface.is_empty()
        })
        .map(|e| e.surface)
        .collect()
}

/// Every invocation shape a handler declares, including the guarded and
/// placeholder ones [`literal_surfaces`] filters out.
///
/// `tests/allow_catalog.rs` probes sibling verbs against this list, so a
/// handler that approves an invocation it never declared fails CI. That is the
/// direction [`literal_surfaces`] cannot check.
#[must_use]
pub fn declared_surfaces() -> Vec<String> {
    handlers::all_handler_surfaces()
        .into_iter()
        .flat_map(|(_, entries)| entries)
        .map(|e| e.surface)
        .filter(|s| !s.is_empty())
        .collect()
}

fn render_contents(out: &mut String) {
    let _ = writeln!(out, "## Contents\n");
    for category in AllowCategory::ALL {
        let _ = writeln!(
            out,
            "- [{}](#{})",
            category.title(),
            anchor(category.title())
        );
    }
    out.push('\n');
}

/// GitHub's heading-anchor form: lowercased, spaces to hyphens, punctuation
/// dropped.
fn anchor(title: &str) -> String {
    title
        .chars()
        .filter_map(|c| match c {
            ' ' => Some('-'),
            c if c.is_ascii_alphanumeric() => Some(c.to_ascii_lowercase()),
            '-' => Some('-'),
            _ => None,
        })
        .collect()
}

/// Exhaustive so a new [`AllowCategory`] cannot be added without a section.
fn render_category(category: AllowCategory, out: &mut String) -> Result<(), RippyError> {
    match category {
        AllowCategory::Allowlist => render_allowlist(out),
        AllowCategory::DynamicArg => render_dynamic_arg(out),
        AllowCategory::Handler => render_handlers(out),
        AllowCategory::Rule => return rules::render_rule_bundles(out),
        AllowCategory::Redirect => render_redirects(out),
        AllowCategory::Structural => render_structural(out),
        AllowCategory::UserControlled => render_user_controlled(out),
    }
    Ok(())
}

fn render_allowlist(out: &mut String) {
    let safe = allowlists::all_simple_safe();
    let _ = writeln!(
        out,
        "### `SIMPLE_SAFE` — {} commands\n\nApproved on the command name alone, whatever the \
         arguments.\n",
        safe.len()
    );
    render_command_list(&safe, out);

    let wrappers = allowlists::all_wrappers();
    let _ = writeln!(
        out,
        "### Wrappers — {} commands\n\nApproved only with no inner command; otherwise the inner \
         command is analyzed in their place. The wrapper's own redirects and heredocs are still \
         evaluated, so `nice ls > /etc/passwd` asks. For `timeout`, its options and the mandatory \
         DURATION are skipped first; an argv that does not match that grammar is analyzed \
         unchanged, so the stray word reads as an unknown command.\n",
        wrappers.len()
    );
    render_command_list(&wrappers, out);

    let _ = writeln!(
        out,
        "### Sole help/version flag\n\nAny command whose *only* argument is one of \
         {} is approved. Short forms (`-h`, `-V`) are excluded: commands overload them.\n",
        code_list(allowlists::SOLE_HELP_FLAGS)
    );
}

fn render_dynamic_arg(out: &mut String) {
    let excluded = allowlists::all_dynamic_arg_unsafe();
    let _ = writeln!(
        out,
        "When an argument is set but its value is unknown (a loop variable, a glob match), an \
         allowlist command stays approved — except for these {}, whose behavior an argument can \
         change dangerously:\n",
        excluded.len()
    );
    render_command_list(&excluded, out);
    let _ = writeln!(
        out,
        "With a *literal* argument these are still approved by the allowlist above.\n"
    );
}

fn render_handlers(out: &mut String) {
    let groups = handlers::all_handler_surfaces();
    let _ = writeln!(
        out,
        "{} handlers. A handler that only re-analyzes an inner command or asks declares an empty \
         surface, which is itself listed below.\n",
        groups.len()
    );
    for (cmds, entries) in groups {
        let _ = writeln!(out, "### `{}`\n", cmds.join("`, `"));
        // One handler serves every name in the heading, but the rows can only
        // spell one of them.
        if let Some(first) = cmds.first().filter(|_| cmds.len() > 1) {
            let _ = writeln!(
                out,
                "Rows are written with `{first}`; unless a row says otherwise they apply the \
                 same way to every command name in this heading.\n"
            );
        }
        if entries.is_empty() {
            let _ = writeln!(out, "Delegates only — approves nothing directly.\n");
            continue;
        }
        let _ = writeln!(out, "| Approved invocation | Condition |");
        let _ = writeln!(out, "| --- | --- |");
        for entry in entries {
            let guard = if entry.guard.is_empty() {
                "—".to_owned()
            } else {
                escape_cell(&entry.guard)
            };
            let _ = writeln!(out, "| `{}` | {guard} |", escape_cell(&entry.surface));
        }
        out.push('\n');
    }
}

fn render_redirects(out: &mut String) {
    let _ = writeln!(
        out,
        "- Redirects to {} are approved: they discard or re-emit output.\n\
         - An input redirect (`< file`) is approved: it cannot write.\n\
         - A file-descriptor duplication (`2>&1`) is approved: it names no path.\n\
         - A write redirect is approved when its target resolves inside a default safe directory \
         ({}) or a directory you declared as a safe scope. Targets inside the working directory \
         still ask.\n\n\
         See `docs/security-invariants.md` for the symlink hardening applied to the \
         world-writable defaults.\n",
        code_list(ast::SAFE_REDIRECT_TARGETS),
        code_list(handlers::SAFE_DIRECTORIES),
    );
}

fn render_structural(out: &mut String) {
    let _ = writeln!(
        out,
        "- An empty parse result, or a construct the walker does not gate.\n\
         - A command node with no command name (a bare `FOO=bar` assignment).\n\
         - A heredoc body, which cannot expand into a command.\n"
    );
}

fn render_user_controlled(out: &mut String) {
    let _ = writeln!(
        out,
        "These depend on your machine and are **not** part of rippy's shipped surface. Run \
         `rippy inspect` to see what is active for you.\n\n\
         - Allow rules in `~/.rippy/config.toml` or a project `.rippy.toml`.\n\
         - Custom packages under `~/.rippy/packages/`.\n\
         - Claude Code `permissions.allow` entries.\n\
         - `default-action = \"allow\"`, which approves anything no rule or handler matched.\n\
         - `PostToolUse` after-rules, which report rather than gate.\n"
    );
}

fn render_command_list(cmds: &[&str], out: &mut String) {
    let _ = writeln!(out, "{}\n", code_list(cmds));
}

fn code_list(items: &[&str]) -> String {
    items
        .iter()
        .map(|c| format!("`{c}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Keep a string inside one markdown table cell: an unescaped `|` would split
/// the row into extra columns, even inside a code span.
fn escape_cell(text: &str) -> String {
    text.replace('|', "\\|").replace('\n', " ")
}

#[cfg(test)]
#[expect(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn every_category_renders_a_heading() {
        let doc = render().unwrap();
        for category in AllowCategory::ALL {
            assert!(
                doc.contains(&format!("## {}", category.title())),
                "missing section for {category:?}"
            );
        }
    }

    #[test]
    fn every_handler_command_appears() {
        let doc = render().unwrap();
        for cmd in handlers::all_handler_commands() {
            assert!(doc.contains(&format!("`{cmd}`")), "{cmd} missing from doc");
        }
    }

    #[test]
    fn rendered_doc_is_tab_free_and_substantial() {
        let doc = render().unwrap();
        assert!(!doc.contains('\t'), "tabs break markdown tables");
        assert!(doc.lines().count() > 100, "doc looks truncated");
    }

    #[test]
    fn literal_surfaces_are_complete_invocations() {
        let literals = literal_surfaces();
        assert!(literals.contains(&"git status".to_owned()));
        assert!(literals.iter().all(|s| !s.contains('<')));
    }

    #[test]
    fn anchor_matches_github_slug_rules() {
        assert_eq!(
            anchor("User-controlled (not shipped)"),
            "user-controlled-not-shipped"
        );
    }
}
