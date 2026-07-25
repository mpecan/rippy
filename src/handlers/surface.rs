//! The declared allow surface of every command handler.
//!
//! Handlers classify imperatively, so the only way a reviewer can see what a
//! handler approves is to read its `classify`. [`Handler::allow_surface`]
//! re-states the same set as data; `src/allow_catalog.rs` renders it into
//! `docs/allow-catalog.md`, where a widening shows up as a diff.
//!
//! [`Handler::allow_surface`]: super::Handler::allow_surface

use std::collections::BTreeMap;

use super::Handler;

/// One invocation shape a handler auto-approves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AllowEntry {
    /// The approved invocation including the command word, e.g. `git status`.
    /// `<...>` marks an operand the shape does not constrain.
    pub(crate) surface: String,
    /// The extra condition the invocation must also satisfy, or empty when the
    /// shape alone is approved.
    pub(crate) guard: String,
}

impl AllowEntry {
    pub(crate) fn new(surface: impl Into<String>) -> Self {
        Self {
            surface: surface.into(),
            guard: String::new(),
        }
    }

    pub(crate) fn guarded(surface: impl Into<String>, guard: impl Into<String>) -> Self {
        Self {
            surface: surface.into(),
            guard: guard.into(),
        }
    }
}

/// Join a command prefix to a subcommand; an empty subcommand means the bare
/// prefix is itself the approved invocation.
fn join(prefix: &str, sub: &str) -> String {
    if sub.is_empty() {
        prefix.to_owned()
    } else {
        format!("{prefix} {sub}")
    }
}

/// Expand a safe-subcommand list into one unguarded entry per subcommand.
pub(crate) fn subcommands(prefix: &str, subs: &[&str]) -> Vec<AllowEntry> {
    subs.iter()
        .map(|sub| AllowEntry::new(join(prefix, sub)))
        .collect()
}

/// Expand a safe-subcommand list where every member shares one extra condition.
pub(crate) fn guarded_subcommands(prefix: &str, subs: &[&str], guard: &str) -> Vec<AllowEntry> {
    subs.iter()
        .map(|sub| AllowEntry::guarded(join(prefix, sub), guard))
        .collect()
}

/// Every registered handler with its declared surface, keyed by the command
/// names it owns.
///
/// Handlers registered under several names appear once. The `BTreeMap` keeps
/// the order independent of the registry's `HashMap` iteration order, which the
/// generated catalog depends on.
pub(crate) fn all_handler_surfaces() -> Vec<(Vec<&'static str>, Vec<AllowEntry>)> {
    let mut groups: BTreeMap<Vec<&'static str>, &'static dyn Handler> = BTreeMap::new();
    for cmd in super::all_handler_commands() {
        if let Some(handler) = super::get_handler(cmd) {
            groups.insert(handler.commands().to_vec(), handler);
        }
    }
    groups
        .into_iter()
        .map(|(cmds, handler)| (cmds, handler.allow_surface()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_registered_command_belongs_to_exactly_one_group() {
        let groups = all_handler_surfaces();
        for cmd in super::super::all_handler_commands() {
            let hits = groups
                .iter()
                .filter(|(cmds, _)| cmds.contains(&cmd))
                .count();
            assert_eq!(hits, 1, "{cmd} must appear in exactly one surface group");
        }
    }

    #[test]
    fn subcommands_helper_prefixes_every_member() {
        let entries = subcommands("git", &["status", "log"]);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].surface, "git status");
        assert_eq!(entries[1].surface, "git log");
        assert!(entries[0].guard.is_empty());

        let guarded = guarded_subcommands("helm", &["install"], "--dry-run present");
        assert_eq!(guarded[0].surface, "helm install");
        assert_eq!(guarded[0].guard, "--dry-run present");
    }

    /// A handler that approves nothing must say so with an empty surface, but a
    /// handler that does approve something must not silently return nothing.
    #[test]
    fn surfaces_are_free_of_blank_entries() {
        for (cmds, entries) in all_handler_surfaces() {
            for entry in entries {
                assert!(
                    !entry.surface.trim().is_empty(),
                    "{cmds:?} declared a blank surface"
                );
            }
        }
    }
}
