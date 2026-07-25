use std::fmt;

/// Which config layer a rule-driven approval came from.
///
/// Only two tiers are distinguishable today: `Config` tracks a single
/// `project_rules_range`, so stdlib, package and global rules are all flattened
/// into `Baseline`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSource {
    /// A stdlib, package or global rule.
    Baseline,
    /// A rule from the project-level config.
    Project,
}

/// Why a command was approved — the machine-readable provenance of every
/// `Decision::Allow` rippy emits.
///
/// This is the typed replacement for the free-text allow reason. Its [`Display`]
/// impl reproduces the exact strings rippy has always written to the
/// `reason` field, which is part of the JSON hook output, so the wire format is
/// unaffected by the categorization. `Verdict::reason` is *initialized* from
/// this Display; `annotate_with_resolution` may later append `(resolved: …)` to
/// that string, so the two are not required to stay equal for the lifetime of a
/// verdict.
///
/// `Ask` and `Deny` reasons stay free-text: only the allow surface needs to be
/// enumerable.
///
/// [`Display`]: std::fmt::Display
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowReason {
    /// Nothing to report: an empty node list, a construct the walker does not
    /// gate, or a `PostToolUse` hook with no after-rule message.
    Empty,
    /// A command node with no command name.
    EmptyCommand,
    /// The command is in the `SIMPLE_SAFE` allowlist.
    SimpleSafe(String),
    /// A wrapper command (`env`, `nohup`, …) invoked with no inner command.
    Wrapper(String),
    /// `--help`/`--version` was the sole argument.
    HelpFlag(String),
    /// A pure-reader allowlist command carrying a dynamically-known argument.
    DynamicArgSafe(String),
    /// An input (`<`) redirect, which cannot write.
    InputRedirect,
    /// A file-descriptor duplication (`2>&1`), which targets no path.
    FdRedirect,
    /// A redirect to an inherently safe device (`/dev/null`, `/dev/stdout`).
    DeviceRedirect(String),
    /// A write redirect whose target resolves inside the trusted safe-dir set.
    SafeDirWrite(String),
    /// A heredoc body that cannot expand into a command.
    Heredoc,
    /// A command-specific handler approved this invocation; the payload is the
    /// handler's own description.
    Handler(String),
    /// A config rule matched. `detail` is the rendered rule message.
    ConfigRule { source: RuleSource, detail: String },
    /// A Claude Code `permissions.allow` entry matched.
    CcPermission(String),
    /// No rule or handler matched and the configured `default-action` is allow.
    DefaultAction { cmd: String, weakening: String },
    /// A `PostToolUse` after-rule produced a message.
    AfterRule(String),
}

impl AllowReason {
    /// Build a handler-provenance reason from a handler's description.
    pub fn handler(detail: impl Into<String>) -> Self {
        Self::Handler(detail.into())
    }
}

impl fmt::Display for AllowReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => Ok(()),
            Self::EmptyCommand => f.write_str("empty command"),
            Self::SimpleSafe(cmd) => write!(f, "{cmd} is safe"),
            Self::Wrapper(cmd) => write!(f, "{cmd} (no inner command)"),
            Self::HelpFlag(cmd) => write!(f, "{cmd} help/version"),
            Self::DynamicArgSafe(cmd) => write!(f, "{cmd} is safe (dynamic arg)"),
            Self::InputRedirect => f.write_str("input redirect"),
            Self::FdRedirect => f.write_str("fd redirect"),
            Self::DeviceRedirect(target) => write!(f, "redirect to {target}"),
            Self::SafeDirWrite(target) => write!(f, "redirect to {target} (safe dir)"),
            Self::Heredoc => f.write_str("heredoc"),
            Self::Handler(detail) | Self::ConfigRule { detail, .. } | Self::AfterRule(detail) => {
                f.write_str(detail)
            }
            Self::CcPermission(cmd) => write!(f, "{cmd} (CC permission: allow)"),
            Self::DefaultAction { cmd, weakening } => {
                write!(f, "{cmd} (default action){weakening}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::{Decision, Verdict};

    /// The wire lock: each expected string is the literal that variant replaced.
    /// A new variant must be added here, and a changed string is a wire-format
    /// change that has to be deliberate.
    #[test]
    fn display_reproduces_wire_strings() {
        let cases: Vec<(AllowReason, &str)> = vec![
            (AllowReason::Empty, ""),
            (AllowReason::EmptyCommand, "empty command"),
            (AllowReason::SimpleSafe("ls".into()), "ls is safe"),
            (AllowReason::Wrapper("env".into()), "env (no inner command)"),
            (AllowReason::HelpFlag("tar".into()), "tar help/version"),
            (
                AllowReason::DynamicArgSafe("cat".into()),
                "cat is safe (dynamic arg)",
            ),
            (AllowReason::InputRedirect, "input redirect"),
            (AllowReason::FdRedirect, "fd redirect"),
            (
                AllowReason::DeviceRedirect("/dev/null".into()),
                "redirect to /dev/null",
            ),
            (
                AllowReason::SafeDirWrite("/tmp/x".into()),
                "redirect to /tmp/x (safe dir)",
            ),
            (AllowReason::Heredoc, "heredoc"),
            (AllowReason::handler("git status"), "git status"),
            (
                AllowReason::ConfigRule {
                    source: RuleSource::Baseline,
                    detail: "matched rule: command=ls".into(),
                },
                "matched rule: command=ls",
            ),
            (
                AllowReason::ConfigRule {
                    source: RuleSource::Project,
                    detail: "matched project rule (overrides ask: foo*) [weakened]".into(),
                },
                "matched project rule (overrides ask: foo*) [weakened]",
            ),
            (
                AllowReason::CcPermission("ls -la".into()),
                "ls -la (CC permission: allow)",
            ),
            (
                AllowReason::DefaultAction {
                    cmd: "foo".into(),
                    weakening: String::new(),
                },
                "foo (default action)",
            ),
            (
                AllowReason::DefaultAction {
                    cmd: "foo".into(),
                    weakening: " | NOTE: project config allows by default".into(),
                },
                "foo (default action) | NOTE: project config allows by default",
            ),
            (AllowReason::AfterRule("ran linter".into()), "ran linter"),
        ];
        for (reason, expected) in cases {
            assert_eq!(reason.to_string(), expected, "Display for {reason:?}");
        }
    }

    #[test]
    fn display_drives_the_verdict_reason() {
        let v = Verdict::allow(AllowReason::SimpleSafe("ls".into()));
        assert_eq!(v.reason, "ls is safe");
        assert_eq!(v.decision, Decision::Allow);
    }
}
