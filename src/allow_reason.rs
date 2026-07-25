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

/// The `docs/allow-catalog.md` section an [`AllowReason`] is documented under.
///
/// [`AllowReason::category`] maps every variant exhaustively, so a new reason
/// cannot be added without deciding where it appears in the published allow
/// catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowCategory {
    /// Parse-shape approvals that carry no command to judge.
    Structural,
    /// The static command-name allowlists.
    Allowlist,
    /// The allowlist relaxation for set-but-unknown argument values.
    DynamicArg,
    /// Redirect targets that cannot write anything worth guarding.
    Redirect,
    /// A command-specific handler.
    Handler,
    /// A config rule (stdlib, package, git style, global or project).
    Rule,
    /// Approvals that exist only because this machine's config asked for them.
    UserControlled,
}

impl AllowCategory {
    /// Every category, in the order the catalog renders them.
    pub const ALL: &'static [Self] = &[
        Self::Allowlist,
        Self::DynamicArg,
        Self::Handler,
        Self::Rule,
        Self::Redirect,
        Self::Structural,
        Self::UserControlled,
    ];

    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Structural => "Structural approvals",
            Self::Allowlist => "Command-name allowlists",
            Self::DynamicArg => "Dynamic-argument relaxation",
            Self::Redirect => "Redirect targets",
            Self::Handler => "Handler surfaces",
            Self::Rule => "Rule bundles",
            Self::UserControlled => "User-controlled (not shipped)",
        }
    }

    #[must_use]
    pub const fn summary(self) -> &'static str {
        match self {
            Self::Structural => {
                "Shapes with nothing to judge: an empty node, a bare assignment, a heredoc body."
            }
            Self::Allowlist => "Commands approved on their name alone, regardless of arguments.",
            Self::DynamicArg => {
                "Which allowlist commands stay approved when an argument is set but unknown."
            }
            Self::Redirect => "Which redirect targets are approved without asking.",
            Self::Handler => "Per-command handlers: the exact invocations each one auto-approves.",
            Self::Rule => "Allow rules from the embedded stdlib and the opt-in bundles.",
            Self::UserControlled => {
                "Approvals that come from this machine's configuration, not from rippy's defaults."
            }
        }
    }
}

impl AllowReason {
    /// Build a handler-provenance reason from a handler's description.
    pub fn handler(detail: impl Into<String>) -> Self {
        Self::Handler(detail.into())
    }

    /// Which catalog section documents this kind of approval.
    #[must_use]
    pub const fn category(&self) -> AllowCategory {
        match self {
            Self::Empty | Self::EmptyCommand | Self::Heredoc => AllowCategory::Structural,
            Self::SimpleSafe(_) | Self::Wrapper(_) | Self::HelpFlag(_) => AllowCategory::Allowlist,
            Self::DynamicArgSafe(_) => AllowCategory::DynamicArg,
            Self::InputRedirect
            | Self::FdRedirect
            | Self::DeviceRedirect(_)
            | Self::SafeDirWrite(_) => AllowCategory::Redirect,
            Self::Handler(_) => AllowCategory::Handler,
            Self::ConfigRule { .. } => AllowCategory::Rule,
            Self::CcPermission(_) | Self::DefaultAction { .. } | Self::AfterRule(_) => {
                AllowCategory::UserControlled
            }
        }
    }

    /// Stable label for this variant, used by `rippy inspect` to name the
    /// approval's provenance. Diagnostic only — [`Display`] remains the wire
    /// string that goes into the hook's `reason` field.
    ///
    /// [`Display`]: std::fmt::Display
    #[must_use]
    pub const fn variant_name(&self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::EmptyCommand => "empty-command",
            Self::SimpleSafe(_) => "simple-safe",
            Self::Wrapper(_) => "wrapper",
            Self::HelpFlag(_) => "help-flag",
            Self::DynamicArgSafe(_) => "dynamic-arg-safe",
            Self::InputRedirect => "input-redirect",
            Self::FdRedirect => "fd-redirect",
            Self::DeviceRedirect(_) => "device-redirect",
            Self::SafeDirWrite(_) => "safe-dir-write",
            Self::Heredoc => "heredoc",
            Self::Handler(_) => "handler",
            Self::ConfigRule { .. } => "config-rule",
            Self::CcPermission(_) => "cc-permission",
            Self::DefaultAction { .. } => "default-action",
            Self::AfterRule(_) => "after-rule",
        }
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

    /// One row per variant: the reason, the literal wire string it replaced, and
    /// the catalog section it is published under. A new variant must be added
    /// here; a changed string is a wire-format change that has to be deliberate.
    #[expect(clippy::too_many_lines, reason = "one row per variant, by design")]
    fn cases() -> Vec<(AllowReason, &'static str, AllowCategory)> {
        vec![
            (AllowReason::Empty, "", AllowCategory::Structural),
            (
                AllowReason::EmptyCommand,
                "empty command",
                AllowCategory::Structural,
            ),
            (
                AllowReason::SimpleSafe("ls".into()),
                "ls is safe",
                AllowCategory::Allowlist,
            ),
            (
                AllowReason::Wrapper("env".into()),
                "env (no inner command)",
                AllowCategory::Allowlist,
            ),
            (
                AllowReason::HelpFlag("tar".into()),
                "tar help/version",
                AllowCategory::Allowlist,
            ),
            (
                AllowReason::DynamicArgSafe("cat".into()),
                "cat is safe (dynamic arg)",
                AllowCategory::DynamicArg,
            ),
            (
                AllowReason::InputRedirect,
                "input redirect",
                AllowCategory::Redirect,
            ),
            (
                AllowReason::FdRedirect,
                "fd redirect",
                AllowCategory::Redirect,
            ),
            (
                AllowReason::DeviceRedirect("/dev/null".into()),
                "redirect to /dev/null",
                AllowCategory::Redirect,
            ),
            (
                AllowReason::SafeDirWrite("/tmp/x".into()),
                "redirect to /tmp/x (safe dir)",
                AllowCategory::Redirect,
            ),
            (AllowReason::Heredoc, "heredoc", AllowCategory::Structural),
            (
                AllowReason::handler("git status"),
                "git status",
                AllowCategory::Handler,
            ),
            (
                AllowReason::ConfigRule {
                    source: RuleSource::Baseline,
                    detail: "matched rule: command=ls".into(),
                },
                "matched rule: command=ls",
                AllowCategory::Rule,
            ),
            (
                AllowReason::ConfigRule {
                    source: RuleSource::Project,
                    detail: "matched project rule (overrides ask: foo*) [weakened]".into(),
                },
                "matched project rule (overrides ask: foo*) [weakened]",
                AllowCategory::Rule,
            ),
            (
                AllowReason::CcPermission("ls -la".into()),
                "ls -la (CC permission: allow)",
                AllowCategory::UserControlled,
            ),
            (
                AllowReason::DefaultAction {
                    cmd: "foo".into(),
                    weakening: String::new(),
                },
                "foo (default action)",
                AllowCategory::UserControlled,
            ),
            (
                AllowReason::DefaultAction {
                    cmd: "foo".into(),
                    weakening: " | NOTE: project config allows by default".into(),
                },
                "foo (default action) | NOTE: project config allows by default",
                AllowCategory::UserControlled,
            ),
            (
                AllowReason::AfterRule("ran linter".into()),
                "ran linter",
                AllowCategory::UserControlled,
            ),
        ]
    }

    #[test]
    fn display_reproduces_wire_strings() {
        for (reason, expected, _) in cases() {
            assert_eq!(reason.to_string(), expected, "Display for {reason:?}");
        }
    }

    /// Pairs with the exhaustive match in [`AllowReason::category`]: together
    /// they make a new variant impossible to ship uncatalogued.
    #[test]
    fn category_is_assigned_for_every_wire_case() {
        for (reason, _, expected) in cases() {
            assert_eq!(reason.category(), expected, "category for {reason:?}");
        }
    }

    #[test]
    fn every_category_has_a_distinct_title() {
        let mut titles: Vec<&str> = AllowCategory::ALL.iter().map(|c| c.title()).collect();
        titles.sort_unstable();
        let count = titles.len();
        titles.dedup();
        assert_eq!(titles.len(), count, "AllowCategory titles must be unique");
    }

    #[test]
    fn variant_names_are_distinct_and_non_empty() {
        let variants = vec![
            AllowReason::Empty,
            AllowReason::EmptyCommand,
            AllowReason::SimpleSafe("ls".into()),
            AllowReason::Wrapper("env".into()),
            AllowReason::HelpFlag("tar".into()),
            AllowReason::DynamicArgSafe("cat".into()),
            AllowReason::InputRedirect,
            AllowReason::FdRedirect,
            AllowReason::DeviceRedirect("/dev/null".into()),
            AllowReason::SafeDirWrite("/tmp/x".into()),
            AllowReason::Heredoc,
            AllowReason::handler("git status"),
            AllowReason::ConfigRule {
                source: RuleSource::Baseline,
                detail: "matched rule: command=ls".into(),
            },
            AllowReason::CcPermission("ls".into()),
            AllowReason::DefaultAction {
                cmd: "foo".into(),
                weakening: String::new(),
            },
            AllowReason::AfterRule("ran linter".into()),
        ];
        let mut names: Vec<&str> = variants.iter().map(AllowReason::variant_name).collect();
        assert!(names.iter().all(|n| !n.is_empty()));
        let total = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), total, "variant names collide: {names:?}");
    }

    #[test]
    fn display_drives_the_verdict_reason() {
        let v = Verdict::allow(AllowReason::SimpleSafe("ls".into()));
        assert_eq!(v.reason, "ls is safe");
        assert_eq!(v.decision, Decision::Allow);
    }
}
