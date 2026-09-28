/// Why a verdict is `Ask`: a human must approve, or rippy could not decide.
///
/// Every `Ask` is [`AskClass::Approval`] unless the site that minted it opted
/// into [`AskClass::Uncertain`] explicitly, so an unclassified ask can never be
/// mistaken for a merely uncertain one. The class is metadata only: it never
/// changes the decision, the reason string, or the hook output.
/// See docs/jev.md#two-kinds-of-ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AskClass {
    /// rippy understands the command and a human must approve it.
    Approval,
    /// rippy cannot determine whether the command is safe.
    Uncertain(UncertainKind),
}

/// What kept rippy from deciding an [`AskClass::Uncertain`] ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UncertainKind {
    /// No handler and no rule knows the command.
    UnknownCommand,
    /// A handler knows the command but not this subcommand.
    UnknownSubcommand,
    /// An unresolvable `$VAR`, `$(…)` or other expansion hides the real argv.
    DynamicExpansion,
    /// The command's behaviour lives in input rippy cannot see: an unreadable
    /// script or SQL file, or an interactive REPL.
    OpaqueInput,
    /// rippy could not analyze the input at all: parse failure, size or depth
    /// limits, internal errors, fail-closed paths.
    Unanalyzable,
    /// rippy judged a command it rebuilt from another command's arguments
    /// (a wrapper, `env`, `xargs`, `find -exec`) or read from a file (a shell
    /// script), so the command as written is not the text it judged.
    Indirect,
    /// What runs is defined outside the command text, by files or config the
    /// project controls: a path-qualified or script-named program, a task
    /// runner, a possible git alias, an interpreter given a script. A reviewer
    /// that sees only the text cannot judge it.
    ProjectDefined,
}

impl AskClass {
    /// Every class, for exhaustive tests and catalog validation.
    pub const ALL: [Self; 8] = [
        Self::Approval,
        Self::Uncertain(UncertainKind::UnknownCommand),
        Self::Uncertain(UncertainKind::UnknownSubcommand),
        Self::Uncertain(UncertainKind::DynamicExpansion),
        Self::Uncertain(UncertainKind::OpaqueInput),
        Self::Uncertain(UncertainKind::Unanalyzable),
        Self::Uncertain(UncertainKind::Indirect),
        Self::Uncertain(UncertainKind::ProjectDefined),
    ];

    /// Stable kebab-case name, used by the catalog and the reason snapshot.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approval => "approval",
            Self::Uncertain(kind) => kind.as_str(),
        }
    }

    /// Merge rank when several asks combine: `Approval` dominates, then the
    /// kinds a text-only reviewer can never judge, so a compound command is
    /// only as eligible for model-assisted review as its least-understood part.
    const fn rank(self) -> u8 {
        match self {
            Self::Approval => 2,
            Self::Uncertain(
                UncertainKind::Unanalyzable
                | UncertainKind::Indirect
                | UncertainKind::ProjectDefined,
            ) => 1,
            Self::Uncertain(_) => 0,
        }
    }

    /// Whether a text-only reviewer could ever judge an ask of this class.
    #[must_use]
    pub const fn is_reviewable(self) -> bool {
        self.rank() == 0
    }

    /// The more cautious of two classes; `self` wins ties.
    #[must_use]
    pub const fn max(self, other: Self) -> Self {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }
}

impl UncertainKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownCommand => "unknown-command",
            Self::UnknownSubcommand => "unknown-subcommand",
            Self::DynamicExpansion => "dynamic-expansion",
            Self::OpaqueInput => "opaque-input",
            Self::Unanalyzable => "unanalyzable",
            Self::Indirect => "indirect",
            Self::ProjectDefined => "project-defined",
        }
    }
}

impl std::fmt::Display for AskClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::super::Verdict;
    use super::{AskClass, UncertainKind};

    const DYN: AskClass = AskClass::Uncertain(UncertainKind::DynamicExpansion);
    const UNA: AskClass = AskClass::Uncertain(UncertainKind::Unanalyzable);

    #[test]
    fn names_are_unique_and_stable() {
        let names: Vec<&str> = AskClass::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(
            names,
            [
                "approval",
                "unknown-command",
                "unknown-subcommand",
                "dynamic-expansion",
                "opaque-input",
                "unanalyzable",
                "indirect",
                "project-defined"
            ]
        );
    }

    #[test]
    fn approval_dominates_every_uncertain_kind() {
        for class in AskClass::ALL {
            assert_eq!(AskClass::Approval.max(class), AskClass::Approval);
            assert_eq!(class.max(AskClass::Approval), AskClass::Approval);
        }
    }

    #[test]
    fn unanalyzable_dominates_other_uncertain_kinds() {
        assert_eq!(DYN.max(UNA), UNA);
        assert_eq!(UNA.max(DYN), UNA);
    }

    #[test]
    fn equal_rank_keeps_self() {
        let unknown = AskClass::Uncertain(UncertainKind::UnknownCommand);
        assert_eq!(DYN.max(unknown), DYN);
        assert_eq!(unknown.max(DYN), unknown);
    }

    #[test]
    fn constructors_set_class_only_on_ask() {
        assert_eq!(Verdict::ask("x").ask_class(), Some(AskClass::Approval));
        let uncertain = Verdict::uncertain(UncertainKind::DynamicExpansion, "x");
        assert_eq!(uncertain.ask_class(), Some(DYN));
        assert_eq!(Verdict::deny("x").ask_class(), None);
        let allow = Verdict::allow(crate::verdict::AllowReason::Empty);
        assert_eq!(allow.ask_class(), None);
    }

    #[test]
    fn combine_keeps_reason_but_takes_most_cautious_class() {
        let v = Verdict::combine(&[
            Verdict::ask("git push"),
            Verdict::uncertain(UncertainKind::DynamicExpansion, "shell expansion"),
        ]);
        // `max_by_key` keeps the last of equal decisions, so the reason is the
        // uncertain one's while the class is the approval it combined with.
        assert_eq!(v.reason, "shell expansion");
        assert_eq!(v.ask_class(), Some(AskClass::Approval));
    }

    #[test]
    fn combine_of_uncertain_asks_stays_uncertain() {
        let v = Verdict::combine(&[
            Verdict::allow(crate::verdict::AllowReason::Empty),
            Verdict::uncertain(UncertainKind::UnknownCommand, "a"),
            Verdict::uncertain(UncertainKind::DynamicExpansion, "b"),
        ]);
        assert_eq!(v.ask_class(), Some(DYN));
    }

    #[test]
    fn combine_under_deny_has_no_class() {
        let v = Verdict::combine(&[Verdict::ask("a"), Verdict::deny("b")]);
        assert_eq!(v.ask_class(), None);
    }

    #[test]
    fn combine_empty_is_unanalyzable() {
        assert_eq!(Verdict::combine(&[]).ask_class(), Some(UNA));
    }

    #[test]
    fn most_restrictive_keeps_first_reason_and_merges_class() {
        let v = Verdict::most_restrictive(
            Verdict::uncertain(UncertainKind::DynamicExpansion, "first"),
            Verdict::ask("second"),
        );
        assert_eq!(v.reason, "first");
        assert_eq!(v.ask_class(), Some(AskClass::Approval));
    }

    #[test]
    fn most_restrictive_ignores_class_of_less_restrictive_side() {
        let v = Verdict::most_restrictive(
            Verdict::allow(crate::verdict::AllowReason::Empty),
            Verdict::uncertain(UncertainKind::DynamicExpansion, "b"),
        );
        assert_eq!(v.ask_class(), Some(DYN));
        let v = Verdict::most_restrictive(Verdict::deny("a"), Verdict::ask("b"));
        assert_eq!(v.ask_class(), None);
    }
}
