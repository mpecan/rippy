use crate::mode::{HookType, Mode, PermissionMode};

#[path = "allow_reason.rs"]
mod allow_reason;

pub use allow_reason::{AllowReason, RuleSource};

/// The three possible safety decisions, ordered so `max()` gives the most restrictive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Decision {
    Allow,
    Ask,
    Deny,
}

/// A decision paired with a human-readable reason.
///
/// Construct one through [`Verdict::allow`], [`Verdict::ask`], [`Verdict::deny`]
/// or [`Verdict::from_rule`]: the private `allow_reason` field makes struct
/// literals impossible outside this module, which is what forces every approval
/// through the typed [`AllowReason`] surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub decision: Decision,
    /// Human-readable reason, part of the JSON hook output. For an approval it
    /// is *initialized* from `Display for AllowReason`; the analyzer may later
    /// append `(resolved: …)` to it, so it is not permanently equal to that
    /// rendering.
    pub reason: String,
    /// The fully-resolved command (after expansion of `$VAR`, `$'...'`, `$((...))`,
    /// etc.) when the analyzer was able to statically resolve all expansions.
    /// `None` when no resolution occurred or it failed.
    pub resolved_command: Option<String>,
    /// Typed provenance of an approval; always `None` for `Ask`/`Deny`.
    allow_reason: Option<AllowReason>,
}

impl Verdict {
    #[must_use]
    pub fn allow(reason: AllowReason) -> Self {
        Self {
            decision: Decision::Allow,
            reason: reason.to_string(),
            resolved_command: None,
            allow_reason: Some(reason),
        }
    }

    #[must_use]
    pub fn ask(reason: impl Into<String>) -> Self {
        Self {
            decision: Decision::Ask,
            reason: reason.into(),
            resolved_command: None,
            allow_reason: None,
        }
    }

    #[must_use]
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            decision: Decision::Deny,
            reason: reason.into(),
            resolved_command: None,
            allow_reason: None,
        }
    }

    /// Build the verdict for a matched config rule, typing the allow arm as
    /// [`AllowReason::ConfigRule`] while `ask`/`deny` keep their free text.
    #[must_use]
    pub fn from_rule(decision: Decision, reason: String, source: RuleSource) -> Self {
        match decision {
            Decision::Allow => Self::allow(AllowReason::ConfigRule {
                source,
                detail: reason,
            }),
            Decision::Ask => Self::ask(reason),
            Decision::Deny => Self::deny(reason),
        }
    }

    /// Typed provenance of this approval, or `None` for `Ask`/`Deny`.
    #[must_use]
    pub const fn allow_reason(&self) -> Option<&AllowReason> {
        self.allow_reason.as_ref()
    }

    /// Attach a resolved command form to this verdict for transparency.
    #[must_use]
    pub fn with_resolution(mut self, resolved: impl Into<String>) -> Self {
        self.resolved_command = Some(resolved.into());
        self
    }

    /// Combine multiple verdicts, keeping the most restrictive decision
    /// and the reason from whichever verdict drove that decision.
    ///
    /// The resolved command is preserved from the chosen verdict, or from any
    /// other verdict in the input if the chosen one has none — so resolution
    /// info is never accidentally dropped during combination.
    #[must_use]
    pub fn combine(verdicts: &[Self]) -> Self {
        let mut chosen = verdicts
            .iter()
            .max_by_key(|v| v.decision)
            .cloned()
            .unwrap_or_default();
        if chosen.resolved_command.is_none() {
            chosen.resolved_command = verdicts.iter().find_map(|v| v.resolved_command.clone());
        }
        chosen
    }

    /// Serialize this verdict as JSON for the given AI tool mode.
    ///
    /// `ctx` carries the hook type, Claude's active permission mode, and the
    /// `auto-mode` policy; only the Claude arm consults the mode.
    #[must_use]
    pub fn to_json(&self, mode: Mode, ctx: ClaudeContext) -> serde_json::Value {
        match mode {
            Mode::Claude => self.to_claude_json(ctx),
            Mode::Gemini | Mode::Codex => serde_json::json!({
                "decision": self.decision.as_gemini_str(),
                "reason": self.reason,
            }),
            Mode::Cursor => serde_json::json!({
                "permission": self.decision.as_str(),
                "userMessage": self.reason,
                "agentMessage": self.reason,
            }),
        }
    }

    /// Build the Claude Code hook output. The `hookEventName` field is required
    /// by Claude's validator and must match the firing event. `permissionDecision`
    /// is `PreToolUse`-only; `PostToolUse` surfaces any message via `additionalContext`.
    ///
    /// In an auto permission mode an uncertain `Ask` is resolved to `defer`
    /// (see [`Decision::resolve_claude`]) so rippy steps aside for the mode.
    fn to_claude_json(&self, ctx: ClaudeContext) -> serde_json::Value {
        match ctx.hook_type {
            HookType::PreToolUse => {
                let decision = self
                    .decision
                    .resolve_claude(ctx.permission_mode, ctx.auto_mode);
                serde_json::json!({
                    "hookSpecificOutput": {
                        "hookEventName": ctx.hook_type.event_name(),
                        "permissionDecision": decision.as_str(),
                        "permissionDecisionReason": self.reason,
                    }
                })
            }
            HookType::PostToolUse => {
                let mut inner = serde_json::json!({ "hookEventName": ctx.hook_type.event_name() });
                if !self.reason.is_empty() {
                    inner["additionalContext"] = serde_json::json!(self.reason);
                }
                serde_json::json!({ "hookSpecificOutput": inner })
            }
        }
    }
}

/// The `auto-mode` config policy: how an uncertain `Ask` behaves in Claude's
/// auto permission modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AutoMode {
    /// Default — step aside in auto modes so the mode decides (emit `defer`).
    #[default]
    Defer,
    /// Force rippy's prompt even in auto modes (emit `ask`).
    Ask,
}

/// Context for rendering a Claude Code hook verdict: the firing event, the
/// session's permission mode, and the `auto-mode` policy.
#[derive(Debug, Clone, Copy)]
pub struct ClaudeContext {
    pub hook_type: HookType,
    pub permission_mode: PermissionMode,
    pub auto_mode: AutoMode,
}

/// The Claude `permissionDecision` wire value after applying permission-mode
/// policy. `Defer` hands the decision back to Claude's normal evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaudeDecision {
    Allow,
    Ask,
    Deny,
    Defer,
}

impl ClaudeDecision {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Ask => "ask",
            Self::Deny => "deny",
            Self::Defer => "defer",
        }
    }

    /// Whether this decision blocks the tool call (drives exit code 2). Only a
    /// hard `deny` blocks; `ask`/`defer` exit 0 and let the JSON decision drive.
    #[must_use]
    pub const fn blocks(self) -> bool {
        matches!(self, Self::Deny)
    }
}

impl Default for Verdict {
    fn default() -> Self {
        Self::allow(AllowReason::Empty)
    }
}

impl Decision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Ask => "ask",
            Self::Deny => "deny",
        }
    }

    /// Gemini has no "ask" concept — map Ask to "deny".
    const fn as_gemini_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Ask | Self::Deny => "deny",
        }
    }

    /// Resolve this verdict to the Claude wire decision. `Allow` and `Deny` are
    /// unconditional (deny is the hard floor); an `Ask` becomes `Defer` only in
    /// an auto permission mode when the `auto-mode` policy defers, otherwise it
    /// stays `Ask`.
    #[must_use]
    pub const fn resolve_claude(
        self,
        permission_mode: PermissionMode,
        auto_mode: AutoMode,
    ) -> ClaudeDecision {
        match self {
            Self::Allow => ClaudeDecision::Allow,
            Self::Deny => ClaudeDecision::Deny,
            Self::Ask if matches!(auto_mode, AutoMode::Defer) && permission_mode.is_auto() => {
                ClaudeDecision::Defer
            }
            Self::Ask => ClaudeDecision::Ask,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Manual permission mode with deferral enabled — the default rendering
    /// context, so existing serialization tests keep their original behavior.
    fn ctx(hook_type: HookType) -> ClaudeContext {
        ClaudeContext {
            hook_type,
            permission_mode: PermissionMode::Default,
            auto_mode: AutoMode::Defer,
        }
    }

    #[test]
    fn resolve_claude_allow_and_deny_are_unconditional() {
        for mode in [PermissionMode::Default, PermissionMode::BypassPermissions] {
            for auto_mode in [AutoMode::Defer, AutoMode::Ask] {
                assert_eq!(
                    Decision::Allow.resolve_claude(mode, auto_mode),
                    ClaudeDecision::Allow
                );
                assert_eq!(
                    Decision::Deny.resolve_claude(mode, auto_mode),
                    ClaudeDecision::Deny
                );
            }
        }
    }

    #[test]
    fn resolve_claude_ask_defers_only_in_auto_mode() {
        // Manual modes always keep the prompt.
        assert_eq!(
            Decision::Ask.resolve_claude(PermissionMode::Default, AutoMode::Defer),
            ClaudeDecision::Ask
        );
        assert_eq!(
            Decision::Ask.resolve_claude(PermissionMode::Plan, AutoMode::Defer),
            ClaudeDecision::Ask
        );
        // Auto modes defer when the policy defers.
        assert_eq!(
            Decision::Ask.resolve_claude(PermissionMode::AcceptEdits, AutoMode::Defer),
            ClaudeDecision::Defer
        );
        assert_eq!(
            Decision::Ask.resolve_claude(PermissionMode::BypassPermissions, AutoMode::Defer),
            ClaudeDecision::Defer
        );
    }

    #[test]
    fn resolve_claude_ask_knob_off_keeps_prompt_in_auto_mode() {
        assert_eq!(
            Decision::Ask.resolve_claude(PermissionMode::AcceptEdits, AutoMode::Ask),
            ClaudeDecision::Ask
        );
    }

    #[test]
    fn claude_decision_wire_strings_and_blocking() {
        assert_eq!(ClaudeDecision::Allow.as_str(), "allow");
        assert_eq!(ClaudeDecision::Ask.as_str(), "ask");
        assert_eq!(ClaudeDecision::Deny.as_str(), "deny");
        assert_eq!(ClaudeDecision::Defer.as_str(), "defer");
        assert!(ClaudeDecision::Deny.blocks());
        assert!(!ClaudeDecision::Ask.blocks());
        assert!(!ClaudeDecision::Defer.blocks());
        assert!(!ClaudeDecision::Allow.blocks());
    }

    #[test]
    fn claude_ask_defers_in_auto_mode() {
        let auto_ctx = ClaudeContext {
            hook_type: HookType::PreToolUse,
            permission_mode: PermissionMode::AcceptEdits,
            auto_mode: AutoMode::Defer,
        };
        let json = Verdict::ask("uncertain command").to_json(Mode::Claude, auto_ctx);
        assert_eq!(json["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "defer");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecisionReason"],
            "uncertain command"
        );
    }

    #[test]
    fn claude_deny_holds_in_auto_mode() {
        let auto_ctx = ClaudeContext {
            hook_type: HookType::PreToolUse,
            permission_mode: PermissionMode::BypassPermissions,
            auto_mode: AutoMode::Defer,
        };
        let json = Verdict::deny("dangerous").to_json(Mode::Claude, auto_ctx);
        assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
    }

    #[test]
    fn claude_ask_stays_ask_in_manual_mode() {
        let json = Verdict::ask("review").to_json(Mode::Claude, ctx(HookType::PreToolUse));
        assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "ask");
    }

    #[test]
    fn allow_reason_present_only_for_allow() {
        assert!(
            Verdict::allow(AllowReason::Heredoc)
                .allow_reason()
                .is_some()
        );
        assert!(Verdict::ask("review").allow_reason().is_none());
        assert!(Verdict::deny("dangerous").allow_reason().is_none());
    }

    #[test]
    fn from_rule_types_allow_only() {
        let allow = Verdict::from_rule(
            Decision::Allow,
            "matched rule: command=ls".to_owned(),
            RuleSource::Project,
        );
        assert_eq!(
            allow.allow_reason(),
            Some(&AllowReason::ConfigRule {
                source: RuleSource::Project,
                detail: "matched rule: command=ls".to_owned(),
            })
        );
        assert_eq!(allow.reason, "matched rule: command=ls");

        for decision in [Decision::Ask, Decision::Deny] {
            let v = Verdict::from_rule(
                decision,
                "matched rule: command=rm".to_owned(),
                RuleSource::Baseline,
            );
            assert_eq!(v.decision, decision);
            assert_eq!(v.reason, "matched rule: command=rm");
            assert!(v.allow_reason().is_none());
        }
    }

    #[test]
    fn decision_ordering() {
        assert!(Decision::Allow < Decision::Ask);
        assert!(Decision::Ask < Decision::Deny);
        assert!(Decision::Allow < Decision::Deny);
    }

    #[test]
    fn combine_takes_most_restrictive() {
        let verdicts = vec![
            Verdict::allow(AllowReason::handler("safe")),
            Verdict::ask("needs review"),
            Verdict::allow(AllowReason::handler("also safe")),
        ];
        let combined = Verdict::combine(&verdicts);
        assert_eq!(combined.decision, Decision::Ask);
        assert_eq!(combined.reason, "needs review");
    }

    #[test]
    fn combine_empty_defaults_to_allow() {
        let combined = Verdict::combine(&[]);
        assert_eq!(combined.decision, Decision::Allow);
    }

    #[test]
    fn claude_json_format() {
        let v = Verdict::allow(AllowReason::handler("git status is safe"));
        let json = v.to_json(Mode::Claude, ctx(HookType::PreToolUse));
        assert_eq!(json["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "allow");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecisionReason"],
            "git status is safe"
        );
    }

    #[test]
    fn claude_post_tool_uses_post_event_name() {
        let v = Verdict::allow(AllowReason::Empty);
        let json = v.to_json(Mode::Claude, ctx(HookType::PostToolUse));
        assert_eq!(json["hookSpecificOutput"]["hookEventName"], "PostToolUse");
        // permissionDecision is PreToolUse-only and must not appear here.
        assert!(
            json["hookSpecificOutput"]
                .get("permissionDecision")
                .is_none()
        );
        assert!(
            json["hookSpecificOutput"]
                .get("additionalContext")
                .is_none()
        );
    }

    #[test]
    fn claude_post_tool_maps_reason_to_additional_context() {
        let v = Verdict::allow(AllowReason::AfterRule("ran linter".into()));
        let json = v.to_json(Mode::Claude, ctx(HookType::PostToolUse));
        assert_eq!(json["hookSpecificOutput"]["hookEventName"], "PostToolUse");
        assert_eq!(
            json["hookSpecificOutput"]["additionalContext"],
            "ran linter"
        );
        assert!(
            json["hookSpecificOutput"]
                .get("permissionDecision")
                .is_none()
        );
    }

    #[test]
    fn claude_deny_includes_hook_event_name() {
        let json = Verdict::deny("dangerous").to_json(Mode::Claude, ctx(HookType::PreToolUse));
        assert_eq!(json["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
    }

    #[test]
    fn gemini_ask_maps_to_deny() {
        let v = Verdict::ask("needs review");
        let json = v.to_json(Mode::Gemini, ctx(HookType::PreToolUse));
        assert_eq!(json["decision"], "deny");
    }

    #[test]
    fn cursor_json_format() {
        let v = Verdict::deny("dangerous");
        let json = v.to_json(Mode::Cursor, ctx(HookType::PreToolUse));
        assert_eq!(json["permission"], "deny");
        assert_eq!(json["userMessage"], "dangerous");
        assert_eq!(json["agentMessage"], "dangerous");
    }

    #[test]
    fn with_resolution_attaches_resolved_command() {
        let v = Verdict::allow(AllowReason::SimpleSafe("ls".into())).with_resolution("ls /tmp");
        assert_eq!(v.resolved_command.as_deref(), Some("ls /tmp"));
        assert_eq!(v.decision, Decision::Allow);
    }

    #[test]
    fn combine_preserves_resolved_command_from_chosen() {
        let verdicts = vec![
            Verdict::allow(AllowReason::handler("safe")),
            Verdict::ask("review").with_resolution("rm -rf /tmp"),
        ];
        let combined = Verdict::combine(&verdicts);
        assert_eq!(combined.decision, Decision::Ask);
        assert_eq!(combined.resolved_command.as_deref(), Some("rm -rf /tmp"));
    }

    #[test]
    fn combine_borrows_resolved_command_from_other_when_chosen_has_none() {
        let verdicts = vec![
            Verdict::ask("review"),
            Verdict::allow(AllowReason::handler("safe")).with_resolution("ls /tmp"),
        ];
        let combined = Verdict::combine(&verdicts);
        assert_eq!(combined.decision, Decision::Ask);
        assert_eq!(combined.resolved_command.as_deref(), Some("ls /tmp"));
    }

    #[test]
    fn json_output_unchanged_when_resolved_present() {
        // resolved_command is internal-only, not part of any wire format
        let v = Verdict::allow(AllowReason::SimpleSafe("ls".into())).with_resolution("ls /tmp");
        let json = v.to_json(Mode::Claude, ctx(HookType::PreToolUse));
        assert!(json.get("resolved_command").is_none());
        assert!(json["hookSpecificOutput"].get("resolved_command").is_none());
    }
}
