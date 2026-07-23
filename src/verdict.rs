use crate::mode::{HookType, Mode};

/// The three possible safety decisions, ordered so `max()` gives the most restrictive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Decision {
    Allow,
    Ask,
    Deny,
}

/// A decision paired with a human-readable reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub decision: Decision,
    pub reason: String,
    /// The fully-resolved command (after expansion of `$VAR`, `$'...'`, `$((...))`,
    /// etc.) when the analyzer was able to statically resolve all expansions.
    /// `None` when no resolution occurred or it failed.
    pub resolved_command: Option<String>,
}

impl Verdict {
    #[must_use]
    pub fn allow(reason: impl Into<String>) -> Self {
        Self {
            decision: Decision::Allow,
            reason: reason.into(),
            resolved_command: None,
        }
    }

    #[must_use]
    pub fn ask(reason: impl Into<String>) -> Self {
        Self {
            decision: Decision::Ask,
            reason: reason.into(),
            resolved_command: None,
        }
    }

    #[must_use]
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            decision: Decision::Deny,
            reason: reason.into(),
            resolved_command: None,
        }
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

    /// Serialize this verdict as JSON for the given AI tool mode and hook type.
    #[must_use]
    pub fn to_json(&self, mode: Mode, hook_type: HookType) -> serde_json::Value {
        match mode {
            Mode::Claude => self.to_claude_json(hook_type),
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
    fn to_claude_json(&self, hook_type: HookType) -> serde_json::Value {
        match hook_type {
            HookType::PreToolUse => serde_json::json!({
                "hookSpecificOutput": {
                    "hookEventName": hook_type.event_name(),
                    "permissionDecision": self.decision.as_str(),
                    "permissionDecisionReason": self.reason,
                }
            }),
            HookType::PostToolUse => {
                let mut inner = serde_json::json!({ "hookEventName": hook_type.event_name() });
                if !self.reason.is_empty() {
                    inner["additionalContext"] = serde_json::json!(self.reason);
                }
                serde_json::json!({ "hookSpecificOutput": inner })
            }
        }
    }
}

impl Default for Verdict {
    fn default() -> Self {
        Self {
            decision: Decision::Allow,
            reason: String::new(),
            resolved_command: None,
        }
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::unwrap_used)]
    #[test]
    fn decision_ordering() {
        assert!(Decision::Allow < Decision::Ask);
        assert!(Decision::Ask < Decision::Deny);
        assert!(Decision::Allow < Decision::Deny);
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn combine_takes_most_restrictive() {
        let verdicts = vec![
            Verdict::allow("safe"),
            Verdict::ask("needs review"),
            Verdict::allow("also safe"),
        ];
        let combined = Verdict::combine(&verdicts);
        assert_eq!(combined.decision, Decision::Ask);
        assert_eq!(combined.reason, "needs review");
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn combine_empty_defaults_to_allow() {
        let combined = Verdict::combine(&[]);
        assert_eq!(combined.decision, Decision::Allow);
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn claude_json_format() {
        let v = Verdict::allow("git status is safe");
        let json = v.to_json(Mode::Claude, HookType::PreToolUse);
        assert_eq!(json["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "allow");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecisionReason"],
            "git status is safe"
        );
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn claude_post_tool_uses_post_event_name() {
        let v = Verdict::allow("");
        let json = v.to_json(Mode::Claude, HookType::PostToolUse);
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

    #[allow(clippy::unwrap_used)]
    #[test]
    fn claude_post_tool_maps_reason_to_additional_context() {
        let v = Verdict::allow("ran linter");
        let json = v.to_json(Mode::Claude, HookType::PostToolUse);
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

    #[allow(clippy::unwrap_used)]
    #[test]
    fn claude_deny_includes_hook_event_name() {
        let json = Verdict::deny("dangerous").to_json(Mode::Claude, HookType::PreToolUse);
        assert_eq!(json["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "deny");
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn gemini_ask_maps_to_deny() {
        let v = Verdict::ask("needs review");
        let json = v.to_json(Mode::Gemini, HookType::PreToolUse);
        assert_eq!(json["decision"], "deny");
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn cursor_json_format() {
        let v = Verdict::deny("dangerous");
        let json = v.to_json(Mode::Cursor, HookType::PreToolUse);
        assert_eq!(json["permission"], "deny");
        assert_eq!(json["userMessage"], "dangerous");
        assert_eq!(json["agentMessage"], "dangerous");
    }

    #[test]
    fn with_resolution_attaches_resolved_command() {
        let v = Verdict::allow("ls is safe").with_resolution("ls /tmp");
        assert_eq!(v.resolved_command.as_deref(), Some("ls /tmp"));
        assert_eq!(v.decision, Decision::Allow);
    }

    #[test]
    fn combine_preserves_resolved_command_from_chosen() {
        let verdicts = vec![
            Verdict::allow("safe"),
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
            Verdict::allow("safe").with_resolution("ls /tmp"),
        ];
        let combined = Verdict::combine(&verdicts);
        assert_eq!(combined.decision, Decision::Ask);
        assert_eq!(combined.resolved_command.as_deref(), Some("ls /tmp"));
    }

    #[test]
    fn json_output_unchanged_when_resolved_present() {
        // resolved_command is internal-only, not part of any wire format
        let v = Verdict::allow("ls is safe").with_resolution("ls /tmp");
        let json = v.to_json(Mode::Claude, HookType::PreToolUse);
        assert!(json.get("resolved_command").is_none());
        assert!(json["hookSpecificOutput"].get("resolved_command").is_none());
    }
}
