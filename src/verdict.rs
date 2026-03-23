use crate::mode::Mode;

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
}

impl Verdict {
    #[must_use]
    pub fn allow(reason: impl Into<String>) -> Self {
        Self {
            decision: Decision::Allow,
            reason: reason.into(),
        }
    }

    #[must_use]
    pub fn ask(reason: impl Into<String>) -> Self {
        Self {
            decision: Decision::Ask,
            reason: reason.into(),
        }
    }

    #[must_use]
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            decision: Decision::Deny,
            reason: reason.into(),
        }
    }

    /// Combine multiple verdicts, keeping the most restrictive decision
    /// and the reason from whichever verdict drove that decision.
    #[must_use]
    pub fn combine(verdicts: &[Self]) -> Self {
        verdicts
            .iter()
            .max_by_key(|v| v.decision)
            .cloned()
            .unwrap_or_default()
    }

    /// Serialize this verdict as JSON for the given AI tool mode.
    #[must_use]
    pub fn to_json(&self, mode: Mode) -> serde_json::Value {
        match mode {
            Mode::Claude => serde_json::json!({
                "hookSpecificOutput": {
                    "permissionDecision": self.decision.as_str(),
                    "permissionDecisionReason": self.reason,
                }
            }),
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
}

impl Default for Verdict {
    fn default() -> Self {
        Self {
            decision: Decision::Allow,
            reason: String::new(),
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
        let json = v.to_json(Mode::Claude);
        assert_eq!(json["hookSpecificOutput"]["permissionDecision"], "allow");
        assert_eq!(
            json["hookSpecificOutput"]["permissionDecisionReason"],
            "git status is safe"
        );
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn gemini_ask_maps_to_deny() {
        let v = Verdict::ask("needs review");
        let json = v.to_json(Mode::Gemini);
        assert_eq!(json["decision"], "deny");
    }

    #[allow(clippy::unwrap_used)]
    #[test]
    fn cursor_json_format() {
        let v = Verdict::deny("dangerous");
        let json = v.to_json(Mode::Cursor);
        assert_eq!(json["permission"], "deny");
        assert_eq!(json["userMessage"], "dangerous");
        assert_eq!(json["agentMessage"], "dangerous");
    }
}
