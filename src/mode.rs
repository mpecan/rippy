/// Which AI coding tool is invoking rippy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Claude,
    Gemini,
    Cursor,
    Codex,
}

/// Whether the hook fires before or after tool execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookType {
    PreToolUse,
    PostToolUse,
}

impl HookType {
    /// The `hookEventName` string Claude Code expects in hook output.
    pub const fn event_name(self) -> &'static str {
        match self {
            Self::PreToolUse => "PreToolUse",
            Self::PostToolUse => "PostToolUse",
        }
    }
}

/// Claude Code's active permission mode, sent on the hook payload as
/// `permission_mode`. Determines whether rippy forces a prompt for an uncertain
/// verdict or defers to the mode's own handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PermissionMode {
    /// Manual mode (also the value for `plan` when unspecified) and the safe
    /// fallback for any unrecognized or absent value — rippy keeps forcing prompts.
    #[default]
    Default,
    Plan,
    AcceptEdits,
    Auto,
    DontAsk,
    BypassPermissions,
}

impl PermissionMode {
    /// Parse the wire value of Claude's `permission_mode` field. Unknown or
    /// absent values fall back to [`PermissionMode::Default`] (force prompts).
    #[must_use]
    pub fn from_wire(value: &str) -> Self {
        match value {
            "plan" => Self::Plan,
            "acceptEdits" => Self::AcceptEdits,
            "auto" => Self::Auto,
            "dontAsk" => Self::DontAsk,
            "bypassPermissions" => Self::BypassPermissions,
            _ => Self::Default,
        }
    }

    /// Whether this is an auto mode where rippy should defer an uncertain `Ask`
    /// verdict to the mode instead of forcing a prompt. `default`/`plan` are manual.
    #[must_use]
    pub const fn is_auto(self) -> bool {
        matches!(
            self,
            Self::AcceptEdits | Self::Auto | Self::DontAsk | Self::BypassPermissions
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_wire_maps_known_modes() {
        assert_eq!(PermissionMode::from_wire("plan"), PermissionMode::Plan);
        assert_eq!(
            PermissionMode::from_wire("acceptEdits"),
            PermissionMode::AcceptEdits
        );
        assert_eq!(PermissionMode::from_wire("auto"), PermissionMode::Auto);
        assert_eq!(
            PermissionMode::from_wire("dontAsk"),
            PermissionMode::DontAsk
        );
        assert_eq!(
            PermissionMode::from_wire("bypassPermissions"),
            PermissionMode::BypassPermissions
        );
        assert_eq!(
            PermissionMode::from_wire("default"),
            PermissionMode::Default
        );
    }

    #[test]
    fn from_wire_unknown_or_empty_is_default() {
        assert_eq!(PermissionMode::from_wire(""), PermissionMode::Default);
        assert_eq!(PermissionMode::from_wire("manual"), PermissionMode::Default);
        assert_eq!(PermissionMode::from_wire("weird"), PermissionMode::Default);
    }

    #[test]
    fn is_auto_only_for_auto_modes() {
        assert!(!PermissionMode::Default.is_auto());
        assert!(!PermissionMode::Plan.is_auto());
        assert!(PermissionMode::AcceptEdits.is_auto());
        assert!(PermissionMode::Auto.is_auto());
        assert!(PermissionMode::DontAsk.is_auto());
        assert!(PermissionMode::BypassPermissions.is_auto());
    }

    #[test]
    fn default_is_manual() {
        assert_eq!(PermissionMode::default(), PermissionMode::Default);
        assert!(!PermissionMode::default().is_auto());
    }
}
