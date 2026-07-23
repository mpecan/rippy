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
