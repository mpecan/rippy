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
