use serde_json::Value;

use crate::error::RippyError;
use crate::mode::{HookType, Mode};

/// Parsed input from stdin — the hook payload from an AI coding tool.
#[derive(Debug)]
pub struct Payload {
    pub mode: Mode,
    pub hook_type: HookType,
    pub tool_name: String,
    pub command: Option<String>,
    pub raw: Value,
}

impl Payload {
    /// Parse a JSON payload, auto-detecting the mode if not forced.
    ///
    /// # Errors
    ///
    /// Returns `RippyError::MissingField` if required fields are absent, or
    /// `RippyError::UnknownMode` if the mode cannot be determined.
    pub fn parse(json: &str, forced_mode: Option<Mode>) -> Result<Self, RippyError> {
        let raw: Value =
            serde_json::from_str(json).map_err(|e| RippyError::Parse(e.to_string()))?;

        let tool_name = raw
            .get("tool_name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();

        let hook_type = detect_hook_type(&raw);
        let mode = forced_mode.map_or_else(|| detect_mode(&raw), Ok)?;
        let command = extract_command(&raw, mode);

        Ok(Self {
            mode,
            hook_type,
            tool_name,
            command,
            raw,
        })
    }

    /// Whether this is an MCP tool invocation.
    #[must_use]
    pub fn is_mcp(&self) -> bool {
        self.tool_name.starts_with("mcp__")
    }
}

/// Detect hook type from the payload.
fn detect_hook_type(raw: &Value) -> HookType {
    // PostToolUse payloads typically contain tool_result
    if raw.get("tool_result").is_some() {
        HookType::PostToolUse
    } else {
        HookType::PreToolUse
    }
}

/// Auto-detect the AI tool mode from the JSON structure.
fn detect_mode(raw: &Value) -> Result<Mode, RippyError> {
    // Claude: tool_input is an object with "command" key
    if let Some(tool_input) = raw.get("tool_input") {
        if tool_input.is_object() && tool_input.get("command").is_some() {
            return Ok(Mode::Claude);
        }
        // Gemini: tool_input is a string
        if tool_input.is_string() {
            return Ok(Mode::Gemini);
        }
    }

    // Cursor: has "command" at top level (not inside tool_input)
    if raw.get("command").is_some() && raw.get("tool_input").is_none() {
        return Ok(Mode::Cursor);
    }

    // Fallback: try Claude if tool_name looks like Claude's format
    if raw.get("tool_name").is_some() {
        return Ok(Mode::Claude);
    }

    Err(RippyError::UnknownMode(
        "could not detect AI tool from payload".into(),
    ))
}

/// Extract the shell command string from the payload based on mode.
fn extract_command(raw: &Value, mode: Mode) -> Option<String> {
    match mode {
        Mode::Claude => raw
            .get("tool_input")
            .and_then(|ti| ti.get("command"))
            .and_then(Value::as_str)
            .map(String::from),
        Mode::Gemini => raw
            .get("tool_input")
            .and_then(Value::as_str)
            .map(String::from),
        Mode::Cursor => raw.get("command").and_then(Value::as_str).map(String::from),
        Mode::Codex => raw.get("tool_input").and_then(|ti| {
            // Codex may use either format
            ti.as_str()
                .map(String::from)
                .or_else(|| ti.get("command").and_then(Value::as_str).map(String::from))
        }),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn claude_auto_detect() {
        let json = r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#;
        let payload = Payload::parse(json, None).unwrap();
        assert_eq!(payload.mode, Mode::Claude);
        assert_eq!(payload.command.as_deref(), Some("git status"));
        assert_eq!(payload.tool_name, "Bash");
        assert_eq!(payload.hook_type, HookType::PreToolUse);
    }

    #[test]
    fn gemini_auto_detect() {
        let json = r#"{"tool_name":"bash","tool_input":"ls -la"}"#;
        let payload = Payload::parse(json, None).unwrap();
        assert_eq!(payload.mode, Mode::Gemini);
        assert_eq!(payload.command.as_deref(), Some("ls -la"));
    }

    #[test]
    fn cursor_auto_detect() {
        let json = r#"{"tool_name":"bash","command":"npm install"}"#;
        let payload = Payload::parse(json, None).unwrap();
        assert_eq!(payload.mode, Mode::Cursor);
        assert_eq!(payload.command.as_deref(), Some("npm install"));
    }

    #[test]
    fn forced_mode_overrides() {
        let json = r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#;
        let payload = Payload::parse(json, Some(Mode::Gemini)).unwrap();
        assert_eq!(payload.mode, Mode::Gemini);
    }

    #[test]
    fn mcp_detection() {
        let json = r#"{"tool_name":"mcp__my_server__my_tool","tool_input":{}}"#;
        let payload = Payload::parse(json, Some(Mode::Claude)).unwrap();
        assert!(payload.is_mcp());
    }

    #[test]
    fn post_tool_use_detection() {
        let json = r#"{"tool_name":"Bash","tool_input":{"command":"ls"},"tool_result":{"output":"file.txt"}}"#;
        let payload = Payload::parse(json, None).unwrap();
        assert_eq!(payload.hook_type, HookType::PostToolUse);
    }

    #[test]
    fn non_mcp() {
        let json = r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#;
        let payload = Payload::parse(json, None).unwrap();
        assert!(!payload.is_mcp());
    }
}
