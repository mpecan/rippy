use std::process::ExitCode;

use crate::cli::DirectHookArgs;
use crate::error::RippyError;

use super::json_settings::{install_matcher_hook, resolve_tool_path};

/// Install rippy as a direct hook for Claude Code.
///
/// # Errors
///
/// Returns `RippyError::Setup` if the settings file cannot be read/written,
/// or if tokf is already installed as a hook.
pub fn run(args: &DirectHookArgs) -> Result<ExitCode, RippyError> {
    let path = resolve_tool_path(args.global, ".claude", "settings.json")?;
    install_matcher_hook(&path, "PreToolUse", "Bash|Read|Write|Edit", "Claude Code")?;
    Ok(ExitCode::SUCCESS)
}
