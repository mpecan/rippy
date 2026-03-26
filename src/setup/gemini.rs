use std::process::ExitCode;

use crate::cli::DirectHookArgs;
use crate::error::RippyError;

use super::json_settings::{install_matcher_hook, resolve_tool_path};

/// Install rippy as a direct hook for Gemini CLI.
///
/// # Errors
///
/// Returns `RippyError::Setup` if the settings file cannot be read/written,
/// or if tokf is already installed as a hook.
pub fn run(args: &DirectHookArgs) -> Result<ExitCode, RippyError> {
    let path = resolve_tool_path(args.global, ".gemini", "settings.json")?;
    install_matcher_hook(&path, "BeforeTool", "run_shell_command", "Gemini CLI")?;
    Ok(ExitCode::SUCCESS)
}
