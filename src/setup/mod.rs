mod claude_code;
mod cursor;
mod gemini;
mod json_settings;
mod tokf;

use std::process::ExitCode;

use crate::cli::{SetupArgs, SetupTarget};
use crate::error::RippyError;

/// Run a setup subcommand.
///
/// # Errors
///
/// Returns `RippyError::Setup` if the target tool is not installed or
/// configuration cannot be written.
pub fn run(args: &SetupArgs) -> Result<ExitCode, RippyError> {
    match &args.target {
        SetupTarget::Tokf(a) => tokf::run(a),
        SetupTarget::ClaudeCode(a) => claude_code::run(a),
        SetupTarget::Gemini(a) => gemini::run(a),
        SetupTarget::Cursor(a) => cursor::run(a),
    }
}
