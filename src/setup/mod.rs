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
        SetupTarget::Tokf(tokf_args) => tokf::run(tokf_args),
    }
}
