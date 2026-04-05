//! CLI handler for `rippy debug` — trace the decision path for a command.

use std::path::PathBuf;
use std::process::ExitCode;

use crate::cli::DebugArgs;
use crate::config::{self, ConfigSourceInfo};
use crate::error::RippyError;
use crate::inspect;

/// Run the `rippy debug` subcommand.
///
/// # Errors
///
/// Returns `RippyError` if parsing or tracing fails.
pub fn run(args: &DebugArgs) -> Result<ExitCode, RippyError> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let trace = inspect::collect_trace_data(&args.command, &cwd, args.config.as_deref())?;
    let sources = config::enumerate_config_sources(&cwd, args.config.as_deref());

    if args.json {
        let json_output = serde_json::json!({
            "command": trace.command,
            "sources": sources,
            "decision": trace.decision,
            "reason": trace.reason,
            "steps": trace.steps.iter().map(|s| serde_json::json!({
                "stage": s.stage,
                "matched": s.matched,
                "detail": s.detail,
            })).collect::<Vec<_>>(),
        });
        let json = serde_json::to_string_pretty(&json_output)
            .map_err(|e| RippyError::Setup(format!("JSON serialization failed: {e}")))?;
        println!("{json}");
    } else {
        print_debug_text(&trace, &sources);
    }

    Ok(ExitCode::SUCCESS)
}

fn print_debug_text(trace: &inspect::TraceOutput, sources: &[ConfigSourceInfo]) {
    println!("Command: {}\n", trace.command);

    println!("Config sources:");
    for (i, source) in sources.iter().enumerate() {
        let path_info = source
            .path
            .as_ref()
            .map_or(String::new(), |p| format!(" ({})", p.display()));
        println!("  {}. {}{path_info}", i + 1, source.tier);
    }

    println!("\nDecision trace:");
    for (i, step) in trace.steps.iter().enumerate() {
        let status = if step.matched { "+" } else { "-" };
        println!("  {}. {:<16} [{status}] {}", i + 1, step.stage, step.detail);
    }

    println!("\nVerdict: {}", trace.decision.to_uppercase());
    println!("  Reason: {}", trace.reason);
}
