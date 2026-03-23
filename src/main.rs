use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use rippy::analyzer::Analyzer;
use rippy::cli::Args;
use rippy::config::Config;
use rippy::error::RippyError;
use rippy::mode::HookType;
use rippy::parser::BashParser;
use rippy::payload::Payload;
use rippy::verdict::{Decision, Verdict};

fn run() -> Result<ExitCode, RippyError> {
    let args = Args::parse();

    // Read JSON from stdin
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;

    // Parse payload and detect mode
    let payload = Payload::parse(&input, args.forced_mode())?;

    // Load config
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let env_config = args.config_path();
    let config = Config::load(&cwd, env_config.as_deref())?;

    // Dispatch based on hook type
    let verdict = match payload.hook_type {
        HookType::PreToolUse => {
            if payload.is_mcp() {
                // MCP tool: check config MCP rules
                config
                    .match_mcp(&payload.tool_name)
                    .unwrap_or_else(|| Verdict::ask(format!("MCP tool: {}", payload.tool_name)))
            } else if let Some(command) = &payload.command {
                // Shell command: full analysis
                let mut analyzer = Analyzer {
                    config,
                    parser: BashParser::new()?,
                    remote: args.remote,
                    working_directory: cwd,
                };
                analyzer.analyze(command)?
            } else {
                Verdict::ask("no command found in payload")
            }
        }
        HookType::PostToolUse => payload.command.as_ref().map_or_else(
            || Verdict::allow(""),
            |command| {
                config
                    .match_after(command)
                    .map_or_else(|| Verdict::allow(""), Verdict::allow)
            },
        ),
    };

    // Serialize and output
    let json = verdict.to_json(payload.mode);
    println!("{json}");

    // Exit code: 0 for allow, 2 for ask/deny
    Ok(match verdict.decision {
        Decision::Allow => ExitCode::SUCCESS,
        Decision::Ask | Decision::Deny => ExitCode::from(2),
    })
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            let error_json = serde_json::json!({
                "error": e.to_string()
            });
            println!("{error_json}");
            ExitCode::from(1)
        }
    }
}
