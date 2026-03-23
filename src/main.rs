use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use rippy::analyzer::Analyzer;
use rippy::cli::Args;
use rippy::config::Config;
use rippy::error::RippyError;
use rippy::mode::HookType;
use rippy::payload::Payload;
use rippy::verdict::{Decision, Verdict};

fn evaluate(
    payload: &Payload,
    config: Config,
    args: &Args,
    cwd: PathBuf,
) -> Result<Verdict, RippyError> {
    match payload.hook_type {
        HookType::PreToolUse => {
            if payload.is_mcp() {
                let v = config
                    .match_mcp(&payload.tool_name)
                    .unwrap_or_else(|| Verdict::ask(format!("MCP tool: {}", payload.tool_name)));
                if args.verbose {
                    eprintln!(
                        "[rippy] mcp: {} -> {}",
                        payload.tool_name,
                        v.decision.as_str()
                    );
                }
                Ok(v)
            } else if let Some(command) = &payload.command {
                let mut analyzer = Analyzer::new(config, args.remote, cwd, args.verbose)?;
                Ok(analyzer.analyze(command)?)
            } else {
                Ok(Verdict::ask("no command found in payload"))
            }
        }
        HookType::PostToolUse => Ok(payload.command.as_ref().map_or_else(
            || Verdict::allow(""),
            |command| {
                config
                    .match_after(command)
                    .map_or_else(|| Verdict::allow(""), Verdict::allow)
            },
        )),
    }
}

const MAX_INPUT_SIZE: usize = 1_048_576; // 1 MB

fn run() -> Result<ExitCode, RippyError> {
    let args = Args::parse();

    let mut buffer = Vec::new();
    std::io::stdin()
        .take(MAX_INPUT_SIZE as u64 + 1)
        .read_to_end(&mut buffer)?;
    if buffer.len() > MAX_INPUT_SIZE {
        return Err(RippyError::Parse(format!(
            "input exceeds {MAX_INPUT_SIZE} byte limit"
        )));
    }
    let input =
        String::from_utf8(buffer).map_err(|e| RippyError::Parse(format!("invalid UTF-8: {e}")))?;

    let payload = Payload::parse(&input, args.forced_mode())?;

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let config = Config::load(&cwd, args.config_path().as_deref())?;
    let log_file = config.log_file.clone();
    let log_full = config.log_full;

    if args.verbose {
        eprintln!(
            "[rippy] mode: {:?}, tool: {}",
            payload.mode, payload.tool_name
        );
        if let Some(cmd) = &payload.command {
            eprintln!("[rippy] command: {cmd}");
        }
    }

    let verdict = evaluate(&payload, config, &args, cwd)?;

    log_verdict(log_file.as_ref(), log_full, &payload, &verdict);

    let json = verdict.to_json(payload.mode);
    println!("{json}");

    Ok(match verdict.decision {
        Decision::Allow => ExitCode::SUCCESS,
        Decision::Ask | Decision::Deny => ExitCode::from(2),
    })
}

fn log_verdict(log_file: Option<&PathBuf>, log_full: bool, payload: &Payload, verdict: &Verdict) {
    if let Some(path) = log_file {
        rippy::logging::write_log_entry(&rippy::logging::LogEntry {
            log_file: path,
            log_full,
            command: payload.command.as_deref(),
            verdict,
            mode: payload.mode,
            raw_payload: if log_full { Some(&payload.raw) } else { None },
        });
    }
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
