use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use rippy_cli::analyzer::Analyzer;
use rippy_cli::cli::{Cli, Command, HookArgs};
use rippy_cli::config::Config;
use rippy_cli::error::RippyError;
use rippy_cli::mode::HookType;
use rippy_cli::payload::{FileOp, Payload};
use rippy_cli::setup;
use rippy_cli::verdict::{Decision, Verdict};

/// Evaluate a payload. Returns `None` for passthrough (file tools with no matching rule).
fn evaluate(
    payload: &Payload,
    config: Config,
    args: &HookArgs,
    cwd: PathBuf,
) -> Result<Option<Verdict>, RippyError> {
    match payload.hook_type {
        HookType::PreToolUse => evaluate_pre_tool(payload, config, args, cwd),
        HookType::PostToolUse => Ok(Some(evaluate_post_tool(payload, &config))),
    }
}

fn evaluate_pre_tool(
    payload: &Payload,
    config: Config,
    args: &HookArgs,
    cwd: PathBuf,
) -> Result<Option<Verdict>, RippyError> {
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
        return Ok(Some(v));
    }

    // Self-protection: deny Write/Edit to rippy's own config files.
    if config.self_protect
        && let Some(file_path) = &payload.file_path
        && matches!(payload.file_operation(), Some(FileOp::Write | FileOp::Edit))
        && rippy_cli::self_protect::is_protected_path(file_path)
    {
        return Ok(Some(Verdict::deny(
            rippy_cli::self_protect::PROTECTION_MESSAGE,
        )));
    }

    if let Some(verdict) = evaluate_file_access(payload, &config, args.verbose) {
        return Ok(Some(verdict));
    }
    if payload.file_operation().is_some() && payload.command.is_none() {
        return Ok(None); // passthrough — no rule matched, let the tool decide
    }

    if let Some(command) = &payload.command {
        let mut analyzer = Analyzer::new(config, args.remote, cwd, args.verbose)?;
        return Ok(Some(analyzer.analyze(command)?));
    }

    Ok(Some(Verdict::ask("no command found in payload")))
}

fn evaluate_post_tool(payload: &Payload, config: &Config) -> Verdict {
    payload.command.as_ref().map_or_else(
        || Verdict::allow(""),
        |command| {
            config
                .match_after(command)
                .map_or_else(|| Verdict::allow(""), Verdict::allow)
        },
    )
}

const MAX_INPUT_SIZE: usize = 1_048_576; // 1 MB

fn run_hook(args: &HookArgs) -> Result<ExitCode, RippyError> {
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

    let tracking_db = config.tracking_db.clone();
    let maybe_verdict = evaluate(&payload, config, args, cwd)?;

    let Some(verdict) = maybe_verdict else {
        // Passthrough: no opinion. Output empty JSON, exit 0.
        println!("{{}}");
        return Ok(ExitCode::SUCCESS);
    };

    log_verdict(log_file.as_ref(), log_full, &payload, &verdict);
    track_verdict(tracking_db.as_deref(), &payload, &verdict);

    let json = verdict.to_json(payload.mode);
    println!("{json}");

    Ok(match verdict.decision {
        Decision::Allow => ExitCode::SUCCESS,
        Decision::Ask | Decision::Deny => ExitCode::from(2),
    })
}

/// Evaluate file-access tools (Read/Write/Edit) against config rules.
/// Returns `Some(verdict)` if a rule matched, `None` for passthrough.
fn evaluate_file_access(payload: &Payload, config: &Config, verbose: bool) -> Option<Verdict> {
    let file_path = payload.file_path.as_deref()?;
    let op = payload.file_operation()?;

    let verdict = match op {
        FileOp::Read => config.match_file_read(file_path, None),
        FileOp::Write => config.match_file_write(file_path, None),
        FileOp::Edit => config.match_file_edit(file_path, None),
    };

    if verbose && let Some(v) = &verdict {
        eprintln!(
            "[rippy] file {}: {} -> {}",
            match op {
                FileOp::Read => "read",
                FileOp::Write => "write",
                FileOp::Edit => "edit",
            },
            file_path,
            v.decision.as_str()
        );
    }

    verdict
}

fn log_verdict(log_file: Option<&PathBuf>, log_full: bool, payload: &Payload, verdict: &Verdict) {
    if let Some(path) = log_file {
        rippy_cli::logging::write_log_entry(&rippy_cli::logging::LogEntry {
            log_file: path,
            log_full,
            command: payload.command.as_deref(),
            verdict,
            mode: payload.mode,
            raw_payload: if log_full { Some(&payload.raw) } else { None },
        });
    }
}

fn track_verdict(db_path: Option<&std::path::Path>, payload: &Payload, verdict: &Verdict) {
    if let Some(path) = db_path {
        let session_id = payload
            .raw
            .get("session_id")
            .and_then(serde_json::Value::as_str);
        rippy_cli::tracking::record(
            path,
            &rippy_cli::tracking::TrackingEntry {
                session_id,
                mode: payload.mode,
                tool_name: &payload.tool_name,
                command: payload.command.as_deref(),
                decision: verdict.decision,
                reason: &verdict.reason,
                payload_json: None,
            },
        );
    }
}

fn run() -> Result<ExitCode, RippyError> {
    let cli = Cli::parse();

    match cli.command {
        Some(Command::Setup(ref setup_args)) => setup::run(setup_args),
        Some(Command::Migrate(ref migrate_args)) => rippy_cli::migrate::run(migrate_args),
        Some(Command::Inspect(ref inspect_args)) => rippy_cli::inspect::run(inspect_args),
        Some(Command::Stats(ref stats_args)) => rippy_cli::stats::run(stats_args),
        Some(Command::Allow(ref a)) => {
            rippy_cli::rule_cmd::run(rippy_cli::verdict::Decision::Allow, a)
        }
        Some(Command::Deny(ref a)) => {
            rippy_cli::rule_cmd::run(rippy_cli::verdict::Decision::Deny, a)
        }
        Some(Command::Ask(ref a)) => rippy_cli::rule_cmd::run(rippy_cli::verdict::Decision::Ask, a),
        Some(Command::Suggest(ref a)) => rippy_cli::suggest::run(a),
        None => run_hook(&cli.hook_args),
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
