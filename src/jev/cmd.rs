//! `rippy jev <command>`: one command through rippy and then Jev.
//!
//! Shows every step, including the state sent and Jev's raw answers, for
//! checking thresholds against your own commands before relying on them.

use std::path::PathBuf;
use std::process::ExitCode;

use serde_json::json;

use super::transport::HttpTransport;
use super::{Env, review};
use crate::analyzer::Analyzer;
use crate::cli::JevArgs;
use crate::config::Config;
use crate::error::RippyError;
use crate::verdict::{AskClass, Verdict};

/// Run the `rippy jev` subcommand. Reviews even when `[jev] enabled = false`,
/// since asking is the point of the command; settings are otherwise as loaded.
///
/// # Errors
///
/// Returns `RippyError` when config loading or analysis fails.
pub fn run(args: &JevArgs) -> Result<ExitCode, RippyError> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let config = Config::load(&cwd, args.config.as_deref())?;
    let configured = config.jev.clone();
    let mut settings = configured.clone().unwrap_or_default();
    settings.enabled = true;
    let before = Analyzer::new(config, false, cwd.clone(), false)?.analyze(&args.command)?;
    let var = |name: &str| std::env::var(name).ok();
    let env = Env {
        cwd: &cwd,
        home: dirs::home_dir(),
        var: &var,
    };
    let result = review(
        before.clone(),
        &args.command,
        &settings,
        &env,
        &HttpTransport,
    );
    let note = match &configured {
        None => Some("no [jev] section in the global config; using defaults"),
        Some(s) if !s.enabled => Some("[jev] is disabled in config; reviewing anyway"),
        Some(_) => None,
    };
    let report = json!({
        "command": args.command,
        "note": note,
        "rippy": describe(&before),
        "jev": result.log,
        "final": describe(&result.verdict),
        "force_prompt": result.force_prompt,
    });
    if args.json {
        let text = serde_json::to_string_pretty(&report)
            .map_err(|e| RippyError::Setup(format!("JSON serialization failed: {e}")))?;
        println!("{text}");
    } else {
        print_report(&report);
    }
    Ok(ExitCode::SUCCESS)
}

fn describe(v: &Verdict) -> serde_json::Value {
    json!({
        "decision": v.decision.as_str(),
        "class": v.ask_class().map(AskClass::as_str),
        "reason": v.reason,
    })
}

fn print_report(report: &serde_json::Value) {
    if let Some(note) = report["note"].as_str() {
        println!("note: {note}\n");
    }
    let line = |label: &str, v: &serde_json::Value| {
        let class = v["class"]
            .as_str()
            .map_or(String::new(), |c| format!(" [{c}]"));
        println!(
            "{label:<7} {}{class}: {}",
            v["decision"].as_str().unwrap_or("?"),
            v["reason"].as_str().unwrap_or("")
        );
    };
    line("rippy", &report["rippy"]);
    let jev = &report["jev"];
    if let Some(why) = jev["skipped"].as_str() {
        println!("jev     not consulted: {why}");
    } else {
        for key in ["state", "answers"] {
            if !jev[key].is_null() {
                let pretty = serde_json::to_string_pretty(&jev[key]).unwrap_or_default();
                println!("\n{key}:\n{pretty}");
            }
        }
        if let Some(ms) = jev["latency_ms"].as_u64() {
            println!("\nlatency: {ms} ms");
        }
        if let Some(problem) = jev["unavailable"].as_str() {
            println!("jev     unavailable: {problem}");
        }
    }
    println!();
    line("final", &report["final"]);
    if report["force_prompt"].as_bool() == Some(true) {
        println!("        (always prompts, even in auto modes)");
    }
}
