//! CLI handler for `rippy trust` — manage trust for project config files.

use std::path::Path;
use std::process::ExitCode;

use crate::cli::TrustArgs;
use crate::config::find_project_config;
use crate::error::RippyError;
use crate::trust::{TrustDb, TrustStatus};

/// Run the `rippy trust` subcommand.
///
/// # Errors
///
/// Returns `RippyError::Trust` on trust database or config errors.
pub fn run(args: &TrustArgs) -> Result<ExitCode, RippyError> {
    if args.list {
        return list_trusted();
    }

    let cwd = std::env::current_dir()
        .map_err(|e| RippyError::Trust(format!("could not determine working directory: {e}")))?;

    let config_path = find_project_config(&cwd).ok_or_else(|| {
        RippyError::Trust("no project config found (.rippy.toml, .rippy, or .dippy)".to_string())
    })?;

    if args.revoke {
        return revoke_trust(&config_path);
    }

    if args.status {
        return show_status(&config_path);
    }

    trust_config(&config_path, args.yes)
}

/// Add the project config to the trust database.
fn trust_config(config_path: &Path, skip_confirm: bool) -> Result<ExitCode, RippyError> {
    let content = std::fs::read_to_string(config_path)
        .map_err(|e| RippyError::Trust(format!("could not read {}: {e}", config_path.display())))?;

    if !skip_confirm {
        print_config_summary(config_path, &content);
        eprintln!();
        eprint!("Trust this config? [y/N] ");
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .map_err(|e| RippyError::Trust(format!("could not read confirmation: {e}")))?;
        if !answer.trim().eq_ignore_ascii_case("y") {
            eprintln!("[rippy] trust cancelled");
            return Ok(ExitCode::from(1));
        }
    }

    let mut db = TrustDb::load();
    db.trust(config_path, &content);
    db.save()?;

    eprintln!("[rippy] trusted: {}", config_path.display());
    Ok(ExitCode::SUCCESS)
}

/// Print a summary of the config file contents with safety analysis.
fn print_config_summary(path: &Path, content: &str) {
    eprintln!("Project config: {}", path.display());
    eprintln!("---");
    for line in content.lines() {
        eprintln!("  {line}");
    }
    eprintln!("---");

    let stats = analyze_config_safety(content);
    eprintln!(
        "{} line(s), {} rule(s): {} allow, {} ask, {} deny",
        content.lines().count(),
        stats.allow + stats.ask + stats.deny,
        stats.allow,
        stats.ask,
        stats.deny,
    );

    if stats.allow > 0 || stats.sets_default_allow {
        eprintln!();
        eprintln!("WARNING: this config WEAKENS protections:");
        if stats.allow > 0 {
            eprintln!(
                "  - {} allow rule(s) will auto-approve commands",
                stats.allow
            );
        }
        if stats.sets_default_allow {
            eprintln!("  - sets default action to allow (all unknown commands auto-approved)");
        }
    }
}

/// Lightweight safety analysis of config content.
struct ConfigSafety {
    allow: usize,
    ask: usize,
    deny: usize,
    sets_default_allow: bool,
}

fn analyze_config_safety(content: &str) -> ConfigSafety {
    let mut stats = ConfigSafety {
        allow: 0,
        ask: 0,
        deny: 0,
        sets_default_allow: false,
    };

    for line in content.lines() {
        let trimmed = line.trim();
        // Line-based format
        if trimmed.starts_with("allow ") {
            stats.allow += 1;
        } else if trimmed.starts_with("ask ") {
            stats.ask += 1;
        } else if trimmed.starts_with("deny") {
            stats.deny += 1;
        } else if trimmed.starts_with("set default allow") {
            stats.sets_default_allow = true;
        }
        // TOML format
        if trimmed.contains("action") && trimmed.contains("allow") && !trimmed.contains("deny") {
            stats.allow += 1;
        } else if trimmed.contains("action") && trimmed.contains("ask") {
            stats.ask += 1;
        } else if trimmed.contains("action") && trimmed.contains("deny") {
            stats.deny += 1;
        }
        if trimmed.contains("default") && trimmed.contains("allow") && !trimmed.starts_with('#') {
            stats.sets_default_allow = true;
        }
    }
    stats
}

/// Remove trust for the project config.
fn revoke_trust(config_path: &Path) -> Result<ExitCode, RippyError> {
    let mut db = TrustDb::load();
    if db.revoke(config_path) {
        db.save()?;
        eprintln!("[rippy] trust revoked: {}", config_path.display());
        Ok(ExitCode::SUCCESS)
    } else {
        eprintln!(
            "[rippy] no trust entry found for: {}",
            config_path.display()
        );
        Ok(ExitCode::from(1))
    }
}

/// Show the trust status of the current project config.
fn show_status(config_path: &Path) -> Result<ExitCode, RippyError> {
    let content = std::fs::read_to_string(config_path)
        .map_err(|e| RippyError::Trust(format!("could not read {}: {e}", config_path.display())))?;

    let db = TrustDb::load();
    let status = db.check(config_path, &content);
    match status {
        TrustStatus::Trusted => {
            eprintln!("[rippy] trusted: {}", config_path.display());
            Ok(ExitCode::SUCCESS)
        }
        TrustStatus::Untrusted => {
            eprintln!(
                "[rippy] untrusted: {} — run `rippy trust` to approve",
                config_path.display()
            );
            Ok(ExitCode::from(2))
        }
        TrustStatus::Modified { .. } => {
            eprintln!(
                "[rippy] modified since last trust: {} — run `rippy trust` to re-approve",
                config_path.display()
            );
            Ok(ExitCode::from(2))
        }
    }
}

/// List all trusted project configs.
#[allow(clippy::unnecessary_wraps)]
fn list_trusted() -> Result<ExitCode, RippyError> {
    let db = TrustDb::load();
    if db.is_empty() {
        eprintln!("[rippy] no trusted project configs");
    } else {
        for (path, entry) in db.list() {
            eprintln!(
                "{path}  (trusted {}, hash {})",
                entry.trusted_at, entry.hash
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}
