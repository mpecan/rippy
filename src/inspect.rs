//! The `rippy inspect` command — display rules and trace command decisions.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::Serialize;

use crate::allowlists;
use crate::cc_permissions;
use crate::cli::InspectArgs;
use crate::config::{self, Config, ConfigDirective, Rule};
use crate::error::RippyError;
use crate::handlers;
use crate::parser::BashParser;
use crate::verdict::Decision;

/// Run the `rippy inspect` command.
///
/// # Errors
///
/// Returns `RippyError` if config files cannot be loaded.
pub fn run(args: &InspectArgs) -> Result<ExitCode, RippyError> {
    if let Some(command) = &args.command {
        trace_command(command, args)?;
    } else {
        list_rules(args)?;
    }
    Ok(ExitCode::SUCCESS)
}

// Mode 1: List all rules

/// Collected rules from a single source file.
#[derive(Debug, Serialize)]
pub(crate) struct SourceRules {
    pub(crate) path: String,
    pub(crate) rules: Vec<RuleDisplay>,
}

/// A single rule formatted for display.
#[derive(Debug, Serialize)]
pub(crate) struct RuleDisplay {
    pub(crate) action: String,
    pub(crate) pattern: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) message: Option<String>,
}

/// Summary of active configuration for JSON output.
#[derive(Debug, Serialize)]
pub(crate) struct ListOutput {
    pub(crate) config_sources: Vec<SourceRules>,
    pub(crate) cc_sources: Vec<SourceRules>,
    active_package: Option<String>,
    default_action: Option<String>,
    handler_count: usize,
    simple_safe_count: usize,
    wrapper_count: usize,
}

fn list_rules(args: &InspectArgs) -> Result<(), RippyError> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let output = collect_list_data(&cwd, args.config.as_deref())?;

    if args.json {
        let json = serde_json::to_string_pretty(&output)
            .map_err(|e| RippyError::Setup(format!("JSON serialization failed: {e}")))?;
        println!("{json}");
    } else {
        print_list_text(&output);
    }
    Ok(())
}

pub(crate) fn collect_list_data(
    cwd: &Path,
    config_override: Option<&Path>,
) -> Result<ListOutput, RippyError> {
    let mut config_sources = Vec::new();

    for source in config::enumerate_config_sources(cwd, config_override) {
        match source.path {
            None => {
                // Stdlib — load from embedded directives.
                let directives = crate::stdlib::stdlib_directives()?;
                let displays: Vec<RuleDisplay> =
                    directives.iter().filter_map(directive_to_display).collect();
                if !displays.is_empty() {
                    config_sources.push(SourceRules {
                        path: "(stdlib)".to_string(),
                        rules: displays,
                    });
                }
            }
            Some(path) => {
                config_sources.push(load_source_rules(&path)?);
            }
        }
    }

    // CC permissions.
    let cc_sources = collect_cc_rules(cwd);

    // Load merged config to get default action.
    let merged = Config::load(cwd, config_override)?;

    Ok(ListOutput {
        config_sources,
        cc_sources,
        active_package: merged.active_package.map(|p| p.name().to_string()),
        default_action: merged.default_action.map(|d| d.as_str().to_string()),
        handler_count: handlers::handler_count(),
        simple_safe_count: allowlists::simple_safe_count(),
        wrapper_count: allowlists::wrapper_count(),
    })
}

fn load_source_rules(path: &Path) -> Result<SourceRules, RippyError> {
    let mut directives = Vec::new();
    config::load_file(path, &mut directives)?;

    let displays: Vec<RuleDisplay> = directives.iter().filter_map(directive_to_display).collect();
    Ok(SourceRules {
        path: path.display().to_string(),
        rules: displays,
    })
}

fn directive_to_display(directive: &ConfigDirective) -> Option<RuleDisplay> {
    match directive {
        ConfigDirective::Rule(rule) => Some(rule_to_display(rule)),
        ConfigDirective::Set { .. }
        | ConfigDirective::Alias { .. }
        | ConfigDirective::SafeScope(_)
        | ConfigDirective::ProjectBoundary => None,
    }
}

fn rule_to_display(rule: &Rule) -> RuleDisplay {
    let pattern = if rule.has_structured_fields() && rule.pattern.is_any() {
        rule.structured_description()
    } else if rule.has_structured_fields() {
        format!("{} + {}", rule.pattern.raw(), rule.structured_description())
    } else {
        rule.pattern.raw().to_string()
    };
    RuleDisplay {
        action: rule.action_str(),
        pattern,
        message: rule.message.clone(),
    }
}

fn collect_cc_rules(cwd: &Path) -> Vec<SourceRules> {
    let paths = cc_permissions::get_settings_paths(cwd);
    let cc_rules = cc_permissions::load_cc_rules(cwd);
    let all = cc_rules.all_rules();

    if all.is_empty() {
        return Vec::new();
    }

    // Group all CC rules under the first settings path that exists.
    let source_path = paths.iter().find(|p| p.is_file()).map_or_else(
        || "Claude Code settings".to_string(),
        |p| p.display().to_string(),
    );

    let displays: Vec<RuleDisplay> = all
        .iter()
        .map(|(decision, pattern)| RuleDisplay {
            action: decision.as_str().to_string(),
            pattern: format!("Bash({pattern})"),
            message: None,
        })
        .collect();

    vec![SourceRules {
        path: source_path,
        rules: displays,
    }]
}

fn print_list_text(output: &ListOutput) {
    println!("Rules:\n");

    for source in &output.config_sources {
        println!("  {}:", source.path);
        for rule in &source.rules {
            let msg = rule
                .message
                .as_ref()
                .map_or(String::new(), |m| format!("  \"{m}\""));
            println!("    {:<6} {}{msg}", rule.action, rule.pattern);
        }
        println!();
    }

    for source in &output.cc_sources {
        println!("  {}:", source.path);
        for rule in &source.rules {
            println!("    {:<6} {}", rule.action, rule.pattern);
        }
        println!();
    }

    if let Some(package) = &output.active_package {
        println!("  Package: {package}");
    }

    if let Some(default) = &output.default_action {
        println!("  Default: {default}");
    }

    println!("  Handlers: {} registered", output.handler_count);
    println!("  Simple safe: {} commands", output.simple_safe_count);
    println!("  Wrappers: {} commands", output.wrapper_count);
}

// Mode 2: Trace a command

/// Structured trace of a command's decision path.
#[derive(Debug, Serialize)]
pub(crate) struct TraceOutput {
    pub command: String,
    pub decision: String,
    pub reason: String,
    /// The fully-resolved command form (after `$VAR`, `$'...'`, `$((...))`, `{a,b}`
    /// expansion) when the analyzer resolved expansions statically. `None` when
    /// no resolution occurred.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved: Option<String>,
    pub steps: Vec<TraceStep>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct TraceStep {
    pub stage: String,
    pub matched: bool,
    pub detail: String,
}

fn trace_command(command: &str, args: &InspectArgs) -> Result<(), RippyError> {
    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let output = collect_trace_data(command, &cwd, args.config.as_deref())?;

    if args.json {
        let json = serde_json::to_string_pretty(&output)
            .map_err(|e| RippyError::Setup(format!("JSON serialization failed: {e}")))?;
        println!("{json}");
    } else {
        print_trace_text(&output);
    }
    Ok(())
}

pub(crate) fn collect_trace_data(
    command: &str,
    cwd: &Path,
    config_override: Option<&Path>,
) -> Result<TraceOutput, RippyError> {
    let config = Config::load(cwd, config_override)?;
    let cc_rules = cc_permissions::load_cc_rules(cwd);
    let mut steps = Vec::new();

    // Mirror the analyzer: strip a leading `NAME=VALUE` env prefix so the
    // string-matching CC/config steps see the real command. Parse resiliently.
    let match_str = BashParser::new()
        .ok()
        .and_then(|mut p| p.parse(command).ok())
        .and_then(|n| crate::ast::strip_env_prefix(command, &n));
    let match_str = match_str.as_deref().unwrap_or(command);

    // Transparency: disclose that the leading env prefix was normalized away, so
    // a reader can see why `VAR=x echo evil` matched an `echo evil` rule.
    if match_str != command {
        steps.push(TraceStep {
            stage: "Normalize env prefix".to_string(),
            matched: true,
            detail: format!("matching against `{match_str}`"),
        });
    }

    if let Some(out) = trace_cc_step(command, match_str, &cc_rules, &mut steps) {
        return Ok(out);
    }
    if let Some(out) = trace_config_step(command, match_str, &config, &mut steps) {
        return Ok(out);
    }
    trace_parse_and_classify(command, config, cwd, &mut steps)
}

fn trace_cc_step(
    command: &str,
    match_str: &str,
    cc_rules: &cc_permissions::CcRules,
    steps: &mut Vec<TraceStep>,
) -> Option<TraceOutput> {
    let result = cc_rules.check(match_str);
    steps.push(TraceStep {
        stage: "CC permissions".to_string(),
        matched: result.is_some(),
        detail: result.map_or_else(
            || "no match".to_string(),
            |d| format!("{} matched", d.as_str()),
        ),
    });
    result.map(|decision| TraceOutput {
        command: command.to_string(),
        decision: decision.as_str().to_string(),
        reason: format!("CC permission: {command}"),
        resolved: None,
        steps: steps.clone(),
    })
}

fn trace_config_step(
    command: &str,
    match_str: &str,
    config: &Config,
    steps: &mut Vec<TraceStep>,
) -> Option<TraceOutput> {
    let result = config.match_command(match_str, None);
    steps.push(TraceStep {
        stage: "Config rules".to_string(),
        matched: result.is_some(),
        detail: result.as_ref().map_or_else(
            || "no match".to_string(),
            |v| format!("{}: {}", v.decision.as_str(), v.reason),
        ),
    });
    result.map(|verdict| TraceOutput {
        command: command.to_string(),
        decision: verdict.decision.as_str().to_string(),
        reason: verdict.reason,
        resolved: verdict.resolved_command,
        steps: steps.clone(),
    })
}

fn trace_parse_and_classify(
    command: &str,
    config: Config,
    cwd: &Path,
    steps: &mut Vec<TraceStep>,
) -> Result<TraceOutput, RippyError> {
    let cmd_name = match classify_parse(command) {
        ParseOutcome::Unparseable => {
            steps.push(TraceStep {
                stage: "Parse".to_string(),
                matched: false,
                detail: "parse failed".to_string(),
            });
            return Ok(make_output(
                command,
                "ask",
                "could not parse command",
                steps,
            ));
        }
        ParseOutcome::Compound => {
            // Route compound/redirecting commands to the full analyzer so the
            // verdict is not judged on the first sub-command alone.
            steps.push(TraceStep {
                stage: "Parse".to_string(),
                matched: true,
                detail: "compound or redirecting command; analyzed recursively".to_string(),
            });
            return run_analyzer_for_trace(command, config, cwd, steps);
        }
        ParseOutcome::Simple(name) => name,
    };
    steps.push(TraceStep {
        stage: "Parse".to_string(),
        matched: true,
        detail: cmd_name.clone(),
    });

    let is_safe = allowlists::is_simple_safe(&cmd_name);
    steps.push(TraceStep {
        stage: "Allowlist".to_string(),
        matched: is_safe,
        detail: if is_safe {
            format!("{cmd_name} is in simple_safe list")
        } else {
            "not in allowlist".to_string()
        },
    });

    // Commands with expansions run the full analyzer so the resolved form
    // reaches `TraceOutput.resolved`; plain safe ones short-circuit.
    let has_expansions = crate::ast::has_shell_expansion_pattern(command);
    if is_safe && !has_expansions {
        return Ok(make_output(command, "allow", &cmd_name, steps));
    }
    if is_safe || crate::handlers::get_handler(&cmd_name).is_none() {
        // Safe command WITH expansions, or unknown command — go through the
        // analyzer to resolve and re-classify.
        return run_analyzer_for_trace(command, config, cwd, steps);
    }

    trace_handler_step(command, &cmd_name, config, cwd, steps)
}

/// Run the full analyzer and convert its verdict to a `TraceOutput`. Shared
/// between the safe-with-expansions path and the handler path so resolution
/// info propagates uniformly.
fn run_analyzer_for_trace(
    command: &str,
    config: Config,
    cwd: &Path,
    steps: &[TraceStep],
) -> Result<TraceOutput, RippyError> {
    let mut analyzer = crate::analyzer::Analyzer::new(config, false, cwd.to_path_buf(), false)?;
    let verdict = analyzer.analyze(command)?;
    Ok(make_output_with_resolution(
        command,
        verdict.decision.as_str(),
        &verdict.reason,
        verdict.resolved_command,
        steps,
    ))
}

fn trace_handler_step(
    command: &str,
    cmd_name: &str,
    config: Config,
    cwd: &Path,
    steps: &mut Vec<TraceStep>,
) -> Result<TraceOutput, RippyError> {
    let has_handler = handlers::get_handler(cmd_name).is_some();
    steps.push(TraceStep {
        stage: "Handler".to_string(),
        matched: has_handler,
        detail: if has_handler {
            format!("handler registered for {cmd_name}")
        } else {
            "no handler registered".to_string()
        },
    });

    if has_handler {
        return run_analyzer_for_trace(command, config, cwd, steps);
    }

    let default = config.default_action.unwrap_or(Decision::Ask);
    let reason = format!("default action: {}", default.as_str());
    steps.push(TraceStep {
        stage: "Default".to_string(),
        matched: true,
        detail: reason.clone(),
    });
    Ok(make_output(command, default.as_str(), &reason, steps))
}

fn make_output(command: &str, decision: &str, reason: &str, steps: &[TraceStep]) -> TraceOutput {
    make_output_with_resolution(command, decision, reason, None, steps)
}

fn make_output_with_resolution(
    command: &str,
    decision: &str,
    reason: &str,
    resolved: Option<String>,
    steps: &[TraceStep],
) -> TraceOutput {
    TraceOutput {
        command: command.to_string(),
        decision: decision.to_string(),
        reason: reason.to_string(),
        resolved,
        steps: steps.to_vec(),
    }
}

/// The shape of a parsed command, used to route the trace.
///
/// `Simple` is deliberately restricted to a single top-level simple `Command`
/// node so that any compound form (pipeline, list, control-flow, or more than
/// one top-level node) is routed to the full analyzer instead of being judged
/// on its first sub-command alone.
enum ParseOutcome {
    /// Exactly one top-level node that is a simple `Command` with a name.
    Simple(String),
    /// Parse succeeded but the input is not a single simple command.
    Compound,
    /// The parser could not parse the input.
    Unparseable,
}

/// Classify a command string by parse shape (see [`ParseOutcome`]).
fn classify_parse(command: &str) -> ParseOutcome {
    let mut parser = BashParser;
    let Ok(nodes) = parser.parse(command) else {
        return ParseOutcome::Unparseable;
    };
    let [only] = nodes.as_slice() else {
        return ParseOutcome::Compound;
    };
    // A redirect target may be protected, so route lone commands with redirects
    // through the analyzer rather than treating them as plain-safe.
    if crate::ast::command_has_redirects(only) {
        return ParseOutcome::Compound;
    }
    crate::ast::command_name(only).map_or(ParseOutcome::Compound, |name| {
        ParseOutcome::Simple(name.to_string())
    })
}

fn print_trace_text(output: &TraceOutput) {
    println!("Decision: {}", output.decision.to_uppercase());
    println!("Reason: {}", output.reason);
    if let Some(resolved) = &output.resolved {
        println!("Resolved: {resolved}");
    }
    println!("\nTrace:");
    for (i, step) in output.steps.iter().enumerate() {
        let status = if step.matched { "✓" } else { "·" };
        println!("  {}. {:<16} {status} {}", i + 1, step.stage, step.detail);
    }
}

// Tests

#[cfg(test)]
#[expect(clippy::unwrap_used)]
#[path = "inspect_tests.rs"]
mod tests;
