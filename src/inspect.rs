//! The `rippy inspect` command — display rules and trace command decisions.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::Serialize;

use crate::allowlists;
use crate::analyzer::Analyzer;
use crate::cc_permissions;
use crate::cli::InspectArgs;
use crate::config::{self, Config, ConfigDirective, Rule};
use crate::error::RippyError;
use crate::handlers;
use crate::trace::TraceEvent;
use crate::verdict::AllowReason;

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
    /// The [`AllowReason`] variant that approved the command, when it was
    /// approved. Diagnostic only: never part of the hook wire format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<String>,
    pub steps: Vec<TraceStep>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct TraceStep {
    pub stage: String,
    pub matched: bool,
    pub detail: String,
}

impl From<TraceEvent> for TraceStep {
    fn from(event: TraceEvent) -> Self {
        Self {
            stage: event.stage.label().to_owned(),
            matched: event.matched,
            detail: event.detail,
        }
    }
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
    let mut analyzer = Analyzer::new(config, false, cwd.to_path_buf(), false)?;
    trace_with_analyzer(&mut analyzer, command)
}

/// Render one analyzer run as a trace. The decision is whatever
/// `Analyzer::analyze` returned — this function derives nothing of its own.
/// see docs/security-invariants.md#inspect-delegation
pub(crate) fn trace_with_analyzer(
    analyzer: &mut Analyzer,
    command: &str,
) -> Result<TraceOutput, RippyError> {
    analyzer.record_trace();
    let verdict = analyzer.analyze(command)?;
    Ok(TraceOutput {
        command: command.to_string(),
        decision: verdict.decision.as_str().to_string(),
        reason: verdict.reason.clone(),
        provenance: verdict
            .allow_reason()
            .map(|r| AllowReason::variant_name(r).to_string()),
        resolved: verdict.resolved_command,
        steps: analyzer.take_trace().into_iter().map(Into::into).collect(),
    })
}

fn print_trace_text(output: &TraceOutput) {
    println!("Decision: {}", output.decision.to_uppercase());
    println!("Reason: {}", output.reason);
    if let Some(provenance) = &output.provenance {
        println!("Provenance: {provenance}");
    }
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
