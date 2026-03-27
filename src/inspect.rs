//! The `rippy inspect` command — display rules and trace command decisions.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::Serialize;

use crate::allowlists;
use crate::cc_permissions;
use crate::cli::InspectArgs;
use crate::config::{self, Config, Rule};
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

// ---------------------------------------------------------------------------
// Mode 1: List all rules
// ---------------------------------------------------------------------------

/// Collected rules from a single source file.
#[derive(Debug, Serialize)]
struct SourceRules {
    path: String,
    rules: Vec<RuleDisplay>,
}

/// A single rule formatted for display.
#[derive(Debug, Serialize)]
struct RuleDisplay {
    action: String,
    pattern: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

/// Summary of active configuration for JSON output.
#[derive(Debug, Serialize)]
struct ListOutput {
    config_sources: Vec<SourceRules>,
    cc_sources: Vec<SourceRules>,
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

fn collect_list_data(cwd: &Path, config_override: Option<&Path>) -> Result<ListOutput, RippyError> {
    let mut config_sources = Vec::new();

    // Global config.
    if let Some(home) = config::home_dir() {
        for candidate in &[
            home.join(".rippy/config.toml"),
            home.join(".rippy/config"),
            home.join(".dippy/config"),
        ] {
            if candidate.is_file() {
                config_sources.push(load_source_rules(candidate)?);
                break;
            }
        }
    }

    // Project config (or override).
    if let Some(override_path) = config_override {
        config_sources.push(load_source_rules(override_path)?);
    } else if let Some(project) = config::find_project_config(cwd) {
        config_sources.push(load_source_rules(&project)?);
    }

    // CC permissions.
    let cc_sources = collect_cc_rules(cwd);

    // Load merged config to get default action.
    let merged = Config::load(cwd, config_override)?;

    Ok(ListOutput {
        config_sources,
        cc_sources,
        default_action: merged.default_action.map(|d| d.as_str().to_string()),
        handler_count: handlers::handler_count(),
        simple_safe_count: allowlists::simple_safe_count(),
        wrapper_count: allowlists::wrapper_count(),
    })
}

fn load_source_rules(path: &Path) -> Result<SourceRules, RippyError> {
    let mut rules = Vec::new();
    config::load_file(path, &mut rules)?;

    let displays: Vec<RuleDisplay> = rules.iter().filter_map(rule_to_display).collect();
    Ok(SourceRules {
        path: path.display().to_string(),
        rules: displays,
    })
}

fn rule_to_display(rule: &Rule) -> Option<RuleDisplay> {
    match rule {
        Rule::Command {
            kind,
            pattern,
            message,
        } => Some(RuleDisplay {
            action: kind.as_str().to_string(),
            pattern: pattern.raw().to_string(),
            message: message.clone(),
        }),
        Rule::Redirect {
            kind,
            pattern,
            message,
        } => Some(RuleDisplay {
            action: format!("{}-redirect", kind.as_str()),
            pattern: pattern.raw().to_string(),
            message: message.clone(),
        }),
        Rule::Mcp { kind, pattern } => Some(RuleDisplay {
            action: format!("{}-mcp", kind.as_str()),
            pattern: pattern.raw().to_string(),
            message: None,
        }),
        Rule::After { pattern, message } => Some(RuleDisplay {
            action: "after".to_string(),
            pattern: pattern.raw().to_string(),
            message: Some(message.clone()),
        }),
        Rule::Set { .. } | Rule::Alias { .. } => None,
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

    if let Some(default) = &output.default_action {
        println!("  Default: {default}");
    }

    println!("  Handlers: {} registered", output.handler_count);
    println!("  Simple safe: {} commands", output.simple_safe_count);
    println!("  Wrappers: {} commands", output.wrapper_count);
}

// ---------------------------------------------------------------------------
// Mode 2: Trace a command
// ---------------------------------------------------------------------------

/// Structured trace of a command's decision path.
#[derive(Debug, Serialize)]
struct TraceOutput {
    command: String,
    decision: String,
    reason: String,
    steps: Vec<TraceStep>,
}

#[derive(Debug, Clone, Serialize)]
struct TraceStep {
    stage: String,
    matched: bool,
    detail: String,
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

fn collect_trace_data(
    command: &str,
    cwd: &Path,
    config_override: Option<&Path>,
) -> Result<TraceOutput, RippyError> {
    let config = Config::load(cwd, config_override)?;
    let cc_rules = cc_permissions::load_cc_rules(cwd);
    let mut steps = Vec::new();

    if let Some(out) = trace_cc_step(command, &cc_rules, &mut steps) {
        return Ok(out);
    }
    if let Some(out) = trace_config_step(command, &config, &mut steps) {
        return Ok(out);
    }
    trace_parse_and_classify(command, config, cwd, &mut steps)
}

fn trace_cc_step(
    command: &str,
    cc_rules: &cc_permissions::CcRules,
    steps: &mut Vec<TraceStep>,
) -> Option<TraceOutput> {
    let result = cc_rules.check(command);
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
        steps: steps.clone(),
    })
}

fn trace_config_step(
    command: &str,
    config: &Config,
    steps: &mut Vec<TraceStep>,
) -> Option<TraceOutput> {
    let result = config.match_command(command);
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
        steps: steps.clone(),
    })
}

fn trace_parse_and_classify(
    command: &str,
    config: Config,
    cwd: &Path,
    steps: &mut Vec<TraceStep>,
) -> Result<TraceOutput, RippyError> {
    let cmd_name = parse_command_name(command);
    steps.push(TraceStep {
        stage: "Parse".to_string(),
        matched: cmd_name.is_some(),
        detail: cmd_name
            .as_ref()
            .map_or_else(|| "parse failed".to_string(), Clone::clone),
    });

    let Some(cmd_name) = cmd_name else {
        return Ok(make_output(
            command,
            "ask",
            "could not parse command",
            steps,
        ));
    };

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
    if is_safe {
        return Ok(make_output(command, "allow", &cmd_name, steps));
    }

    trace_handler_step(command, &cmd_name, config, cwd, steps)
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
        let mut analyzer = crate::analyzer::Analyzer::new(config, false, cwd.to_path_buf(), false)?;
        let verdict = analyzer.analyze(command)?;
        return Ok(make_output(
            command,
            verdict.decision.as_str(),
            &verdict.reason,
            steps,
        ));
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
    TraceOutput {
        command: command.to_string(),
        decision: decision.to_string(),
        reason: reason.to_string(),
        steps: steps.to_vec(),
    }
}

/// Extract command name from a command string, if parseable.
fn parse_command_name(command: &str) -> Option<String> {
    let mut parser = BashParser;
    let nodes = parser.parse(command).ok()?;
    let first = nodes.first()?;
    crate::ast::command_name(first).map(String::from)
}

fn print_trace_text(output: &TraceOutput) {
    println!("Decision: {}", output.decision.to_uppercase());
    println!("Reason: {}\n", output.reason);
    println!("Trace:");
    for (i, step) in output.steps.iter().enumerate() {
        let status = if step.matched { "✓" } else { "·" };
        println!("  {}. {:<16} {status} {}", i + 1, step.stage, step.detail);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rule_to_display_command() {
        let rule = Rule::Command {
            kind: Decision::Allow,
            pattern: crate::pattern::Pattern::new("git status"),
            message: None,
        };
        let d = rule_to_display(&rule).unwrap();
        assert_eq!(d.action, "allow");
        assert_eq!(d.pattern, "git status");
        assert!(d.message.is_none());
    }

    #[test]
    fn rule_to_display_with_message() {
        let rule = Rule::Command {
            kind: Decision::Deny,
            pattern: crate::pattern::Pattern::new("rm -rf *"),
            message: Some("use trash".to_string()),
        };
        let d = rule_to_display(&rule).unwrap();
        assert_eq!(d.action, "deny");
        assert_eq!(d.message.as_deref(), Some("use trash"));
    }

    #[test]
    fn rule_to_display_redirect() {
        let rule = Rule::Redirect {
            kind: Decision::Deny,
            pattern: crate::pattern::Pattern::new("**/.env*"),
            message: Some("protected".to_string()),
        };
        let d = rule_to_display(&rule).unwrap();
        assert_eq!(d.action, "deny-redirect");
    }

    #[test]
    fn rule_to_display_skips_set() {
        let rule = Rule::Set {
            key: "default".to_string(),
            value: "ask".to_string(),
        };
        assert!(rule_to_display(&rule).is_none());
    }

    #[test]
    fn trace_safe_command() {
        let cwd = std::env::current_dir().unwrap();
        let output = collect_trace_data("cat /tmp/file", &cwd, None).unwrap();
        assert_eq!(output.decision, "allow");
        assert!(
            output
                .steps
                .iter()
                .any(|s| s.stage == "Allowlist" && s.matched)
        );
    }

    #[test]
    fn trace_with_config_rule() {
        let dir = tempfile::TempDir::new().unwrap();
        let config_path = dir.path().join("test.toml");
        std::fs::write(
            &config_path,
            "[[rules]]\naction = \"deny\"\npattern = \"echo evil\"\nmessage = \"no evil\"\n",
        )
        .unwrap();

        let output = collect_trace_data("echo evil", dir.path(), Some(&config_path)).unwrap();
        assert_eq!(output.decision, "deny");
        assert_eq!(output.reason, "no evil");
        assert!(
            output
                .steps
                .iter()
                .any(|s| s.stage == "Config rules" && s.matched)
        );
    }

    #[test]
    fn trace_unknown_command_asks() {
        let dir = tempfile::TempDir::new().unwrap();
        let output = collect_trace_data("some_unknown_tool --flag", dir.path(), None).unwrap();
        // Unknown commands should result in ask (default).
        assert_eq!(output.decision, "ask");
    }

    #[test]
    fn list_rules_from_config_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let config = dir.path().join("test.toml");
        std::fs::write(&config, "[[rules]]\naction = \"allow\"\npattern = \"ls\"\n").unwrap();

        let source = load_source_rules(&config).unwrap();
        assert_eq!(source.rules.len(), 1);
        assert_eq!(source.rules[0].action, "allow");
        assert_eq!(source.rules[0].pattern, "ls");
    }

    #[test]
    fn collect_list_with_config_override() {
        let dir = tempfile::TempDir::new().unwrap();
        let config = dir.path().join("test.toml");
        std::fs::write(
            &config,
            "[settings]\ndefault = \"deny\"\n\n[[rules]]\naction = \"allow\"\npattern = \"git *\"\n",
        )
        .unwrap();

        let output = collect_list_data(dir.path(), Some(&config)).unwrap();
        assert!(!output.config_sources.is_empty());
        assert_eq!(output.default_action.as_deref(), Some("deny"));
        assert!(output.handler_count > 0);
        assert!(output.simple_safe_count > 0);
    }

    #[test]
    fn json_output_parses() {
        let output = ListOutput {
            config_sources: vec![SourceRules {
                path: "test.toml".to_string(),
                rules: vec![RuleDisplay {
                    action: "allow".to_string(),
                    pattern: "git status".to_string(),
                    message: None,
                }],
            }],
            cc_sources: vec![],
            default_action: Some("ask".to_string()),
            handler_count: 43,
            simple_safe_count: 165,
            wrapper_count: 8,
        };
        let json = serde_json::to_string(&output).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["handler_count"], 43);
    }

    #[test]
    fn trace_json_output_parses() {
        let output = TraceOutput {
            command: "git status".to_string(),
            decision: "allow".to_string(),
            reason: "git is safe".to_string(),
            steps: vec![TraceStep {
                stage: "Allowlist".to_string(),
                matched: true,
                detail: "git is safe".to_string(),
            }],
        };
        let json = serde_json::to_string(&output).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["decision"], "allow");
    }
}
