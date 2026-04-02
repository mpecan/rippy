use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::mode::Mode;

/// Mode selection for which AI tool is calling rippy.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ModeArg {
    Claude,
    Gemini,
    Cursor,
    Codex,
}

impl ModeArg {
    const fn to_mode(self) -> Mode {
        match self {
            Self::Claude => Mode::Claude,
            Self::Gemini => Mode::Gemini,
            Self::Cursor => Mode::Cursor,
            Self::Codex => Mode::Codex,
        }
    }
}

/// A shell command safety hook for AI coding tools.
#[derive(Parser, Debug)]
#[command(
    name = "rippy",
    version,
    about,
    after_help = "\
Reads a JSON hook payload from stdin and writes a verdict to stdout.\n\n\
Exit codes: 0 = allow, 2 = ask/deny, 1 = error\n\n\
Example:\n  \
echo '{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"git status\"}}' | rippy --mode claude"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    #[command(flatten)]
    pub hook_args: HookArgs,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Configure rippy as the permission engine for another tool
    Setup(SetupArgs),
    /// Convert a .rippy config file to .rippy.toml format
    Migrate(MigrateArgs),
    /// Show configured rules and trace command decisions
    Inspect(InspectArgs),
    /// Show aggregate decision tracking statistics
    Stats(StatsArgs),
    /// Add an allow rule to the config
    Allow(RuleArgs),
    /// Add a deny rule to the config
    Deny(RuleArgs),
    /// Add an ask rule to the config
    Ask(RuleArgs),
    /// Analyze tracking data and suggest config rules
    Suggest(SuggestArgs),
    /// Copy default stdlib rules to config for customization
    Init(InitArgs),
    /// Discover flag aliases from command --help output
    Discover(DiscoverArgs),
    /// Manage trust for project-level config files
    Trust(TrustArgs),
}

#[derive(Args, Debug)]
pub struct DiscoverArgs {
    /// Command and optional subcommand (e.g. "git push")
    pub args: Vec<String>,

    /// Re-discover all previously cached commands
    #[arg(long)]
    pub all: bool,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct InitArgs {
    /// Write to global config (~/.rippy/config.toml) instead of project .rippy.toml
    #[arg(long)]
    pub global: bool,

    /// Print stdlib to stdout instead of writing to file
    #[arg(long)]
    pub stdout: bool,
}

#[derive(Args, Debug)]
pub struct StatsArgs {
    /// Time filter, e.g. "7d", "30d", "1h", "30m"
    #[arg(long)]
    pub since: Option<String>,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,

    /// Override tracking database path
    #[arg(long)]
    pub db: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct RuleArgs {
    /// Pattern to match (e.g. "git push *")
    pub pattern: String,
    /// Optional rejection/guidance message
    pub message: Option<String>,
    /// Write to global config (~/.rippy/config.toml) instead of project .rippy.toml
    #[arg(long)]
    pub global: bool,
}

#[derive(Args, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct SuggestArgs {
    /// Generate patterns from a command string instead of analyzing the DB
    #[arg(long)]
    pub from_command: Option<String>,

    /// Time filter, e.g. "7d", "30d", "1h", "30m"
    #[arg(long)]
    pub since: Option<String>,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,

    /// Override tracking database path
    #[arg(long)]
    pub db: Option<PathBuf>,

    /// Apply all suggestions to config
    #[arg(long)]
    pub apply: bool,

    /// Write to global config (~/.rippy/config.toml) instead of project .rippy.toml
    #[arg(long)]
    pub global: bool,

    /// Minimum number of occurrences to generate a suggestion
    #[arg(long, default_value = "3")]
    pub min_count: i64,

    /// Use Claude Code session files (default if sessions exist, use --db to override)
    #[arg(long)]
    pub sessions: bool,

    /// Analyze a specific session JSONL file
    #[arg(long)]
    pub session_file: Option<PathBuf>,

    /// Audit mode: classify commands against current config
    #[arg(long)]
    pub audit: bool,
}

#[derive(Args, Debug)]
pub struct InspectArgs {
    /// Command to trace through the decision pipeline (omit to list all rules)
    pub command: Option<String>,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,

    /// Override config file path
    #[arg(long, env = "RIPPY_CONFIG")]
    pub config: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct MigrateArgs {
    /// Path to the config file to convert (defaults to .rippy in current directory)
    pub path: Option<PathBuf>,

    /// Write to stdout instead of creating .rippy.toml
    #[arg(long)]
    pub stdout: bool,
}

#[derive(Args, Debug)]
pub struct SetupArgs {
    #[command(subcommand)]
    pub target: SetupTarget,
}

#[derive(Subcommand, Debug)]
pub enum SetupTarget {
    /// Configure tokf to use rippy as its external permission engine
    Tokf(TokfSetupArgs),
    /// Install rippy as a direct hook for Claude Code
    ClaudeCode(DirectHookArgs),
    /// Install rippy as a direct hook for Gemini CLI
    Gemini(DirectHookArgs),
    /// Install rippy as a direct hook for Cursor
    Cursor(DirectHookArgs),
}

#[derive(Args, Debug)]
pub struct DirectHookArgs {
    /// Install at user level (~/.claude/ etc.) instead of project level (.claude/ etc.)
    #[arg(long)]
    pub global: bool,
}

#[derive(Args, Debug)]
pub struct TokfSetupArgs {
    /// Install at user level (~/.config/tokf/) instead of project level (.tokf/)
    #[arg(long)]
    pub global: bool,

    /// Also install tokf hooks for these AI tools (comma-separated).
    /// Supported: claude-code, opencode, codex, gemini-cli, cursor, cline,
    /// windsurf, copilot, aider
    #[arg(long, value_delimiter = ',')]
    pub install_hooks: Vec<String>,

    /// Install tokf hooks for all supported AI tools
    #[arg(long)]
    pub all_hooks: bool,
}

/// Arguments for `rippy trust` — manage project config trust.
#[derive(Args, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct TrustArgs {
    /// Remove trust for the current project config
    #[arg(long)]
    pub revoke: bool,

    /// Show trust status without modifying
    #[arg(long)]
    pub status: bool,

    /// List all trusted project configs
    #[arg(long)]
    pub list: bool,

    /// Trust without interactive confirmation
    #[arg(long, short = 'y')]
    pub yes: bool,
}

/// Hook-mode arguments (the original rippy behavior).
#[derive(Args, Debug)]
pub struct HookArgs {
    /// Force a specific AI tool mode
    #[arg(long, value_enum)]
    pub mode: Option<ModeArg>,

    /// Override config file path (also reads `RIPPY_CONFIG` / `DIPPY_CONFIG` env vars)
    #[arg(long, env = "RIPPY_CONFIG")]
    pub config: Option<PathBuf>,

    /// Remote mode (container/SSH context — skip local path validation)
    #[arg(long)]
    pub remote: bool,

    /// Print decision trace to stderr for debugging
    #[arg(long, short = 'v')]
    pub verbose: bool,

    /// Suppress informational stderr messages (trust warnings, etc.)
    #[arg(long, short = 'q')]
    pub quiet: bool,
}

impl HookArgs {
    /// Return the explicitly forced mode, if any.
    #[must_use]
    pub fn forced_mode(&self) -> Option<Mode> {
        self.mode.map(ModeArg::to_mode)
    }

    /// Resolve the config path: CLI flag > `RIPPY_CONFIG` > `DIPPY_CONFIG` env var.
    #[must_use]
    pub fn config_path(&self) -> Option<PathBuf> {
        self.config
            .clone()
            .or_else(|| std::env::var_os("DIPPY_CONFIG").map(PathBuf::from))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forced_mode_claude() {
        let args = HookArgs {
            mode: Some(ModeArg::Claude),
            config: None,
            remote: false,
            verbose: false,
            quiet: false,
        };
        assert_eq!(args.forced_mode(), Some(Mode::Claude));
    }

    #[test]
    fn no_forced_mode() {
        let args = HookArgs {
            mode: None,
            config: None,
            remote: false,
            verbose: false,
            quiet: false,
        };
        assert_eq!(args.forced_mode(), None);
    }
}
