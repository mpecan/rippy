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
        };
        assert_eq!(args.forced_mode(), None);
    }
}
