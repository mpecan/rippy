use std::path::PathBuf;

use crate::resolve::{EnvLookup, VarLookup};

/// External environment dependencies for the analysis pipeline.
///
/// Groups all values that come from the OS environment so they can be
/// overridden in tests without manipulating env vars. Production code
/// creates this via [`Environment::from_system`]; tests use the builder
/// methods to inject specific values.
pub struct Environment {
    /// Home directory (`$HOME`). Used for `~/.rippy/config`, `~/.claude/settings`.
    /// `None` skips all home-based lookups.
    pub home: Option<PathBuf>,

    /// Working directory for the analysis (usually `std::env::current_dir()`).
    pub working_directory: PathBuf,

    /// Variable lookup for static expansion resolution.
    /// Defaults to `EnvLookup` (real `std::env::var`).
    pub var_lookup: Box<dyn VarLookup>,

    /// Whether the command originates from a remote context (e.g. `docker exec`).
    pub remote: bool,

    /// Emit tracing to stderr.
    pub verbose: bool,
}

impl Environment {
    /// Build from the real system environment.
    #[must_use]
    pub fn from_system(working_directory: PathBuf, remote: bool, verbose: bool) -> Self {
        Self {
            home: std::env::var_os("HOME").map(PathBuf::from),
            working_directory,
            var_lookup: Box::new(EnvLookup),
            remote,
            verbose,
        }
    }

    /// Override the home directory (builder pattern).
    #[must_use]
    pub fn with_home(mut self, home: Option<PathBuf>) -> Self {
        self.home = home;
        self
    }

    /// Override the variable lookup (builder pattern).
    #[must_use]
    pub fn with_var_lookup(mut self, var_lookup: Box<dyn VarLookup>) -> Self {
        self.var_lookup = var_lookup;
        self
    }
}
