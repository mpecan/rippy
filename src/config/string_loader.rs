//! In-memory config loading for embedders and fuzz targets.
//!
//! `Config::load_from_str` parses a config string directly without touching
//! the filesystem. Unlike `Config::load`, it does NOT consult stdlib rules,
//! the home directory, or project discovery — it parses exactly the given
//! string and returns the resulting `Config`.

use std::path::Path;

use super::Config;
use super::loader::load_file_from_content;
use crate::error::RippyError;

/// Format hint for `Config::load_from_str`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFormat {
    /// Parse as TOML (`.rippy.toml` / `config.toml`).
    Toml,
    /// Parse as legacy line-based syntax (`.rippy` / `~/.rippy/config`).
    Lines,
}

impl Config {
    /// Parse a config string directly into a `Config`, without touching the filesystem.
    ///
    /// # Errors
    ///
    /// Returns `RippyError::Config` if `content` contains invalid syntax.
    /// The error's `path` field is set to the sentinel `<memory>` so callers
    /// can distinguish in-memory parses from file-based ones.
    pub fn load_from_str(content: &str, format: ConfigFormat) -> Result<Self, RippyError> {
        let sentinel: &Path = Path::new("<memory>");
        let mut directives = Vec::new();
        match format {
            ConfigFormat::Toml => {
                directives.extend(crate::toml_config::parse_toml_config(content, sentinel)?);
            }
            ConfigFormat::Lines => {
                // Reuse the file-based loader's line parser. The sentinel path
                // has no `.toml` extension, so the loader routes it through the
                // line-based branch.
                load_file_from_content(content, sentinel, &mut directives)?;
            }
        }
        Ok(Self::from_directives(directives))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::verdict::Decision;

    #[test]
    fn load_from_str_toml_minimal() {
        let cfg = Config::load_from_str(
            "[[rules]]\naction = \"allow\"\npattern = \"git status\"\n",
            ConfigFormat::Toml,
        )
        .unwrap();
        let v = cfg.match_command("git status", None).unwrap();
        assert_eq!(v.decision, Decision::Allow);
    }

    #[test]
    fn load_from_str_lines_minimal() {
        let cfg = Config::load_from_str("allow git status\n", ConfigFormat::Lines).unwrap();
        let v = cfg.match_command("git status", None).unwrap();
        assert_eq!(v.decision, Decision::Allow);
    }

    #[test]
    fn load_from_str_toml_error_has_memory_path() {
        let err = Config::load_from_str("this is not toml [[", ConfigFormat::Toml).unwrap_err();
        match err {
            RippyError::Config { path, .. } => {
                assert_eq!(path, PathBuf::from("<memory>"));
            }
            other => panic!("wrong error variant: {other:?}"),
        }
    }

    #[test]
    fn load_from_str_lines_skips_comments_and_blanks() {
        let cfg = Config::load_from_str(
            "# a comment\n\nallow ls\n# another\nallow pwd\n",
            ConfigFormat::Lines,
        )
        .unwrap();
        assert!(cfg.match_command("ls", None).is_some());
        assert!(cfg.match_command("pwd", None).is_some());
    }

    #[test]
    fn load_from_str_lines_error_reports_line_number() {
        let err = Config::load_from_str(
            "# header comment\nallow ls\nbogus directive here\n",
            ConfigFormat::Lines,
        )
        .unwrap_err();
        match err {
            RippyError::Config { path, line, .. } => {
                assert_eq!(path, PathBuf::from("<memory>"));
                assert_eq!(line, 3);
            }
            other => panic!("wrong error variant: {other:?}"),
        }
    }
}
