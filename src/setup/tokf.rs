use std::path::{Path, PathBuf};
use std::process::{self, ExitCode};

use serde::Deserialize;
use tokf_hook_types::{
    ErrorFallback, ExternalEngineConfig, PermissionEngineType, PermissionsConfig, RewriteConfig,
};

use crate::cli::TokfSetupArgs;
use crate::error::RippyError;

const ALL_SUPPORTED_TOOLS: &[&str] = &[
    "claude-code",
    "opencode",
    "codex",
    "gemini-cli",
    "cursor",
    "cline",
    "windsurf",
    "copilot",
    "aider",
];

/// Minimal subset of `tokf info --json` output we need.
#[derive(Debug, Deserialize)]
struct TokfInfo {
    search_dirs: Vec<TokfSearchDir>,
}

#[derive(Debug, Deserialize)]
struct TokfSearchDir {
    scope: String,
    path: PathBuf,
}

/// Run the `rippy setup tokf` command.
///
/// # Errors
///
/// Returns `RippyError::Setup` if tokf is not installed, the target directory
/// cannot be determined, or the config file cannot be written.
pub fn run(args: &TokfSetupArgs) -> Result<ExitCode, RippyError> {
    let info = discover_tokf_info()?;
    let target_dir = select_target_dir(&info, args.global)?;

    write_permissions_config(&target_dir)?;

    let tools = resolve_tools(args);
    if !tools.is_empty() {
        install_hooks(&tools);
    }

    eprintln!("[rippy] Done! rippy is now active as tokf's permission engine.");
    Ok(ExitCode::SUCCESS)
}

/// Run `tokf info --json` and parse the output.
fn discover_tokf_info() -> Result<TokfInfo, RippyError> {
    let output = process::Command::new("tokf")
        .args(["info", "--json"])
        .stdout(process::Stdio::piped())
        .stderr(process::Stdio::inherit())
        .output()
        .map_err(|e| {
            RippyError::Setup(format!(
                "could not run `tokf info --json`: {e}. \
                 Is tokf installed? Install from https://tokf.net"
            ))
        })?;

    if !output.status.success() {
        return Err(RippyError::Setup(format!(
            "`tokf info --json` exited with status {}",
            output.status
        )));
    }

    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| RippyError::Setup(format!("tokf output was not valid UTF-8: {e}")))?;

    serde_json::from_str(&stdout)
        .map_err(|e| RippyError::Setup(format!("could not parse tokf info output: {e}")))
}

/// Pick the target directory based on --global flag.
fn select_target_dir(info: &TokfInfo, global: bool) -> Result<PathBuf, RippyError> {
    let target_scope = if global { "user" } else { "local" };

    info.search_dirs
        .iter()
        .find(|d| d.scope == target_scope)
        .map(|d| d.path.clone())
        .ok_or_else(|| {
            RippyError::Setup(format!(
                "tokf has no {target_scope} search directory configured"
            ))
        })
}

/// Read existing rewrites.toml (if any), inject permissions config, write back.
fn write_permissions_config(target_dir: &Path) -> Result<(), RippyError> {
    let rewrites_path = target_dir.join("rewrites.toml");

    let mut config = match std::fs::read_to_string(&rewrites_path) {
        Ok(content) => toml::from_str::<RewriteConfig>(&content).map_err(|e| {
            RippyError::Setup(format!("could not parse {}: {e}", rewrites_path.display()))
        })?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => RewriteConfig::default(),
        Err(e) => {
            return Err(RippyError::Setup(format!(
                "could not read {}: {e}",
                rewrites_path.display()
            )));
        }
    };

    config.permissions = Some(PermissionsConfig {
        engine: PermissionEngineType::External,
        external: Some(ExternalEngineConfig {
            command: "rippy".to_string(),
            timeout_ms: tokf_hook_types::engine::default_timeout(),
            on_error: ErrorFallback::Builtin,
            ..Default::default()
        }),
    });

    let toml_str = toml::to_string_pretty(&config)
        .map_err(|e| RippyError::Setup(format!("could not serialize permissions config: {e}")))?;

    // Create the directory if it doesn't exist.
    if let Some(parent) = rewrites_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            RippyError::Setup(format!(
                "could not create directory {}: {e}",
                parent.display()
            ))
        })?;
    }

    std::fs::write(&rewrites_path, toml_str).map_err(|e| {
        RippyError::Setup(format!("could not write {}: {e}", rewrites_path.display()))
    })?;

    eprintln!(
        "[rippy] Wrote permissions config to {}",
        rewrites_path.display()
    );
    Ok(())
}

/// Determine which tools to install hooks for.
fn resolve_tools(args: &TokfSetupArgs) -> Vec<String> {
    if args.all_hooks {
        ALL_SUPPORTED_TOOLS.iter().map(ToString::to_string).collect()
    } else {
        args.install_hooks.clone()
    }
}

/// Run `tokf hook install --tool <tool>` for each tool. Non-fatal on failure.
fn install_hooks(tools: &[String]) {
    eprintln!("[rippy] Installing tokf hooks...");
    for tool in tools {
        let result = process::Command::new("tokf")
            .args(["hook", "install", "--tool", tool])
            .stdout(process::Stdio::inherit())
            .stderr(process::Stdio::inherit())
            .status();

        match result {
            Ok(status) if status.success() => {
                eprintln!("[rippy]   {tool}: installed");
            }
            Ok(status) => {
                eprintln!("[rippy]   {tool}: failed (tokf hook install exited with {status})");
            }
            Err(e) => {
                eprintln!("[rippy]   {tool}: failed ({e})");
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn resolve_tools_all_hooks() {
        let args = TokfSetupArgs {
            global: false,
            install_hooks: vec![],
            all_hooks: true,
        };
        let tools = resolve_tools(&args);
        assert_eq!(tools.len(), ALL_SUPPORTED_TOOLS.len());
        assert!(tools.contains(&"claude-code".to_string()));
        assert!(tools.contains(&"cursor".to_string()));
    }

    #[test]
    fn resolve_tools_specific() {
        let args = TokfSetupArgs {
            global: false,
            install_hooks: vec!["claude-code".to_string(), "cursor".to_string()],
            all_hooks: false,
        };
        let tools = resolve_tools(&args);
        assert_eq!(tools, vec!["claude-code", "cursor"]);
    }

    #[test]
    fn resolve_tools_none() {
        let args = TokfSetupArgs {
            global: false,
            install_hooks: vec![],
            all_hooks: false,
        };
        let tools = resolve_tools(&args);
        assert!(tools.is_empty());
    }

    #[test]
    fn select_target_dir_global() {
        let info = TokfInfo {
            search_dirs: vec![
                TokfSearchDir {
                    scope: "local".to_string(),
                    path: PathBuf::from("/project/.tokf"),
                },
                TokfSearchDir {
                    scope: "user".to_string(),
                    path: PathBuf::from("/home/user/.config/tokf"),
                },
            ],
        };
        let dir = select_target_dir(&info, true).unwrap();
        assert_eq!(dir, PathBuf::from("/home/user/.config/tokf"));
    }

    #[test]
    fn select_target_dir_local() {
        let info = TokfInfo {
            search_dirs: vec![
                TokfSearchDir {
                    scope: "local".to_string(),
                    path: PathBuf::from("/project/.tokf"),
                },
                TokfSearchDir {
                    scope: "user".to_string(),
                    path: PathBuf::from("/home/user/.config/tokf"),
                },
            ],
        };
        let dir = select_target_dir(&info, false).unwrap();
        assert_eq!(dir, PathBuf::from("/project/.tokf"));
    }

    #[test]
    fn select_target_dir_missing_scope() {
        let info = TokfInfo {
            search_dirs: vec![TokfSearchDir {
                scope: "user".to_string(),
                path: PathBuf::from("/home/user/.config/tokf"),
            }],
        };
        let result = select_target_dir(&info, false);
        assert!(result.is_err());
    }

    #[test]
    fn parse_tokf_info_json() {
        let json = r#"{
            "version": "0.2.37",
            "search_dirs": [
                {"scope": "local", "path": "/tmp/project/.tokf", "exists": true, "access": "writable"},
                {"scope": "user", "path": "/home/user/.config/tokf", "exists": true, "access": "writable"}
            ],
            "config_files": [],
            "tracking_db": {"path": "/tmp/db", "exists": true, "access": "writable"},
            "cache": {"path": "/tmp/cache", "exists": false, "access": "will-be-created"},
            "filters": {"local": 0, "user": 0, "builtin": 200, "total": 200}
        }"#;
        let info: TokfInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.search_dirs.len(), 2);
        assert_eq!(info.search_dirs[0].scope, "local");
        assert_eq!(
            info.search_dirs[1].path,
            PathBuf::from("/home/user/.config/tokf")
        );
    }

    #[test]
    fn write_permissions_config_fresh() {
        let dir = tempfile::TempDir::new().unwrap();
        write_permissions_config(dir.path()).unwrap();

        let content = std::fs::read_to_string(dir.path().join("rewrites.toml")).unwrap();
        let config: RewriteConfig = toml::from_str(&content).unwrap();

        let perms = config.permissions.unwrap();
        assert_eq!(perms.engine, PermissionEngineType::External);
        let ext = perms.external.unwrap();
        assert_eq!(ext.command, "rippy");
        assert_eq!(ext.on_error, ErrorFallback::Builtin);
    }

    #[test]
    fn write_permissions_config_preserves_existing() {
        let dir = tempfile::TempDir::new().unwrap();
        let rewrites_path = dir.path().join("rewrites.toml");

        // Write existing config with skip patterns and rewrite rules.
        std::fs::write(
            &rewrites_path,
            r#"
[skip]
patterns = ["^my-tool "]

[[rewrite]]
match = "^docker compose"
replace = "tokf run {0}"
"#,
        )
        .unwrap();

        write_permissions_config(dir.path()).unwrap();

        let content = std::fs::read_to_string(&rewrites_path).unwrap();
        let config: RewriteConfig = toml::from_str(&content).unwrap();

        // Existing config preserved.
        let skip = config.skip.unwrap();
        assert_eq!(skip.patterns, vec!["^my-tool "]);
        assert_eq!(config.rewrite.len(), 1);
        assert_eq!(config.rewrite[0].match_pattern, "^docker compose");

        // Permissions added.
        let perms = config.permissions.unwrap();
        assert_eq!(perms.engine, PermissionEngineType::External);
        assert_eq!(perms.external.unwrap().command, "rippy");
    }
}
