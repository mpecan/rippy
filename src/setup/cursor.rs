use std::process::ExitCode;

use crate::cli::DirectHookArgs;
use crate::error::RippyError;

use super::json_settings::{
    ensure_hooks_array, has_tokf_hook, read_json_file, remove_rippy_entries, resolve_tool_path,
    write_json_file,
};

/// Install rippy as a direct hook for Cursor.
///
/// Cursor uses a different hook schema from Claude Code/Gemini:
/// `{"version": 1, "hooks": {"beforeShellExecution": [...]}}`
/// with flat entries (no `matcher` field).
///
/// # Errors
///
/// Returns `RippyError::Setup` if the hooks file cannot be read/written,
/// or if tokf is already installed as a hook.
pub fn run(args: &DirectHookArgs) -> Result<ExitCode, RippyError> {
    let path = resolve_tool_path(args.global, ".cursor", "hooks.json")?;
    install_cursor_hook(&path)?;
    Ok(ExitCode::SUCCESS)
}

fn install_cursor_hook(path: &std::path::Path) -> Result<(), RippyError> {
    let mut settings = read_json_file(path)?;

    if settings.get("version").is_none() {
        settings["version"] = serde_json::json!(1);
    }

    let hooks =
        ensure_hooks_array(&mut settings, "hooks", "beforeShellExecution").ok_or_else(|| {
            RippyError::Setup(
                "hooks.beforeShellExecution is not an array in Cursor config".to_string(),
            )
        })?;

    if has_tokf_hook(hooks) {
        return Err(RippyError::Setup(
            "tokf is already installed as a hook for Cursor. \
             Use `rippy setup tokf` to configure rippy as tokf's permission engine instead."
                .to_string(),
        ));
    }

    remove_rippy_entries(hooks);

    hooks.push(serde_json::json!({
        "type": "command",
        "command": "rippy"
    }));

    write_json_file(path, &settings)?;
    eprintln!("[rippy] Installed hook for Cursor at {}", path.display());
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use serde_json::Value;

    use super::*;

    #[test]
    fn fresh_install() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("hooks.json");
        install_cursor_hook(&path).unwrap();

        let value: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(value["version"], 1);
        let hooks = value["hooks"]["beforeShellExecution"].as_array().unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0]["type"], "command");
        assert_eq!(hooks[0]["command"], "rippy");
    }

    #[test]
    fn idempotent() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("hooks.json");
        install_cursor_hook(&path).unwrap();
        install_cursor_hook(&path).unwrap();

        let value: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let hooks = value["hooks"]["beforeShellExecution"].as_array().unwrap();
        assert_eq!(hooks.len(), 1);
    }

    #[test]
    fn preserves_existing_hooks() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("hooks.json");
        std::fs::write(
            &path,
            r#"{
                "version": 1,
                "hooks": {
                    "beforeShellExecution": [
                        {"type": "command", "command": "other-tool"}
                    ]
                }
            }"#,
        )
        .unwrap();

        install_cursor_hook(&path).unwrap();

        let value: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(value["version"], 1);
        let hooks = value["hooks"]["beforeShellExecution"].as_array().unwrap();
        assert_eq!(hooks.len(), 2);
    }

    #[test]
    fn rejects_tokf_conflict() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("hooks.json");
        std::fs::write(
            &path,
            r#"{
                "version": 1,
                "hooks": {
                    "beforeShellExecution": [
                        {"type": "command", "command": "/path/to/tokf hook handle --format cursor"}
                    ]
                }
            }"#,
        )
        .unwrap();

        let result = install_cursor_hook(&path);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("tokf"));
    }
}
