use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::error::RippyError;

/// Resolve a tool-specific config file path.
///
/// When `global` is true, resolves relative to the home directory (e.g.
/// `~/.claude/settings.json`). Otherwise returns a project-relative path.
pub fn resolve_tool_path(global: bool, dir: &str, file: &str) -> Result<PathBuf, RippyError> {
    if global {
        dirs::home_dir()
            .map(|h| h.join(dir).join(file))
            .ok_or_else(|| RippyError::Setup("could not determine home directory".to_string()))
    } else {
        Ok(PathBuf::from(dir).join(file))
    }
}

/// Read a JSON file, returning `{}` if the file does not exist.
pub fn read_json_file(path: &Path) -> Result<Value, RippyError> {
    match std::fs::read_to_string(path) {
        Ok(content) => serde_json::from_str(&content)
            .map_err(|e| RippyError::Setup(format!("could not parse {}: {e}", path.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(serde_json::json!({})),
        Err(e) => Err(RippyError::Setup(format!(
            "could not read {}: {e}",
            path.display()
        ))),
    }
}

/// Write a JSON value to a file, creating parent directories as needed.
pub fn write_json_file(path: &Path, value: &Value) -> Result<(), RippyError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            RippyError::Setup(format!(
                "could not create directory {}: {e}",
                parent.display()
            ))
        })?;
    }

    let content = serde_json::to_string_pretty(value)
        .map_err(|e| RippyError::Setup(format!("could not serialize JSON: {e}")))?;

    std::fs::write(path, content.as_bytes())
        .map_err(|e| RippyError::Setup(format!("could not write {}: {e}", path.display())))
}

/// Check if any hook entry in an array contains "tokf" in its command field.
pub fn has_tokf_hook(hooks_array: &[Value]) -> bool {
    hooks_array
        .iter()
        .any(|entry| entry_has_command(entry, "tokf"))
}

/// Remove any hook entries that contain "rippy" in their command field.
pub fn remove_rippy_entries(hooks_array: &mut Vec<Value>) {
    hooks_array.retain(|entry| !entry_has_command(entry, "rippy"));
}

/// Check if a hook entry's command field (direct or nested) contains `needle`.
fn entry_has_command(entry: &Value, needle: &str) -> bool {
    // Direct command field (Cursor style)
    if entry
        .get("command")
        .and_then(Value::as_str)
        .is_some_and(|c| c.contains(needle))
    {
        return true;
    }
    // Nested hooks array (Claude/Gemini style)
    entry
        .get("hooks")
        .and_then(Value::as_array)
        .is_some_and(|inner| {
            inner.iter().any(|h| {
                h.get("command")
                    .and_then(Value::as_str)
                    .is_some_and(|c| c.contains(needle))
            })
        })
}

/// Ensure a nested JSON path `root[key1][key2]` exists as an array.
///
/// Creates intermediate objects and the final array as needed.
/// Returns `None` only if the structure cannot be created.
pub fn ensure_hooks_array<'a>(
    root: &'a mut Value,
    key1: &str,
    key2: &str,
) -> Option<&'a mut Vec<Value>> {
    if !root.is_object() {
        *root = serde_json::json!({});
    }
    if root.get(key1).is_none() {
        root[key1] = serde_json::json!({});
    }
    if root[key1].get(key2).is_none() {
        root[key1][key2] = serde_json::json!([]);
    }
    root[key1][key2].as_array_mut()
}

/// Install a matcher-style hook (shared by Claude Code and Gemini).
///
/// Patches `path` to add a hook entry under `hooks.<hook_type_key>` with the
/// given matcher.
///
/// # Errors
///
/// Returns `RippyError::Setup` if the file cannot be read/written, or if tokf
/// is already installed as a hook.
pub fn install_matcher_hook(
    path: &Path,
    hook_type_key: &str,
    matcher: &str,
    tool_name: &str,
) -> Result<(), RippyError> {
    let mut settings = read_json_file(path)?;
    let hooks = ensure_hooks_array(&mut settings, "hooks", hook_type_key).ok_or_else(|| {
        RippyError::Setup(format!(
            "could not create hooks array in {}",
            path.display()
        ))
    })?;

    if has_tokf_hook(hooks) {
        return Err(RippyError::Setup(format!(
            "tokf is already installed as a hook for {tool_name}. \
             Use `rippy setup tokf` to configure rippy as tokf's permission engine instead."
        )));
    }

    remove_rippy_entries(hooks);

    hooks.push(serde_json::json!({
        "matcher": matcher,
        "hooks": [{"type": "command", "command": "rippy"}]
    }));

    write_json_file(path, &settings)?;
    eprintln!(
        "[rippy] Installed hook for {tool_name} at {}",
        path.display()
    );
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn read_missing_file_returns_empty_object() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("nonexistent.json");
        let value = read_json_file(&path).unwrap();
        assert_eq!(value, serde_json::json!({}));
    }

    #[test]
    fn read_existing_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.json");
        std::fs::write(&path, r#"{"key": "value"}"#).unwrap();
        let value = read_json_file(&path).unwrap();
        assert_eq!(value["key"], "value");
    }

    #[test]
    fn read_malformed_json_errors() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("bad.json");
        std::fs::write(&path, "not json {{{").unwrap();
        assert!(read_json_file(&path).is_err());
    }

    #[test]
    fn write_creates_parent_dirs() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("sub").join("dir").join("test.json");
        let value = serde_json::json!({"hello": "world"});
        write_json_file(&path, &value).unwrap();
        let read_back: Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(read_back["hello"], "world");
    }

    #[test]
    fn has_tokf_hook_direct_command() {
        let hooks = vec![serde_json::json!({
            "type": "command",
            "command": "/path/to/tokf hook handle"
        })];
        assert!(has_tokf_hook(&hooks));
    }

    #[test]
    fn has_tokf_hook_nested() {
        let hooks = vec![serde_json::json!({
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": "tokf hook handle"}]
        })];
        assert!(has_tokf_hook(&hooks));
    }

    #[test]
    fn has_tokf_hook_no_tokf() {
        let hooks = vec![serde_json::json!({
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": "rippy"}]
        })];
        assert!(!has_tokf_hook(&hooks));
    }

    #[test]
    fn remove_rippy_entries_direct() {
        let mut hooks = vec![
            serde_json::json!({"type": "command", "command": "rippy"}),
            serde_json::json!({"type": "command", "command": "other-tool"}),
        ];
        remove_rippy_entries(&mut hooks);
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0]["command"], "other-tool");
    }

    #[test]
    fn remove_rippy_entries_nested() {
        let mut hooks = vec![
            serde_json::json!({
                "matcher": "Bash",
                "hooks": [{"type": "command", "command": "rippy"}]
            }),
            serde_json::json!({
                "matcher": "Bash",
                "hooks": [{"type": "command", "command": "other"}]
            }),
        ];
        remove_rippy_entries(&mut hooks);
        assert_eq!(hooks.len(), 1);
    }

    #[test]
    fn install_matcher_hook_fresh_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        install_matcher_hook(&path, "PreToolUse", "Bash", "Claude Code").unwrap();

        let value: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let hooks = value["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(hooks.len(), 1);
        assert_eq!(hooks[0]["matcher"], "Bash");
        assert_eq!(hooks[0]["hooks"][0]["command"], "rippy");
    }

    #[test]
    fn install_matcher_hook_idempotent() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        install_matcher_hook(&path, "PreToolUse", "Bash", "Claude Code").unwrap();
        install_matcher_hook(&path, "PreToolUse", "Bash", "Claude Code").unwrap();

        let value: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let hooks = value["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(hooks.len(), 1);
    }

    #[test]
    fn install_matcher_hook_preserves_existing() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            r#"{
                "permissions": {"allow": ["Bash(git status)"]},
                "hooks": {
                    "PreToolUse": [
                        {"matcher": "Read", "hooks": [{"type": "command", "command": "other"}]}
                    ]
                }
            }"#,
        )
        .unwrap();

        install_matcher_hook(&path, "PreToolUse", "Bash", "Claude Code").unwrap();

        let value: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(value["permissions"]["allow"].is_array());
        let hooks = value["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(hooks.len(), 2);
    }

    #[test]
    fn install_matcher_hook_rejects_tokf_conflict() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            r#"{
                "hooks": {
                    "PreToolUse": [
                        {"matcher": "Bash", "hooks": [{"type": "command", "command": "tokf hook handle"}]}
                    ]
                }
            }"#,
        )
        .unwrap();

        let result = install_matcher_hook(&path, "PreToolUse", "Bash", "Claude Code");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("tokf"));
        assert!(err.contains("rippy setup tokf"));
    }

    #[test]
    fn resolve_tool_path_project() {
        let path = resolve_tool_path(false, ".claude", "settings.json").unwrap();
        assert_eq!(path, PathBuf::from(".claude/settings.json"));
    }

    #[test]
    fn resolve_tool_path_global() {
        let path = resolve_tool_path(true, ".claude", "settings.json").unwrap();
        assert!(path.ends_with(".claude/settings.json"));
        assert!(path.is_absolute());
    }
}
