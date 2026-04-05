use std::path::{Path, PathBuf};

use super::home_dir;

/// Walk up from `start` looking for `.rippy` or `.dippy` config files.
pub fn find_project_config(start: &Path) -> Option<PathBuf> {
    let mut dir = start;
    loop {
        let toml = dir.join(".rippy.toml");
        if toml.is_file() {
            return Some(toml);
        }
        let rippy = dir.join(".rippy");
        if rippy.is_file() {
            return Some(rippy);
        }
        let dippy = dir.join(".dippy");
        if dippy.is_file() {
            return Some(dippy);
        }
        dir = dir.parent()?;
    }
}

/// A config source with its tier label and optional file path.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ConfigSourceInfo {
    pub tier: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
}

/// Enumerate the config sources that would be loaded for a given cwd.
///
/// Returns `(tier, path)` tuples in load order: stdlib → global → project/override.
pub fn enumerate_config_sources(
    cwd: &Path,
    config_override: Option<&Path>,
) -> Vec<ConfigSourceInfo> {
    let mut sources = vec![ConfigSourceInfo {
        tier: "stdlib",
        path: None,
    }];

    if let Some(home) = home_dir() {
        for candidate in [
            home.join(".rippy/config.toml"),
            home.join(".rippy/config"),
            home.join(".dippy/config"),
        ] {
            if candidate.is_file() {
                sources.push(ConfigSourceInfo {
                    tier: "global",
                    path: Some(candidate),
                });
                break;
            }
        }
    }

    if let Some(override_path) = config_override {
        sources.push(ConfigSourceInfo {
            tier: "override",
            path: Some(override_path.to_owned()),
        });
    } else if let Some(project) = find_project_config(cwd) {
        sources.push(ConfigSourceInfo {
            tier: "project",
            path: Some(project),
        });
    }

    sources
}
