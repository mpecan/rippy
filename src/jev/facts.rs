//! Facts rippy computes without running anything, sent to Jev under `facts`.
//!
//! Labels only: variable values and full paths never leave the machine, so a
//! secret in `$TOKEN` or a username in a home path is not disclosed.
//! See docs/jev.md#context.

use std::path::{Component, Path, PathBuf};

use rable::NodeKind;
use serde_json::{Map, Value, json};

use super::shape::Shape;

/// Where the paths a command touches live, relative to the project.
pub struct Places<'a> {
    pub project_root: PathBuf,
    pub home: Option<PathBuf>,
    pub path_var: Option<&'a str>,
}

impl Places<'_> {
    /// The nearest ancestor of `cwd` holding `.git`, or `cwd` itself.
    #[must_use]
    pub fn project_root(cwd: &Path) -> PathBuf {
        cwd.ancestors()
            .find(|dir| dir.join(".git").exists())
            .unwrap_or(cwd)
            .to_path_buf()
    }

    fn label(&self, path: &Path) -> &'static str {
        if path.starts_with(&self.project_root) {
            "inside project"
        } else if self.home.as_ref().is_some_and(|h| path.starts_with(h)) {
            "outside project (home directory)"
        } else if path.starts_with("/dev") {
            "outside project (device)"
        } else if path.starts_with("/tmp") || path.starts_with("/private/tmp") {
            "outside project (temporary directory)"
        } else {
            "outside project (system path)"
        }
    }

    fn resolve(&self, cwd: &Path, raw: &str) -> PathBuf {
        let expanded = match (raw.strip_prefix('~'), &self.home) {
            (Some(rest), Some(home)) if rest.is_empty() || rest.starts_with('/') => {
                home.join(rest.trim_start_matches('/'))
            }
            _ => PathBuf::from(raw),
        };
        normalize(&cwd.join(expanded))
    }

    fn program_label(&self, name: &str) -> &'static str {
        let found = self
            .path_var
            .into_iter()
            .flat_map(std::env::split_paths)
            .map(|dir| dir.join(name))
            .find(|candidate| candidate.is_file());
        match found {
            None => "not found on PATH",
            Some(p) if p.starts_with(&self.project_root) => "project dependency",
            Some(p) if self.home.as_ref().is_some_and(|h| p.starts_with(h)) => "user-installed",
            Some(_) => "system-installed",
        }
    }
}

fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

fn looks_like_path(arg: &str) -> bool {
    !arg.contains("://")
        && !arg.starts_with('-')
        && (arg.starts_with(['/', '.', '~']) || arg.contains('/'))
}

/// Build the `facts` object. `lookup` reads an environment variable; it is a
/// parameter so tests stay independent of the process environment.
pub fn collect(
    shape: &Shape<'_>,
    cwd: &Path,
    places: &Places<'_>,
    lookup: &dyn Fn(&str) -> Option<String>,
    user_context: Option<&str>,
) -> Value {
    let mut variables = Map::new();
    let mut paths = Map::new();
    let mut programs = Map::new();
    for leaf in &shape.leaves {
        let Some(name) = leaf.name.as_deref() else {
            continue;
        };
        if !name.contains('/') {
            programs.insert(name.to_owned(), json!(places.program_label(name)));
        }
        for (i, word) in leaf.words.iter().enumerate() {
            for var in expanded_names(word) {
                let role = role_of(leaf.words, i, name);
                let status = match lookup(&var) {
                    None => "not set".to_owned(),
                    Some(v) if looks_like_path(&v) => {
                        format!("set to a path {}", places.label(&places.resolve(cwd, &v)))
                    }
                    Some(_) => "set (value not sent)".to_owned(),
                };
                variables.insert(var, json!(format!("{role}; {status}")));
            }
        }
        for arg in leaf
            .args
            .iter()
            .filter(|a| looks_like_path(a) && !a.contains('$'))
        {
            paths.insert(arg.clone(), json!(places.label(&places.resolve(cwd, arg))));
        }
    }
    let mut facts = Map::new();
    for (key, map) in [
        ("variables", variables),
        ("paths", paths),
        ("programs", programs),
    ] {
        if !map.is_empty() {
            facts.insert(key.to_owned(), Value::Object(map));
        }
    }
    if let Some(context) = user_context {
        facts.insert("user_context".to_owned(), json!(context));
    }
    Value::Object(facts)
}

fn role_of(words: &[rable::Node], i: usize, command: &str) -> String {
    if i == 0 {
        return "the command name".to_owned();
    }
    let previous = words.get(i - 1).map(word_text).unwrap_or_default();
    if previous.starts_with('-') {
        format!("argument after {previous} for {command}")
    } else {
        format!("argument of {command}")
    }
}

fn word_text(node: &rable::Node) -> String {
    match &node.kind {
        NodeKind::Word { value, .. } => value.clone(),
        _ => String::new(),
    }
}

/// Names of the parameters a word expands (`$NS`, `${OUT}`, `${X:-y}`).
fn expanded_names(word: &rable::Node) -> Vec<String> {
    let NodeKind::Word { parts, .. } = &word.kind else {
        return Vec::new();
    };
    parts
        .iter()
        .filter_map(|p| match &p.kind {
            NodeKind::ParamExpansion { param, .. } => Some(param.clone()),
            _ => None,
        })
        .collect()
}

#[cfg(test)]
#[path = "facts_tests.rs"]
mod tests;
