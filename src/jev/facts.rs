//! Facts rippy computes without running anything, sent to Jev under `facts`.
//!
//! Labels only: variable values never leave the machine, and a path is named
//! only as it already appears in the sanitized command, so a fact can never
//! carry text that redaction removed. See docs/jev.md#context.

use std::path::{Component, Path, PathBuf};

use rable::NodeKind;
use serde_json::{Map, Value, json};

use super::shape::Shape;

/// The label of a program that resolves inside the project. Such a command is
/// never sent: its behaviour is the project's own code.
pub const PROJECT_PROGRAM: &str = "project dependency";

/// A program rippy's own `PATH` lookup missed. Worded so the model cannot read
/// it as "the command will fail harmlessly"; see docs/jev.md#fact-wording.
pub const PROGRAM_NOT_FOUND: &str =
    "not found on rippy's PATH; may still exist when the command runs";

/// A variable unset in rippy's environment. Worded so the model cannot read it
/// as an empty value; see docs/jev.md#fact-wording.
pub const VARIABLE_UNSET: &str =
    "not set in rippy's environment; may hold any value when the command runs";

/// Whether any program in `facts` resolves inside the project.
#[must_use]
pub fn names_project_program(facts: &Value) -> bool {
    facts["programs"]
        .as_object()
        .is_some_and(|m| m.values().any(|v| v == PROJECT_PROGRAM))
}

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
        // `~user`, `~+`, `~-`: another home or a directory stack entry, never
        // the project (`resolve` leaves them relative).
        if path.to_str().is_some_and(|p| p.starts_with('~')) {
            return "outside project (another user's home or the directory stack)";
        }
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

    /// A path as shown to Jev: under the home directory, relative to `~`.
    fn display(&self, raw: &str) -> String {
        self.home
            .as_ref()
            .and_then(|home| Path::new(raw).strip_prefix(home).ok())
            .map_or_else(|| raw.to_owned(), |rest| format!("~/{}", rest.display()))
    }

    fn resolve(&self, cwd: &Path, raw: &str) -> PathBuf {
        if raw.starts_with('~') && raw != "~" && !raw.starts_with("~/") {
            return PathBuf::from(raw);
        }
        let expanded = match (raw.strip_prefix('~'), &self.home) {
            (Some(rest), Some(home)) if rest.is_empty() || rest.starts_with('/') => {
                home.join(rest.trim_start_matches('/'))
            }
            _ => PathBuf::from(raw),
        };
        normalize(&cwd.join(expanded))
    }

    /// Where `name` resolves on `PATH`. A relative entry (including an empty
    /// one, meaning the working directory) resolves against `cwd`, so a
    /// program found through it is the project's own.
    fn program_label(&self, cwd: &Path, name: &str) -> &'static str {
        for dir in self.path_var.into_iter().flat_map(std::env::split_paths) {
            let relative = dir.is_relative();
            let candidate = normalize(&cwd.join(dir).join(name));
            if !candidate.is_file() {
                continue;
            }
            return if relative || candidate.starts_with(&self.project_root) {
                PROJECT_PROGRAM
            } else if self.home.as_ref().is_some_and(|h| candidate.starts_with(h)) {
                "user-installed"
            } else {
                "system-installed"
            };
        }
        PROGRAM_NOT_FOUND
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

/// A path argument worth labelling, present verbatim in what is sent.
fn is_sendable_path(arg: &str, sanitized: &str) -> bool {
    looks_like_path(arg) && !arg.contains('$') && sanitized.contains(arg)
}

fn looks_like_path(arg: &str) -> bool {
    !arg.contains("://")
        && !arg.starts_with('-')
        && (arg.starts_with(['/', '.', '~']) || arg.contains('/'))
}

/// Where a command runs, for resolving and labelling what it names.
pub struct Where<'a> {
    pub cwd: &'a Path,
    pub places: &'a Places<'a>,
    /// Reads an environment variable; a parameter so tests stay independent
    /// of the process environment.
    pub lookup: &'a dyn Fn(&str) -> Option<String>,
}

/// Build the `facts` object.
pub fn collect(
    shape: &Shape<'_>,
    sanitized: &str,
    at: &Where<'_>,
    user_context: Option<&str>,
) -> Value {
    let (cwd, places, lookup) = (at.cwd, at.places, at.lookup);
    let mut variables = Map::new();
    let mut paths = Map::new();
    let mut programs = Map::new();
    for leaf in &shape.leaves {
        let Some(name) = leaf.name.as_deref() else {
            continue;
        };
        if !name.contains('/') {
            programs.insert(name.to_owned(), json!(places.program_label(cwd, name)));
        }
        for (i, word) in leaf.words.iter().enumerate() {
            for var in crate::ast::expanded_names(word) {
                let role = role_of(leaf.words, i, name);
                let status = match lookup(&var) {
                    None => VARIABLE_UNSET.to_owned(),
                    Some(v) if looks_like_path(&v) => {
                        format!("set to a path {}", places.label(&places.resolve(cwd, &v)))
                    }
                    Some(_) => "set (value not sent)".to_owned(),
                };
                variables.insert(var, json!(format!("{role}; {status}")));
            }
        }
        for arg in leaf.args.iter().filter(|a| is_sendable_path(a, sanitized)) {
            paths.insert(
                places.display(arg),
                json!(places.label(&places.resolve(cwd, arg))),
            );
        }
    }
    for target in shape
        .redirect_targets
        .iter()
        .filter(|t| is_sendable_path(t, sanitized))
    {
        paths.insert(
            places.display(target),
            json!(places.label(&places.resolve(cwd, target))),
        );
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

#[cfg(test)]
#[path = "facts_tests.rs"]
mod tests;
