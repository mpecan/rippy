#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use serde_json::json;

use super::*;

fn places() -> Places<'static> {
    Places {
        project_root: PathBuf::from("/work/app"),
        home: Some(PathBuf::from("/home/dev")),
        path_var: None,
    }
}

fn facts_with(
    command: &str,
    places: &Places<'_>,
    lookup: &dyn Fn(&str) -> Option<String>,
    context: Option<&str>,
) -> Value {
    let nodes = rable::parse(command, false).unwrap();
    let shape = Shape::of(command, &nodes);
    let sanitized = shape.sanitized();
    let at = Where {
        cwd: Path::new("/work/app"),
        places,
        lookup,
    };
    collect(&shape, &sanitized, &at, context)
}

fn facts_for(command: &str, lookup: &dyn Fn(&str) -> Option<String>) -> Value {
    facts_with(command, &places(), lookup, None)
}

fn unset(_: &str) -> Option<String> {
    None
}

#[test]
fn unresolved_variable_names_its_role() {
    let facts = facts_for("kubectl get pods -n $NS", &unset);
    assert_eq!(
        facts["variables"]["NS"],
        "argument after -n for kubectl; not set in rippy's environment"
    );
}

#[test]
fn a_path_valued_variable_is_labelled_not_disclosed() {
    let lookup = |name: &str| (name == "OUT").then(|| "./target".to_owned());
    let facts = facts_for("mkdir -p $OUT/build", &lookup);
    assert_eq!(
        facts["variables"]["OUT"],
        "argument after -p for mkdir; set to a path inside project"
    );
    assert!(!facts.to_string().contains("./target"));
}

#[test]
fn a_non_path_value_is_never_sent() {
    let lookup = |_: &str| Some("hunter2".to_owned());
    let facts = facts_for("cli login --user $USERNAME", &lookup);
    assert_eq!(
        facts["variables"]["USERNAME"],
        "argument after --user for cli; set (value not sent)"
    );
    assert!(!facts.to_string().contains("hunter2"));
}

#[test]
fn paths_are_labelled_relative_to_the_project() {
    let facts = facts_for("tar c ~/.ssh src/ ../other /etc/hosts /dev/sda", &unset);
    assert_eq!(
        facts["paths"],
        json!({
            "~/.ssh": "outside project (home directory)",
            "src/": "inside project",
            "../other": "outside project (system path)",
            "/etc/hosts": "outside project (system path)",
            "/dev/sda": "outside project (device)",
        })
    );
}

// Review finding: a value redacted from the command came back as a path key.
#[test]
fn a_redacted_value_never_becomes_a_path_fact() {
    for command in [
        "somecli --password hunter2/abc list",
        "somecli --token ab/CDEFGHIJKLMNOP/xyz list",
        "somecli wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    ] {
        let facts = facts_for(command, &unset);
        for secret in ["hunter2", "CDEFGHIJ", "wJalrXUtn"] {
            assert!(!facts.to_string().contains(secret), "{command}: {facts}");
        }
    }
}

#[test]
fn home_paths_are_shown_relative_to_home() {
    let facts = facts_for("cat /home/dev/notes/todo.txt", &unset);
    assert_eq!(
        facts["paths"]["~/notes/todo.txt"],
        "outside project (home directory)"
    );
    assert!(!facts.to_string().contains("/home/dev"));
}

#[test]
fn redirect_targets_are_labelled() {
    let facts = facts_for("somecli < ~/.ssh/id_rsa > out.txt", &unset);
    assert_eq!(
        facts["paths"]["~/.ssh/id_rsa"],
        "outside project (home directory)"
    );
}

#[test]
fn urls_and_flags_are_not_paths() {
    let facts = facts_for("curl -s https://example.com/a/b --data-binary x", &unset);
    assert!(facts.get("paths").is_none());
}

#[test]
fn programs_are_labelled_by_where_they_resolve() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(bin.join("rippy-fact-tool"), "").unwrap();
    let path_var = bin.to_string_lossy().into_owned();
    let places = Places {
        project_root: dir.path().to_path_buf(),
        home: None,
        path_var: Some(&path_var),
    };
    let facts = facts_with(
        "rippy-fact-tool list | rippy-fact-missing",
        &places,
        &unset,
        None,
    );
    assert_eq!(facts["programs"]["rippy-fact-tool"], "project dependency");
    assert_eq!(facts["programs"]["rippy-fact-missing"], "not found on PATH");
}

#[test]
fn user_context_is_passed_through() {
    let context = "kubectl only talks to local kind clusters";
    let facts = facts_with("ls", &places(), &unset, Some(context));
    assert_eq!(facts["user_context"], context);
}

#[test]
fn project_root_is_the_nearest_git_ancestor() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".git")).unwrap();
    let nested = dir.path().join("a/b");
    std::fs::create_dir_all(&nested).unwrap();
    assert_eq!(Places::project_root(&nested), dir.path());
}
