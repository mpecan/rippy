//! Keeps `docs/allow-catalog.md` honest.
//!
//! Regenerate the committed file with:
//! `RIPPY_UPDATE_ALLOW_CATALOG=1 cargo test --test allow_catalog`

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use rippy_cli::allow_catalog;
use rippy_cli::verdict::{AllowCategory, AllowReason, Decision};

mod common;

use common::surfaces::{declared_namespaces, is_declared};

/// Verbs a widening would plausibly introduce. Each declared namespace is
/// probed with all of them; an approval no `allow_surface()` declares is a
/// handler that widened without saying so.
const MUTATION_VERBS: &[&str] = &[
    "add",
    "apply",
    "clean",
    "commit",
    "copy",
    "create",
    "delete",
    "deploy",
    "destroy",
    "disable",
    "edit",
    "enable",
    "exec",
    "export",
    "import",
    "init",
    "install",
    "kill",
    "load",
    "login",
    "move",
    "publish",
    "prune",
    "pull",
    "push",
    "remove",
    "rename",
    "reset",
    "restart",
    "restore",
    "rm",
    "run",
    "save",
    "set",
    "start",
    "stop",
    "sync",
    "uninstall",
    "update",
    "upgrade",
    "upload",
    "write",
];

const REGENERATE: &str =
    "regenerate with RIPPY_UPDATE_ALLOW_CATALOG=1 cargo test --test allow_catalog";

/// Surfaces the pipeline does not actually approve, with the observed reason.
///
/// Every entry was confirmed by running the command through
/// `common::isolated_analyzer()`. Shrinking this list is progress; growing it
/// without an observed reason is a bug being papered over.
const KNOWN_DIVERGENT: &[(&str, &str)] = &[];

fn catalog_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("docs/allow-catalog.md")
}

#[test]
fn allow_catalog_is_current() {
    let actual = allow_catalog::render().expect("catalog renders");
    let path = catalog_path();

    if std::env::var_os("RIPPY_UPDATE_ALLOW_CATALOG").is_some() {
        std::fs::write(&path, &actual).unwrap();
        return;
    }

    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{} unreadable: {e}; {REGENERATE}", path.display()));
    if expected == actual {
        return;
    }
    let diff: Vec<String> = expected
        .lines()
        .zip(actual.lines())
        .filter(|(e, a)| e != a)
        .take(10)
        .map(|(e, a)| format!("\n  committed: {e}\n  rendered:  {a}"))
        .collect();
    panic!(
        "docs/allow-catalog.md is stale ({} committed lines vs {} rendered).{}\n\
         This file is the record of everything rippy auto-approves: review the diff, \
         then {REGENERATE}.",
        expected.lines().count(),
        actual.lines().count(),
        diff.join("")
    );
}

/// The renderer walks a handler registry backed by a `HashMap`; a leaked
/// iteration order would make CI fail on some machines only.
#[test]
fn render_is_deterministic() {
    let first = allow_catalog::render().unwrap();
    let second = allow_catalog::render().unwrap();
    assert_eq!(first, second);
}

/// The catalog must never claim an approval the analyzer does not grant.
#[test]
fn every_literal_surface_is_allowed() {
    let mut analyzer = common::isolated_analyzer();
    let mut unexpected = Vec::new();

    for surface in allow_catalog::literal_surfaces() {
        let verdict = analyzer.analyze(&surface).unwrap();
        let divergent = KNOWN_DIVERGENT.iter().any(|(cmd, _)| *cmd == surface);
        match (verdict.decision, divergent) {
            (Decision::Allow, false) | (Decision::Ask | Decision::Deny, true) => {}
            (Decision::Allow, true) => unexpected.push(format!(
                "`{surface}` is listed as divergent but now Allows — drop it from KNOWN_DIVERGENT"
            )),
            (decision, false) => unexpected.push(format!(
                "`{surface}` is declared as an approved surface but the pipeline says \
                 {decision:?}: {}",
                verdict.reason
            )),
        }
    }

    assert!(
        unexpected.is_empty(),
        "handler allow surfaces disagree with the analyzer:\n  {}",
        unexpected.join("\n  ")
    );
}

/// Each declared namespace crossed with every mutation verb it does not
/// already declare — the invocations the sibling-verb check actually runs.
fn sibling_verb_probes(declared: &[String]) -> Vec<String> {
    let mut probes = Vec::new();
    for namespace in declared_namespaces(declared) {
        for verb in MUTATION_VERBS {
            let mut probe = namespace.clone();
            probe.push(verb);
            if !is_declared(declared, &probe) {
                probes.push(probe.join(" "));
            }
        }
    }
    probes
}

/// The direction `every_literal_surface_is_allowed` cannot check: a handler
/// that approves an invocation its `allow_surface()` never mentions. Without
/// this, a widening added straight to `classify` produces no catalog diff.
#[test]
fn no_handler_approves_an_undeclared_verb() {
    let declared = allow_catalog::declared_surfaces();
    let mut analyzer = common::isolated_analyzer();
    let mut undeclared = Vec::new();

    for command in sibling_verb_probes(&declared) {
        let verdict = analyzer.analyze(&command).unwrap();
        let from_handler =
            verdict.allow_reason().map(AllowReason::category) == Some(AllowCategory::Handler);
        if verdict.decision == Decision::Allow && from_handler {
            undeclared.push(format!("`{command}` -> {}", verdict.reason));
        }
    }

    assert!(
        undeclared.is_empty(),
        "a handler approves invocations it does not declare in allow_surface(); either stop \
         approving them or declare them (then {REGENERATE}):\n  {}",
        undeclared.join("\n  ")
    );
}

/// A matching bug can disarm the sibling-verb check without failing anything:
/// an overly generous `is_declared` skips every probe and the suite still goes
/// green. Pin the probe set so that silence is impossible.
#[test]
fn sibling_verb_probes_cover_the_declared_namespaces() {
    let declared = allow_catalog::declared_surfaces();
    let probes = sibling_verb_probes(&declared);
    let namespaces = declared_namespaces(&declared).len();

    assert!(namespaces > 40, "only {namespaces} namespaces derived");
    assert!(
        probes.len() > 30 * MUTATION_VERBS.len(),
        "only {} probes generated from {namespaces} namespaces",
        probes.len()
    );
    for expected in ["git lfs prune", "docker compose start", "npm install"] {
        assert!(
            probes.contains(&expected.to_owned()),
            "`{expected}` is no longer probed"
        );
    }
}

/// A divergence recorded but no longer produced by any handler is stale text.
#[test]
fn known_divergences_are_still_declared_surfaces() {
    let literals = allow_catalog::literal_surfaces();
    for (surface, _) in KNOWN_DIVERGENT {
        assert!(
            literals.contains(&(*surface).to_owned()),
            "`{surface}` is in KNOWN_DIVERGENT but is no longer a declared surface"
        );
    }
}
