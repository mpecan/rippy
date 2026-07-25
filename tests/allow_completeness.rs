//! The allow surface must be *covered*, not merely declared.
//!
//! `tests/allow_catalog.rs` proves the declaration and the analyzer agree.
//! This file proves the catalog exercises them: a new safe verb ships with a
//! `decision = "allow"` case, and the prefix it hangs off ships with a
//! dangerous neighbor that must Ask or Deny. Adding an approval with neither
//! fails CI, which is the gap behind #155–#162.
//!
//! Issue #165 words the neighbor requirement per surface entry; it is enforced
//! per *approved prefix* instead — every declared namespace, every guarded
//! surface's literal prefix, and every handler command name. That narrowing is
//! deliberate, not an oversight:
//! a neighbor has to be a command someone can actually write, and most approved
//! verbs have no dangerous form at all. 430 of the 451 fully-spelled surfaces
//! (`docker version`, `aws sts get-caller-identity`, `ansible-config view`)
//! admit none, and a per-entry rule would answer that with 430 exemptions,
//! which is a weaker gate than the one below. Probing does not rescue it
//! either: crossing every declared surface with `--output=/etc/x`,
//! `--exec=id` and `--use-compress-program=sh` leaves 1227 of 1233 probes
//! approved, because an unknown flag is simply not dangerous for most tools —
//! which flag is dangerous is knowledge only the handler has.
//!
//! What the allow half still guarantees is per entry: `git bugreport` added to
//! `SAFE_SUBCOMMANDS` fails `every_declared_surface_has_an_allow_case` until an
//! observed case is written for it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use rippy_cli::verdict::Decision;
use rippy_cli::{allow_catalog, allowlists};

mod common;

use common::catalog::CatalogCase;
use common::surfaces::{declared_namespaces, exercises, guarded_prefixes, segments};

/// Surfaces whose approval depends on file content the command string only
/// names, so a catalog case reaches the Ask branch instead. Each is pinned by
/// a white-box test that injects the file, per CLAUDE.md's split.
const SURFACES_NEEDING_INJECTED_STATE: &[(&str, &str)] = &[
    (
        "awk -f <script>",
        "approval reads the script file: tests/file_reading.rs::awk_f_safe_file_allows",
    ),
    (
        "gh api <endpoint> --input <file>",
        "approval reads the request body: src/handlers/gh.rs::api_input_query_file_allows",
    ),
    (
        "psql -f|--file <path>",
        "approval reads the SQL file: src/handlers/database.rs::psql_f_readonly_allows",
    ),
];

/// Command names a handler approves unconditionally, so no invocation of them
/// can Ask and no contrast case can exist. An entry is a blanket approval on
/// record, not a gap to be quietly tolerated.
const GROUPS_WITHOUT_A_BOUNDARY: &[(&str, &str)] = &[
    (
        "ansible-doc",
        "handler returns Allow(\"ansible-doc (read-only)\") for every argv, including \
         `-M <dir>`",
    ),
    (
        "ansible-lint",
        "handler returns Allow(\"ansible-lint (read-only)\") for every argv, including \
         `--fix` and `--write`",
    ),
];

/// Approved prefixes knowingly shipped without a dangerous neighbor. Empty is
/// the only healthy state; an entry here is a boundary nobody has pinned.
const PREFIXES_WITHOUT_A_NEIGHBOR: &[(&str, &str)] = &[];

const HOWTO: &str = "add an observed case to tests/data/catalog/ — run the command through \
                     the analyzer first and transcribe the decision it actually returns";

/// Report at most this many missing items before summarising; a full list of
/// several hundred is unreadable in CI output.
const MAX_REPORTED: usize = 25;

fn report(missing: &[String], headline: &str) {
    let shown: Vec<&str> = missing
        .iter()
        .take(MAX_REPORTED)
        .map(String::as_str)
        .collect();
    assert!(
        missing.is_empty(),
        "{headline}\n  {}{}\n{HOWTO}",
        shown.join("\n  "),
        if missing.len() > MAX_REPORTED {
            format!("\n  ... and {} more", missing.len() - MAX_REPORTED)
        } else {
            String::new()
        }
    );
}

/// Every command segment of every `decision = "allow"` case.
fn allowed_segments(cases: &[CatalogCase]) -> Vec<Vec<String>> {
    cases
        .iter()
        .filter(|c| c.decision == Decision::Allow)
        .flat_map(|c| segments(&c.command))
        .collect()
}

/// The leading invocation of every Ask/Deny case simple enough to read as one.
///
/// A case is only usable as a neighbor when the command it names is the whole
/// reason it is not approved. Cases carrying a redirect, a substitution or a
/// second segment are skipped: their verdict may come from the plumbing rather
/// than from the verb, and crediting one would let a namespace look bounded
/// when nothing bounds it.
fn neighbor_invocations(cases: &[CatalogCase]) -> Vec<Vec<String>> {
    cases
        .iter()
        .filter(|c| c.decision >= Decision::Ask)
        .filter(|c| !c.command.contains(['>', '<', '$', '`', '(', ')']))
        .filter_map(|c| {
            let mut parts = segments(&c.command);
            (parts.len() == 1).then(|| parts.remove(0))
        })
        .collect()
}

fn as_refs(words: &[String]) -> Vec<&str> {
    words.iter().map(String::as_str).collect()
}

/// Is `probe` spelled out, word for word, as an unguarded declared surface?
///
/// Such an invocation cannot be its own boundary, so it is not accepted as a
/// neighbor. Guarded and placeholder surfaces are deliberately *not* consulted:
/// there the guard is exactly what the neighbor demonstrates — `npm run build`
/// bounds `npm run`, `cd /etc` bounds `cd <path>`.
fn is_unconditionally_declared(literals: &[String], probe: &[&str]) -> bool {
    literals.contains(&probe.join(" "))
}

/// The command names every handler group answers to, taken from the first word
/// of each declared surface. `handlers` is `pub(crate)`, so the group list has
/// to be derived rather than read.
fn declared_groups(declared: &[String]) -> BTreeSet<&str> {
    declared
        .iter()
        .filter_map(|s| s.split_whitespace().next())
        .flat_map(|first| first.split('|'))
        .collect()
}

/// Does `probe` extend `prefix` with at least one further word?
fn extends(prefix: &[&str], probe: &[&str]) -> bool {
    probe.len() > prefix.len() && probe.starts_with(prefix)
}

/// Every prefix an approval hangs off: the namespaces of fully-spelled surfaces
/// and the literal head of every guarded one.
fn approved_prefixes(declared: &[String]) -> Vec<Vec<&str>> {
    let mut prefixes = declared_namespaces(declared);
    for prefix in guarded_prefixes(declared) {
        if !prefixes.contains(&prefix) {
            prefixes.push(prefix);
        }
    }
    prefixes
}

#[test]
fn every_simple_safe_command_has_an_allow_case() {
    let cases = common::catalog::load();
    let allowed = allowed_segments(&cases);
    let leading: BTreeSet<&str> = allowed
        .iter()
        .filter_map(|words| words.first().map(String::as_str))
        .collect();

    let missing: Vec<String> = allowlists::all_simple_safe()
        .into_iter()
        .filter(|cmd| !leading.contains(cmd))
        .map(|cmd| format!("`{cmd}` (SIMPLE_SAFE) has no allow case"))
        .collect();

    report(
        &missing,
        "commands rippy approves on the name alone, with nothing pinning that:",
    );
}

#[test]
fn every_declared_surface_has_an_allow_case() {
    let cases = common::catalog::load();
    let allowed = allowed_segments(&cases);

    let missing: Vec<String> = allow_catalog::declared_surfaces()
        .into_iter()
        .filter(|surface| {
            !SURFACES_NEEDING_INJECTED_STATE
                .iter()
                .any(|(exempt, _)| exempt == surface)
        })
        .filter(|surface| {
            !allowed
                .iter()
                .any(|words| exercises(surface, &as_refs(words)))
        })
        .map(|surface| format!("`{surface}` is declared approved but no allow case exercises it"))
        .collect();

    report(&missing, "declared allow surfaces with no catalog case:");
}

#[test]
fn every_approved_prefix_has_a_dangerous_neighbor() {
    let declared = allow_catalog::declared_surfaces();
    let literals = allow_catalog::literal_surfaces();
    let cases = common::catalog::load();
    let neighbors = neighbor_invocations(&cases);

    let missing: Vec<String> = approved_prefixes(&declared)
        .into_iter()
        .filter(|prefix| {
            let joined = prefix.join(" ");
            !PREFIXES_WITHOUT_A_NEIGHBOR
                .iter()
                .any(|(exempt, _)| *exempt == joined)
        })
        .filter(|prefix| {
            !neighbors.iter().any(|words| {
                let probe = as_refs(words);
                extends(prefix, &probe) && !is_unconditionally_declared(&literals, &probe)
            })
        })
        .map(|prefix| {
            format!(
                "`{}` has approved verbs but no ask/deny case marking where they stop",
                prefix.join(" ")
            )
        })
        .collect();

    report(&missing, "approved prefixes with no dangerous neighbor:");
}

/// Catches handlers whose surfaces are all single-word, guarded or
/// alternation-only and so produce no namespace at all — the ones the check
/// above cannot see.
#[test]
fn every_handler_group_has_a_dangerous_case() {
    let declared = allow_catalog::declared_surfaces();
    let literals = allow_catalog::literal_surfaces();
    let cases = common::catalog::load();
    let neighbors = neighbor_invocations(&cases);

    let missing: Vec<String> = declared_groups(&declared)
        .into_iter()
        .filter(|group| {
            !GROUPS_WITHOUT_A_BOUNDARY
                .iter()
                .any(|(exempt, _)| exempt == group)
        })
        .filter(|group| {
            !neighbors.iter().any(|words| {
                let probe = as_refs(words);
                probe.first() == Some(group) && !is_unconditionally_declared(&literals, &probe)
            })
        })
        .map(|group| format!("`{group}` approves invocations but no ask/deny case bounds it"))
        .collect();

    report(&missing, "handler groups with no dangerous case:");
}

/// An exemption for something that no longer exists is stale text that would
/// silently excuse a future surface of the same name.
#[test]
fn exemptions_are_still_real() {
    let declared = allow_catalog::declared_surfaces();
    for (surface, _) in SURFACES_NEEDING_INJECTED_STATE {
        assert!(
            declared.contains(&(*surface).to_owned()),
            "`{surface}` is exempted but is no longer a declared surface"
        );
    }
    let prefixes: Vec<String> = approved_prefixes(&declared)
        .iter()
        .map(|prefix| prefix.join(" "))
        .collect();
    for (prefix, _) in PREFIXES_WITHOUT_A_NEIGHBOR {
        assert!(
            prefixes.contains(&(*prefix).to_owned()),
            "`{prefix}` is exempted but is no longer an approved prefix"
        );
    }
    let groups = declared_groups(&declared);
    for (group, _) in GROUPS_WITHOUT_A_BOUNDARY {
        assert!(
            groups.contains(group),
            "`{group}` is exempted but is no longer a handler command"
        );
    }
}

/// Every check above is a set difference, so a bug that empties one of the
/// input sets makes it pass in silence. Pin the inputs and the matcher.
#[test]
fn completeness_inputs_are_not_vacuous() {
    let declared = allow_catalog::declared_surfaces();
    assert!(declared.len() > 500, "{} declared surfaces", declared.len());
    assert!(allowlists::all_simple_safe().len() > 120);
    assert!(declared_namespaces(&declared).len() > 50);
    assert!(guarded_prefixes(&declared).len() > 30);
    assert!(approved_prefixes(&declared).len() > 80);
    assert!(declared_groups(&declared).len() > 40);

    let cases = common::catalog::load();
    let allowed = allowed_segments(&cases);
    let neighbors = neighbor_invocations(&cases);
    assert!(cases.len() > 1000, "{} catalog cases", cases.len());
    assert!(allowed.len() > 800, "{} allow segments", allowed.len());
    assert!(neighbors.len() > 40, "{} neighbors", neighbors.len());

    // The escape hatches are the one place this gate can rot into a silent
    // skip, so cap them: growth has to be argued for, not merged.
    assert!(SURFACES_NEEDING_INJECTED_STATE.len() <= 5);
    assert!(GROUPS_WITHOUT_A_BOUNDARY.len() <= 5);
    assert!(PREFIXES_WITHOUT_A_NEIGHBOR.len() <= 5);

    assert!(exercises("git log", &["git", "log", "--oneline"]));
    assert!(!exercises("git log", &["git", "commit"]));
    assert!(!exercises("npm --help|-h", &["npm", "install"]));
    assert!(exercises("aws <service> ls", &["aws", "s3", "ls"]));
    assert!(!exercises("aws <service> wait", &["aws", "s3", "ls"]));
    assert!(
        segments("echo hi | tee")
            .iter()
            .any(|words| words.first().is_some_and(|w| w == "tee"))
    );
}
