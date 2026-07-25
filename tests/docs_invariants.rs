//! Keeps the traceability table in `docs/security-invariants.md` honest, and
//! every `docs/*.md#anchor` pointer under `src/` and `tests/` resolvable.
//!
//! The table is only useful if it cannot rot: a new anchor without a row, a
//! source pointer to a heading that no longer exists, or a renamed test would
//! otherwise leave the document quietly wrong.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The table's own heading — it documents no invariant, so it needs no row.
const TABLE_HEADING: &str = "traceability";

const SECURITY_DOC: &str = "docs/security-invariants.md";
const FUZZING_DOC: &str = "docs/fuzzing.md";

/// Excluded from the pointer scan: it carries the doc paths as string data, so
/// scanning itself would find a prefix with no anchor behind it.
const SELF_FILE: &str = "docs_invariants.rs";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read_doc(relative: &str) -> String {
    let path = repo_root().join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn doc() -> String {
    read_doc(SECURITY_DOC)
}

fn anchors(doc: &str) -> BTreeSet<String> {
    doc.lines()
        .filter_map(|l| l.strip_prefix("## "))
        .map(str::trim)
        .filter(|a| *a != TABLE_HEADING)
        .map(str::to_owned)
        .collect()
}

/// The contiguous run of `|` lines after the table header, minus the separator.
/// Prose elsewhere may mention an anchor, so only this block counts as rows.
fn table_rows(doc: &str) -> Vec<Vec<String>> {
    doc.lines()
        .skip_while(|l| !l.starts_with("| Anchor |"))
        .skip(1)
        .take_while(|l| l.starts_with('|'))
        .filter(|l| !l.trim_start_matches('|').trim().starts_with("---"))
        .map(|l| {
            l.trim()
                .trim_matches('|')
                .split('|')
                .map(|c| c.trim().to_owned())
                .collect()
        })
        .collect()
}

fn backticked(cell: &str) -> Vec<String> {
    cell.split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

fn rust_files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {}: {e}", dir.display()));
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files_under(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn every_doc_anchor_has_a_traceability_row() {
    let doc = doc();
    let rows = table_rows(&doc);
    assert!(!rows.is_empty(), "no traceability table found");
    let cited: BTreeSet<String> = rows
        .iter()
        .filter_map(|cells| cells.first())
        .flat_map(|cell| backticked(cell))
        .map(|a| a.trim_start_matches('#').to_owned())
        .collect();
    assert_eq!(
        anchors(&doc),
        cited,
        "doc headings and traceability-table anchors disagree"
    );
}

fn scanned_files() -> Vec<PathBuf> {
    let root = repo_root();
    let mut files = Vec::new();
    rust_files_under(&root.join("src"), &mut files);
    rust_files_under(&root.join("tests"), &mut files);
    files.retain(|p| p.file_name().is_some_and(|n| n != SELF_FILE));
    files
}

/// GitHub's heading-to-anchor rule, restricted to what the docs actually use:
/// lowercase, spaces to hyphens, everything else but `[a-z0-9-]` dropped.
fn slug(heading: &str) -> String {
    heading
        .trim()
        .to_lowercase()
        .chars()
        .filter_map(|c| match c {
            ' ' => Some('-'),
            c if c.is_ascii_alphanumeric() || c == '-' => Some(c),
            _ => None,
        })
        .collect()
}

fn heading_anchors(doc: &str) -> BTreeSet<String> {
    doc.lines()
        .filter_map(|l| {
            l.strip_prefix("### ")
                .or_else(|| l.strip_prefix("## "))
                .or_else(|| l.strip_prefix("# "))
        })
        .map(slug)
        .collect()
}

fn assert_pointers_resolve(relative_doc: &str, known: &BTreeSet<String>) {
    let prefix = format!("{relative_doc}#");
    let mut checked = 0_usize;
    for file in scanned_files() {
        let text = std::fs::read_to_string(&file).expect("read source file");
        for (offset, _) in text.match_indices(prefix.as_str()) {
            let anchor: String = text[offset + prefix.len()..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
                .collect();
            checked += 1;
            assert!(
                known.contains(&anchor),
                "{} points at unknown anchor {prefix}{anchor}",
                file.display()
            );
        }
    }
    assert!(checked > 0, "found no {relative_doc} pointers to check");
}

#[test]
fn every_source_pointer_resolves_to_a_doc_anchor() {
    assert_pointers_resolve(SECURITY_DOC, &anchors(&doc()));
}

#[test]
fn every_fuzzing_pointer_resolves_to_a_doc_anchor() {
    assert_pointers_resolve(FUZZING_DOC, &heading_anchors(&read_doc(FUZZING_DOC)));
}

#[test]
fn every_test_named_in_the_table_exists() {
    let root = repo_root();
    let doc = doc();
    let mut checked = 0_usize;
    for cells in table_rows(&doc) {
        let cell = cells.last().expect("row has a test column");
        for reference in backticked(cell) {
            let (relative, test_name) = match reference.split_once("::") {
                Some((path, name)) => (path.to_owned(), Some(name.to_owned())),
                None => (reference.clone(), None),
            };
            let path = root.join(&relative);
            assert!(path.is_file(), "table cites missing file {relative}");
            checked += 1;
            let Some(name) = test_name else { continue };
            let text = std::fs::read_to_string(&path).expect("read cited file");
            assert!(
                text.contains(&format!("fn {name}(")),
                "{relative} does not define a test named {name}"
            );
        }
    }
    assert!(checked > 0, "traceability table cited no tests");
}
