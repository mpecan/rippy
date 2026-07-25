//! Reads `tests/data/catalog/*.toml` at test runtime.
//!
//! `build.rs` turns the same files into one `#[test]` per entry, which is what
//! asserts the decisions. This loader exists so a test can reason about the
//! catalog as a *set* — which commands it contains, and what each one is
//! expected to decide. The schema is duplicated rather than shared because
//! `build.rs`, `src/analyzer_snapshot_tests.rs` and this file live in three
//! crates that cannot see each other's `#[cfg(test)]` types.

use std::path::PathBuf;

use rippy_cli::verdict::Decision;
use serde::Deserialize;

#[derive(Deserialize)]
struct CatalogFile {
    #[serde(default)]
    case: Vec<RawCase>,
    #[serde(default)]
    contrast: Vec<RawContrast>,
}

#[derive(Deserialize)]
struct RawCase {
    command: String,
    decision: String,
}

#[derive(Deserialize)]
struct RawContrast {
    template: String,
    #[serde(default)]
    safe: Vec<RawContrastCase>,
    #[serde(default)]
    dangerous: Vec<RawContrastCase>,
}

#[derive(Deserialize)]
struct RawContrastCase {
    inner: String,
}

/// One catalog expectation, with contrast groups already expanded into the
/// concrete command the runner builds from `template` and `inner`.
pub struct CatalogCase {
    pub file: String,
    pub command: String,
    pub decision: Decision,
}

fn parse_decision(raw: &str, file: &str) -> Decision {
    match raw {
        "allow" => Decision::Allow,
        "ask" => Decision::Ask,
        "deny" => Decision::Deny,
        other => panic!("{file}: unknown decision {other:?}"),
    }
}

fn expand(file: &str, parsed: CatalogFile, out: &mut Vec<CatalogCase>) {
    for case in parsed.case {
        let decision = parse_decision(&case.decision, file);
        out.push(CatalogCase {
            file: file.to_owned(),
            command: case.command,
            decision,
        });
    }
    for group in parsed.contrast {
        // Mirrors tests/catalog_runner.rs::run_contrast, which asserts Allow
        // for every `safe` inner and Ask-or-worse for every `dangerous` one.
        let expanded = group
            .safe
            .into_iter()
            .map(|c| (c.inner, Decision::Allow))
            .chain(
                group
                    .dangerous
                    .into_iter()
                    .map(|c| (c.inner, Decision::Ask)),
            );
        for (inner, decision) in expanded {
            out.push(CatalogCase {
                file: file.to_owned(),
                command: group.template.replace("{CMD}", &inner),
                decision,
            });
        }
    }
}

/// Every expectation in the committed catalog, in file-name order.
pub fn load() -> Vec<CatalogCase> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/catalog");
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("catalog directory is readable")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "toml"))
        .collect();
    paths.sort();

    let mut cases = Vec::new();
    for path in &paths {
        let name = path.file_stem().unwrap_or_default().to_string_lossy();
        let text = std::fs::read_to_string(path).expect("catalog file is readable");
        let parsed: CatalogFile = toml::from_str(&text).expect("catalog file parses");
        expand(&name, parsed, &mut cases);
    }
    cases
}
