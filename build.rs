#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::too_many_lines
)]

use std::collections::HashSet;
use std::fmt::Write as _;
use std::path::Path;
use std::{env, fs};

use serde::Deserialize;

// ---------------------------------------------------------------------------
// TOML schema (mirrors the test catalog format)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct TestCatalog {
    #[serde(default)]
    case: Vec<TestCase>,
    #[serde(default)]
    contrast: Vec<ContrastGroup>,
}

#[derive(Debug, Deserialize)]
struct TestCase {
    command: String,
    decision: String,
    reason_contains: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ContrastGroup {
    description: Option<String>,
    template: String,
    #[serde(default)]
    safe: Vec<ContrastCase>,
    #[serde(default)]
    dangerous: Vec<ContrastCase>,
}

#[derive(Debug, Deserialize)]
struct ContrastCase {
    inner: String,
    reason_contains: Option<String>,
}

/// Sanitize a string into a valid `snake_case` Rust identifier fragment.
/// Collapses consecutive underscores and trims leading/trailing ones.
/// Returns `"empty"` for blank inputs.
fn sanitize(s: &str) -> String {
    let raw: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    // Collapse runs of underscores into one.
    let mut result = String::with_capacity(raw.len());
    let mut prev_underscore = true; // trim leading
    for c in raw.chars() {
        if c == '_' {
            if !prev_underscore {
                result.push('_');
            }
            prev_underscore = true;
        } else {
            result.push(c);
            prev_underscore = false;
        }
    }
    let trimmed = result.trim_end_matches('_').to_owned();
    if trimmed.is_empty() {
        "empty".to_owned()
    } else {
        trimmed
    }
}

/// Build a test function name from parts, joining with `_` and collapsing runs.
fn make_name(parts: &[&str], seen: &mut HashSet<String>) -> String {
    let joined = parts.join("_");
    let base = sanitize(&joined);
    unique_name(&base, seen)
}

/// Ensure a test name is unique by appending a counter if needed.
fn unique_name(base: &str, seen: &mut HashSet<String>) -> String {
    let mut name = base.to_owned();
    if !seen.insert(name.clone()) {
        let mut i = 2;
        loop {
            name = format!("{base}_{i}");
            if seen.insert(name.clone()) {
                break;
            }
            i += 1;
        }
    }
    name
}

fn emit_cases(
    output: &mut String,
    file_stem: &str,
    catalog: &TestCatalog,
    seen: &mut HashSet<String>,
) {
    let stem = sanitize(file_stem);
    for (i, case) in catalog.case.iter().enumerate() {
        let slug: String = sanitize(&case.command).chars().take(40).collect();
        let name = make_name(&["catalog", &stem, &slug, &i.to_string()], seen);

        let _ = writeln!(output, "#[test]");
        let _ = writeln!(output, "fn {name}() {{");
        let _ = writeln!(output, "    let mut a = isolated_analyzer();");
        let _ = writeln!(
            output,
            "    run_case(&mut a, &Case {{ file: {:?}, idx: {i}, command: {:?}, decision: {:?}, reason_contains: {:?} }});",
            file_stem, case.command, case.decision, case.reason_contains,
        );
        let _ = writeln!(output, "}}");
        let _ = writeln!(output);
    }
}

fn emit_contrasts(
    output: &mut String,
    _file_stem: &str,
    catalog: &TestCatalog,
    seen: &mut HashSet<String>,
) {
    for (gi, group) in catalog.contrast.iter().enumerate() {
        let desc: String = sanitize(group.description.as_deref().unwrap_or("contrast"))
            .chars()
            .take(30)
            .collect();

        for (si, safe_case) in group.safe.iter().enumerate() {
            let inner: String = sanitize(&safe_case.inner).chars().take(20).collect();
            let idx = (gi * 100 + si).to_string();
            let name = make_name(&["catalog", &desc, "safe", &inner, &idx], seen);

            let _ = writeln!(output, "#[test]");
            let _ = writeln!(output, "fn {name}() {{");
            let _ = writeln!(output, "    let mut a = isolated_analyzer();");
            let _ = writeln!(
                output,
                "    run_contrast_safe(&mut a, {:?}, {:?}, {:?});",
                group.description.as_deref().unwrap_or("contrast"),
                group.template,
                safe_case.inner,
            );
            let _ = writeln!(output, "}}");
            let _ = writeln!(output);
        }

        for (di, danger_case) in group.dangerous.iter().enumerate() {
            let inner: String = sanitize(&danger_case.inner).chars().take(20).collect();
            let idx = (gi * 100 + di).to_string();
            let name = make_name(&["catalog", &desc, "danger", &inner, &idx], seen);

            let _ = writeln!(output, "#[test]");
            let _ = writeln!(output, "fn {name}() {{");
            let _ = writeln!(output, "    let mut a = isolated_analyzer();");
            let _ = writeln!(
                output,
                "    run_contrast_danger(&mut a, {:?}, {:?}, {:?}, {:?});",
                group.description.as_deref().unwrap_or("contrast"),
                group.template,
                danger_case.inner,
                danger_case.reason_contains,
            );
            let _ = writeln!(output, "}}");
            let _ = writeln!(output);
        }
    }
}

fn main() {
    let catalog_dir = Path::new("tests/data/catalog");
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest = Path::new(&out_dir).join("catalog_generated_tests.rs");

    println!("cargo:rerun-if-changed=tests/data/catalog");

    let mut output = String::new();
    let mut seen = HashSet::new();

    let Ok(entries) = fs::read_dir(catalog_dir) else {
        fs::write(&dest, "// No catalog TOML files found.\n").unwrap();
        return;
    };
    let mut paths: Vec<_> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "toml"))
        .collect();
    paths.sort();

    for path in &paths {
        let file_stem = path.file_stem().unwrap().to_string_lossy().to_string();
        let content = fs::read_to_string(path).unwrap();
        let catalog: TestCatalog =
            toml::from_str(&content).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));

        emit_cases(&mut output, &file_stem, &catalog, &mut seen);
        emit_contrasts(&mut output, &file_stem, &catalog, &mut seen);
    }

    fs::write(&dest, output).unwrap();
}
