//! Materializes the `analyze` fuzz target's seed corpus from the test catalog.
//!
//! The seeds are generated rather than committed: `tests/data/catalog/*.toml`
//! grows on nearly every handler change, and 700+ one-line corpus files would
//! churn with it. The nightly fuzz workflow sets `RIPPY_WRITE_FUZZ_SEEDS` to
//! fill `fuzz/seeds/analyze/` before starting a run; a plain `cargo test` only
//! checks that the catalog still yields a usable corpus, so the standard gate
//! stays hermetic. See docs/fuzzing.md.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// FNV-1a over the command text: content-addressed names make a re-run
/// idempotent and a concurrent run harmless.
fn seed_name(command: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in command.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}.txt")
}

fn commands_in(value: &toml::Value) -> Vec<String> {
    let mut commands = Vec::new();
    if let Some(cases) = value.get("case").and_then(toml::Value::as_array) {
        for case in cases {
            if let Some(cmd) = case.get("command").and_then(toml::Value::as_str) {
                commands.push(cmd.to_string());
            }
        }
    }
    for group in value
        .get("contrast")
        .and_then(toml::Value::as_array)
        .unwrap_or(&Vec::new())
    {
        let Some(template) = group.get("template").and_then(toml::Value::as_str) else {
            continue;
        };
        for key in ["safe", "dangerous"] {
            for entry in group
                .get(key)
                .and_then(toml::Value::as_array)
                .unwrap_or(&Vec::new())
            {
                if let Some(inner) = entry.get("inner").and_then(toml::Value::as_str) {
                    commands.push(template.replace("{CMD}", inner));
                }
            }
        }
    }
    commands
}

fn catalog_commands(catalog_dir: &Path) -> BTreeSet<String> {
    let mut commands = BTreeSet::new();
    for entry in std::fs::read_dir(catalog_dir).expect("catalog directory exists") {
        let path = entry.expect("readable dir entry").path();
        if path.extension().is_none_or(|e| e != "toml") {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("catalog file is readable");
        let value: toml::Value = toml::from_str(&text).expect("catalog file is valid TOML");
        commands.extend(commands_in(&value));
    }
    commands
}

#[test]
fn catalog_yields_a_usable_seed_corpus() {
    let commands = catalog_commands(&repo_root().join("tests/data/catalog"));
    assert!(
        commands.len() > 100,
        "catalog yielded only {} commands — the seed corpus would be near-empty",
        commands.len()
    );

    let names: BTreeSet<String> = commands.iter().map(|c| seed_name(c)).collect();
    assert_eq!(
        names.len(),
        commands.len(),
        "seed file names collide — distinct catalog commands would overwrite each other"
    );
}

/// Writing is opt-in: it rewrites hundreds of files under the source tree, which
/// a read-only or sandboxed `cargo test` cannot do and no non-fuzz run needs.
#[test]
fn seed_corpus_written_from_catalog() {
    if std::env::var_os("RIPPY_WRITE_FUZZ_SEEDS").is_none() {
        return;
    }
    let root = repo_root();
    let commands = catalog_commands(&root.join("tests/data/catalog"));

    let seed_dir = root.join("fuzz/seeds/analyze");
    if seed_dir.exists() {
        std::fs::remove_dir_all(&seed_dir).expect("stale seed directory is removable");
    }
    std::fs::create_dir_all(&seed_dir).expect("seed directory is creatable");

    for command in &commands {
        std::fs::write(seed_dir.join(seed_name(command)), command).expect("seed file is writable");
    }

    let written: BTreeSet<String> = std::fs::read_dir(&seed_dir)
        .expect("seed directory is readable")
        .map(|e| std::fs::read_to_string(e.expect("dir entry").path()).expect("seed is readable"))
        .collect();
    assert_eq!(written, commands, "seed corpus does not round-trip");
}
