# rippy fuzz targets

Coverage-guided fuzzing for rippy. This crate is its own workspace root and is
excluded from the published package, so `cargo test` and
`cargo clippy --all-targets` at the repo root never build it and never need
nightly.

Invariants, known gaps and crash triage: [`../docs/fuzzing.md`](../docs/fuzzing.md).

## Targets

- **`analyze`** — robustness. `Analyzer::analyze` must not panic or hang on any
  UTF-8 input. Seed corpus is generated from every command in
  `tests/data/catalog/*.toml`.
- **`metamorphic`** — the "never fail open" invariants. libfuzzer steers a byte
  decoder that produces command specs from the shared grammar in
  `tests/metamorphic/`, the same harness the proptests use.

## Running

```sh
cargo install cargo-fuzz
cd ..
cargo test --test fuzz_seeds     # writes fuzz/seeds/analyze/
cargo +nightly fuzz run analyze fuzz/corpus/analyze fuzz/seeds/analyze -- -max_total_time=300
cargo +nightly fuzz run metamorphic -- -max_total_time=300
```

`rust-toolchain.toml` pins stable 1.93, so `+nightly` (or
`RUSTUP_TOOLCHAIN=nightly`) is required. Add `--sanitizer none` if the ASan
build of rusqlite's bundled SQLite fails — the oracle here is panics and hangs,
not memory errors.

Crashes land in `fuzz/artifacts/<target>/`; replay one with
`cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<file>`.

`corpus/`, `seeds/` and `artifacts/` are gitignored: the seed corpus is
regenerated from the catalog rather than committed, so adding catalog cases
never produces a corpus diff.
