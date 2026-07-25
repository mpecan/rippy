# CLAUDE.md — rippy

## Constitution

1. **Transparent in all** — users know exactly what gets approved or blocked. Rules are predictable, diagnostics are clear, defaults are documented.
2. **Simplicity is king** — solve the problem with the least complexity. No premature abstractions, no over-engineering.
3. **If it is not tested, it is not shipped** — every feature has unit tests and integration tests. No exceptions.
4. **Correctness over speed** — use rable for bash AST parsing, never hand-roll a shell parser. Get the right answer first.
5. **User first** — sensible defaults, zero-config experience, clear error messages.
6. **No gatekeeping** — contributions of all kinds are welcome. Keep the codebase approachable.

## Project overview

`rippy` is a shell command safety hook for AI coding tools (Claude Code, Cursor, Gemini CLI). It reads tool-use JSON from stdin, parses the shell command with rable (a standalone bash AST parser), evaluates it against safety rules, and returns a verdict (approve, block, or deny-redirect). It is a Rust rewrite of [Dippy](https://github.com/ldayton/Dippy).

- **Binary:** `rippy` (crate name is `rippy-cli` on crates.io)
- **Config:** `~/.rippy/config.toml` (global) and `.rippy.toml` (project-level override). Legacy flat `.rippy` / `.dippy` files are still read for backward compatibility; new configs should prefer TOML.
- **Input:** JSON on stdin (tool-use hook payload)
- **Output:** JSON on stdout (hook verdict), exit code 0 (approve) / 2 (block)

## Architecture

| Module | Role |
|---|---|
| `src/main.rs` | Entry point, stdin reading, JSON I/O, exit codes |
| `src/lib.rs` | Library re-exports |
| `src/cli.rs` | CLI argument parsing (clap) |
| `src/config.rs` | Config file loading and merging (global + project) |
| `src/pattern.rs` | Glob-style pattern matching for config rules |
| `src/parser.rs` | rable bash AST parsing |
| `src/ast.rs` | AST node helpers (command name/args/redirects extraction) |
| `src/analyzer.rs` | Recursive AST walker: Tree + Config + Handlers → Verdict |
| `src/allowlists.rs` | SIMPLE_SAFE (~200 cmds) and WRAPPER_COMMANDS sets |
| `src/handlers/` | 85+ CLI-specific command handlers (git, docker, etc.) |
| `src/payload.rs` | JSON input deserialization (4 AI tool formats) |
| `src/verdict.rs` | Decision (Allow/Ask/Deny), per-mode JSON serialization |
| `src/allow_reason.rs` | Typed Allow provenance (`AllowReason`) + `Display` that reproduces the wire strings |
| `src/mode.rs` | Mode (Claude/Gemini/Cursor/Codex) and HookType enums |
| `src/error.rs` | RippyError via thiserror |
| `src/sql.rs` | SQL read-only classifier for database handlers |
| `tests/` | Integration tests |

### Command flow

1. Read JSON from stdin (hook payload from AI tool)
2. Detect mode (Claude Code / Cursor / Gemini) from payload or CLI flags
3. Extract the shell command string
4. Parse with rable into a bash AST
5. Load config (global `~/.rippy/config.toml` merged with project `.rippy.toml`; legacy flat files still accepted)
6. Evaluate rules against the parsed AST
7. Return JSON verdict on stdout

## Code standards

### Enforced limits

| Limit | Value | Enforced by |
|---|---|---|
| Line width | 100 chars | `.rustfmt.toml` |
| Function length | 60 lines | `clippy.toml` |
| Cognitive complexity | 15 | `clippy.toml` |
| Function arguments | 5 | `clippy.toml` |

### Clippy rules (`Cargo.toml`)

- **Denied:** `unwrap_used`, `expect_used`, `panic`, `todo`
- **Warned:** `pedantic`, `nursery` groups
- **Allowed:** `module_name_repetitions`, `must_use_candidate`

Use `#[allow(...)]` only in test code. Prefer returning `Result` or using pattern matching over unwrapping.

### Formatting

- `rustfmt` with `max_width = 100`, edition 2024
- Run `cargo fmt` before committing

### Comment style

Enforced by `cargo-lint-extra` (`.cargo-lint-extra.toml`, run as `cargo lint-extra` in CI).

- Document public items and non-obvious **why**; never restate the **what** the code already says.
- No step-narration (`// now loop over the args`) and no comments that echo a self-named call.
- No decorative banner dividers (`// ---- foo ----`, `// ==== Config ====`, box-drawing rules).
- Skip `///` doc stubs on trivial private one-liners.
- Keep inline comments under ~30% of a function's lines; break up or delete dense blocks.
- Deep rationale (security invariants, attack models, parser hazards) goes in a short `docs/`
  file (e.g. `docs/security-invariants.md`) with a terse inline pointer
  (`// see docs/security-invariants.md#dynamic-arg`), not a wall of inline text.
- Files stay under the 700-line hard cap; split oversized modules into sibling files.

### Before every change

```sh
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
cargo lint-extra
```

All four must pass clean.

## Conventions

### Commits

Use [Conventional Commits](https://www.conventionalcommits.org/): `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `ci`, `perf`. One logical change per commit.

### Error handling

- No `.unwrap()` or `.expect()` in production code (Clippy denies these)
- Use `Result` propagation or graceful fallbacks
- Use `thiserror` for custom error types

### Test organization

- Unit tests: `#[cfg(test)]` module in the source file
- Test modules use `#[allow(clippy::unwrap_used)]`
- Integration tests in `tests/`
- **Handler behavior belongs in the data-driven catalog.** Prefer a
  `command -> decision` case in `tests/data/catalog/*.toml` over a white-box
  `handler.classify(&HandlerContext{..})` unit test. Catalog cases run the real
  parse+analyze pipeline (`build.rs` generates one `#[test]` per TOML entry;
  `tests/catalog_runner.rs` asserts `verdict.decision`), so they test the actual
  user-facing verdict and are immune to `HandlerContext` struct refactors. New
  handlers add catalog cases first.
- **Reserve white-box `HandlerContext` tests for what a command string cannot
  reach:** internal helpers, and behavior that depends on injected state —
  `working_directory`/cwd-relative resolution, `remote = true`, non-empty
  `safe_scopes`, and real-file `read_file` content (script/SQL/workflow files).
  Route these through `HandlerContext::test(name, &args)` with struct-update
  overrides for the non-default fields.
- **Author every catalog case from OBSERVED analyzer output, never from memory.**
  The full pipeline can differ from a handler's raw `Classification` (a catch-all
  config rule may Ask over a handler Allow; the shell parser may mangle an
  arg such as `-f query={...}`; redirects/pipelines change the verdict). Run the
  candidate through `isolated_analyzer()` and use its `Decision` as ground truth;
  when it diverges from the handler variant, keep the white-box test. This is a
  security tool — a mis-transcribed `decision = "allow"` silently passes while
  asserting the wrong thing, so keep contrast pairs and never migrate an
  `ask`/`deny` case you have not observed.
- **Assert Allow provenance by category, not by reason substring.** Use
  `Verdict::allow_reason()` and match the `AllowReason` variant
  (`tests/allow_provenance.rs`). Reason strings themselves are pinned wholesale
  by `tests/data/reason_snapshot.txt` — they are part of the JSON hook output,
  so a change there is a wire-format change and must be deliberate.
- Property-based tests in `tests/proptest_robustness.rs` — proptest covers
  the four parsing/analysis surfaces (`Payload::parse`, `BashParser` +
  `Analyzer`, `Pattern::matches`, `Config::load_from_str`) against random
  input. They run as part of `cargo test`. Failures auto-persist to
  `proptest-regressions/` and should be committed as permanent regression seeds.
