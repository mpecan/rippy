# CLAUDE.md — rippy

## Constitution

1. **Transparent in all** — users know exactly what gets approved or blocked. Rules are predictable, diagnostics are clear, defaults are documented.
2. **Simplicity is king** — solve the problem with the least complexity. No premature abstractions, no over-engineering.
3. **If it is not tested, it is not shipped** — every feature has unit tests and integration tests. No exceptions.
4. **Correctness over speed** — use tree-sitter-bash for parsing, never hand-roll a shell parser. Get the right answer first.
5. **User first** — sensible defaults, zero-config experience, clear error messages.
6. **No gatekeeping** — contributions of all kinds are welcome. Keep the codebase approachable.

## Project overview

`rippy` is a shell command safety hook for AI coding tools (Claude Code, Cursor, Gemini CLI). It reads tool-use JSON from stdin, parses the shell command with tree-sitter-bash, evaluates it against safety rules, and returns a verdict (approve, block, or deny-redirect). It is a Rust rewrite of [Dippy](https://github.com/ldayton/Dippy).

- **Binary:** `rppy` (crate name is `rippy`, binary is `rppy` to avoid crates.io conflict)
- **Config:** `~/.rippy/config` (global) and `.rippy` (project-level override)
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
| `src/parser.rs` | tree-sitter-bash command parsing |
| `src/ast.rs` | AST node helpers (command name/args/redirects extraction) |
| `src/analyzer.rs` | Recursive AST walker: Tree + Config + Handlers → Verdict |
| `src/allowlists.rs` | SIMPLE_SAFE (~200 cmds) and WRAPPER_COMMANDS sets |
| `src/handlers/` | 85+ CLI-specific command handlers (git, docker, etc.) |
| `src/payload.rs` | JSON input deserialization (4 AI tool formats) |
| `src/verdict.rs` | Decision (Allow/Ask/Deny), per-mode JSON serialization |
| `src/mode.rs` | Mode (Claude/Gemini/Cursor/Codex) and HookType enums |
| `src/error.rs` | RippyError via thiserror |
| `src/sql.rs` | SQL read-only classifier for database handlers |
| `tests/` | Integration tests |

### Command flow

1. Read JSON from stdin (hook payload from AI tool)
2. Detect mode (Claude Code / Cursor / Gemini) from payload or CLI flags
3. Extract the shell command string
4. Parse with tree-sitter-bash into an AST
5. Load config (global `~/.rippy/config` merged with project `.rippy`)
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

### Before every change

```sh
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
```

All three must pass clean.

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
