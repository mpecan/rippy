# rippy

[![Crates.io](https://img.shields.io/crates/v/rippy-cli.svg)](https://crates.io/crates/rippy-cli)
[![CI](https://github.com/mpecan/rippy/actions/workflows/ci.yml/badge.svg)](https://github.com/mpecan/rippy/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A fast shell command safety hook for AI coding tools — written in Rust.

rippy intercepts shell commands from **Claude Code**, **Cursor**, **Gemini CLI**, and **Codex CLI**, parses them with [rable](https://crates.io/crates/rable) (a pure-Rust bash parser), and automatically approves safe commands while blocking dangerous ones.

**Fully inspired by [Dippy](https://github.com/ldayton/Dippy) by [@ldayton](https://github.com/ldayton)** — rippy is a Rust rewrite with drop-in config compatibility, faster startup, and no runtime dependencies.

## Why rippy?

| | Dippy | rippy |
|---|---|---|
| Language | Python | Rust |
| Runtime | Python 3.9+, pip | Single static binary |
| Startup | ~200ms | <1ms |
| Parser | bash-parser (Parable) | [rable](https://crates.io/crates/rable) (pure Rust) |
| Config | `.dippy` | `.rippy` (reads `.dippy` too) |
| Handlers | ~50 commands | 100+ commands |
| File analysis | — | Reads `.py`, `.sql`, `.sh`, `.awk`, `.graphql` for informed decisions |
| CC permissions | — | Reads Claude Code `settings.json` allow/deny/ask rules |

## Install

### Homebrew (macOS/Linux)

```bash
brew install mpecan/tools/rippy
```

### Cargo

```bash
cargo install rippy-cli
```

### cargo-binstall (prebuilt binaries)

```bash
cargo binstall rippy-cli
```

### GitHub Releases

Download prebuilt binaries from [Releases](https://github.com/mpecan/rippy/releases) for:
- macOS (Apple Silicon, Intel)
- Linux (x86_64, aarch64)

## Quick Start

### Claude Code

Add to `~/.claude/settings.json` (or `.claude/settings.json` in your project):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "rippy --mode claude" }]
      }
    ]
  }
}
```

### Cursor

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "rippy --mode cursor" }]
      }
    ]
  }
}
```

### Gemini CLI

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{ "type": "command", "command": "rippy --mode gemini" }]
      }
    ]
  }
}
```

That's it. rippy reads JSON from stdin and returns a verdict on stdout. Your AI tool handles the rest.

## How It Works

```
stdin (JSON) → parse command → AST analysis → evaluate rules → verdict (JSON) → stdout
```

1. Reads a JSON hook payload from stdin
2. Detects the AI tool mode (or uses `--mode`)
3. Checks Claude Code permission rules (`settings.json` allow/deny/ask)
4. Checks user config rules (`.rippy` files)
5. Parses the command into an AST with [rable](https://crates.io/crates/rable)
6. Evaluates against built-in safety rules and 100+ CLI-specific handlers
7. For file-referencing commands (`python script.py`, `psql -f query.sql`, `bash script.sh`), reads and analyzes file contents
8. Returns a JSON verdict on stdout

**Exit codes:** `0` = allow, `2` = ask/deny, `1` = error

## What Gets Auto-Approved?

rippy has **130+ commands** in its safe allowlist (read-only tools like `cat`, `ls`, `grep`, `jq`, `rg`, etc.) plus **40+ CLI-specific handlers** that understand subcommand safety:

| Command | Safe | Needs approval |
|---------|------|----------------|
| `git` | `status`, `log`, `diff`, `branch` | `push`, `reset`, `rebase` |
| `docker` | `ps`, `images`, `logs` | `run`, `exec`, `rm` |
| `cargo` | `test`, `build`, `check`, `clippy` | `run`, `publish`, `install` |
| `python` | `-c 'print(1)'`, safe scripts | `-c 'import os'`, unknown scripts |
| `kubectl` | `get`, `describe`, `logs` | `apply`, `delete`, `exec` |
| `psql` | `-c 'SELECT ...'`, read-only `.sql` files | write SQL, interactive |
| `gh` | `pr view`, `issue list` | `pr create`, `pr merge` |
| `ansible` | `--check`, `--syntax-check`, `ansible-doc` | playbook runs, vault encrypt |

**Default for unknown commands: Ask** (fail-safe).

## Configuration

rippy loads config from three tiers (lowest to highest priority):

1. **Claude Code settings:** `~/.claude/settings.json` → `permissions.allow/deny/ask` rules
2. **Global config:** `~/.rippy/config` (or `~/.dippy/config`)
3. **Project config:** `.rippy` file walked up from cwd (or `.dippy`)
4. **Environment:** `RIPPY_CONFIG` or `DIPPY_CONFIG` env var

See [`examples/recommended.rippy`](examples/recommended.rippy) for a starter config covering macOS system tools, process management, network utilities, and more.

### Example config

```bash
# Block dangerous commands with guidance
deny rm -rf "use trash instead"
deny python "use uv run python"

# Allow specific safe patterns
allow git status
allow uv run python -c

# Redirect rules (block writes to sensitive paths)
deny-redirect **/.env*
deny-redirect /etc/*

# MCP tool rules
deny-mcp dangerous_tool

# Post-execution feedback
after git commit "committed successfully"

# Settings
set default ask
set log ~/.rippy/audit.log

# Aliases
alias ~/custom-git git
```

### Rule types

| Syntax | Description |
|--------|-------------|
| `allow\|ask\|deny PATTERN ["message"]` | Command rules |
| `allow-redirect\|ask-redirect\|deny-redirect PATH ["message"]` | Redirect rules |
| `after PATTERN "message"` | Post-execution feedback |
| `allow-mcp\|ask-mcp\|deny-mcp TOOL` | MCP tool rules |
| `set KEY VALUE` | Settings (`default`, `log`, `log-full`) |
| `alias SOURCE TARGET` | Command aliases |

### Pattern matching

- Default: **prefix matching** — `git` matches `git status`, `git push`, etc.
- `*` matches any characters, `?` matches one, `[abc]` character class, `**` globstar
- Trailing `|` forces **exact matching** — `git|` only matches bare `git`

## Migrating from Dippy

rippy reads `.dippy` config files and the `DIPPY_CONFIG` environment variable automatically. To migrate:

1. Install rippy
2. Replace `dippy` with `rippy --mode claude` in your hook config
3. Your existing `.dippy` config files work as-is

Optionally rename `.dippy` → `.rippy` and `~/.dippy/config` → `~/.rippy/config`.

## Integration with tokf

rippy works as a permission engine for [tokf](https://github.com/mpecan/tokf) (a CLI output compressor for LLM context). When paired together, tokf handles output compression while rippy handles permission decisions.

See [tokf's external permission engine docs](https://github.com/mpecan/tokf#external-permission-engine) for setup.

## Contributing

Contributions welcome! rippy follows these conventions:

- **Commits:** [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `test:`, etc.)
- **Quality:** `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test` must pass
- **Testing:** Every feature needs unit tests and integration tests
- **Limits:** 100-char lines, 60-line functions, cognitive complexity ≤ 15

## Acknowledgments

rippy is a Rust rewrite of [Dippy](https://github.com/ldayton/Dippy) by [@ldayton](https://github.com/ldayton). The original Python implementation pioneered the concept of AI tool command safety hooks. rippy maintains full config compatibility with Dippy.

The bash parser is [rable](https://crates.io/crates/rable), a pure-Rust parser with 100% [Parable](https://github.com/ldayton/Parable) test compatibility.

## License

MIT
