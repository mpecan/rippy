# rippy

A fast shell command safety hook for AI coding tools — written in Rust.

rippy intercepts shell commands from **Claude Code**, **Cursor**, **Gemini CLI**, and **Codex CLI**, parses them with [tree-sitter-bash](https://github.com/tree-sitter/tree-sitter-bash), and automatically approves safe commands while blocking dangerous ones. It is a Rust rewrite of [Dippy](https://github.com/ldayton/Dippy) with drop-in config compatibility.

## Why rippy?

- **Single static binary** — no Python runtime, no pip, no virtualenv
- **Fast startup** — Rust binary, sub-millisecond overhead per command
- **Structural parsing** — tree-sitter AST analysis, not regex matching
- **100+ commands handled** — deep knowledge of git, docker, kubectl, aws, and more
- **Drop-in compatible** — reads `.dippy` configs and `DIPPY_CONFIG` env var
- **4 AI tool modes** — Claude Code, Cursor, Gemini CLI, Codex CLI

## Quick Start

### Install

```bash
cargo install rippy
```

Or with [cargo-binstall](https://github.com/cargo-bins/cargo-binstall):

```bash
cargo binstall rippy
```

### Configure Claude Code

Add to `~/.claude/settings.json`:

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

### Configure Cursor

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

### Configure Gemini CLI

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

## How It Works

```
stdin (JSON) → parse command → tree-sitter AST → evaluate rules → verdict (JSON) → stdout
```

1. Reads a JSON hook payload from stdin
2. Detects the AI tool mode (or uses `--mode`)
3. Extracts the shell command string
4. Parses it into an AST with tree-sitter-bash
5. Evaluates against built-in safety rules, CLI handlers, and user config
6. Returns a JSON verdict on stdout

**Exit codes:** `0` = allow, `2` = ask/deny, `1` = error

## Configuration

rippy loads config from three tiers (lowest to highest priority):

1. **Global:** `~/.rippy/config` (or `~/.dippy/config`)
2. **Project:** `.rippy` file walked up from cwd (or `.dippy`)
3. **Environment:** `RIPPY_CONFIG` or `DIPPY_CONFIG` env var

### Example config

```bash
# Block dangerous commands with guidance
deny rm -rf "use trash instead"
deny python "Use uv run python"

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
- Trailing `|` forces **exact matching** — `git|` only matches `git`

## What gets auto-approved?

rippy has 130+ commands in its safe allowlist (read-only tools like `cat`, `ls`, `grep`, `git status`, `kubectl get`, etc.) plus 40+ CLI-specific handlers that understand subcommand safety (e.g., `git log` is safe but `git push` needs approval).

**Default for unknown commands: Ask** (fail-safe).

## Migrating from Dippy

rippy reads `.dippy` config files and the `DIPPY_CONFIG` environment variable automatically. To migrate:

1. Install rippy
2. Replace `dippy` with `rippy --mode claude` in your hook config
3. Your existing `.dippy` config files work as-is

Optionally rename `.dippy` to `.rippy` and `~/.dippy/config` to `~/.rippy/config`.

## License

MIT
