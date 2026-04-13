---
title: Configuration overview
description: Where rippy looks for config files and how they are merged.
---

rippy loads config from four tiers, merged in ascending priority:

1. **Claude Code settings** — `~/.claude/settings.json` →
   `permissions.allow`, `permissions.deny`, `permissions.ask` rules.
2. **Global rippy config** — `~/.rippy/config` (or `~/.rippy/config.toml`).
   Also reads `~/.dippy/config` for backward compatibility.
3. **Project config** — a `.rippy` or `.rippy.toml` file walked up from
   the current directory. `.dippy` is also accepted.
4. **Environment override** — the `RIPPY_CONFIG` env var (or
   `DIPPY_CONFIG`) can point at a config file explicitly.

Higher tiers override lower tiers. Within a tier, earlier rules take
precedence over later ones.

## Two file formats

rippy accepts either:

- A **plain-text `.rippy`** file, the Dippy format — one rule per line.
- A **TOML `.rippy.toml`** file, the structured format with explicit
  `[[rules]]` tables.

Both formats support the same rule types. Use whichever reads better to
you — [`examples/recommended.rippy.toml`](https://github.com/mpecan/rippy/blob/main/examples/recommended.rippy.toml)
ships in the repo as a starter.

## Project config trust

Project-level config files can weaken protections (imagine a cloned repo
with `allow rm -rf /` in its `.rippy`). rippy uses a trust model:

- **Untrusted by default** — unknown project configs are ignored until you
  run `rippy trust` in that directory.
- **Repo-level trust** — once you trust a repo, config changes pulled via
  `git` stay trusted.
- **Hash verification** — edits made outside git revoke trust automatically.
- **AI tools cannot self-trust** — rippy rejects attempts by its own hook
  callers to write to the trust database.

You can opt out globally with `trust-project-configs = true` in
`~/.rippy/config.toml`, but the safe default is to stay cautious.

## Where to go next

- [Rules](/configuration/rules/) — the rule grammar (`allow`, `deny`,
  `ask`, `redirect`, `mcp`, `alias`, `after`, `set`).
- [Patterns](/configuration/patterns/) — prefix, glob, and exact matching.
- [Examples](/configuration/examples/) — annotated starter configs.
