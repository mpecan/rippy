---
title: Configuration overview
description: Where rippy looks for config files, how the tiers are merged, and where Claude Code settings fit in.
---

The easiest way to get started is with a [package](/getting-started/packages/) —
`rippy init` will walk you through picking one. For full control, rippy
loads config from five tiers, merged in ascending priority:

1. **Built-in stdlib** — the safe allowlist + 100+ CLI handlers compiled
   into the binary. Always active.
2. **Package** — if your config has `package = "develop"` (or `"review"` /
   `"autopilot"`) in its `[settings]` block, the matching package TOML is
   loaded from the binary as a baseline.
3. **Global config** — `~/.rippy/config.toml` (or `~/.rippy/config` for
   the legacy plain-text form). Also reads `~/.dippy/config` for
   backward compatibility.
4. **Project config** — a `.rippy.toml` or `.rippy` file walked up from
   the current directory. `.dippy` is also accepted.
5. **Environment override** — the `RIPPY_CONFIG` env var (or
   `DIPPY_CONFIG`) can point at a config file explicitly.

Higher tiers override lower tiers. Within a tier, earlier rules take
precedence over later ones.

## Claude Code settings are a separate pre-analysis step

Independently of the tiers above, rippy checks
`~/.claude/settings.json` → `permissions.allow` / `permissions.deny` /
`permissions.ask` rules **before** running its own config evaluation.
That means Claude Code's own permission rules act as a fast-path filter
on top of rippy's config, not as another config tier. If a command is
already covered by a Claude Code `allow` or `deny` rule, rippy respects
that decision and skips its own analysis.

You do not need to duplicate Claude Code rules into `.rippy.toml`.

## Two file formats

rippy accepts either:

- A **TOML `.rippy.toml`** file — the structured format with explicit
  `[[rules]]` tables. Recommended for new configs.
- A **plain-text `.rippy`** file — the legacy Dippy format, one rule per
  line. Still fully supported; run `rippy migrate` to convert it to
  TOML.

Both formats support the same rule types. See
[Example configs](/configuration/examples/) for ready-to-copy starters.

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

- [Packages](/getting-started/packages/) — the `review` / `develop` /
  `autopilot` profiles.
- [Rules](/configuration/rules/) — the rule grammar (`allow`, `deny`,
  `ask`, `redirect`, `mcp`, `alias`, `after`, `set`).
- [Patterns](/configuration/patterns/) — prefix, glob, and exact matching.
- [Examples](/configuration/examples/) — annotated starter configs.
