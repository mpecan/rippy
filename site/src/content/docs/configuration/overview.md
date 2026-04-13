---
title: Configuration overview
description: Where rippy looks for config files, how the tiers are merged, and where Claude Code settings fit in.
---

The easiest way to get started is with a [package](/getting-started/packages/) —
`rippy init` will walk you through picking one and drop a
`.rippy.toml` in your home directory. For full control, rippy loads
config from five tiers, merged in ascending priority:

1. **Built-in stdlib** — the safe allowlist + 100+ CLI handlers compiled
   into the binary. Always active.
2. **Package** — if your config has `package = "develop"` (or `"review"` /
   `"autopilot"`) in its `[settings]` block, the matching package TOML is
   loaded from the binary as a baseline.
3. **Global config** — `~/.rippy/config.toml`. (Falls back to
   `~/.rippy/config` or `~/.dippy/config` in the legacy flat format for
   backward compatibility.)
4. **Project config** — a `.rippy.toml` file walked up from the current
   directory. (Falls back to `.rippy` or `.dippy` in the flat format.)
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

## Config format: prefer `.rippy.toml`

Write new configs as `.rippy.toml`. TOML is where new features land —
every command, redirect, MCP, and `after` rule is a `[[rules]]` table,
aliases go in `[[aliases]]`, settings go in `[settings]`, and
[structured matching](/configuration/rules/#structured-matching)
(`command` / `subcommand` / `flags` / `args-contain`) is TOML-only. The
CLI reflects this: `rippy init`, `rippy allow`, `rippy deny`, and
`rippy ask` all write to `.rippy.toml`.

```toml
[settings]
default = "ask"
package = "develop"

[[rules]]
action = "deny"
pattern = "git push --force"
message = "Use --force-with-lease instead"
```

The legacy **flat `.rippy` / `.dippy` format** (one rule per line, a
carry-over from [Dippy](https://github.com/ldayton/Dippy)) is still
loaded so existing configs keep working unchanged, but it doesn't
support structured matching and won't see new features. Run
`rippy migrate` to convert a flat file to `.rippy.toml` in one shot.

See [Rules](/configuration/rules/) for the full grammar and
[Examples](/configuration/examples/) for ready-to-copy starter configs.

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
