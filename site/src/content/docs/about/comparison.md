---
title: Comparison with Dippy
description: How rippy relates to — and differs from — the original Dippy project.
---

rippy is **fully inspired by** and a **Rust rewrite of**
[Dippy](https://github.com/ldayton/Dippy) by
[@ldayton](https://github.com/ldayton). Dippy pioneered the idea of a
command safety hook for AI coding tools; rippy ports the idea to Rust,
adds a few capabilities, and keeps config compatibility so you can switch
without rewriting anything.

## Side by side

|  | Dippy | rippy |
|---|---|---|
| **Language** | Python | Rust |
| **Runtime** | Python 3.9+, `pip` | Single static binary |
| **Startup** | ~200 ms | < 1 ms |
| **Parser** | `bash-parser` (Parable) | [rable](https://crates.io/crates/rable), pure Rust |
| **Config files** | `.dippy` | `.rippy` **and** `.dippy` (both work) |
| **Handlers** | ~50 commands | 100+ commands |
| **File analysis** | — | Reads `.py`, `.sql`, `.sh`, `.awk`, `.graphql` for informed decisions |
| **Claude Code permission integration** | — | Reads `~/.claude/settings.json` `allow/deny/ask` rules |

## Migrating from Dippy

rippy reads `.dippy` config files and the `DIPPY_CONFIG` environment
variable out of the box. The full migration is three steps:

1. [Install rippy](/getting-started/installation/).
2. Replace `dippy` with `rippy --mode claude` (or `--mode cursor`,
   `--mode gemini`, `--mode codex`) in your hook config.
3. Done. Your existing `.dippy` config keeps working.

Renaming `.dippy` → `.rippy` and `~/.dippy/config` → `~/.rippy/config` is
optional — rippy accepts both paths indefinitely.

## Why a rewrite?

A 200ms cold start is fine for a one-off tool, but it adds up fast when
you run a hook before **every** `Bash` call in an AI coding session. A
sub-millisecond static binary disappears into the background — you stop
thinking about whether to turn the hook off "because it's slow".

The rewrite was also a chance to:

- Build on [rable](https://crates.io/crates/rable), a properly typed
  pure-Rust bash parser, instead of shelling out to a JavaScript bash
  parser.
- Add file-content analysis for scripts, which is much easier to do
  safely with a compiled language and a real AST.
- Integrate with Claude Code's own permission rules so you don't have to
  maintain the same allow/deny list in two places.

The **ideas**, though, are all Dippy's. Huge thanks to
[@ldayton](https://github.com/ldayton) for shipping the original and
making the concept real.
