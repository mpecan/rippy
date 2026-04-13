---
title: CLI commands
description: Every subcommand rippy ships with, grouped by what it's for.
---

Most of the time you'll invoke rippy as a hook — `rippy --mode claude` or
similar — and the rest of the machinery is invisible. But rippy also has a
handful of subcommands for setting up, inspecting, and evolving your
config. Here's the full list.

## Running as a hook

| Command | Description |
|---------|-------------|
| `rippy --mode claude` | Run as a Claude Code `PreToolUse` hook (reads JSON from stdin, returns verdict on stdout) |
| `rippy --mode cursor` | Run as a [Cursor](/getting-started/cursor/) hook |
| `rippy --mode gemini` | Run as a [Gemini CLI](/getting-started/gemini-cli/) hook |
| `rippy --mode codex` | Run as a [Codex CLI](/getting-started/codex/) hook |

## Setup

| Command | Description |
|---------|-------------|
| `rippy init` | Initialize config with interactive package selection |
| `rippy init --package <name>` | Initialize with a specific [package](/getting-started/packages/) (`review`, `develop`, `autopilot`) |
| `rippy setup claude-code` | Install rippy as a hook for Claude Code |
| `rippy setup gemini` | Install rippy as a hook for Gemini CLI |
| `rippy setup cursor` | Install rippy as a hook for Cursor |
| `rippy setup tokf` | Configure [tokf](https://github.com/mpecan/tokf) to use rippy as its permission engine |

## Packages and profiles

| Command | Description |
|---------|-------------|
| `rippy profile list` | List available safety packages |
| `rippy profile show <name>` | Show what a package auto-approves, asks, and blocks |
| `rippy profile set <name>` | Activate a safety package |

## Inspect and debug

| Command | Description |
|---------|-------------|
| `rippy inspect` | Show all configured rules |
| `rippy inspect <command>` | Trace the decision rippy would make for a specific command |
| `rippy debug <command>` | Trace the full decision path (every rule considered) for a command |
| `rippy list safe` | List all auto-approved safe commands |
| `rippy list handlers` | List commands with dedicated handlers |
| `rippy list rules` | Show effective rules merged from all config sources |
| `rippy stats` | Show aggregate decision-tracking statistics |

## Evolve your config

| Command | Description |
|---------|-------------|
| `rippy allow <pattern>` | Add an `allow` rule to your config |
| `rippy deny <pattern>` | Add a `deny` rule to your config |
| `rippy ask <pattern>` | Add an `ask` rule to your config |
| `rippy suggest` | Analyze your tracking data and suggest new rules |
| `rippy discover <cmd>` | Discover flag aliases from a command's help output |
| `rippy migrate` | Convert a legacy `.rippy` plain-text config to `.rippy.toml` |

## Trust and safety

| Command | Description |
|---------|-------------|
| `rippy trust` | Manage trust for project-level config files (see [Configuration overview → Project config trust](/configuration/overview/#project-config-trust)) |

## Tips

- `rippy inspect <command>` is the fastest way to answer "why did rippy
  block / approve / ask about this?" — it reports which rule fired and
  which config file it came from.
- `rippy suggest` pairs well with `rippy stats`: let rippy watch your
  sessions for a while, then ask it which rules would have saved you
  approval prompts.
- `rippy migrate` is a one-shot converter for the legacy plain-text
  `.rippy` / `.dippy` format — the TOML form is preferred for new configs
  but the flat format stays supported for compatibility.
