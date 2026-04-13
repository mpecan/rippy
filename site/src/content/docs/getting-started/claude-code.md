---
title: Claude Code
description: Wire rippy into Claude Code as a PreToolUse hook.
---

rippy plugs into [Claude Code](https://www.anthropic.com/claude-code) as a
`PreToolUse` hook on the `Bash` tool. Every shell command Claude Code wants
to run is piped to rippy first; rippy approves, asks, or blocks.

## One-line setup

The fastest path is to let rippy edit `settings.json` for you:

```sh
rippy setup claude-code
```

That's it — rippy writes the hook stanza into `~/.claude/settings.json`.
Run it from inside a repo to install the hook at the project level
instead of globally.

## Manual setup

If you prefer to edit `settings.json` by hand, add this block to
`~/.claude/settings.json` (or `.claude/settings.json` inside a repo for
project-scoped setup):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "rippy --mode claude" }
        ]
      }
    ]
  }
}
```

## What happens on each call

1. Claude Code serializes the `Bash` tool-use payload to JSON and pipes it
   to `rippy`.
2. rippy first checks Claude Code's own
   `permissions.allow` / `permissions.deny` / `permissions.ask` rules in
   `~/.claude/settings.json` as a **pre-analysis step**.
3. If nothing matches there, rippy parses the command into an AST,
   consults your [`.rippy.toml` config](/configuration/overview/), and
   applies its [safety model](/reference/safety-model/).
4. rippy prints a JSON verdict on stdout. Exit code `0` means **allow**,
   `2` means **ask / deny**, `1` means an internal error (rippy fails
   open on internal errors — see the [FAQ](/about/faq/)).

## Claude Code permissions are honored automatically

You do **not** need to duplicate Claude Code's `permissions.allow` /
`permissions.deny` / `permissions.ask` rules into your `.rippy.toml`.
rippy reads them directly from `~/.claude/settings.json` as a separate
pre-analysis step. Edit them in one place, keep both rippy and Claude
Code in sync automatically.
