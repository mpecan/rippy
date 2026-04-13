---
title: Claude Code
description: Wire rippy into Claude Code as a PreToolUse hook.
---

rippy plugs into [Claude Code](https://www.anthropic.com/claude-code) as a
`PreToolUse` hook on the `Bash` tool. Every shell command Claude Code wants
to run is piped to rippy first; rippy approves, asks, or blocks.

## Global setup

Add the hook to `~/.claude/settings.json`:

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

## Project-scoped setup

Drop the same block into `.claude/settings.json` inside a repository to
override the global hook for that project only.

## What happens on each call

1. Claude Code serializes the `Bash` tool-use payload to JSON and pipes it
   to `rippy`.
2. rippy parses the command string into an AST, consults your
   [`.rippy` config](/configuration/overview/) and Claude Code's own
   `permissions.allow/deny/ask` rules, and applies its
   [safety model](/reference/safety-model/).
3. rippy prints a JSON verdict on stdout. Exit code `0` means **allow**,
   `2` means **ask / deny**, `1` means an internal error (rippy
   fails open on internal errors — see the FAQ).

## Reading Claude Code permission rules

rippy reads `permissions.allow`, `permissions.deny`, and `permissions.ask`
from `~/.claude/settings.json` automatically — you do not need to duplicate
them into `.rippy`. This lets rippy act as a drop-in enforcer for rules you
already maintain in your Claude Code settings.
