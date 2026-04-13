---
title: Cursor
description: Wire rippy into Cursor as a PreToolUse hook.
---

## One-line setup

```sh
rippy setup cursor
```

writes the hook stanza into Cursor's settings for you.

## Manual setup

[Cursor](https://cursor.sh)'s hook format mirrors Claude Code's. Add
rippy as a `PreToolUse` hook on the `Bash` tool:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "rippy --mode cursor" }
        ]
      }
    ]
  }
}
```

The only thing that changes between AI tools is the `--mode` flag — rippy
uses it to emit the verdict in the JSON shape that tool expects. All your
[`.rippy.toml` config files](/configuration/overview/) work across every
supported tool unchanged.
