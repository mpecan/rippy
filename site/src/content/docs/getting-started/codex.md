---
title: Codex CLI
description: Wire rippy into Codex CLI as a PreToolUse hook.
---

rippy supports [Codex CLI](https://github.com/openai/codex) via
`--mode codex`. The hook setup follows the same pattern as the other tools:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "rippy --mode codex" }
        ]
      }
    ]
  }
}
```

Configuration files, safety rules, and handlers are shared across every
mode — see [Configuration overview](/configuration/overview/) to write
rules once and have them apply everywhere.
