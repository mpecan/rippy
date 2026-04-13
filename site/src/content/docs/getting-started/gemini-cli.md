---
title: Gemini CLI
description: Wire rippy into Google's Gemini CLI as a PreToolUse hook.
---

[Gemini CLI](https://github.com/google-gemini/gemini-cli) supports the same
`PreToolUse` hook shape. Use `--mode gemini` so rippy formats verdicts the
way Gemini expects:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "rippy --mode gemini" }
        ]
      }
    ]
  }
}
```

All [`.rippy` config rules](/configuration/overview/) apply identically
across Claude Code, Cursor, and Gemini CLI — the mode flag only controls
output formatting.
