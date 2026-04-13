---
title: Rules
description: The complete rule grammar for rippy config files.
---

Every line in a `.rippy` file is either a comment (`#`), a blank line, or
a **rule**. The TOML form wraps the same rules into `[[rules]]` tables —
the semantics are identical.

## Command rules

```
allow|ask|deny PATTERN ["message"]
```

- `allow` — auto-approve. rippy exits with code `0` and lets the command run.
- `ask` — prompt the AI tool to confirm with the user.
- `deny` — block and (optionally) return a guidance message explaining
  what the model should do instead.

Example:

```
allow git status
deny  git push --force "Use --force-with-lease instead"
ask   npm install "Double-check the package name before installing"
```

## Redirect rules

Guard writes to sensitive paths, independent of the command doing the
writing:

```
allow-redirect|ask-redirect|deny-redirect PATH ["message"]
```

Any command that writes to a matching path — `>`, `>>`, `tee`, `cp`, `mv`
— is caught:

```
deny-redirect **/.env*   "Do not write to environment files"
deny-redirect /etc/*     "Do not modify system config"
```

## MCP tool rules

For AI tools that use MCP (Model Context Protocol) servers, gate individual
MCP tools by name:

```
allow-mcp mcp__github__*
deny-mcp  dangerous_mcp_tool
```

## Post-execution feedback

`after` rules inject a message back to the AI tool after a command runs —
useful for reminders and workflow nudges:

```
after git commit "Changes committed locally. Don't forget to push when ready."
```

## Aliases

Rewrite a command to something rippy already knows how to analyze:

```
alias ~/bin/custom-git git
```

Now rules targeting `git` apply to `~/bin/custom-git` too.

## Settings

```
set default ask         # default action for unknown commands (allow | ask | deny)
set log ~/.rippy/audit  # path to the audit log
set log-full true       # include full command strings in the log
```

## Putting it together

A minimal but effective config:

```
# Block the really dangerous stuff
deny rm -rf /     "Never delete the root filesystem"
deny rm -rf ~     "Never delete the home directory"
deny git push --force "Use --force-with-lease instead"

# Auto-allow read-only git
allow git status
allow git log
allow git diff

# Keep secrets out of writes
deny-redirect **/.env*
deny-redirect **/*.pem

# Default everything else to ask
set default ask
```

See [Examples](/configuration/examples/) for a longer, annotated starter.
