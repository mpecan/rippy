---
title: Rules
description: The complete rule grammar for rippy config files.
---

rippy configs are TOML files. A `.rippy.toml` is a list of `[[rules]]`
tables plus an optional `[settings]` block:

```toml
[settings]
default = "ask"

[[rules]]
action = "deny"
pattern = "git push --force"
message = "Use --force-with-lease instead"
```

Every rule type described below is written the same way: one `[[rules]]`
table with an `action`, a `pattern`, and an optional `message`. Extra
fields (`risk`, structured matchers) are noted where they apply.

:::tip[TOML is the preferred format]
`.rippy.toml` is the recommended format for all new configs. It's
structured, validates cleanly, round-trips through `rippy allow`/`deny`/
`ask`, and supports richer matching (per-arg matchers, risk levels). The
legacy flat `.rippy` / `.dippy` format is still read for
backward-compatibility — see [Legacy flat format](#legacy-flat-format)
at the bottom of this page — but `rippy migrate` will convert it for you
and new documentation targets TOML exclusively.
:::

## Command rules

Match a command by its name and arguments and decide what to do with it:

```toml
[[rules]]
action = "allow"        # "allow" | "ask" | "deny"
pattern = "git status"
message = "optional guidance shown on deny"
```

- `allow` — auto-approve. rippy exits with code `0` and lets the command run.
- `ask` — prompt the AI tool to confirm with the user.
- `deny` — block and (optionally) return a `message` explaining
  what the model should do instead.

A fuller example:

```toml
[[rules]]
action = "allow"
pattern = "git status"

[[rules]]
action = "deny"
pattern = "git push --force"
message = "Use --force-with-lease instead"

[[rules]]
action = "ask"
pattern = "npm install"
message = "Double-check the package name before installing"
```

### Structured matching

Instead of a single `pattern` string, command rules can match on the
command name, subcommand, flags, and argument content as separate
fields. This is the safest way to pin a rule to a specific subcommand
without relying on prefix tricks:

```toml
[[rules]]
action = "deny"
command = "git"
subcommand = "push"
flags = ["--force"]
message = "Use --force-with-lease instead"
```

Supported fields (all optional, combined with AND):

- `command` — the command name (e.g. `"git"`, `"docker"`)
- `subcommand` — a single subcommand, or `subcommands` for a list
  (e.g. `["push", "reset"]`)
- `flags` — required flags (e.g. `["--force"]`)
- `args-contain` — match rules where any argument contains this string

Structured matching is TOML-only; the flat format has no equivalent.
See [Patterns](/configuration/patterns/) for the pattern grammar.

## Redirect rules

Guard writes to sensitive paths, independent of the command doing the
writing. Any command that writes to a matching path — `>`, `>>`, `tee`,
`cp`, `mv` — is caught:

```toml
[[rules]]
action = "deny-redirect"
pattern = "**/.env*"
message = "Do not write to environment files"

[[rules]]
action = "deny-redirect"
pattern = "/etc/*"
message = "Do not modify system config"
```

Valid actions: `allow-redirect`, `ask-redirect`, `deny-redirect`.

## MCP tool rules

For AI tools that use MCP (Model Context Protocol) servers, gate
individual MCP tools by name:

```toml
[[rules]]
action = "allow-mcp"
pattern = "mcp__github__*"

[[rules]]
action = "deny-mcp"
pattern = "dangerous_mcp_tool"
```

Valid actions: `allow-mcp`, `ask-mcp`, `deny-mcp`.

## Post-execution feedback

`after` rules inject a message back to the AI tool after a command runs —
useful for reminders and workflow nudges:

```toml
[[rules]]
action = "after"
pattern = "git commit"
message = "Changes committed locally. Don't forget to push when ready."
```

## Aliases

Rewrite a command to something rippy already knows how to analyze. Use
a top-level `[[aliases]]` table:

```toml
[[aliases]]
source = "~/bin/custom-git"
target = "git"
```

Now rules targeting `git` apply to `~/bin/custom-git` too.

## Settings

All settings live in a single `[settings]` block at the top of the file:

```toml
[settings]
default = "ask"          # default action for unknown commands (allow | ask | deny)
log = "~/.rippy/audit"   # path to the audit log
log-full = true          # include full command strings in the log
package = "develop"      # start from a safety package baseline
```

## Putting it together

A minimal but effective `.rippy.toml`:

```toml
[settings]
default = "ask"

# Block the really dangerous stuff
[[rules]]
action = "deny"
pattern = "rm -rf /"
message = "Never delete the root filesystem"

[[rules]]
action = "deny"
pattern = "rm -rf ~"
message = "Never delete the home directory"

[[rules]]
action = "deny"
pattern = "git push --force"
message = "Use --force-with-lease instead"

# Auto-allow read-only git
[[rules]]
action = "allow"
pattern = "git status"

[[rules]]
action = "allow"
pattern = "git log"

[[rules]]
action = "allow"
pattern = "git diff"

# Keep secrets out of writes
[[rules]]
action = "deny-redirect"
pattern = "**/.env*"

[[rules]]
action = "deny-redirect"
pattern = "**/*.pem"
```

See [Examples](/configuration/examples/) for the full package-based
starters you can copy into your project.

## Legacy flat format

Before TOML, rippy accepted a Dippy-compatible flat format — one rule
per line in a file named `.rippy` or `.dippy`. It's still loaded for
backward compatibility, but **new configs should prefer
`.rippy.toml`**. Run `rippy migrate` to convert an existing flat file
into TOML.

The flat grammar, for reference:

```
# Command rules
allow|ask|deny PATTERN ["message"]

# Redirect rules
allow-redirect|ask-redirect|deny-redirect PATH ["message"]

# MCP tool rules
allow-mcp|ask-mcp|deny-mcp TOOL

# Post-execution feedback
after PATTERN "message"

# Aliases
alias SOURCE TARGET

# Settings
set KEY VALUE
```

The flat form does not support structured matching (`command` / `args`)
or per-rule `risk` levels — those are TOML-only. If you need either,
migrate the file.
