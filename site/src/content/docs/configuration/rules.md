---
title: Rules
description: The complete rule grammar for rippy config files.
---

Write rippy config as a `.rippy.toml` file — a list of rules plus an
optional `[settings]` block:

```toml
[settings]
default = "ask"

[[rules]]
action = "deny"
pattern = "git push --force"
message = "Use --force-with-lease instead"
```

Each rule type below is one `[[rules]]` table with an `action`, a
`pattern` (or [structured fields](#structured-matching)), and an
optional `message`. The legacy flat `.rippy` / `.dippy` format is still
read for backward compatibility — see [Legacy flat format](#legacy-flat-format)
at the bottom — but new configs should use `.rippy.toml`, and
`rippy migrate` will convert an existing flat file for you.

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

## Structured matching

Instead of a single `pattern` string, a command rule can match on the
command name, subcommand, flags, and argument content as separate
fields. This is the cleanest way to pin a rule to a specific subcommand
without depending on how the command string is written:

```toml
[[rules]]
action = "deny"
command = "git"
subcommand = "push"
flags = ["--force"]
message = "Use --force-with-lease instead"
```

Supported fields (all optional; a rule matches only when every field
you supply matches):

- `command` — the command name (e.g. `"git"`, `"docker"`)
- `subcommand` — a single subcommand; use `subcommands` for a list
  (e.g. `["push", "reset"]`)
- `flags` — required flags (e.g. `["--force"]`)
- `args-contain` — matches if any argument contains this substring

Structured matching is TOML-only; the legacy flat format has no
equivalent. See [Patterns](/configuration/patterns/) for the pattern
grammar used inside individual fields.

## Conditional rules

Gate any rule on runtime context — git branch, working directory,
environment variables, a file on disk, or an external command — by
adding a `when` table to the `[[rules]]` entry. The rule only applies
when every condition inside `when` is true:

```toml
# Only enforce the force-push deny on main
[[rules]]
action = "deny"
command = "git"
subcommand = "push"
flags = ["--force"]
message = "Use --force-with-lease instead"
when = { branch = { eq = "main" } }
```

### Supported conditions

**Branch** — match against the current git branch. Three forms:

```toml
# Exact match
when = { branch = { eq = "main" } }

# Negated match (also true when outside a git repo)
when = { branch = { not = "main" } }

# Glob match — same grammar as the [Patterns](/configuration/patterns/) page
when = { branch = { match = "feat/*" } }
```

**Working directory** — only apply when the hook's working directory
is inside a given path. Use an absolute path, or `"."` to always match:

```toml
when = { cwd = { under = "/Users/alice/work/monorepo" } }
```

**File exists** — only apply when a file is present on disk. Useful for
scoping rules to repos that use a specific tool:

```toml
when = { file-exists = "pnpm-lock.yaml" }
```

**Environment variable** — only apply when an env var has a specific
value:

```toml
when = { env = { name = "CI", eq = "true" } }
```

**External command** — run an arbitrary shell command and apply the
rule only if it exits with code 0. The command runs via `sh -c` with a
**hard 1-second timeout** and executes on every matching evaluation, so
use this sparingly:

```toml
when = { exec = "test -f .rippy-strict" }
```

### Combining conditions

Multiple keys in the same `when` table are AND-combined — the rule
applies only when every condition is true:

```toml
[[rules]]
action = "allow"
pattern = "docker compose up"
when = { branch = { match = "feat/*" }, file-exists = "docker-compose.yml" }
```

### Worked example — branch-aware push policy

The most common use is scoping a rule to a particular branch. Here,
pushes are auto-approved on feature branches but always ask on `main`:

```toml
# Auto-approve pushes on feature branches
[[rules]]
action = "allow"
command = "git"
subcommand = "push"
when = { branch = { match = "feat/*" } }

# On main, always ask first
[[rules]]
action = "ask"
command = "git"
subcommand = "push"
when = { branch = { eq = "main" } }
```

Conditional rules are TOML-only; the legacy flat format has no
equivalent.

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
per line in a file named `.rippy` or `.dippy`. It's still loaded so
existing configs keep working, but new configs should use
`.rippy.toml`. Run `rippy migrate` to convert an existing flat file.

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

Structured matching (`command` / `subcommand` / `flags` /
`args-contain`) is not available in the flat format.
