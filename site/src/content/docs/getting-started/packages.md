---
title: Packages
description: Preconfigured safety profiles — review, develop, and autopilot — and how to pick one.
---

A **package** is a preconfigured safety profile you can pick as a starting
point instead of hand-writing rules. rippy ships three packages out of the
box, each targeting a different level of AI autonomy:

```
  review      [===]     Full supervision. Every command asks.
  develop     [==.]     Auto-approves builds, tests, VCS. Asks for destructive ops.
  autopilot   [=..]     Maximum AI autonomy. Only catastrophic ops are blocked.
```

Packages are a **starting point** — once you pick one, you layer your own
`allow` / `ask` / `deny` rules on top in your `.rippy.toml`. The package
supplies the defaults; your config has the final word.

## Pick one interactively

```sh
rippy init
```

walks you through package selection and writes `~/.rippy/config.toml` with
`package = "…"` set to your choice.

## Or pick one directly

```sh
rippy init --package develop
```

Replace `develop` with `review` or `autopilot` depending on how much
friction you want.

## Manage packages later

```sh
rippy profile list              # see all packages
rippy profile show develop      # see what a package auto-approves, asks, and blocks
rippy profile set autopilot     # switch packages without rewriting your config
```

The active package is stored in your config's `[settings]` block as
`package = "<name>"`. You can also edit that line directly.

## How packages compose with rules

When rippy evaluates a command, your explicit rules win over the package.
That means you can run under `autopilot` but still `deny git push --force`
for peace of mind, or run under `review` but `allow git status` so you
don't get asked about read-only commands.

See [Configuration overview](/configuration/overview/) for the full
ordering and [Example configs](/configuration/examples/) for ready-to-copy
starters for each package.

## Custom packages

If the three built-ins don't fit your workflow, you can define your own
package in `~/.rippy/packages/<name>.toml`. The format is the same as any
other rippy TOML config, plus a `[meta]` block for display metadata.

### Extend a built-in

The fastest way to build a custom package is to inherit from a built-in
and layer extra rules on top:

```toml
# ~/.rippy/packages/backend-dev.toml
[meta]
name = "backend-dev"
tagline = "Go + Postgres + K8s workflow"
shield = "==."
extends = "develop"

[[rules]]
action = "allow"
command = "kubectl"
subcommands = ["get", "describe", "logs"]

[[rules]]
action = "deny"
pattern = "kubectl delete"
message = "destructive — run manually"
```

`extends = "develop"` pulls in every rule from the `develop` package first;
your own rules are applied afterwards so they win under last-match-wins.
Only built-in packages (`review`, `develop`, `autopilot`) can be extended
in v1 — this prevents cycles and keeps the resolution order predictable.

If you omit `extends`, your custom package starts from an empty rule set
and only the stdlib defaults apply underneath.

### Activate a custom package

Custom packages are discovered automatically. Use the same CLI as
built-ins:

```sh
rippy profile list              # your custom package appears under "Custom packages:"
rippy profile show backend-dev  # shows inherited + your own rules
rippy profile set backend-dev   # writes package = "backend-dev" to your config
```

Or put `package = "backend-dev"` directly in your global or project
`[settings]` block.

### Naming and priority

- The **filename** (minus `.toml`) is the authoritative package name —
  what you type after `package = "…"` and in `rippy profile`. The
  `[meta] name` field is informational; if it disagrees with the filename
  you'll see a warning and the filename wins.
- **Built-in names always take priority.** If you create
  `~/.rippy/packages/develop.toml`, rippy will use the built-in `develop`
  and print a warning telling you your file is shadowed.
- **Malformed files don't break `profile list`** — rippy skips them with
  a stderr warning so one bad file can't hide the rest. `profile show`
  on a malformed file returns a clear error with the file path.

### Sharing

Custom packages are plain TOML files. You can share them by copying to a
teammate's `~/.rippy/packages/`, committing to a shared repo and
symlinking in, or distributing via your own tooling.

## Where to go from here

- Full breakdown of what each built-in package auto-approves, asks, and
  blocks — [rippy wiki / Packages](https://github.com/mpecan/rippy/wiki/Packages).
- Three package-specific starter configs you can drop into your repo:
  [`examples/review.rippy.toml`](https://github.com/mpecan/rippy/blob/main/examples/review.rippy.toml),
  [`examples/recommended.rippy.toml`](https://github.com/mpecan/rippy/blob/main/examples/recommended.rippy.toml)
  (develop-style), and
  [`examples/autopilot.rippy.toml`](https://github.com/mpecan/rippy/blob/main/examples/autopilot.rippy.toml).
