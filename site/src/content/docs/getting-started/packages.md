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

## Where to go from here

- Full breakdown of what each package auto-approves, asks, and blocks —
  [rippy wiki / Packages](https://github.com/mpecan/rippy/wiki/Packages).
- Three package-specific starter configs you can drop into your repo:
  [`examples/review.rippy.toml`](https://github.com/mpecan/rippy/blob/main/examples/review.rippy.toml),
  [`examples/recommended.rippy.toml`](https://github.com/mpecan/rippy/blob/main/examples/recommended.rippy.toml)
  (develop-style), and
  [`examples/autopilot.rippy.toml`](https://github.com/mpecan/rippy/blob/main/examples/autopilot.rippy.toml).
