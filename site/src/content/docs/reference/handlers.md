---
title: Handlers
description: The command-specific handlers that know which subcommands are safe.
---

Handlers are rippy's per-CLI safety experts. Where the built-in allowlist
treats a command as "safe in all forms", a handler inspects the actual
subcommand, flags, and arguments and decides whether the specific
invocation is safe. This is how rippy can auto-approve `git status` while
still asking about `git push --force`.

## Handler families

rippy ships with handlers for 100+ commands grouped by domain:

| Family | Handlers include |
|---|---|
| **Version control** | `git`, `gh` (GitHub CLI) |
| **Containers & orchestration** | `docker`, `kubectl`, `helm`, `ansible` |
| **Cloud** | `aws`, `gcloud`, `az`, `doctl` (via `cloud.rs`) |
| **Languages & package managers** | `cargo`, `npm`, `pnpm`, `yarn`, `python`, `uv`, `pip`, `poetry`, `node`, `ruby`, `gem`, `bundler`, `perl` |
| **Databases** | `psql`, `mysql`, `sqlite3`, `redis-cli`, `mongo` |
| **Networking** | `curl`, `wget`, `ssh`, `scp`, `rsync`, `nc`, `ping` |
| **Filesystem** | `cd`, `mkdir`, `find`, `rm`, `mv`, `cp`, `ln`, `touch` |
| **Shell & scripting** | `bash`, `sh`, `zsh`, `env`, `xargs` |
| **Text processing** | `sed`, `awk`, `grep`, `jq`, `yq`, `tr`, `cut` |

Each handler understands the subcommand grammar of its tool. For example,
the `git` handler auto-approves read-only subcommands (`status`, `log`,
`diff`, `branch`, `show`, …) but asks about anything that modifies refs,
rewrites history, or pushes.

## How handlers compose with rules

When a command arrives, rippy evaluates in this order:

1. **Explicit `.rippy.toml` rules** — your config has the final say.
2. **Claude Code `permissions.*` rules** — imported from
   `~/.claude/settings.json`.
3. **Safe allowlist** — the ~130 read-only tools that are always fine.
4. **Handler verdict** — the per-CLI handler for the specific command.
5. **Default** — whatever you set via `default` in the `[settings]`
   block of your config (usually `ask`).

The first layer that produces a decision wins. That means you can always
override a handler with an explicit rule — an `action = "deny"` rule
matching `git push` in your `.rippy.toml` blocks every `git push`, even
the variants the handler considers "needs approval" but not "deny".

## Where to find them in the source

Handlers live in
[`src/handlers/`](https://github.com/mpecan/rippy/tree/main/src/handlers)
as one Rust file per family (`git.rs`, `docker.rs`, `kubectl.rs` is in
`system.rs`, and so on). The coverage grows with each release — if your
favorite tool is missing a handler, open an issue or a PR.
