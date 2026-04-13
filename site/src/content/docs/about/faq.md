---
title: FAQ
description: Common questions about rippy.
---

## Does rippy slow down my AI tool?

No. rippy is a static Rust binary that starts in under a millisecond and
exits as soon as it has printed its verdict. For practical purposes, the
overhead of running rippy on every `Bash` call is indistinguishable from
not running it.

## What happens if rippy crashes or hits an internal error?

rippy **fails open** — it exits with code `1`, and the AI tool treats
that as "no verdict" and falls back to its own default behavior. The
reasoning: rippy is a seatbelt, not a single point of failure. If you'd
rather fail closed, wrap the hook in a one-line shell script that maps
exit code `1` to `2`.

## Does rippy send any data over the network?

No. rippy is an entirely local tool. It reads config from your disk,
reads the incoming command from stdin, optionally reads script files
from disk (see [File analysis](/reference/file-analysis/)), and writes
the verdict to stdout. There is no telemetry, no update check, no
outbound network call of any kind.

## Can I use rippy without any config?

Yes. Out of the box rippy ships with its built-in safe allowlist and
command handlers, which cover most common tools. Add a `.rippy` only when
you want to customize the defaults (e.g. `deny git push --force` with a
specific message).

## What about tokf?

rippy pairs with [tokf](https://github.com/mpecan/tokf), a CLI output
compressor for LLM context. tokf can delegate permission decisions to
rippy via its external permission engine hook, so you get compression
and safety checks from one coherent pair of tools. See
[tokf's external permission engine docs](https://github.com/mpecan/tokf#external-permission-engine).

## My tool / command isn't handled — what do I do?

Two options:

1. Add an explicit rule in your `.rippy` file — `allow`, `ask`, or `deny`
   works for any command.
2. Open an issue (or even better, a PR) at
   [github.com/mpecan/rippy](https://github.com/mpecan/rippy) so the
   handler can ship for everyone.

## Is rippy a security boundary?

No — it's a **permission layer**, not a sandbox. See
[Safety model](/reference/safety-model/) for a detailed breakdown of
what rippy protects against and what it doesn't. Use it as part of
defense in depth, not as your only line of defense.
