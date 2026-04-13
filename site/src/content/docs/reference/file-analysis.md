---
title: File analysis
description: How rippy reads script files before approving commands that run them.
---

Most command safety hooks stop at the command line. rippy goes one step
further: when a command points at an executable script or SQL file, rippy
**reads the file contents** and analyzes them before making a decision.

This catches the case where an AI tool silently writes a destructive
script and then runs it — the command itself (`python script.py`) looks
innocent in isolation.

## Supported file types

| File type | Triggered by | What rippy looks for |
|---|---|---|
| **Python** (`.py`) | `python`, `python3`, `uv run`, `poetry run`, ... | Dangerous imports (`os`, `subprocess`, `shutil`), destructive calls (`shutil.rmtree`, `os.remove`, `subprocess.run`), file writes to sensitive paths |
| **SQL** (`.sql`) | `psql -f`, `mysql <`, `sqlite3 <`, ... | Read-only vs. write intent — `SELECT` is safe, `DROP` / `DELETE` / `UPDATE` / `TRUNCATE` needs approval |
| **Shell** (`.sh`, `.bash`, `.zsh`) | `bash script.sh`, `sh script.sh` | Recursive analysis: each command in the script is walked through rippy's own rules |
| **AWK** (`.awk`) | `awk -f script.awk` | `system(…)` calls, shell escapes |
| **GraphQL** (`.graphql`, `.gql`) | GraphQL CLIs | Mutation detection |

## How the decision is made

1. Rippy identifies a file argument it knows how to analyze.
2. It reads the file from disk (read-only, size-limited).
3. It runs the language-specific classifier over the contents.
4. The classifier emits one of three results:
   - **Safe** → command is auto-approved.
   - **Dangerous** → command is blocked or asked about, with the
     offending file contents quoted back to the AI tool as guidance.
   - **Unknown** → command falls through to `ask`.

The SQL classifier, in particular, is a full read-only detector — not a
regex hack — so `SELECT * FROM users WHERE name = 'DROP TABLE'` is still
correctly classified as a read.

## Why heuristic, not perfect

File analysis is explicitly **heuristic**. Things like `import os as
system` in Python, or SQL that builds its statement dynamically, can
defeat a purely static check. That's fine — when the classifier sees
anything it can't prove safe, the result is **ask**, never silent
**allow**. The goal is to turn "blind execution of AI-written scripts"
into "human review of suspicious ones".
