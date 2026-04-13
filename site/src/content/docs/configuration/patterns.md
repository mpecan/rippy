---
title: Patterns
description: How rippy matches command strings against rule patterns.
---

All rule patterns are matched against the parsed command — not the raw
string — so whitespace, quoting, and argument order are normalized for you.

## Prefix matching (the default)

By default, a pattern matches any command that **starts with** the given
tokens:

| Pattern | Matches | Doesn't match |
|---|---|---|
| `git` | `git`, `git status`, `git push --force` | `jj git` |
| `docker run` | `docker run alpine`, `docker run -it ubuntu bash` | `docker ps` |
| `rm -rf` | `rm -rf ./build`, `rm -rf /tmp/foo` | `rm file.txt` |

This is usually what you want — `allow git status` really does mean "every
invocation of `git status`, regardless of flags".

## Exact matching (trailing pipe)

Add a trailing `|` to force an exact match:

| Pattern | Matches | Doesn't match |
|---|---|---|
| `git\|` | `git` (bare) | `git status` |
| `ls\|` | `ls` (bare) | `ls -la` |

Useful when you want to allow a bare command but ask about any flags.

## Glob wildcards

Patterns support standard glob metacharacters:

| Metachar | Meaning |
|---|---|
| `*` | Any characters except a path separator |
| `**` | Any characters including path separators (globstar) |
| `?` | Exactly one character |
| `[abc]` | Character class |

Examples:

```
allow  git log *
ask    docker run *
deny-redirect **/.env*
deny-redirect **/secrets/**
```

## Variables and subshells

When rippy sees a variable expansion (`$VAR`, `${FOO}`) or a command
substitution (`$(…)`) inside the command, it refuses to guess the expanded
value and **falls back to `ask`**. This is conservative by design — it is
better to ask a human than to approve `rm $DIR` without knowing what `$DIR`
will be.

The same applies to function definitions, exotic quoting forms, and
anything else the parser cannot reduce to concrete tokens. Fail-safe, not
fail-clever.
