# Jev: model-assisted resolution of uncertain `ask` verdicts

Status: **implemented** (phases 0–2; phase 3 is future work). This document
describes an opt-in rippy
distribution that consults TypeSafe's [Jev](https://docs.typesafe.ai/introduction.md)
decision model when rippy asks *because it is unsure*, never when it asks
because a human must approve. The default `rippy` build is unaffected and
contains no network code.

## Contents

- [Problem](#problem)
- [Two kinds of ask](#two-kinds-of-ask)
- [What Jev is](#what-jev-is)
- [Scope and guarantees](#scope-and-guarantees)
- [Phase 0: ask classification](#phase-0-ask-classification)
- [Phase 1: the jev feature](#phase-1-the-jev-feature)
- [Phase 2: distribution](#phase-2-distribution)
- [Phase 3: later](#phase-3-later)
- [Threat model](#threat-model)
- [Testing](#testing)
- [Prototype results](#prototype-results)
- [Decisions](#decisions)
- [References](#references)

## Problem

Every `ask` interrupts the user. Many asks are not a judgment that the command is
dangerous. They are rippy admitting it cannot tell: an unknown CLI, an
unresolvable `$VAR`, a subcommand no handler knows. For those, a fast calibrated
classifier can often say "this is a read-only listing" with high confidence, and
save a prompt.

The asks where rippy *knows* the command is consequential, such as `git push
--force`, `rm`, `sed -i` or a user's own `action = "ask"` rule, must keep
prompting. No model gets a say there.

## Two kinds of ask

Today an `Ask` is only a reason string. `Verdict` has no provenance for
it, and `Classification::Ask(String)` is shared by both kinds. This design
splits them:

| Class | Meaning | Examples | Jev-eligible |
|---|---|---|---|
| **Approval** (P) | rippy understands the command; a human must approve | stdlib/package/user `action = "ask"` rules, `git push --force`, `find -delete`, `curl -X POST`, `sed -i`, write redirects, `(write SQL)`, interpreter `-c` flagged by the safety denylists | never |
| **Uncertain** (U) | rippy cannot determine safety | `(unknown command)`, unknown subcommand, unresolvable expansion / command substitution, unreadable script or SQL file, `cd $DIR`, `(ambiguous SQL)` | yes, except `Unanalyzable` |

Roughly 160 handler ask sites plus ~35 analyzer sites exist. By a first
survey, about two thirds are P.

**Fail-safe default.** Every existing ask stays P. A site becomes U only when a
change marks it so explicitly, reviewed like any other allow-surface change.
Handlers whose single catch-all branch mixes known-dangerous and unknown
subcommands (kubectl, docker, npm, gh, aws, …) stay P until that branch is
split.

## What Jev is

Jev is a *System One* model. It does not generate text. It takes a `state`
and a map of typed questions, and returns calibrated probabilities:

- `noul`: a yes/no statement → `{ "noul": p }`
- `choice`: one option from a set → `{ "choice", "probabilities", "confidence" }`
- `score`: a position on an ordered scale

Wire format (TypeSafe's "System One" API):

```http
POST <endpoint>
Authorization: Bearer <key>
Content-Type: application/json

{ "model": "jev-1.13", "state": {...}, "questions": { "<id>": { "type": "noul", "instructions": "...", "criteria": {...} } } }
```

The same body works against every access path, so rippy needs one client with a
configurable endpoint:

| Access path | Endpoint | Model id |
|---|---|---|
| OpenRouter | `https://openrouter.ai/api/v1/systemone` | `jev-1.13` (routed to `typesafe/jev-1.13`) |
| TypeSafe direct | `https://api.typesafe.ai/v1/systemone` | `jev-latest` |
| Proxy / gateway | any compatible URL | as configured |

OpenRouter's separate `/api/alpha/decisions` surface has a different shape and
is alpha. It is not supported.

Other operational facts:
- Only input tokens are billed.
- OpenRouter caps context at 32k tokens.
- Error statuses are 401, 402 (OpenRouter: empty wallet), 422, 429 and 529.

## Scope and guarantees

These hold for every build, and are what the tests pin:

1. **Jev only informs.** It can move a U-ask to Allow, or annotate it. It never
   produces Deny, never changes an Allow or a Deny, and never sees a P-ask.
2. **Exfiltration is escalated, not blocked.** If Jev signals exfiltration, the
   verdict stays Ask, the reason leads with a warning, and the class is promoted
   to P. In the jev build, a flagged command is always emitted as `ask`, even
   when `auto-mode = defer` would otherwise hand it to Claude's auto mode.
3. **Failure changes nothing.** A timeout, HTTP error, malformed response,
   missing key or oversize input leaves the original Ask in place, with
   `(jev unavailable: …)` appended.
4. **Only the user's global config can enable or aim it.** A project
   `.rippy.toml` cannot turn Jev on, change the endpoint, or lower thresholds.
5. **Visible.** Every Jev-influenced verdict says so in its reason, with the
   model id and the numbers it was decided on.
6. **Absent by default.** Without `--features jev`, none of this code is
   compiled.

## Phase 0: ask classification

Status: **implemented.** This ships in the default build and changes **no
behaviour**: no decision, reason string or wire output moves, and
`auto-mode = defer` keeps applying to every Ask, whatever its class. The
reason snapshot proves it. Every earlier line is byte-identical once the new
class column is set aside. The classification is data only, for the jev build
to read (see [decisions](#decisions)).

### Types

`src/ask_class.rs`, re-exported from `verdict`:

```rust
pub enum AskClass { Approval, Uncertain(UncertainKind) }
pub enum UncertainKind {
    UnknownCommand,    // no handler and no rule knows the command
    UnknownSubcommand, // a handler knows the command, not this subcommand
    DynamicExpansion,  // an unknown argument *value*
    OpaqueInput,       // unreadable script/SQL/awk file, ambiguous SQL, a REPL
    Unanalyzable,      // parse failure, limits, internal, fail-closed, unvetted code
}
```

- `Verdict` carries a private `ask_class: Option<AskClass>`, set only on Ask and
  read through `ask_class()`.
- `Verdict::ask()` is Approval, and `Verdict::uncertain(kind, reason)` is new.
  Every rule-derived Ask (`from_rule`) is Approval.
- Handlers return `Classification::Uncertain(kind, reason)` beside
  `Ask(reason)`.
- Anything not explicitly marked stays Approval.

### Combining

A compound command asks with one reason, but its class is the most cautious
among all its asking parts: Approval, then Unanalyzable, then the other
uncertain kinds (`AskClass::max`).
- `Verdict::combine` and `Verdict::most_restrictive` apply this rule.
- `database.rs`'s `least_safe` applies it to classifications.

The *reason* is still chosen exactly as before (`combine` keeps the last of
equal decisions). Changing that would have changed the wire output.

### Classification rules

These were refined during implementation by auditing every uncertain line of
the reason snapshot.

- **`DynamicExpansion` means an unknown argument value, and nothing more.**
  `expansion_ask` (`src/analyzer_dispatch.rs`) is the single place that decides:
  - A command name that comes from an expansion is Approval. `$cmd args` is
    an evasion shape, and `${CMD:-rm} -rf /` even resolves to `rm -rf /`.
  - An unresolved word that would run code (`$(…)`, backticks, `<(…)`) is
    Unanalyzable, because rippy never vetted that code.
    `x=$(rm -rf /); echo $x` and `echo $(rm -rf /)` must not look like an
    unknown value.
  - Heredocs with a substitution, and assignments whose value runs code,
    follow the same rule.
- **An unknown value in a command that asks anyway stays Approval.**
  `for f in *; do rm $f; done` would otherwise be uncertain.
  `unless_asks_anyway` classifies the command a second time with every
  expanded word replaced by an inert placeholder. If that still needs
  approval, the unknown value is not what is in doubt. This check changes only
  the class, never the decision or reason, and does not appear in traces.
  `kubectl get pods -n $NS`, where the placeholder form is allowed, stays
  `DynamicExpansion`.
- **A REPL is `OpaqueInput`; code fed on stdin is Approval.** `opaque_code`
  (`src/handlers/mod.rs`) reads `receives_piped_input`. That flag was
  previously populated but never read. It is now also set for a heredoc,
  here-string or `<` redirect. So `python3` is uncertain, while
  `curl … | sh`, `python3 <<< '…'` and `bash < setup.sh` are Approval.
- **Unknown subcommands** are `UnknownSubcommand` for `SubcommandHandler`
  (`gzip`, `7z`) and git's fallback. Other handler catch-alls (kubectl, docker,
  npm, gh, aws, …) mix known-dangerous and unknown subcommands in one branch
  and stay Approval until they are split.
- Security-sensitive asks stay Approval even where they are technically an
  allowlist miss: `git -c` keys, dangerous environment names, `env -S`,
  unknown `cd` flags, remote contexts.
- MCP tools stay Approval. They are not shell commands.

On the catalog (reason snapshot), 121 of 671 asks are uncertain:
21 `dynamic-expansion`, 28 `opaque-input`, 61 `unanalyzable`,
8 `unknown-command` and 3 `unknown-subcommand`. Excluding `unanalyzable`,
which is never eligible, 60 are candidates for model-assisted review. The catalog is weighted toward attack shapes, so real
sessions will see a higher uncertain share.

### Tests

- `tests/data/catalog/ask_class.toml`: 27 cases taken from observed output,
  each paired with a neighbour of the other class. Catalog cases take an
  optional `ask_class`, which `tests/catalog_runner.rs` asserts.
- `tests/data/reason_snapshot.txt` has a class column, so every
  reclassification is a reviewable diff.
- Unit tests for class ordering and merging are in `src/ask_class.rs`. The
  `least_safe` regression is in `src/handlers/database.rs`.
- Metamorphic invariant 9, "approval dominates" (`docs/fuzzing.md#invariant-9`),
  checks that joining an approval-grade command before or after any generated
  command, with an unknown command appended, never yields an uncertain class
  other than `unanalyzable`.
- `tests/ask_class.rs` checks that the placeholder check does not leak into
  traces.

Two of these tests were checked against deliberate mutations. The first version
of invariant 9 did not fail when class merging was removed, and was
strengthened until it did.

### Lessons for Phase 1

- **Anything that ranks classifications must know every variant.**
  `least_safe` matched only `Ask`, so the new variant fell through and briefly
  turned `psql -c "SELECT 1" -f drop_table.sql` from ask into allow. The
  reason snapshot caught it.
- **An uncertain tag is a claim that only one specific thing is unknown.**
  The first pass over-applied it: code-bearing expansions, interpreters fed on
  stdin, dynamic command names and `rm $f` all started out uncertain. Phase 1
  eligibility should still exclude name-defined commands (see
  [Placement](#placement)), because an honest `UnknownSubcommand` for
  `git frobnicate` may be an alias.

## Phase 1: the jev feature

Status: **implemented.** `jev = ["dep:ureq"]`, off by default. `ureq` is a
blocking HTTPS client over rustls with bundled web-PKI roots; there is no async
runtime.

### Placement

`src/jev_settings.rs` holds the `[jev]` schema and is always compiled, so a
default build can recognise the section and warn that it has no Jev support.
Everything else is in `src/jev/`, compiled only with the feature:

| File | Role |
|---|---|
| `mod.rs` | `review(verdict, command, &JevSettings, &Env, &dyn Transport) -> Review`, the single entry point |
| `eligibility.rs` | which uncertain asks may be sent at all |
| `shape.rs` | a rable walk: every simple command, word spans, and the redacted, comment-free text |
| `facts.rs` | the facts rippy computes: variables, paths, programs |
| `request.rs` | the versioned question set and the state |
| `policy.rs` | pure function: answers + thresholds → outcome |
| `transport.rs` | the `Transport` trait and the `ureq` implementation |
| `cmd.rs` | `rippy jev <command>` |

**Name-defined commands are never eligible.** Jev sees only the text of the
command, so it judges by name and flags. Where a repository decides what a name
does, the name proves nothing:
- path-qualified executables (`./scripts/x.sh`, `bin/x`, `/tmp/x`)
- unknown git subcommands, which may be aliases
- task runners (`make`, `just`, `task`, `mise`, `npm`, `pnpm`, `yarn`, `bun`,
  `npx`, `rake`, `nox`, `tox`, `invoke`)
- an `opaque-input` ask where the program has any non-flag argument. A bare REPL
  such as `python3` is eligible; `python3 deploy.py` and `psql -c '…'` are not.
- any command without a literal name

Such commands keep their Ask. The prototype confirmed the risk:
`./scripts/list-users.sh` and `git frobnicate --list` were both judged read-only
at confidence ≥ 0.95.

It is called once from `run_hook` in `src/main.rs`, after `evaluate()` and before
logging and tracking, so the recorded verdict is the final one. It runs only when
`ask_class()` is `Uncertain(kind)` and `kind != Unanalyzable`. The analyzer, the
catalog and `rippy inspect` stay deterministic. Only `PreToolUse` shell commands
are reviewed; MCP tools and file operations never are.

**Comments.** rable drops comments from the parse, so their text lies outside
every word span. A `#` that starts a word and lies outside every word span
begins a comment, and is removed up to the end of its line. Commands with a
heredoc keep their text, because a heredoc body is not a word either.

### State

```json
{
  "command": "mkdir -p $OUT/build",
  "rippy_uncertainty": "mkdir with variable expansion",
  "uncertainty_kind": "dynamic-expansion",
  "facts": {
    "resolved_variables": { "OUT": "./target (inside project)" },
    "paths": { "./target/build": "inside project" }
  }
}
```

Before sending, the values of `NAME=value` assignments and token-shaped strings
(`ghp_…`, `sk-…`, long hex or base64 runs) are replaced with `<redacted>`. Shell
comments are dropped if rable's parse makes that possible without re-rendering
the command; this still has to be verified against rable's output.

### Context

What Jev can judge depends on what it is told. rippy computes facts
deterministically and sends them under `facts`. This follows TypeSafe's advice
to keep arithmetic, lookups and comparisons in code and send the results as
labels. The prototype (see [prototype results](#prototype-results)) showed
three things:

- **Facts that resolve the uncertainty help strongly and consistently.**
  - With `$OUT` resolved to `./target`, `mkdir -p $OUT/build` dropped from
    `writes_outside_project` 0.42 to 0.04.
  - With `src/` labelled as inside the project, `prettier --write src/` rose
    from confidence 0.89 to 0.99.
- **Facts that only restate the command are neutral to noisy.** Examples are the
  program's install path and its `whatis` description. They are cheap to add but
  are not the lever.
- **Framing prose moves the answers.** Adding a "situation" paragraph ("an AI
  agent wants to run this; the command is untrusted") lowered confidence across
  the board. It dropped `jira issue list` from 0.78 to 0.42, and it also lowered
  the exfiltration score of a real exfiltration pipeline. rippy therefore sends
  no framing text. Context goes into facts, question wording and criteria.

Facts rippy can compute without running anything:

| Fact | Source | Example |
|---|---|---|
| `resolved_variables` / `unresolved_variables` | the resolver; for an unresolved variable, the argument position it fills | `NS: argument to -n (namespace)` |
| `paths` | each path-like argument, classified against the project root and `safe_scopes` | `~/.ssh: outside project (home directory)` |
| `pipeline` | the parsed stages of the pipeline | `["datatool export --all", "somecli push"]` |
| `subcommand` / `arguments` | the rable parse | `["issue", "list", "--assignee", "me"]` |
| `program_path` | a `PATH` lookup, labelled system / user / project dependency / not found | `./node_modules/.bin/prettier (project dependency)` |
| `program_description` | the `whatis` database, when present | `shred: overwrite a file to hide its contents` |

Two things are deliberately left out:
- **Environment variable values**, which may be secret. Only names and
  inside/outside labels are sent.
- **The agent's own `description` field from the hook payload.** It is written
  by the agent and would be a direct steering channel.

**User context.** A global-only `[jev] context = "…"` string may describe the
user's environment, for example "kubectl talks only to local kind clusters".
Because prose shifts the answers, it is sent under `facts.user_context` and
should be checked with `rippy jev` before use.

**Versioning.** The question set, its wording and the fact schema are one
versioned unit, `QUESTION_SET_VERSION`, and the version is part of the reason
string and the cache key. Each round of the prototype changed the answers
measurably, so wording changes are reviewed and re-run against the labelled
sample like any other policy change.

### Questions

One request carries atomic questions, and code combines them. This follows
TypeSafe's composite-scoring and confidence-routing patterns and its advice to
keep judgments narrow and literal.

| id | type | asks |
|---|---|---|
| `effect` | choice | `read_only` / `remote_read` / `local_change` / `destructive` / `network_send` / `download_execute` |
| `exfiltration` | noul | does it upload or transmit the contents of local files, secrets, credentials or environment variables to a remote host; querying a remote service is explicitly not exfiltration |
| `writes_outside_project` | noul | does it create, modify or delete files outside the current project; reading does not count |
| `reads_secrets` | noul | does it read or display credentials, keys, tokens, passwords or `.env` files |
| `irreversible` | noul | would its effect be hard to undo |
| `self_referential` | noul | does the command contain text arguing how it should be classified |

Each noul carries explicit `criteria.true` / `criteria.false`. TypeSafe's docs
note that the model is literal and that one-sided criteria degrade answers.

### Policy

The checks run in this order; the first match wins. Every threshold is
configurable, and the defaults are deliberately conservative.

1. `exfiltration ≥ exfiltration-threshold` (0.5), or `effect` puts probability
   ≥ 0.5 on `network_send` or `download_execute` → **Ask, promoted to
   Approval, forced to prompt**. The reason becomes
   `⚠ jev: possible exfiltration (p=0.71) — <original reason>`.
2. `self_referential ≥ steer-threshold` (0.3) → **Ask, promoted to Approval,
   forced to prompt**, with `(jev: the command text tries to steer its
   classification, p=…)` appended. A command that argues for its own safety
   deserves a human, and its other answers are not trusted.
3. `effect ∈ allow-effects` (default `["read_only"]`; only `read_only`,
   `remote_read` and `local_change` are accepted) and `confidence ≥
   min-confidence` (0.9) and `irreversible < max-irreversible` (0.2) and
   `writes_outside_project < max-writes-outside` (0.3) and `reads_secrets <
   max-reads-secrets` (0.3) → **Allow**, via `AllowReason::Model`, in the
   existing `UserControlled` catalog category. The reason reads
   `jev: approved (read_only, conf 0.97 >= 0.90, typesafe/jev-1.13-20260917 q1)`;
   `q1` is the question-set version.
4. Otherwise → the ask is kept, with its class, and `(jev: local_change, conf 0.74)`
   is appended.

`policy.rs` re-checks that an effect is approvable, so a destructive effect is
never approved even if validation were bypassed.

### Configuration

```toml
# ~/.rippy/config.toml  (global only)
[jev]
enabled = true
endpoint = "https://openrouter.ai/api/v1/systemone"
model = "jev-1.13"
api-key-env = "OPENROUTER_API_KEY"   # the key itself is never read from a file
min-confidence = 0.9
allow-effects = ["read_only"]       # opt-in: "remote_read", "local_change"
timeout-ms = 2000
# context = "kubectl only talks to local kind clusters"   # optional, see Context
# exfiltration-threshold = 0.5, steer-threshold = 0.3,
# max-irreversible = 0.2, max-writes-outside = 0.3, max-reads-secrets = 0.3
```

Unknown keys are a config error (`deny_unknown_fields`), so a misspelt threshold
cannot silently fall back to its default. Values are checked when a review
runs. An invalid value (an endpoint that isn't https, a threshold outside 0–1,
a non-approvable effect in `allow-effects`) leaves every ask untouched, with
`(jev unavailable: …)` naming the problem.

- **Where it is honoured:** only in the global config and the env/CLI override
  file. A `[jev]` table in a project config is ignored with a stderr warning. A
  trusted-but-hostile repository could otherwise point `endpoint` at itself and
  collect the key, or loosen the thresholds. rippy has no per-setting project
  gate today; this adds one on `in_project_section` in
  `from_directives_with_home`.
- **Endpoint:** must be `https://`. `http://` is accepted only for loopback, so
  local proxies and tests still work.
- **Default builds:** a build without the feature warns on stderr whenever it
  sees `[jev] enabled = true`: `this rippy build has no Jev support`.
- **Retries:** none. Hook latency matters more than a retried answer.

### Transparency

- The reason string carries the model id and the deciding numbers, so the hook
  output, `rippy stats` and the tracking DB show them without schema changes.
- The JSON-lines log gains an optional `jev` object: the state sent, the raw
  answers, the policy branch and the latency.
- `rippy --version` prints `0.x.y+jev` on the feature build.
- `rippy jev '<command>'` (with `--json`) prints rippy's own verdict, why a
  command was not sent, the state, the raw answers, the latency and the final
  verdict. It reviews even when `[jev] enabled = false`, since asking is the
  point of the command. It exists for calibration: judge a labelled sample once,
  then replay thresholds offline.
- A flagged review (exfiltration or steering) forces `ask` for that verdict,
  even under `auto-mode = defer`. An uncertain ask Jev simply keeps still
  defers, as it would in the default build.

## Phase 2: distribution

Status: **implemented.** The two builds are mutually exclusive by design. Both install a binary named
`rippy`, so hook configurations need no change.

- **Releases:** the release build matrix is every target × `{rippy, rippy-jev}`.
  The jev leg builds with `--features jev` and publishes
  `rippy-jev-v{version}-{target}.tar.gz` (+ `.sha256`) next to the unchanged
  default archive. `ring` needs `CC_aarch64_unknown_linux_gnu` for the aarch64
  Linux cross-build.
- **Homebrew:** the tap step writes `rippy.rb` and `rippy-jev.rb`, each with
  `conflicts_with` the other.
- **Cargo:** `cargo install rippy-cli --features jev`.
- **cargo-binstall:** it cannot pick an archive by feature. The README documents
  a `--pkg-url` override for the jev archive.
- **CI:** a job runs clippy and the test suite with `--features jev`.
- **README:** an "Optional: Jev" section that states plainly that this trades
  some safety for convenience, and exactly what is sent to a third party.

## Phase 3: later

- A cache in the existing SQLite store, keyed by
  `sha256(redacted state, model, question-set version)`, so repeated commands
  cost nothing and add no latency.
- Per-kind opt-in: `eligible-kinds = ["unknown-command", "dynamic-expansion"]`.
- More handler catch-alls split into P and U, each with catalog contrast pairs.

## Threat model

- **Prompt injection through the command.** The command is written by the
  coding agent, and the agent may itself be following injected instructions.
  TypeSafe documents that adversarial text in `state` "can move the answer".
  Mitigations:
  - Jev never sees P-asks.
  - Default thresholds are high.
  - A `self_referential` question catches commands that argue for their own
    classification.
  - Exfiltration signals escalate rather than approve.
  - Comments are stripped where possible.

  Even so, a feature build is strictly more permissive than the default build.
- **Name-based judgement.** Jev cannot see what a program does, only what it is
  called. A command whose behaviour is defined by the repository, such as a
  script, a git alias or a task-runner recipe, is excluded for that reason (see
  [Placement](#placement)). A malicious binary on `PATH` with an innocent name
  remains a residual risk.
- **Key theft through config.** Addressed by the global-only `[jev]` rule, and
  by reading the key from an environment variable only.
- **Data disclosure.** Eligible commands leave the machine. Redaction covers the
  common secret shapes; it is not a guarantee, and the README must say so.
- **Availability.** An unreachable endpoint only costs the prompt that would have
  happened anyway.

## Testing

- `policy.rs` unit tests over fixture answers: every branch, and every threshold
  at its boundary.
- `request.rs` tests: the question set is stable, and redaction works on
  assignments and token shapes.
- End-to-end tests (`tests/jev_*.rs`, `#![cfg(feature = "jev")]`) spawn the
  `rippy` binary through `tests/common::run_rippy_cmd` against a
  `std::net::TcpListener` mock on loopback. Cases:
  - approve
  - exfiltration warning and promotion
  - HTTP 500 → unchanged
  - timeout → unchanged
  - a P-ask → the endpoint is never contacted
  - a project `[jev]` → ignored
- A proptest with an always-"safe" fake transport: Allow, Deny and Approval
  verdicts are unchanged, and an error from the transport changes nothing.
- The default-build catalog, the reason snapshot and the allow-completeness
  tests run as today. The feature build adds `AllowCategory::Model` to their
  expectations only under `cfg(feature = "jev")`.

## Prototype results

Run on 2026-09-28 against `typesafe/jev-1.13-20260917` via OpenRouter's
`/api/v1/systemone`, with the question set above, one request per command and 40
commands across two rounds.

- **Latency:** about 300 ms typical, 660 ms worst observed. The 2000 ms default
  timeout leaves ample headroom.
- **Cost:** about $0.00004 per command for the full six-question set.
- **Dangerous commands were never approved.**
  - Destructive commands (`shred -u`, `reboot`, `dd … of=/dev/disk2`) were
    classed `destructive`.
  - Every exfiltration case (`tar c ~/.ssh | nc …`, uploading
    `~/.aws/credentials`, `rsync ~/.ssh host:`, `env | base64 | … upload`)
    scored `exfiltration` between 0.81 and 0.95.
  - `bash <(curl …)` was classed `download_execute`.
- **Injection was caught.** A comment claiming `somecli purge --all` was a
  "harmless read-only listing" scored `self_referential` 0.99, and the model
  still classed the command `destructive`.
- **Secrets were caught.** `cat ~/.aws/credentials`, `sops -d`, `printenv` and
  `kubectl get secret` scored `reads_secrets` between 0.60 and 0.95. The model
  itself classed them `read_only`, which is why `reads_secrets` is a separate
  gate.
- **Safe commands were approved:** `somecli list --format json`, `lsusb -v`,
  `grep -rn TODO $SRC_DIR`, `wc -l $(git ls-files)`, `hyperfine …`,
  `terraform-docs markdown .`.
- **Question wording mattered.**
  - A first `outside_project` noul that also counted reads flagged `lsusb` at
    0.94, so it became `writes_outside_project`.
  - Without the clause "querying a remote service is not exfiltration",
    `kubectl get pods` scored 0.51. With it, the score was 0.24.
  - An exfiltration threshold of 0.3 would have flagged `jira issue list`
    (0.31), so the default is 0.5.
- **Local changes** (`cd $DIR`, `mkdir -p $OUT/build`, `prettier --write src/`)
  were classed `local_change` at 0.85 to 1.00 confidence. That makes the opt-in
  `local_change` approval workable. `mkdir -p $OUT/build` still asks, because an
  unknown `$OUT` scores `writes_outside_project` 0.43, which is correct.
- **Interactive REPLs:** a bare `python3` came back `read_only` at only 0.42
  confidence, so it keeps asking.

**Round 3: context and wording** (10 borderline commands, each sent with and
without facts):
- The context findings are summarised under [Context](#context).
- Without a `remote_read` option, read-only calls to remote services
  (`kubectl get pods`, `jira issue list`) landed as `read_only` with
  exfiltration scores between 0.31 and 0.51, so they tripped the warning or
  were denied approval.
  - With the option added and the exfiltration noul reworded to "upload or
    transmit the contents of local files, secrets …", `kubectl get pods -n $NS`
    became `remote_read` at 0.99 confidence with exfiltration at 0.17.
  - Every real exfiltration case stayed at 0.61 to 0.96.
- The injection case still scored `self_referential` 0.99 and `destructive`.
- **Run-to-run variance:** the same borderline command varied by up to about
  0.2 in confidence across rounds. For example, `kubectl get pods` went 0.75,
  then 0.65, then 0.54, as facts and wording changed around it. Thresholds must
  sit well away from where a borderline case lands.

These numbers come from a small hand-labelled sample. They support the defaults
but do not calibrate them; `rippy jev` exists to do that properly.

## Decisions

Recorded 2026-09-28.

- **No default-build behaviour changes.** Phase 0 adds the classification only.
  `auto-mode = defer` keeps applying to every Ask in the default build.
- **Interactive REPLs are Uncertain** (`OpaqueInput`), and are eligible for Jev.
- **Jev may approve commands; wider approvals are opt-in.** The default is
  `allow-effects = ["read_only"]`.
  - Adding `"local_change"` lets Jev approve in-project modifications, still
    subject to the `writes_outside_project` and `irreversible` gates.
  - Adding `"remote_read"` lets it approve read-only queries to remote services.
- **Context is facts, not framing.** rippy sends computed facts and a versioned
  question set, and never sends persuasive or situational prose of its own.
  User-supplied context is global-only and opt-in.
- **Jev does not tighten.** It never produces Deny. Exfiltration signals
  escalate to a forced, warned `ask`.

## References

- TypeSafe API reference: <https://docs.typesafe.ai/api.md>
- Jev 1.13 known limitations: <https://docs.typesafe.ai/model-jaggedness/jev-1.13.md>
- Confidence and thresholds: <https://docs.typesafe.ai/confidence.md>
- OpenRouter Jev guide: <https://openrouter.ai/docs/guides/community/jev>
- OpenRouter tutorial: <https://openrouter.ai/blog/tutorials/how-to-use-jev/>
