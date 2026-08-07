# Mutation testing

Coverage answers "was this line executed?". For a security tool that is the
wrong question — `analyzer.rs` is near-fully covered, and covered code can still
have its meaning changed without a single test turning red.

Mutation testing asks the useful question instead: **if this line quietly
changed meaning, would anything notice?** `cargo-mutants` rewrites one
expression at a time (`>` becomes `>=`, a `&&` becomes `||`, a function body is
replaced with `Default::default()`), reruns the suite, and reports the verdict.

| Outcome | Meaning |
|---|---|
| **caught** | A test failed. The line is genuinely pinned. |
| **missed** | Every test still passed. The line can be weakened silently. |
| **unviable** | The mutant does not compile (no `Default` impl, etc.). Not a gap. |
| **timeout** | The mutant hangs — treated as caught, but worth a look. |

A **missed** mutant in decision logic is the finding. It means there is a way to
change what rippy approves that the suite would wave through.

## Running it

```sh
cargo install cargo-mutants     # once
scripts/cargo-mutants-ramdisk           # full sweep, scratch trees in RAM
```

**Run it on a RAM disk.** `cargo-mutants` copies the source tree *and*
`target/` into one scratch directory per job. On this crate each job settles
around 6.5 GB, so a 12-job sweep is ~78 GB written to the system drive and
deleted again — every run. A full sweep once filled the disk to 99%.

`scripts/cargo-mutants-ramdisk` creates a RAM disk, points `TMPDIR` at it, and
forwards every argument to `cargo mutants`. It is project-agnostic — it reads
nothing from this repo except the size of `target/` — so symlink it onto your
`PATH` (`ln -s "$PWD/scripts/cargo-mutants-ramdisk" ~/.local/bin/`) and it works
from any crate root:

```sh
scripts/cargo-mutants-ramdisk --file src/handlers/text_tools.rs
scripts/cargo-mutants-ramdisk -j 8 --in-diff pr.diff
MUTANTS_RAMDISK_KEEP=1 scripts/cargo-mutants-ramdisk   # reuse the disk next run
```

It sizes the disk from `target/` and the job count, caps itself at 60% of RAM,
and reduces the job count rather than overflowing mid-run. It refuses to touch
the mount point if anything other than a RAM disk is already there, and detaches
on exit unless `MUTANTS_RAMDISK_KEEP=1`.

Plain `cargo mutants` works identically — the wrapper only changes where the
scratch trees live.

**There is no CI job, deliberately.** The scoped sweep is 81 min on 12 local
cores; a full one on a 2-4 core GitHub runner would plausibly exceed the 6h job
limit, and the output of mutation testing is a triage queue rather than a
pass/fail signal. The nightly `fuzz.yml` cron is not the answer either, for the
same reason it gives: the value is in reading the survivors. The one shape that
*could* be automated is `cargo mutants -D <diff>`, which mutates only lines a PR
touched and costs minutes — worth adding once the survivor list is small enough
that a PR-scoped run is usually green.

Scope it while iterating — a single file is a couple of minutes:

```sh
cargo mutants --file src/handlers/text_tools.rs
cargo mutants --file 'src/handlers/*.rs' -j 8
cargo mutants --list            # enumerate without running anything
```

Results land in `mutants.out/` (git-ignored), one file per outcome:
`missed.txt` is the one to read. Per-mutant build and test logs are under
`mutants.out/log/`, and `mutants.out/outcomes.json` has timings.

Re-check a single surviving mutant after writing a test for it — `--re` matches
against the mutant names `--list` prints:

```sh
cargo mutants --file src/sql.rs --re 'replace .. with .. in strip_comments'
```

## Configuration

`.cargo/mutants.toml` holds the run config. The part that matters is the
timeout: **`timeout_multiplier = 5.0`, `minimum_test_timeout = 60`**. A mutant
that flips a loop bound hangs rather than fails, and the suite takes ~40s warm,
so cargo-mutants derives a ~170s ceiling from its own baseline run. The 60s
floor only binds on a machine much faster than CI.

The `exclude_globs` entries (`fuzz/**`, `build.rs`) are belt-and-braces: verified
with `cargo mutants --list-files` against `--no-config`, both produce the same 90
files, because `fuzz/` is outside the workspace and `build.rs` is not a mutation
target anyway. They are kept so that neither becomes one silently.

Test-only code needs no exclusion either: `cargo-mutants` skips `#[cfg(test)]`
modules, which covers the `#[path]`-included `src/*_tests.rs` files.

## Baseline

A point-in-time record, not a maintained metric — there is no gate on it,
because a check would cost the same hours as the sweep. Re-measure with the
command under [Reproducing](#reproducing) rather than trusting these numbers.

Measured 2026-08-06, scoped to the decision logic — `analyzer*`, `ast`,
`allowlists`, `cc_permissions`, `resolve*`, `pattern`, `sql`, `*_safety`,
`handlers/`, `verdict`, `condition`:

| | before | after |
|---|---|---|
| Mutants | 2129, in 81 min at `-j 12` | same set |
| Caught | 1593 | — |
| **Missed** | **260** | **~120 killed by this document's first pass** |
| Unviable | 207 | — |
| Timeouts | 69 | — |
| **Score** | **86.0%** | — |

Score is `caught / (caught + missed)`; unviable and timeouts are excluded from
both sides. Counting timeouts as caught — which is what the outcome table above
implies — gives 86.5% instead. Neither is wrong, but they are different
questions, so pick one before comparing runs.

Survivors before, by file: `handlers/text_tools.rs` 51, `resolve.rs` 46,
`sql.rs` 31, `analyzer.rs` 29, `perl_safety.rs` 15, `cc_permissions.rs` 14,
`ast.rs` 13, `handlers/git.rs` 12.

After the catalog cases landed, re-running the same files: `text_tools` 51→1,
`resolve` 46→15, `sql` 31→7, `git` 12→0, `ruby`/`node`/`unix_utils`/`gh`/`helm`/
`cloud` all →0. Most of what remains is the EQUIVALENT set below plus the
`analyzer.rs` depth and node-budget guards, which need inputs too large for a
catalog file (a 10 001-stage pipeline, a 1024-item brace list) and are better
served by a generated test.

All 260 were triaged individually; **31 are provably EQUIVALENT** and must not
be given tests. Two worth recording, because they show how easily a survivor is
mis-rated in either direction:

- **`analyzer.rs` `most_restrictive` → `Default::default()` survives.**
  `Verdict::default()` is `allow(AllowReason::Empty)`, so the mutant returns
  Allow unconditionally — which looks alarming. Building it and diffing verdicts
  across all 1380 catalog commands plus `$(reboot)` / `<(reboot)` probes produced
  **zero** changes. The first reading was "shadowed by the expansion pre-guard";
  arm instrumentation over 1517 commands showed something stronger — the function
  is **never invoked at all**, because both call sites sit inside `analyze_node`
  arms that are themselves dead. Dead code, not defence in depth ([#196]).
- **`ast.rs` `is_harmless_fallback` → `true` is equivalent.** The `continue` it
  gates (`analyzer.rs:368`) only fires when the item's verdict is already Allow,
  so dropping it cannot loosen the combined verdict. No test needed.

Two coverage holes explained most of the fail-open survivors, and each was one
missing habit rather than one missing test:

1. **Every test in `perl_safety`/`ruby_safety`/`node_safety` put the dangerous
   token at byte 0 of the script.** Six mutants survived by collapsing a
   "preceded by a word byte" boundary check into "position == 0". One leading
   statement — `ruby -e 'puts %x(id)'` — walks past all of them.
2. **No test anywhere put a double quote inside SQL, or a comment marker inside
   a string literal.** That produced ten severity-4 survivors in `strip_comments`
   alone; two hang rather than panic, so `main.rs`'s `catch_unwind` fail-closed
   net does not cover them.

The most valuable output was not the mutants. Triaging them — and reviewing the
cases written to kill them — surfaced **six live fail-opens that reproduce on the
unmutated binary**:

| issue | fail-open |
|---|---|
| [#193] | `case $(reboot) in …` — the subject word is never analyzed |
| [#195] | ~250 nested constructs abort the hook with no verdict at all |
| [#197] | `ConditionalExpr` drops its redirects; self-protect Deny → Ask |
| [#198] | `tar --to-command cat` *downgrades* an extraction from Ask to Allow |
| [#199] | only the first `-c`/`-e` is classified: `psql -c "SELECT 1" -c "DROP TABLE t"` |
| [#200] | `git --exec-path=/tmp/evil status` is unchecked |

Plus [#194], where `cc_permissions`' worst survivors need settings fixtures
rather than catalog cases, and [#196] for the dead arms.

Reproducers are pinned in `tests/known_fail_opens.rs` as `#[ignore]`d tests that
genuinely fail under `--ignored`. [#195] is the exception: a stack overflow
aborts the process rather than failing an assertion, so it would take the test
binary down with it. It belongs in `tests/hook_fail_closed.rs` as a subprocess
assertion once fixed.

Three of the six were found not by the sweep but by **reviewing the new test
cases** — a proposed case would have pinned `tar -xf a.tar --to-command cat` as a
green `allow`, asserting the bug was correct behaviour. That is the failure mode
to watch for here: mutation testing pushes you to write a case for every
survivor, and a case written to kill a mutant will happily enshrine whatever the
code currently does.

[#193]: https://github.com/mpecan/rippy/issues/193
[#194]: https://github.com/mpecan/rippy/issues/194
[#195]: https://github.com/mpecan/rippy/issues/195
[#196]: https://github.com/mpecan/rippy/issues/196
[#197]: https://github.com/mpecan/rippy/issues/197
[#198]: https://github.com/mpecan/rippy/issues/198
[#199]: https://github.com/mpecan/rippy/issues/199
[#200]: https://github.com/mpecan/rippy/issues/200

### Reproducing

```sh
scripts/cargo-mutants-ramdisk -j 12 \
  --file 'src/analyzer*.rs' --file 'src/ast.rs' --file 'src/allowlists.rs' \
  --file 'src/cc_permissions.rs' --file 'src/resolve*.rs' --file 'src/pattern.rs' \
  --file 'src/sql.rs' --file 'src/*_safety.rs' --file 'src/handlers/*.rs' \
  --file 'src/verdict.rs' --file 'src/condition.rs'
```

A caveat learned the hard way: `cargo-mutants` scores a *build failure* as
`unviable`, indistinguishable from a mutant that genuinely cannot compile. An
earlier full sweep reported 2614 unviable (80%) because a partially-copied
`target/` broke `libsqlite3-sys` in every scratch tree — the mutants never ran.
A run whose unviable rate is far above ~10% is a broken run, not a clean bill of
health. Check with:

```sh
grep -l 'could not compile `libsqlite3-sys`' mutants.out/log/*.log | wc -l
```

## How this relates to the other harnesses

The three testing layers answer different questions, and none subsumes another:

| Harness | Question |
|---|---|
| `tests/data/catalog/*.toml` | Does *this command* get *this verdict*? |
| `tests/metamorphic/` + `fuzz/` (see [fuzzing.md](fuzzing.md)) | Can *any generated command* fail open? |
| `cargo mutants` | Is the code that decides it *pinned by a test at all*? |

Mutation testing is the one that finds **absent** tests. The catalog says what
rippy does today; a missed mutant says nobody would notice if that changed.

## Acting on a missed mutant

Not every survivor deserves a test — chase the ones that change a verdict.
Roughly in priority order:

1. **It can flip a decision.** Anything in `analyzer.rs`, `handlers/`,
   `allowlists.rs`, `resolve.rs`, `pattern.rs`, `sql.rs` or the `*_safety.rs`
   modules where the mutant could turn an `Ask`/`Deny` into an `Allow`. Fix by
   adding a catalog case (per CLAUDE.md, a `command -> decision` pair beats a
   white-box test), then re-run that file to confirm the mutant dies.
2. **It weakens a guard without flipping a verdict today.** Worth a test — it
   is a fail-open waiting for the next refactor.
3. **It only changes a diagnostic string.** Reason strings are already pinned
   wholesale by `tests/data/reason_snapshot.txt`; if a mutant there survives,
   the snapshot has a hole.
4. **It is genuinely equivalent** — the mutated code cannot behave differently
   (a redundant bounds check, an unreachable arm). Leave it. If a file
   accumulates these, `skip_calls` or a targeted `#[mutants::skip]` with a
   comment explaining *why* is preferable to pretending it was caught.

Never silence a survivor by loosening an assertion. The rule from
[fuzzing.md](fuzzing.md) applies unchanged: carve out the real shape with a
named predicate, or pin the gap as an issue-referencing `#[ignore]`d test.
