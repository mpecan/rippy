# Fuzzing and metamorphic testing

rippy's spec is "never `Allow` something harmful". That is a *metamorphic*
property: it needs no oracle for the correct verdict, only transformations that
must never lower restrictiveness. This document states the invariants, records
the known gaps, and explains how to run both harnesses.

Related issue: [#168](https://github.com/mpecan/rippy/issues/168).

## Layout

| Path | Role |
|---|---|
| `tests/metamorphic/grammar.rs` | Generated command grammar (stages, wrappers, env prefixes, leaves, args, redirects) |
| `tests/metamorphic/invariants.rs` | Invariants 1-7 as small functions over a `CmdSpec` |
| `tests/proptest_metamorphic.rs` | Fast proptest driver, runs under `cargo test` |
| `src/resolve_proptests.rs` | Invariant 8 (in-crate: `resolve::WordResolution` is `pub(crate)`) |
| `src/fuzz_support.rs` | `feature = "fuzzing"` shim so the libfuzzer target can reach invariant 8 |
| `fuzz/fuzz_targets/analyze.rs` | Coverage-guided no-panic/no-hang target |
| `fuzz/fuzz_targets/metamorphic.rs` | Coverage-guided version of invariants 1-8 |
| `tests/fuzz_seeds.rs` | Writes `fuzz/seeds/analyze/` from every catalog command |

The grammar is *generated*, not a fixed cross-product: the space is up to three
pipeline stages, each with an optional inert env prefix, an optional wrapper,
a leaf drawn from the ~200-entry `SIMPLE_SAFE` set or a handler form, up to four
generated argument tokens, and an optional redirect, joined by `;`/`&&`/`||`/`|`.
Argument tokens come from an alphabet with no quote, operator, expansion or
newline character, so a rendered command can never accidentally *be* the
injection the invariants are trying to detect — `grammar_renders_shell_inert`
pins that.

## The invariants

Throughout, `analyze(x)` is the verdict from the real parse-and-analyze
pipeline, and a parse failure counts as `Ask`: rippy fails closed on
unparseable input (`tests/data/catalog/unparseable.toml`), so `Err` is a
non-`Allow` outcome and satisfies every invariant below.

1. **Suffix inject.** For every separator in `;`, `&&`, `||`, `|` and every
   danger in `rm -rf /`, `curl x|sh`, `reboot`, `sh`:
   `analyze(cmd + sep + danger) >= Ask`.
2. **Prefix inject.** `analyze("rm -rf / ; " + cmd) >= Ask` and
   `analyze("sudo " + cmd) >= Ask`.
3. **Redirect inject.** `analyze(cmd + " > /etc/passwd") >= Ask`.
4. **Expansion substitution.** Replacing any literal argument token with
   `$(reboot)`, `${U:-$(reboot)}` or `$"$(reboot)"` may stay `Allow` only when
   the stage's command name is `allowlists::is_dynamic_arg_safe`; otherwise
   `>= Ask`.
5. **Env-prefix inject.** `analyze("LD_PRELOAD=x " + cmd) >= Ask` and likewise
   for `GIT_CONFIG_COUNT=1` — the guard keys on the variable *name*, so it is
   value-independent.
6. **Wrapper monotonicity.** `analyze(w + " " + cmd).decision >= analyze(cmd).decision`
   for every entry of `WRAPPER_COMMANDS`.
7. **Resolution monotonicity.** If `verdict.resolved_command == Some(r)` then
   `verdict.decision >= analyze(r).decision`.
8. **Resolver `Literal` invariant.** No `WordResolution::Literal` returned by
   resolution contains `ast::has_shell_expansion_pattern` or a process
   substitution.

### Invariant 6 is stated over a single command

Issue #168 writes invariant 6 as `analyze("time " + cmd) >= analyze(cmd)`.
Textually prefixing a wrapper to a *compound* command wraps only its first
stage, so the two sides are not the same program and the relation is not
meaningful there. Concretely, `cargo check; ls` is `Ask` — the
[string-rule chokepoint](security-invariants.md) refuses to let a whole-string
allow rule cover a compound — while `builtin cargo check; ls` is `Allow`,
because `builtin` re-enters analysis with `cargo check` alone, which legitimately
is a single plain command. That is the base being conservative, not the wrapped
form failing open. The harness therefore applies invariant 6 to single-stage
specs, where prefixing a wrapper really does wrap the whole command. An
exhaustive sweep of every `SIMPLE_SAFE` leaf times every wrapper in that shape
found exactly one violation, recorded below.

### Invariant 7 is monotone, not an equality

Issue #168 writes invariant 7 as `analyze(r).decision == verdict.decision`.
Equality is wrong and would fire on strictly-more-restrictive behavior: the
command-position dynamic branch in `src/analyzer_dispatch.rs` returns `Ask`
*with* a resolved command attached, and that resolved command re-analyzes to
`Allow` (`$CMD arg` with `CMD=ls` → `Ask`, `ls arg` → `Allow`).
`Verdict::combine` likewise keeps `resolved_command` when a redirect verdict
dominates, so the resolved string can omit the redirect that drove the decision.
Only the monotone direction expresses "never fail open".

## Known fail-opens

### Wrapper commands drop the redirect guard — [#181](https://github.com/mpecan/rippy/issues/181)

Found by invariant 3.

```
ls > /etc/passwd                    => Ask   | redirect to /etc/passwd
nice ls > /etc/passwd               => Allow | ls is safe
command echo pwned > /etc/sudoers   => Allow | echo is safe
```

`analyze_command_node` returns the wrapper's inner verdict directly instead of
funnelling it through `with_redirects`, so `nice`, `nohup`, `strace`, `ltrace`,
`command`, `builtin` and bare `timeout` all discard the node's redirects.
`time` is unaffected because rable parses it as a keyword.

Until it is fixed:

- `invariants::redirect_guard_lost_by_wrapper` skips exactly this shape during
  generation. The invariant itself is unchanged.
- `tests/proptest_metamorphic.rs::wrapper_must_not_drop_the_redirect_guard`
  pins the reproducers as an `#[ignore]`d failing test.

Fixing #181 means deleting both.

### Non-ASCII in a ruby/perl inline script panics the hook — [#182](https://github.com/mpecan/rippy/issues/182)

Found by the `analyze` target within 30 seconds of its first run.

```
ruby -e '%x+їd/'     -> panic at src/ruby_safety.rs:124, exit 101
perl -e 'їopen'      -> panic at src/perl_safety.rs:74
```

`contains_word` indexes a `&str` with byte offsets taken from `as_bytes()`, so a
multi-byte character splits mid-scalar. No verdict is written and the process
exits 101, which Claude Code treats as a non-blocking error — the command runs
un-gated, making this a fail-open rather than a mere crash.

`tests/proptest_robustness.rs::interpreter_scanners_must_not_panic_on_non_ascii`
pins the reproducers as an `#[ignore]`d failing test. Until #182 is fixed the
nightly `analyze` job will keep rediscovering this crash and failing; that is the
intended behavior of a scheduled fuzz job with a known open bug.

## Running the harnesses

The proptests are part of the normal gate:

```sh
cargo test --test proptest_metamorphic
PROPTEST_CASES=4000 cargo test --test proptest_metamorphic   # deeper sweep
cargo test --lib resolve                                     # invariant 8
```

The libfuzzer targets need nightly and `cargo-fuzz`:

```sh
cargo install cargo-fuzz
cargo test --test fuzz_seeds                    # fills fuzz/seeds/analyze/
cargo +nightly fuzz run analyze fuzz/corpus/analyze fuzz/seeds/analyze -- -max_total_time=300
cargo +nightly fuzz run metamorphic -- -max_total_time=300
```

The first corpus directory is the writable one; the seed directory is read-only
input. If the ASan build of rusqlite's bundled SQLite misbehaves, add
`--sanitizer none` — coverage-guided fuzzing still works and a panic/hang oracle
does not need ASan.

`rust-toolchain.toml` pins 1.93.0, so a plain `cargo fuzz` inside the repo picks
the pinned stable and fails on missing `-Z` flags. Use `cargo +nightly` or set
`RUSTUP_TOOLCHAIN=nightly`, as `.github/workflows/fuzz.yml` does.

## Promoting a crash into a regression seed

1. Replay it: `cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<crash>`.
2. Reduce it to a command string — the metamorphic panic message already prints
   the base and transformed commands.
3. If it is a rippy bug, add the command to `tests/data/catalog/*.toml` with the
   *observed* decision, or as an `#[ignore]`d test plus an issue when the
   observed decision is the bug.
4. If a proptest reproduces it, commit the generated
   `proptest-regressions/*.txt` file so CI re-runs the counterexample forever.

Integration-test proptests persist to `tests/<name>.proptest-regressions`
(proptest's `SourceParallel` cannot find a `lib.rs`/`main.rs` above `tests/`);
in-crate proptests persist to `proptest-regressions/<module>.txt`.

## Authoring catalog cases

Never transcribe a decision from memory, and do not use `rippy inspect` as the
oracle — it can diverge from the analyzer pipeline (issue #167). Run the
candidate through `common::isolated_analyzer()` and use the observed `Decision`.
