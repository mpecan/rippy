# rable heredoc / substitution regression locks

The Category 6 tests in `tests/corner_cases.rs` lock in fixes from the rable
0.1.13 → 0.1.15 upgrade. Each test name maps to a case below.

Before 0.1.14 (rable issue #26), `read_matched_parens_inner` did not skip heredoc
bodies when tracking `$(...)` paren depth, so an unmatched `(` inside a heredoc
body could corrupt the counter and produce a malformed AST with the `HereDoc`
node missing. rable 0.1.15 (issues #29/#30/#31) rewrote the `$(...)`, backtick,
and process-substitution lexers to fork and re-enter the real grammar, fixing the
same bug class structurally across all three surfaces.

The high-value cases are those where a pre-0.1.14 malformed AST could have leaked
a dangerous token past rippy's walker by absorbing it into the wrong node.

## Shape conventions

- Cases are wrapped in `echo "$(...)"` rather than `x=$(...)` so the command-sub
  *walker* runs on the substitution; an assignment would route through the
  separate assignment-expansion guard and Ask for a different reason.
- An unquoted heredoc delimiter (`<<EOF`, not `<<'EOF'`) keeps the static
  resolver from treating the body as a safe data-passing idiom; combined with an
  inner `$(...)` it forces Ask through the command-sub floor.

## Cases

- **heredoc_with_unmatched_paren_in_cmdsub_asks** — rable #26 behavioral witness:
  a heredoc body with `(bar` and no matching `)`.
- **heredoc_with_dangerous_unmatched_paren_in_cmdsub_asks** — headline security
  regression. `cat <<'EOF'...EOF` is recognized as a safe heredoc passthrough,
  the resolver extracts the body literal `rm -rf /\n(\n`, and the reparse routes
  to the rm/unknown-command path. The test pins the reason substring `rm -rf`
  (not just exit 2): two cmdsub Ask floors fire regardless of the heredoc node's
  integrity, so an exit-code-only assertion would pass even if `HereDoc` were
  dropped.
- **nested_cmdsub_with_heredoc_inner_asks** — rable #29 fork-and-merge for nested
  `$(...)` with an inner heredoc.
- **backtick_with_dangerous_heredoc_body_asks** — rable #30 backtick lexer.
- **proc_sub_with_heredoc_body_asks** / **proc_sub_write_with_dangerous_body_asks**
  — rable #31, read-side `<(...)` and write-side `>(...)`. Process substitution
  always Asks via the analyzer floor; these pin the AST shape.
- **case_pattern_paren_in_cmdsub_asks** — case-pattern parens (`(foo)`, `(*)`)
  were another victim of the pre-0.1.14 paren-tracking bug.
- **extglob_in_cmdsub_asks** — extglob `!(*.bak)` inside `$(...)`.
- **cmdsub_echo_literal_still_asks** / **backtick_echo_literal_still_asks** —
  consistency locks: a fully-literal inner command must NOT be resolved away into
  Allow; `CommandSubstitution` and backticks always combine with the Ask floor.
