# Security invariants

Load-bearing safety rationale for rippy's analyzer core. Inline comments in the
source point here with `see docs/security-invariants.md#<anchor>`. When changing
the referenced code, keep this document in sync — these are the reasons the tool
fails **closed** (Ask/Deny) rather than open (Allow).

## traceability

Every invariant below is restated as a mechanically-checkable property with the
test that enforces it. Rust tests are cited as `path::test_name` (grep with
`rg 'fn <name>\('`); data-driven catalog cases are cited by TOML file path
because `build.rs` derives their generated `#[test]` names positionally, so
those names are not stable. `tests/docs_invariants.rs` keeps this table honest:
every anchor needs a row, every `see docs/security-invariants.md#…` pointer in
`src/` must resolve to a heading, and every name cited here must exist.

| Anchor | Property (testable statement) | Test(s) |
|---|---|---|
| `#env-prefix-strip` | A leading literal `NAME=VALUE` prefix is stripped so the string layers match the real command | `src/ast_tests.rs::strip_env_prefix_single_assignment`, `src/ast_tests.rs::strip_env_prefix_multiple_assignments`, `src/analyzer_tests2.rs::env_prefix_matches_command_rule` |
| `#env-prefix-strip` | Stripping preserves the rest of the command verbatim (redirects, pipelines, `&&` lists) | `src/ast_tests.rs::strip_env_prefix_preserves_redirects`, `src/ast_tests.rs::strip_env_prefix_pipeline_first_command`, `src/ast_tests.rs::strip_env_prefix_list_first_command` |
| `#env-prefix-strip` | A value containing an expansion is never stripped, and the command still Asks under an allow rule | `src/ast_tests.rs::strip_env_prefix_none_when_value_has_expansion`, `src/analyzer_tests2.rs::env_prefix_with_cmdsub_not_stripped_still_asks`, `tests/security_invariants.rs::env_prefix_with_expansion_asks_even_when_command_is_allow_ruled` |
| `#env-prefix-strip` | A code-influencing var is never stripped, and the un-stripped command falls through to the analyzer and Asks even when the command is allow-ruled (the #157 gap) | `src/ast_tests.rs::strip_env_prefix_none_for_dangerous_var`, `tests/security_invariants.rs::env_prefix_dangerous_var_asks_even_when_command_is_allow_ruled` |
| `#env-prefix-strip` | Ordinary vars are stripped and the command stays Allow | `src/ast_tests.rs::strip_env_prefix_allows_ordinary_vars`, `src/analyzer_tests2.rs::literal_assignment_prefix_still_allows` |
| `#env-prefix-strip` | No Allow rule bypasses the redirect guards via an env prefix | `tests/security_invariants.rs::env_prefix_does_not_launder_redirect_past_self_protect` |
| `#env-prefix-strip` | On unparseable input we fall back to the raw string: deny rules still match, and the parse error still surfaces as an Ask | `tests/security_invariants.rs::deny_rule_still_matches_unparseable_command`, `src/analyzer_tests.rs::unparseable_command_asks_fail_closed`, `tests/infrastructure.rs::claude_unparseable_command_asks_not_fail_open` |
| `#dangerous-env-name` | `is_dangerous_env_name` flags the linker/interpreter hooks plus the `GIT_CONFIG*` and `BASH_FUNC_*` prefix families | `src/ast_tests.rs::is_dangerous_env_name_flags_known_injection_families` |
| `#dangerous-env-name` | Common build/CI names on the inert list (`CI`, `NODE_ENV`, `RUST_LOG`, `LANG`) stay Allow | `src/ast_tests.rs::inert_env_names_are_allowed` |
| `#dangerous-env-name` | A dangerous literal assignment Asks even on a safe-listed command, before the fast path or any handler runs | `tests/data/catalog/injection_env_var.toml`, `tests/security_invariants.rs::env_prefix_dangerous_var_asks_even_when_command_is_allow_ruled` |
| `#dangerous-env-name` | The `env` handler applies the same check to the `NAME=VALUE` args it sets | `tests/data/catalog/injection_env_var.toml` |
| `#dangerous-env-name` | `env -S` / `--split-string=` / `-vS` payloads are extracted and recursed into | `src/handlers/env_xargs.rs::split_string_separate_arg`, `src/handlers/env_xargs.rs::split_string_attached_short_and_long`, `src/handlers/env_xargs.rs::split_string_bundled_boolean_cluster`, `tests/data/catalog/injection_env_var.toml` |
| `#dangerous-env-name` | A short cluster with an ambiguous option boundary yields an empty payload so the handler Asks | `src/handlers/env_xargs.rs::split_string_uncertain_cluster_fails_closed` |
| `#dangerous-env-name` | A dangerous prefix cannot ride a chain to Allow | `tests/data/catalog/injection_string_rule_chokepoint.toml` |
| `#dangerous-env-name` | A name rippy has no entry for is dangerous — the predicate is inert-listed, not denylisted | `src/ast_tests.rs::unknown_env_names_are_dangerous`, `tests/data/catalog/injection_env_var.toml` |
| `#dangerous-env-name` | Every inert name is pinned, so widening the list is a visible change | `src/ast_tests.rs::inert_env_names_are_allowed` |
| `#dangerous-env-name` | Names that read as inert but select code (`LOCPATH`, `TERMINFO`, `PAGER`) stay dangerous | `src/ast_tests.rs::lookalike_env_names_stay_dangerous` |
| `#dangerous-env-name` | The prefix Ask does not short-circuit the command's own verdict, so a Deny is not downgraded | `tests/data/catalog/injection_env_var.toml` |
| `#append-assignment-shadow` | `literal_assignment` rejects `NAME+=VALUE` | `src/ast_tests.rs::literal_assignment_rejects_append` |
| `#append-assignment-shadow` | `append_assignment_name` matches append-only forms | `src/ast_tests.rs::append_assignment_name_matches_append_only` |
| `#append-assignment-shadow` | An append shadows a prior literal as set-but-unknown rather than resolving the stale value | `src/analyzer_tests2.rs::append_assignment_shadows_prior_literal_not_a_stale_value`, `src/analyzer_tests2.rs::append_assignment_handler_still_asks` |
| `#append-assignment-shadow` | An append prefix on a safe command still allows | `src/analyzer_tests2.rs::append_assignment_env_prefix_safe_command_allows` |
| `#fd-dup-remap` | Bare-descriptor and close targets stay real fd operations | `src/ast_tests.rs::fd_dup_target_recognizes_descriptors_but_not_paths`, `src/analyzer_tests.rs::fd_dup_to_descriptor_allows`, `src/analyzer_tests.rs::fd_dup_to_dev_null_allows` |
| `#fd-dup-remap` | A path target is re-mapped to `Write` and runs the full write pipeline (safe-dir check and self-protection) | `src/analyzer_tests.rs::fd_dup_to_unsafe_file_asks`, `src/analyzer_tests.rs::fd_dup_to_safe_dir_allows`, `src/analyzer_tests.rs::fd_dup_to_self_protected_denies` |
| `#wrapper-redirects` | A wrapper prefix never launders a redirect or heredoc past the write pipeline, including nested wrappers, chained lists, and the no-inner-command form | `tests/data/catalog/injection_wrappers.toml`, `tests/proptest_metamorphic.rs::wrapper_must_not_drop_the_redirect_guard`, `tests/metamorphic/invariants.rs::redirect_inject` |
| `#wrapper-redirects` | A safe wrapped redirect still Allows, so the guard is not a blanket Ask | `tests/data/catalog/injection_wrappers.toml` |
| `#wrapper-redirects` | `timeout`'s options and DURATION are skipped so the inner command is analyzed, and an argv that does not match that grammar is left unchanged | `src/allowlists.rs::timeout_duration_and_options_are_skipped`, `src/allowlists.rs::unparseable_timeout_argv_falls_back_to_the_whole_slice`, `src/allowlists.rs::wrappers_without_an_option_grammar_keep_their_whole_argv` |
| `#wrapper-redirects` | `nice`'s adjustment options are skipped so the inner command is analyzed, and a malformed argv falls back to Asking | `src/allowlists.rs::nice_adjustment_options_are_skipped`, `src/allowlists.rs::incomplete_nice_argv_falls_back_to_the_whole_argv`, `tests/data/catalog/injection_wrappers.toml` |
| `#tmp-symlink` | Targets whose runtime value is not statically known (expansions, `~`, globs) are rejected | `src/analyzer_tests.rs::redirect_dynamic_target_asks`, `src/analyzer_tests.rs::redirect_glob_target_asks` |
| `#tmp-symlink` | `..` escapes and prefix-not-component matches are rejected | `src/analyzer_tests.rs::redirect_dotdot_escape_asks`, `src/analyzer_tests.rs::redirect_component_boundary_asks` |
| `#tmp-symlink` | cwd exclusion: a target inside the working-directory subtree keeps asking even when cwd lives under a safe dir | `src/analyzer_tests.rs::redirect_into_cwd_under_safe_dir_asks` |
| `#tmp-symlink` | symlink re-check: a redirect through `/tmp/evil -> /etc` is rejected | `src/analyzer_tests.rs::redirect_through_symlink_out_of_safe_dir_asks` |
| `#tmp-symlink` | User-declared scopes are trusted opt-ins and skip the re-check (accepted trade-off) | `tests/security_invariants.rs::declared_scope_skips_symlink_recheck`, `tests/scopes.rs::redirect_into_declared_scope_allows` |
| `#dynamic-arg` | A dynamic argument relaxes to Allow only for a literal command name that is safe regardless of its argument values | `src/analyzer_tests2.rs::dynamic_arg_only_still_allows_safe_command`, `src/analyzer_tests2.rs::dynamic_arg_mount_asks`, `src/analyzer_tests2.rs::dynamic_arg_pager_asks`, `src/analyzer_tests2.rs::dynamic_arg_fzf_asks`, `src/analyzer_tests2.rs::for_loop_dynamic_arg_handler_asks` |
| `#dynamic-arg` | Any other unresolvable word (an un-executed substitution) dominates that relaxation | `src/analyzer_tests2.rs::dynamic_arg_before_command_substitution_asks`, `src/analyzer_tests2.rs::dynamic_arg_before_process_substitution_asks`, `src/analyzer_tests2.rs::dynamic_arg_before_backtick_substitution_asks` |
| `#dynamic-arg` | `resolve_command_args` does not stop scanning at a `DynamicKnown` word, so a later `Unresolvable` is still recorded | `src/resolve_tests.rs::resolve_command_args_unresolvable_wins_over_later_dynamic`, `src/resolve_tests.rs::resolve_unresolvable_wins_over_dynamic_in_word` |
| `#heredoc-rable-26` | The manifest pins `rable >= 0.1.14` | `tests/ast_invariants.rs::rable_dependency_pinned_above_heredoc_fix` |
| `#heredoc-rable-26` | A quoted `HereDoc` node survives an unmatched `(` in its body inside `$(...)` | `tests/ast_invariants.rs::heredoc_in_cmdsub_produces_quoted_heredoc_node`, `tests/corner_cases.rs::heredoc_with_unmatched_paren_in_cmdsub_asks`, `tests/corner_cases.rs::heredoc_with_dangerous_unmatched_paren_in_cmdsub_asks` |
| `#heredoc-rable-26` | The safe-substitution conditions hold: `SIMPLE_SAFE` command, all redirects quoted heredocs, no word expansions | `src/analyzer_tests2.rs::safe_heredoc_in_command_substitution_allows`, `src/analyzer_tests2.rs::unquoted_heredoc_in_command_substitution_asks`, `src/analyzer_tests2.rs::unsafe_command_heredoc_in_substitution_asks`, `src/analyzer_tests2.rs::pipeline_in_heredoc_substitution_asks` |
| `#git-undeclared-repo` | A read-only git invocation against a repository outside every declared scope still Asks | `tests/scopes.rs::git_read_outside_any_scope_still_asks` |
| `#git-undeclared-repo` | A git write inside a declared scope still Asks | `tests/scopes.rs::git_write_in_declared_scope_still_asks` |
| `#non-ascii-inline-code` | Multi-byte inline source is classified instead of crashing the scanner, and a dangerous call inside it still Asks | `src/ruby_safety.rs::non_ascii_source_is_classified_without_panicking`, `src/perl_safety.rs::non_ascii_source_is_classified_without_panicking`, `tests/data/catalog/handlers_interpreters.toml` |
| `#non-ascii-inline-code` | The CTE skipper derives byte offsets, so multi-byte SQL is classified by its real main statement | `src/sql.rs::cte_with_non_ascii_body_is_classified_without_panicking`, `tests/data/catalog/handlers_text_system.toml` |
| `#non-ascii-inline-code` | A multi-byte sed delimiter is classified instead of panicking, and a `w`/`e` flag behind one is still caught | `src/handlers/text_tools.rs::non_ascii_sed_delimiter_is_classified_without_panicking`, `tests/data/catalog/handlers_text_system.toml` |
| `#non-ascii-inline-code` | A non-ASCII segment in a Claude Code permission rule is matched instead of panicking the wildcard walk | `src/cc_permissions.rs::non_ascii_rule_is_matched_without_panicking` |
| `#word-parts-trust` | A `Word` whose parts are all literal contains no expansion, even when its raw value has metacharacters | `tests/ast_invariants.rs::single_quoted_expansion_text_is_not_an_expansion`, `tests/data/catalog/safe_quoting.toml` |
| `#word-parts-trust` | Real expansions still produce expansion nodes, and the textual scan agrees on parts-less inputs | `tests/ast_invariants.rs::every_source_level_expansion_produces_expansion_node`, `tests/ast_invariants.rs::has_expansions_agrees_on_simple_inputs` |
| `#string-rule-chokepoint` | The whole-string check may only short-circuit an Allow for exactly one plain simple command | `tests/ast_invariants.rs::is_single_plain_command_matches_only_bare_simple_commands` |
| `#string-rule-chokepoint` | A trailing payload never rides along on a leading allow-ruled command (#155) | `tests/security_invariants.rs::allow_rule_does_not_short_circuit_chained_payload`, `tests/data/catalog/injection_string_rule_chokepoint.toml` |
| `#string-rule-chokepoint` | A chain or pipeline whose every leaf is individually allow-ruled still combines to Allow | `tests/security_invariants.rs::allow_ruled_leaves_combine_to_allow`, `tests/data/catalog/injection_string_rule_chokepoint.toml` |
| `#string-rule-chokepoint` | A deny/ask rule catches a leaf that is not the leading command | `tests/security_invariants.rs::deny_rule_matches_non_leading_leaf`, `tests/data/catalog/injection_string_rule_chokepoint.toml` |
| `#string-rule-chokepoint` | An allow-ruled leaf with a redirect still reaches `self_protect` and the safe-dir check | `tests/security_invariants.rs::allow_rule_leaf_with_redirect_still_self_protects`, `tests/data/catalog/injection_string_rule_chokepoint.toml` |
| `#string-rule-chokepoint` | The dangerous-env gate runs before `leaf_string_rule`, so a code-influencing prefix is never allow-listed | `tests/security_invariants.rs::env_prefix_dangerous_var_asks_even_when_command_is_allow_ruled`, `tests/data/catalog/injection_string_rule_chokepoint.toml` |
| `#string-rule-chokepoint` | A leaf carrying a word expansion skips the string match and is resolved first | `tests/ast_invariants.rs::is_single_plain_command_matches_only_bare_simple_commands`, `tests/data/catalog/injection_string_rule_chokepoint.toml` |
| `#inspect-delegation` | The explain path reports the analyzer's decision across the routing shapes the old parallel implementation got wrong | `src/inspect_tests.rs::trace_decision_matches_analyzer_across_spread`, `tests/inspect_delegation.rs::inspect_binary_agrees_with_hook_binary` |
| `#inspect-delegation` | A dangerous env prefix is not approved on the command name (#dangerous-env-name) | `src/inspect_tests.rs::trace_dangerous_env_prefix_is_not_allowed` |
| `#inspect-delegation` | A whole-string allow rule does not cover a compound command (#string-rule-chokepoint) | `src/inspect_tests.rs::trace_whole_string_allow_does_not_cover_compound`, `tests/inspect_delegation.rs::inspect_binary_agrees_on_a_whole_string_allow_rule` |
| `#inspect-delegation` | Rule `when` conditions are evaluated with a real `MatchContext`, so conditional rules fire | `src/inspect_tests.rs::trace_evaluates_rule_conditions`, `tests/inspect_delegation.rs::inspect_binary_agrees_on_a_conditional_rule` |
| `#inspect-delegation` | The rendered provenance names the same approval route as the verdict's `AllowReason` | `src/inspect_tests.rs::trace_provenance_matches_allow_reason`, `src/inspect_tests.rs::trace_provenance_names_the_approval_route` |
| `#inspect-delegation` | Every gate that can decide emits an event, so the trace never ends on a step contradicting the verdict | `src/inspect_tests.rs::trace_records_the_deciding_gate`, `src/inspect_tests.rs::trace_explains_every_non_allow_verdict` |
| `#inspect-delegation` | A withheld whole-string ALLOW is recorded as a non-match, never as a hit | `src/inspect_tests.rs::trace_env_prefix_pipeline_records_withheld_allow_rule` |
| `#parser-stack-bound` | Every unbounded lexer recursion is counted and refused past its limit | `src/nesting.rs::the_bounds_refuse_what_they_name` |
| `#parser-stack-bound` | No quoting the scan cannot interpret — comment, heredoc body, `$'\''`, a re-balanced stray quote — lowers a count | `src/nesting.rs::nothing_that_looks_like_quoting_hides_an_opener`, `tests/hook_fail_closed.rs::quoting_the_scanner_cannot_read_still_asks_instead_of_aborting` |
| `#parser-stack-bound` | Anything that can open a construct leaves the inline-parse path, so only a provably flat source parses on the caller's stack | `src/nesting.rs::every_construct_opener_leaves_the_flat_path`, `src/nesting.rs::ordinary_commands_open_nothing` |
| `#parser-stack-bound` | A flat statement chain is bounded too, since list elements recurse the same way | `src/nesting.rs::the_bounds_refuse_what_they_name`, `tests/hook_fail_closed.rs::a_flat_statement_chain_asks_instead_of_aborting` |
| `#parser-stack-bound` | Input past a bound comes back through the hook as a normal Ask, never an abort | `tests/hook_fail_closed.rs::deeply_nested_constructs_ask_instead_of_aborting` |
| `#parser-stack-bound` | Plain nesting carries no rippy bound, so the widest the input cap allows must still answer | `tests/hook_fail_closed.rs::the_widest_plain_nesting_the_input_cap_allows_still_answers` |
| `#parser-stack-bound` | Ordinary documents, scripts and nested commands are not refused for their shape | `src/nesting.rs::a_prose_document_stays_within_every_bound`, `src/nesting.rs::a_json_document_stays_within_every_bound`, `src/nesting.rs::a_long_script_stays_within_every_bound`, `tests/hook_fail_closed.rs::ordinary_documents_and_scripts_are_not_refused_for_their_shape`, `tests/hook_fail_closed.rs::a_legitimately_nested_command_still_gets_a_real_verdict` |
| `#parser-stack-bound` | A shape that would make the parser hang is refused, since a hook that never answers reads as one that failed | `src/nesting.rs::the_bounds_refuse_what_they_name`, `tests/hook_fail_closed.rs::shapes_that_would_hang_the_parser_ask_promptly` |
| `#empty-combine` | Combining an empty verdict set fails closed rather than returning the Allow default | `src/verdict.rs::combine_empty_fails_closed`, `src/verdict.rs::combine_of_allows_is_still_allow` |
| `#empty-combine` | An arithmetic context carrying a substitution is not approved by the arm that drops its expression | `tests/data/catalog/injection_constructs.toml` |
| `#empty-combine` | A redirect target is checked for substitutions in both directions, so the read shortcut cannot skip it | `tests/data/catalog/injection_expansion.toml` |

## env-prefix-strip

`Analyzer::analyze` normalizes a leading `NAME=VALUE` env prefix so the
string-matching config/CC layers see the real command (e.g. `cargo test`) rather
than the assignment token. `strip_env_prefix` keeps the rest of the command
verbatim (redirects, pipes, `&&` chains), refuses to strip when a value contains
an expansion, and refuses to strip code-influencing vars (`LD_PRELOAD`,
`GIT_SSH_COMMAND`, `NODE_OPTIONS`, ...). Consequence: no Allow rule can bypass the
analyzer's redirect or assignment-expansion guards via an env prefix. On
unparseable input we fall back to the raw string and the real parse error still
surfaces downstream.

## dangerous-env-name

Refusing to *strip* a code-influencing env prefix is not enough on its own: the
un-stripped command still lands on the analyzer, and if the command itself is
safe-listed (`cat`, `git fetch`, `bash -c :`, `perl`, `node`) the fast path would
Allow it with the dangerous assignment intact (issue #157). So `analyze_command`
enforces the gate directly — `Analyzer::dangerous_assignment_name` Asks on any
simple command carrying a literal assignment whose name matches
`ast::is_dangerous_env_name`, before the safe-command path or any handler runs.
The `env` handler applies the same check to the `NAME=VALUE` args it sets, since
delegating to the inner command alone would hide them.

**The polarity is inverted: a name is dangerous unless it is on an inert list.**
Enumerating dangerous names does not converge (#203). Every tool invents its own
variable for "where my config lives" or "which program to run", and each is the
twin of a flag guard — `--exec-path`/`GIT_EXEC_PATH`,
`--use-compress-program`/`TAR_OPTIONS`, `--pager`/`MANPAGER`. Two rounds of
enumeration shipped and were each then shown to miss a dozen more
(`CARGO_HOME`, `RUSTC`, `RUSTFLAGS`, `KUBECONFIG`, `PSQLRC`, `PERLLIB`,
`PYTHONHOME`, `NODE_PATH`, `LESSOPEN`, `DOCKER_CONFIG`, ...). The list of
*harmless* names is the one that can be closed, because it is a property of the
name rather than of every tool that might read it.

An unknown name therefore Asks once, against silent arbitrary code execution for
every variable rippy has not heard of. The inert list is an allow surface and is
pinned test-by-test; `PAGER`, `EDITOR`, `TMPDIR`, `LOCPATH`, `TERMINFO` and the
proxy variables all look harmless and are deliberately absent.

The prefix Ask is combined with the command's own verdict rather than returned
in its place. Short-circuiting would mask a `Deny` — `FOO=bar echo hi >
~/.rippy/config.toml` must stay Deny — and would replace a more specific reason
(`rm`, `shell expansion`) with a generic one.

GNU `env -S "STRING"` / `--split-string=STRING` (also the `-vS` short cluster)
reparses `STRING` as the whole command line. Because that payload arg contains
`=`, it otherwise looks like a bare `env` invocation and is auto-approved,
carrying both a dangerous env prefix (`env -S "LD_PRELOAD=x cat"`) and any
dangerous inner command (`env -S "X=1 rm -rf /"`) past every check. The handler
therefore extracts the split-string payload and `Recurse`s into it so the
dangerous-env gate and inner-command analysis both run. A short cluster whose
leading flags are not known booleans (e.g. `-uS`, where `-u` consumes an
argument) has an ambiguous option boundary and is treated as an empty payload so
the handler Asks rather than misparse.

`is_dangerous_env_name` covers the dynamic-linker families (`LD_*`, `DYLD_*`), a
fixed list of interpreter/shell hooks (`BASH_ENV`, `PERL5OPT`, `NODE_OPTIONS`,
`GIT_SSH_COMMAND`, ...), and two **prefix** families:

- `GIT_CONFIG*` — env-based git-config injection (git >= 2.31):
  `GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_n` / `GIT_CONFIG_VALUE_n` /
  `GIT_CONFIG_GLOBAL` / `GIT_CONFIG_SYSTEM` / `GIT_CONFIG_PARAMETERS` inject
  `core.pager` / `alias.*` / `core.hooksPath` that git executes during
  ordinarily-"safe" commands (the same vectors as #git-undeclared-repo, reachable
  purely from the environment).
- `BASH_FUNC_*` — exported-function injection (Shellshock family): a
  `BASH_FUNC_foo%%` binding defines a function that shadows a command name in a
  child bash.

A prefix match is used (rather than an exact enumeration) because these families
have per-index or per-name members (`GIT_CONFIG_KEY_0`, `BASH_FUNC_anything`); the
broad match may Ask on an unrelated variable that literally starts with
`GIT_CONFIG`, an accepted fail-closed trade-off. Ordinary build/CI prefixes
(`FOO`, `NODE_ENV`, `CI`, `RUST_LOG`, ...) are not matched and stay Allow.

## append-assignment-shadow

`push_literal_bindings` binds only literal `VAR=val` assignments. A `NAME+=VALUE`
append concatenates onto a value we cannot reconstruct (a shadowed literal, an
env var, or unknown), so we shadow the name as set-but-unknown (`Dynamic`) rather
than resolve a stale prior literal. Resolving the stale value could under-block if
the appended text made the real path/flag dangerous.

## fd-dup-remap

`analyze_redirect`: `&>`/`>&` parse as `FdDup`, but only bare-descriptor / close
targets (`2>&1`, `>&2`, `>&-`) are true fd operations. A path target
(`&> out.log`) is a *file write* and must run the same safety pipeline as `>`,
otherwise it would bypass self-protection, deny rules, and the safe-dir check. We
re-map such targets to `Write`.

## wrapper-redirects

`analyze_command_node`: unwrapping a `WRAPPER_COMMANDS` entry re-analyzes only
the inner *words*, and `analyze_inner_command` re-parses that joined string on
its own. The `>` target and any heredoc live on the OUTER `NodeKind::Command`'s
`redirects` slice, which the inner parse never sees. The whole write pipeline —
self-protection, deny rules, the safe-dir check, heredoc expansion — hangs off
`analyze_redirects`, so the branch must end in `with_redirects` or a wrapper
prefix strips all of it (#181: `ls > /etc/passwd` asked, `nice ls > /etc/passwd`
was approved). The no-inner-command path needs the same treatment: `nice >
/etc/passwd` is a write with no command at all.

`time` never had the bug because rable parses it as a keyword, leaving the
redirect on the outer node.

`wrapper_inner_args` strips a wrapper's own options before the unwrap. It is
`timeout`-only on purpose: `timeout` is the one wrapper with a mandatory
DURATION operand, and a generic "skip leading flags" rule would swallow the
path in `strace -o /etc/passwd ls`. An argv that does not match GNU timeout's
grammar (`timeout 1m30s ls`, `timeout --bogus 5 ls`) is deliberately analyzed
unchanged rather than guessed at, which keeps the fail-closed path where the
stray word reads as an unknown command.

## tmp-symlink

`is_safe_write_target` auto-approves writes only for statically-known targets that
resolve inside the trusted safe-dir set. It is conservative by construction: any
target whose runtime value we cannot know statically — shell expansions (`$VAR`,
`${...}`, `$(...)`, backticks), a leading `~`, or glob metacharacters — is
rejected so it keeps asking. Two extra guards:

- **cwd exclusion:** a target inside the working-directory subtree keeps asking
  even when the cwd itself lives under a safe dir (e.g. a checkout under `/tmp`),
  so project writes are never silently approved.
- **symlink re-check:** the world-writable default safe dirs (`/tmp`, `/var/tmp`)
  let an attacker plant a symlink, so for those the target's real path (deepest
  existing ancestor, canonicalized) must ALSO stay within the defaults — a
  redirect through `/tmp/evil -> /etc` is rejected. User-declared scopes are
  trusted opt-ins and skip this re-check.

## dynamic-arg

`try_resolve` / `dynamic_arg_verdict`: a set-but-unknown value in argument
position is never fabricated. We allow only if the literal command name is safe
regardless of its argument *values* (a pure reader/printer that cannot write,
spawn a shell, or execute based on an arg); every handler/wrapper/unknown command
with a dynamic argument stays Ask.

This relaxation is gated on `failure_reason.is_none()`: if *any* other word was
unresolvable — an un-executed command/process substitution such as
`echo $? $(rm -rf /)` — that Ask must dominate, or the substitution would run
un-analyzed. Correspondingly, `resolve_command_args` does NOT stop scanning at a
`DynamicKnown` word: a later `Unresolvable` word must still be recorded so it
dominates the dynamic-arg relaxation.

## heredoc-rable-26

`is_safe_heredoc_substitution`'s structural guarantees assume rable produces a
faithful AST for heredocs inside `$(...)`. That held unreliably before rable
0.1.14 (see rable issue #26): an unmatched `(` in a heredoc body could corrupt
paren tracking and drop the `HereDoc` node. Pin `rable >= 0.1.14`. The conditions
(`SIMPLE_SAFE` command + all redirects are quoted heredocs + no word-expansions)
are structurally tight; the 0.1.14 fix makes them *reliable*.

## git-undeclared-repo

A read-only git invocation against a repository outside every declared safe scope
(e.g. `git -C /opt/other log`) still Asks. The target repo's `.git/config` can
carry `core.fsmonitor`, alias, or hook directives that execute code on an
otherwise "read-only" command, so scope-widening must not silently approve it.
Tested by `tests/scopes.rs::git_read_outside_any_scope_still_asks`.

## non-ascii-inline-code

The inline-code scanners (`ruby_safety`, `perl_safety`) and the SQL CTE skipper
locate ASCII keywords by scanning `str::as_bytes()`. Every offset they derive
that way is a *byte* offset, and slicing a `str` at a byte offset that lands
inside a multi-byte UTF-8 sequence panics. A panic is a fail-open: the hook exits
without a verdict and the caller treats that as a non-blocking error, so
`ruby -e '%x+їd/'` executed unreviewed (#182). Keep these scanners byte-only
(compare `&bytes[..]` against `word.as_bytes()`), and where a byte offset must be
produced from a character walk, use `char_indices()` rather than
`chars().enumerate()`. Regression cases live in
`tests/data/catalog/handlers_interpreters.toml` and `handlers_text_system.toml`.

The same shape appears wherever an offset derived from bytes indexes a `str`, so
it is not confined to the inline-code scanners. Two further sites carried it: the
sed delimiter scan read the delimiter as a single byte (`cmd.as_bytes()[1]`), so a
multi-byte delimiter matched its own lead byte and produced a flags offset inside a
scalar; and the Claude Code permission matcher advanced `search_from += idx + 1`,
one byte past a boundary. When a scan must step past a match, step by
`char::len_utf8` or skip to the next `is_char_boundary`.

## word-parts-trust

`has_expansions_kind` trusts rable's parsed `parts` when present: rable decomposes
words into typed expansion nodes, so a `Word` whose parts are all literal (e.g.
`WordLiteral` for `'$(whoami)'`) contains no expansion even though its raw value
has metacharacters. The textual scan is only a fallback for synthetic words (e.g.
heredoc content) that carry no parts.

## string-rule-chokepoint

The string-match allow layers (`CcRules::check`, `Config::match_command`, and the
stdlib rules underneath) run on the whole raw command string and each only inspects
the *leading* command — a following `&&`/`;`/`|`/`` ` ``/`>` boundary satisfies their
"word boundary", so `cargo build && rm -rf ~` matched a leading `cargo` allow and
short-circuited before the AST walk ever ran (#155). A trailing payload thus rode
along on any allow-ruled command, and the redirect form also skipped `self_protect`.

The fix moves string-rule matching **into the per-leaf AST walk**. Two parts:

- The top-of-`analyze` whole-string check may only short-circuit an ALLOW when the
  tree is exactly one plain simple command (`ast::is_single_plain_command`); a
  chain/pipe/subst/redirect falls through. `Ask`/`Deny` still short-circuit there,
  since honoring a stronger decision early is always fail-closed.
- `analyze_command` then matches **each simple command (leaf)** against the string
  rules (`leaf_string_rule`) before the handler/allowlist path. The leaf is
  reconstructed from its own `words` only. `Verdict::combine` (most-restrictive)
  merges the leaves, so a chain whose every leaf is individually allow-ruled
  (`cargo fmt && cargo test`) is Allow — rippy's compound-safety value — while any
  dangerous leaf's Ask/Deny dominates, and a deny/ask rule now catches a leaf even
  when it is not the leading command.

Per-leaf matching is sound because the laundering vectors are closed:

- **Dangerous env prefix.** The `analyze_command` dangerous-env gate (see
  #dangerous-env-name) runs *before* `leaf_string_rule`, so a leaf carrying a
  code-influencing prefix (`LD_PRELOAD=`, `BASH_ENV=`, `PAGER=`, ...) Asks and is
  never allow-listed by a string rule — single or chained. The `env` handler and
  the `time`/`nohup`/`command` wrappers close the same laundering through
  recursion (see #dangerous-env-name).
- **Redirects.** `leaf_string_rule` routes an allow-ruled leaf through
  `with_redirects`, so `cargo build > ~/.rippy/config.toml` still reaches
  `self_protect`/safe-dir and Denies.
- **Expansions.** A leaf with a word expansion skips the string match and is
  resolved first (`try_resolve`); its re-analysis re-enters `analyze_command` on
  the literal form, so `cargo $X` cannot match a `cargo` rule before `$X` is known.

## inspect-delegation

The explain path (`rippy inspect <cmd>`, `rippy debug <cmd>`) must obtain its
decision **only** from `Analyzer::analyze`. It renders the trace events the
analyzer emits (`src/trace.rs`); it may never re-run CC/config matching,
re-classify parse shape, or short-circuit on the allowlist itself. A reviewer
reads `inspect` to understand what the hook did, so an explain path with its own
routing is a correctness bug, not a cosmetic one.

Before #167 `inspect` re-derived the routing and diverged on three live cases,
each of which reported `allow` while the hook did not:

- `LD_PRELOAD=/tmp/x ls` — the parallel `is_safe && !has_expansions`
  short-circuit approved on the command name, missing the dangerous-env gate
  (#dangerous-env-name); the hook Asks.
- `ls && rm -rf /` under an `allow "ls*"` rule — `inspect` applied the
  whole-string allow to a compound command, missing the single-plain-command
  gate (#string-rule-chokepoint); the hook Asks.
- Any rule with a `[rules.when.*]` condition — `inspect` called
  `Config::match_command` with a null `MatchContext`, so conditional rules never
  fired; the hook Denies.

#137 (inspect/debug disagreeing with the hook on compound commands) is the
historical form of the same failure. `src/inspect_tests.rs` and
`tests/inspect_delegation.rs` pin the invariant at the library and binary level.

Delegating the decision is only half of it: every gate that can *produce* a
decision must also emit an event, or the trace ends on an affirmative step that
contradicts the printed verdict (`echo x > /etc/passwd` once closed on
`Allowlist ✓ echo is in the simple-safe list` and then printed `ASK`). The
redirect pipeline (`Stage::Redirect`), the dangerous / expanding env prefix
(`Stage::EnvPrefix`) and the dynamic-argument allow (`Stage::Expansion`)
therefore each record their own verdict. `matched` means *this layer decided*,
so a whole-string ALLOW withheld by #string-rule-chokepoint is recorded as a
non-match with a "not applied" detail — never as a hit.

## parser-stack-bound

rable parses by recursive descent: one stack frame per open construct
(`case`/`for`/`if`/`{`/`(`/`$(`) and per element of a `;`/`&&`/`|` list. The
analyzer's own limits (`MAX_DEPTH` 256, `MAX_NODES` 10 000) only apply to a tree
that already exists, so a command of ~250 nested constructs — or ~15 000 flat
statements — overflowed the main thread's stack *during parsing* (#195).

That is a fail-open, not a crash-bug: a stack overflow **aborts** the process
instead of unwinding, so `fail_closed`'s `catch_unwind` net (#182) cannot
convert it into an Ask. The hook died with exit 134 and an empty stdout, which
the calling agent reads as a non-blocking hook failure — an auto-approval.

Two things prevent it.

**The parse runs on a 256 MB stack.** `parser::parse_on_a_deep_stack` hands the
source to a scoped thread sized for the bounds below. rable stops its own
descent at `MAX_DEPTH` 1 000 frames, which the most expensive construct (`case`)
needs about 16 MB for, so with that stack no amount of `(`, `{`, backtick, `[[`
or `if`/`for`/`case` nesting can overflow — measured up to the widest such input
the 1 MB stdin cap can carry. Those constructs therefore carry no rippy bound at
all, which is why a heredoc full of prose is no longer refused for containing
English `if`s and unbalanced parens. A source that opens no construct at all
skips the thread and parses inline.

**`nesting::Shape` bounds what rable does not.** rable's `MAX_DEPTH` does not
reach its *lexer's* substitution or brace-expansion work, so four shapes are
counted and refused: `$(`/`<(`/`>(` at 128 (nesting them is super-linear — 128
takes 0.5 s, 384 takes 37 s — and 16 384 overflow 256 MB), `${` at 4 096
(~131 000 overflow), `{` at 8 192 (unclosed `{a,` costs the brace count times the
input length: 8 192 takes 0.74 s, 50 000 takes 29 s), and runs of `;`/`&`/`|`/
newline at 16 384 (~262 000 overflow). A hang is as much a fail-open as an abort
— the agent reads a hook that never answers as a hook that failed — so the cost
bounds sit alongside the stack ones. Exceeding one yields
`RippyError::TooComplex`, which `Analyzer::analyze` renders as the ordinary
fail-closed Ask, so a whole-string Deny/Ask rule still takes precedence.

The scan is a genuine **over**-approximation: it skips nothing and never cancels
a count against a closer. The first fix for #195 tried to lex quoting so it
could skip quoted spans, and every construct that a scanner must interpret —
an apostrophe in a `#` comment, a quote in a heredoc body, `\'` inside `$'…'`,
a stray quote re-balanced later in the string — desynced it into skipping the
nesting it existed to measure, restoring the abort. Counting openers and never
matching a closer needs no such interpretation, so no input, however malformed,
can make a count come out low.


## empty-combine

`Verdict::combine` on an empty slice means the caller analyzed nothing. That is
an error state, not a safe one: it is exactly what a node arm produces when its
meaningful fields were discarded by `..`. Returning `Verdict::default()` there —
an Allow with a blank reason — approved `(( $(rm -rf /) ))` and every other arm
with the same shape, so the empty case now fails closed to Ask.

A caller whose construct is genuinely inert states its own Allow instead of
inheriting one: `case x in y) ;; esac` and `(( i = 1 ))` run nothing, and saying
so at the call site keeps the combinator free to treat emptiness as the bug it
usually is. The arms that dropped an executing expression — `ArithmeticCommand`,
`ForArith`, and the input-redirect shortcut — read their raw text instead,
because rable does not descend into arithmetic for a nested substitution.