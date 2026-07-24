# Security invariants

Load-bearing safety rationale for rippy's analyzer core. Inline comments in the
source point here with `see docs/security-invariants.md#<anchor>`. When changing
the referenced code, keep this document in sync — these are the reasons the tool
fails **closed** (Ask/Deny) rather than open (Allow).

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
Tested by `git_read_outside_any_scope_still_asks` in `tests/scopes.rs`.

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

Per-leaf matching is sound because the two laundering vectors are closed:

- **Dangerous env prefix.** A leaf whose `assignments` set a code-influencing var
  (`LD_PRELOAD=`, `BASH_ENV=`, ...; `ast::assignment_is_dangerous_env`) is excluded
  from `leaf_string_rule`, mirroring `strip_env_prefix`'s refusal to strip such
  prefixes. The `env` handler likewise refuses to recurse-launder a bare inner
  command when it sets such a var (`env LD_PRELOAD=… cargo test` → Ask), and the
  `time`/`nohup`/`command` wrappers preserve the prefix as text so it re-parses as
  an assignment on the recursed leaf.
- **Redirects.** `leaf_string_rule` routes an allow-ruled leaf through
  `with_redirects`, so `cargo build > ~/.rippy/config.toml` still reaches
  `self_protect`/safe-dir and Denies.
- **Expansions.** A leaf with a word expansion skips the string match and is
  resolved first (`try_resolve`); its re-analysis re-enters `analyze_command` on
  the literal form, so `cargo $X` cannot match a `cargo` rule before `$X` is known.
