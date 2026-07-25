<!-- GENERATED FILE — do not edit by hand. -->
<!-- Regenerate with: RIPPY_UPDATE_ALLOW_CATALOG=1 cargo test --test allow_catalog -->

# rippy allow catalog

Every way rippy can decide `allow` without asking you, grouped by why.

**How far the guarantee goes.** The handler sections are what each handler
*declares* as its allow surface, not a proof about its code.
`tests/allow_catalog.rs` fails when this file drifts from those declarations,
and it checks both directions: every literal surface listed here must really be
approved by the analyzer, and each declared namespace is probed with a set of
mutation verbs so an approval a handler grants without declaring it also fails.
The probe vocabulary is finite, so treat a missing row as *not declared* rather
than as a proof that nothing else is approved.

**What this file is not.** Handlers that judge *content* — inline `python -c`
code, a `sed` script, the SQL behind `psql -c` — are listed by the invocation
shape that reaches the analyzer, not by which programs that analyzer accepts.
For those, the `Condition` column names the module that decides.

## Contents

- [Command-name allowlists](#command-name-allowlists)
- [Dynamic-argument relaxation](#dynamic-argument-relaxation)
- [Handler surfaces](#handler-surfaces)
- [Rule bundles](#rule-bundles)
- [Redirect targets](#redirect-targets)
- [Structural approvals](#structural-approvals)
- [User-controlled (not shipped)](#user-controlled-not-shipped)

## Command-name allowlists

Commands approved on their name alone, regardless of arguments.

### `SIMPLE_SAFE` — 131 commands

Approved on the command name alone, whatever the arguments.

`:`, `[`, `ag`, `apropos`, `arch`, `base32`, `base64`, `basename`, `bat`, `bc`, `blkid`, `bzcat`, `cat`, `cksum`, `cloc`, `column`, `comm`, `cut`, `date`, `df`, `diff`, `dig`, `dirname`, `dos2unix`, `du`, `echo`, `exa`, `expand`, `expr`, `eza`, `false`, `file`, `findmnt`, `fmt`, `fold`, `free`, `fzf`, `getconf`, `getent`, `grep`, `groups`, `head`, `help`, `hexdump`, `host`, `hostname`, `htop`, `hyperfine`, `iconv`, `id`, `info`, `iostat`, `join`, `jq`, `ldd`, `less`, `locale`, `locate`, `ls`, `lsb_release`, `lsblk`, `lsd`, `lsof`, `man`, `md5sum`, `more`, `mount`, `netstat`, `nl`, `nm`, `nproc`, `nslookup`, `objdump`, `od`, `otool`, `paste`, `pgrep`, `ping`, `printenv`, `printf`, `ps`, `pwd`, `readelf`, `readlink`, `realpath`, `rev`, `rg`, `scc`, `seq`, `sha1sum`, `sha256sum`, `sha512sum`, `shuf`, `size`, `sleep`, `ss`, `stat`, `strings`, `stty`, `sum`, `tac`, `tail`, `test`, `tldr`, `tokei`, `top`, `tput`, `tr`, `tracepath`, `traceroute`, `tree`, `true`, `tty`, `type`, `uname`, `unexpand`, `uniq`, `unix2dos`, `uptime`, `vmstat`, `wc`, `whatis`, `whence`, `whereis`, `which`, `whoami`, `xxd`, `xzcat`, `yes`, `zcat`, `zstdcat`

### Wrappers — 8 commands

Approved only with no inner command; otherwise the inner command is analyzed in their place. The wrapper's own redirects and heredocs are still evaluated, so `nice ls > /etc/passwd` asks. For `timeout`, its options and the mandatory DURATION are skipped first; an argv that does not match that grammar is analyzed unchanged, so the stray word reads as an unknown command.

`builtin`, `command`, `ltrace`, `nice`, `nohup`, `strace`, `time`, `timeout`

### Sole help/version flag

Any command whose *only* argument is one of `--help`, `--version` is approved. Short forms (`-h`, `-V`) are excluded: commands overload them.

## Dynamic-argument relaxation

Which allowlist commands stay approved when an argument is set but unknown.

When an argument is set but its value is unknown (a loop variable, a glob match), an allowlist command stays approved — except for these 7, whose behavior an argument can change dangerously:

`fzf`, `info`, `less`, `man`, `more`, `mount`, `stty`

With a *literal* argument these are still approved by the allowlist above.

## Handler surfaces

Per-command handlers: the exact invocations each one auto-approves.

45 handlers. A handler that only re-analyzes an inner command or asks declares an empty surface, which is itself listed below.

### `ansible`, `ansible-playbook`, `ansible-vault`, `ansible-galaxy`, `ansible-config`, `ansible-inventory`, `ansible-doc`, `ansible-lint`

Rows are written with `ansible`; unless a row says otherwise they apply the same way to every command name in this heading.

| Approved invocation | Condition |
| --- | --- |
| `ansible-doc` | — |
| `ansible-lint` | — |
| `ansible` | one of --check/-C/--list-hosts present |
| `ansible-playbook` | one of --check/-C/--syntax-check/--list-hosts/--list-tasks/--list-tags present |
| `ansible-vault view` | — |
| `ansible-inventory` | one of --list/--graph/--host present, and either no inventory operand or one ending in .ini/.yaml/.yml/.json |
| `ansible-galaxy list` | — |
| `ansible-galaxy search` | — |
| `ansible-galaxy info` | — |
| `ansible-config list` | — |
| `ansible-config dump` | — |
| `ansible-config view` | — |

### `awk`, `gawk`, `mawk`, `nawk`

Rows are written with `awk`; unless a row says otherwise they apply the same way to every command name in this heading.

| Approved invocation | Condition |
| --- | --- |
| `awk <program> [<file>...]` | no system() call, pipe-to-command or file redirect in the program |
| `awk -f <script>` | script readable from the working directory; no system() call, pipe-to-command or file redirect in the program |

### `aws`

| Approved invocation | Condition |
| --- | --- |
| `aws --help\|--version` | sole argument |
| `aws <service> ls` | any --endpoint-url must point at localhost |
| `aws <service> wait` | any --endpoint-url must point at localhost |
| `aws <service> help` | any --endpoint-url must point at localhost |
| `aws <service> query` | any --endpoint-url must point at localhost |
| `aws <service> scan` | any --endpoint-url must point at localhost |
| `aws <service> tail` | any --endpoint-url must point at localhost |
| `aws <service> receive-message` | any --endpoint-url must point at localhost |
| `aws <service> batch-get-item` | any --endpoint-url must point at localhost |
| `aws <service> transact-get-items` | any --endpoint-url must point at localhost |
| `aws <service> describe-*` | any --endpoint-url must point at localhost; `get-login-password` is excluded |
| `aws <service> list-*` | any --endpoint-url must point at localhost; `get-login-password` is excluded |
| `aws <service> get-*` | any --endpoint-url must point at localhost; `get-login-password` is excluded |
| `aws <service> show-*` | any --endpoint-url must point at localhost; `get-login-password` is excluded |
| `aws <service> head-*` | any --endpoint-url must point at localhost; `get-login-password` is excluded |
| `aws <service> lookup-*` | any --endpoint-url must point at localhost; `get-login-password` is excluded |
| `aws <service> filter-*` | any --endpoint-url must point at localhost; `get-login-password` is excluded |
| `aws <service> validate-*` | any --endpoint-url must point at localhost; `get-login-password` is excluded |
| `aws <service> estimate-*` | any --endpoint-url must point at localhost; `get-login-password` is excluded |
| `aws <service> simulate-*` | any --endpoint-url must point at localhost; `get-login-password` is excluded |
| `aws <service> generate-*` | any --endpoint-url must point at localhost; `get-login-password` is excluded |
| `aws <service> download-*` | any --endpoint-url must point at localhost; `get-login-password` is excluded |
| `aws <service> detect-*` | any --endpoint-url must point at localhost; `get-login-password` is excluded |
| `aws <service> test-*` | any --endpoint-url must point at localhost; `get-login-password` is excluded |
| `aws <service> check-if-*` | any --endpoint-url must point at localhost; `get-login-password` is excluded |
| `aws <service> admin-get-*` | any --endpoint-url must point at localhost; `get-login-password` is excluded |
| `aws <service> admin-list-*` | any --endpoint-url must point at localhost; `get-login-password` is excluded |
| `aws configure list` | any --endpoint-url must point at localhost |
| `aws configure list-profiles` | any --endpoint-url must point at localhost |
| `aws configure get` | any --endpoint-url must point at localhost |
| `aws configure` | any --endpoint-url must point at localhost |
| `aws sts get-caller-identity` | any --endpoint-url must point at localhost |
| `aws sts get-session-token` | any --endpoint-url must point at localhost |
| `aws sts get-access-key-info` | any --endpoint-url must point at localhost |
| `aws sts decode-authorization-message` | any --endpoint-url must point at localhost |

### `az`

| Approved invocation | Condition |
| --- | --- |
| `az --help\|-h\|--version` | sole argument |
| `az <group>... show` | no mutating verb anywhere in the command path |
| `az <group>... list` | no mutating verb anywhere in the command path |
| `az <group>... get` | no mutating verb anywhere in the command path |
| `az <group>... exists` | no mutating verb anywhere in the command path |
| `az <group>... query` | no mutating verb anywhere in the command path |
| `az <group>... logs` | no mutating verb anywhere in the command path |
| `az <group>... check-health` | no mutating verb anywhere in the command path |
| `az <group>... download` | no mutating verb anywhere in the command path |
| `az <group>... tail` | no mutating verb anywhere in the command path |
| `az <group>... list-*` | no mutating verb anywhere in the command path |
| `az <group>... show-*` | no mutating verb anywhere in the command path |
| `az <group>... get-*` | no mutating verb anywhere in the command path |

### `bash`, `sh`, `zsh`, `dash`, `ksh`, `fish`

Rows are written with `bash`; unless a row says otherwise they apply the same way to every command name in this heading.

Delegates only — approves nothing directly.

### `black`

| Approved invocation | Condition |
| --- | --- |
| `black --check\|--diff` | — |

### `cd`, `pushd`, `popd`

Rows are written with `cd`; unless a row says otherwise they apply the same way to every command name in this heading.

| Approved invocation | Condition |
| --- | --- |
| `cd\|pushd -` | not a remote (docker/kubectl exec) context |
| `cd\|pushd <path>` | local context, no `$`/backtick expansion, no leading `~`, and the normalized target is inside the cwd, a declared safe scope, or a default safe directory |

### `curl`

| Approved invocation | Condition |
| --- | --- |
| `curl --help\|-h\|--version\|-V` | sole argument |
| `curl <url>` | no request body flag (-d --data --data-raw --data-binary --data-urlencode --data-ascii -F --form -T --upload-file --json), no -X/--request with POST/PUT/DELETE/PATCH, no -K/--config, and no server-named output flag (-O, -J, --remote-name, --remote-name-all, --remote-header-name, --output-dir); an -o/--output target runs the redirect pipeline |

### `dmesg`

| Approved invocation | Condition |
| --- | --- |
| `dmesg` | no -c/-C/--clear |

### `docker`, `docker-compose`, `podman`, `podman-compose`

Rows are written with `docker`; unless a row says otherwise they apply the same way to every command name in this heading.

| Approved invocation | Condition |
| --- | --- |
| `docker version` | — |
| `docker help` | — |
| `docker info` | — |
| `docker ps` | — |
| `docker images` | — |
| `docker inspect` | — |
| `docker logs` | — |
| `docker stats` | — |
| `docker top` | — |
| `docker port` | — |
| `docker diff` | — |
| `docker history` | — |
| `docker search` | — |
| `docker events` | — |
| `docker image ls` | — |
| `docker image list` | — |
| `docker image inspect` | — |
| `docker image df` | — |
| `docker image history` | — |
| `docker image events` | — |
| `docker image info` | — |
| `docker image show` | — |
| `docker system ls` | — |
| `docker system list` | — |
| `docker system inspect` | — |
| `docker system df` | — |
| `docker system history` | — |
| `docker system events` | — |
| `docker system info` | — |
| `docker system show` | — |
| `docker network ls` | — |
| `docker network list` | — |
| `docker network inspect` | — |
| `docker network df` | — |
| `docker network history` | — |
| `docker network events` | — |
| `docker network info` | — |
| `docker network show` | — |
| `docker volume ls` | — |
| `docker volume list` | — |
| `docker volume inspect` | — |
| `docker volume df` | — |
| `docker volume history` | — |
| `docker volume events` | — |
| `docker volume info` | — |
| `docker volume show` | — |
| `docker config ls` | — |
| `docker config list` | — |
| `docker config inspect` | — |
| `docker config df` | — |
| `docker config history` | — |
| `docker config events` | — |
| `docker config info` | — |
| `docker config show` | — |
| `docker context ls` | — |
| `docker context list` | — |
| `docker context inspect` | — |
| `docker context df` | — |
| `docker context history` | — |
| `docker context events` | — |
| `docker context info` | — |
| `docker context show` | — |
| `docker compose ps` | — |
| `docker compose logs` | — |
| `docker compose config` | — |
| `docker compose images` | — |
| `docker compose ls` | — |
| `docker compose top` | — |
| `docker compose version` | — |
| `docker compose port` | — |
| `docker compose events` | — |
| `docker-compose ps` | — |
| `docker-compose logs` | — |
| `docker-compose config` | — |
| `docker-compose images` | — |
| `docker-compose ls` | — |
| `docker-compose top` | — |
| `docker-compose version` | — |
| `docker-compose port` | — |
| `docker-compose events` | — |
| `docker export` | no -o/--output; with one, the target runs the redirect pipeline |
| `docker save` | no -o/--output; with one, the target runs the redirect pipeline |
| `docker --help\|-h\|--version` | sole argument |

### `env`

| Approved invocation | Condition |
| --- | --- |
| `env [NAME=VALUE]...` | no inner command, no -S/--split-string, and no assignment to a code-influencing variable (see docs/security-invariants.md#dangerous-env-name) |

### `fd`

| Approved invocation | Condition |
| --- | --- |
| `fd <pattern>` | no -x/--exec or -X/--exec-batch |

### `find`

| Approved invocation | Condition |
| --- | --- |
| `find <path> <expression>` | no -delete, -ok/-okdir, -fprint/-fprint0/-fprintf/-fls, -exec or -execdir |

### `gcloud`, `gsutil`

Rows are written with `gcloud`; unless a row says otherwise they apply the same way to every command name in this heading.

| Approved invocation | Condition |
| --- | --- |
| `gcloud --help\|-h\|--version` | sole argument |
| `gsutil --help\|-h\|--version` | sole argument |
| `gcloud <group>... describe` | no mutating verb anywhere in the command path; a leading `alpha`/`beta` is skipped |
| `gcloud <group>... list` | no mutating verb anywhere in the command path; a leading `alpha`/`beta` is skipped |
| `gcloud <group>... get` | no mutating verb anywhere in the command path; a leading `alpha`/`beta` is skipped |
| `gcloud <group>... show` | no mutating verb anywhere in the command path; a leading `alpha`/`beta` is skipped |
| `gcloud <group>... info` | no mutating verb anywhere in the command path; a leading `alpha`/`beta` is skipped |
| `gcloud <group>... status` | no mutating verb anywhere in the command path; a leading `alpha`/`beta` is skipped |
| `gcloud <group>... version` | no mutating verb anywhere in the command path; a leading `alpha`/`beta` is skipped |
| `gcloud <group>... get-credentials` | no mutating verb anywhere in the command path; a leading `alpha`/`beta` is skipped |
| `gcloud <group>... list-tags` | no mutating verb anywhere in the command path; a leading `alpha`/`beta` is skipped |
| `gcloud <group>... read` | no mutating verb anywhere in the command path; a leading `alpha`/`beta` is skipped |
| `gcloud <group>... configurations` | no mutating verb anywhere in the command path; a leading `alpha`/`beta` is skipped |
| `gsutil ls` | — |
| `gsutil cat` | — |
| `gsutil stat` | — |
| `gsutil du` | — |
| `gsutil hash` | — |
| `gsutil version` | — |
| `gsutil help` | — |

### `gh`

| Approved invocation | Condition |
| --- | --- |
| `gh --help\|-h\|--version` | sole argument |
| `gh api <endpoint>` | no -X/--method in POST/PUT/DELETE/PATCH, no field flag (-f -F --raw-field --field) outside a GraphQL query, and no `mutation` in a field value |
| `gh api <endpoint> --input <file>` | no -X/--method in POST/PUT/DELETE/PATCH, no field flag (-f -F --raw-field --field) outside a GraphQL query, and no `mutation` in a field value; the file is readable and contains no GraphQL mutation |
| `gh status` | — |
| `gh browse` | — |
| `gh search` | — |
| `gh completion` | — |
| `gh help` | — |
| `gh pr view` | — |
| `gh pr list` | — |
| `gh pr status` | — |
| `gh pr diff` | — |
| `gh pr checks` | — |
| `gh pr search` | — |
| `gh pr download` | — |
| `gh pr watch` | — |
| `gh pr verify` | — |
| `gh pr logs` | — |
| `gh pr ports` | — |
| `gh issue view` | — |
| `gh issue list` | — |
| `gh issue status` | — |
| `gh issue diff` | — |
| `gh issue checks` | — |
| `gh issue search` | — |
| `gh issue download` | — |
| `gh issue watch` | — |
| `gh issue verify` | — |
| `gh issue logs` | — |
| `gh issue ports` | — |
| `gh release view` | — |
| `gh release list` | — |
| `gh release status` | — |
| `gh release diff` | — |
| `gh release checks` | — |
| `gh release search` | — |
| `gh release download` | — |
| `gh release watch` | — |
| `gh release verify` | — |
| `gh release logs` | — |
| `gh release ports` | — |
| `gh repo view` | — |
| `gh repo list` | — |
| `gh repo status` | — |
| `gh repo diff` | — |
| `gh repo checks` | — |
| `gh repo search` | — |
| `gh repo download` | — |
| `gh repo watch` | — |
| `gh repo verify` | — |
| `gh repo logs` | — |
| `gh repo ports` | — |
| `gh run view` | — |
| `gh run list` | — |
| `gh run status` | — |
| `gh run diff` | — |
| `gh run checks` | — |
| `gh run search` | — |
| `gh run download` | — |
| `gh run watch` | — |
| `gh run verify` | — |
| `gh run logs` | — |
| `gh run ports` | — |
| `gh workflow view` | — |
| `gh workflow list` | — |
| `gh workflow status` | — |
| `gh workflow diff` | — |
| `gh workflow checks` | — |
| `gh workflow search` | — |
| `gh workflow download` | — |
| `gh workflow watch` | — |
| `gh workflow verify` | — |
| `gh workflow logs` | — |
| `gh workflow ports` | — |
| `gh gist view` | — |
| `gh gist list` | — |
| `gh gist status` | — |
| `gh gist diff` | — |
| `gh gist checks` | — |
| `gh gist search` | — |
| `gh gist download` | — |
| `gh gist watch` | — |
| `gh gist verify` | — |
| `gh gist logs` | — |
| `gh gist ports` | — |
| `gh project view` | — |
| `gh project list` | — |
| `gh project status` | — |
| `gh project diff` | — |
| `gh project checks` | — |
| `gh project search` | — |
| `gh project download` | — |
| `gh project watch` | — |
| `gh project verify` | — |
| `gh project logs` | — |
| `gh project ports` | — |
| `gh label view` | — |
| `gh label list` | — |
| `gh label status` | — |
| `gh label diff` | — |
| `gh label checks` | — |
| `gh label search` | — |
| `gh label download` | — |
| `gh label watch` | — |
| `gh label verify` | — |
| `gh label logs` | — |
| `gh label ports` | — |
| `gh codespace view` | — |
| `gh codespace list` | — |
| `gh codespace status` | — |
| `gh codespace diff` | — |
| `gh codespace checks` | — |
| `gh codespace search` | — |
| `gh codespace download` | — |
| `gh codespace watch` | — |
| `gh codespace verify` | — |
| `gh codespace logs` | — |
| `gh codespace ports` | — |
| `gh secret view` | — |
| `gh secret list` | — |
| `gh secret status` | — |
| `gh secret diff` | — |
| `gh secret checks` | — |
| `gh secret search` | — |
| `gh secret download` | — |
| `gh secret watch` | — |
| `gh secret verify` | — |
| `gh secret logs` | — |
| `gh secret ports` | — |
| `gh variable view` | — |
| `gh variable list` | — |
| `gh variable status` | — |
| `gh variable diff` | — |
| `gh variable checks` | — |
| `gh variable search` | — |
| `gh variable download` | — |
| `gh variable watch` | — |
| `gh variable verify` | — |
| `gh variable logs` | — |
| `gh variable ports` | — |

### `git`

| Approved invocation | Condition |
| --- | --- |
| `git` | no subcommand; -C/--git-dir/--work-tree must stay in the cwd or a declared safe scope, and any -c/--config-env key must be on the safe config-key list |
| `git -c <key>=<value> <subcommand>` | gate only, not an approval — the key must be one of user.name, user.email, color.ui, core.autocrlf, core.quotepath, init.defaultbranch, pull.rebase, advice.detachedhead, and the `<subcommand>` still has to be approved by its own row |
| `git status` | — |
| `git log` | — |
| `git show` | — |
| `git diff` | no --ext-diff; an --output target runs the redirect pipeline |
| `git blame` | — |
| `git annotate` | — |
| `git shortlog` | — |
| `git describe` | — |
| `git rev-parse` | — |
| `git rev-list` | — |
| `git reflog` | — |
| `git whatchanged` | — |
| `git diff-tree` | — |
| `git diff-files` | — |
| `git diff-index` | — |
| `git range-diff` | — |
| `git format-patch` | an -o/--output-directory target runs the redirect pipeline |
| `git difftool` | no -x/--extcmd |
| `git grep` | no -O/--open-files-in-pager |
| `git ls-files` | — |
| `git ls-tree` | — |
| `git ls-remote` | — |
| `git cat-file` | — |
| `git verify-commit` | — |
| `git verify-tag` | — |
| `git name-rev` | — |
| `git merge-base` | — |
| `git show-ref` | — |
| `git show-branch` | — |
| `git check-ignore` | — |
| `git cherry` | — |
| `git for-each-ref` | — |
| `git count-objects` | — |
| `git fsck` | — |
| `git var` | — |
| `git request-pull` | — |
| `git archive` | an -o/--output target runs the redirect pipeline |
| `git fetch` | no URL-like or scp-like remote operand |
| `git version` | — |
| `git help` | — |
| `git branch` | none of -d -D -m -M -c -C --set-upstream-to |
| `git tag` | no positional tag name and none of -d --delete |
| `git remote show` | — |
| `git remote get-url` | — |
| `git remote` | — |
| `git stash list` | — |
| `git stash show` | — |
| `git notes list` | — |
| `git notes show` | — |
| `git notes` | — |
| `git bisect log` | — |
| `git bisect visualize` | — |
| `git bisect view` | — |
| `git lfs fetch` | — |
| `git lfs ls-files` | — |
| `git lfs status` | — |
| `git lfs env` | — |
| `git lfs version` | — |
| `git config` | one of --get --get-all --list -l --get-regexp present, or at most one argument (bare `git config` included) and none of --unset --add --edit --replace-all |

### `gzip`, `gunzip`

Rows are written with `gzip`; unless a row says otherwise they apply the same way to every command name in this heading.

| Approved invocation | Condition |
| --- | --- |
| `gzip --stdout` | — |
| `gzip -c` | — |
| `gzip --list` | — |
| `gzip -l` | — |
| `gzip --test` | — |
| `gzip -t` | — |
| `gzip --help\|-h\|--version\|-V` | sole argument |

### `helm`

| Approved invocation | Condition |
| --- | --- |
| `helm completion` | — |
| `helm env` | — |
| `helm get` | — |
| `helm help` | — |
| `helm history` | — |
| `helm lint` | — |
| `helm list` | — |
| `helm ls` | — |
| `helm search` | — |
| `helm show` | — |
| `helm inspect` | — |
| `helm status` | — |
| `helm template` | — |
| `helm verify` | — |
| `helm version` | — |
| `helm install` | --dry-run present |
| `helm upgrade` | --dry-run present |
| `helm uninstall` | --dry-run present |
| `helm rollback` | --dry-run present |
| `helm dependency list` | — |
| `helm dependency update` | — |
| `helm dependency build` | — |
| `helm repo list` | — |
| `helm plugin list` | — |
| `helm --help\|-h\|--version` | sole argument |

### `ifconfig`

| Approved invocation | Condition |
| --- | --- |
| `ifconfig <interface>` | at most one positional operand (more means a config change) |

### `ip`

| Approved invocation | Condition |
| --- | --- |
| `ip <object> <action>` | action not one of add del delete change set flush replace |

### `just`

| Approved invocation | Condition |
| --- | --- |
| `just --list` | the flag appears in the leading run of flags, before any recipe name |
| `just -l` | the flag appears in the leading run of flags, before any recipe name |
| `just --summary` | the flag appears in the leading run of flags, before any recipe name |
| `just --dump` | the flag appears in the leading run of flags, before any recipe name |
| `just --variables` | the flag appears in the leading run of flags, before any recipe name |
| `just --evaluate` | the flag appears in the leading run of flags, before any recipe name |
| `just --show` | the flag appears in the leading run of flags, before any recipe name |
| `just -s` | the flag appears in the leading run of flags, before any recipe name |

### `kubectl`, `k`

Rows are written with `kubectl`; unless a row says otherwise they apply the same way to every command name in this heading.

| Approved invocation | Condition |
| --- | --- |
| `kubectl get` | — |
| `kubectl describe` | — |
| `kubectl explain` | — |
| `kubectl logs` | — |
| `kubectl top` | — |
| `kubectl cluster-info` | — |
| `kubectl version` | — |
| `kubectl api-resources` | — |
| `kubectl api-versions` | — |
| `kubectl auth` | — |
| `kubectl wait` | — |
| `kubectl diff` | — |
| `kubectl plugin` | — |
| `kubectl completion` | — |
| `kubectl kustomize` | — |
| `kubectl config view` | — |
| `kubectl config current-context` | — |
| `kubectl config get-contexts` | — |
| `kubectl config get-clusters` | — |
| `kubectl config get-users` | — |
| `kubectl config get-context` | — |
| `kubectl --help\|-h\|--version` | sole argument |

### `mise`

| Approved invocation | Condition |
| --- | --- |
| `mise ls` | — |
| `mise list` | — |
| `mise current` | — |
| `mise doctor` | — |
| `mise dr` | — |
| `mise env` | — |
| `mise where` | — |
| `mise which` | — |
| `mise bin-paths` | — |
| `mise ls-remote` | — |
| `mise version` | — |
| `mise tasks [<child>]` | child not one of run r add edit |

### `mkdir`

| Approved invocation | Condition |
| --- | --- |
| `mkdir <path>...` | local context, at least one target, and every target normalizes inside the cwd, a declared safe scope, or a default safe directory |

### `mktemp`

| Approved invocation | Condition |
| --- | --- |
| `mktemp -u` | — |

### `mysql`

| Approved invocation | Condition |
| --- | --- |
| `mysql --help\|--version\|-V` | sole argument |
| `mysql -e\|--execute <sql>` | statement classified read-only by src/sql.rs |

### `node`, `nodejs`, `deno`

Rows are written with `node`; unless a row says otherwise they apply the same way to every command name in this heading.

| Approved invocation | Condition |
| --- | --- |
| `node\|nodejs\|deno --version\|-v\|-V\|--help\|-h` | sole argument |
| `node -e\|--eval\|-p\|--print <code>` | source passes the analysis in src/node_safety.rs |
| `deno eval <code>` | source passes the analysis in src/node_safety.rs |
| `node <script>` | script readable from the working directory and its source passes the analysis in src/node_safety.rs |

### `npm`, `npx`, `yarn`, `pnpm`, `bun`

Rows are written with `npm`; unless a row says otherwise they apply the same way to every command name in this heading.

| Approved invocation | Condition |
| --- | --- |
| `npm list` | — |
| `npm ls` | — |
| `npm ll` | — |
| `npm la` | — |
| `npm info` | — |
| `npm show` | — |
| `npm view` | — |
| `npm search` | — |
| `npm outdated` | — |
| `npm help` | — |
| `npm docs` | — |
| `npm whoami` | — |
| `npm ping` | — |
| `npm explain` | — |
| `npm why` | — |
| `npm fund` | — |
| `npm doctor` | — |
| `npm licenses` | — |
| `npm completion` | — |
| `npm diff` | — |
| `npm find-dupes` | — |
| `npm query` | — |
| `npm stars` | — |
| `npm sbom` | — |
| `npm config list` | — |
| `npm config ls` | — |
| `npm config get` | — |
| `npm c list` | — |
| `npm c ls` | — |
| `npm c get` | — |
| `npm cache ls` | — |
| `npm cache list` | — |
| `npm run` | no script name, or --list present |
| `npm audit` | no `fix` operand |
| `npm --help\|-h\|--version\|-v` | sole argument |

### `open`

| Approved invocation | Condition |
| --- | --- |
| `open -R` | — |

### `perl`

| Approved invocation | Condition |
| --- | --- |
| `perl --version\|-v\|--help\|-h` | sole argument |
| `perl -e\|-E <code>` | every -e/-E fragment concatenated; the source passes the analysis in src/perl_safety.rs |
| `perl <script>` | script readable from the working directory and its source passes the analysis in src/perl_safety.rs |

### `psql`

| Approved invocation | Condition |
| --- | --- |
| `psql --help\|-?\|--version\|-V` | sole argument |
| `psql --list\|-l` | — |
| `psql -c\|--command <sql>` | statement classified read-only by src/sql.rs |
| `psql -f\|--file <path>` | file readable from the working directory and classified read-only by src/sql.rs |

### `python`, `python3`, `python3.8`, `python3.9`, `python3.10`, `python3.11`, `python3.12`, `python3.13`, `python3.14`

Rows are written with `python`; unless a row says otherwise they apply the same way to every command name in this heading.

| Approved invocation | Condition |
| --- | --- |
| `python --version\|-V\|-VV\|--help\|-h` | sole argument |
| `python -c <code>` | source passes the analysis in src/python_safety.rs |
| `python -m calendar` | — |
| `python -m json.tool` | — |
| `python -m this` | — |
| `python -m antigravity` | — |
| `python <script>` | script readable from the working directory and its source passes the analysis in src/python_safety.rs |

### `ruby`, `irb`

Rows are written with `ruby`; unless a row says otherwise they apply the same way to every command name in this heading.

| Approved invocation | Condition |
| --- | --- |
| `ruby\|irb --version\|-v\|--help\|-h` | sole argument |
| `ruby -e <code>` | source passes the analysis in src/ruby_safety.rs |
| `ruby <script>` | script readable from the working directory and its source passes the analysis in src/ruby_safety.rs |

### `ruff`

| Approved invocation | Condition |
| --- | --- |
| `ruff <subcommand>` | subcommand is neither `format` nor `clean`, and neither --fix nor --fix-only present |

### `sed`

| Approved invocation | Condition |
| --- | --- |
| `sed <script> [<file>...]` | no -i (in-place), and no `w`/`e` command or `s///w`/`s///e` flag in the script |

### `sort`

| Approved invocation | Condition |
| --- | --- |
| `sort` | no -o/--output; with one, the target runs the redirect pipeline |

### `sqlite3`

| Approved invocation | Condition |
| --- | --- |
| `sqlite3 --help\|-help\|--version` | sole argument |
| `sqlite3 -readonly\|-safe` | — |
| `sqlite3 <database> <sql>` | statement classified read-only by src/sql.rs |

### `tar`

| Approved invocation | Condition |
| --- | --- |
| `tar -t\|--list` | no flag that runs an external program (-I, --use-compress-program, --to-command, --checkpoint-action, --rmt-command, -F, --info-script, --new-volume-script) |

### `tee`

| Approved invocation | Condition |
| --- | --- |
| `tee` | no file operand; file operands run the redirect pipeline |

### `tokf`

| Approved invocation | Condition |
| --- | --- |
| `tokf raw` | — |
| `tokf ls` | — |
| `tokf which` | — |
| `tokf show` | — |
| `tokf info` | — |
| `tokf gain` | — |
| `tokf check` | — |
| `tokf apply` | — |
| `tokf verify` | — |
| `tokf discover` | — |
| `tokf doctor` | — |
| `tokf completions` | — |
| `tokf rewrite` | — |

### `unzip`, `7z`, `7za`, `7zr`, `7zz`

Rows are written with `unzip`; unless a row says otherwise they apply the same way to every command name in this heading.

| Approved invocation | Condition |
| --- | --- |
| `unzip l` | — |
| `unzip t` | — |
| `unzip --help\|-h\|--version\|-V` | sole argument |

### `uv`, `uvx`

Rows are written with `uv`; unless a row says otherwise they apply the same way to every command name in this heading.

| Approved invocation | Condition |
| --- | --- |
| `uv sync` | — |
| `uv lock` | — |
| `uv tree` | — |
| `uv version` | — |
| `uv help` | — |
| `uv venv` | — |
| `uv export` | — |
| `uv pip list` | — |
| `uv pip freeze` | — |
| `uv pip show` | — |
| `uv pip check` | — |
| `uv pip tree` | — |
| `uv python list` | — |
| `uv python find` | — |
| `uv python dir` | — |
| `uv cache dir` | — |

### `wget`

| Approved invocation | Condition |
| --- | --- |
| `wget --spider` | — |
| `wget --help\|-h\|--version\|-V` | sole argument |

### `xargs`

Delegates only — approves nothing directly.

### `yq`

| Approved invocation | Condition |
| --- | --- |
| `yq <filter>` | no -i/--inplace |

## Rule bundles

Allow rules from the embedded stdlib and the opt-in bundles.

### Stdlib — always active

Shipped with the binary and loaded as the lowest-priority tier; your own config overrides them.

#### `(stdlib:cargo)`

| Action | Matches | Message | Conditions |
| --- | --- | --- | --- |
| `allow` | `command=cargo flags=[--help,-h,--version,-V]` | — | — |
| `allow` | `command=cargo subcommands=[help,version,search,info,tree,metadata,read-manifest,locate-project,pkgid,verify-project,build,test,bench,check,clippy,fmt,doc,clean,nextest,fetch,generate-lockfile,update,vendor,login,logout,owner,audit,deny,expand,outdated,bloat,machete,llvm-lines,udeps,depgraph,msrv]` | — | — |

#### `(stdlib:brew)`

| Action | Matches | Message | Conditions |
| --- | --- | --- | --- |
| `allow` | `command=brew flags=[--help,-h,--version,-V]` | — | — |
| `allow` | `command=brew subcommands=[list,ls,leaves,info,desc,home,deps,uses,search,doctor,config,outdated,missing,tap-info,formulae,casks,log,cat,fetch,docs,shellenv,help]` | — | — |

#### `(stdlib:pip)`

| Action | Matches | Message | Conditions |
| --- | --- | --- | --- |
| `allow` | `command=pip flags=[--help,-h,--version,-V]` | — | — |
| `allow` | `command=pip subcommands=[list,freeze,show,search,check,config,help,version,debug,cache,index,inspect,hash]` | — | — |
| `allow` | `command=pip3 flags=[--help,-h,--version,-V]` | — | — |
| `allow` | `command=pip3 subcommands=[list,freeze,show,search,check,config,help,version,debug,cache,index,inspect,hash]` | — | — |

#### `(stdlib:terraform)`

| Action | Matches | Message | Conditions |
| --- | --- | --- | --- |
| `allow` | `command=terraform flags=[--help,-h,--version,-V]` | — | — |
| `allow` | `command=terraform subcommands=[version,help,fmt,validate,plan,show,state,output,graph,providers,console,workspace,get,modules,metadata,test,refresh]` | — | — |
| `allow` | `command=tf flags=[--help,-h,--version,-V]` | — | — |
| `allow` | `command=tf subcommands=[version,help,fmt,validate,plan,show,state,output,graph,providers,console,workspace,get,modules,metadata,test,refresh]` | — | — |

#### `(stdlib:pytest)`

| Action | Matches | Message | Conditions |
| --- | --- | --- | --- |
| `allow` | `command=pytest flags=[--help,-h,--version,-V]` | — | — |

#### `(stdlib:make)`

| Action | Matches | Message | Conditions |
| --- | --- | --- | --- |
| `allow` | `command=make flags=[--help,-h,--version,-V]` | — | — |
| `allow` | `command=gmake flags=[--help,-h,--version,-V]` | — | — |

#### `(stdlib:rustup)`

| Action | Matches | Message | Conditions |
| --- | --- | --- | --- |
| `allow` | `command=rustup flags=[--help,-h,--version,-V]` | — | — |
| `allow` | `command=rustup subcommands=[show,which,doc,man,completions,check,default,target,component,toolchain]` | — | — |

#### `(stdlib:openssl)`

| Action | Matches | Message | Conditions |
| --- | --- | --- | --- |
| `allow` | `command=openssl flags=[--help,-h]` | — | — |
| `allow` | `command=openssl subcommands=[version,help,list,s_client]` | — | — |

#### `(stdlib:file_ops)`

No allow rules.

#### `(stdlib:builtins)`

No allow rules.

#### `(stdlib:sudo)`

No allow rules.

#### `(stdlib:ssh)`

No allow rules.

#### `(stdlib:interpreters)`

No allow rules.

#### `(stdlib:package_managers)`

No allow rules.

### Packages — opt-in

Active only when selected via `package = "..."` in your config.

#### `review`

No allow rules.

#### `develop`

| Action | Matches | Message | Conditions |
| --- | --- | --- | --- |
| `allow` | `command=git subcommands=[add,commit,push,pull,merge,rebase,cherry-pick,checkout,switch,am,apply,fetch,rm,mv,restore,revert,init,clone,submodule,worktree]` | — | — |
| `allow` | `command=git subcommand=stash` | — | — |
| `allow` | `command=git subcommand=branch` | — | — |
| `allow` | `command=git subcommand=tag` | — | — |
| `allow` | `command=git subcommands=[add,commit,push,pull,merge,rebase,cherry-pick,checkout,switch,am,apply,fetch,rm,mv,restore,revert,init,clone,submodule,worktree,gc,prune,reset]` | — | `branch matches feat/*` |
| `allow` | `command=git subcommand=stash` | — | `branch matches feat/*` |
| `allow` | `command=git subcommand=branch` | — | `branch matches feat/*` |
| `allow` | `command=git subcommand=tag` | — | `branch matches feat/*` |
| `allow` | `command=git subcommands=[add,commit,push,pull,merge,rebase,cherry-pick,checkout,switch,am,apply,fetch,rm,mv,restore,revert,init,clone,submodule,worktree,gc,prune,reset]` | — | `branch matches fix/*` |
| `allow` | `command=git subcommand=stash` | — | `branch matches fix/*` |
| `allow` | `command=git subcommand=branch` | — | `branch matches fix/*` |
| `allow` | `command=git subcommand=tag` | — | `branch matches fix/*` |
| `allow` | `command=cargo subcommands=[build,test,check,clippy,fmt,doc,clean,bench,fetch,metadata,tree,vendor,add,remove,update,search,install]` | — | — |
| `allow` | `command=npm subcommands=[test,run,install,ci,start,build,init]` | — | — |
| `allow` | `command=npx` | — | — |
| `allow` | `command=yarn subcommands=[test,run,install,add,build,start,init]` | — | — |
| `allow` | `command=pnpm subcommands=[test,run,install,add,build,start,init]` | — | — |
| `allow` | `command=go subcommands=[build,test,run,vet,fmt,mod,get,install]` | — | — |
| `allow` | `command=make` | — | — |
| `allow` | `command=pip` | — | — |
| `allow` | `command=pip3` | — | — |
| `allow` | `command=uv` | — | — |
| `allow` | `command=pytest` | — | — |
| `allow` | `command=python` | — | — |
| `allow` | `command=python3` | — | — |
| `allow` | `command=node` | — | — |
| `allow` | `command=ruby` | — | — |
| `allow` | `command=ruff` | — | — |
| `allow` | `command=black` | — | — |
| `allow` | `command=mypy` | — | — |
| `allow` | `command=eslint` | — | — |
| `allow` | `command=prettier` | — | — |
| `allow` | `command=rustfmt` | — | — |
| `allow` | `command=rm` | — | — |
| `allow` | `command=mv` | — | — |
| `allow` | `command=cp` | — | — |
| `allow` | `command=touch` | — | — |
| `allow` | `command=mkdir` | — | — |
| `allow` | `command=ln` | — | — |
| `allow` | `command=chmod` | — | — |
| `allow` | `command=docker` | — | — |
| `allow` | `command=curl` | — | — |
| `allow` | `command=wget` | — | — |
| `allow` | `command=gh` | — | — |
| `allow-redirect` | `/tmp/**` | — | — |
| `allow-write` | `/tmp/**` | — | — |

#### `autopilot`

| Action | Matches | Message | Conditions |
| --- | --- | --- | --- |
| `allow` | `command=git subcommands=[add,commit,push,pull,merge,rebase,cherry-pick,checkout,switch,am,apply,fetch,rm,mv,restore,revert,init,clone,submodule,worktree,gc,prune,reset]` | — | — |
| `allow` | `command=git subcommand=stash` | — | — |
| `allow` | `command=git subcommand=branch` | — | — |
| `allow` | `command=git subcommand=tag` | — | — |
| `allow` | `command=git subcommands=[add,commit,push,pull,merge,rebase,cherry-pick,checkout,switch,am,apply,fetch,rm,mv,restore,revert,init,clone,submodule,worktree]` | — | `branch matches main` |
| `allow` | `command=git subcommand=stash` | — | `branch matches main` |
| `allow` | `command=git subcommand=branch` | — | `branch matches main` |
| `allow` | `command=git subcommand=tag` | — | `branch matches main` |
| `allow` | `command=git subcommands=[add,commit,push,pull,merge,rebase,cherry-pick,checkout,switch,am,apply,fetch,rm,mv,restore,revert,init,clone,submodule,worktree]` | — | `branch matches master` |
| `allow` | `command=git subcommand=stash` | — | `branch matches master` |
| `allow` | `command=git subcommand=branch` | — | `branch matches master` |
| `allow` | `command=git subcommand=tag` | — | `branch matches master` |

### Git styles — opt-in

Active only when selected via `[git] style = "..."`.

#### `cautious`

No allow rules.

#### `standard`

| Action | Matches | Message | Conditions |
| --- | --- | --- | --- |
| `allow` | `command=git subcommands=[add,commit,push,pull,merge,rebase,cherry-pick,checkout,switch,am,apply,fetch,rm,mv,restore,revert,init,clone,submodule,worktree]` | — | — |
| `allow` | `command=git subcommand=stash` | — | — |
| `allow` | `command=git subcommand=branch` | — | — |
| `allow` | `command=git subcommand=tag` | — | — |

#### `permissive`

| Action | Matches | Message | Conditions |
| --- | --- | --- | --- |
| `allow` | `command=git subcommands=[add,commit,push,pull,merge,rebase,cherry-pick,checkout,switch,am,apply,fetch,rm,mv,restore,revert,init,clone,submodule,worktree,gc,prune,reset]` | — | — |
| `allow` | `command=git subcommand=stash` | — | — |
| `allow` | `command=git subcommand=branch` | — | — |
| `allow` | `command=git subcommand=tag` | — | — |

## Redirect targets

Which redirect targets are approved without asking.

- Redirects to `/dev/null`, `/dev/stdout`, `/dev/stderr` are approved: they discard or re-emit output.
- An input redirect (`< file`) is approved: it cannot write.
- A file-descriptor duplication (`2>&1`) is approved: it names no path.
- A write redirect is approved when its target resolves inside a default safe directory (`/tmp`, `/var/tmp`, `/private/tmp`, `/private/var/tmp`) or a directory you declared as a safe scope. Targets inside the working directory still ask.

See `docs/security-invariants.md` for the symlink hardening applied to the world-writable defaults.

## Structural approvals

Shapes with nothing to judge: an empty node, a bare assignment, a heredoc body.

- An empty parse result, or a construct the walker does not gate.
- A command node with no command name (a bare `FOO=bar` assignment).
- A heredoc body, which cannot expand into a command.

## User-controlled (not shipped)

Approvals that come from this machine's configuration, not from rippy's defaults.

These depend on your machine and are **not** part of rippy's shipped surface. Run `rippy inspect` to see what is active for you.

- Allow rules in `~/.rippy/config.toml` or a project `.rippy.toml`.
- Custom packages under `~/.rippy/packages/`.
- Claude Code `permissions.allow` entries.
- `default-action = "allow"`, which approves anything no rule or handler matched.
- `PostToolUse` after-rules, which report rather than gate.

