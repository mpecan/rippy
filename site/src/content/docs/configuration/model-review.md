---
title: Model-assisted review
description: Let a hosted or local decision model approve commands rippy asks about only because it is unsure.
---

rippy asks for two reasons.

- **Approval asks:** a human must approve the command (`git push --force`, `rm`,
  your own `ask` rules).
- **Uncertain asks:** rippy cannot tell whether the command is safe (an unknown
  command, an unresolvable `$VAR`).

The optional `rippy-jev` build can send **uncertain asks only** to a *System One*
decision model. A System One model answers typed questions with calibrated
probabilities instead of text. The model may approve the command or leave the ask
in place.

It never blocks anything, and it never touches an `allow`, a `deny` or an approval
ask. The default `rippy` build contains no network code.

## Install the `rippy-jev` build

```sh
brew install mpecan/tools/rippy-jev    # conflicts with the rippy formula
cargo install rippy-cli --features jev
```

`rippy --version` ends in `+jev`. Nothing changes until you enable `[jev]` in your
global config, `~/.rippy/config.toml`. rippy ignores a `[jev]` section in a project
`.rippy.toml` and warns about it.

## Option 1: a local model (nothing leaves your machine)

[rippy-kev](https://github.com/mpecan/rippy-kev) trains small open models
(Apache-2.0) on rippy's own questions. They answer locally, so commands never
leave your machine. The models need rippy 0.2.4 or later.

| model | weights | p50 per command (M4 Max) | `min-confidence` |
|---|---|---|---|
| rippy-kev-4b | [Risethagain/rippy-kev-4b](https://huggingface.co/Risethagain/rippy-kev-4b) | ~0.75 s | 0.75 |
| rippy-kev-0.8b | [Risethagain/rippy-kev-0.8b](https://huggingface.co/Risethagain/rippy-kev-0.8b) | ~0.2 s | 0.85 |

Prefer the 4B. On programs it never saw in training, it approves more safe
commands than hosted Jev (71% against 65%) and approves fewer severe ones. The 0.8B
is faster but approves fewer safe commands, and it can miss commands that *display*
stored credentials. Read its model card before using it.

### Serve the model

With Kev's server, the fastest option on Apple silicon:

```sh
git clone https://github.com/jaredpalmer/kev && cd kev && uv sync --extra serve
uv run --extra serve python -m kev.serve --run Risethagain/rippy-kev-4b --port 8012
```

Or with llama.cpp (build 11361 or later), using the Q8_0 GGUF in the model repo:

```sh
huggingface-cli download Risethagain/rippy-kev-4b rippy-kev-4b-v2-Q8_0.gguf --local-dir .
llama-server -m rippy-kev-4b-v2-Q8_0.gguf --port 8012 -ngl 99 --parallel 1 \
  -c 4096 --cache-ram 0 --ctx-checkpoints 0
```

Keep the last three flags. With llama-server's defaults, latency grows over a long
run.

### Configure rippy

```toml
# ~/.rippy/config.toml
[jev]
enabled = true
endpoint = "http://127.0.0.1:8012/v1/systemone"
model = "kev-latest"
api-key-env = "RIPPY_KEV_KEY"   # any non-empty value; the local server needs no key
timeout-ms = 2000
min-confidence = 0.75           # rippy-kev-0.8b: 0.85
max-irreversible = 0.2
max-writes-outside = 0.3
```

Use each model's own thresholds. The built-in defaults were tuned on Jev, and they
make a local model approve far less.

## Option 2: hosted Jev

```toml
[jev]
enabled = true
endpoint = "https://openrouter.ai/api/v1/systemone"  # or https://api.typesafe.ai/v1/systemone
model = "jev-1.13"                                   # "jev-latest" on TypeSafe's own API
api-key-env = "OPENROUTER_API_KEY"                   # the key is read only from this variable
min-confidence = 0.9
timeout-ms = 2000
```

With a hosted endpoint, eligible commands leave your machine. Before rippy sends
them, it removes comments and replaces secrets with `<redacted>`. The redaction
covers common shapes; it is not a guarantee.

## What the model may and may not do

- **Only plain commands are sent.** rippy never sends a command whose behaviour is
  defined elsewhere:
  - path- or script-named programs and task runners;
  - interpreters given arguments;
  - anything judged through a wrapper or a script's contents;
  - programs that resolve inside the project.

  It also never sends a group, loop, substitution, heredoc, stdin redirect,
  `NAME=value` prefix, multi-line command or non-ASCII text.
- **Suspicious answers escalate.** On possible exfiltration, or text in the command
  that argues for its own approval, the ask stays, gets a warning and always
  prompts.
- **Failures change nothing.** A timeout, an error or an odd answer leaves the ask
  as it was, with `(jev unavailable: …)` in the reason.
- **Every decision is visible.** An approval reads like
  `jev: approved (read_only, conf 0.97 >= 0.75, kev-latest q3)`, and the JSON log
  records the state sent and the raw answers.

## Check before you rely on it

- **Single commands:** `rippy jev '<command>'` shows what rippy would send, the raw
  answers, and the final decision under your config.
- **A whole backend:** `scripts/jev-eval` in the repository compares System One
  backends on a labelled sample through the real binary. It reports false
  approvals, safe approvals, exfiltration escalations and latency, and `sweep.py`
  finds thresholds for a new model.

The full design, threat model and measurements are in
[docs/jev.md](https://github.com/mpecan/rippy/blob/main/docs/jev.md).
