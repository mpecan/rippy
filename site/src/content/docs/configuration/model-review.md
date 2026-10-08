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

This page is the setup guide. The design, threat model, training and evaluation
are in [docs/jev.md](https://github.com/mpecan/rippy/blob/main/docs/jev.md).

## Install the `rippy-jev` build

```sh
brew install mpecan/tools/rippy-jev    # conflicts with the rippy formula
# or
cargo install rippy-cli --features jev
# or
cargo binstall rippy-cli --pkg-url '{ repo }/releases/download/rippy-cli-v{ version }/rippy-jev-v{ version }-{ target }.tar.gz'
```

`rippy --version` ends in `+jev`. Nothing changes until you enable `[jev]` in your
global config, `~/.rippy/config.toml`. rippy ignores a `[jev]` section in a project
`.rippy.toml` and warns about it.

## Option 1: a local model (nothing leaves your machine)

[rippy-kev](https://github.com/mpecan/rippy-kev) trains small open models
(Apache-2.0) on rippy's own questions. They answer on your machine, so commands are
never sent anywhere. The models need rippy 0.2.4 or later.

| model | weights | median per command (M4 Max) | `min-confidence` |
|---|---|---|---|
| rippy-kev-4b | [Risethagain/rippy-kev-4b](https://huggingface.co/Risethagain/rippy-kev-4b) | ~0.75 s | 0.75 |
| rippy-kev-0.8b | [Risethagain/rippy-kev-0.8b](https://huggingface.co/Risethagain/rippy-kev-0.8b) | ~0.25 s | 0.85 |

Prefer the 4B. On programs it never saw in training, and at matched risk
(thresholds fitted per backend for 1% severe approvals on dev), it approves more
safe commands than hosted Jev (71% against 65%) at a similar severe-approval rate.
The 0.8B is three times faster but approves fewer safe commands (44% at 0.85).
Like Jev, both models occasionally approve a severe command from a tool they do not
know (file transfers, config tools), and both have approved commands that list
stored credentials, such as `xauth list`. Read the model card before you rely on
either.

### Prerequisites

- **For Kev's server:** [uv](https://docs.astral.sh/uv/), Python 3.12 or 3.13, and
  a checkout of [Kev](https://github.com/jaredpalmer/kev). It runs on MLX on Apple
  silicon and on CUDA or ROCm elsewhere. The first run downloads the Qwen3.5 base
  model, several GB.
- **For llama.cpp:** `llama-server` from release b11361 or later (tested on
  b11429), and the Hugging Face CLI (`hf`) to fetch the GGUF.

### Serve the model with Kev's server

The faster option on Apple silicon:

```sh
git clone https://github.com/jaredpalmer/kev && cd kev && uv sync --extra serve
uv run --extra serve python -m kev.serve --run Risethagain/rippy-kev-4b --port 8012
# or, for the small model
uv run --extra serve python -m kev.serve --run Risethagain/rippy-kev-0.8b --port 8012
```

### Or serve it with llama.cpp

Each model repository carries a Q8_0 GGUF:

```sh
hf download Risethagain/rippy-kev-4b rippy-kev-4b-v2-Q8_0.gguf --local-dir .
llama-server -m rippy-kev-4b-v2-Q8_0.gguf --alias kev-latest --port 8012 \
  -ngl 99 --parallel 1 -c 4096 --cache-ram 0 --ctx-checkpoints 0
```

For the small model, download `rippy-kev-0-8b-v2-Q8_0.gguf` from
`Risethagain/rippy-kev-0.8b` (note `0-8b` in the file name) and pass it to `-m`.

Why these flags:

- `-c 4096 --cache-ram 0 --ctx-checkpoints 0`: with llama-server's defaults,
  latency grew over a long run and memory reached 11 GB. Keep all three.
- `--alias kev-latest`: llama-server ignores the request's `model` field when it
  serves one model, and otherwise names the GGUF file in its answers. The alias
  keeps the model id in rippy's reasons the same under both servers.
- Q8_0 closely matches the original model's decisions. Smaller quantisations such
  as Q4_K_M drift, so they are not recommended.

### Set the key variable

rippy will not call an endpoint unless the variable named in `api-key-env` is set
and not empty. Local servers ignore its value, so any value works:

```sh
export RIPPY_KEV_KEY=local
```

Set it where your AI tool is launched from (your shell profile, for example), since
hooks inherit that tool's environment.

### Configure rippy

```toml
# ~/.rippy/config.toml
[jev]
enabled = true
endpoint = "http://127.0.0.1:8012/v1/systemone"
model = "kev-latest"
api-key-env = "RIPPY_KEV_KEY"
timeout-ms = 5000               # see below; the 2000 default suits hosted Jev
min-confidence = 0.75           # rippy-kev-0.8b: 0.85
```

Give a local model more time than hosted Jev needs. On an idle M4 Max the 4B answers
in about 0.75 s, but with other GPU or memory load on the machine it took 2.4 s, and
a request past `timeout-ms` leaves the ask in place (`jev unavailable: timed out`).
5000 ms keeps the review working under load; the hook only waits this long for
commands rippy would otherwise ask about.

Use each model's own `min-confidence`. The default, 0.9, was tuned on Jev and makes
a local model approve far less. The other thresholds keep their defaults
(`max-irreversible = 0.2`, `max-writes-outside = 0.3`, and so on).

For the 4B, `min-confidence = 0.95` is a stricter alternative. For the 0.8B, 0.80 is
more permissive and 0.95 is the strictest published setting.

### Check that it works

Pick a command rippy is unsure about, and run it through `rippy jev`. Nothing is
executed; rippy only analyses the text:

```sh
rippy jev 'lsusb -v'
```

The output shows rippy's own verdict, the state sent, the model's raw answers and
the final verdict. When the model approves the command, the output ends like this:

```text
final   allow: jev: approved (read_only, conf 0.98 >= 0.75, kev-latest q3)
```

The confidence varies. If the model keeps the ask, the final line names the first
gate that failed instead.

### Troubleshooting

`jev unavailable: …` in the output or in a hook's reason means the model was not
asked, and the ask stays as it was:

- **`$RIPPY_KEV_KEY is not set`:** export the variable (see above) in the
  environment your AI tool starts from, then restart the tool.
- **`Connection refused`:** the server is not running, or it listens on another
  port than `endpoint`.
- **A timeout:** the first request after a start can be slow while the model loads.
  If timeouts persist, raise `timeout-ms` or use the smaller model.

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
  backends on a labelled sample through the real binary. See
  [docs/jev.md](https://github.com/mpecan/rippy/blob/main/docs/jev.md#local-models)
  for how to run it and for the measurements behind the thresholds above.
