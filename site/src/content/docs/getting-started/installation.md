---
title: Installation
description: Install rippy with Homebrew, cargo, cargo-binstall, or from GitHub Releases.
---

rippy ships as a single static binary. Pick whichever installer you prefer —
all four produce the same `rippy` executable.

## Homebrew (macOS and Linux)

```sh
brew install mpecan/tools/rippy
```

This installs the latest release from the
[`mpecan/tools`](https://github.com/mpecan/homebrew-tools) tap.

## Cargo (build from source)

```sh
cargo install rippy-cli
```

The crate name is `rippy-cli`; the binary it installs is called `rippy`.
Requires a recent stable Rust toolchain (edition 2024, Rust 1.93+).

## cargo-binstall (prebuilt binaries)

```sh
cargo binstall rippy-cli
```

Downloads the prebuilt binary for your platform instead of compiling from
source. Faster than `cargo install`, no Rust toolchain needed.

## GitHub Releases (manual download)

Prebuilt binaries are attached to each
[GitHub release](https://github.com/mpecan/rippy/releases) for:

- macOS Apple Silicon (`aarch64-apple-darwin`)
- macOS Intel (`x86_64-apple-darwin`)
- Linux x86_64 (`x86_64-unknown-linux-gnu`)
- Linux aarch64 (`aarch64-unknown-linux-gnu`)

Extract the `.tar.gz`, drop `rippy` on your `PATH`, and you are done.

## Verify the install

```sh
rippy --version
```

If that prints a version number, you are ready to
[wire rippy into Claude Code](/getting-started/claude-code/) — or pick your
AI tool from the sidebar.
