#!/usr/bin/env bash
# Vercel install step for the web app: pnpm deps + pinned Rust toolchain + prebuilt wasm-bindgen.
set -euo pipefail
corepack enable && corepack prepare pnpm@10.14.0 --activate
pnpm install --frozen-lockfile --ignore-scripts

RUST=1.99.1
WB=0.2.130
export PATH="$HOME/.cargo/bin:$PATH"
mkdir -p "$HOME/.cargo/bin"

if command -v rustup >/dev/null 2>&1; then
  rustup toolchain install "$RUST" --profile minimal -t wasm32-unknown-unknown
  rustup default "$RUST"
else
  curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain "$RUST" -t wasm32-unknown-unknown
fi
cargo --version

if ! wasm-bindgen --version 2>/dev/null | grep -q "$WB"; then
  curl -sSL "https://github.com/rustwasm/wasm-bindgen/releases/download/${WB}/wasm-bindgen-${WB}-x86_64-unknown-linux-musl.tar.gz" | tar xz
  install -m 755 "wasm-bindgen-${WB}-x86_64-unknown-linux-musl/wasm-bindgen" "$HOME/.cargo/bin/wasm-bindgen"
  rm -rf "wasm-bindgen-${WB}-x86_64-unknown-linux-musl"
fi
wasm-bindgen --version
