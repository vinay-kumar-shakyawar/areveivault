#!/usr/bin/env bash
# Builds /core to WebAssembly and generates JS bindings into packages/core-wasm/pkg.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"
cargo build -p arevei-core --target wasm32-unknown-unknown --features wasm --release --locked
rm -rf packages/core-wasm/pkg
wasm-bindgen --target web --out-dir packages/core-wasm/pkg --out-name arevei_core \
  target/wasm32-unknown-unknown/release/arevei_core.wasm
sha256sum packages/core-wasm/pkg/arevei_core_bg.wasm
