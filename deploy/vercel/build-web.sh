#!/usr/bin/env bash
# Vercel build step for the web app: WASM core + web bundle, plus the landing page under /welcome.
# Run from the repo root (web/vercel.json does `cd ..` first).
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"

bash scripts/build-wasm.sh
pnpm --filter web build

# Landing page shares the app's origin: same-origin links, assets under /welcome/.
APP_URL=/ ASSET_BASE=/welcome/ GTM_ID=GTM-PL2X5WDJ node landing/build.mjs
mkdir -p web/dist/welcome
cp -r landing/dist/. web/dist/welcome/
rm -f web/dist/welcome/_headers
