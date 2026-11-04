# Reproducible build of the web bundle (core → WASM → Vite), served by Caddy.
# Build from the repo root:  docker build -f deploy/web.Dockerfile -t arevei-vault-web .

FROM rust:1.99-bookworm AS wasm
RUN rustup target add wasm32-unknown-unknown \
 && cargo install wasm-bindgen-cli --version 0.2.130 --locked
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY core ./core
COPY server/Cargo.toml ./server/Cargo.toml
# The workspace lists `server`; give cargo a stub so it can resolve without the server sources.
RUN mkdir -p server/src && echo "fn main() {}" > server/src/main.rs
COPY scripts ./scripts
COPY packages/core-wasm/package.json ./packages/core-wasm/package.json
ENV SOURCE_DATE_EPOCH=0
RUN bash scripts/build-wasm.sh

FROM node:20.18-bookworm AS web
RUN corepack enable && corepack prepare pnpm@10.14.0 --activate
WORKDIR /src
COPY . .
COPY --from=wasm /src/packages/core-wasm/pkg ./packages/core-wasm/pkg
ENV SOURCE_DATE_EPOCH=0
RUN pnpm install --frozen-lockfile --ignore-scripts \
 && pnpm --filter web build \
 && node web/scripts/check-csp.mjs web/dist

FROM caddy:2.8.4-alpine
COPY deploy/Caddyfile /etc/caddy/Caddyfile
COPY --from=web /src/web/dist /srv/web
