# Arevei Vault

A zero-knowledge, self-hostable password manager for teams that manage credentials on behalf of clients.

Every piece of cryptography runs on the client, in one Rust engine compiled to WebAssembly. The server stores and syncs **ciphertext only**. It can't read passwords, item titles, URLs, usernames, notes, or client and project names.

## Features

- **Zero-knowledge vaults.** Items are encrypted with XChaCha20-Poly1305 under per-vault keys. Account keys come from your master password (Argon2id) combined with a device-held Secret Key.
- **No password-equivalent on the server.** Login uses OPAQUE (a PAKE), plus TOTP for two-factor.
- **Team sharing.** Organizations, clients and projects, roles, invites with owner-signed membership certificates, read-only access, and key rotation when someone is revoked or offboarded.
- **Item types.** Logins, authenticator (TOTP) codes, recovery codes, API keys, SSH keys, server and database credentials, secure notes, and documents, with custom fields and encrypted attachments.
- **Browser extension (Manifest V3).** Saves and autofills credentials and one-time codes, with strict origin matching and protection against phishing pages.
- **Tamper-evident audit log.** An append-only, hash-chained log with signed checkpoints.
- **Security tools.** Password generator, strength meter, breached-password checks (HIBP k-anonymity), QR import for TOTP, CSV import and export, and a printable Emergency Kit.
- **Hardened web app.** A static SPA with a strict CSP and Trusted Types, built reproducibly, with published bundle hashes that the extension verifies.

## Repository layout

| Path | What's there |
|---|---|
| [`core/`](core) | Rust crypto and vault engine, compiled to WASM for the web app and extension |
| [`server/`](server) | Rust/Axum API on PostgreSQL 16 and Redis 7 |
| [`web/`](web) | React + TypeScript + Vite web app |
| [`extension/`](extension) | Browser extension for Chrome, Edge, Brave and Firefox |
| [`packages/`](packages) | Shared TypeScript: API client, UI components, WASM bindings |
| [`landing/`](landing) | Static marketing page |
| [`deploy/`](deploy) | Docker Compose with Caddy, encrypted backups, and Terraform for AWS |
| [`e2e/`](e2e) | End-to-end test fixtures |
| [`docs/`](docs) | Architecture, threat model, API, schema, setup, and backups |

## Quick start (local development)

You need Rust (stable, plus the `wasm32-unknown-unknown` target), `wasm-bindgen-cli` 0.2.130, Node 20+, pnpm 10, and Docker.

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.130 --locked

pnpm install
bash scripts/build-wasm.sh                              # core → packages/core-wasm/pkg
docker compose -f deploy/docker-compose.dev.yml up -d   # Postgres :55432, Redis :56379

cp server/.env.example server/.env                      # set SERVER_SECRET_KEY (openssl rand -hex 32)
cargo run -p arevei-server                              # API on :8080, migrations run at startup

pnpm --filter web dev                                   # https://localhost:5173, proxies /api to :8080
```

The session cookie is `__Host-` and `Secure`, so sign-in needs HTTPS even in development. Before running `pnpm --filter web dev`, set `DEV_TLS_CERT` and `DEV_TLS_KEY` to a localhost certificate (for example, one from [mkcert](https://github.com/FiloSottile/mkcert)), and set `PUBLIC_ORIGIN=https://localhost:5173` in `server/.env`.

The first account you sign up with creates the organization and becomes its Owner. After that, new members need an invite (unless `ALLOW_SIGNUP=true`).

To try the extension, run `pnpm --filter extension build`, then load `extension/dist/chrome` as an unpacked extension.

## Self-hosting

On a Linux host with Docker:

```bash
cp deploy/.env.example deploy/.env    # fill in secrets, see the setup guide
docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --build
```

Caddy gets TLS certificates automatically. For first-run steps, upgrades, and the AWS (Terraform) path, see [docs/setup-guide.md](docs/setup-guide.md). Back up `SERVER_SECRET_KEY` offline: if you lose it, every account is locked out. See [docs/backup-and-recovery.md](docs/backup-and-recovery.md).

## Tests

| Suite | Command |
|---|---|
| Core (crypto vectors, property tests, engine flows) | `cargo test -p arevei-core` |
| Server integration (needs the dev compose stack running) | `cargo test -p arevei-server -- --test-threads=1` |
| Web unit tests, build, and CSP audit | `pnpm --filter web test && pnpm --filter web build` |
| Extension unit and e2e | `pnpm --filter extension test && pnpm --filter extension e2e` |

The server suite includes a **zero-plaintext canary** test. It puts marker strings in every encrypted field, dumps the database and the attachment store, and fails if any marker appears.

CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) enforces at least 80% line coverage on the core. It also builds the web app twice and fails if the bundle hashes differ.

## Security

- [docs/architecture.md](docs/architecture.md): crypto design, key hierarchy, sharing, and sync
- [docs/threat-model.md](docs/threat-model.md): assets, trust boundaries, attackers, and residual risks
- [docs/api.md](docs/api.md) and [docs/openapi.yaml](docs/openapi.yaml): the API contract
- [docs/schema.md](docs/schema.md): the database schema and row-level security

If you find a vulnerability, please report it privately through GitHub's **Security → Report a vulnerability** on this repository. Don't open a public issue.

## License

[MIT](LICENSE)
