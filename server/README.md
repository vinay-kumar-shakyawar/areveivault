# arevei-server

The Rust/Axum API for Arevei Vault. It stores and syncs **ciphertext only**. The contract is in [docs/api.md](../docs/api.md) and [docs/openapi.yaml](../docs/openapi.yaml), and the schema is in [docs/schema.md](../docs/schema.md).

## Run locally

```bash
docker compose -f deploy/docker-compose.dev.yml up -d      # Postgres :55432, Redis :56379 (localhost only)
cp server/.env.example server/.env                         # set SERVER_SECRET_KEY (openssl rand -hex 32)
export $(grep -v '^#' server/.env | xargs)
DATABASE_URL=postgres://postgres:postgres@127.0.0.1:55432/arevei cargo run -p arevei-server
```

Migrations run automatically at startup. After migrating, the server switches every pooled connection to the `arevei_app` role (`SET ROLE`). That role isn't a superuser and doesn't own the tables, so row-level security applies to it and it can only append to the audit log. In production, connect as a dedicated schema-owner login rather than as `postgres`.

## Tests

```bash
docker compose -f deploy/docker-compose.dev.yml up -d
cargo test -p arevei-server
```

Each test creates its own database (`t_<uuid>`) on the dev Postgres. It also uses its own Redis key prefix and a temp attachment directory, so tests run in parallel without interfering. You can override the endpoints with `TEST_DATABASE_URL` (an admin connection URL ending in `/postgres`) and `TEST_REDIS_URL`. The canary test runs `docker exec arevei-dev-postgres pg_dump`, so the container name from `deploy/docker-compose.dev.yml` is required. To reset all test databases, run `docker compose -f deploy/docker-compose.dev.yml down -v`.

The tests drive the server with the real `arevei_core::engine::Engine`, the same code the web app and extension run as WASM:

| Test | Covers |
|---|---|
| `full_flow` | Bootstrap signup with TOTP, invite-only enforcement, clients and projects, items, a second browser seeing the same data, invite and pending member, approval via an engine-issued certificate, grants, member decrypts, read-only gets 403, 409 conflict, revoke plus rotation (including rejected incomplete and replayed rotations), trash/restore/30-day purge with tombstones, offboarding, client audit events, chain verification and checkpoint, superuser tampering blocked by the trigger, and trigger-bypass tampering detected by the chain |
| `zero_plaintext_canary` | Canaries in every item field, client name, project name, tags, custom fields, prefs, and an attachment. `pg_dump` and the attachment directory contain none of them, and no TOTP seed, Secret Key, or master password. |
| `cross_org_isolation` | Org B can't see or modify org A's vaults or items via the API. RLS hides them even from raw SQL with B's org set, and from SQL with no org set. |
| `rate_limits_lockout_and_replay` | Per-IP limit returns 429 |
| `account_lockout_mfa_replay_and_enumeration` | Fake prelogin and OPAQUE fake records for unknown emails, TOTP step replay rejected, account backoff and lockout |
| `csrf_and_headers` | `X-Arevei-Request` requirement, foreign-Origin rejection, the extension-Origin rule, security headers, and logout |
