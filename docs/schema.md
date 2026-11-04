# Arevei Vault — Database schema (PostgreSQL 16)

Source: [`server/migrations/0001_init.sql`](../server/migrations/0001_init.sql). All timestamps are Unix seconds (`bigint`).

**Legend:** 🔒 = ciphertext or opaque protocol data the server can't interpret. Everything else is routing metadata the server needs in order to enforce access.

## Tenancy and access control

- Every org-scoped table has `org_id` plus **row-level security** (`ENABLE` + `FORCE`). Request transactions run `set_config('app.org_id', <session org>, true)`, and the policy only shows rows whose `org_id` matches. With no org set, nothing is visible. The value `*` is used only by auth bootstrap (the invite-token lookup and the "first org?" check) and by the background maintenance jobs.
- The server connects as the schema owner, runs migrations, and then every pooled connection runs `SET ROLE arevei_app`. That role is neither a superuser nor the table owner, so RLS always applies. It has `INSERT`/`SELECT` only on `audit_events` and `audit_checkpoints`.
- The audit tables also carry `BEFORE UPDATE/DELETE/TRUNCATE` triggers that raise an exception, **even for superusers**. An attacker who disables the trigger is still caught by hash-chain verification (`GET /audit/verify`).
- **Per-org sync revision:** `organizations.revision` is incremented with `UPDATE ... RETURNING` inside each writing transaction. The row lock serializes writers per org, and every changed row is stamped with the new revision.

## Tables

### User-scoped (no RLS — looked up before the org is known)

| Table | Columns | Notes |
|---|---|---|
| `users` | id, org_id, email (unique), status (`active`/`disabled`), created_at | The email is plaintext, as it must be to sign in |
| `opaque_records` | user_id, 🔒 record, updated_at | OPAQUE registration record. It isn't a password equivalent, and offline guessing also needs the 128-bit Secret Key. |
| `keysets` | user_id, 🔒 keyset (jsonb), updated_at | `EncryptedKeyset`: wrapped ASK and wrapped private keys are 🔒. Public keys, salt, and KDF params are plaintext, and the client binds them into the associated data. |
| `mfa_totp` | user_id, 🔒 secret_enc, last_used_step, created_at | The account 2FA seed, XChaCha20-Poly1305 under an HKDF subkey of `SERVER_SECRET_KEY`. `last_used_step` blocks replay. |
| `devices` | id, user_id, name, ip, created_at, last_seen_at | |
| `sessions` | token_hash (SHA-256), user_id, device_id, created_at, last_seen_at | Raw tokens are never stored. Idle and absolute expiry are enforced on every request. |
| `pending_tokens` | token_hash, kind (`signup`/`login`/`mfa`/`pending`), 🔒/opaque data, attempts, expires_at | Single use with a TTL (5 min; 10 min for `pending`). `pending` holds the not-yet-created account, with the TOTP seed encrypted. |
| `user_prefs` | user_id, 🔒 blob, updated_at | Encrypted under the user's ASK (favorites, UI preferences) |
| `server_state` | key, 🔒 value | The OPAQUE `ServerSetup`, encrypted under a server subkey |

### Org-scoped (RLS)

| Table | Columns | Notes |
|---|---|---|
| `organizations` | id, org_sign_pk, 🔒 org_secrets, revision, audit_head, audit_count, created_at | `org_secrets` is the org signing key, encrypted under the org admin key. The server can verify org signatures but can't make them. |
| `org_memberships` | org_id, user_id, role (`owner`/`admin`/`member`), status (`pending_approval`/`active`/`disabled`), cert (jsonb), created_at, approved_at | `cert` is a `MembershipCert` signed client-side by an admin. The server checks it against `org_sign_pk` and the user's keyset before storing it. |
| `invites` | id, org_id, token_hash, email, role, created_by, created_at, expires_at, used_at, used_by | Single use, 7 days |
| `clients` | id, org_id, 🔒 name_enc, revision, created_at | Name encrypted under the org directory key |
| `vaults` | id, org_id, kind (`personal`/`project`), client_id, owner_user_id, 🔒 name_enc, key_version, 🔒 admin_wrapped_key, revision, created_at | A personal vault has `id = owner_user_id`. Admins never receive other users' personal vaults. |
| `vault_permissions` | vault_id, user_id, org_id, role (`manager`/`member`/`read_only`), copy_only, created_at | Server-enforced write and manage rights |
| `key_grants` | id, org_id, keyring_id, key_version, recipient_id, grantor_id, 🔒 wrapped, signature, created_at | HPKE-sealed vault, directory, and admin keys. Each is signed by its grantor and verified by clients against membership certificates. |
| `items` | id, org_id, vault_id, version, key_version, 🔒 wrapped_key, 🔒 payload, revision, created_at, updated_at, created_by, updated_by, deleted_at | **Type, title, URLs, usernames, secrets, notes, tags, history, and expiry are all inside the 🔒 payload** (Padmé-padded) |
| `item_tombstones` | item_id, org_id, vault_id, revision, purged_at | Lets clients drop purged items during delta sync |
| `attachments` | id, org_id, item_id, size, uploaded_by, created_at | 🔒 content lives on disk at `ATTACHMENT_DIR/<org>/<id>` (STREAM ciphertext). The file name and MIME type are inside the item payload. |
| `audit_events` | id, org_id, seq, ts, actor_user_id, device_id, ip, user_agent, event_type, target_type, target_id, vault_id, client_ts, prev_hash, entry_hash | `entry_hash = SHA-256(prev_hash ‖ canonical JSON)`. IDs only, never titles. |
| `audit_checkpoints` | id, org_id, ts, count, head_hash, signature | Ed25519 signature by the server audit key (HKDF of `SERVER_SECRET_KEY`), created hourly and on `GET /audit/verify` |

## What the server can see (by design)

- Email addresses, the org/client/project/vault structure (as IDs), who can access which vault, item counts, padded ciphertext sizes, timestamps, IPs, and user agents.
- **Never:** master passwords, Secret Keys, any symmetric or private key, item contents, item types, titles, URLs, usernames, client names, project names, or attachment names or contents. The `zero_plaintext_canary` test enforces this by grepping `pg_dump` and the attachment directory.
