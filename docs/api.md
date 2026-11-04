# Arevei Vault — API contract (v1)

The source of truth for `/server`, `/web`, and `/extension`. The machine-readable version is [`openapi.yaml`](openapi.yaml).

## Conventions

- Base path `/api/v1`. JSON request and response bodies. Binary data is base64.
- Every state-changing request needs the header `X-Arevei-Request: 1`, and must carry an `Origin` that matches the server's configured origin (or no Origin at all, which is how extensions send it). Otherwise the server returns `403`.
- Auth is the `__Host-av_session` cookie (HttpOnly, Secure, SameSite=Strict, Path=/). Non-browser clients can send `Authorization: Bearer <session token>` instead. The extension uses this because an MV3 service worker can't rely on SameSite=Strict cookies.
- Errors: `{ "error": "<code>", "message": "<human text>" }`. Codes: `bad_request`, `unauthorized`, `forbidden`, `not_found`, `conflict`, `rate_limited`, `mfa_required`, `internal`.
- IDs are client-generated UUIDv4 strings unless noted otherwise. **A user's personal vault id is the user id.**
- Timestamps are Unix seconds (integer).
- `revision` is a per-organization monotonic bigint. Every mutation stamps the rows it touches.

## Auth

| Method & path | Body | Response |
|---|---|---|
| `POST /auth/prelogin` | `{email}` | `{salt, kdf:{m_kib,t,p}}`. Unknown emails get deterministic fake values. |
| `POST /auth/register/start` | `{email, invite_token?, registration_request}` | `{registration_response, signup_token}`. With no `invite_token`, this succeeds only when the server has zero orgs (bootstrap), or for a self-signup org when `ALLOW_SIGNUP=true`. |
| `POST /auth/register/finish` | `{signup_token, user_id, registration_upload, keyset, org_bootstrap?}` | `{pending_token, totp_secret, otpauth_uri}`. The user exists but is inactive until MFA is confirmed. |
| `POST /auth/mfa/totp/confirm` | `{pending_token, code, device_name}` | Sets the session cookie. Returns `Session` and `session_token`. |
| `POST /auth/login/start` | `{email, credential_request}` | `{credential_response, login_token}` |
| `POST /auth/login/finish` | `{login_token, credential_finalization}` | `{mfa_token, methods:["totp"]}`, or `401` |
| `POST /auth/mfa/verify` | `{mfa_token, code, device_name}` | Sets the session cookie. Returns `Session` and `session_token`. |
| `POST /auth/logout` | — | `204` |
| `GET /auth/session` | — | `Session`, or `401` |

`Session = {user_id, email, org_id, role, status, device_id}`. `role` is one of `owner | admin | member`. `status` is one of `active | pending_approval`.

`org_bootstrap` (first user only) = `{org_id, org_sign_pk, org_secrets, grants:[KeyGrant], cert}`.

**Rate limits:** login and prelogin allow 10 per minute per IP and 5 failures per account before exponential backoff. MFA allows 5 attempts per token.

## Account

| Method & path | Body | Response |
|---|---|---|
| `GET /keyset` | — | `EncryptedKeyset` (see the core `keyset.rs` JSON) |
| `GET /prefs` / `PUT /prefs` | `{blob}` (ASK-encrypted) | `{blob}` |
| `GET /devices` | — | `[{id, name, created_at, last_seen_at, current}]` |
| `DELETE /devices/{id}` | — | `204` (revokes the device's sessions) |

## Sync

`GET /sync?since=<revision>` (`since=0` gets everything):

```json
{
  "revision": 123,
  "org": {"id": "...", "org_sign_pk": "b64", "org_secrets": "b64 | null"},
  "me": {"user_id": "...", "role": "owner", "status": "active"},
  "members": [{"user_id","email","role","status","public_keys":{"x25519","ed25519"},"cert": MembershipCert|null}],
  "vaults": [{"id","kind":"personal|project","client_id":null,"name_enc":"b64|null","key_version":1,
              "admin_wrapped_key":"b64|null","role":"manager|member|read_only","copy_only":false,"revision":5}],
  "clients": [{"id","name_enc","revision"}],
  "grants": [KeyGrant],
  "items": [{"id","vault_id","version","key_version","wrapped_key","payload",
             "revision","created_at","updated_at","created_by","updated_by","deleted_at":null}],
  "purged_item_ids": ["..."]
}
```

- `vaults`, `clients`, `grants`, and `members` are always the **full** current lists. They're small, and a full list means revocations show up immediately. `items` holds only rows with `revision > since` that are in vaults the caller can access. `org_secrets` is non-null only for owners and admins. `admin_wrapped_key` is non-null only for owners and admins.
- `members` is visible to every active member, because grantor certificates are needed to verify grants.

`GET /events` is Server-Sent Events. It emits `event: sync` with `data: {"revision": N}` whenever something the caller can see changes, and a keep-alive comment every 25 s.

## Items

| Method & path | Body | Response |
|---|---|---|
| `PUT /items/{id}` | `{vault_id, version, key_version, wrapped_key, payload, expected_version: int\|null}` | `200` with the stored item row. `409` with `{error:"conflict", current: row}` if `expected_version` doesn't match. `null` means create, and is `409` if the item already exists. Moving an item is a PUT with a new `vault_id`, and needs write access to both vaults. |
| `DELETE /items/{id}` | — | Soft delete (sets `deleted_at`). The trash is purged after 30 days. |
| `POST /items/{id}/restore` | — | Clears `deleted_at` |
| `DELETE /items/{id}?purge=true` | — | Hard delete, with a tombstone in `purged_item_ids` |

Write access: personal vault owner, or project `manager`/`member`, or org `owner`/`admin`. `read_only` gets `403`.

## Clients and projects (vaults)

| Method & path | Who | Body |
|---|---|---|
| `POST /clients` | admin+ | `{id, name_enc}` |
| `PUT /clients/{id}` | admin+ | `{name_enc}` |
| `DELETE /clients/{id}` | admin+ | Only when the client has no projects |
| `POST /vaults` | admin+ | `{id, client_id, name_enc, key_version:1, admin_wrapped_key, grants:[KeyGrant]}` |
| `PUT /vaults/{id}` | admin+ or manager | `{name_enc}` |
| `DELETE /vaults/{id}` | admin+ | Soft-deletes every item, then removes the vault |
| `GET /vaults/{id}/members` | members of the vault, admin+ | `[{user_id, role, copy_only}]` |
| `PUT /vaults/{id}/members/{user_id}` | admin+ or manager | `{role, copy_only, grant: KeyGrant\|null}`. A grant is required when the user doesn't already have one for the current key version. |
| `DELETE /vaults/{id}/members/{user_id}` | admin+ or manager | Removes the permission and all of that user's grants for the vault |
| `POST /vaults/{id}/rotate` | admin+ or manager | `{key_version, name_enc, admin_wrapped_key, grants:[KeyGrant], items:[{id, version, key_version, wrapped_key}]}`. Atomic. `key_version` must be the current version + 1, and `items` must cover every item in the vault. |

## Organization and members

| Method & path | Who | Body / Response |
|---|---|---|
| `POST /org/invites` | admin+ | `{email, role}` → `{invite_token, expires_at}` (7 days, single use) |
| `GET /org/invites` / `DELETE /org/invites/{token_id}` | admin+ | — |
| `POST /org/members/{user_id}/approve` | admin+ | `{cert, grants:[KeyGrant]}`. Grants include the directory key, plus the org admin key if the role is admin. |
| `PATCH /org/members/{user_id}` | owner (for admin/owner roles), admin+ | `{role, grants?:[KeyGrant]}` |
| `DELETE /org/members/{user_id}` | admin+ | Offboarding: disables the user, kills sessions, and deletes their permissions and grants. Returns `{affected_vault_ids}` so the client can rotate them. |

## Attachments

| Method & path | Body |
|---|---|
| `PUT /attachments/{id}?item_id=...` | Raw `application/octet-stream` (STREAM ciphertext, ≤ 10 MB + overhead) |
| `GET /attachments/{id}` | Raw ciphertext |
| `DELETE /attachments/{id}` | — |

## Audit

| Method & path | Body / Response |
|---|---|
| `POST /audit/events` | `{events:[{event_type, target_type, target_id, vault_id?, client_ts}]}`. Client-reported (view, reveal, copy, autofill, export). Max 100 per request. |
| `GET /audit?before=<id>&limit=100` | admin+ → `[{id, ts, actor_user_id, actor_email, device_id, ip, user_agent, event_type, target_type, target_id, vault_id, entry_hash}]` |
| `GET /audit/verify` | admin+ → `{ok, count, head_hash, checkpoints:[{ts, count, head_hash, signature}]}` |

The server records its own events (login, failed login, MFA, item writes, shares, revocations, rotations, membership changes) without any client involvement.
