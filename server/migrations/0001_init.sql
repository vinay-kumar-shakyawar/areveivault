-- Arevei Vault schema v1. See docs/schema.md.
-- All timestamps are Unix seconds (bigint). Columns suffixed _enc / named payload,
-- wrapped_*, org_secrets, keyset, record are ciphertext or opaque protocol data.

-- ---------------------------------------------------------------- tenancy root
CREATE TABLE organizations (
    id            uuid PRIMARY KEY,
    org_sign_pk   text   NOT NULL,              -- Ed25519 public key (base64)
    org_secrets   text   NOT NULL,              -- org signing key, encrypted under org admin key
    revision      bigint NOT NULL DEFAULT 0,    -- per-org monotonic sync revision
    audit_head    bytea  NOT NULL DEFAULT '\x0000000000000000000000000000000000000000000000000000000000000000',
    audit_count   bigint NOT NULL DEFAULT 0,
    created_at    bigint NOT NULL
);

-- ---------------------------------------------------------------- user-scoped (no RLS: looked up before an org is known)
CREATE TABLE users (
    id          uuid PRIMARY KEY,
    org_id      uuid NOT NULL REFERENCES organizations(id),
    email       text NOT NULL UNIQUE,
    status      text NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at  bigint NOT NULL
);
CREATE INDEX users_org_idx ON users(org_id);

CREATE TABLE opaque_records (
    user_id     uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    record      bytea  NOT NULL,                -- OPAQUE registration record (no password-equivalent)
    updated_at  bigint NOT NULL
);

CREATE TABLE keysets (
    user_id     uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    keyset      jsonb  NOT NULL,                -- EncryptedKeyset (wrapped ASK, wrapped private keys, public keys)
    updated_at  bigint NOT NULL
);

CREATE TABLE mfa_totp (
    user_id         uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret_enc      bytea  NOT NULL,            -- TOTP seed, XChaCha20-Poly1305 under server key
    last_used_step  bigint NOT NULL DEFAULT 0,  -- replay protection
    created_at      bigint NOT NULL
);

CREATE TABLE devices (
    id            uuid PRIMARY KEY,
    user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name          text NOT NULL,
    ip            text,
    created_at    bigint NOT NULL,
    last_seen_at  bigint NOT NULL
);
CREATE INDEX devices_user_idx ON devices(user_id);

CREATE TABLE sessions (
    token_hash    bytea PRIMARY KEY,            -- SHA-256 of the bearer/cookie token
    user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id     uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    created_at    bigint NOT NULL,
    last_seen_at  bigint NOT NULL
);
CREATE INDEX sessions_user_idx ON sessions(user_id);

CREATE TABLE pending_tokens (
    token_hash  bytea PRIMARY KEY,
    kind        text   NOT NULL,
    data        jsonb  NOT NULL,
    attempts    int    NOT NULL DEFAULT 0,
    expires_at  bigint NOT NULL
);
CREATE INDEX pending_tokens_exp_idx ON pending_tokens(expires_at);

CREATE TABLE user_prefs (
    user_id     uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    blob        text   NOT NULL,                -- encrypted under the user's ASK
    updated_at  bigint NOT NULL
);

CREATE TABLE server_state (
    key    text PRIMARY KEY,
    value  bytea NOT NULL                       -- e.g. OPAQUE ServerSetup, encrypted under server key
);

-- ---------------------------------------------------------------- org-scoped (RLS)
CREATE TABLE org_memberships (
    org_id       uuid NOT NULL REFERENCES organizations(id),
    user_id      uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    role         text NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    status       text NOT NULL CHECK (status IN ('pending_approval', 'active', 'disabled')),
    cert         jsonb,                         -- MembershipCert signed by the org key (client-side)
    created_at   bigint NOT NULL,
    approved_at  bigint
);
CREATE INDEX org_memberships_org_idx ON org_memberships(org_id);

CREATE TABLE invites (
    id          uuid PRIMARY KEY,
    org_id      uuid NOT NULL REFERENCES organizations(id),
    token_hash  bytea NOT NULL UNIQUE,
    email       text NOT NULL,
    role        text NOT NULL CHECK (role IN ('admin', 'member')),
    created_by  uuid NOT NULL REFERENCES users(id),
    created_at  bigint NOT NULL,
    expires_at  bigint NOT NULL,
    used_at     bigint,
    used_by     uuid REFERENCES users(id)
);
CREATE INDEX invites_org_idx ON invites(org_id);

CREATE TABLE clients (
    id          uuid PRIMARY KEY,
    org_id      uuid NOT NULL REFERENCES organizations(id),
    name_enc    text   NOT NULL,                -- encrypted under org directory key
    revision    bigint NOT NULL,
    created_at  bigint NOT NULL
);
CREATE INDEX clients_org_idx ON clients(org_id);

CREATE TABLE vaults (
    id                 uuid PRIMARY KEY,
    org_id             uuid NOT NULL REFERENCES organizations(id),
    kind               text NOT NULL CHECK (kind IN ('personal', 'project')),
    client_id          uuid REFERENCES clients(id),
    owner_user_id      uuid REFERENCES users(id) ON DELETE CASCADE,
    name_enc           text,                    -- encrypted under the vault key
    key_version        int    NOT NULL DEFAULT 1,
    admin_wrapped_key  text,                    -- vault key wrapped by org admin key
    revision           bigint NOT NULL,
    created_at         bigint NOT NULL,
    CHECK ((kind = 'personal') = (owner_user_id IS NOT NULL))
);
CREATE INDEX vaults_org_idx ON vaults(org_id);
CREATE INDEX vaults_client_idx ON vaults(client_id);

CREATE TABLE vault_permissions (
    vault_id    uuid NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    user_id     uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id      uuid NOT NULL REFERENCES organizations(id),
    role        text NOT NULL CHECK (role IN ('manager', 'member', 'read_only')),
    copy_only   boolean NOT NULL DEFAULT false,
    created_at  bigint NOT NULL,
    PRIMARY KEY (vault_id, user_id)
);
CREATE INDEX vault_permissions_user_idx ON vault_permissions(user_id);

CREATE TABLE key_grants (
    id            bigserial PRIMARY KEY,
    org_id        uuid NOT NULL REFERENCES organizations(id),
    keyring_id    text NOT NULL,                -- vault id, org-admin:<org>, org-dir:<org>
    key_version   int  NOT NULL,
    recipient_id  uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    grantor_id    uuid NOT NULL REFERENCES users(id),
    wrapped       text NOT NULL,                -- HPKE-sealed key
    signature     text NOT NULL,                -- grantor Ed25519 signature
    created_at    bigint NOT NULL,
    UNIQUE (keyring_id, key_version, recipient_id)
);
CREATE INDEX key_grants_recipient_idx ON key_grants(recipient_id);

CREATE TABLE items (
    id           uuid PRIMARY KEY,
    org_id       uuid NOT NULL REFERENCES organizations(id),
    vault_id     uuid NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    version      bigint NOT NULL,
    key_version  int    NOT NULL,
    wrapped_key  text   NOT NULL,               -- item key wrapped by vault key
    payload      text   NOT NULL,               -- padded, encrypted item (title, URLs, secrets, ...)
    revision     bigint NOT NULL,
    created_at   bigint NOT NULL,
    updated_at   bigint NOT NULL,
    created_by   uuid REFERENCES users(id),
    updated_by   uuid REFERENCES users(id),
    deleted_at   bigint
);
CREATE INDEX items_vault_rev_idx ON items(vault_id, revision);
CREATE INDEX items_deleted_idx ON items(deleted_at) WHERE deleted_at IS NOT NULL;

CREATE TABLE item_tombstones (
    item_id    uuid PRIMARY KEY,
    org_id     uuid NOT NULL REFERENCES organizations(id),
    vault_id   uuid NOT NULL,
    revision   bigint NOT NULL,
    purged_at  bigint NOT NULL
);
CREATE INDEX item_tombstones_vault_rev_idx ON item_tombstones(vault_id, revision);

CREATE TABLE attachments (
    id           uuid PRIMARY KEY,
    org_id       uuid NOT NULL REFERENCES organizations(id),
    item_id      uuid NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    size         bigint NOT NULL,
    uploaded_by  uuid NOT NULL REFERENCES users(id),
    created_at   bigint NOT NULL
);
CREATE INDEX attachments_item_idx ON attachments(item_id);

CREATE TABLE audit_events (
    id             bigserial PRIMARY KEY,
    org_id         uuid NOT NULL REFERENCES organizations(id),
    seq            bigint NOT NULL,
    ts             bigint NOT NULL,
    actor_user_id  uuid,
    device_id      uuid,
    ip             text,
    user_agent     text,
    event_type     text NOT NULL,
    target_type    text NOT NULL,
    target_id      text,
    vault_id       uuid,
    client_ts      bigint,
    prev_hash      bytea NOT NULL,
    entry_hash     bytea NOT NULL,
    UNIQUE (org_id, seq)
);

CREATE TABLE audit_checkpoints (
    id          bigserial PRIMARY KEY,
    org_id      uuid NOT NULL REFERENCES organizations(id),
    ts          bigint NOT NULL,
    count       bigint NOT NULL,
    head_hash   bytea  NOT NULL,
    signature   bytea  NOT NULL
);
CREATE INDEX audit_checkpoints_org_idx ON audit_checkpoints(org_id, id);

-- Audit log is append-only, even for superusers (tamper evidence; see architecture §11).
CREATE FUNCTION audit_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit log is append-only';
END $$;
CREATE TRIGGER audit_events_immutable BEFORE UPDATE OR DELETE ON audit_events
    FOR EACH ROW EXECUTE FUNCTION audit_immutable();
CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION audit_immutable();
CREATE TRIGGER audit_checkpoints_immutable BEFORE UPDATE OR DELETE ON audit_checkpoints
    FOR EACH ROW EXECUTE FUNCTION audit_immutable();

-- ---------------------------------------------------------------- row-level security
-- Every request transaction runs `set_config('app.org_id', <session org>, true)`.
-- '*' is used only by auth bootstrap (invite lookup, first-org check) and background jobs.
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['org_memberships','invites','clients','vaults','vault_permissions',
                             'key_grants','items','item_tombstones','attachments','audit_events','audit_checkpoints']
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($p$CREATE POLICY org_isolation ON %I
            USING (org_id::text = current_setting('app.org_id', true) OR current_setting('app.org_id', true) = '*')
            WITH CHECK (org_id::text = current_setting('app.org_id', true) OR current_setting('app.org_id', true) = '*')$p$, t);
    END LOOP;
END $$;
ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY org_isolation ON organizations
    USING (id::text = current_setting('app.org_id', true) OR current_setting('app.org_id', true) = '*')
    WITH CHECK (id::text = current_setting('app.org_id', true) OR current_setting('app.org_id', true) = '*');

-- ---------------------------------------------------------------- application role
-- The server connects as the schema owner but immediately `SET ROLE arevei_app`, a
-- non-superuser, non-owner role, so RLS applies and the audit log is insert-only.
DO $$ BEGIN
    CREATE ROLE arevei_app NOLOGIN;
EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
END $$;
DO $$ BEGIN
    EXECUTE format('GRANT arevei_app TO %I', current_user);
EXCEPTION WHEN OTHERS THEN NULL;
END $$;
GRANT USAGE ON SCHEMA public TO arevei_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO arevei_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO arevei_app;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_events, audit_checkpoints FROM arevei_app;
REVOKE ALL ON _sqlx_migrations FROM arevei_app;
