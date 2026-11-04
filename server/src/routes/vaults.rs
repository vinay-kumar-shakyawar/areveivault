//! Clients, project vaults, vault membership and key rotation.

use std::collections::HashSet;

use arevei_core::share::KeyGrant;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use super::{bump_revision, parse_uuid, store_grant, vault_access, Body, P};
use crate::attachments_fs;
use crate::audit::{self, Actor, Event};
use crate::auth::{AuthUser, ReqMeta};
use crate::error::{ApiResult, AppError};
use crate::state::AppState;

const MAX_NAME: usize = 4096;

// ------------------------------------------------------------------ clients

#[derive(Deserialize)]
pub struct CreateClientReq {
    id: Uuid,
    name_enc: String,
}

pub async fn create_client(State(st): State<AppState>, user: AuthUser, meta: ReqMeta, Body(r): Body<CreateClientReq>) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    if r.name_enc.len() > MAX_NAME {
        return Err(AppError::bad_request("name too large"));
    }
    let mut tx = st.org_tx(user.org_id).await?;
    let rev = bump_revision(&mut tx, user.org_id).await?;
    sqlx::query("INSERT INTO clients (id, org_id, name_enc, revision, created_at) VALUES ($1,$2,$3,$4,$5)")
        .bind(r.id)
        .bind(user.org_id)
        .bind(&r.name_enc)
        .bind(rev)
        .bind(st.now())
        .execute(&mut *tx)
        .await?;
    audit::record(&mut tx, &st, &Actor::from(&user, &meta), Event::new("client_create", "client", r.id)).await?;
    tx.commit().await?;
    st.publish(user.org_id, rev);
    Ok(Json(json!({ "id": r.id, "name_enc": r.name_enc, "revision": rev })))
}

#[derive(Deserialize)]
pub struct NameReq {
    name_enc: String,
}

pub async fn update_client(State(st): State<AppState>, user: AuthUser, meta: ReqMeta, P(id): P<Uuid>, Body(r): Body<NameReq>) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    if r.name_enc.len() > MAX_NAME {
        return Err(AppError::bad_request("name too large"));
    }
    let mut tx = st.org_tx(user.org_id).await?;
    let rev = bump_revision(&mut tx, user.org_id).await?;
    let n = sqlx::query("UPDATE clients SET name_enc = $2, revision = $3 WHERE id = $1")
        .bind(id)
        .bind(&r.name_enc)
        .bind(rev)
        .execute(&mut *tx)
        .await?;
    if n.rows_affected() == 0 {
        return Err(AppError::not_found());
    }
    audit::record(&mut tx, &st, &Actor::from(&user, &meta), Event::new("client_update", "client", id)).await?;
    tx.commit().await?;
    st.publish(user.org_id, rev);
    Ok(Json(json!({ "id": id, "name_enc": r.name_enc, "revision": rev })))
}

pub async fn delete_client(State(st): State<AppState>, user: AuthUser, meta: ReqMeta, P(id): P<Uuid>) -> ApiResult<StatusCode> {
    user.require_admin()?;
    let mut tx = st.org_tx(user.org_id).await?;
    let (projects,): (i64,) = sqlx::query_as("SELECT count(*) FROM vaults WHERE client_id = $1").bind(id).fetch_one(&mut *tx).await?;
    if projects > 0 {
        return Err(AppError::conflict("client still has projects"));
    }
    let rev = bump_revision(&mut tx, user.org_id).await?;
    if sqlx::query("DELETE FROM clients WHERE id = $1").bind(id).execute(&mut *tx).await?.rows_affected() == 0 {
        return Err(AppError::not_found());
    }
    audit::record(&mut tx, &st, &Actor::from(&user, &meta), Event::new("client_delete", "client", id)).await?;
    tx.commit().await?;
    st.publish(user.org_id, rev);
    Ok(StatusCode::NO_CONTENT)
}

// ------------------------------------------------------------------ vaults

#[derive(Deserialize)]
pub struct CreateVaultReq {
    id: Uuid,
    #[serde(default)]
    client_id: Option<Uuid>,
    name_enc: String,
    key_version: i32,
    admin_wrapped_key: String,
    #[serde(default)]
    grants: Vec<KeyGrant>,
}

pub async fn create_vault(State(st): State<AppState>, user: AuthUser, meta: ReqMeta, Body(r): Body<CreateVaultReq>) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    if r.key_version != 1 {
        return Err(AppError::bad_request("new projects start at key_version 1"));
    }
    if r.name_enc.len() > MAX_NAME || r.admin_wrapped_key.len() > 1024 {
        return Err(AppError::bad_request("field too large"));
    }
    for g in &r.grants {
        if g.keyring_id != r.id.to_string() || g.key_version != 1 || g.grantor_id != user.user_id.to_string() {
            return Err(AppError::bad_request("grant does not match this project"));
        }
    }
    let now = st.now();
    let mut tx = st.org_tx(user.org_id).await?;
    let rev = bump_revision(&mut tx, user.org_id).await?;
    sqlx::query(
        "INSERT INTO vaults (id, org_id, kind, client_id, name_enc, key_version, admin_wrapped_key, revision, created_at)
         VALUES ($1,$2,'project',$3,$4,1,$5,$6,$7)",
    )
    .bind(r.id)
    .bind(user.org_id)
    .bind(r.client_id)
    .bind(&r.name_enc)
    .bind(&r.admin_wrapped_key)
    .bind(rev)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    for g in &r.grants {
        store_grant(&mut tx, user.org_id, g, now).await?;
    }
    audit::record(&mut tx, &st, &Actor::from(&user, &meta), Event::new("vault_create", "vault", r.id).vault(r.id)).await?;
    tx.commit().await?;
    st.publish(user.org_id, rev);
    Ok(Json(json!({
        "id": r.id, "kind": "project", "client_id": r.client_id, "name_enc": r.name_enc, "key_version": 1,
        "admin_wrapped_key": r.admin_wrapped_key, "role": "manager", "copy_only": false, "revision": rev,
    })))
}

pub async fn update_vault(State(st): State<AppState>, user: AuthUser, meta: ReqMeta, P(id): P<Uuid>, Body(r): Body<NameReq>) -> ApiResult<Json<Value>> {
    if r.name_enc.len() > MAX_NAME {
        return Err(AppError::bad_request("name too large"));
    }
    let mut tx = st.org_tx(user.org_id).await?;
    vault_access(&mut tx, &user, id).await?.require_manage()?;
    let rev = bump_revision(&mut tx, user.org_id).await?;
    sqlx::query("UPDATE vaults SET name_enc = $2, revision = $3 WHERE id = $1").bind(id).bind(&r.name_enc).bind(rev).execute(&mut *tx).await?;
    audit::record(&mut tx, &st, &Actor::from(&user, &meta), Event::new("vault_update", "vault", id).vault(id)).await?;
    tx.commit().await?;
    st.publish(user.org_id, rev);
    Ok(Json(json!({ "id": id, "name_enc": r.name_enc, "revision": rev })))
}

/// Deletes a project: its items are purged (tombstoned) and the vault removed.
pub async fn delete_vault(State(st): State<AppState>, user: AuthUser, meta: ReqMeta, P(id): P<Uuid>) -> ApiResult<StatusCode> {
    user.require_admin()?;
    let mut tx = st.org_tx(user.org_id).await?;
    let access = vault_access(&mut tx, &user, id).await?;
    if access.kind != "project" {
        return Err(AppError::bad_request("personal vaults cannot be deleted"));
    }
    let rev = bump_revision(&mut tx, user.org_id).await?;
    let items: Vec<(Uuid, Uuid)> = sqlx::query_as("SELECT id, vault_id FROM items WHERE vault_id = $1").bind(id).fetch_all(&mut *tx).await?;
    let files = super::items::purge_items(&mut tx, user.org_id, &items, rev, st.now()).await?;
    sqlx::query("DELETE FROM key_grants WHERE keyring_id = $1").bind(id.to_string()).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM vaults WHERE id = $1").bind(id).execute(&mut *tx).await?;
    audit::record(&mut tx, &st, &Actor::from(&user, &meta), Event::new("vault_delete", "vault", id).vault(id)).await?;
    tx.commit().await?;
    attachments_fs::remove_all(&st, user.org_id, &files).await;
    st.publish(user.org_id, rev);
    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_members(State(st): State<AppState>, user: AuthUser, P(id): P<Uuid>) -> ApiResult<Json<Value>> {
    let mut tx = st.org_tx(user.org_id).await?;
    let access = vault_access(&mut tx, &user, id).await?;
    if access.kind != "project" {
        return Ok(Json(json!([])));
    }
    let rows: Vec<(Uuid, String, bool)> =
        sqlx::query_as("SELECT user_id, role, copy_only FROM vault_permissions WHERE vault_id = $1 ORDER BY created_at")
            .bind(id)
            .fetch_all(&mut *tx)
            .await?;
    tx.commit().await?;
    Ok(Json(json!(rows.into_iter().map(|(u, r, c)| json!({ "user_id": u, "role": r, "copy_only": c })).collect::<Vec<_>>())))
}

#[derive(Deserialize)]
pub struct PutMemberReq {
    role: String,
    #[serde(default)]
    copy_only: bool,
    #[serde(default)]
    grant: Option<KeyGrant>,
}

pub async fn put_member(
    State(st): State<AppState>,
    user: AuthUser,
    meta: ReqMeta,
    P((id, member)): P<(Uuid, Uuid)>,
    Body(r): Body<PutMemberReq>,
) -> ApiResult<Json<Value>> {
    if !matches!(r.role.as_str(), "manager" | "member" | "read_only") {
        return Err(AppError::bad_request("role must be manager, member or read_only"));
    }
    let now = st.now();
    let mut tx = st.org_tx(user.org_id).await?;
    let access = vault_access(&mut tx, &user, id).await?;
    access.require_manage()?;
    let status: Option<(String,)> = sqlx::query_as("SELECT status FROM org_memberships WHERE user_id = $1").bind(member).fetch_optional(&mut *tx).await?;
    if status.map(|s| s.0) != Some("active".into()) {
        return Err(AppError::bad_request("user is not an active member of this organization"));
    }
    if let Some(g) = &r.grant {
        if g.keyring_id != id.to_string()
            || g.key_version as i32 != access.key_version
            || g.recipient_id != member.to_string()
            || g.grantor_id != user.user_id.to_string()
        {
            return Err(AppError::bad_request("grant does not match this project, key version and member"));
        }
        store_grant(&mut tx, user.org_id, g, now).await?;
    } else {
        let has: Option<(i64,)> = sqlx::query_as("SELECT id FROM key_grants WHERE keyring_id = $1 AND key_version = $2 AND recipient_id = $3")
            .bind(id.to_string())
            .bind(access.key_version)
            .bind(member)
            .fetch_optional(&mut *tx)
            .await?;
        if has.is_none() {
            return Err(AppError::bad_request("a key grant is required to add this member"));
        }
    }
    sqlx::query(
        "INSERT INTO vault_permissions (vault_id, user_id, org_id, role, copy_only, created_at) VALUES ($1,$2,$3,$4,$5,$6)
         ON CONFLICT (vault_id, user_id) DO UPDATE SET role = EXCLUDED.role, copy_only = EXCLUDED.copy_only",
    )
    .bind(id)
    .bind(member)
    .bind(user.org_id)
    .bind(&r.role)
    .bind(r.copy_only)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    let rev = bump_revision(&mut tx, user.org_id).await?;
    sqlx::query("UPDATE vaults SET revision = $2 WHERE id = $1").bind(id).bind(rev).execute(&mut *tx).await?;
    audit::record(&mut tx, &st, &Actor::from(&user, &meta), Event::new("vault_share", "user", member).vault(id)).await?;
    tx.commit().await?;
    st.publish(user.org_id, rev);
    Ok(Json(json!({ "user_id": member, "role": r.role, "copy_only": r.copy_only })))
}

pub async fn remove_member(
    State(st): State<AppState>,
    user: AuthUser,
    meta: ReqMeta,
    P((id, member)): P<(Uuid, Uuid)>,
) -> ApiResult<StatusCode> {
    let mut tx = st.org_tx(user.org_id).await?;
    vault_access(&mut tx, &user, id).await?.require_manage()?;
    sqlx::query("DELETE FROM vault_permissions WHERE vault_id = $1 AND user_id = $2").bind(id).bind(member).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM key_grants WHERE keyring_id = $1 AND recipient_id = $2").bind(id.to_string()).bind(member).execute(&mut *tx).await?;
    let rev = bump_revision(&mut tx, user.org_id).await?;
    audit::record(&mut tx, &st, &Actor::from(&user, &meta), Event::new("vault_revoke", "user", member).vault(id)).await?;
    tx.commit().await?;
    st.publish(user.org_id, rev);
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct RotateItem {
    id: Uuid,
    version: i64,
    key_version: i32,
    wrapped_key: String,
}

#[derive(Deserialize)]
pub struct RotateReq {
    key_version: i32,
    name_enc: String,
    admin_wrapped_key: String,
    grants: Vec<KeyGrant>,
    items: Vec<RotateItem>,
}

/// Atomic vault key rotation (after revocation). The server checks that the new
/// version is current+1, that every item is re-wrapped exactly once at its current
/// version, and that every remaining member receives a grant.
pub async fn rotate(State(st): State<AppState>, user: AuthUser, meta: ReqMeta, P(id): P<Uuid>, Body(r): Body<RotateReq>) -> ApiResult<Json<Value>> {
    let now = st.now();
    let mut tx = st.org_tx(user.org_id).await?;
    let (current,): (i32,) = sqlx::query_as("SELECT key_version FROM vaults WHERE id = $1 AND kind = 'project' FOR UPDATE")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(AppError::not_found)?;
    vault_access(&mut tx, &user, id).await?.require_manage()?;
    if r.key_version != current + 1 {
        return Err(AppError::conflict("key_version must be the current version + 1"));
    }

    let existing: Vec<(Uuid, i64)> = sqlx::query_as("SELECT id, version FROM items WHERE vault_id = $1 FOR UPDATE").bind(id).fetch_all(&mut *tx).await?;
    let submitted: HashSet<Uuid> = r.items.iter().map(|i| i.id).collect();
    if submitted.len() != r.items.len() || submitted.len() != existing.len() || existing.iter().any(|(i, _)| !submitted.contains(i)) {
        return Err(AppError::conflict("items must cover every item in the vault exactly once; sync and retry"));
    }
    for it in &r.items {
        let cur_version = existing.iter().find(|(i, _)| *i == it.id).map(|(_, v)| *v).unwrap();
        if it.version != cur_version {
            return Err(AppError::conflict("an item changed during rotation; sync and retry"));
        }
        if it.key_version != r.key_version || it.wrapped_key.len() > 1024 {
            return Err(AppError::bad_request("invalid rotated item"));
        }
    }
    for g in &r.grants {
        if g.keyring_id != id.to_string() || g.key_version as i32 != r.key_version || g.grantor_id != user.user_id.to_string() {
            return Err(AppError::bad_request("grant does not match this rotation"));
        }
    }
    let granted: HashSet<String> = r.grants.iter().map(|g| g.recipient_id.clone()).collect();
    let permitted: Vec<(Uuid,)> = sqlx::query_as("SELECT user_id FROM vault_permissions WHERE vault_id = $1").bind(id).fetch_all(&mut *tx).await?;
    if let Some((missing,)) = permitted.iter().find(|(u,)| !granted.contains(&u.to_string())) {
        return Err(AppError::bad_request(format!("member {missing} has no grant for the new key; remove them first or include a grant")));
    }

    let rev = bump_revision(&mut tx, user.org_id).await?;
    for it in &r.items {
        sqlx::query("UPDATE items SET key_version = $2, wrapped_key = $3, revision = $4 WHERE id = $1")
            .bind(it.id)
            .bind(it.key_version)
            .bind(&it.wrapped_key)
            .bind(rev)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("UPDATE vaults SET key_version = $2, name_enc = $3, admin_wrapped_key = $4, revision = $5 WHERE id = $1")
        .bind(id)
        .bind(r.key_version)
        .bind(&r.name_enc)
        .bind(&r.admin_wrapped_key)
        .bind(rev)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM key_grants WHERE keyring_id = $1").bind(id.to_string()).execute(&mut *tx).await?;
    for g in &r.grants {
        parse_uuid(&g.recipient_id)?;
        store_grant(&mut tx, user.org_id, g, now).await?;
    }
    audit::record(&mut tx, &st, &Actor::from(&user, &meta), Event::new("vault_rotate", "vault", id).vault(id)).await?;
    tx.commit().await?;
    st.publish(user.org_id, rev);
    Ok(Json(json!({ "id": id, "key_version": r.key_version, "revision": rev, "items": r.items.len() })))
}
