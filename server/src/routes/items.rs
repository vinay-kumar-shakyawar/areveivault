use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use super::{bump_revision, item_json, vault_access, Body, ItemDbRow, ITEM_COLUMNS, P, Q};
use crate::attachments_fs;
use crate::audit::{self, Actor, Event};
use crate::auth::{AuthUser, ReqMeta};
use crate::error::{ApiResult, AppError};
use crate::state::{AppState, Tx};

const MAX_PAYLOAD: usize = 1_500_000;

#[derive(Deserialize)]
pub struct PutItemReq {
    vault_id: Uuid,
    version: i64,
    key_version: i32,
    wrapped_key: String,
    payload: String,
    #[serde(default)]
    expected_version: Option<i64>,
}

async fn fetch_item(tx: &mut Tx, id: Uuid, lock: bool) -> ApiResult<Option<ItemDbRow>> {
    let sql = format!("SELECT {ITEM_COLUMNS} FROM items WHERE id = $1{}", if lock { " FOR UPDATE" } else { "" });
    Ok(sqlx::query_as(&sql).bind(id).fetch_optional(&mut **tx).await?)
}

pub async fn put_item(
    State(st): State<AppState>,
    user: AuthUser,
    meta: ReqMeta,
    P(id): P<Uuid>,
    Body(r): Body<PutItemReq>,
) -> ApiResult<Json<Value>> {
    if r.payload.len() > MAX_PAYLOAD || r.wrapped_key.len() > 1024 {
        return Err(AppError::bad_request("item too large"));
    }
    let now = st.now();
    let mut tx = st.org_tx(user.org_id).await?;
    let target = vault_access(&mut tx, &user, r.vault_id).await?;
    target.require_write()?;
    if r.key_version != target.key_version {
        return Err(AppError::conflict("vault key was rotated; sync and retry"));
    }

    let existing = fetch_item(&mut tx, id, true).await?;
    let (event, created_at, created_by) = match (&existing, r.expected_version) {
        (None, None) => {
            if r.version != 1 {
                return Err(AppError::bad_request("new items must have version 1"));
            }
            ("item_create", now, Some(user.user_id))
        }
        (None, Some(_)) => return Err(AppError::not_found()),
        (Some(cur), expected) => {
            // Never reveal rows from vaults the caller cannot read.
            let src = match vault_access(&mut tx, &user, cur.1).await {
                Ok(a) => a,
                Err(_) => return Err(AppError::conflict("an item with this id already exists")),
            };
            match expected {
                Some(e) if e == cur.2 => {}
                _ => return Err(AppError::conflict_with(item_json(cur))),
            }
            if r.version != cur.2 + 1 {
                return Err(AppError::bad_request("version must be expected_version + 1"));
            }
            let moving = cur.1 != r.vault_id;
            if moving {
                src.require_write()?;
            }
            (if moving { "item_move" } else { "item_update" }, cur.7, cur.9)
        }
    };

    let rev = bump_revision(&mut tx, user.org_id).await?;
    let row: ItemDbRow = sqlx::query_as(&format!(
        "INSERT INTO items (id, org_id, vault_id, version, key_version, wrapped_key, payload, revision, created_at, updated_at, created_by, updated_by)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
         ON CONFLICT (id) DO UPDATE SET vault_id = EXCLUDED.vault_id, version = EXCLUDED.version, key_version = EXCLUDED.key_version,
             wrapped_key = EXCLUDED.wrapped_key, payload = EXCLUDED.payload, revision = EXCLUDED.revision,
             updated_at = EXCLUDED.updated_at, updated_by = EXCLUDED.updated_by
         RETURNING {ITEM_COLUMNS}"
    ))
    .bind(id)
    .bind(user.org_id)
    .bind(r.vault_id)
    .bind(r.version)
    .bind(r.key_version)
    .bind(&r.wrapped_key)
    .bind(&r.payload)
    .bind(rev)
    .bind(created_at)
    .bind(now)
    .bind(created_by)
    .bind(user.user_id)
    .fetch_one(&mut *tx)
    .await?;
    audit::record(&mut tx, &st, &Actor::from(&user, &meta), Event::new(event, "item", id).vault(r.vault_id)).await?;
    tx.commit().await?;
    st.publish(user.org_id, rev);
    Ok(Json(item_json(&row)))
}

#[derive(Deserialize)]
pub struct DeleteQuery {
    #[serde(default)]
    purge: bool,
}

pub async fn delete_item(
    State(st): State<AppState>,
    user: AuthUser,
    meta: ReqMeta,
    P(id): P<Uuid>,
    Q(q): Q<DeleteQuery>,
) -> ApiResult<StatusCode> {
    let mut tx = st.org_tx(user.org_id).await?;
    let cur = fetch_item(&mut tx, id, true).await?.ok_or_else(AppError::not_found)?;
    vault_access(&mut tx, &user, cur.1).await?.require_write()?;
    let rev = bump_revision(&mut tx, user.org_id).await?;
    let now = st.now();
    let mut files = vec![];
    if q.purge {
        files = purge_items(&mut tx, user.org_id, &[(id, cur.1)], rev, now).await?;
        audit::record(&mut tx, &st, &Actor::from(&user, &meta), Event::new("item_purge", "item", id).vault(cur.1)).await?;
    } else {
        sqlx::query("UPDATE items SET deleted_at = $2, revision = $3, updated_at = $2, updated_by = $4 WHERE id = $1")
            .bind(id)
            .bind(now)
            .bind(rev)
            .bind(user.user_id)
            .execute(&mut *tx)
            .await?;
        audit::record(&mut tx, &st, &Actor::from(&user, &meta), Event::new("item_delete", "item", id).vault(cur.1)).await?;
    }
    tx.commit().await?;
    attachments_fs::remove_all(&st, user.org_id, &files).await;
    st.publish(user.org_id, rev);
    Ok(StatusCode::NO_CONTENT)
}

/// Hard-delete items, writing tombstones. Returns attachment ids whose files must be removed after commit.
pub async fn purge_items(tx: &mut Tx, org_id: Uuid, items: &[(Uuid, Uuid)], rev: i64, now: i64) -> ApiResult<Vec<Uuid>> {
    let ids: Vec<Uuid> = items.iter().map(|i| i.0).collect();
    let files: Vec<(Uuid,)> = sqlx::query_as("SELECT id FROM attachments WHERE item_id = ANY($1)").bind(&ids).fetch_all(&mut **tx).await?;
    for (item_id, vault_id) in items {
        sqlx::query(
            "INSERT INTO item_tombstones (item_id, org_id, vault_id, revision, purged_at) VALUES ($1,$2,$3,$4,$5)
             ON CONFLICT (item_id) DO UPDATE SET revision = EXCLUDED.revision, purged_at = EXCLUDED.purged_at",
        )
        .bind(item_id)
        .bind(org_id)
        .bind(vault_id)
        .bind(rev)
        .bind(now)
        .execute(&mut **tx)
        .await?;
    }
    sqlx::query("DELETE FROM items WHERE id = ANY($1)").bind(&ids).execute(&mut **tx).await?;
    Ok(files.into_iter().map(|f| f.0).collect())
}

pub async fn restore_item(State(st): State<AppState>, user: AuthUser, meta: ReqMeta, P(id): P<Uuid>) -> ApiResult<Json<Value>> {
    let mut tx = st.org_tx(user.org_id).await?;
    let cur = fetch_item(&mut tx, id, true).await?.ok_or_else(AppError::not_found)?;
    vault_access(&mut tx, &user, cur.1).await?.require_write()?;
    let rev = bump_revision(&mut tx, user.org_id).await?;
    let row: ItemDbRow = sqlx::query_as(&format!(
        "UPDATE items SET deleted_at = NULL, revision = $2 WHERE id = $1 RETURNING {ITEM_COLUMNS}"
    ))
    .bind(id)
    .bind(rev)
    .fetch_one(&mut *tx)
    .await?;
    audit::record(&mut tx, &st, &Actor::from(&user, &meta), Event::new("item_restore", "item", id).vault(cur.1)).await?;
    tx.commit().await?;
    st.publish(user.org_id, rev);
    Ok(Json(item_json(&row)))
}
