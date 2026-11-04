use axum::body::Bytes;
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use uuid::Uuid;

use super::{vault_access, P, Q};
use crate::attachments_fs;
use crate::audit::{self, Actor, Event};
use crate::auth::{AuthUser, ReqMeta};
use crate::error::{ApiResult, AppError};
use crate::state::AppState;

#[derive(Deserialize)]
pub struct PutQuery {
    item_id: Uuid,
}

pub async fn put_attachment(
    State(st): State<AppState>,
    user: AuthUser,
    meta: ReqMeta,
    P(id): P<Uuid>,
    Q(q): Q<PutQuery>,
    body: Bytes,
) -> ApiResult<StatusCode> {
    if body.is_empty() {
        return Err(AppError::bad_request("empty attachment"));
    }
    let mut tx = st.org_tx(user.org_id).await?;
    let (vault_id,): (Uuid,) = sqlx::query_as("SELECT vault_id FROM items WHERE id = $1")
        .bind(q.item_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(AppError::not_found)?;
    vault_access(&mut tx, &user, vault_id).await?.require_write()?;
    sqlx::query("INSERT INTO attachments (id, org_id, item_id, size, uploaded_by, created_at) VALUES ($1,$2,$3,$4,$5,$6)")
        .bind(id)
        .bind(user.org_id)
        .bind(q.item_id)
        .bind(body.len() as i64)
        .bind(user.user_id)
        .bind(st.now())
        .execute(&mut *tx)
        .await?;
    attachments_fs::write(&st, user.org_id, id, &body).await.map_err(|e| {
        tracing::error!(error = %e, "attachment write failed");
        AppError::internal()
    })?;
    audit::record(&mut tx, &st, &Actor::from(&user, &meta), Event::new("attachment_upload", "attachment", id).vault(vault_id)).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn attachment_vault(st: &AppState, user: &AuthUser, id: Uuid, write: bool) -> ApiResult<()> {
    let mut tx = st.org_tx(user.org_id).await?;
    let (vault_id,): (Uuid,) = sqlx::query_as("SELECT i.vault_id FROM attachments a JOIN items i ON i.id = a.item_id WHERE a.id = $1")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(AppError::not_found)?;
    let a = vault_access(&mut tx, user, vault_id).await?;
    if write {
        a.require_write()?;
    }
    tx.commit().await?;
    Ok(())
}

pub async fn get_attachment(State(st): State<AppState>, user: AuthUser, P(id): P<Uuid>) -> ApiResult<Response> {
    attachment_vault(&st, &user, id, false).await?;
    let data = tokio::fs::read(attachments_fs::path(&st, user.org_id, id)).await.map_err(|_| AppError::not_found())?;
    Ok(([(CONTENT_TYPE, "application/octet-stream")], data).into_response())
}

pub async fn delete_attachment(State(st): State<AppState>, user: AuthUser, meta: ReqMeta, P(id): P<Uuid>) -> ApiResult<StatusCode> {
    attachment_vault(&st, &user, id, true).await?;
    let mut tx = st.org_tx(user.org_id).await?;
    sqlx::query("DELETE FROM attachments WHERE id = $1").bind(id).execute(&mut *tx).await?;
    audit::record(&mut tx, &st, &Actor::from(&user, &meta), Event::new("attachment_delete", "attachment", id)).await?;
    tx.commit().await?;
    attachments_fs::remove_all(&st, user.org_id, &[id]).await;
    Ok(StatusCode::NO_CONTENT)
}
