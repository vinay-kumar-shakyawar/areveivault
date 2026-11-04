use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use super::{Body, P};
use crate::auth::AuthUser;
use crate::error::{ApiResult, AppError};
use crate::state::AppState;

pub async fn keyset(State(st): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    let (ks,): (Value,) = sqlx::query_as("SELECT keyset FROM keysets WHERE user_id = $1").bind(user.user_id).fetch_one(&st.db).await?;
    Ok(Json(ks))
}

pub async fn get_prefs(State(st): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    let row: Option<(String,)> = sqlx::query_as("SELECT blob FROM user_prefs WHERE user_id = $1").bind(user.user_id).fetch_optional(&st.db).await?;
    Ok(Json(json!({ "blob": row.map(|r| r.0) })))
}

#[derive(Deserialize)]
pub struct PrefsReq {
    blob: String,
}

pub async fn put_prefs(State(st): State<AppState>, user: AuthUser, Body(r): Body<PrefsReq>) -> ApiResult<Json<Value>> {
    if r.blob.len() > 256 * 1024 {
        return Err(AppError::bad_request("preferences too large"));
    }
    sqlx::query(
        "INSERT INTO user_prefs (user_id, blob, updated_at) VALUES ($1,$2,$3)
         ON CONFLICT (user_id) DO UPDATE SET blob = EXCLUDED.blob, updated_at = EXCLUDED.updated_at",
    )
    .bind(user.user_id)
    .bind(&r.blob)
    .bind(st.now())
    .execute(&st.db)
    .await?;
    Ok(Json(json!({ "blob": r.blob })))
}

pub async fn devices(State(st): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    let rows: Vec<(Uuid, String, i64, i64)> =
        sqlx::query_as("SELECT id, name, created_at, last_seen_at FROM devices WHERE user_id = $1 ORDER BY last_seen_at DESC")
            .bind(user.user_id)
            .fetch_all(&st.db)
            .await?;
    Ok(Json(json!(rows
        .into_iter()
        .map(|(id, name, created_at, last_seen_at)| json!({
            "id": id, "name": name, "created_at": created_at, "last_seen_at": last_seen_at,
            "current": id == user.device_id,
        }))
        .collect::<Vec<_>>())))
}

pub async fn revoke_device(State(st): State<AppState>, user: AuthUser, P(id): P<Uuid>) -> ApiResult<StatusCode> {
    let r = sqlx::query("DELETE FROM devices WHERE id = $1 AND user_id = $2").bind(id).bind(user.user_id).execute(&st.db).await?;
    if r.rows_affected() == 0 {
        return Err(AppError::not_found());
    }
    Ok(StatusCode::NO_CONTENT)
}
