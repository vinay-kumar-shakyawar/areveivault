//! Short-lived, single-use protocol tokens (signup, login, mfa, pending registration),
//! stored hashed in Postgres with a TTL.

use serde_json::Value;

use crate::auth::{hash_token, new_token};
use crate::error::ApiResult;
use crate::state::AppState;

pub const MAX_ATTEMPTS: i32 = 5;

pub async fn create(state: &AppState, kind: &str, data: &Value, ttl_secs: i64) -> ApiResult<String> {
    let token = new_token();
    sqlx::query("INSERT INTO pending_tokens (token_hash, kind, data, expires_at) VALUES ($1,$2,$3,$4)")
        .bind(hash_token(&token))
        .bind(kind)
        .bind(data)
        .bind(state.now() + ttl_secs)
        .execute(&state.db)
        .await?;
    Ok(token)
}

/// Consume a token (single use). `None` if unknown, expired or of another kind.
pub async fn take(state: &AppState, kind: &str, token: &str) -> ApiResult<Option<Value>> {
    let row: Option<(Value,)> = sqlx::query_as(
        "DELETE FROM pending_tokens WHERE token_hash = $1 AND kind = $2 AND expires_at > $3 RETURNING data",
    )
    .bind(hash_token(token))
    .bind(kind)
    .bind(state.now())
    .fetch_optional(&state.db)
    .await?;
    Ok(row.map(|r| r.0))
}

/// Count one verification attempt against a token without consuming it.
/// Returns `None` once `MAX_ATTEMPTS` is exhausted (the token is then deleted).
pub async fn attempt(state: &AppState, kind: &str, token: &str) -> ApiResult<Option<Value>> {
    let hash = hash_token(token);
    let row: Option<(Value, i32)> = sqlx::query_as(
        "UPDATE pending_tokens SET attempts = attempts + 1
         WHERE token_hash = $1 AND kind = $2 AND expires_at > $3 AND attempts < $4
         RETURNING data, attempts",
    )
    .bind(&hash)
    .bind(kind)
    .bind(state.now())
    .bind(MAX_ATTEMPTS)
    .fetch_optional(&state.db)
    .await?;
    if row.is_none() {
        sqlx::query("DELETE FROM pending_tokens WHERE token_hash = $1").bind(&hash).execute(&state.db).await?;
    }
    Ok(row.map(|r| r.0))
}

pub async fn delete(state: &AppState, token: &str) -> ApiResult<()> {
    sqlx::query("DELETE FROM pending_tokens WHERE token_hash = $1").bind(hash_token(token)).execute(&state.db).await?;
    Ok(())
}
