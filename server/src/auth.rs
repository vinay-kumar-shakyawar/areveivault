//! Sessions, request metadata and the authenticated-user extractor.

use std::net::SocketAddr;

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::header::{AUTHORIZATION, COOKIE, USER_AGENT};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::RngCore;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::error::{ApiResult, AppError};
use crate::state::AppState;

pub const COOKIE_NAME: &str = "__Host-av_session";

pub fn new_token() -> String {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    URL_SAFE_NO_PAD.encode(b)
}

pub fn hash_token(t: &str) -> Vec<u8> {
    Sha256::digest(t.as_bytes()).to_vec()
}

pub fn token_from_headers(headers: &HeaderMap) -> Option<String> {
    if let Some(v) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(t) = v.strip_prefix("Bearer ") {
            return Some(t.trim().to_string());
        }
    }
    session_cookie(headers)
}

pub fn session_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|kv| kv.trim().split_once('='))
        .find(|(k, _)| *k == COOKIE_NAME)
        .map(|(_, v)| v.to_string())
}

pub fn set_cookie(token: &str) -> HeaderValue {
    HeaderValue::from_str(&format!("{COOKIE_NAME}={token}; Path=/; Secure; HttpOnly; SameSite=Strict")).unwrap()
}

pub fn clear_cookie() -> HeaderValue {
    HeaderValue::from_static("__Host-av_session=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0")
}

/// Client IP + user agent for audit and rate limiting.
#[derive(Clone, Debug, Default)]
pub struct ReqMeta {
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

impl FromRequestParts<AppState> for ReqMeta {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let forwarded = state
            .cfg
            .trust_proxy
            .then(|| parts.headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()))
            .flatten()
            .and_then(|v| v.split(',').next())
            .map(|s| s.trim().to_string());
        let ip = forwarded.or_else(|| parts.extensions.get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip().to_string()));
        let user_agent = parts
            .headers
            .get(USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.chars().take(256).collect());
        Ok(ReqMeta { ip, user_agent })
    }
}

/// An authenticated session. `status` is the org membership status.
#[derive(Clone, Debug)]
pub struct AuthUser {
    pub user_id: Uuid,
    pub org_id: Uuid,
    pub email: String,
    pub role: String,
    pub status: String,
    pub device_id: Uuid,
    pub token_hash: Vec<u8>,
}

impl AuthUser {
    pub fn is_active(&self) -> bool {
        self.status == "active"
    }
    pub fn is_admin(&self) -> bool {
        self.is_active() && matches!(self.role.as_str(), "owner" | "admin")
    }
    pub fn is_owner(&self) -> bool {
        self.is_active() && self.role == "owner"
    }
    pub fn require_active(&self) -> ApiResult<()> {
        if self.is_active() {
            Ok(())
        } else {
            Err(AppError::forbidden("account awaiting administrator approval"))
        }
    }
    pub fn require_admin(&self) -> ApiResult<()> {
        if self.is_admin() {
            Ok(())
        } else {
            Err(AppError::forbidden("administrator role required"))
        }
    }

    pub fn session_json(&self) -> Value {
        json!({
            "user_id": self.user_id,
            "email": self.email,
            "org_id": self.org_id,
            "role": self.role,
            "status": self.status,
            "device_id": self.device_id,
        })
    }
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Self::Rejection> {
        let token = token_from_headers(&parts.headers).ok_or_else(AppError::unauthorized)?;
        load_session(state, &token).await
    }
}

pub async fn load_session(state: &AppState, token: &str) -> ApiResult<AuthUser> {
    let hash = hash_token(token);
    let now = state.now();
    let row: Option<(Uuid, Uuid, i64, i64, Uuid, String, String)> = sqlx::query_as(
        "SELECT s.user_id, s.device_id, s.created_at, s.last_seen_at, u.org_id, u.email, u.status
         FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = $1",
    )
    .bind(&hash)
    .fetch_optional(&state.db)
    .await?;
    let Some((user_id, device_id, created_at, last_seen, org_id, email, user_status)) = row else {
        return Err(AppError::unauthorized());
    };
    if user_status != "active"
        || now - last_seen > state.cfg.session_idle_secs
        || now - created_at > state.cfg.session_absolute_secs
    {
        sqlx::query("DELETE FROM sessions WHERE token_hash = $1").bind(&hash).execute(&state.db).await?;
        return Err(AppError::unauthorized());
    }
    let mut tx = state.org_tx(org_id).await?;
    let m: Option<(String, String)> = sqlx::query_as("SELECT role, status FROM org_memberships WHERE user_id = $1")
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
    tx.commit().await?;
    let Some((role, status)) = m.filter(|(_, s)| s != "disabled") else {
        return Err(AppError::unauthorized());
    };
    if now - last_seen > 60 {
        sqlx::query("UPDATE sessions SET last_seen_at = $2 WHERE token_hash = $1").bind(&hash).bind(now).execute(&state.db).await?;
        sqlx::query("UPDATE devices SET last_seen_at = $2 WHERE id = $1").bind(device_id).bind(now).execute(&state.db).await?;
    }
    Ok(AuthUser { user_id, org_id, email, role, status, device_id, token_hash: hash })
}

/// Creates a device + session. Returns the raw token (sent once to the client).
pub async fn create_session(state: &AppState, user_id: Uuid, device_name: &str, ip: Option<&str>) -> ApiResult<(String, Uuid)> {
    let now = state.now();
    let device_id = Uuid::new_v4();
    let name: String = device_name.trim().chars().take(100).collect();
    let name = if name.is_empty() { "Unnamed device".to_string() } else { name };
    sqlx::query("INSERT INTO devices (id, user_id, name, ip, created_at, last_seen_at) VALUES ($1,$2,$3,$4,$5,$5)")
        .bind(device_id)
        .bind(user_id)
        .bind(&name)
        .bind(ip)
        .bind(now)
        .execute(&state.db)
        .await?;
    let token = new_token();
    sqlx::query("INSERT INTO sessions (token_hash, user_id, device_id, created_at, last_seen_at) VALUES ($1,$2,$3,$4,$4)")
        .bind(hash_token(&token))
        .bind(user_id)
        .bind(device_id)
        .bind(now)
        .execute(&state.db)
        .await?;
    Ok((token, device_id))
}
