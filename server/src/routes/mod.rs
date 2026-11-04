pub mod account;
pub mod attachments;
pub mod audit_log;
pub mod auth;
pub mod events;
pub mod items;
pub mod org;
pub mod sync;
pub mod vaults;

use axum::extract::{DefaultBodyLimit, FromRequest, FromRequestParts, Request, State};
use axum::http::header::{CACHE_CONTROL, COOKIE, ORIGIN, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS};
use axum::http::{HeaderValue, Method};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::Router;
use serde_json::{json, Value};
use tower_http::set_header::SetResponseHeaderLayer;
use uuid::Uuid;

use crate::auth::{AuthUser, COOKIE_NAME};
use crate::error::{ApiResult, AppError};
use crate::state::{AppState, Tx};

pub const JSON_LIMIT: usize = 2 * 1024 * 1024;
pub const ATTACHMENT_LIMIT: usize = 11 * 1024 * 1024;

/// JSON body extractor whose rejections use the uniform error format.
#[derive(FromRequest)]
#[from_request(via(axum::Json), rejection(AppError))]
pub struct Body<T>(pub T);

#[derive(FromRequestParts)]
#[from_request(via(axum::extract::Path), rejection(AppError))]
pub struct P<T>(pub T);

#[derive(FromRequestParts)]
#[from_request(via(axum::extract::Query), rejection(AppError))]
pub struct Q<T>(pub T);

pub fn router(state: AppState) -> Router {
    let api = Router::new()
        // auth
        .route("/auth/prelogin", post(auth::prelogin))
        .route("/auth/register/start", post(auth::register_start))
        .route("/auth/register/finish", post(auth::register_finish))
        .route("/auth/mfa/totp/confirm", post(auth::confirm_totp))
        .route("/auth/login/start", post(auth::login_start))
        .route("/auth/login/finish", post(auth::login_finish))
        .route("/auth/mfa/verify", post(auth::mfa_verify))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/session", get(auth::session))
        // account
        .route("/keyset", get(account::keyset))
        .route("/prefs", get(account::get_prefs).put(account::put_prefs))
        .route("/devices", get(account::devices))
        .route("/devices/{id}", delete(account::revoke_device))
        // sync
        .route("/sync", get(sync::sync))
        .route("/events", get(events::events))
        // items
        .route("/items/{id}", put(items::put_item).delete(items::delete_item))
        .route("/items/{id}/restore", post(items::restore_item))
        // clients & vaults
        .route("/clients", post(vaults::create_client))
        .route("/clients/{id}", put(vaults::update_client).delete(vaults::delete_client))
        .route("/vaults", post(vaults::create_vault))
        .route("/vaults/{id}", put(vaults::update_vault).delete(vaults::delete_vault))
        .route("/vaults/{id}/members", get(vaults::list_members))
        .route("/vaults/{id}/members/{user_id}", put(vaults::put_member).delete(vaults::remove_member))
        .route("/vaults/{id}/rotate", post(vaults::rotate))
        // org
        .route("/org/invites", post(org::create_invite).get(org::list_invites))
        .route("/org/invites/{id}", delete(org::delete_invite))
        .route("/org/members/{user_id}/approve", post(org::approve))
        .route("/org/members/{user_id}", axum::routing::patch(org::update_member).delete(org::offboard))
        // attachments
        .route(
            "/attachments/{id}",
            put(attachments::put_attachment)
                .layer(DefaultBodyLimit::max(ATTACHMENT_LIMIT))
                .get(attachments::get_attachment)
                .delete(attachments::delete_attachment),
        )
        // audit
        .route("/audit/events", post(audit_log::report))
        .route("/audit", get(audit_log::list))
        .route("/audit/verify", get(audit_log::verify));

    Router::new()
        .nest("/api/v1", api)
        .route("/healthz", get(|| async { "ok" }))
        .layer(middleware::from_fn_with_state(state.clone(), csrf))
        .layer(DefaultBodyLimit::max(JSON_LIMIT))
        .layer(SetResponseHeaderLayer::overriding(CACHE_CONTROL, HeaderValue::from_static("no-store")))
        .layer(SetResponseHeaderLayer::overriding(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")))
        .layer(SetResponseHeaderLayer::overriding(REFERRER_POLICY, HeaderValue::from_static("no-referrer")))
        .layer(SetResponseHeaderLayer::overriding(X_FRAME_OPTIONS, HeaderValue::from_static("DENY")))
        .with_state(state)
}

/// CSRF defense for state-changing requests:
/// - `X-Arevei-Request: 1` is required (a custom header forces a CORS preflight cross-origin);
/// - `Origin`, when present, must be the web app origin. Browser-extension origins are
///   accepted only when the request does not carry the session cookie (they authenticate
///   with a Bearer token, which a cross-site page cannot attach).
async fn csrf(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS) {
        let marked = req.headers().get("x-arevei-request").and_then(|v| v.to_str().ok()) == Some("1");
        if !marked {
            return AppError::forbidden("missing X-Arevei-Request header").into_response();
        }
        if let Some(origin) = req.headers().get(ORIGIN).and_then(|v| v.to_str().ok()) {
            if origin != state.cfg.public_origin {
                let extension = ["chrome-extension://", "moz-extension://", "safari-web-extension://"]
                    .iter()
                    .any(|p| origin.starts_with(p));
                let has_cookie = req
                    .headers()
                    .get_all(COOKIE)
                    .iter()
                    .filter_map(|v| v.to_str().ok())
                    .any(|v| v.contains(COOKIE_NAME));
                if !(extension && !has_cookie) {
                    return AppError::forbidden("origin not allowed").into_response();
                }
            }
        }
    }
    next.run(req).await
}

// ------------------------------------------------------------------ shared helpers

pub fn parse_uuid(s: &str) -> ApiResult<Uuid> {
    Uuid::parse_str(s).map_err(|_| AppError::bad_request("invalid id"))
}

pub fn normalize_email(e: &str) -> ApiResult<String> {
    let e = e.trim().to_lowercase();
    if e.len() > 254 || e.len() < 3 || !e.contains('@') || e.starts_with('@') || e.ends_with('@') || e.contains(char::is_whitespace) {
        return Err(AppError::bad_request("invalid email address"));
    }
    Ok(e)
}

/// Increment the org revision inside the transaction (row lock serializes writers).
pub async fn bump_revision(tx: &mut Tx, org_id: Uuid) -> ApiResult<i64> {
    let (rev,): (i64,) = sqlx::query_as("UPDATE organizations SET revision = revision + 1 WHERE id = $1 RETURNING revision")
        .bind(org_id)
        .fetch_one(&mut **tx)
        .await?;
    Ok(rev)
}

/// Caller's effective access to a vault.
#[derive(Debug, Clone)]
pub struct VaultAccess {
    pub kind: String,
    /// owner (personal), admin (org admin), manager, member, read_only
    pub role: String,
    pub key_version: i32,
}

impl VaultAccess {
    pub fn can_write(&self) -> bool {
        self.role != "read_only"
    }
    pub fn can_manage(&self) -> bool {
        self.kind == "project" && matches!(self.role.as_str(), "admin" | "manager")
    }
    pub fn require_write(&self) -> ApiResult<()> {
        if self.can_write() {
            Ok(())
        } else {
            Err(AppError::forbidden("read-only access"))
        }
    }
    pub fn require_manage(&self) -> ApiResult<()> {
        if self.can_manage() {
            Ok(())
        } else {
            Err(AppError::forbidden("manager or administrator role required"))
        }
    }
}

/// 404 when the vault does not exist or the caller has no access (no existence oracle).
/// Personal vaults are visible only to their owner — never to admins.
pub async fn vault_access(tx: &mut Tx, user: &AuthUser, vault_id: Uuid) -> ApiResult<VaultAccess> {
    let row: Option<(String, Option<Uuid>, i32)> =
        sqlx::query_as("SELECT kind, owner_user_id, key_version FROM vaults WHERE id = $1")
            .bind(vault_id)
            .fetch_optional(&mut **tx)
            .await?;
    let (kind, owner, key_version) = row.ok_or_else(AppError::not_found)?;
    if kind == "personal" {
        return if owner == Some(user.user_id) {
            Ok(VaultAccess { kind, role: "owner".into(), key_version })
        } else {
            Err(AppError::not_found())
        };
    }
    if !user.is_active() {
        return Err(AppError::not_found());
    }
    if user.is_admin() {
        return Ok(VaultAccess { kind, role: "admin".into(), key_version });
    }
    let perm: Option<(String,)> = sqlx::query_as("SELECT role FROM vault_permissions WHERE vault_id = $1 AND user_id = $2")
        .bind(vault_id)
        .bind(user.user_id)
        .fetch_optional(&mut **tx)
        .await?;
    perm.map(|(role,)| VaultAccess { kind, role, key_version }).ok_or_else(AppError::not_found)
}

pub type ItemDbRow = (Uuid, Uuid, i64, i32, String, String, i64, i64, i64, Option<Uuid>, Option<Uuid>, Option<i64>);

pub const ITEM_COLUMNS: &str =
    "id, vault_id, version, key_version, wrapped_key, payload, revision, created_at, updated_at, created_by, updated_by, deleted_at";

pub fn item_json(r: &ItemDbRow) -> Value {
    json!({
        "id": r.0, "vault_id": r.1, "version": r.2, "key_version": r.3,
        "wrapped_key": r.4, "payload": r.5, "revision": r.6,
        "created_at": r.7, "updated_at": r.8, "created_by": r.9, "updated_by": r.10, "deleted_at": r.11,
    })
}

/// Validates a core `KeyGrant` and stores it (replacing an existing grant for the same slot).
pub async fn store_grant(
    tx: &mut Tx,
    org_id: Uuid,
    g: &arevei_core::share::KeyGrant,
    now: i64,
) -> ApiResult<()> {
    let recipient = parse_uuid(&g.recipient_id)?;
    let grantor = parse_uuid(&g.grantor_id)?;
    if g.wrapped.len() > 4096 || g.signature.len() > 256 || g.keyring_id.len() > 128 {
        return Err(AppError::bad_request("grant too large"));
    }
    // Recipient must belong to this org (RLS limits the lookup to the org).
    let member: Option<(String,)> = sqlx::query_as("SELECT status FROM org_memberships WHERE user_id = $1")
        .bind(recipient)
        .fetch_optional(&mut **tx)
        .await?;
    if member.is_none() {
        return Err(AppError::bad_request("grant recipient is not a member of this organization"));
    }
    sqlx::query(
        "INSERT INTO key_grants (org_id, keyring_id, key_version, recipient_id, grantor_id, wrapped, signature, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
         ON CONFLICT (keyring_id, key_version, recipient_id)
         DO UPDATE SET grantor_id = EXCLUDED.grantor_id, wrapped = EXCLUDED.wrapped, signature = EXCLUDED.signature, created_at = EXCLUDED.created_at",
    )
    .bind(org_id)
    .bind(&g.keyring_id)
    .bind(g.key_version as i32)
    .bind(recipient)
    .bind(grantor)
    .bind(&g.wrapped)
    .bind(&g.signature)
    .bind(now)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub fn org_keyring_ok(keyring: &str, org_id: Uuid) -> bool {
    keyring == format!("org-admin:{org_id}") || keyring == format!("org-dir:{org_id}")
}
