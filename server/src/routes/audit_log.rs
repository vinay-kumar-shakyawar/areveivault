use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use super::{Body, Q};
use crate::audit::{self, Actor, Event};
use crate::auth::{AuthUser, ReqMeta};
use crate::error::{ApiResult, AppError};
use crate::state::AppState;

const CLIENT_EVENTS: &[&str] = &["item_view", "item_reveal", "item_copy", "autofill", "export", "totp_copy"];

#[derive(Deserialize)]
pub struct ClientEvent {
    event_type: String,
    target_type: String,
    target_id: String,
    #[serde(default)]
    vault_id: Option<Uuid>,
    #[serde(default)]
    client_ts: Option<i64>,
}

#[derive(Deserialize)]
pub struct ReportReq {
    events: Vec<ClientEvent>,
}

/// Client-reported events (view/reveal/copy/autofill/export). Best effort by nature:
/// a modified client can skip them (architecture §11).
pub async fn report(State(st): State<AppState>, user: AuthUser, meta: ReqMeta, Body(r): Body<ReportReq>) -> ApiResult<StatusCode> {
    if r.events.len() > 100 {
        return Err(AppError::bad_request("at most 100 events per request"));
    }
    for e in &r.events {
        if !CLIENT_EVENTS.contains(&e.event_type.as_str())
            || !matches!(e.target_type.as_str(), "item" | "vault" | "org")
            || e.target_id.len() > 64
        {
            return Err(AppError::bad_request("invalid audit event"));
        }
    }
    let mut tx = st.org_tx(user.org_id).await?;
    let actor = Actor::from(&user, &meta);
    for e in &r.events {
        let mut ev = Event::new(&e.event_type, &e.target_type, &e.target_id);
        ev.vault_id = e.vault_id;
        ev.client_ts = e.client_ts;
        audit::record(&mut tx, &st, &actor, ev).await?;
    }
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    before: Option<i64>,
    #[serde(default)]
    limit: Option<i64>,
}

type AuditRow = (i64, i64, Option<Uuid>, Option<Uuid>, Option<String>, Option<String>, String, String, Option<String>, Option<Uuid>, Vec<u8>);

pub async fn list(State(st): State<AppState>, user: AuthUser, Q(q): Q<ListQuery>) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let mut tx = st.org_tx(user.org_id).await?;
    let rows: Vec<AuditRow> = sqlx::query_as(
        "SELECT id, ts, actor_user_id, device_id, ip, user_agent, event_type, target_type, target_id, vault_id, entry_hash
         FROM audit_events WHERE ($1::bigint IS NULL OR id < $1) ORDER BY id DESC LIMIT $2",
    )
    .bind(q.before)
    .bind(limit)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    let ids: Vec<Uuid> = rows.iter().filter_map(|r| r.2).collect();
    let emails: Vec<(Uuid, String)> = sqlx::query_as("SELECT id, email FROM users WHERE id = ANY($1)").bind(&ids).fetch_all(&st.db).await?;
    Ok(Json(json!(rows
        .into_iter()
        .map(|r| json!({
            "id": r.0, "ts": r.1, "actor_user_id": r.2,
            "actor_email": r.2.and_then(|a| emails.iter().find(|(id, _)| *id == a).map(|(_, e)| e.clone())),
            "device_id": r.3, "ip": r.4, "user_agent": r.5, "event_type": r.6, "target_type": r.7,
            "target_id": r.8, "vault_id": r.9, "entry_hash": hex::encode(r.10),
        }))
        .collect::<Vec<_>>())))
}

pub async fn verify(State(st): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    let mut tx = st.org_tx(user.org_id).await?;
    let v = audit::verify_chain(&mut tx, user.org_id).await?;
    if v.ok {
        audit::checkpoint(&mut tx, &st, user.org_id).await?;
    }
    let checkpoints = audit::checkpoints_json(&mut tx, user.org_id).await?;
    tx.commit().await?;
    Ok(Json(json!({
        "ok": v.ok,
        "count": v.count,
        "head_hash": hex::encode(&v.head),
        "first_bad_seq": v.first_bad_seq,
        "checkpoints": checkpoints,
        "server_audit_public_key": arevei_core::encoding::b64(&st.keys.audit_pk),
    })))
}
