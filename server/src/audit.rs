//! Tamper-evident audit log: per-org hash chain + signed checkpoints (architecture §11).
//! Entries reference ids only; titles/URLs are never known to the server.

use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::{AuthUser, ReqMeta};
use crate::error::ApiResult;
use crate::state::{AppState, Tx};

pub struct Actor {
    pub org_id: Uuid,
    pub user_id: Option<Uuid>,
    pub device_id: Option<Uuid>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

impl Actor {
    pub fn from(user: &AuthUser, meta: &ReqMeta) -> Self {
        Actor {
            org_id: user.org_id,
            user_id: Some(user.user_id),
            device_id: Some(user.device_id),
            ip: meta.ip.clone(),
            user_agent: meta.user_agent.clone(),
        }
    }
}

pub struct Event<'a> {
    pub event_type: &'a str,
    pub target_type: &'a str,
    pub target_id: Option<String>,
    pub vault_id: Option<Uuid>,
    pub client_ts: Option<i64>,
}

impl<'a> Event<'a> {
    pub fn new(event_type: &'a str, target_type: &'a str, target_id: impl ToString) -> Self {
        Event { event_type, target_type, target_id: Some(target_id.to_string()), vault_id: None, client_ts: None }
    }
    pub fn vault(mut self, v: Uuid) -> Self {
        self.vault_id = Some(v);
        self
    }
}

/// Canonical form hashed into the chain. Field order is fixed by the struct.
#[derive(Serialize)]
struct Canonical<'a> {
    org_id: String,
    seq: i64,
    ts: i64,
    actor_user_id: Option<String>,
    device_id: Option<String>,
    ip: Option<&'a str>,
    user_agent: Option<&'a str>,
    event_type: &'a str,
    target_type: &'a str,
    target_id: Option<&'a str>,
    vault_id: Option<String>,
    client_ts: Option<i64>,
}

#[allow(clippy::too_many_arguments)]
fn entry_hash(
    prev: &[u8],
    org_id: Uuid,
    seq: i64,
    ts: i64,
    actor: Option<Uuid>,
    device: Option<Uuid>,
    ip: Option<&str>,
    ua: Option<&str>,
    event_type: &str,
    target_type: &str,
    target_id: Option<&str>,
    vault_id: Option<Uuid>,
    client_ts: Option<i64>,
) -> Vec<u8> {
    let c = Canonical {
        org_id: org_id.to_string(),
        seq,
        ts,
        actor_user_id: actor.map(|u| u.to_string()),
        device_id: device.map(|u| u.to_string()),
        ip,
        user_agent: ua,
        event_type,
        target_type,
        target_id,
        vault_id: vault_id.map(|u| u.to_string()),
        client_ts,
    };
    let mut h = Sha256::new();
    h.update(prev);
    h.update(serde_json::to_vec(&c).expect("serializable"));
    h.finalize().to_vec()
}

/// Append an event inside the caller's transaction (commits atomically with the change).
pub async fn record(tx: &mut Tx, state: &AppState, actor: &Actor, ev: Event<'_>) -> ApiResult<()> {
    let (prev, count): (Vec<u8>, i64) =
        sqlx::query_as("SELECT audit_head, audit_count FROM organizations WHERE id = $1 FOR UPDATE")
            .bind(actor.org_id)
            .fetch_one(&mut **tx)
            .await?;
    let seq = count + 1;
    let ts = state.now();
    let hash = entry_hash(
        &prev,
        actor.org_id,
        seq,
        ts,
        actor.user_id,
        actor.device_id,
        actor.ip.as_deref(),
        actor.user_agent.as_deref(),
        ev.event_type,
        ev.target_type,
        ev.target_id.as_deref(),
        ev.vault_id,
        ev.client_ts,
    );
    sqlx::query(
        "INSERT INTO audit_events (org_id, seq, ts, actor_user_id, device_id, ip, user_agent, event_type,
            target_type, target_id, vault_id, client_ts, prev_hash, entry_hash)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
    )
    .bind(actor.org_id)
    .bind(seq)
    .bind(ts)
    .bind(actor.user_id)
    .bind(actor.device_id)
    .bind(&actor.ip)
    .bind(&actor.user_agent)
    .bind(ev.event_type)
    .bind(ev.target_type)
    .bind(&ev.target_id)
    .bind(ev.vault_id)
    .bind(ev.client_ts)
    .bind(&prev)
    .bind(&hash)
    .execute(&mut **tx)
    .await?;
    sqlx::query("UPDATE organizations SET audit_head = $2, audit_count = $3 WHERE id = $1")
        .bind(actor.org_id)
        .bind(&hash)
        .bind(seq)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

type EventRow = (
    i64,
    i64,
    Option<Uuid>,
    Option<Uuid>,
    Option<String>,
    Option<String>,
    String,
    String,
    Option<String>,
    Option<Uuid>,
    Option<i64>,
    Vec<u8>,
    Vec<u8>,
);

pub struct Verification {
    pub ok: bool,
    pub count: i64,
    pub head: Vec<u8>,
    pub first_bad_seq: Option<i64>,
}

/// Recompute the whole chain for an org and compare with the stored head.
pub async fn verify_chain(tx: &mut Tx, org_id: Uuid) -> ApiResult<Verification> {
    let rows: Vec<EventRow> = sqlx::query_as(
        "SELECT seq, ts, actor_user_id, device_id, ip, user_agent, event_type, target_type, target_id,
                vault_id, client_ts, prev_hash, entry_hash
         FROM audit_events WHERE org_id = $1 ORDER BY seq",
    )
    .bind(org_id)
    .fetch_all(&mut **tx)
    .await?;
    let (stored_head, stored_count): (Vec<u8>, i64) =
        sqlx::query_as("SELECT audit_head, audit_count FROM organizations WHERE id = $1")
            .bind(org_id)
            .fetch_one(&mut **tx)
            .await?;
    let mut prev = vec![0u8; 32];
    let mut first_bad = None;
    for (i, r) in rows.iter().enumerate() {
        let expected_seq = i as i64 + 1;
        let h = entry_hash(&prev, org_id, r.0, r.1, r.2, r.3, r.4.as_deref(), r.5.as_deref(), &r.6, &r.7, r.8.as_deref(), r.9, r.10);
        if r.0 != expected_seq || r.11 != prev || r.12 != h {
            first_bad = Some(r.0);
            break;
        }
        prev = h;
    }
    let ok = first_bad.is_none() && prev == stored_head && rows.len() as i64 == stored_count;
    Ok(Verification { ok, count: rows.len() as i64, head: prev, first_bad_seq: first_bad })
}

fn checkpoint_message(org_id: Uuid, ts: i64, count: i64, head: &[u8]) -> Vec<u8> {
    let mut m = b"arevei-vault/v1/audit-checkpoint".to_vec();
    m.extend_from_slice(org_id.as_bytes());
    m.extend_from_slice(&ts.to_be_bytes());
    m.extend_from_slice(&count.to_be_bytes());
    m.extend_from_slice(head);
    m
}

/// Sign the current head if it changed since the last checkpoint.
pub async fn checkpoint(tx: &mut Tx, state: &AppState, org_id: Uuid) -> ApiResult<()> {
    let (head, count): (Vec<u8>, i64) = sqlx::query_as("SELECT audit_head, audit_count FROM organizations WHERE id = $1")
        .bind(org_id)
        .fetch_one(&mut **tx)
        .await?;
    let last: Option<(i64,)> =
        sqlx::query_as("SELECT count FROM audit_checkpoints WHERE org_id = $1 ORDER BY id DESC LIMIT 1")
            .bind(org_id)
            .fetch_optional(&mut **tx)
            .await?;
    if count == 0 || last.map(|l| l.0) == Some(count) {
        return Ok(());
    }
    let ts = state.now();
    let sig = arevei_core::sign::sign(&state.keys.audit_sk, &checkpoint_message(org_id, ts, count, &head));
    sqlx::query("INSERT INTO audit_checkpoints (org_id, ts, count, head_hash, signature) VALUES ($1,$2,$3,$4,$5)")
        .bind(org_id)
        .bind(ts)
        .bind(count)
        .bind(&head)
        .bind(sig.to_vec())
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub async fn checkpoints_json(tx: &mut Tx, org_id: Uuid) -> ApiResult<Vec<Value>> {
    let rows: Vec<(i64, i64, Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT ts, count, head_hash, signature FROM audit_checkpoints WHERE org_id = $1 ORDER BY id DESC LIMIT 100",
    )
    .bind(org_id)
    .fetch_all(&mut **tx)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(ts, count, head, sig)| {
            json!({ "ts": ts, "count": count, "head_hash": hex::encode(head), "signature": arevei_core::encoding::b64(&sig) })
        })
        .collect())
}
