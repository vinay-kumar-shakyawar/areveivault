//! GET /sync — full lists of vaults/clients/grants/members + changed items (docs/api.md).

use axum::extract::State;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use super::{item_json, ItemDbRow, ITEM_COLUMNS, Q};
use crate::auth::AuthUser;
use crate::error::ApiResult;
use crate::state::AppState;

#[derive(Deserialize)]
pub struct SyncQuery {
    #[serde(default)]
    since: i64,
}

type VaultDbRow = (Uuid, String, Option<Uuid>, Option<String>, i32, Option<String>, i64, Option<String>, Option<bool>);

pub async fn sync(State(st): State<AppState>, user: AuthUser, Q(q): Q<SyncQuery>) -> ApiResult<Json<Value>> {
    let mut tx = st.org_tx(user.org_id).await?;
    let active = user.is_active();
    let admin = user.is_admin();

    let (org_id, org_sign_pk, org_secrets, revision): (Uuid, String, String, i64) =
        sqlx::query_as("SELECT id, org_sign_pk, org_secrets, revision FROM organizations WHERE id = $1")
            .bind(user.org_id)
            .fetch_one(&mut *tx)
            .await?;

    let members: Vec<(Uuid, String, String, String, Option<Value>, Option<Value>)> = sqlx::query_as(
        "SELECT m.user_id, u.email, m.role, m.status, k.keyset->'public_keys', m.cert
         FROM org_memberships m JOIN users u ON u.id = m.user_id JOIN keysets k ON k.user_id = m.user_id
         WHERE m.status <> 'disabled' AND ($1 OR m.user_id = $2)
         ORDER BY u.email",
    )
    .bind(active)
    .bind(user.user_id)
    .fetch_all(&mut *tx)
    .await?;

    let vaults: Vec<VaultDbRow> = sqlx::query_as(
        "SELECT v.id, v.kind, v.client_id, v.name_enc, v.key_version, v.admin_wrapped_key, v.revision, p.role, p.copy_only
         FROM vaults v LEFT JOIN vault_permissions p ON p.vault_id = v.id AND p.user_id = $1
         WHERE (v.kind = 'personal' AND v.owner_user_id = $1)
            OR (v.kind = 'project' AND $2 AND ($3 OR p.user_id IS NOT NULL))",
    )
    .bind(user.user_id)
    .bind(active)
    .bind(admin)
    .fetch_all(&mut *tx)
    .await?;
    let vault_ids: Vec<Uuid> = vaults.iter().map(|v| v.0).collect();

    let clients: Vec<(Uuid, String, i64)> = if active {
        sqlx::query_as("SELECT id, name_enc, revision FROM clients ORDER BY created_at").fetch_all(&mut *tx).await?
    } else {
        vec![]
    };

    let grants: Vec<(String, i32, Uuid, Uuid, String, String)> = sqlx::query_as(
        "SELECT keyring_id, key_version, recipient_id, grantor_id, wrapped, signature FROM key_grants WHERE recipient_id = $1 ORDER BY id",
    )
    .bind(user.user_id)
    .fetch_all(&mut *tx)
    .await?;

    let items: Vec<ItemDbRow> = sqlx::query_as(&format!(
        "SELECT {ITEM_COLUMNS} FROM items WHERE vault_id = ANY($1) AND revision > $2 ORDER BY revision"
    ))
    .bind(&vault_ids)
    .bind(q.since)
    .fetch_all(&mut *tx)
    .await?;

    let purged: Vec<(Uuid,)> =
        sqlx::query_as("SELECT item_id FROM item_tombstones WHERE vault_id = ANY($1) AND revision > $2")
            .bind(&vault_ids)
            .bind(q.since)
            .fetch_all(&mut *tx)
            .await?;
    tx.commit().await?;

    Ok(Json(json!({
        "revision": revision,
        "org": { "id": org_id, "org_sign_pk": org_sign_pk, "org_secrets": if admin { Some(org_secrets) } else { None } },
        "me": { "user_id": user.user_id, "role": user.role, "status": user.status },
        "members": members.into_iter().map(|(uid, email, role, status, pk, cert)| json!({
            "user_id": uid, "email": email, "role": role, "status": status,
            "public_keys": pk.unwrap_or(Value::Null), "cert": cert,
        })).collect::<Vec<_>>(),
        "vaults": vaults.into_iter().map(|(id, kind, client_id, name_enc, kv, awk, rev, role, copy_only)| {
            let role = if kind == "personal" { "owner".to_string() } else { role.unwrap_or_else(|| "manager".into()) };
            json!({
                "id": id, "kind": kind, "client_id": client_id, "name_enc": name_enc, "key_version": kv,
                "admin_wrapped_key": if admin && kind == "project" { awk } else { None },
                "role": role, "copy_only": copy_only.unwrap_or(false), "revision": rev,
            })
        }).collect::<Vec<_>>(),
        "clients": clients.into_iter().map(|(id, n, rev)| json!({ "id": id, "name_enc": n, "revision": rev })).collect::<Vec<_>>(),
        "grants": grants.into_iter().map(|(k, v, r, g, w, s)| json!({
            "keyring_id": k, "key_version": v, "recipient_id": r, "grantor_id": g, "wrapped": w, "signature": s,
        })).collect::<Vec<_>>(),
        "items": items.iter().map(item_json).collect::<Vec<_>>(),
        "purged_item_ids": purged.into_iter().map(|p| p.0).collect::<Vec<_>>(),
    })))
}
