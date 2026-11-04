//! Invitations, member approval (certificate issued client-side by an admin),
//! role changes and offboarding.

use arevei_core::share::KeyGrant;
use arevei_core::sign::MembershipCert;
use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use super::{bump_revision, normalize_email, org_keyring_ok, store_grant, Body, P};
use crate::audit::{self, Actor, Event};
use crate::auth::{hash_token, new_token, AuthUser, ReqMeta};
use crate::error::{ApiResult, AppError};
use crate::notify::Notice;
use crate::state::AppState;

const INVITE_TTL: i64 = 7 * 24 * 3600;

#[derive(Deserialize)]
pub struct InviteReq {
    email: String,
    role: String,
}

pub async fn create_invite(State(st): State<AppState>, user: AuthUser, meta: ReqMeta, Body(r): Body<InviteReq>) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    let email = normalize_email(&r.email)?;
    match r.role.as_str() {
        "member" => {}
        "admin" if user.is_owner() => {}
        "admin" => return Err(AppError::forbidden("only owners can invite administrators")),
        _ => return Err(AppError::bad_request("role must be member or admin")),
    }
    let exists: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM users WHERE email = $1").bind(&email).fetch_optional(&st.db).await?;
    if exists.is_some() {
        return Err(AppError::conflict("a user with this email already exists"));
    }
    let token = new_token();
    let id = Uuid::new_v4();
    let now = st.now();
    let mut tx = st.org_tx(user.org_id).await?;
    sqlx::query(
        "INSERT INTO invites (id, org_id, token_hash, email, role, created_by, created_at, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(id)
    .bind(user.org_id)
    .bind(hash_token(&token))
    .bind(&email)
    .bind(&r.role)
    .bind(user.user_id)
    .bind(now)
    .bind(now + INVITE_TTL)
    .execute(&mut *tx)
    .await?;
    audit::record(&mut tx, &st, &Actor::from(&user, &meta), Event::new("invite_create", "invite", id)).await?;
    tx.commit().await?;
    st.notifier.notify(&email, Notice::Invited, &format!("invited to Arevei Vault by {}", user.email));
    Ok(Json(json!({ "id": id, "invite_token": token, "expires_at": now + INVITE_TTL })))
}

pub async fn list_invites(State(st): State<AppState>, user: AuthUser) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    let mut tx = st.org_tx(user.org_id).await?;
    let rows: Vec<(Uuid, String, String, i64, i64, Option<i64>)> =
        sqlx::query_as("SELECT id, email, role, created_at, expires_at, used_at FROM invites ORDER BY created_at DESC")
            .fetch_all(&mut *tx)
            .await?;
    tx.commit().await?;
    Ok(Json(json!(rows
        .into_iter()
        .map(|(id, email, role, c, e, u)| json!({ "id": id, "email": email, "role": role, "created_at": c, "expires_at": e, "used_at": u }))
        .collect::<Vec<_>>())))
}

pub async fn delete_invite(State(st): State<AppState>, user: AuthUser, P(id): P<Uuid>) -> ApiResult<StatusCode> {
    user.require_admin()?;
    let mut tx = st.org_tx(user.org_id).await?;
    let n = sqlx::query("DELETE FROM invites WHERE id = $1 AND used_at IS NULL").bind(id).execute(&mut *tx).await?;
    tx.commit().await?;
    if n.rows_affected() == 0 {
        return Err(AppError::not_found());
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct ApproveReq {
    cert: MembershipCert,
    #[serde(default)]
    grants: Vec<KeyGrant>,
}

fn validate_member_grants(grants: &[KeyGrant], org_id: Uuid, member: Uuid, grantor: Uuid) -> ApiResult<()> {
    for g in grants {
        if g.recipient_id != member.to_string() || g.grantor_id != grantor.to_string() || !org_keyring_ok(&g.keyring_id, org_id) {
            return Err(AppError::bad_request("grants must give organization keys to this member"));
        }
    }
    Ok(())
}

pub async fn approve(
    State(st): State<AppState>,
    user: AuthUser,
    meta: ReqMeta,
    P(member): P<Uuid>,
    Body(r): Body<ApproveReq>,
) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    let now = st.now();
    let mut tx = st.org_tx(user.org_id).await?;
    let row: Option<(String, String)> = sqlx::query_as("SELECT role, status FROM org_memberships WHERE user_id = $1 FOR UPDATE")
        .bind(member)
        .fetch_optional(&mut *tx)
        .await?;
    let (role, status) = row.ok_or_else(AppError::not_found)?;
    if status != "pending_approval" {
        return Err(AppError::conflict("member is not awaiting approval"));
    }
    if role == "admin" && !user.is_owner() {
        return Err(AppError::forbidden("only owners can approve administrators"));
    }
    // The server can and does check the certificate it is about to store.
    let (org_pk, email, ks): (String, String, Value) = sqlx::query_as(
        "SELECT o.org_sign_pk, u.email, k.keyset FROM organizations o, users u JOIN keysets k ON k.user_id = u.id WHERE o.id = $1 AND u.id = $2",
    )
    .bind(user.org_id)
    .bind(member)
    .fetch_one(&mut *tx)
    .await?;
    let org_pk: [u8; 32] = arevei_core::encoding::unb64_array(&org_pk)?;
    let c = &r.cert;
    c.verify(&org_pk).map_err(|_| AppError::bad_request("certificate signature is invalid"))?;
    if c.org_id != user.org_id.to_string()
        || c.user_id != member.to_string()
        || c.email != email
        || c.issuer_id != user.user_id.to_string()
        || Some(c.x25519.as_str()) != ks["public_keys"]["x25519"].as_str()
        || Some(c.ed25519.as_str()) != ks["public_keys"]["ed25519"].as_str()
    {
        return Err(AppError::bad_request("certificate does not match this member"));
    }
    validate_member_grants(&r.grants, user.org_id, member, user.user_id)?;
    sqlx::query("UPDATE org_memberships SET status = 'active', cert = $2, approved_at = $3 WHERE user_id = $1")
        .bind(member)
        .bind(serde_json::to_value(&r.cert).map_err(|_| AppError::internal())?)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    for g in &r.grants {
        store_grant(&mut tx, user.org_id, g, now).await?;
    }
    let rev = bump_revision(&mut tx, user.org_id).await?;
    audit::record(&mut tx, &st, &Actor::from(&user, &meta), Event::new("member_approve", "user", member)).await?;
    tx.commit().await?;
    st.publish(user.org_id, rev);
    st.notifier.notify(&email, Notice::AccountApproved, "your Arevei Vault account was approved");
    Ok(Json(json!({ "user_id": member, "status": "active", "role": role })))
}

#[derive(Deserialize)]
pub struct UpdateMemberReq {
    role: String,
    #[serde(default)]
    grants: Vec<KeyGrant>,
}

pub async fn update_member(
    State(st): State<AppState>,
    user: AuthUser,
    meta: ReqMeta,
    P(member): P<Uuid>,
    Body(r): Body<UpdateMemberReq>,
) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    if !matches!(r.role.as_str(), "owner" | "admin" | "member") {
        return Err(AppError::bad_request("invalid role"));
    }
    let now = st.now();
    let mut tx = st.org_tx(user.org_id).await?;
    let (cur_role, status): (String, String) = sqlx::query_as("SELECT role, status FROM org_memberships WHERE user_id = $1 FOR UPDATE")
        .bind(member)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(AppError::not_found)?;
    if status == "disabled" {
        return Err(AppError::conflict("member is offboarded"));
    }
    let touches_privileged = cur_role != "member" || r.role != "member";
    if touches_privileged && !user.is_owner() {
        return Err(AppError::forbidden("only owners can change owner or administrator roles"));
    }
    if cur_role == "owner" && r.role != "owner" {
        let (owners,): (i64,) = sqlx::query_as("SELECT count(*) FROM org_memberships WHERE role = 'owner' AND status = 'active'")
            .fetch_one(&mut *tx)
            .await?;
        if owners <= 1 {
            return Err(AppError::conflict("the organization must keep at least one owner"));
        }
    }
    validate_member_grants(&r.grants, user.org_id, member, user.user_id)?;
    sqlx::query("UPDATE org_memberships SET role = $2 WHERE user_id = $1").bind(member).bind(&r.role).execute(&mut *tx).await?;
    if r.role == "member" && cur_role != "member" {
        // Demoted: drop the org admin key grant (rotation of the admin key is a client follow-up).
        sqlx::query("DELETE FROM key_grants WHERE keyring_id = $1 AND recipient_id = $2")
            .bind(format!("org-admin:{}", user.org_id))
            .bind(member)
            .execute(&mut *tx)
            .await?;
    }
    for g in &r.grants {
        store_grant(&mut tx, user.org_id, g, now).await?;
    }
    let rev = bump_revision(&mut tx, user.org_id).await?;
    audit::record(&mut tx, &st, &Actor::from(&user, &meta), Event::new("member_role_change", "user", member)).await?;
    tx.commit().await?;
    st.publish(user.org_id, rev);
    Ok(Json(json!({ "user_id": member, "role": r.role })))
}

/// One-action offboarding: disable, kill sessions, drop every permission and grant.
/// Returns the vaults the user could decrypt so the admin's client can rotate them.
pub async fn offboard(State(st): State<AppState>, user: AuthUser, meta: ReqMeta, P(member): P<Uuid>) -> ApiResult<Json<Value>> {
    user.require_admin()?;
    if member == user.user_id {
        return Err(AppError::bad_request("you cannot offboard yourself"));
    }
    let mut tx = st.org_tx(user.org_id).await?;
    let (role,): (String,) = sqlx::query_as("SELECT role FROM org_memberships WHERE user_id = $1 FOR UPDATE")
        .bind(member)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(AppError::not_found)?;
    if role != "member" && !user.is_owner() {
        return Err(AppError::forbidden("only owners can offboard administrators"));
    }
    let affected: Vec<(Uuid,)> = if role == "member" {
        sqlx::query_as("SELECT vault_id FROM vault_permissions WHERE user_id = $1").bind(member).fetch_all(&mut *tx).await?
    } else {
        // Admins held the org admin key, i.e. every project key.
        sqlx::query_as("SELECT id FROM vaults WHERE kind = 'project'").fetch_all(&mut *tx).await?
    };
    sqlx::query("UPDATE org_memberships SET status = 'disabled' WHERE user_id = $1").bind(member).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM vault_permissions WHERE user_id = $1").bind(member).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM key_grants WHERE recipient_id = $1").bind(member).execute(&mut *tx).await?;
    let rev = bump_revision(&mut tx, user.org_id).await?;
    audit::record(&mut tx, &st, &Actor::from(&user, &meta), Event::new("member_offboard", "user", member)).await?;
    tx.commit().await?;
    sqlx::query("UPDATE users SET status = 'disabled' WHERE id = $1").bind(member).execute(&st.db).await?;
    sqlx::query("DELETE FROM sessions WHERE user_id = $1").bind(member).execute(&st.db).await?;
    st.publish(user.org_id, rev);
    let email: Option<(String,)> = sqlx::query_as("SELECT email FROM users WHERE id = $1").bind(member).fetch_optional(&st.db).await?;
    if let Some((e,)) = email {
        st.notifier.notify(&e, Notice::AccountOffboarded, "your Arevei Vault access was removed");
    }
    Ok(Json(json!({ "affected_vault_ids": affected.into_iter().map(|a| a.0).collect::<Vec<_>>() })))
}
