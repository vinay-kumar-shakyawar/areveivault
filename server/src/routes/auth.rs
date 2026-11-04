//! Registration (OPAQUE + mandatory TOTP) and login (OPAQUE → TOTP → session).
//!
//! Nothing is persisted at `register/finish`: the account (and, for the founding
//! user, the organization) is created only after the TOTP code is confirmed, so an
//! abandoned signup leaves no half-created account behind.

use arevei_core::encoding::{b64, unb64, Aad};
use arevei_core::envelope;
use arevei_core::kdf::KdfParams;
use arevei_core::keyset::EncryptedKeyset;
use arevei_core::opaque::opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload, ServerLogin,
    ServerLoginStartParameters, ServerRegistration,
};
use arevei_core::opaque::Suite;
use arevei_core::share::KeyGrant;
use arevei_core::sign::MembershipCert;
use arevei_core::totp::{self, Algorithm, TotpConfig};
use axum::extract::State;
use axum::http::header::SET_COOKIE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::Sha256;
use uuid::Uuid;

use super::{bump_revision, normalize_email, org_keyring_ok, parse_uuid, store_grant, Body};
use crate::audit::{self, Actor, Event};
use crate::auth::{self as session, AuthUser, ReqMeta};
use crate::error::{ApiResult, AppError};
use crate::notify::Notice;
use crate::state::AppState;
use crate::{ratelimit, tokens};

const PROTOCOL_TTL: i64 = 300;
/// Registration waits for the user to scan a QR code, so it gets a bit longer.
const PENDING_TTL: i64 = 600;

fn mfa_aad(user_id: &str) -> Vec<u8> {
    Aad::new("account-totp").str(user_id).bytes().to_vec()
}

fn issuer_config(secret: &str, email: &str) -> TotpConfig {
    TotpConfig {
        issuer: "Arevei Vault".into(),
        account: email.into(),
        secret: secret.into(),
        algorithm: Algorithm::Sha1,
        digits: 6,
        period: 30,
    }
}

// ------------------------------------------------------------------ prelogin

#[derive(Deserialize)]
pub struct PreloginReq {
    email: String,
}

pub async fn prelogin(State(st): State<AppState>, meta: ReqMeta, Body(r): Body<PreloginReq>) -> ApiResult<Json<Value>> {
    ratelimit::ip(&st, &meta, "prelogin").await?;
    let email = normalize_email(&r.email)?;
    let row: Option<(Value,)> = sqlx::query_as(
        "SELECT k.keyset FROM keysets k JOIN users u ON u.id = k.user_id WHERE u.email = $1 AND u.status = 'active'",
    )
    .bind(&email)
    .fetch_optional(&st.db)
    .await?;
    if let Some((ks,)) = row {
        return Ok(Json(json!({ "salt": ks["salt"], "kdf": ks["kdf"] })));
    }
    // Unknown email: deterministic fake values, indistinguishable from a real account.
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&*st.keys.fake_salt).unwrap();
    mac.update(email.as_bytes());
    let salt = mac.finalize().into_bytes();
    Ok(Json(json!({ "salt": b64(&salt[..16]), "kdf": KdfParams::DEFAULT })))
}

// ------------------------------------------------------------------ registration

#[derive(Deserialize)]
pub struct RegisterStartReq {
    email: String,
    #[serde(default)]
    invite_token: Option<String>,
    registration_request: String,
}

pub async fn register_start(
    State(st): State<AppState>,
    meta: ReqMeta,
    Body(r): Body<RegisterStartReq>,
) -> ApiResult<Json<Value>> {
    ratelimit::ip(&st, &meta, "register").await?;
    let email = normalize_email(&r.email)?;
    let now = st.now();

    let mut tx = st.system_tx().await?;
    let mode = if let Some(tok) = r.invite_token.as_deref().filter(|t| !t.is_empty()) {
        let inv: Option<(Uuid, Uuid, String, String)> = sqlx::query_as(
            "SELECT id, org_id, email, role FROM invites WHERE token_hash = $1 AND used_at IS NULL AND expires_at > $2",
        )
        .bind(session::hash_token(tok))
        .bind(now)
        .fetch_optional(&mut *tx)
        .await?;
        match inv {
            Some((id, org_id, inv_email, role)) if inv_email == email => {
                json!({ "mode": "invite", "invite_id": id, "org_id": org_id, "role": role })
            }
            _ => return Err(AppError::forbidden("invalid or expired invitation")),
        }
    } else {
        let (orgs,): (i64,) = sqlx::query_as("SELECT count(*) FROM organizations").fetch_one(&mut *tx).await?;
        if orgs == 0 {
            json!({ "mode": "bootstrap" })
        } else if st.cfg.allow_signup {
            json!({ "mode": "self" })
        } else {
            return Err(AppError::forbidden("registration requires an invitation"));
        }
    };
    tx.commit().await?;

    let exists: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM users WHERE email = $1").bind(&email).fetch_optional(&st.db).await?;
    if exists.is_some() {
        return Err(AppError::bad_request("this email cannot be registered"));
    }

    let req = RegistrationRequest::<Suite>::deserialize(&unb64(&r.registration_request)?)
        .map_err(|_| AppError::bad_request("invalid registration request"))?;
    let resp = ServerRegistration::<Suite>::start(&st.opaque, req, email.as_bytes())
        .map_err(|_| AppError::bad_request("invalid registration request"))?;

    let mut data = mode;
    data["email"] = json!(email);
    let signup_token = tokens::create(&st, "signup", &data, PROTOCOL_TTL).await?;
    Ok(Json(json!({ "registration_response": b64(&resp.message.serialize()), "signup_token": signup_token })))
}

#[derive(Deserialize)]
pub struct OrgBootstrap {
    org_id: Uuid,
    org_sign_pk: String,
    org_secrets: String,
    grants: Vec<KeyGrant>,
    cert: MembershipCert,
}

#[derive(Deserialize)]
pub struct RegisterFinishReq {
    signup_token: String,
    user_id: Uuid,
    registration_upload: String,
    keyset: EncryptedKeyset,
    #[serde(default)]
    org_bootstrap: Option<OrgBootstrap>,
}

pub async fn register_finish(State(st): State<AppState>, Body(r): Body<RegisterFinishReq>) -> ApiResult<Json<Value>> {
    let data = tokens::take(&st, "signup", &r.signup_token).await?.ok_or_else(|| AppError::bad_request("invalid or expired signup token"))?;
    let email = data["email"].as_str().unwrap_or_default().to_string();
    let mode = data["mode"].as_str().unwrap_or_default().to_string();
    let user_id = r.user_id.to_string();

    // Keyset sanity: belongs to this user, KDF parameters at or above the floor.
    if r.keyset.user_id != user_id {
        return Err(AppError::bad_request("keyset does not belong to this user"));
    }
    r.keyset.kdf.validate()?;
    r.keyset.salt_bytes()?;

    let upload = RegistrationUpload::<Suite>::deserialize(&unb64(&r.registration_upload)?)
        .map_err(|_| AppError::bad_request("invalid registration upload"))?;
    let record = ServerRegistration::<Suite>::finish(upload).serialize().to_vec();

    let bootstrap = match (mode.as_str(), &r.org_bootstrap) {
        ("bootstrap" | "self", Some(b)) => {
            let pk: [u8; 32] = arevei_core::encoding::unb64_array(&b.org_sign_pk)?;
            let c = &b.cert;
            c.verify(&pk).map_err(|_| AppError::bad_request("invalid membership certificate"))?;
            if c.user_id != user_id
                || c.org_id != b.org_id.to_string()
                || c.email != email
                || c.x25519 != r.keyset.public_keys.x25519
                || c.ed25519 != r.keyset.public_keys.ed25519
            {
                return Err(AppError::bad_request("membership certificate does not match account"));
            }
            for g in &b.grants {
                if g.recipient_id != user_id || g.grantor_id != user_id || !org_keyring_ok(&g.keyring_id, b.org_id) {
                    return Err(AppError::bad_request("invalid bootstrap grant"));
                }
            }
            if b.org_secrets.len() > 4096 {
                return Err(AppError::bad_request("org secrets too large"));
            }
            Some(json!({
                "org_id": b.org_id, "org_sign_pk": b.org_sign_pk, "org_secrets": b.org_secrets,
                "grants": b.grants, "cert": b.cert,
            }))
        }
        ("bootstrap" | "self", None) => return Err(AppError::bad_request("org_bootstrap is required to create an organization")),
        ("invite", None) => None,
        ("invite", Some(_)) => return Err(AppError::bad_request("invited users cannot create an organization")),
        _ => return Err(AppError::bad_request("invalid signup token")),
    };

    let secret = totp::generate_secret();
    let secret_enc = envelope::seal(&st.keys.mfa, secret.as_bytes(), &mfa_aad(&user_id));
    let pending = json!({
        "mode": mode,
        "email": email,
        "user_id": user_id,
        "invite_id": data.get("invite_id"),
        "org_id": data.get("org_id"),
        "role": data.get("role"),
        "record": b64(&record),
        "keyset": r.keyset,
        "org_bootstrap": bootstrap,
        "totp_enc": b64(&secret_enc),
    });
    let pending_token = tokens::create(&st, "pending", &pending, PENDING_TTL).await?;
    Ok(Json(json!({
        "pending_token": pending_token,
        "totp_secret": secret,
        "otpauth_uri": issuer_config(&secret, &email).to_uri(),
    })))
}

#[derive(Deserialize)]
pub struct ConfirmReq {
    pending_token: String,
    code: String,
    #[serde(default)]
    device_name: String,
}

pub async fn confirm_totp(State(st): State<AppState>, meta: ReqMeta, Body(r): Body<ConfirmReq>) -> ApiResult<Response> {
    let p = tokens::attempt(&st, "pending", &r.pending_token).await?.ok_or_else(AppError::invalid_credentials)?;
    let user_id_s = p["user_id"].as_str().unwrap_or_default().to_string();
    let user_id = parse_uuid(&user_id_s)?;
    let email = p["email"].as_str().unwrap_or_default().to_string();
    let secret_enc = unb64(p["totp_enc"].as_str().unwrap_or_default())?;
    let secret = envelope::open(&st.keys.mfa, &secret_enc, &mfa_aad(&user_id_s)).map_err(|_| AppError::internal())?;
    let secret = String::from_utf8(secret.to_vec()).map_err(|_| AppError::internal())?;
    let now = st.now();
    let Some(step) = issuer_config(&secret, &email).verify(&r.code, now as u64, 1) else {
        return Err(AppError::invalid_credentials());
    };
    tokens::delete(&st, &r.pending_token).await?;

    let mode = p["mode"].as_str().unwrap_or_default();
    let mut tx = st.system_tx().await?;
    let (org_id, role, status, cert) = if let Some(b) = p.get("org_bootstrap").filter(|b| !b.is_null()) {
        sqlx::query("LOCK TABLE organizations IN EXCLUSIVE MODE").execute(&mut *tx).await?;
        if mode == "bootstrap" {
            let (orgs,): (i64,) = sqlx::query_as("SELECT count(*) FROM organizations").fetch_one(&mut *tx).await?;
            if orgs > 0 {
                return Err(AppError::conflict("an organization already exists; ask an administrator for an invitation"));
            }
        }
        let org_id = parse_uuid(b["org_id"].as_str().unwrap_or_default())?;
        sqlx::query("INSERT INTO organizations (id, org_sign_pk, org_secrets, created_at) VALUES ($1,$2,$3,$4)")
            .bind(org_id)
            .bind(b["org_sign_pk"].as_str())
            .bind(b["org_secrets"].as_str())
            .bind(now)
            .execute(&mut *tx)
            .await?;
        (org_id, "owner".to_string(), "active", Some(b["cert"].clone()))
    } else {
        let invite_id = parse_uuid(p["invite_id"].as_str().unwrap_or_default())?;
        let used = sqlx::query("UPDATE invites SET used_at = $2 WHERE id = $1 AND used_at IS NULL AND expires_at > $2")
            .bind(invite_id)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        if used.rows_affected() != 1 {
            return Err(AppError::forbidden("invitation is no longer valid"));
        }
        let org_id = parse_uuid(p["org_id"].as_str().unwrap_or_default())?;
        (org_id, p["role"].as_str().unwrap_or("member").to_string(), "pending_approval", None)
    };

    sqlx::query("INSERT INTO users (id, org_id, email, status, created_at) VALUES ($1,$2,$3,'active',$4)")
        .bind(user_id)
        .bind(org_id)
        .bind(&email)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    if mode == "invite" {
        sqlx::query("UPDATE invites SET used_by = $2 WHERE id = $1")
            .bind(parse_uuid(p["invite_id"].as_str().unwrap_or_default())?)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query(
        "INSERT INTO org_memberships (org_id, user_id, role, status, cert, created_at, approved_at) VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(org_id)
    .bind(user_id)
    .bind(&role)
    .bind(status)
    .bind(&cert)
    .bind(now)
    .bind((status == "active").then_some(now))
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO opaque_records (user_id, record, updated_at) VALUES ($1,$2,$3)")
        .bind(user_id)
        .bind(unb64(p["record"].as_str().unwrap_or_default())?)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO keysets (user_id, keyset, updated_at) VALUES ($1,$2,$3)")
        .bind(user_id)
        .bind(&p["keyset"])
        .bind(now)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO mfa_totp (user_id, secret_enc, last_used_step, created_at) VALUES ($1,$2,$3,$4)")
        .bind(user_id)
        .bind(&secret_enc)
        .bind(step as i64)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    let rev = bump_revision(&mut tx, org_id).await?;
    sqlx::query(
        "INSERT INTO vaults (id, org_id, kind, owner_user_id, key_version, revision, created_at) VALUES ($1,$2,'personal',$1,1,$3,$4)",
    )
    .bind(user_id)
    .bind(org_id)
    .bind(rev)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    if let Some(b) = p.get("org_bootstrap").filter(|b| !b.is_null()) {
        let grants: Vec<KeyGrant> = serde_json::from_value(b["grants"].clone()).map_err(|_| AppError::internal())?;
        for g in &grants {
            store_grant(&mut tx, org_id, g, now).await?;
        }
    }
    let actor = Actor { org_id, user_id: Some(user_id), device_id: None, ip: meta.ip.clone(), user_agent: meta.user_agent.clone() };
    audit::record(&mut tx, &st, &actor, Event::new("account_created", "user", user_id)).await?;
    tx.commit().await?;
    st.publish(org_id, rev);

    finish_login(&st, user_id, &r.device_name, &meta, false).await
}

// ------------------------------------------------------------------ login

#[derive(Deserialize)]
pub struct LoginStartReq {
    email: String,
    credential_request: String,
}

pub async fn login_start(State(st): State<AppState>, meta: ReqMeta, Body(r): Body<LoginStartReq>) -> ApiResult<Json<Value>> {
    ratelimit::ip(&st, &meta, "login").await?;
    let email = normalize_email(&r.email)?;
    ratelimit::account_check(&st, &email).await?;
    // With OPAQUE the *client* learns at this step whether the password is right and a
    // guesser never needs to call /login/finish. So every start counts as a failed
    // attempt until a matching finish succeeds (which resets the counter).
    ratelimit::account_fail(&st, &email).await?;
    let row: Option<(Vec<u8>, Uuid)> = sqlx::query_as(
        "SELECT o.record, u.id FROM opaque_records o JOIN users u ON u.id = o.user_id WHERE u.email = $1 AND u.status = 'active'",
    )
    .bind(&email)
    .fetch_optional(&st.db)
    .await?;
    let record = match &row {
        Some((rec, _)) => Some(ServerRegistration::<Suite>::deserialize(rec).map_err(|_| AppError::internal())?),
        None => None, // opaque-ke runs the fake-record flow: same response shape, login fails at finish.
    };
    let req = CredentialRequest::<Suite>::deserialize(&unb64(&r.credential_request)?)
        .map_err(|_| AppError::bad_request("invalid credential request"))?;
    let start = ServerLogin::start(
        &mut rand::rngs::OsRng,
        &st.opaque,
        record,
        req,
        email.as_bytes(),
        ServerLoginStartParameters::default(),
    )
    .map_err(|_| AppError::bad_request("invalid credential request"))?;
    let data = json!({
        "email": email,
        "user_id": row.map(|r| r.1),
        "state": b64(&start.state.serialize()),
    });
    let login_token = tokens::create(&st, "login", &data, PROTOCOL_TTL).await?;
    Ok(Json(json!({ "credential_response": b64(&start.message.serialize()), "login_token": login_token })))
}

#[derive(Deserialize)]
pub struct LoginFinishReq {
    login_token: String,
    credential_finalization: String,
}

pub async fn login_finish(State(st): State<AppState>, meta: ReqMeta, Body(r): Body<LoginFinishReq>) -> ApiResult<Json<Value>> {
    let data = tokens::take(&st, "login", &r.login_token).await?.ok_or_else(AppError::invalid_credentials)?;
    let email = data["email"].as_str().unwrap_or_default().to_string();
    let user_id = data["user_id"].as_str().and_then(|s| Uuid::parse_str(s).ok());
    let ok = (|| {
        let state = ServerLogin::<Suite>::deserialize(&unb64(data["state"].as_str()?).ok()?).ok()?;
        let fin = CredentialFinalization::<Suite>::deserialize(&unb64(&r.credential_finalization).ok()?).ok()?;
        state.finish(fin).ok()
    })()
    .is_some();
    match (ok, user_id) {
        (true, Some(uid)) => {
            ratelimit::account_reset(&st, &email).await?;
            let mfa_token = tokens::create(&st, "mfa", &json!({ "user_id": uid, "email": email }), PROTOCOL_TTL).await?;
            Ok(Json(json!({ "mfa_token": mfa_token, "methods": ["totp"] })))
        }
        _ => {
            if let Some(uid) = user_id {
                audit_auth_event(&st, uid, "login_failed", &meta).await?;
            }
            Err(AppError::invalid_credentials())
        }
    }
}

#[derive(Deserialize)]
pub struct MfaVerifyReq {
    mfa_token: String,
    code: String,
    #[serde(default)]
    device_name: String,
}

pub async fn mfa_verify(State(st): State<AppState>, meta: ReqMeta, Body(r): Body<MfaVerifyReq>) -> ApiResult<Response> {
    let data = tokens::attempt(&st, "mfa", &r.mfa_token).await?.ok_or_else(AppError::invalid_credentials)?;
    let user_id = parse_uuid(data["user_id"].as_str().unwrap_or_default())?;
    let email = data["email"].as_str().unwrap_or_default().to_string();
    let (secret_enc, last_step): (Vec<u8>, i64) = sqlx::query_as("SELECT secret_enc, last_used_step FROM mfa_totp WHERE user_id = $1")
        .bind(user_id)
        .fetch_one(&st.db)
        .await?;
    let secret = envelope::open(&st.keys.mfa, &secret_enc, &mfa_aad(&user_id.to_string())).map_err(|_| AppError::internal())?;
    let secret = String::from_utf8(secret.to_vec()).map_err(|_| AppError::internal())?;
    let step = issuer_config(&secret, &email).verify(&r.code, st.now() as u64, 1).map(|s| s as i64);
    // Replay protection: each time step may be used once, and never an older one.
    let accepted = match step {
        Some(s) if s > last_step => sqlx::query("UPDATE mfa_totp SET last_used_step = $2 WHERE user_id = $1 AND last_used_step < $2")
            .bind(user_id)
            .bind(s)
            .execute(&st.db)
            .await?
            .rows_affected()
            == 1,
        _ => false,
    };
    if !accepted {
        ratelimit::account_fail(&st, &email).await?;
        audit_auth_event(&st, user_id, "mfa_failed", &meta).await?;
        return Err(AppError::invalid_credentials());
    }
    tokens::delete(&st, &r.mfa_token).await?;
    ratelimit::account_reset(&st, &email).await?;
    st.notifier.notify(
        &email,
        Notice::NewDeviceLogin,
        &format!("new sign-in from device \"{}\" ({})", r.device_name.chars().take(100).collect::<String>(), meta.ip.as_deref().unwrap_or("unknown IP")),
    );
    finish_login(&st, user_id, &r.device_name, &meta, true).await
}

async fn audit_auth_event(st: &AppState, user_id: Uuid, event: &str, meta: &ReqMeta) -> ApiResult<()> {
    let org: Option<(Uuid,)> = sqlx::query_as("SELECT org_id FROM users WHERE id = $1").bind(user_id).fetch_optional(&st.db).await?;
    if let Some((org_id,)) = org {
        let mut tx = st.org_tx(org_id).await?;
        let actor = Actor { org_id, user_id: Some(user_id), device_id: None, ip: meta.ip.clone(), user_agent: meta.user_agent.clone() };
        audit::record(&mut tx, st, &actor, Event::new(event, "user", user_id)).await?;
        tx.commit().await?;
    }
    Ok(())
}

async fn finish_login(st: &AppState, user_id: Uuid, device_name: &str, meta: &ReqMeta, log: bool) -> ApiResult<Response> {
    let (token, _) = session::create_session(st, user_id, device_name, meta.ip.as_deref()).await?;
    let user = session::load_session(st, &token).await?;
    if log {
        let mut tx = st.org_tx(user.org_id).await?;
        audit::record(&mut tx, st, &Actor::from(&user, meta), Event::new("login", "user", user_id)).await?;
        tx.commit().await?;
    }
    let mut body = user.session_json();
    body["session_token"] = json!(token);
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, session::set_cookie(&token));
    Ok((StatusCode::OK, headers, Json(body)).into_response())
}

pub async fn logout(State(st): State<AppState>, user: AuthUser) -> ApiResult<Response> {
    sqlx::query("DELETE FROM sessions WHERE token_hash = $1").bind(&user.token_hash).execute(&st.db).await?;
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, session::clear_cookie());
    Ok((StatusCode::NO_CONTENT, headers).into_response())
}

pub async fn session(user: AuthUser) -> Json<Value> {
    Json(user.session_json())
}
