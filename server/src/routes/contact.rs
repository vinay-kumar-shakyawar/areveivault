//! The landing page's "Talk to Arevei about self-hosting" form.
//!
//! The landing page ships no JavaScript, so this is a plain HTML form post: urlencoded in,
//! `303` to a static page out. It is mounted outside the CSRF layer (a form can't send
//! `X-Arevei-Request`, and under `Referrer-Policy: no-referrer` browsers send `Origin: null`).
//! That is safe here: the endpoint is public, reads no cookie or session, and only appends a row.
//! Abuse is bounded by the per-IP rate limit, the field limits and the honeypot.

use axum::extract::rejection::FormRejection;
use axum::extract::State;
use axum::response::Redirect;
use axum::Form;
use serde::Deserialize;
use uuid::Uuid;

use super::normalize_email;
use crate::auth::ReqMeta;
use crate::error::{ApiResult, AppError};
use crate::ratelimit;
use crate::state::AppState;

pub const FORM_LIMIT: usize = 16 * 1024;

const TEAM_SIZES: [&str; 5] = ["", "1", "2-10", "11-50", "51+"];
const HOSTING: [&str; 4] = ["", "arevei", "own", "unsure"];

#[derive(Deserialize)]
pub struct SelfHostReq {
    #[serde(default)]
    name: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    company: String,
    #[serde(default)]
    team_size: String,
    #[serde(default)]
    hosting: String,
    #[serde(default)]
    message: String,
    /// Honeypot: hidden from people, so only bots fill it.
    #[serde(default)]
    website: String,
}

pub async fn self_host(
    State(st): State<AppState>,
    meta: ReqMeta,
    form: Result<Form<SelfHostReq>, FormRejection>,
) -> Redirect {
    let ok = match form {
        Ok(Form(r)) => store(&st, &meta, r).await.is_ok(),
        Err(_) => false,
    };
    let page = if ok { "thanks.html" } else { "request-failed.html" };
    Redirect::to(&format!("{}/{page}", st.cfg.landing_url))
}

async fn store(st: &AppState, meta: &ReqMeta, r: SelfHostReq) -> ApiResult<()> {
    ratelimit::ip(st, meta, "contact").await?;
    if !r.website.trim().is_empty() {
        return Ok(()); // a bot: show it the thank-you page, store nothing
    }
    let name = text(&r.name, 120)?;
    if name.is_empty() {
        return Err(AppError::bad_request("name is required"));
    }
    let email = normalize_email(&r.email)?;
    let company = text(&r.company, 160)?;
    let message = text(&r.message, 4000)?;
    let team_size = choice(&r.team_size, &TEAM_SIZES)?;
    let hosting = choice(&r.hosting, &HOSTING)?;
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO selfhost_requests (id, name, email, company, team_size, hosting, message, created_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(id)
    .bind(&name)
    .bind(&email)
    .bind(&company)
    .bind(team_size)
    .bind(hosting)
    .bind(&message)
    .bind(st.now())
    .execute(&st.db)
    .await?;
    tracing::info!(target: "contact", %id, "self-host request received (see table selfhost_requests)");
    Ok(())
}

fn text(s: &str, max_chars: usize) -> ApiResult<String> {
    let s = s.trim();
    if s.chars().count() > max_chars || s.contains('\0') {
        return Err(AppError::bad_request("field too long"));
    }
    Ok(s.to_string())
}

fn choice<'a>(s: &'a str, allowed: &[&str]) -> ApiResult<&'a str> {
    let s = s.trim();
    if allowed.contains(&s) {
        Ok(s)
    } else {
        Err(AppError::bad_request("invalid choice"))
    }
}
