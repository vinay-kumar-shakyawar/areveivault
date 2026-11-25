//! The landing page's "Talk to Arevei about self-hosting" form.
//!
//! The landing page ships no JavaScript, so this is a plain HTML form post: urlencoded in,
//! `303` to a static page out. It is mounted outside the CSRF layer (a form can't send
//! `X-Arevei-Request`, and under `Referrer-Policy: no-referrer` browsers send `Origin: null`).
//! That is safe here: the endpoint is public, reads no cookie or session, and only appends a row.
//! Abuse is bounded by the per-IP rate limit, the field limits and the honeypot.
//!
//! Each stored request is also emailed to `CONTACT_NOTIFY_TO` / `CONTACT_NOTIFY_CC` when SMTP
//! is configured. The email is sent in the background: the row is the record, so a mail
//! failure is logged and never fails the visitor's submission.

use axum::extract::rejection::FormRejection;
use axum::extract::State;
use axum::response::Redirect;
use axum::Form;
use serde::Deserialize;
use uuid::Uuid;

use super::normalize_email;
use crate::auth::ReqMeta;
use crate::error::{ApiResult, AppError};
use crate::mail;
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
    notify_staff(st, id, Details { name, email, company, team_size, hosting, message });
    Ok(())
}

struct Details<'a> {
    name: String,
    email: String,
    company: String,
    team_size: &'a str,
    hosting: &'a str,
    message: String,
}

fn notify_staff(st: &AppState, id: Uuid, d: Details<'_>) {
    if st.cfg.smtp.is_none() || st.cfg.contact_notify_to.is_empty() {
        return;
    }
    let or_dash = |s: &str| if s.is_empty() { "-".to_string() } else { s.to_string() };
    let runs_on = match d.hosting {
        "own" => "On their own infrastructure",
        "arevei" => "On a server Arevei manages",
        "unsure" => "Not sure yet",
        _ => "-",
    };
    // Header values must be one line.
    let one_line = |s: &str| s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect::<String>();
    let subject = match d.company.as_str() {
        "" => format!("Self-hosting request from {}", one_line(&d.name)),
        c => format!("Self-hosting request from {} ({})", one_line(&d.name), one_line(c)),
    };
    let lines = [
        "New self-hosting request from the Arevei Vault website.".to_string(),
        String::new(),
        format!("Name:       {}", d.name),
        format!("Email:      {}", d.email),
        format!("Company:    {}", or_dash(&d.company)),
        format!("Team size:  {}", or_dash(d.team_size)),
        format!("Runs on:    {runs_on}"),
        String::new(),
        "Message:".to_string(),
        or_dash(&d.message),
        String::new(),
        format!("Reply to this email to answer {} directly.", d.name),
        format!("Request ID: {id}"),
    ];
    let body = lines.join("\r\n");
    let email = d.email;
    let st = st.clone();
    tokio::spawn(async move {
        let Some(smtp) = &st.cfg.smtp else { return };
        let mail = mail::Email {
            to: &st.cfg.contact_notify_to,
            cc: &st.cfg.contact_notify_cc,
            reply_to: Some(&email),
            subject: &subject,
            body,
        };
        match mail::send(smtp, mail).await {
            Ok(()) => tracing::info!(target: "contact", %id, "self-host request emailed to staff"),
            Err(e) => tracing::error!(target: "contact", %id, error = %format!("{e:#}"), "could not email the self-host request"),
        }
    });
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
