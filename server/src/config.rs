use std::path::PathBuf;

use anyhow::{bail, Context};
use base64::Engine as _;

/// Runtime configuration (see `server/.env.example`). Deliberately not `Debug`: holds the server secret.
#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    pub redis_url: String,
    pub bind: String,
    /// Exact origin of the web app, e.g. `https://vault.arevei.com`.
    pub public_origin: String,
    pub server_secret: [u8; 32],
    pub allow_signup: bool,
    pub trust_proxy: bool,
    pub session_idle_secs: i64,
    pub session_absolute_secs: i64,
    pub attachment_dir: PathBuf,
    pub rate_limit_per_min: u64,
    /// Prefix for Redis keys (lets several instances/tests share one Redis).
    pub redis_prefix: String,
    pub trash_retention_secs: i64,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let get = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
        let flag = |k: &str| matches!(get(k, "false").to_ascii_lowercase().as_str(), "1" | "true" | "yes");
        let secret = std::env::var("SERVER_SECRET_KEY")
            .context("SERVER_SECRET_KEY is required (32 random bytes, hex or base64)")?;
        Ok(Config {
            database_url: std::env::var("DATABASE_URL").context("DATABASE_URL is required")?,
            redis_url: get("REDIS_URL", "redis://127.0.0.1:6379"),
            bind: get("BIND_ADDR", "0.0.0.0:8080"),
            public_origin: get("PUBLIC_ORIGIN", "https://vault.arevei.com"),
            server_secret: parse_secret(&secret)?,
            allow_signup: flag("ALLOW_SIGNUP"),
            trust_proxy: flag("TRUST_PROXY"),
            session_idle_secs: get("SESSION_IDLE_SECS", "43200").parse()?,
            session_absolute_secs: get("SESSION_ABSOLUTE_SECS", "604800").parse()?,
            attachment_dir: get("ATTACHMENT_DIR", "./data/attachments").into(),
            rate_limit_per_min: get("RATE_LIMIT_PER_MIN", "10").parse()?,
            redis_prefix: get("REDIS_PREFIX", "av"),
            trash_retention_secs: 30 * 24 * 3600,
        })
    }
}

pub fn parse_secret(s: &str) -> anyhow::Result<[u8; 32]> {
    let s = s.trim();
    let bytes = if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        hex::decode(s)?
    } else {
        base64::engine::general_purpose::STANDARD.decode(s)?
    };
    if bytes.len() != 32 {
        bail!("SERVER_SECRET_KEY must decode to exactly 32 bytes");
    }
    Ok(bytes.try_into().unwrap())
}
