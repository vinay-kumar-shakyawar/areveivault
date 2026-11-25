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
    /// Where the landing page is served; the contact form redirects to pages under it.
    pub landing_url: String,
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
            .context("SERVER_SECRET_KEY is required (32 random bytes as hex or base64, or a random string of 32+ characters)")?;
        let public_origin = normalize_origin(&get("PUBLIC_ORIGIN", "https://vault.arevei.com"));
        let landing_url = match get("LANDING_URL", "").trim().trim_end_matches('/') {
            "" => format!("{public_origin}/welcome"),
            u => u.to_string(),
        };
        Ok(Config {
            database_url: std::env::var("DATABASE_URL").context("DATABASE_URL is required")?,
            redis_url: get("REDIS_URL", "redis://127.0.0.1:6379"),
            bind: get("BIND_ADDR", "0.0.0.0:8080"),
            public_origin,
            landing_url,
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

/// Accepts 32 random bytes as hex or base64, or any random string of at least 32 characters
/// (a hosting panel's generated password, e.g. Coolify's SERVICE_PASSWORD_64_*), which is
/// hashed down to 32 bytes. Hex and base64 inputs decode exactly as before, so existing
/// deployments keep the same key.
pub fn parse_secret(s: &str) -> anyhow::Result<[u8; 32]> {
    use sha2::Digest as _;
    let s = s.trim();
    if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(hex::decode(s)?.try_into().unwrap());
    }
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(s) {
        if let Ok(key) = <[u8; 32]>::try_from(bytes.as_slice()) {
            return Ok(key);
        }
    }
    if s.len() >= 32 {
        let mut h = sha2::Sha256::new();
        h.update(b"arevei-server-secret-v1\0");
        h.update(s.as_bytes());
        return Ok(h.finalize().into());
    }
    bail!("SERVER_SECRET_KEY must be 32 random bytes (hex or base64) or a random string of at least 32 characters")
}

/// `PUBLIC_ORIGIN` is compared byte-for-byte with the browser's `Origin` header, so accept the
/// forms hosting panels produce (bare domain, trailing slash, explicit default port) and
/// reduce them to `scheme://host[:port]`.
pub fn normalize_origin(s: &str) -> String {
    let mut o = s.trim().trim_end_matches('/').to_string();
    if !o.contains("://") {
        o = format!("https://{o}");
    }
    // Coolify's `https://domain:80` means "proxy to container port 80", not a public port.
    for (scheme, port) in [("https://", ":443"), ("https://", ":80"), ("http://", ":80")] {
        if o.starts_with(scheme) && o.ends_with(port) {
            o.truncate(o.len() - port.len());
        }
    }
    o.to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_formats() {
        let hex = "11".repeat(32);
        assert_eq!(parse_secret(&hex).unwrap(), [0x11; 32]);
        let b64 = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        assert_eq!(parse_secret(&b64).unwrap(), [7; 32]);
        let generated = "Zq3xV9pLm2Rt8YwK4sNb6HcJ1dFgUe5aQo7TiXyPzLkMnBvCrE0WuSjDhGfA2b3c";
        assert_eq!(parse_secret(generated).unwrap(), parse_secret(generated).unwrap());
        assert_ne!(parse_secret(generated).unwrap(), [0; 32]);
        assert!(parse_secret("short").is_err());
    }

    #[test]
    fn origins() {
        assert_eq!(normalize_origin("vault.yourco.com"), "https://vault.yourco.com");
        assert_eq!(normalize_origin("https://vault.yourco.com/"), "https://vault.yourco.com");
        assert_eq!(normalize_origin("https://vault.yourco.com:80"), "https://vault.yourco.com");
        assert_eq!(normalize_origin("http://localhost:5173"), "http://localhost:5173");
        assert_eq!(normalize_origin("https://Vault.YourCo.com"), "https://vault.yourco.com");
    }
}
