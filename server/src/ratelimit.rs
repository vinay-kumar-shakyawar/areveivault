//! Redis-backed rate limiting and account lockout.

use redis::AsyncCommands;

use crate::auth::ReqMeta;
use crate::error::{ApiResult, AppError};
use crate::notify::Notice;
use crate::state::AppState;

/// Fixed one-minute window per (bucket, IP).
pub async fn ip(state: &AppState, meta: &ReqMeta, bucket: &str) -> ApiResult<()> {
    let ip = meta.ip.as_deref().unwrap_or("unknown");
    let window = state.now() / 60;
    let key = state.redis_key(&["rl", bucket, ip, &window.to_string()]);
    let mut r = state.redis.clone();
    let n: u64 = r.incr(&key, 1).await?;
    if n == 1 {
        let _: () = r.expire(&key, 70).await?;
    }
    if n > state.cfg.rate_limit_per_min {
        return Err(AppError::rate_limited());
    }
    Ok(())
}

/// Rejects login attempts for an account that is in backoff or locked.
/// Applies identically to unknown emails (no enumeration).
pub async fn account_check(state: &AppState, email: &str) -> ApiResult<()> {
    let mut r = state.redis.clone();
    let locked: bool = r.exists(state.redis_key(&["lock", email])).await?;
    if locked {
        return Err(AppError::rate_limited());
    }
    Ok(())
}

/// Exponential backoff after 5 failures (2^(n-5) s), 1 h lock after 20.
pub async fn account_fail(state: &AppState, email: &str) -> ApiResult<()> {
    let mut r = state.redis.clone();
    let key = state.redis_key(&["fail", email]);
    let n: u64 = r.incr(&key, 1).await?;
    let _: () = r.expire(&key, 3600).await?;
    let lock_secs = if n >= 20 {
        state.notifier.notify(email, Notice::AccountLocked, "too many failed sign-in attempts; locked for 1 hour");
        3600
    } else if n >= 5 {
        (1u64 << (n - 5).min(11)).min(3600)
    } else {
        0
    };
    if lock_secs > 0 {
        let _: () = r.set_ex(state.redis_key(&["lock", email]), 1, lock_secs).await?;
    }
    Ok(())
}

pub async fn account_reset(state: &AppState, email: &str) -> ApiResult<()> {
    let mut r = state.redis.clone();
    let _: () = r.del(&[state.redis_key(&["fail", email]), state.redis_key(&["lock", email])]).await?;
    Ok(())
}
