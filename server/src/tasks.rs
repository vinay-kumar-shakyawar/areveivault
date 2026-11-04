//! Background maintenance: trash purge (30 days), expired sessions/tokens, audit checkpoints.

use std::time::Duration;

use uuid::Uuid;

use crate::error::ApiResult;
use crate::routes::{bump_revision, items::purge_items};
use crate::state::AppState;
use crate::{attachments_fs, audit};

pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(30)).await;
        loop {
            if let Err(e) = run_once(&state).await {
                tracing::error!(error = ?e.message, "maintenance run failed");
            }
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    });
}

pub async fn run_once(state: &AppState) -> ApiResult<()> {
    purge_trash(state).await?;
    cleanup_sessions(state).await?;
    checkpoint_all(state).await?;
    Ok(())
}

pub async fn purge_trash(state: &AppState) -> ApiResult<usize> {
    let cutoff = state.now() - state.cfg.trash_retention_secs;
    let mut tx = state.system_tx().await?;
    let orgs: Vec<(Uuid,)> =
        sqlx::query_as("SELECT DISTINCT org_id FROM items WHERE deleted_at IS NOT NULL AND deleted_at < $1")
            .bind(cutoff)
            .fetch_all(&mut *tx)
            .await?;
    tx.commit().await?;
    let mut total = 0;
    for (org_id,) in orgs {
        let mut tx = state.org_tx(org_id).await?;
        let items: Vec<(Uuid, Uuid)> =
            sqlx::query_as("SELECT id, vault_id FROM items WHERE deleted_at IS NOT NULL AND deleted_at < $1 FOR UPDATE")
                .bind(cutoff)
                .fetch_all(&mut *tx)
                .await?;
        let rev = bump_revision(&mut tx, org_id).await?;
        let files = purge_items(&mut tx, org_id, &items, rev, state.now()).await?;
        let actor = audit::Actor { org_id, user_id: None, device_id: None, ip: None, user_agent: Some("maintenance".into()) };
        audit::record(&mut tx, state, &actor, audit::Event::new("trash_purge", "org", format!("{} items", items.len()))).await?;
        tx.commit().await?;
        attachments_fs::remove_all(state, org_id, &files).await;
        state.publish(org_id, rev);
        total += items.len();
    }
    Ok(total)
}

pub async fn cleanup_sessions(state: &AppState) -> ApiResult<()> {
    let now = state.now();
    sqlx::query("DELETE FROM sessions WHERE last_seen_at < $1 OR created_at < $2")
        .bind(now - state.cfg.session_idle_secs)
        .bind(now - state.cfg.session_absolute_secs)
        .execute(&state.db)
        .await?;
    sqlx::query("DELETE FROM pending_tokens WHERE expires_at < $1").bind(now).execute(&state.db).await?;
    Ok(())
}

pub async fn checkpoint_all(state: &AppState) -> ApiResult<()> {
    let mut tx = state.system_tx().await?;
    let orgs: Vec<(Uuid,)> = sqlx::query_as("SELECT id FROM organizations").fetch_all(&mut *tx).await?;
    tx.commit().await?;
    for (org_id,) in orgs {
        let mut tx = state.org_tx(org_id).await?;
        audit::checkpoint(&mut tx, state, org_id).await?;
        tx.commit().await?;
    }
    Ok(())
}
