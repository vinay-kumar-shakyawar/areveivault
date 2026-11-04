//! Arevei Vault API server. Stores and syncs ciphertext; never sees vault plaintext
//! or user key material. See docs/api.md (contract) and docs/schema.md.

pub mod attachments_fs;
pub mod audit;
pub mod auth;
pub mod config;
pub mod error;
pub mod notify;
pub mod ratelimit;
pub mod routes;
pub mod state;
pub mod tasks;
pub mod tokens;

use std::sync::Arc;

use anyhow::Context;
use arevei_core::encoding::Aad;
use arevei_core::envelope;
use arevei_core::opaque::{opaque_ke::ServerSetup, Suite};
use axum::Router;
use sqlx::postgres::PgPoolOptions;
use sqlx::{Executor, PgPool};

use crate::config::Config;
use crate::notify::LogNotifier;
use crate::state::{AppState, ServerKeys};

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Run migrations with a plain (owner) connection, then open the application pool,
/// whose connections drop to the RLS-bound `arevei_app` role.
pub async fn connect(database_url: &str) -> anyhow::Result<PgPool> {
    let owner = PgPoolOptions::new().max_connections(1).connect(database_url).await.context("connect to Postgres")?;
    MIGRATOR.run(&owner).await.context("run migrations")?;
    owner.close().await;
    let pool = PgPoolOptions::new()
        .max_connections(20)
        .after_connect(|conn, _| {
            Box::pin(async move {
                conn.execute("SET ROLE arevei_app").await?;
                Ok(())
            })
        })
        .connect(database_url)
        .await?;
    Ok(pool)
}

async fn load_opaque_setup(db: &PgPool, keys: &ServerKeys) -> anyhow::Result<ServerSetup<Suite>> {
    let aad = Aad::new("opaque-server-setup");
    if let Some((blob,)) = sqlx::query_as::<_, (Vec<u8>,)>("SELECT value FROM server_state WHERE key = 'opaque_setup'")
        .fetch_optional(db)
        .await?
    {
        let raw = envelope::open(&keys.opaque, &blob, aad.bytes()).context("decrypt OPAQUE setup (wrong SERVER_SECRET_KEY?)")?;
        return ServerSetup::<Suite>::deserialize(&raw).map_err(|_| anyhow::anyhow!("corrupt OPAQUE setup"));
    }
    let setup = ServerSetup::<Suite>::new(&mut rand::rngs::OsRng);
    let blob = envelope::seal(&keys.opaque, &setup.serialize(), aad.bytes());
    sqlx::query("INSERT INTO server_state (key, value) VALUES ('opaque_setup', $1) ON CONFLICT (key) DO NOTHING")
        .bind(&blob)
        .execute(db)
        .await?;
    // Re-read in case another instance won the race.
    let (blob,): (Vec<u8>,) = sqlx::query_as("SELECT value FROM server_state WHERE key = 'opaque_setup'").fetch_one(db).await?;
    let raw = envelope::open(&keys.opaque, &blob, aad.bytes())?;
    ServerSetup::<Suite>::deserialize(&raw).map_err(|_| anyhow::anyhow!("corrupt OPAQUE setup"))
}

pub async fn build_state(cfg: Config) -> anyhow::Result<AppState> {
    let db = connect(&cfg.database_url).await?;
    let redis = redis::Client::open(cfg.redis_url.as_str())?;
    let redis = redis::aio::ConnectionManager::new(redis).await.context("connect to Redis")?;
    let keys = ServerKeys::derive(&cfg.server_secret);
    let opaque = load_opaque_setup(&db, &keys).await?;
    tokio::fs::create_dir_all(&cfg.attachment_dir).await.context("create ATTACHMENT_DIR")?;
    Ok(AppState::new(cfg, db, redis, keys, opaque, Arc::new(LogNotifier)))
}

pub fn app(state: AppState) -> Router {
    routes::router(state)
}
