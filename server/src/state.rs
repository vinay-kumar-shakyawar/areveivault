use std::collections::HashMap;
use std::ops::Deref;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use arevei_core::keys::SymKey;
use arevei_core::opaque::{opaque_ke::ServerSetup, Suite};
use hkdf::Hkdf;
use sha2::Sha256;
use sqlx::PgPool;
use tokio::sync::broadcast;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::config::Config;
use crate::error::ApiResult;
use crate::notify::Notifier;

pub type Tx = sqlx::Transaction<'static, sqlx::Postgres>;

/// Purpose-separated subkeys derived from `SERVER_SECRET_KEY` (HKDF-SHA256).
pub struct ServerKeys {
    /// Encrypts account TOTP seeds at rest.
    pub mfa: SymKey,
    /// Encrypts the persisted OPAQUE ServerSetup.
    pub opaque: SymKey,
    /// HMAC key for deterministic fake prelogin salts.
    pub fake_salt: Zeroizing<[u8; 32]>,
    /// Ed25519 key signing audit checkpoints.
    pub audit_sk: Zeroizing<[u8; 32]>,
    pub audit_pk: [u8; 32],
}

impl ServerKeys {
    pub fn derive(secret: &[u8; 32]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(b"arevei-vault/server/v1"), secret);
        let expand = |label: &str| {
            let mut out = Zeroizing::new([0u8; 32]);
            hk.expand(label.as_bytes(), &mut *out).expect("valid length");
            out
        };
        let audit_sk = expand("audit-signing");
        ServerKeys {
            mfa: SymKey::from_bytes(*expand("mfa-at-rest")),
            opaque: SymKey::from_bytes(*expand("opaque-setup")),
            fake_salt: expand("fake-prelogin-salt"),
            audit_pk: arevei_core::sign::verifying_key(&audit_sk),
            audit_sk,
        }
    }
}

pub struct Inner {
    pub cfg: Config,
    pub db: PgPool,
    pub redis: redis::aio::ConnectionManager,
    pub keys: ServerKeys,
    pub opaque: ServerSetup<Suite>,
    pub notifier: Arc<dyn Notifier>,
    events: Mutex<HashMap<Uuid, broadcast::Sender<i64>>>,
    clock_offset: AtomicI64,
}

#[derive(Clone)]
pub struct AppState(pub Arc<Inner>);

impl Deref for AppState {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl AppState {
    pub fn new(
        cfg: Config,
        db: PgPool,
        redis: redis::aio::ConnectionManager,
        keys: ServerKeys,
        opaque: ServerSetup<Suite>,
        notifier: Arc<dyn Notifier>,
    ) -> Self {
        AppState(Arc::new(Inner {
            cfg,
            db,
            redis,
            keys,
            opaque,
            notifier,
            events: Mutex::new(HashMap::new()),
            clock_offset: AtomicI64::new(0),
        }))
    }

    pub fn now(&self) -> i64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64 + self.clock_offset.load(Ordering::Relaxed)
    }

    /// Test hook: move the server clock forward (TOTP steps, expiry).
    pub fn advance_clock(&self, secs: i64) {
        self.clock_offset.fetch_add(secs, Ordering::Relaxed);
    }

    /// Transaction scoped to one organization: RLS only exposes that org's rows.
    pub async fn org_tx(&self, org_id: Uuid) -> ApiResult<Tx> {
        let mut tx = self.db.begin().await?;
        sqlx::query("SELECT set_config('app.org_id', $1, true)")
            .bind(org_id.to_string())
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }

    /// Cross-org transaction. Only for auth bootstrap (invite lookup, first-org check)
    /// and background maintenance.
    pub async fn system_tx(&self) -> ApiResult<Tx> {
        let mut tx = self.db.begin().await?;
        sqlx::query("SELECT set_config('app.org_id', '*', true)").execute(&mut *tx).await?;
        Ok(tx)
    }

    pub fn publish(&self, org_id: Uuid, revision: i64) {
        if let Some(tx) = self.events.lock().unwrap().get(&org_id) {
            let _ = tx.send(revision);
        }
    }

    pub fn subscribe(&self, org_id: Uuid) -> broadcast::Receiver<i64> {
        let mut map = self.events.lock().unwrap();
        map.retain(|_, s| s.receiver_count() > 0);
        map.entry(org_id).or_insert_with(|| broadcast::channel(64).0).subscribe()
    }

    pub fn redis_key(&self, parts: &[&str]) -> String {
        format!("{}:{}", self.cfg.redis_prefix, parts.join(":"))
    }
}
