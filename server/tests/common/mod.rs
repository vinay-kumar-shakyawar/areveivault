//! Test harness: a fresh database per test, the real router (in-process), and the
//! real `arevei_core::engine::Engine` acting as the client.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::PathBuf;

use arevei_core::engine::Engine;
use arevei_core::totp::TotpConfig;
use arevei_server::config::Config;
use arevei_server::state::AppState;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::{Connection, Executor, PgConnection};
use tower::ServiceExt;
use uuid::Uuid;

pub const PASSWORD: &str = "Correct-Horse-Battery-Staple-42";

pub fn admin_url() -> String {
    std::env::var("TEST_DATABASE_URL").unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:55432/postgres".into())
}

pub fn redis_url() -> String {
    std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:56379".into())
}

pub struct TestApp {
    pub state: AppState,
    pub router: Router,
    pub db_name: String,
    pub attachment_dir: PathBuf,
}

static MIGRATE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub async fn spawn_with(f: impl FnOnce(&mut Config)) -> TestApp {
    let db_name = format!("t_{}", Uuid::new_v4().simple());
    let mut admin = PgConnection::connect(&admin_url()).await.expect("connect admin db (is deploy/docker-compose.dev.yml up?)");
    admin.execute(format!("CREATE DATABASE {db_name}").as_str()).await.unwrap();
    let base = admin_url();
    let url = format!("{}/{}", base.rsplit_once('/').unwrap().0, db_name);
    let attachment_dir = std::env::temp_dir().join("arevei-test-attachments").join(&db_name);
    let mut cfg = Config {
        database_url: url,
        redis_url: redis_url(),
        bind: "127.0.0.1:0".into(),
        public_origin: "https://vault.test".into(),
        server_secret: [7u8; 32],
        allow_signup: false,
        trust_proxy: false,
        session_idle_secs: 43200,
        session_absolute_secs: 604800,
        attachment_dir: attachment_dir.clone(),
        rate_limit_per_min: 1000,
        redis_prefix: db_name.clone(),
        trash_retention_secs: 30 * 24 * 3600,
    };
    f(&mut cfg);
    let state = {
        let _g = MIGRATE_LOCK.lock().await;
        arevei_server::build_state(cfg).await.expect("build state")
    };
    TestApp { router: arevei_server::app(state.clone()), state, db_name, attachment_dir }
}

pub async fn spawn() -> TestApp {
    spawn_with(|_| {}).await
}

#[derive(Debug)]
pub struct Resp {
    pub status: StatusCode,
    pub body: Value,
    pub headers: axum::http::HeaderMap,
}

impl TestApp {
    pub async fn send(&self, req: Request<Body>) -> Resp {
        let mut req = req;
        req.extensions_mut().insert(ConnectInfo("10.1.2.3:4444".parse::<SocketAddr>().unwrap()));
        let res = self.router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let body = if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap_or(Value::String(String::from_utf8_lossy(&bytes).into())) };
        Resp { status, body, headers }
    }

    pub async fn call(&self, method: &str, path: &str, token: Option<&str>, body: Option<Value>) -> Resp {
        let mut b = Request::builder().method(method).uri(format!("/api/v1{path}")).header("x-arevei-request", "1");
        if let Some(t) = token {
            b = b.header("authorization", format!("Bearer {t}"));
        }
        let req = match body {
            Some(v) => b.header("content-type", "application/json").body(Body::from(v.to_string())).unwrap(),
            None => b.body(Body::empty()).unwrap(),
        };
        self.send(req).await
    }

    pub async fn raw_put(&self, path: &str, token: &str, data: Vec<u8>) -> Resp {
        let req = Request::builder()
            .method("PUT")
            .uri(format!("/api/v1{path}"))
            .header("x-arevei-request", "1")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/octet-stream")
            .body(Body::from(data))
            .unwrap();
        self.send(req).await
    }

    pub async fn owner_conn(&self) -> PgConnection {
        let base = admin_url();
        PgConnection::connect(&format!("{}/{}", base.rsplit_once('/').unwrap().0, self.db_name)).await.unwrap()
    }
}

pub fn e(engine: &mut Engine, method: &str, args: Value) -> Value {
    engine.call(method, args).unwrap_or_else(|err| panic!("engine {method}: {err}"))
}

pub struct User {
    pub engine: Engine,
    pub token: String,
    pub email: String,
    pub secret_key: String,
    pub user_id: String,
    pub totp_secret: String,
    pub pinned: Option<String>,
    pub session: Value,
}

/// Mirrors packages/client/src/flows.ts `signup` + TOTP confirmation.
pub async fn signup(app: &TestApp, email: &str, invite: Option<&str>, create_org: bool) -> User {
    let mut engine = Engine::new();
    let sk = e(&mut engine, "generate_secret_key", json!({}))["secret_key"].as_str().unwrap().to_string();
    let params = e(&mut engine, "new_account_params", json!({}));
    e(&mut engine, "derive", json!({"password": PASSWORD, "secret_key": sk, "salt": params["salt"], "kdf": params["kdf"]}));
    let reg = e(&mut engine, "opaque_register_start", json!({}));
    let r = app
        .call("POST", "/auth/register/start", None, Some(json!({"email": email, "invite_token": invite, "registration_request": reg["message"]})))
        .await;
    assert_eq!(r.status, StatusCode::OK, "register/start: {}", r.body);
    let fin = e(&mut engine, "opaque_register_finish", json!({"response": r.body["registration_response"]}));
    let user_id = Uuid::new_v4().to_string();
    let acct = e(
        &mut engine,
        "create_account",
        json!({"user_id": user_id, "email": email, "salt": params["salt"], "kdf": params["kdf"],
               "create_org_id": if create_org { Some(Uuid::new_v4().to_string()) } else { None }, "now": app.state.now()}),
    );
    let mut body = json!({"signup_token": r.body["signup_token"], "user_id": user_id, "registration_upload": fin["upload"], "keyset": acct["keyset"]});
    if !acct["org_bootstrap"].is_null() {
        body["org_bootstrap"] = acct["org_bootstrap"].clone();
    }
    let f = app.call("POST", "/auth/register/finish", None, Some(body)).await;
    assert_eq!(f.status, StatusCode::OK, "register/finish: {}", f.body);
    let secret = f.body["totp_secret"].as_str().unwrap().to_string();
    assert!(f.body["otpauth_uri"].as_str().unwrap().starts_with("otpauth://totp/"));
    let code = TotpConfig::new(&secret).unwrap().code_at(app.state.now() as u64).unwrap().code;
    let c = app
        .call("POST", "/auth/mfa/totp/confirm", None, Some(json!({"pending_token": f.body["pending_token"], "code": code, "device_name": "test"})))
        .await;
    assert_eq!(c.status, StatusCode::OK, "confirm: {}", c.body);
    assert!(c.headers.get("set-cookie").unwrap().to_str().unwrap().starts_with("__Host-av_session="));
    User {
        engine,
        token: c.body["session_token"].as_str().unwrap().to_string(),
        email: email.into(),
        secret_key: sk,
        user_id,
        totp_secret: secret,
        pinned: None,
        session: c.body.clone(),
    }
}

/// Full login in a fresh engine (a "second browser"). Advances the server clock one
/// TOTP step so the code is not a replay of the previous one.
pub async fn login(app: &TestApp, u: &User) -> Result<User, Resp> {
    let mut engine = Engine::new();
    let pre = app.call("POST", "/auth/prelogin", None, Some(json!({"email": u.email}))).await;
    assert_eq!(pre.status, StatusCode::OK);
    e(&mut engine, "derive", json!({"password": PASSWORD, "secret_key": u.secret_key, "salt": pre.body["salt"], "kdf": pre.body["kdf"]}));
    let start = e(&mut engine, "opaque_login_start", json!({}));
    let s = app.call("POST", "/auth/login/start", None, Some(json!({"email": u.email, "credential_request": start["message"]}))).await;
    if s.status != StatusCode::OK {
        return Err(s);
    }
    let fin = match engine.call("opaque_login_finish", json!({"response": s.body["credential_response"]})) {
        Ok(v) => v,
        // Wrong password / Secret Key / unknown user: the client detects it; report like a 401.
        Err(_) => return Err(Resp { status: StatusCode::UNAUTHORIZED, body: Value::Null, headers: Default::default() }),
    };
    let f = app
        .call("POST", "/auth/login/finish", None, Some(json!({"login_token": s.body["login_token"], "credential_finalization": fin["finalization"]})))
        .await;
    if f.status != StatusCode::OK {
        return Err(f);
    }
    app.state.advance_clock(30);
    let code = TotpConfig::new(&u.totp_secret).unwrap().code_at(app.state.now() as u64).unwrap().code;
    let m = app.call("POST", "/auth/mfa/verify", None, Some(json!({"mfa_token": f.body["mfa_token"], "code": code, "device_name": "browser 2"}))).await;
    if m.status != StatusCode::OK {
        return Err(m);
    }
    let token = m.body["session_token"].as_str().unwrap().to_string();
    let ks = app.call("GET", "/keyset", Some(&token), None).await;
    e(&mut engine, "unlock", json!({"keyset": ks.body}));
    Ok(User {
        engine,
        token,
        email: u.email.clone(),
        secret_key: u.secret_key.clone(),
        user_id: u.user_id.clone(),
        totp_secret: u.totp_secret.clone(),
        pinned: u.pinned.clone(),
        session: m.body.clone(),
    })
}

/// GET /sync?since=0 and feed it to the engine with TOFU pinning of the org key.
pub async fn sync(app: &TestApp, u: &mut User) -> Value {
    let r = app.call("GET", "/sync?since=0", Some(&u.token), None).await;
    assert_eq!(r.status, StatusCode::OK, "sync: {}", r.body);
    let mut payload = r.body.clone();
    if u.pinned.is_none() {
        u.pinned = r.body["org"]["org_sign_pk"].as_str().map(String::from);
    }
    payload["pinned_org_pk"] = json!(u.pinned);
    let applied = e(&mut u.engine, "sync_apply", payload);
    let mut out = r.body;
    out["_warnings"] = applied["warnings"].clone();
    out
}

pub fn login_item(title: &str, url: &str, username: &str, password: &str, notes: &str) -> Value {
    json!({"title": title, "notes": notes, "data": {"type": "login", "username": username, "password": password, "urls": [{"url": url}]}})
}

/// Encrypt via the engine and PUT. Returns (status, body); on success feeds the row back.
pub async fn put_item(app: &TestApp, u: &mut User, vault_id: &str, item: Value, item_id: Option<&str>) -> Resp {
    let req = e(&mut u.engine, "encrypt_item", json!({"vault_id": vault_id, "item": item, "item_id": item_id, "now": app.state.now()}));
    let r = app.call("PUT", &format!("/items/{}", req["id"].as_str().unwrap()), Some(&u.token), Some(req)).await;
    if r.status == StatusCode::OK {
        e(&mut u.engine, "sync_apply", json!({"items": [r.body.clone()]}));
    }
    r
}
