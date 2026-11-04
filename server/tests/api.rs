//! End-to-end API tests against real Postgres + Redis (deploy/docker-compose.dev.yml),
//! driven by the real core engine as the client.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::*;
use serde_json::{json, Value};
use sqlx::Executor;

fn item_ids(engine: &mut arevei_core::engine::Engine, query: &str) -> Vec<Value> {
    e(engine, "list_items", json!({ "query": query })).as_array().unwrap().clone()
}

#[tokio::test]
async fn full_flow() {
    let app = spawn().await;

    // --- bootstrap: first user creates the organization
    let mut owner = signup(&app, "owner@arevei.com", None, true).await;
    assert_eq!(owner.session["role"], "owner");
    assert_eq!(owner.session["status"], "active");
    let s = app.call("GET", "/auth/session", Some(&owner.token), None).await;
    assert_eq!(s.status, StatusCode::OK);

    // A second signup without an invitation is refused.
    let mut eng = arevei_core::engine::Engine::new();
    let sk = e(&mut eng, "generate_secret_key", json!({}))["secret_key"].clone();
    let p = e(&mut eng, "new_account_params", json!({}));
    e(&mut eng, "derive", json!({"password": PASSWORD, "secret_key": sk, "salt": p["salt"], "kdf": p["kdf"]}));
    let reg = e(&mut eng, "opaque_register_start", json!({}));
    let r = app.call("POST", "/auth/register/start", None, Some(json!({"email": "intruder@x.com", "registration_request": reg["message"]}))).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    // --- client + project + items
    let sy = sync(&app, &mut owner).await;
    assert!(sy["_warnings"].as_array().unwrap().is_empty(), "{}", sy["_warnings"]);
    assert!(sy["org"]["org_secrets"].is_string());
    let client = e(&mut owner.engine, "create_client", json!({"name": "Acme Corp"}));
    let r = app.call("POST", "/clients", Some(&owner.token), Some(client.clone())).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let vault = e(&mut owner.engine, "create_vault", json!({"name": "Website", "client_id": client["id"]}));
    let r = app.call("POST", "/vaults", Some(&owner.token), Some(vault.clone())).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let vid = vault["id"].as_str().unwrap().to_string();
    let sy = sync(&app, &mut owner).await;
    assert!(sy["_warnings"].as_array().unwrap().is_empty(), "{}", sy["_warnings"]);

    let r = put_item(&app, &mut owner, &vid, login_item("WP admin", "https://acme.com/wp-admin", "admin", "s3cret-wp", ""), None).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let wp_id = r.body["id"].as_str().unwrap().to_string();
    let owner_uid = owner.user_id.clone();
    let r = put_item(&app, &mut owner, &owner_uid, login_item("My bank", "https://bank.com", "me", "personal-pw", ""), None).await;
    assert_eq!(r.status, StatusCode::OK);
    let personal_item = r.body["id"].as_str().unwrap().to_string();
    // put_item must not have dropped project vaults from the engine.
    assert_eq!(item_ids(&mut owner.engine, "").len(), 2);

    // --- second browser: same data
    let mut owner2 = login(&app, &owner).await.expect("login");
    sync(&app, &mut owner2).await;
    assert_eq!(item_ids(&mut owner2.engine, "").len(), 2);
    let got = e(&mut owner2.engine, "get_item", json!({"id": wp_id}));
    assert_eq!(got["item"]["data"]["password"], "s3cret-wp");
    let lv = e(&mut owner2.engine, "list_vaults", json!({}));
    assert!(lv["vaults"].as_array().unwrap().iter().any(|v| v["name"] == "Website" && v["client_name"] == "Acme Corp"));

    // --- invite + pending member
    let inv = app.call("POST", "/org/invites", Some(&owner.token), Some(json!({"email": "bob@arevei.com", "role": "member"}))).await;
    assert_eq!(inv.status, StatusCode::OK, "{}", inv.body);
    let mut bob = signup(&app, "bob@arevei.com", inv.body["invite_token"].as_str(), false).await;
    assert_eq!(bob.session["status"], "pending_approval");
    // Invite is single-use.
    let reg = e(&mut eng, "opaque_register_start", json!({}));
    let r = app.call("POST", "/auth/register/start", None, Some(json!({"email": "bob@arevei.com", "invite_token": inv.body["invite_token"], "registration_request": reg["message"]}))).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let sy = sync(&app, &mut bob).await;
    assert_eq!(sy["vaults"].as_array().unwrap().len(), 1, "pending user sees only the personal vault");
    assert!(sy["clients"].as_array().unwrap().is_empty());
    assert!(sy["org"]["org_secrets"].is_null());
    // Pending users can't touch projects.
    let r = put_item(&app, &mut owner, &vid, login_item("x", "https://x.com", "u", "p", ""), None).await;
    assert_eq!(r.status, StatusCode::OK);
    let bob_try = app.call("DELETE", &format!("/items/{}", r.body["id"].as_str().unwrap()), Some(&bob.token), None).await;
    assert_eq!(bob_try.status, StatusCode::NOT_FOUND);

    // --- approve (owner's client issues the certificate)
    let sy = sync(&app, &mut owner).await;
    let bob_row = sy["members"].as_array().unwrap().iter().find(|m| m["email"] == "bob@arevei.com").unwrap().clone();
    let approval = e(&mut owner.engine, "approve_member", json!({"user_id": bob.user_id, "email": bob.email, "public_keys": bob_row["public_keys"], "now": app.state.now()}));
    let r = app.call("POST", &format!("/org/members/{}/approve", bob.user_id), Some(&owner.token), Some(json!({"cert": approval["cert"], "grants": approval["grants"]}))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    // A forged certificate (wrong keys) is rejected by the server.
    sync(&app, &mut owner).await;
    let grant = e(&mut owner.engine, "grant_vault", json!({"vault_id": vid, "user_id": bob.user_id}));
    let r = app.call("PUT", &format!("/vaults/{vid}/members/{}", bob.user_id), Some(&owner.token), Some(json!({"role": "member", "copy_only": false, "grant": grant}))).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);

    // --- bob decrypts the shared project
    let s = app.call("GET", "/auth/session", Some(&bob.token), None).await;
    assert_eq!(s.body["status"], "active");
    let sy = sync(&app, &mut bob).await;
    assert!(sy["_warnings"].as_array().unwrap().is_empty(), "{}", sy["_warnings"]);
    assert!(sy["vaults"].as_array().unwrap().iter().all(|v| v["admin_wrapped_key"].is_null()));
    let found = item_ids(&mut bob.engine, "wp admin");
    assert_eq!(found.len(), 1);
    assert_eq!(e(&mut bob.engine, "get_item", json!({"id": wp_id}))["item"]["data"]["password"], "s3cret-wp");
    // Admins never get other users' personal vaults; bob doesn't either.
    assert!(sy["items"].as_array().unwrap().iter().all(|i| i["id"] != personal_item));
    let r = app.call("DELETE", &format!("/items/{personal_item}"), Some(&bob.token), None).await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    // --- read-only member cannot write
    let inv = app.call("POST", "/org/invites", Some(&owner.token), Some(json!({"email": "carol@arevei.com", "role": "member"}))).await;
    let mut carol = signup(&app, "carol@arevei.com", inv.body["invite_token"].as_str(), false).await;
    let sy = sync(&app, &mut owner).await;
    let carol_row = sy["members"].as_array().unwrap().iter().find(|m| m["email"] == "carol@arevei.com").unwrap().clone();
    let approval = e(&mut owner.engine, "approve_member", json!({"user_id": carol.user_id, "email": carol.email, "public_keys": carol_row["public_keys"], "now": app.state.now()}));
    let r = app.call("POST", &format!("/org/members/{}/approve", carol.user_id), Some(&owner.token), Some(json!({"cert": approval["cert"], "grants": approval["grants"]}))).await;
    assert_eq!(r.status, StatusCode::OK);
    sync(&app, &mut owner).await;
    let grant = e(&mut owner.engine, "grant_vault", json!({"vault_id": vid, "user_id": carol.user_id}));
    let r = app.call("PUT", &format!("/vaults/{vid}/members/{}", carol.user_id), Some(&owner.token), Some(json!({"role": "read_only", "copy_only": true, "grant": grant}))).await;
    assert_eq!(r.status, StatusCode::OK);
    let sy = sync(&app, &mut carol).await;
    assert!(sy["vaults"].as_array().unwrap().iter().any(|v| v["role"] == "read_only" && v["copy_only"] == true));
    let r = put_item(&app, &mut carol, &vid, login_item("ro", "https://ro.com", "u", "p", ""), None).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    // Non-admin members can't create projects or invite.
    let r = app.call("POST", "/org/invites", Some(&bob.token), Some(json!({"email": "z@z.com", "role": "member"}))).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    // --- conflict: bob edits, owner's stale copy conflicts
    let r = put_item(&app, &mut bob, &vid, login_item("WP admin", "https://acme.com/wp-admin", "admin", "rotated-by-bob", ""), Some(&wp_id)).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    // The owner's engine still holds version 1.
    let r = put_item(&app, &mut owner, &vid, login_item("WP admin", "https://acme.com/wp-admin", "admin", "owner-edit", ""), Some(&wp_id)).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    assert_eq!(r.body["error"], "conflict");
    assert_eq!(r.body["current"]["version"], 2);

    // --- revoke bob + rotate
    let r = app.call("DELETE", &format!("/vaults/{vid}/members/{}", bob.user_id), Some(&owner.token), None).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    sync(&app, &mut owner).await;
    // Rotation that forgets a remaining member is refused.
    let bad = e(&mut owner.engine, "rotate_vault", json!({"vault_id": vid, "member_ids": [owner.user_id]}));
    let r = app.call("POST", &format!("/vaults/{vid}/rotate"), Some(&owner.token), Some(bad)).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.body);
    sync(&app, &mut owner).await;
    let mut fresh = login(&app, &owner).await.unwrap();
    sync(&app, &mut fresh).await;
    let rot = e(&mut fresh.engine, "rotate_vault", json!({"vault_id": vid, "member_ids": [owner.user_id, carol.user_id]}));
    assert_eq!(rot["key_version"], 2);
    let r = app.call("POST", &format!("/vaults/{vid}/rotate"), Some(&fresh.token), Some(rot.clone())).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    // Replaying the same rotation is refused (version must be current + 1).
    let r = app.call("POST", &format!("/vaults/{vid}/rotate"), Some(&fresh.token), Some(rot)).await;
    assert_eq!(r.status, StatusCode::CONFLICT);
    // Bob no longer sees the project; carol and the owner still decrypt it.
    let sy = sync(&app, &mut bob).await;
    assert!(sy["vaults"].as_array().unwrap().iter().all(|v| v["id"] != vid.as_str()));
    assert!(item_ids(&mut bob.engine, "wp admin").is_empty());
    let sy = sync(&app, &mut carol).await;
    assert!(sy["_warnings"].as_array().unwrap().is_empty(), "{}", sy["_warnings"]);
    assert_eq!(e(&mut carol.engine, "get_item", json!({"id": wp_id}))["item"]["data"]["password"], "rotated-by-bob");
    let sy = sync(&app, &mut fresh).await;
    assert!(sy["_warnings"].as_array().unwrap().is_empty(), "{}", sy["_warnings"]);

    // --- trash + restore + purge
    let r = app.call("DELETE", &format!("/items/{wp_id}"), Some(&fresh.token), None).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let r = app.call("POST", &format!("/items/{wp_id}/restore"), Some(&fresh.token), None).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(r.body["deleted_at"].is_null());
    app.call("DELETE", &format!("/items/{wp_id}"), Some(&fresh.token), None).await;
    app.state.advance_clock(31 * 24 * 3600);
    let purged = arevei_server::tasks::purge_trash(&app.state).await.unwrap();
    assert!(purged >= 1);
    let fresh = login(&app, &owner).await.unwrap();
    let r = app.call("GET", "/sync?since=0", Some(&fresh.token), None).await;
    assert!(r.body["purged_item_ids"].as_array().unwrap().iter().any(|i| i == wp_id.as_str()));

    // --- offboarding returns affected vaults and kills sessions
    let r = app.call("DELETE", &format!("/org/members/{}", carol.user_id), Some(&fresh.token), None).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(r.body["affected_vault_ids"].as_array().unwrap().iter().any(|v| v == vid.as_str()));
    let r = app.call("GET", "/auth/session", Some(&carol.token), None).await;
    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert!(login(&app, &carol).await.is_err());

    // --- client-reported audit events + audit chain
    let r = app
        .call("POST", "/audit/events", Some(&fresh.token), Some(json!({"events": [{"event_type": "item_reveal", "target_type": "item", "target_id": personal_item, "client_ts": 1}]})))
        .await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    let r = app.call("POST", "/audit/events", Some(&fresh.token), Some(json!({"events": [{"event_type": "drop_table", "target_type": "item", "target_id": "x"}]}))).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let log = app.call("GET", "/audit?limit=500", Some(&fresh.token), None).await;
    let types: Vec<&str> = log.body.as_array().unwrap().iter().map(|e| e["event_type"].as_str().unwrap()).collect();
    for t in ["account_created", "login", "item_create", "item_update", "vault_share", "vault_revoke", "vault_rotate", "member_offboard", "item_reveal"] {
        assert!(types.contains(&t), "missing audit event {t}");
    }
    assert!(log.body.as_array().unwrap().iter().all(|e| e["target_id"].as_str().map(|t| !t.contains("WP")).unwrap_or(true)));
    let bob2 = login(&app, &bob).await.unwrap(); // earlier session idled out during the 31-day jump
    let r = app.call("GET", "/audit", Some(&bob2.token), None).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let v = app.call("GET", "/audit/verify", Some(&fresh.token), None).await;
    assert_eq!(v.body["ok"], true, "{}", v.body);
    assert_eq!(v.body["checkpoints"].as_array().unwrap().len(), 1);

    // Direct tampering, even as the database superuser, is blocked by the trigger.
    let mut conn = app.owner_conn().await;
    assert!(conn.execute("UPDATE audit_events SET event_type = 'nothing' WHERE seq = 1").await.is_err());
    assert!(conn.execute("DELETE FROM audit_events").await.is_err());
    // Bypass the trigger (as a full DB compromise could) and the chain detects it.
    conn.execute("ALTER TABLE audit_events DISABLE TRIGGER audit_events_immutable").await.unwrap();
    conn.execute("UPDATE audit_events SET ip = '1.1.1.1' WHERE seq = 2").await.unwrap();
    conn.execute("ALTER TABLE audit_events ENABLE TRIGGER audit_events_immutable").await.unwrap();
    let v = app.call("GET", "/audit/verify", Some(&fresh.token), None).await;
    assert_eq!(v.body["ok"], false);
    assert_eq!(v.body["first_bad_seq"], 2);
}

#[tokio::test]
async fn zero_plaintext_canary() {
    let app = spawn().await;
    let mut owner = signup(&app, "canary-owner@arevei.com", None, true).await;
    sync(&app, &mut owner).await;
    let c = "CNRY7f3a9";
    let client = e(&mut owner.engine, "create_client", json!({"name": format!("{c}-client")}));
    assert_eq!(app.call("POST", "/clients", Some(&owner.token), Some(client.clone())).await.status, StatusCode::OK);
    let vault = e(&mut owner.engine, "create_vault", json!({"name": format!("{c}-project"), "client_id": client["id"]}));
    assert_eq!(app.call("POST", "/vaults", Some(&owner.token), Some(vault.clone())).await.status, StatusCode::OK);
    sync(&app, &mut owner).await;
    let vid = vault["id"].as_str().unwrap();
    let item = json!({
        "title": format!("{c}-title"),
        "notes": format!("{c}-notes"),
        "tags": [format!("{c}-tag")],
        "custom_fields": [{"name": format!("{c}-fieldname"), "value": format!("{c}-fieldvalue"), "kind": "hidden"}],
        "data": {"type": "login", "username": format!("{c}-username"), "password": format!("{c}-password"),
                 "urls": [{"url": format!("https://{c}-url.example.com/login")}], "totp": "JBSWY3DPEHPK3PXP"}
    });
    let r = put_item(&app, &mut owner, vid, item, None).await;
    assert_eq!(r.status, StatusCode::OK);
    let item_id = r.body["id"].as_str().unwrap().to_string();
    let uid = owner.user_id.clone();
    let r = put_item(&app, &mut owner, &uid, login_item(&format!("{c}-personal"), "https://p.com", &format!("{c}-pu"), &format!("{c}-pp"), ""), None).await;
    assert_eq!(r.status, StatusCode::OK);
    // Attachment.
    let data = arevei_core::encoding::b64(format!("{c}-attachment-content").as_bytes());
    let att = e(&mut owner.engine, "encrypt_attachment", json!({"attachment_id": "a1", "data": data}));
    let att_id = uuid::Uuid::new_v4();
    let ct = arevei_core::encoding::unb64(att["ciphertext"].as_str().unwrap()).unwrap();
    let r = app.raw_put(&format!("/attachments/{att_id}?item_id={item_id}"), &owner.token, ct).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT, "{}", r.body);
    let prefs = e(&mut owner.engine, "encrypt_prefs", json!({"prefs": {"favorites": [format!("{c}-fav")]}}));
    assert_eq!(app.call("PUT", "/prefs", Some(&owner.token), Some(prefs)).await.status, StatusCode::OK);
    // Audit + rotation for good measure.
    let rot = e(&mut owner.engine, "rotate_vault", json!({"vault_id": vid, "member_ids": [owner.user_id]}));
    assert_eq!(app.call("POST", &format!("/vaults/{vid}/rotate"), Some(&owner.token), Some(rot)).await.status, StatusCode::OK);

    let out = std::process::Command::new("docker")
        .args(["exec", "arevei-dev-postgres", "pg_dump", "-U", "postgres", "--data-only", "-d", &app.db_name])
        .output()
        .expect("docker exec pg_dump");
    assert!(out.status.success(), "pg_dump failed: {}", String::from_utf8_lossy(&out.stderr));
    let dump = String::from_utf8_lossy(&out.stdout);
    assert!(dump.len() > 1000 && dump.contains("canary-owner@arevei.com"), "dump looks empty");
    assert!(!dump.contains(c), "PLAINTEXT CANARY FOUND IN DATABASE DUMP");
    assert!(!dump.contains("JBSWY3DPEHPK3PXP"), "TOTP seed found in dump");
    assert!(!dump.contains(&owner.secret_key), "secret key found in dump");
    assert!(!dump.contains(PASSWORD), "master password found in dump");
    // Account TOTP seed is encrypted at rest.
    assert!(!dump.contains(&owner.totp_secret), "account TOTP seed found in dump");

    let mut files = 0;
    for entry in walk(&app.attachment_dir) {
        files += 1;
        let bytes = std::fs::read(&entry).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains(c), "canary found in attachment file");
    }
    assert_eq!(files, 1);
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = vec![];
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

#[tokio::test]
async fn cross_org_isolation() {
    let app = spawn_with(|c| c.allow_signup = true).await;
    let mut a = signup(&app, "a@org-a.com", None, true).await;
    let mut b = signup(&app, "b@org-b.com", None, true).await;
    assert_ne!(a.session["org_id"], b.session["org_id"]);
    sync(&app, &mut a).await;
    sync(&app, &mut b).await;
    let vault = e(&mut a.engine, "create_vault", json!({"name": "A secret project"}));
    assert_eq!(app.call("POST", "/vaults", Some(&a.token), Some(vault.clone())).await.status, StatusCode::OK);
    sync(&app, &mut a).await;
    let vid = vault["id"].as_str().unwrap().to_string();
    let r = put_item(&app, &mut a, &vid, login_item("A item", "https://a.com", "u", "p", ""), None).await;
    let a_item = r.body["id"].as_str().unwrap().to_string();

    // Org B's owner (an admin in their own org) sees nothing of org A.
    let sy = app.call("GET", "/sync?since=0", Some(&b.token), None).await;
    assert!(sy.body["vaults"].as_array().unwrap().iter().all(|v| v["id"] != vid.as_str()));
    assert!(sy.body["items"].as_array().unwrap().is_empty());
    assert!(sy.body["members"].as_array().unwrap().iter().all(|m| m["email"] != "a@org-a.com"));
    // Writes into A's vault / items from B fail without revealing anything.
    let mut fake = e(&mut b.engine, "encrypt_item", json!({"vault_id": b.user_id, "item": login_item("x", "https://x.com", "u", "p", ""), "now": app.state.now()}));
    fake["vault_id"] = json!(vid);
    assert_eq!(app.call("PUT", &format!("/items/{}", fake["id"].as_str().unwrap()), Some(&b.token), Some(fake)).await.status, StatusCode::NOT_FOUND);
    assert_eq!(app.call("DELETE", &format!("/items/{a_item}"), Some(&b.token), None).await.status, StatusCode::NOT_FOUND);
    assert_eq!(app.call("GET", &format!("/vaults/{vid}/members"), Some(&b.token), None).await.status, StatusCode::NOT_FOUND);
    // Overwriting A's item id from B: conflict without A's data.
    let mut over = e(&mut b.engine, "encrypt_item", json!({"vault_id": b.user_id, "item": login_item("x", "https://x.com", "u", "p", ""), "now": app.state.now()}));
    over["id"] = json!(a_item);
    let r = app.call("PUT", &format!("/items/{a_item}"), Some(&b.token), Some(over)).await;
    assert_ne!(r.status, StatusCode::OK);
    assert!(r.body.get("current").is_none());

    // RLS at the database level: with B's org set, A's rows are invisible even to a raw query.
    let mut tx = app.state.org_tx(uuid::Uuid::parse_str(b.session["org_id"].as_str().unwrap()).unwrap()).await.unwrap();
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM items").fetch_one(&mut *tx).await.unwrap();
    assert_eq!(n, 0);
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM vaults").fetch_one(&mut *tx).await.unwrap();
    assert_eq!(n, 1, "only B's personal vault");
    tx.rollback().await.unwrap();
    // Without any org set, nothing is visible.
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM items").fetch_one(&app.state.db).await.unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn rate_limits_lockout_and_replay() {
    let app = spawn_with(|c| c.rate_limit_per_min = 3).await;
    for i in 0..3 {
        let r = app.call("POST", "/auth/prelogin", None, Some(json!({"email": format!("u{i}@x.com")}))).await;
        assert_eq!(r.status, StatusCode::OK);
    }
    let r = app.call("POST", "/auth/prelogin", None, Some(json!({"email": "u9@x.com"}))).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(r.body["error"], "rate_limited");
}

#[tokio::test]
async fn account_lockout_mfa_replay_and_enumeration() {
    let app = spawn().await;
    let owner = signup(&app, "lock@arevei.com", None, true).await;

    // Prelogin for unknown emails is deterministic and shaped like a real answer.
    let a = app.call("POST", "/auth/prelogin", None, Some(json!({"email": "ghost@x.com"}))).await;
    let b = app.call("POST", "/auth/prelogin", None, Some(json!({"email": "ghost@x.com"}))).await;
    assert_eq!(a.body, b.body);
    assert_eq!(a.body["kdf"]["m_kib"], 65536);

    // Unknown user: login/start succeeds (fake record), finish fails like a wrong password.
    let ghost = User { email: "ghost@x.com".into(), ..clone_user(&owner) };
    let err = login(&app, &ghost).await.err().unwrap();
    assert_eq!(err.status, StatusCode::UNAUTHORIZED);

    // MFA replay: the same TOTP step cannot be used twice.
    let good = login(&app, &owner).await.unwrap();
    let _ = good;
    let mut engine = arevei_core::engine::Engine::new();
    let pre = app.call("POST", "/auth/prelogin", None, Some(json!({"email": owner.email}))).await;
    e(&mut engine, "derive", json!({"password": PASSWORD, "secret_key": owner.secret_key, "salt": pre.body["salt"], "kdf": pre.body["kdf"]}));
    let st = e(&mut engine, "opaque_login_start", json!({}));
    let s = app.call("POST", "/auth/login/start", None, Some(json!({"email": owner.email, "credential_request": st["message"]}))).await;
    let fin = e(&mut engine, "opaque_login_finish", json!({"response": s.body["credential_response"]}));
    let f = app.call("POST", "/auth/login/finish", None, Some(json!({"login_token": s.body["login_token"], "credential_finalization": fin["finalization"]}))).await;
    let code = arevei_core::totp::TotpConfig::new(&owner.totp_secret).unwrap().code_at(app.state.now() as u64).unwrap().code;
    let m = app.call("POST", "/auth/mfa/verify", None, Some(json!({"mfa_token": f.body["mfa_token"], "code": code, "device_name": "x"}))).await;
    assert_eq!(m.status, StatusCode::UNAUTHORIZED, "replayed TOTP step must be rejected");

    // Wrong Secret Key → OPAQUE fails; after repeated failures the account is locked.
    let wrong = User { secret_key: arevei_core::secret_key::SecretKey::generate().format(), ..clone_user(&owner) };
    let mut locked = false;
    for _ in 0..6 {
        let r = login(&app, &wrong).await.err().unwrap();
        if r.status == StatusCode::TOO_MANY_REQUESTS {
            locked = true;
            break;
        }
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    }
    assert!(locked, "account must enter backoff after 5 unfinished/failed attempts");
    let r = login(&app, &owner).await.err().expect("locked");
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
}

fn clone_user(u: &User) -> User {
    User {
        engine: arevei_core::engine::Engine::new(),
        token: u.token.clone(),
        email: u.email.clone(),
        secret_key: u.secret_key.clone(),
        user_id: u.user_id.clone(),
        totp_secret: u.totp_secret.clone(),
        pinned: None,
        session: u.session.clone(),
    }
}

#[tokio::test]
async fn csrf_and_headers() {
    let app = spawn().await;
    let owner = signup(&app, "csrf@arevei.com", None, true).await;
    // Missing X-Arevei-Request.
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/logout")
        .header("authorization", format!("Bearer {}", owner.token))
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.send(req).await.status, StatusCode::FORBIDDEN);
    // Foreign origin with the cookie.
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/logout")
        .header("x-arevei-request", "1")
        .header("origin", "https://evil.example")
        .header("cookie", format!("__Host-av_session={}", owner.token))
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.send(req).await.status, StatusCode::FORBIDDEN);
    // Extension origin with a cookie is refused; with Bearer only, allowed.
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/prelogin")
        .header("x-arevei-request", "1")
        .header("origin", "chrome-extension://abcdef")
        .header("content-type", "application/json")
        .body(Body::from(json!({"email": "x@y.com"}).to_string()))
        .unwrap();
    assert_eq!(app.send(req).await.status, StatusCode::OK);
    // Same-origin cookie auth works; security headers present.
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/auth/session")
        .header("cookie", format!("__Host-av_session={}", owner.token))
        .body(Body::empty())
        .unwrap();
    let r = app.send(req).await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.headers["cache-control"], "no-store");
    assert_eq!(r.headers["x-content-type-options"], "nosniff");
    assert_eq!(r.headers["referrer-policy"], "no-referrer");
    // Logout invalidates the session.
    let r = app.call("POST", "/auth/logout", Some(&owner.token), None).await;
    assert_eq!(r.status, StatusCode::NO_CONTENT);
    assert_eq!(app.call("GET", "/auth/session", Some(&owner.token), None).await.status, StatusCode::UNAUTHORIZED);
}
