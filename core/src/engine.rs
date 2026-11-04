//! Stateful vault engine. The web app's crypto Worker and the extension's service
//! worker each host exactly one `Engine` and talk to it with `call(method, json)`.
//!
//! Keys never cross this boundary. JS receives only what it must render, or the
//! ciphertext it must send to the server. Wire formats are in `docs/api.md`.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::encoding::{b64, unb64, unb64_array, Aad};
use crate::export::ExportEntry;
use crate::generator::{PassphraseOptions, PasswordOptions};
use crate::item::{self, EncryptedItem, Item, ItemData};
use crate::kdf::{self, Derived, KdfParams};
use crate::keys::{random_bytes, SymKey};
use crate::keyset::{EncryptedKeyset, PublicKeys, UnlockedKeyset};
use crate::secret_key::SecretKey;
use crate::share::KeyGrant;
use crate::sign::MembershipCert;
use crate::totp::TotpConfig;
use crate::{envelope, export, generator, import, matching, opaque, qr, security, sign, strength, stream, Error, Result};

fn org_admin_keyring(org_id: &str) -> String {
    format!("org-admin:{org_id}")
}
fn org_dir_keyring(org_id: &str) -> String {
    format!("org-dir:{org_id}")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultRow {
    pub id: String,
    pub kind: String,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub name_enc: Option<String>,
    pub key_version: u32,
    #[serde(default)]
    pub admin_wrapped_key: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub copy_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRow {
    pub id: String,
    pub name_enc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ItemRow {
    pub id: String,
    pub vault_id: String,
    pub version: u64,
    pub key_version: u32,
    pub wrapped_key: String,
    pub payload: String,
    #[serde(default)]
    pub created_at: i64,
    #[serde(default)]
    pub updated_at: i64,
    #[serde(default)]
    pub created_by: Option<String>,
    #[serde(default)]
    pub updated_by: Option<String>,
    #[serde(default)]
    pub deleted_at: Option<i64>,
}

impl ItemRow {
    fn encrypted(&self) -> EncryptedItem {
        EncryptedItem {
            id: self.id.clone(),
            vault_id: self.vault_id.clone(),
            version: self.version,
            key_version: self.key_version,
            wrapped_key: self.wrapped_key.clone(),
            payload: self.payload.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberRow {
    pub user_id: String,
    pub email: String,
    #[serde(default)]
    pub role: String,
    #[serde(default)]
    pub status: String,
    pub public_keys: PublicKeys,
    #[serde(default)]
    pub cert: Option<MembershipCert>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgRow {
    pub id: String,
    pub org_sign_pk: String,
    #[serde(default)]
    pub org_secrets: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SyncPayload {
    pub org: Option<OrgRow>,
    #[serde(default)]
    pub members: Vec<MemberRow>,
    #[serde(default)]
    pub vaults: Vec<VaultRow>,
    #[serde(default)]
    pub clients: Vec<ClientRow>,
    #[serde(default)]
    pub grants: Vec<KeyGrant>,
    #[serde(default)]
    pub items: Vec<ItemRow>,
    #[serde(default)]
    pub purged_item_ids: Vec<String>,
    /// Org signing key pinned on this device at first sight (TOFU). Must match.
    #[serde(default)]
    pub pinned_org_pk: Option<String>,
}

struct VaultState {
    row: VaultRow,
    name: String,
    keys: BTreeMap<u32, SymKey>,
}

struct CachedItem {
    row: ItemRow,
    item: Item,
}

struct OrgState {
    id: String,
    sign_pk: [u8; 32],
    sign_sk: Option<Zeroizing<[u8; 32]>>,
    admin_key: Option<SymKey>,
    dir_key: Option<SymKey>,
}

#[derive(Default)]
pub struct Engine {
    derived: Option<Derived>,
    reg_state: Option<opaque_ke::ClientRegistration<opaque::Suite>>,
    login_state: Option<opaque_ke::ClientLogin<opaque::Suite>>,
    keyset: Option<UnlockedKeyset>,
    org: Option<OrgState>,
    vaults: HashMap<String, VaultState>,
    clients: HashMap<String, String>,
    items: HashMap<String, CachedItem>,
    /// Highest item version ever seen this session (rollback detection).
    high_water: HashMap<String, u64>,
    /// Verified member identities: user_id -> (ed25519, x25519).
    verified_members: HashMap<String, ([u8; 32], [u8; 32])>,
    members: Vec<MemberRow>,
}

use crate::opaque::opaque_ke;

fn arg<T: for<'de> Deserialize<'de>>(args: &Value, key: &str) -> Result<T> {
    serde_json::from_value(args.get(key).cloned().unwrap_or(Value::Null))
        .map_err(|e| Error::Invalid(format!("{key}: {e}")))
}

fn opt_arg<T: for<'de> Deserialize<'de>>(args: &Value, key: &str) -> Result<Option<T>> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => serde_json::from_value(v.clone()).map(Some).map_err(|e| Error::Invalid(format!("{key}: {e}"))),
    }
}

fn vault_meta_aad(vault_id: &str, key_version: u32) -> Vec<u8> {
    Aad::new("vault-meta").str(vault_id).u64(key_version as u64).bytes().to_vec()
}
fn vault_admin_aad(vault_id: &str, key_version: u32) -> Vec<u8> {
    Aad::new("vault-admin-key").str(vault_id).u64(key_version as u64).bytes().to_vec()
}
fn client_name_aad(client_id: &str) -> Vec<u8> {
    Aad::new("client-name").str(client_id).bytes().to_vec()
}
fn org_secrets_aad(org_id: &str) -> Vec<u8> {
    Aad::new("org-secrets").str(org_id).bytes().to_vec()
}
fn prefs_aad(user_id: &str) -> Vec<u8> {
    Aad::new("prefs").str(user_id).bytes().to_vec()
}

impl Engine {
    pub fn new() -> Self {
        Self::default()
    }

    /// JSON dispatcher used by the WASM binding (and by tests).
    pub fn call(&mut self, method: &str, args: Value) -> Result<Value> {
        let a = &args;
        match method {
            // ---- account / auth ----
            "generate_secret_key" => Ok(json!({ "secret_key": SecretKey::generate().format() })),
            "new_account_params" => Ok(json!({ "salt": b64(&random_bytes::<16>()), "kdf": KdfParams::DEFAULT })),
            "validate_secret_key" => Ok(json!({ "valid": SecretKey::parse(&arg::<String>(a, "secret_key")?).is_ok() })),
            "derive" => self.derive(a),
            "opaque_register_start" => self.opaque_register_start(),
            "opaque_register_finish" => self.opaque_register_finish(a),
            "opaque_login_start" => self.opaque_login_start(),
            "opaque_login_finish" => self.opaque_login_finish(a),
            "create_account" => self.create_account(a),
            "unlock" => self.unlock(a),
            "rekey" => self.rekey(a),
            "lock" => {
                *self = Engine::default();
                Ok(json!({}))
            }
            "status" => Ok(json!({
                "unlocked": self.keyset.is_some(),
                "user_id": self.keyset.as_ref().map(|k| k.user_id.clone()),
            })),
            "export_session" => {
                let ks = self.ks()?;
                Ok(json!({ "session": b64(&ks.to_session_bytes()) }))
            }
            "import_session" => {
                let bytes = Zeroizing::new(unb64(&arg::<String>(a, "session")?)?);
                *self = Engine::default();
                self.keyset = Some(UnlockedKeyset::from_session_bytes(&bytes)?);
                self.install_personal_vault();
                Ok(json!({}))
            }
            "my_fingerprint" => {
                let ks = self.ks()?;
                let pk = ks.public_keys();
                Ok(json!({ "fingerprint": sign::fingerprint(&unb64(&pk.ed25519)?), "public_keys": pk }))
            }
            "fingerprint" => Ok(json!({ "fingerprint": sign::fingerprint(&unb64(&arg::<String>(a, "public_key")?)?) })),
            "encrypt_prefs" => {
                let ks = self.ks()?;
                let data = serde_json::to_vec(&arg::<Value>(a, "prefs")?)?;
                Ok(json!({ "blob": b64(&envelope::seal(&ks.ask, &data, &prefs_aad(&ks.user_id))) }))
            }
            "decrypt_prefs" => {
                let ks = self.ks()?;
                let pt = envelope::open(&ks.ask, &unb64(&arg::<String>(a, "blob")?)?, &prefs_aad(&ks.user_id))?;
                Ok(json!({ "prefs": serde_json::from_slice::<Value>(&pt)? }))
            }

            // ---- sync / browse ----
            "sync_apply" => self.sync_apply(serde_json::from_value(args)?),
            "list_vaults" => self.list_vaults(),
            "list_items" => self.list_items(a),
            "get_item" => self.get_item(a),
            "list_tags" => {
                let mut tags: Vec<String> = self.items.values().flat_map(|c| c.item.tags.clone()).collect();
                tags.sort();
                tags.dedup();
                Ok(json!(tags))
            }

            // ---- item writes ----
            "encrypt_item" => self.encrypt_item_req(a),
            "move_item" => self.move_item(a),

            // ---- vault / org administration ----
            "create_vault" => self.create_vault(a),
            "encrypt_vault_name" => self.encrypt_vault_name(a),
            "create_client" => self.encrypt_client_name(a),
            "grant_vault" => self.grant_vault(a),
            "rotate_vault" => self.rotate_vault(a),
            "approve_member" => self.approve_member(a),
            "verify_member" => self.verify_member(a),

            // ---- tools ----
            "totp" => self.totp(a),
            "parse_otpauth" => Ok(serde_json::to_value(TotpConfig::parse(&arg::<String>(a, "uri")?)?)?),
            "decode_qr" => Ok(json!({ "contents": qr::decode(&unb64(&arg::<String>(a, "image")?)?)? })),
            "generate_password" => Ok(serde_json::to_value(generator::generate_password(
                &opt_arg::<PasswordOptions>(a, "options")?.unwrap_or_default(),
            )?)?),
            "generate_passphrase" => Ok(serde_json::to_value(generator::generate_passphrase(
                &opt_arg::<PassphraseOptions>(a, "options")?.unwrap_or_default(),
            )?)?),
            "strength" => {
                let inputs: Vec<String> = opt_arg(a, "inputs")?.unwrap_or_default();
                let refs: Vec<&str> = inputs.iter().map(String::as_str).collect();
                Ok(serde_json::to_value(strength::estimate(&arg::<String>(a, "password")?, &refs))?)
            }
            "tokenize" => Ok(serde_json::to_value(generator::tokenize(&arg::<String>(a, "password")?))?),
            "security_report" => self.security_report(a),
            "parse_url" => Ok(serde_json::to_value(matching::parse(&arg::<String>(a, "url")?))?),

            // ---- autofill (extension) ----
            "match_url" => self.match_url(a),
            "fill_data" => self.fill_data(a),
            "known_domains" => Ok(json!(self.known_domains())),

            // ---- import / export ----
            "import_parse" => Ok(serde_json::to_value(import::import(
                arg(a, "format")?,
                &arg::<String>(a, "text")?,
            )?)?),
            "import_encrypted" => Ok(serde_json::to_value(export::import_encrypted(
                &arg::<String>(a, "file")?,
                &arg::<String>(a, "password")?,
            )?)?),
            "export_encrypted" => {
                let entries = self.export_entries(a)?;
                Ok(json!({ "file": export::export_encrypted(&entries, &arg::<String>(a, "password")?)? }))
            }
            "export_csv" => {
                let entries = self.export_entries(a)?;
                Ok(json!({ "csv": export::export_csv(&entries)? }))
            }

            // ---- attachments ----
            "encrypt_attachment" => {
                let key = SymKey::generate();
                let id: String = arg(a, "attachment_id")?;
                let data = Zeroizing::new(unb64(&arg::<String>(a, "data")?)?);
                Ok(json!({ "file_key": b64(key.as_bytes()), "ciphertext": b64(&stream::encrypt(&key, &id, &data)?) }))
            }
            "decrypt_attachment" => {
                self.ks()?;
                let key = SymKey::from_slice(&unb64(&arg::<String>(a, "file_key")?)?)?;
                let id: String = arg(a, "attachment_id")?;
                Ok(json!({ "data": b64(&stream::decrypt(&key, &id, &unb64(&arg::<String>(a, "ciphertext")?)?)?) }))
            }

            _ => Err(Error::Invalid(format!("unknown method {method}"))),
        }
    }

    fn ks(&self) -> Result<&UnlockedKeyset> {
        self.keyset.as_ref().ok_or(Error::Locked)
    }

    // ------------------------------------------------------------------ auth

    fn derive(&mut self, a: &Value) -> Result<Value> {
        let password: Zeroizing<String> = Zeroizing::new(arg(a, "password")?);
        let sk = SecretKey::parse(&arg::<String>(a, "secret_key")?)?;
        let salt: [u8; 16] = unb64_array(&arg::<String>(a, "salt")?)?;
        let params: KdfParams = arg(a, "kdf")?;
        self.derived = Some(kdf::derive(&password, &sk, &salt, params)?);
        Ok(json!({}))
    }

    fn k_auth(&self) -> Result<Zeroizing<[u8; 32]>> {
        Ok(self.derived.as_ref().ok_or(Error::Invalid("call derive first".into()))?.k_auth.clone())
    }

    fn opaque_register_start(&mut self) -> Result<Value> {
        let r = opaque::registration_start(&*self.k_auth()?)?;
        self.reg_state = Some(r.state);
        Ok(json!({ "message": b64(&r.message) }))
    }

    fn opaque_register_finish(&mut self, a: &Value) -> Result<Value> {
        let state = self.reg_state.take().ok_or(Error::Opaque)?;
        let upload = opaque::registration_finish(state, &*self.k_auth()?, &unb64(&arg::<String>(a, "response")?)?)?;
        Ok(json!({ "upload": b64(&upload) }))
    }

    fn opaque_login_start(&mut self) -> Result<Value> {
        let r = opaque::login_start(&*self.k_auth()?)?;
        self.login_state = Some(r.state);
        Ok(json!({ "message": b64(&r.message) }))
    }

    fn opaque_login_finish(&mut self, a: &Value) -> Result<Value> {
        let state = self.login_state.take().ok_or(Error::Opaque)?;
        let fin = opaque::login_finish(state, &*self.k_auth()?, &unb64(&arg::<String>(a, "response")?)?)?;
        Ok(json!({ "finalization": b64(&fin) }))
    }

    /// Generates the keyset (and, for the founding user, the organization keys).
    /// Leaves the engine unlocked.
    fn create_account(&mut self, a: &Value) -> Result<Value> {
        let user_id: String = arg(a, "user_id")?;
        let email: String = arg(a, "email")?;
        let salt: [u8; 16] = unb64_array(&arg::<String>(a, "salt")?)?;
        let params: KdfParams = arg(a, "kdf")?;
        let auk = self.derived.as_ref().ok_or(Error::Invalid("call derive first".into()))?.auk.clone();
        let ks = UnlockedKeyset::generate(&user_id);
        let enc = ks.encrypt(&auk, params, &salt);
        let public = ks.public_keys();

        let mut bootstrap = Value::Null;
        if let Some(org_id) = opt_arg::<String>(a, "create_org_id")? {
            let (org_sk, org_pk) = sign::generate_signing_key();
            let admin_key = SymKey::generate();
            let dir_key = SymKey::generate();
            let my_x: [u8; 32] = unb64_array(&public.x25519)?;
            let grants = vec![
                KeyGrant::create(&admin_key, &org_admin_keyring(&org_id), 1, &user_id, &my_x, &user_id, &ks.sign_sk)?,
                KeyGrant::create(&dir_key, &org_dir_keyring(&org_id), 1, &user_id, &my_x, &user_id, &ks.sign_sk)?,
            ];
            let cert = MembershipCert::issue(
                &org_id,
                &user_id,
                &email,
                &public.x25519,
                &public.ed25519,
                arg::<i64>(a, "now")?,
                &user_id,
                &org_sk,
            );
            let secrets = envelope::seal(&admin_key, &*org_sk, &org_secrets_aad(&org_id));
            bootstrap = json!({
                "org_id": org_id,
                "org_sign_pk": b64(&org_pk),
                "org_secrets": b64(&secrets),
                "grants": grants,
                "cert": cert,
            });
            self.org = Some(OrgState {
                id: org_id,
                sign_pk: org_pk,
                sign_sk: Some(org_sk),
                admin_key: Some(admin_key),
                dir_key: Some(dir_key),
            });
        }
        self.keyset = Some(ks);
        self.install_personal_vault();
        Ok(json!({ "keyset": enc, "org_bootstrap": bootstrap }))
    }

    fn unlock(&mut self, a: &Value) -> Result<Value> {
        let enc: EncryptedKeyset = arg(a, "keyset")?;
        let auk = self.derived.as_ref().ok_or(Error::Invalid("call derive first".into()))?.auk.clone();
        let ks = enc.decrypt(&auk)?;
        self.derived = None;
        let user_id = ks.user_id.clone();
        self.keyset = Some(ks);
        self.install_personal_vault();
        Ok(json!({ "user_id": user_id }))
    }

    /// Master password / Secret Key change: after `derive` with the new secrets and a
    /// fresh salt, re-wrap the ASK only. Then re-register OPAQUE with the new K_auth.
    fn rekey(&mut self, a: &Value) -> Result<Value> {
        let salt: [u8; 16] = unb64_array(&arg::<String>(a, "salt")?)?;
        let params: KdfParams = arg(a, "kdf")?;
        let auk = self.derived.as_ref().ok_or(Error::Invalid("call derive first".into()))?.auk.clone();
        Ok(json!({ "keyset": self.ks()?.encrypt(&auk, params, &salt) }))
    }

    fn install_personal_vault(&mut self) {
        if let Some(ks) = &self.keyset {
            let mut keys = BTreeMap::new();
            keys.insert(1, ks.personal_vault_key.clone());
            self.vaults.insert(
                ks.user_id.clone(),
                VaultState {
                    row: VaultRow {
                        id: ks.user_id.clone(),
                        kind: "personal".into(),
                        client_id: None,
                        name_enc: None,
                        key_version: 1,
                        admin_wrapped_key: None,
                        role: Some("owner".into()),
                        copy_only: false,
                    },
                    name: "Personal".into(),
                    keys,
                },
            );
        }
    }

    // ------------------------------------------------------------------ sync

    fn sync_apply(&mut self, p: SyncPayload) -> Result<Value> {
        let my_id = self.ks()?.user_id.clone();
        let mut warnings: Vec<String> = Vec::new();

        // 1. Organization: pin check, admin/dir keys from grants, org secrets.
        if let Some(org) = &p.org {
            if let Some(pinned) = &p.pinned_org_pk {
                if pinned != &org.org_sign_pk {
                    return Err(Error::Invalid(
                        "organization signing key changed since this device first saw it — possible server compromise".into(),
                    ));
                }
            }
            let sign_pk: [u8; 32] = unb64_array(&org.org_sign_pk)?;
            let prev = self.org.take();
            let mut st = OrgState { id: org.id.clone(), sign_pk, sign_sk: None, admin_key: None, dir_key: None };
            if let Some(prev) = prev.filter(|p| p.id == org.id && p.sign_pk == sign_pk) {
                st.admin_key = prev.admin_key;
                st.dir_key = prev.dir_key;
                st.sign_sk = prev.sign_sk;
            }
            self.org = Some(st);

            // Verify member certificates against the org key.
            self.verified_members.clear();
            for m in &p.members {
                if let Some(cert) = &m.cert {
                    let ok = cert.verify(&sign_pk).is_ok()
                        && cert.user_id == m.user_id
                        && cert.org_id == org.id
                        && cert.x25519 == m.public_keys.x25519
                        && cert.ed25519 == m.public_keys.ed25519;
                    if ok {
                        self.verified_members.insert(m.user_id.clone(), (cert.ed25519_bytes()?, cert.x25519_bytes()?));
                    } else {
                        warnings.push(format!("member {} has an invalid certificate", m.email));
                    }
                }
            }
            self.members = p.members.clone();
        }

        // 2. Grants addressed to me.
        let mut granted: HashMap<(String, u32), SymKey> = HashMap::new();
        for g in &p.grants {
            if g.recipient_id != my_id {
                continue;
            }
            let ks = self.ks()?;
            let grantor_pk = if g.grantor_id == my_id {
                Some(unb64_array::<32>(&ks.public_keys().ed25519)?)
            } else {
                self.verified_members.get(&g.grantor_id).map(|(ed, _)| *ed)
            };
            let Some(grantor_pk) = grantor_pk else {
                warnings.push(format!("ignored key grant for {} from an unverified member", g.keyring_id));
                continue;
            };
            match g.open(&my_id, &ks.enc_sk, Some(&grantor_pk)) {
                Ok(k) => {
                    granted.insert((g.keyring_id.clone(), g.key_version), k);
                }
                Err(_) => warnings.push(format!("could not open key grant for {}", g.keyring_id)),
            }
        }
        if let Some(org) = self.org.as_mut() {
            if let Some(k) = granted.iter().filter(|((r, _), _)| *r == org_admin_keyring(&org.id)).max_by_key(|((_, v), _)| *v).map(|(_, k)| k.clone()) {
                org.admin_key = Some(k);
            }
            if let Some(k) = granted.iter().filter(|((r, _), _)| *r == org_dir_keyring(&org.id)).max_by_key(|((_, v), _)| *v).map(|(_, k)| k.clone()) {
                org.dir_key = Some(k);
            }
            if let (Some(admin_key), Some(secrets)) = (&org.admin_key, p.org.as_ref().and_then(|o| o.org_secrets.as_ref())) {
                if let Ok(sk) = envelope::open(admin_key, &unb64(secrets)?, &org_secrets_aad(&org.id)) {
                    let sk: [u8; 32] = sk.as_slice().try_into().map_err(|_| Error::Format)?;
                    if sign::verifying_key(&sk) == org.sign_pk {
                        org.sign_sk = Some(Zeroizing::new(sk));
                    } else {
                        warnings.push("organization secrets do not match the organization key".into());
                    }
                }
            }
        }

        // Vault/client lists are authoritative only in a full sync (one that carries `org`).
        // Partial payloads (e.g. `{items}` echoed back after a PUT) must not drop them.
        if p.org.is_some() {
            // 3. Clients (names under the directory key).
            self.clients.clear();
            let dir_key = self.org.as_ref().and_then(|o| o.dir_key.clone());
            for c in &p.clients {
                let name = dir_key
                    .as_ref()
                    .and_then(|k| envelope::open(k, &unb64(&c.name_enc).ok()?, &client_name_aad(&c.id)).ok())
                    .and_then(|pt| String::from_utf8(pt.to_vec()).ok())
                    .unwrap_or_else(|| "(encrypted client)".into());
                self.clients.insert(c.id.clone(), name);
            }

            // 4. Vaults: full list. Drop vaults no longer listed (access revoked).
            let personal = self.vaults.remove(&my_id);
            let mut old = std::mem::take(&mut self.vaults);
            if let Some(pv) = personal {
                self.vaults.insert(my_id.clone(), pv);
            }
            let admin_key = self.org.as_ref().and_then(|o| o.admin_key.clone());
            for v in p.vaults.iter().filter(|v| v.kind != "personal") {
                let mut keys = old.remove(&v.id).map(|s| s.keys).unwrap_or_default();
                for ((rid, ver), k) in &granted {
                    if rid == &v.id {
                        keys.insert(*ver, k.clone());
                    }
                }
                if let (Some(ak), Some(w)) = (&admin_key, &v.admin_wrapped_key) {
                    if let Ok(k) = envelope::open(ak, &unb64(w)?, &vault_admin_aad(&v.id, v.key_version)) {
                        keys.insert(v.key_version, SymKey::from_slice(&k)?);
                    }
                }
                let name = keys
                    .get(&v.key_version)
                    .zip(v.name_enc.as_ref())
                    .and_then(|(k, n)| envelope::open(k, &unb64(n).ok()?, &vault_meta_aad(&v.id, v.key_version)).ok())
                    .and_then(|pt| String::from_utf8(pt.to_vec()).ok())
                    .unwrap_or_else(|| "(locked project)".into());
                if !keys.contains_key(&v.key_version) {
                    warnings.push(format!("no key for project {} (version {})", v.id, v.key_version));
                }
                self.vaults.insert(v.id.clone(), VaultState { row: v.clone(), name, keys });
            }
            if let Some(pv) = p.vaults.iter().find(|v| v.kind == "personal" && v.id == my_id) {
                if let Some(s) = self.vaults.get_mut(&my_id) {
                    s.row.key_version = pv.key_version.max(1);
                }
            }
            // Forget items of vaults we no longer have.
            let vault_ids: Vec<String> = self.vaults.keys().cloned().collect();
            self.items.retain(|_, c| vault_ids.contains(&c.row.vault_id));
        }

        // 5. Items.
        for id in &p.purged_item_ids {
            self.items.remove(id);
        }
        let mut failed = 0usize;
        for row in p.items {
            if let Some(&hw) = self.high_water.get(&row.id) {
                if row.version < hw {
                    warnings.push(format!("server returned an older version of item {} (possible rollback)", row.id));
                    continue;
                }
            }
            let Some(v) = self.vaults.get(&row.vault_id) else { continue };
            let Some(key) = v.keys.get(&row.key_version) else {
                failed += 1;
                continue;
            };
            match item::decrypt_item(&row.encrypted(), key) {
                Ok(it) => {
                    self.high_water.insert(row.id.clone(), row.version);
                    self.items.insert(row.id.clone(), CachedItem { row, item: it });
                }
                Err(_) => failed += 1,
            }
        }
        if failed > 0 {
            warnings.push(format!("{failed} item(s) could not be decrypted and were ignored"));
        }
        Ok(json!({ "warnings": warnings, "item_count": self.items.len() }))
    }

    fn vault_summary(&self, v: &VaultState) -> Value {
        json!({
            "id": v.row.id,
            "kind": v.row.kind,
            "name": v.name,
            "client_id": v.row.client_id,
            "client_name": v.row.client_id.as_ref().and_then(|c| self.clients.get(c)),
            "role": v.row.role,
            "copy_only": v.row.copy_only,
            "key_version": v.row.key_version,
            "unlocked": v.keys.contains_key(&v.row.key_version),
            "item_count": self.items.values().filter(|c| c.row.vault_id == v.row.id && c.row.deleted_at.is_none()).count(),
        })
    }

    fn list_vaults(&self) -> Result<Value> {
        self.ks()?;
        let mut vaults: Vec<&VaultState> = self.vaults.values().collect();
        vaults.sort_by(|a, b| (a.row.kind != "personal", &a.name).cmp(&(b.row.kind != "personal", &b.name)));
        let clients: Vec<Value> = {
            let mut c: Vec<(&String, &String)> = self.clients.iter().collect();
            c.sort_by(|a, b| a.1.to_lowercase().cmp(&b.1.to_lowercase()));
            c.into_iter().map(|(id, name)| json!({ "id": id, "name": name })).collect()
        };
        Ok(json!({
            "vaults": vaults.iter().map(|v| self.vault_summary(v)).collect::<Vec<_>>(),
            "clients": clients,
            "org_admin": self.org.as_ref().map(|o| o.admin_key.is_some()).unwrap_or(false),
        }))
    }

    fn summary(&self, c: &CachedItem) -> Value {
        let it = &c.item;
        let (subtitle, url, has_totp) = match &it.data {
            ItemData::Login { username, urls, totp, .. } => (
                username.clone(),
                urls.first().map(|u| u.url.clone()),
                totp.as_deref().is_some_and(|t| !t.is_empty()),
            ),
            ItemData::Authenticator { issuer, account, .. } => (format!("{issuer} {account}").trim().to_string(), None, true),
            ItemData::Server { host, username, .. } => (format!("{username}@{host}"), None, false),
            ItemData::ApiKey { service, environment, .. } => (format!("{service} {environment}").trim().to_string(), None, false),
            ItemData::RecoveryCodes { service, codes } => {
                (format!("{service} · {} of {} unused", codes.iter().filter(|c| !c.used).count(), codes.len()), None, false)
            }
            ItemData::SshKey { fingerprint, .. } => (fingerprint.clone(), None, false),
            _ => (String::new(), None, false),
        };
        json!({
            "id": c.row.id,
            "vault_id": c.row.vault_id,
            "type": it.data.type_name(),
            "title": it.title,
            "subtitle": subtitle,
            "url": url,
            "host": url.as_deref().and_then(matching::parse).map(|p| p.host),
            "tags": it.tags,
            "has_totp": has_totp,
            "updated_at": c.row.updated_at,
            "deleted_at": c.row.deleted_at,
            "expires_at": it.expires_at,
        })
    }

    fn list_items(&self, a: &Value) -> Result<Value> {
        self.ks()?;
        let vault_id: Option<String> = opt_arg(a, "vault_id")?;
        let client_id: Option<String> = opt_arg(a, "client_id")?;
        let query: String = opt_arg::<String>(a, "query")?.unwrap_or_default().to_lowercase();
        let kind: Option<String> = opt_arg(a, "type")?;
        let tag: Option<String> = opt_arg(a, "tag")?;
        let ids: Option<Vec<String>> = opt_arg(a, "ids")?;
        let trash = opt_arg::<bool>(a, "trash")?.unwrap_or(false);
        let terms: Vec<&str> = query.split_whitespace().collect();

        let mut scored: Vec<(i32, &CachedItem)> = self
            .items
            .values()
            .filter(|c| c.row.deleted_at.is_some() == trash)
            .filter(|c| vault_id.as_ref().is_none_or(|v| &c.row.vault_id == v))
            .filter(|c| {
                client_id.as_ref().is_none_or(|cid| {
                    self.vaults.get(&c.row.vault_id).and_then(|v| v.row.client_id.as_ref()) == Some(cid)
                })
            })
            .filter(|c| kind.as_ref().is_none_or(|k| c.item.data.type_name() == k))
            .filter(|c| tag.as_ref().is_none_or(|t| c.item.tags.contains(t)))
            .filter(|c| ids.as_ref().is_none_or(|ids| ids.contains(&c.row.id)))
            .filter_map(|c| {
                if terms.is_empty() {
                    return Some((0, c));
                }
                let title = c.item.title.to_lowercase();
                let vault = self.vaults.get(&c.row.vault_id);
                let haystack = format!(
                    "{} {} {} {} {} {}",
                    title,
                    c.item.data.username().unwrap_or("").to_lowercase(),
                    match &c.item.data {
                        ItemData::Login { urls, .. } => urls.iter().map(|u| u.url.to_lowercase()).collect::<Vec<_>>().join(" "),
                        ItemData::Server { host, .. } => host.to_lowercase(),
                        ItemData::ApiKey { service, .. } | ItemData::RecoveryCodes { service, .. } => service.to_lowercase(),
                        ItemData::Authenticator { issuer, .. } => issuer.to_lowercase(),
                        _ => String::new(),
                    },
                    c.item.tags.join(" ").to_lowercase(),
                    vault.map(|v| v.name.to_lowercase()).unwrap_or_default(),
                    vault
                        .and_then(|v| v.row.client_id.as_ref())
                        .and_then(|cid| self.clients.get(cid))
                        .map(|n| n.to_lowercase())
                        .unwrap_or_default(),
                );
                if !terms.iter().all(|t| haystack.contains(t)) {
                    return None;
                }
                let mut score = 1;
                if title.starts_with(terms[0]) {
                    score += 10;
                } else if title.contains(terms[0]) {
                    score += 5;
                }
                Some((score, c))
            })
            .collect();
        scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.item.title.to_lowercase().cmp(&b.1.item.title.to_lowercase())));
        Ok(json!(scored.into_iter().map(|(_, c)| self.summary(c)).collect::<Vec<_>>()))
    }

    fn cached(&self, id: &str) -> Result<&CachedItem> {
        self.ks()?;
        self.items.get(id).ok_or_else(|| Error::NotFound(format!("item {id}")))
    }

    fn get_item(&self, a: &Value) -> Result<Value> {
        let c = self.cached(&arg::<String>(a, "id")?)?;
        let vault = self.vaults.get(&c.row.vault_id);
        let creator = |id: &Option<String>| {
            id.as_ref().and_then(|u| self.members.iter().find(|m| &m.user_id == u)).map(|m| m.email.clone())
        };
        Ok(json!({
            "id": c.row.id,
            "vault_id": c.row.vault_id,
            "version": c.row.version,
            "item": c.item,
            "copy_only": vault.map(|v| v.row.copy_only).unwrap_or(false),
            "role": vault.and_then(|v| v.row.role.clone()),
            "created_at": c.row.created_at,
            "updated_at": c.row.updated_at,
            "created_by": creator(&c.row.created_by),
            "updated_by": creator(&c.row.updated_by),
            "deleted_at": c.row.deleted_at,
        }))
    }

    // ------------------------------------------------------------------ writes

    fn vault_current_key(&self, vault_id: &str) -> Result<(SymKey, u32)> {
        let v = self.vaults.get(vault_id).ok_or_else(|| Error::NotFound(format!("vault {vault_id}")))?;
        let k = v.keys.get(&v.row.key_version).ok_or(Error::Locked)?;
        Ok((k.clone(), v.row.key_version))
    }

    /// Returns the PUT /items body. The cache updates only once the server confirms
    /// (the client feeds the returned row back through `sync_apply`).
    fn encrypt_item_req(&self, a: &Value) -> Result<Value> {
        self.ks()?;
        let vault_id: String = arg(a, "vault_id")?;
        let new_item: Item = arg(a, "item")?;
        let now: i64 = arg(a, "now")?;
        validate_item(&new_item)?;
        let existing_id: Option<String> = opt_arg(a, "item_id")?;
        let (item_id, version, expected, item) = match existing_id.and_then(|id| self.items.get(&id).map(|c| (id, c))) {
            Some((id, c)) => (id, c.row.version + 1, Some(c.row.version), Item::apply_update(&c.item, new_item, now)),
            None => (opt_arg::<String>(a, "new_id")?.unwrap_or_else(|| uuid::Uuid::new_v4().to_string()), 1, None, new_item),
        };
        let (key, kv) = self.vault_current_key(&vault_id)?;
        let enc = item::encrypt_item(&item, &key, &vault_id, &item_id, version, kv)?;
        Ok(json!({
            "id": enc.id,
            "vault_id": enc.vault_id,
            "version": enc.version,
            "key_version": enc.key_version,
            "wrapped_key": enc.wrapped_key,
            "payload": enc.payload,
            "expected_version": expected,
        }))
    }

    fn move_item(&self, a: &Value) -> Result<Value> {
        let c = self.cached(&arg::<String>(a, "id")?)?;
        let to: String = arg(a, "to_vault_id")?;
        let (key, kv) = self.vault_current_key(&to)?;
        let enc = item::encrypt_item(&c.item, &key, &to, &c.row.id, c.row.version + 1, kv)?;
        Ok(json!({
            "id": enc.id, "vault_id": enc.vault_id, "version": enc.version, "key_version": enc.key_version,
            "wrapped_key": enc.wrapped_key, "payload": enc.payload, "expected_version": c.row.version,
        }))
    }

    // ------------------------------------------------------------------ vaults & org

    fn org(&self) -> Result<&OrgState> {
        self.org.as_ref().ok_or(Error::Invalid("organization not loaded".into()))
    }

    fn create_vault(&mut self, a: &Value) -> Result<Value> {
        let ks = self.ks()?;
        let vault_id: String = opt_arg(a, "vault_id")?.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let name: String = arg(a, "name")?;
        let client_id: Option<String> = opt_arg(a, "client_id")?;
        let org = self.org()?;
        let admin_key = org.admin_key.as_ref().ok_or(Error::Invalid("only administrators can create projects".into()))?;
        let key = SymKey::generate();
        let my_x: [u8; 32] = unb64_array(&ks.public_keys().x25519)?;
        let grant = KeyGrant::create(&key, &vault_id, 1, &ks.user_id, &my_x, &ks.user_id, &ks.sign_sk)?;
        let req = json!({
            "id": vault_id,
            "client_id": client_id,
            "name_enc": b64(&envelope::seal(&key, name.as_bytes(), &vault_meta_aad(&vault_id, 1))),
            "key_version": 1,
            "admin_wrapped_key": b64(&envelope::seal(admin_key, key.as_bytes(), &vault_admin_aad(&vault_id, 1))),
            "grants": [grant],
        });
        let mut keys = BTreeMap::new();
        keys.insert(1, key);
        self.vaults.insert(
            vault_id.clone(),
            VaultState {
                row: VaultRow {
                    id: vault_id,
                    kind: "project".into(),
                    client_id,
                    name_enc: None,
                    key_version: 1,
                    admin_wrapped_key: None,
                    role: Some("manager".into()),
                    copy_only: false,
                },
                name,
                keys,
            },
        );
        Ok(req)
    }

    fn encrypt_vault_name(&self, a: &Value) -> Result<Value> {
        let vault_id: String = arg(a, "vault_id")?;
        let (key, kv) = self.vault_current_key(&vault_id)?;
        let name: String = arg(a, "name")?;
        Ok(json!({ "name_enc": b64(&envelope::seal(&key, name.as_bytes(), &vault_meta_aad(&vault_id, kv))) }))
    }

    fn encrypt_client_name(&self, a: &Value) -> Result<Value> {
        self.ks()?;
        let client_id: String = opt_arg(a, "client_id")?.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let name: String = arg(a, "name")?;
        let dir = self.org()?.dir_key.as_ref().ok_or(Error::Locked)?;
        Ok(json!({ "id": client_id, "name_enc": b64(&envelope::seal(dir, name.as_bytes(), &client_name_aad(&client_id))) }))
    }

    /// Recipient public key comes only from a certificate verified against the org key.
    fn verified_x25519(&self, user_id: &str) -> Result<[u8; 32]> {
        self.verified_members
            .get(user_id)
            .map(|(_, x)| *x)
            .ok_or_else(|| Error::Invalid(format!("member {user_id} has no verified certificate; approve them first")))
    }

    fn grant_vault(&self, a: &Value) -> Result<Value> {
        let ks = self.ks()?;
        let vault_id: String = arg(a, "vault_id")?;
        let user_id: String = arg(a, "user_id")?;
        let (key, kv) = self.vault_current_key(&vault_id)?;
        let x = self.verified_x25519(&user_id)?;
        Ok(serde_json::to_value(KeyGrant::create(&key, &vault_id, kv, &user_id, &x, &ks.user_id, &ks.sign_sk)?)?)
    }

    /// Key rotation after revocation: new vault key, re-wrap every item key, re-grant.
    fn rotate_vault(&mut self, a: &Value) -> Result<Value> {
        let ks = self.ks()?;
        let vault_id: String = arg(a, "vault_id")?;
        let member_ids: Vec<String> = arg(a, "member_ids")?;
        let v = self.vaults.get(&vault_id).ok_or_else(|| Error::NotFound(format!("vault {vault_id}")))?;
        let new_version = v.row.key_version + 1;
        let new_key = SymKey::generate();
        let admin_key = self.org()?.admin_key.clone().ok_or(Error::Invalid("administrator key required".into()))?;

        let mut grants = Vec::new();
        for uid in &member_ids {
            let x = if uid == &ks.user_id { unb64_array(&ks.public_keys().x25519)? } else { self.verified_x25519(uid)? };
            grants.push(KeyGrant::create(&new_key, &vault_id, new_version, uid, &x, &ks.user_id, &ks.sign_sk)?);
        }
        let mut items = Vec::new();
        for c in self.items.values().filter(|c| c.row.vault_id == vault_id) {
            let old_key = v.keys.get(&c.row.key_version).ok_or(Error::Locked)?;
            let r = item::rewrap_item_key(&c.row.encrypted(), old_key, &new_key, new_version)?;
            items.push(json!({ "id": r.id, "version": r.version, "key_version": r.key_version, "wrapped_key": r.wrapped_key }));
        }
        let req = json!({
            "key_version": new_version,
            "name_enc": b64(&envelope::seal(&new_key, v.name.as_bytes(), &vault_meta_aad(&vault_id, new_version))),
            "admin_wrapped_key": b64(&envelope::seal(&admin_key, new_key.as_bytes(), &vault_admin_aad(&vault_id, new_version))),
            "grants": grants,
            "items": items,
        });
        if let Some(v) = self.vaults.get_mut(&vault_id) {
            v.keys.insert(new_version, new_key);
        }
        Ok(req)
    }

    /// Admin approves a pending member: issue a certificate (after the admin has
    /// compared fingerprints out of band) and grant the directory (+admin) key.
    fn approve_member(&self, a: &Value) -> Result<Value> {
        let ks = self.ks()?;
        let org = self.org()?;
        let sign_sk = org.sign_sk.as_ref().ok_or(Error::Invalid("organization signing key unavailable".into()))?;
        let user_id: String = arg(a, "user_id")?;
        let email: String = arg(a, "email")?;
        let public_keys: PublicKeys = arg(a, "public_keys")?;
        let make_admin = opt_arg::<bool>(a, "admin")?.unwrap_or(false);
        let cert = MembershipCert::issue(
            &org.id,
            &user_id,
            &email,
            &public_keys.x25519,
            &public_keys.ed25519,
            arg(a, "now")?,
            &ks.user_id,
            sign_sk,
        );
        let x: [u8; 32] = unb64_array(&public_keys.x25519)?;
        let mut grants = Vec::new();
        if let Some(dir) = &org.dir_key {
            grants.push(KeyGrant::create(dir, &org_dir_keyring(&org.id), 1, &user_id, &x, &ks.user_id, &ks.sign_sk)?);
        }
        if make_admin {
            let ak = org.admin_key.as_ref().ok_or(Error::Locked)?;
            grants.push(KeyGrant::create(ak, &org_admin_keyring(&org.id), 1, &user_id, &x, &ks.user_id, &ks.sign_sk)?);
        }
        Ok(json!({ "cert": cert, "grants": grants, "fingerprint": sign::fingerprint(&unb64(&public_keys.ed25519)?) }))
    }

    fn verify_member(&self, a: &Value) -> Result<Value> {
        let user_id: String = arg(a, "user_id")?;
        let m = self.members.iter().find(|m| m.user_id == user_id);
        Ok(json!({
            "verified": self.verified_members.contains_key(&user_id),
            "fingerprint": m.map(|m| unb64(&m.public_keys.ed25519).map(|b| sign::fingerprint(&b))).transpose()?,
        }))
    }

    // ------------------------------------------------------------------ tools

    fn totp(&self, a: &Value) -> Result<Value> {
        let now: u64 = arg(a, "now")?;
        let cfg = if let Some(id) = opt_arg::<String>(a, "item_id")? {
            let c = self.cached(&id)?;
            match &c.item.data {
                ItemData::Login { totp: Some(t), .. } if !t.is_empty() => TotpConfig::parse(t)?,
                ItemData::Authenticator { secret, algorithm, digits, period, issuer, account } => TotpConfig {
                    issuer: issuer.clone(),
                    account: account.clone(),
                    secret: secret.clone(),
                    algorithm: crate::totp::Algorithm::parse(algorithm)?,
                    digits: *digits,
                    period: *period,
                },
                _ => return Err(Error::NotFound("item has no TOTP".into())),
            }
        } else {
            TotpConfig::parse(&arg::<String>(a, "secret")?)?
        };
        Ok(serde_json::to_value(cfg.code_at(now)?)?)
    }

    fn security_report(&self, a: &Value) -> Result<Value> {
        self.ks()?;
        let now: i64 = arg(a, "now")?;
        let inputs: Vec<security::ReportInput> = self
            .items
            .values()
            .filter(|c| c.row.deleted_at.is_none())
            .map(|c| security::ReportInput { id: &c.row.id, item: &c.item, updated_at: c.row.updated_at })
            .collect();
        Ok(serde_json::to_value(security::report(&inputs, now))?)
    }

    fn known_domains(&self) -> Vec<String> {
        let mut d: Vec<String> = self
            .items
            .values()
            .filter(|c| c.row.deleted_at.is_none())
            .flat_map(|c| match &c.item.data {
                ItemData::Login { urls, .. } => urls.iter().filter_map(|u| matching::parse(&u.url)?.registrable_domain).collect(),
                _ => vec![],
            })
            .collect();
        d.sort();
        d.dedup();
        d
    }

    /// Autofill candidates for a page. `url` must come from the browser
    /// (`MessageSender.url`), never from a content script.
    fn match_url(&self, a: &Value) -> Result<Value> {
        self.ks()?;
        let url: String = arg(a, "url")?;
        let top_url: Option<String> = opt_arg(a, "top_url")?;
        let page = matching::parse(&url);
        let lookalike = matching::detect_lookalike(&url, &self.known_domains());
        let cross_origin_frame = match (&top_url, &page) {
            (Some(t), Some(p)) => matching::parse(t).map(|t| t.registrable_domain != p.registrable_domain).unwrap_or(true),
            _ => false,
        };
        let mut matches = Vec::new();
        if lookalike.is_none() {
            for c in self.items.values().filter(|c| c.row.deleted_at.is_none()) {
                if let ItemData::Login { urls, .. } = &c.item.data {
                    let hit = urls.iter().find(|u| matching::url_matches(u, &url));
                    if let Some(entry) = hit {
                        let frame_ok = !cross_origin_frame
                            || entry.allowed_frames.iter().any(|f| matching::parse(f).map(|f| Some(&f.host) == page.as_ref().map(|p| &p.host)).unwrap_or(false));
                        if frame_ok {
                            let mut s = self.summary(c);
                            s["insecure"] = json!(matching::is_insecure_downgrade(entry, &url));
                            matches.push(s);
                        }
                    }
                }
            }
        }
        Ok(json!({
            "matches": matches,
            "lookalike": lookalike,
            "insecure_page": page.as_ref().map(|p| p.scheme == "http").unwrap_or(false),
            "cross_origin_frame": cross_origin_frame,
        }))
    }

    /// Returns credentials for exactly one item, re-checking that it matches `url`.
    fn fill_data(&self, a: &Value) -> Result<Value> {
        let c = self.cached(&arg::<String>(a, "item_id")?)?;
        let url: String = arg(a, "url")?;
        let now: u64 = arg(a, "now")?;
        let allow_insecure = opt_arg::<bool>(a, "allow_insecure")?.unwrap_or(false);
        if matching::detect_lookalike(&url, &self.known_domains()).is_some() {
            return Err(Error::Invalid("refusing to fill on a look-alike domain".into()));
        }
        let ItemData::Login { username, password, urls, totp } = &c.item.data else {
            return Err(Error::Invalid("not a login".into()));
        };
        let entry = urls
            .iter()
            .find(|u| matching::url_matches(u, &url))
            .ok_or_else(|| Error::Invalid("item does not match this site".into()))?;
        if matching::is_insecure_downgrade(entry, &url) && !allow_insecure {
            return Err(Error::Invalid("page is not HTTPS".into()));
        }
        let code = match totp.as_deref().filter(|t| !t.is_empty()) {
            Some(t) => Some(TotpConfig::parse(t)?.code_at(now)?.code),
            None => None,
        };
        Ok(json!({ "username": username, "password": password, "totp": code }))
    }

    fn export_entries(&self, a: &Value) -> Result<Vec<ExportEntry>> {
        self.ks()?;
        let vault_ids: Option<Vec<String>> = opt_arg(a, "vault_ids")?;
        let mut out: Vec<ExportEntry> = self
            .items
            .values()
            .filter(|c| c.row.deleted_at.is_none())
            .filter(|c| vault_ids.as_ref().is_none_or(|v| v.contains(&c.row.vault_id)))
            .map(|c| {
                let v = self.vaults.get(&c.row.vault_id);
                let client = v.and_then(|v| v.row.client_id.as_ref()).and_then(|id| self.clients.get(id));
                let location = match (client, v) {
                    (Some(cl), Some(v)) => format!("{cl} / {}", v.name),
                    (None, Some(v)) => v.name.clone(),
                    _ => String::new(),
                };
                ExportEntry { location, item: c.item.clone() }
            })
            .collect();
        out.sort_by(|a, b| (&a.location, &a.item.title).cmp(&(&b.location, &b.item.title)));
        Ok(out)
    }
}

fn validate_item(item: &Item) -> Result<()> {
    if item.title.trim().is_empty() {
        return Err(Error::Invalid("title is required".into()));
    }
    if item.title.len() > 512 || item.notes.len() > 100_000 || item.custom_fields.len() > 100 {
        return Err(Error::Invalid("item too large".into()));
    }
    match &item.data {
        ItemData::Authenticator { secret, algorithm, digits, period, .. } => {
            TotpConfig { issuer: String::new(), account: String::new(), secret: secret.clone(), algorithm: crate::totp::Algorithm::parse(algorithm)?, digits: *digits, period: *period }.validate()?;
        }
        ItemData::Login { totp: Some(t), .. } if !t.is_empty() => {
            TotpConfig::parse(t)?;
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    /// Run signup through the engine (founding user creates the org).
    fn signup(e: &mut Engine, user_id: &str, email: &str, org: Option<&str>) -> (Value, String, Value) {
        let sk = e.call("generate_secret_key", json!({})).unwrap()["secret_key"].as_str().unwrap().to_string();
        let params = e.call("new_account_params", json!({})).unwrap();
        e.call("derive", json!({"password": "Correct-Horse-Battery-9", "secret_key": sk, "salt": params["salt"], "kdf": params["kdf"]}))
            .unwrap();
        let out = e
            .call(
                "create_account",
                json!({"user_id": user_id, "email": email, "salt": params["salt"], "kdf": params["kdf"], "create_org_id": org, "now": NOW}),
            )
            .unwrap();
        (out["keyset"].clone(), sk, out["org_bootstrap"].clone())
    }

    fn login_item(title: &str, url: &str, pw: &str) -> Value {
        json!({"title": title, "data": {"type": "login", "username": "me", "password": pw, "urls": [{"url": url}]}})
    }

    fn row_from_req(req: &Value, user: &str) -> Value {
        let mut r = req.clone();
        r["created_at"] = json!(NOW);
        r["updated_at"] = json!(NOW);
        r["created_by"] = json!(user);
        r["updated_by"] = json!(user);
        r
    }

    #[test]
    fn signup_lock_unlock_and_personal_items() {
        let mut e = Engine::new();
        let (keyset, sk, _) = signup(&mut e, "u1", "a@arevei.com", None);
        let req = e.call("encrypt_item", json!({"vault_id": "u1", "item": login_item("GitHub", "https://github.com", "pw1"), "now": NOW})).unwrap();
        assert!(req["expected_version"].is_null());
        e.call("sync_apply", json!({"items": [row_from_req(&req, "u1")]})).unwrap();
        assert_eq!(e.call("list_items", json!({"query": "git"})).unwrap().as_array().unwrap().len(), 1);

        e.call("lock", json!({})).unwrap();
        assert!(matches!(e.call("list_items", json!({})), Err(Error::Locked)));

        // Unlock in a "second browser" with the same secrets.
        let mut e2 = Engine::new();
        e2.call("derive", json!({"password": "Correct-Horse-Battery-9", "secret_key": sk, "salt": keyset["salt"], "kdf": keyset["kdf"]})).unwrap();
        e2.call("unlock", json!({"keyset": keyset})).unwrap();
        e2.call("sync_apply", json!({"items": [row_from_req(&req, "u1")]})).unwrap();
        let id = req["id"].as_str().unwrap();
        let got = e2.call("get_item", json!({"id": id})).unwrap();
        assert_eq!(got["item"]["data"]["password"], "pw1");

        // Wrong password fails.
        let mut e3 = Engine::new();
        e3.call("derive", json!({"password": "wrong", "secret_key": sk, "salt": keyset["salt"], "kdf": keyset["kdf"]})).unwrap();
        assert!(e3.call("unlock", json!({"keyset": keyset})).is_err());
    }

    #[test]
    fn update_history_and_rollback_detection() {
        let mut e = Engine::new();
        signup(&mut e, "u1", "a@arevei.com", None);
        let v1 = e.call("encrypt_item", json!({"vault_id": "u1", "item": login_item("X", "https://x.com", "old"), "now": NOW})).unwrap();
        e.call("sync_apply", json!({"items": [row_from_req(&v1, "u1")]})).unwrap();
        let id = v1["id"].as_str().unwrap();
        let v2 = e.call("encrypt_item", json!({"vault_id": "u1", "item_id": id, "item": login_item("X", "https://x.com", "new"), "now": NOW})).unwrap();
        assert_eq!(v2["version"], 2);
        assert_eq!(v2["expected_version"], 1);
        e.call("sync_apply", json!({"items": [row_from_req(&v2, "u1")]})).unwrap();
        let got = e.call("get_item", json!({"id": id})).unwrap();
        assert_eq!(got["item"]["password_history"][0]["value"], "old");

        let res = e.call("sync_apply", json!({"items": [row_from_req(&v1, "u1")]})).unwrap();
        assert!(res["warnings"][0].as_str().unwrap().contains("rollback"));
        assert_eq!(e.call("get_item", json!({"id": id})).unwrap()["version"], 2);
    }

    #[test]
    fn autofill_matching_and_phishing() {
        let mut e = Engine::new();
        signup(&mut e, "u1", "a@arevei.com", None);
        let req = e
            .call("encrypt_item", json!({"vault_id": "u1", "item": {"title": "Arevei", "data": {"type": "login", "username": "me", "password": "pw", "urls": [{"url": "https://arevei.com"}], "totp": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"}}, "now": NOW}))
            .unwrap();
        e.call("sync_apply", json!({"items": [row_from_req(&req, "u1")]})).unwrap();
        let id = req["id"].as_str().unwrap();

        let m = e.call("match_url", json!({"url": "https://login.arevei.com/x"})).unwrap();
        assert_eq!(m["matches"].as_array().unwrap().len(), 1);
        let f = e.call("fill_data", json!({"item_id": id, "url": "https://login.arevei.com/x", "now": 59})).unwrap();
        assert_eq!(f["password"], "pw");
        assert_eq!(f["totp"], "287082");

        let look = e.call("match_url", json!({"url": "https://\u{0430}revei.com"})).unwrap();
        assert!(look["matches"].as_array().unwrap().is_empty());
        assert!(!look["lookalike"].is_null());
        assert!(e.call("fill_data", json!({"item_id": id, "url": "https://\u{0430}revei.com", "now": 1})).is_err());
        assert!(e.call("fill_data", json!({"item_id": id, "url": "https://evil.com", "now": 1})).is_err());
        assert!(e.call("fill_data", json!({"item_id": id, "url": "http://arevei.com", "now": 1})).is_err());

        // Cross-origin iframe on the right top site gets nothing.
        let frame = e.call("match_url", json!({"url": "https://arevei.com/login", "top_url": "https://other.com"})).unwrap();
        assert!(frame["matches"].as_array().unwrap().is_empty());
    }

    /// Two users: owner creates org + project, approves a member, shares, then revokes and rotates.
    #[test]
    fn org_sharing_and_rotation() {
        let mut owner = Engine::new();
        let (_, _, boot) = signup(&mut owner, "owner", "owner@arevei.com", Some("org1"));
        let org = json!({"id": "org1", "org_sign_pk": boot["org_sign_pk"], "org_secrets": boot["org_secrets"]});
        let owner_pk = owner.call("my_fingerprint", json!({})).unwrap()["public_keys"].clone();
        let mut members = vec![json!({"user_id": "owner", "email": "owner@arevei.com", "role": "owner", "status": "active", "public_keys": owner_pk, "cert": boot["cert"]})];
        let mut owner_grants: Vec<Value> = boot["grants"].as_array().unwrap().clone();

        // Client + project.
        let client = owner.call("create_client", json!({"name": "Acme Corp"})).unwrap();
        let vault = owner.call("create_vault", json!({"name": "Website", "client_id": client["id"]})).unwrap();
        owner_grants.extend(vault["grants"].as_array().unwrap().clone());
        let vault_id = vault["id"].as_str().unwrap().to_string();
        let item_req = owner.call("encrypt_item", json!({"vault_id": vault_id, "item": login_item("WP admin", "https://acme.com/wp-admin", "s3cret"), "now": NOW})).unwrap();
        let item_row = row_from_req(&item_req, "owner");
        let vault_row = json!({"id": vault_id, "kind": "project", "client_id": client["id"], "name_enc": vault["name_enc"], "key_version": 1, "admin_wrapped_key": vault["admin_wrapped_key"], "role": "manager"});
        let res = owner
            .call("sync_apply", json!({"org": org, "members": members, "vaults": [vault_row], "clients": [{"id": client["id"], "name_enc": client["name_enc"]}], "grants": owner_grants, "items": [item_row]}))
            .unwrap();
        assert!(res["warnings"].as_array().unwrap().is_empty(), "{res}");
        let lv = owner.call("list_vaults", json!({})).unwrap();
        assert!(lv["vaults"].as_array().unwrap().iter().any(|v| v["name"] == "Website" && v["client_name"] == "Acme Corp"));

        // New member signs up (no org), owner approves.
        let mut bob = Engine::new();
        signup(&mut bob, "bob", "bob@arevei.com", None);
        let bob_pk = bob.call("my_fingerprint", json!({})).unwrap()["public_keys"].clone();
        let approval = owner.call("approve_member", json!({"user_id": "bob", "email": "bob@arevei.com", "public_keys": bob_pk, "now": NOW})).unwrap();
        members.push(json!({"user_id": "bob", "email": "bob@arevei.com", "role": "member", "status": "active", "public_keys": bob_pk, "cert": approval["cert"]}));
        let vault_row = json!({"id": vault_id, "kind": "project", "client_id": client["id"], "name_enc": vault["name_enc"], "key_version": 1, "admin_wrapped_key": vault["admin_wrapped_key"], "role": "manager"});
        owner.call("sync_apply", json!({"org": org, "members": members, "vaults": [vault_row], "clients": [{"id": client["id"], "name_enc": client["name_enc"]}], "grants": owner_grants})).unwrap();
        let bob_grant = owner.call("grant_vault", json!({"vault_id": vault_id, "user_id": "bob"})).unwrap();

        // Bob syncs: sees the client name, project name, and item.
        let mut bob_grants: Vec<Value> = approval["grants"].as_array().unwrap().clone();
        bob_grants.push(bob_grant);
        let bob_vault = json!({"id": vault_id, "kind": "project", "client_id": client["id"], "name_enc": vault["name_enc"], "key_version": 1, "role": "member"});
        let org_member_view = json!({"id": "org1", "org_sign_pk": boot["org_sign_pk"], "org_secrets": null});
        let r = bob
            .call("sync_apply", json!({"org": org_member_view, "members": members, "vaults": [bob_vault], "clients": [{"id": client["id"], "name_enc": client["name_enc"]}], "grants": bob_grants, "items": [row_from_req(&item_req, "owner")], "pinned_org_pk": boot["org_sign_pk"]}))
            .unwrap();
        assert!(r["warnings"].as_array().unwrap().is_empty(), "{r}");
        let items = bob.call("list_items", json!({"query": "acme"})).unwrap();
        assert_eq!(items.as_array().unwrap().len(), 1);
        // Bob cannot create projects (not admin).
        assert!(bob.call("create_vault", json!({"name": "x"})).is_err());

        // Pinned org key mismatch is a hard error (server swapped the org key).
        let (_, evil_pk) = sign::generate_signing_key();
        let swapped = json!({"id": "org1", "org_sign_pk": b64(&evil_pk)});
        assert!(bob.call("sync_apply", json!({"org": swapped, "pinned_org_pk": boot["org_sign_pk"]})).is_err());

        // A server-forged grant (signed by an uncertified key) is ignored.
        let (forger_sk, _) = sign::generate_signing_key();
        let bob_x: [u8; 32] = unb64_array(bob_pk["x25519"].as_str().unwrap()).unwrap();
        let fake = KeyGrant::create(&SymKey::generate(), "fake-vault", 1, "bob", &bob_x, "mallory", &forger_sk).unwrap();
        let r = bob.call("sync_apply", json!({"org": org_member_view, "members": members, "grants": [fake]})).unwrap();
        assert!(r["warnings"][0].as_str().unwrap().contains("unverified"));

        // Revoke Bob: owner rotates the vault with only themselves as member.
        let rot = owner.call("rotate_vault", json!({"vault_id": vault_id, "member_ids": ["owner"]})).unwrap();
        assert_eq!(rot["key_version"], 2);
        assert_eq!(rot["items"].as_array().unwrap().len(), 1);
        assert_eq!(rot["grants"].as_array().unwrap().len(), 1);
        // Bob's old key cannot open the re-wrapped item.
        let mut rotated_row = row_from_req(&item_req, "owner");
        rotated_row["key_version"] = rot["items"][0]["key_version"].clone();
        rotated_row["wrapped_key"] = rot["items"][0]["wrapped_key"].clone();
        let bob_vault_v2 = json!({"id": vault_id, "kind": "project", "client_id": client["id"], "name_enc": rot["name_enc"], "key_version": 2, "role": "member"});
        let r = bob
            .call("sync_apply", json!({"org": org_member_view, "members": members, "vaults": [bob_vault_v2], "grants": bob_grants, "items": [rotated_row.clone()]}))
            .unwrap();
        assert!(r.to_string().contains("could not be decrypted") || r.to_string().contains("no key"));
        // Owner (admin) still reads it via the new admin-wrapped key.
        let owner_vault_v2 = json!({"id": vault_id, "kind": "project", "client_id": client["id"], "name_enc": rot["name_enc"], "key_version": 2, "admin_wrapped_key": rot["admin_wrapped_key"], "role": "manager"});
        let mut og = owner_grants.clone();
        og.extend(rot["grants"].as_array().unwrap().clone());
        let r = owner.call("sync_apply", json!({"org": org, "members": members, "vaults": [owner_vault_v2], "clients": [{"id": client["id"], "name_enc": client["name_enc"]}], "grants": og, "items": [rotated_row]})).unwrap();
        assert!(r["warnings"].as_array().unwrap().is_empty(), "{r}");
    }

    #[test]
    fn opaque_through_engine() {
        use opaque_ke::{RegistrationRequest, RegistrationUpload, ServerRegistration, ServerSetup};
        let mut e = Engine::new();
        let sk = SecretKey::generate().format();
        let params = e.call("new_account_params", json!({})).unwrap();
        e.call("derive", json!({"password": "pw-Long-Enough-1", "secret_key": sk, "salt": params["salt"], "kdf": params["kdf"]})).unwrap();
        let start = e.call("opaque_register_start", json!({})).unwrap();
        let setup = ServerSetup::<opaque::Suite>::new(&mut rand::rngs::OsRng);
        let req = RegistrationRequest::deserialize(&unb64(start["message"].as_str().unwrap()).unwrap()).unwrap();
        let resp = ServerRegistration::<opaque::Suite>::start(&setup, req, b"id").unwrap();
        let fin = e.call("opaque_register_finish", json!({"response": b64(&resp.message.serialize())})).unwrap();
        let upload = RegistrationUpload::<opaque::Suite>::deserialize(&unb64(fin["upload"].as_str().unwrap()).unwrap()).unwrap();
        let _record = ServerRegistration::<opaque::Suite>::finish(upload);
    }

    #[test]
    fn tools() {
        let mut e = Engine::new();
        assert_eq!(e.call("totp", json!({"secret": "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "now": 59})).unwrap()["code"], "287082");
        assert_eq!(e.call("generate_password", json!({})).unwrap()["value"].as_str().unwrap().len(), 20);
        assert!(e.call("strength", json!({"password": "password"})).unwrap()["score"].as_u64().unwrap() < 2);
        assert!(e.call("unknown_method", json!({})).is_err());
        assert!(matches!(e.call("security_report", json!({"now": 0})), Err(Error::Locked)));
    }
}
