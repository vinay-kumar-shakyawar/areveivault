//! Item model and per-item encryption (architecture §4.3, §7).
//!
//! Every write uses a fresh random item key, wrapped by the vault key. Both the
//! wrapped key and the payload are bound to (vault, item, version) via AAD.

use serde::{Deserialize, Serialize};

use crate::encoding::{b64, unb64, Aad};
use crate::keys::SymKey;
use crate::{envelope, padding, Result};

pub const PASSWORD_HISTORY_LIMIT: usize = 10;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum MatchMode {
    /// Registrable domain (eTLD+1) — the default.
    #[default]
    Domain,
    /// Exact host (e.g. `admin.example.com` only).
    Host,
    /// URL must start with the saved URL (scheme + host + path prefix).
    Exact,
    /// Never offer for autofill.
    Never,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct UrlEntry {
    pub url: String,
    #[serde(default)]
    pub match_mode: MatchMode,
    /// Cross-origin iframe origins explicitly allowed to receive this credential.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_frames: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    #[default]
    Text,
    Hidden,
    Url,
    Date,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct CustomField {
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub kind: FieldKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistoryEntry {
    pub value: String,
    /// Unix seconds when this value was replaced.
    pub replaced_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecoveryCode {
    pub code: String,
    #[serde(default)]
    pub used: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub used_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AttachmentRef {
    pub id: String,
    pub name: String,
    pub mime: String,
    pub size: u64,
    /// File key, base64 — protected because the whole item payload is encrypted.
    pub file_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ItemData {
    Login {
        #[serde(default)]
        username: String,
        #[serde(default)]
        password: String,
        #[serde(default)]
        urls: Vec<UrlEntry>,
        /// otpauth:// URI or bare base32 secret.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        totp: Option<String>,
    },
    Authenticator {
        #[serde(default)]
        issuer: String,
        #[serde(default)]
        account: String,
        secret: String,
        #[serde(default = "default_algorithm")]
        algorithm: String,
        #[serde(default = "default_digits")]
        digits: u32,
        #[serde(default = "default_period")]
        period: u64,
    },
    RecoveryCodes {
        #[serde(default)]
        service: String,
        codes: Vec<RecoveryCode>,
    },
    ApiKey {
        #[serde(default)]
        service: String,
        #[serde(default)]
        key: String,
        #[serde(default)]
        secret: String,
        #[serde(default)]
        environment: String,
    },
    SshKey {
        #[serde(default)]
        public_key: String,
        #[serde(default)]
        private_key: String,
        #[serde(default)]
        passphrase: String,
        #[serde(default)]
        fingerprint: String,
    },
    Server {
        #[serde(default)]
        host: String,
        #[serde(default)]
        port: Option<u16>,
        #[serde(default)]
        username: String,
        #[serde(default)]
        password: String,
        #[serde(default)]
        database: String,
        #[serde(default)]
        connection_string: String,
    },
    SecureNote {},
    Document {},
}

fn default_algorithm() -> String {
    "SHA1".into()
}
fn default_digits() -> u32 {
    6
}
fn default_period() -> u64 {
    30
}

impl ItemData {
    pub fn type_name(&self) -> &'static str {
        match self {
            ItemData::Login { .. } => "login",
            ItemData::Authenticator { .. } => "authenticator",
            ItemData::RecoveryCodes { .. } => "recovery_codes",
            ItemData::ApiKey { .. } => "api_key",
            ItemData::SshKey { .. } => "ssh_key",
            ItemData::Server { .. } => "server",
            ItemData::SecureNote { .. } => "secure_note",
            ItemData::Document { .. } => "document",
        }
    }

    /// The primary secret that password history and the security report track.
    pub fn primary_password(&self) -> Option<&str> {
        match self {
            ItemData::Login { password, .. } | ItemData::Server { password, .. } => Some(password),
            _ => None,
        }
    }

    pub fn username(&self) -> Option<&str> {
        match self {
            ItemData::Login { username, .. } | ItemData::Server { username, .. } => Some(username),
            ItemData::Authenticator { account, .. } => Some(account),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Item {
    pub title: String,
    pub data: ItemData,
    /// Rich text as a structured document (JSON), or plain text. Never HTML.
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
    #[serde(default)]
    pub password_history: Vec<HistoryEntry>,
    #[serde(default)]
    pub attachments: Vec<AttachmentRef>,
    /// ISO date (YYYY-MM-DD) for expiry reminders (API keys, certificates).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

impl Item {
    /// Apply an edit, pushing a changed primary password into history (max 10).
    pub fn apply_update(old: &Item, mut new: Item, now: i64) -> Item {
        new.password_history = old.password_history.clone();
        if let (Some(o), Some(n)) = (old.data.primary_password(), new.data.primary_password()) {
            if o != n && !o.is_empty() {
                new.password_history.insert(0, HistoryEntry { value: o.to_string(), replaced_at: now });
            }
        }
        new.password_history.truncate(PASSWORD_HISTORY_LIMIT);
        new
    }
}

/// Server-facing representation. Everything except routing ids/versions is ciphertext.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EncryptedItem {
    pub id: String,
    pub vault_id: String,
    pub version: u64,
    pub key_version: u32,
    pub wrapped_key: String,
    pub payload: String,
}

fn item_key_aad(vault_id: &str, item_id: &str, version: u64, key_version: u32) -> Vec<u8> {
    Aad::new("item-key")
        .str(vault_id)
        .str(item_id)
        .u64(version)
        .u64(key_version as u64)
        .bytes()
        .to_vec()
}

fn item_payload_aad(vault_id: &str, item_id: &str, version: u64) -> Vec<u8> {
    Aad::new("item-payload").str(vault_id).str(item_id).u64(version).bytes().to_vec()
}

pub fn encrypt_item(
    item: &Item,
    vault_key: &SymKey,
    vault_id: &str,
    item_id: &str,
    version: u64,
    key_version: u32,
) -> Result<EncryptedItem> {
    let item_key = SymKey::generate();
    let json = zeroize::Zeroizing::new(serde_json::to_vec(item)?);
    let padded = zeroize::Zeroizing::new(padding::pad(&json));
    Ok(EncryptedItem {
        id: item_id.into(),
        vault_id: vault_id.into(),
        version,
        key_version,
        wrapped_key: b64(&envelope::seal(
            vault_key,
            item_key.as_bytes(),
            &item_key_aad(vault_id, item_id, version, key_version),
        )),
        payload: b64(&envelope::seal(&item_key, &padded, &item_payload_aad(vault_id, item_id, version))),
    })
}

pub fn decrypt_item(enc: &EncryptedItem, vault_key: &SymKey) -> Result<Item> {
    let ik = envelope::open(
        vault_key,
        &unb64(&enc.wrapped_key)?,
        &item_key_aad(&enc.vault_id, &enc.id, enc.version, enc.key_version),
    )?;
    let item_key = SymKey::from_slice(&ik)?;
    let padded = envelope::open(&item_key, &unb64(&enc.payload)?, &item_payload_aad(&enc.vault_id, &enc.id, enc.version))?;
    Ok(serde_json::from_slice(padding::unpad(&padded)?)?)
}

/// Re-wrap only the item key under a rotated vault key (payload untouched).
pub fn rewrap_item_key(enc: &EncryptedItem, old_key: &SymKey, new_key: &SymKey, new_key_version: u32) -> Result<EncryptedItem> {
    let ik = envelope::open(
        old_key,
        &unb64(&enc.wrapped_key)?,
        &item_key_aad(&enc.vault_id, &enc.id, enc.version, enc.key_version),
    )?;
    let mut out = enc.clone();
    out.key_version = new_key_version;
    out.wrapped_key = b64(&envelope::seal(
        new_key,
        &ik,
        &item_key_aad(&enc.vault_id, &enc.id, enc.version, new_key_version),
    ));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn sample_login(pw: &str) -> Item {
        Item {
            title: "Acme hosting".into(),
            data: ItemData::Login {
                username: "ops@acme.com".into(),
                password: pw.into(),
                urls: vec![UrlEntry { url: "https://panel.acme.com/login".into(), ..Default::default() }],
                totp: None,
            },
            notes: String::new(),
            tags: vec!["hosting".into()],
            custom_fields: vec![],
            password_history: vec![],
            attachments: vec![],
            expires_at: None,
        }
    }

    #[test]
    fn roundtrip() {
        let vk = SymKey::generate();
        let item = sample_login("hunter2");
        let enc = encrypt_item(&item, &vk, "v1", "i1", 1, 1).unwrap();
        assert!(!enc.payload.contains("Acme"));
        assert_eq!(decrypt_item(&enc, &vk).unwrap(), item);
    }

    #[test]
    fn swap_and_rollback_attacks_fail() {
        let vk = SymKey::generate();
        let enc = encrypt_item(&sample_login("a"), &vk, "v1", "i1", 3, 1).unwrap();

        let mut moved = enc.clone();
        moved.vault_id = "v2".into();
        assert!(decrypt_item(&moved, &vk).is_err());

        let mut renamed = enc.clone();
        renamed.id = "i2".into();
        assert!(decrypt_item(&renamed, &vk).is_err());

        let mut reversioned = enc.clone();
        reversioned.version = 2;
        assert!(decrypt_item(&reversioned, &vk).is_err());

        // Payload of item A spliced with the key of item B.
        let other = encrypt_item(&sample_login("b"), &vk, "v1", "i1", 3, 1).unwrap();
        let mut spliced = enc.clone();
        spliced.payload = other.payload;
        assert!(decrypt_item(&spliced, &vk).is_err());
    }

    #[test]
    fn rotation_rewrap() {
        let old = SymKey::generate();
        let new = SymKey::generate();
        let enc = encrypt_item(&sample_login("x"), &old, "v", "i", 1, 1).unwrap();
        let rotated = rewrap_item_key(&enc, &old, &new, 2).unwrap();
        assert_eq!(rotated.payload, enc.payload);
        assert!(decrypt_item(&rotated, &old).is_err());
        assert_eq!(decrypt_item(&rotated, &new).unwrap().title, "Acme hosting");
    }

    #[test]
    fn history_is_capped() {
        let mut item = sample_login("p0");
        for i in 1..=15 {
            item = Item::apply_update(&item, sample_login(&format!("p{i}")), i);
        }
        assert_eq!(item.password_history.len(), PASSWORD_HISTORY_LIMIT);
        assert_eq!(item.password_history[0].value, "p14");
    }

    #[test]
    fn json_shape_is_stable() {
        let j = serde_json::to_value(sample_login("x")).unwrap();
        assert_eq!(j["data"]["type"], "login");
        assert_eq!(j["data"]["urls"][0]["match_mode"], "domain");
    }
}
