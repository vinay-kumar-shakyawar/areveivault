//! Encrypted export (re-importable) and plaintext CSV export (with formula-injection escaping).

use serde::{Deserialize, Serialize};

use crate::encoding::{b64, unb64, unb64_array, Aad};
use crate::item::{Item, ItemData};
use crate::kdf::{argon2id, KdfParams};
use crate::keys::{random_bytes, SymKey};
use crate::{envelope, Error, Result};

const FORMAT: &str = "arevei-vault-export";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExportEntry {
    /// Human-readable location, e.g. "Personal" or "Acme Corp / Website".
    pub location: String,
    pub item: Item,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportFile {
    pub format: String,
    pub version: u32,
    pub kdf: KdfParams,
    pub salt: String,
    pub data: String,
}

fn aad(kdf: &KdfParams, salt: &[u8]) -> Vec<u8> {
    Aad::new("export").u64(kdf.m_kib as u64).u64(kdf.t as u64).u64(kdf.p as u64).part(salt).bytes().to_vec()
}

pub fn export_encrypted(entries: &[ExportEntry], password: &str) -> Result<String> {
    let kdf = KdfParams::DEFAULT;
    let salt = random_bytes::<16>();
    let key = SymKey::from_bytes(*argon2id(password, &salt, kdf)?);
    let json = zeroize::Zeroizing::new(serde_json::to_vec(entries)?);
    let file = ExportFile {
        format: FORMAT.into(),
        version: 1,
        kdf,
        salt: b64(&salt),
        data: b64(&envelope::seal(&key, &json, &aad(&kdf, &salt))),
    };
    Ok(serde_json::to_string_pretty(&file)?)
}

pub fn import_encrypted(file_json: &str, password: &str) -> Result<Vec<ExportEntry>> {
    let file: ExportFile = serde_json::from_str(file_json)?;
    if file.format != FORMAT || file.version != 1 {
        return Err(Error::Format);
    }
    file.kdf.validate()?;
    let salt: [u8; 16] = unb64_array(&file.salt)?;
    let key = SymKey::from_bytes(*argon2id(password, &salt, file.kdf)?);
    let json = envelope::open(&key, &unb64(&file.data)?, &aad(&file.kdf, &salt))?;
    Ok(serde_json::from_slice(&json)?)
}

/// Neutralize spreadsheet formula injection (OWASP CSV Injection).
fn escape_cell(s: &str) -> String {
    if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{s}")
    } else {
        s.to_string()
    }
}

pub fn export_csv(entries: &[ExportEntry]) -> Result<String> {
    let mut w = csv::Writer::from_writer(Vec::new());
    w.write_record(["location", "type", "title", "username", "password", "url", "totp", "notes"])
        .map_err(|e| Error::Parse(e.to_string()))?;
    for e in entries {
        let it = &e.item;
        let (username, password, url, totp) = match &it.data {
            ItemData::Login { username, password, urls, totp } => (
                username.as_str(),
                password.as_str(),
                urls.iter().map(|u| u.url.as_str()).collect::<Vec<_>>().join(","),
                totp.clone().unwrap_or_default(),
            ),
            ItemData::Server { username, password, host, .. } => (username.as_str(), password.as_str(), host.clone(), String::new()),
            ItemData::Authenticator { secret, .. } => ("", "", String::new(), secret.clone()),
            ItemData::ApiKey { key, secret, .. } => (key.as_str(), secret.as_str(), String::new(), String::new()),
            _ => ("", "", String::new(), String::new()),
        };
        w.write_record(
            [&e.location, it.data.type_name(), &it.title, username, password, &url, &totp, &it.notes].map(|s| escape_cell(s)),
        )
        .map_err(|e| Error::Parse(e.to_string()))?;
    }
    String::from_utf8(w.into_inner().map_err(|e| Error::Parse(e.to_string()))?).map_err(|e| Error::Parse(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::UrlEntry;

    fn entry(title: &str, pw: &str) -> ExportEntry {
        ExportEntry {
            location: "Personal".into(),
            item: Item {
                title: title.into(),
                data: ItemData::Login {
                    username: "u".into(),
                    password: pw.into(),
                    urls: vec![UrlEntry { url: "https://x.com".into(), ..Default::default() }],
                    totp: None,
                },
                notes: String::new(),
                tags: vec![],
                custom_fields: vec![],
                password_history: vec![],
                attachments: vec![],
                expires_at: None,
            },
        }
    }

    #[test]
    fn encrypted_roundtrip() {
        let entries = vec![entry("A", "p1"), entry("B", "p2")];
        let f = export_encrypted(&entries, "export pass phrase").unwrap();
        assert!(!f.contains("p1"));
        assert_eq!(import_encrypted(&f, "export pass phrase").unwrap(), entries);
        assert!(import_encrypted(&f, "wrong").is_err());
    }

    #[test]
    fn csv_formula_escaping() {
        let csv = export_csv(&[entry("=HYPERLINK(\"http://evil\")", "+1")]).unwrap();
        assert!(csv.contains("'=HYPERLINK"));
        assert!(csv.contains("'+1"));
    }
}
