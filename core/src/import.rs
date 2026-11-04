//! Importers: Chrome/Google CSV, Bitwarden (CSV + JSON), 1Password CSV, LastPass CSV,
//! and generic CSV. All parsing happens client-side; nothing is sent anywhere.

use serde::{Deserialize, Serialize};

use crate::item::{CustomField, FieldKind, Item, ItemData, UrlEntry};
use crate::{matching, Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Chrome,
    Bitwarden,
    BitwardenJson,
    OnePassword,
    LastPass,
    Generic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedItem {
    pub item: Item,
    pub folder: Option<String>,
    pub favorite: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ImportResult {
    pub items: Vec<ImportedItem>,
    /// Human-readable reasons for skipped rows ("row 12: no password or URL").
    pub skipped: Vec<String>,
}

pub fn import(format: Format, text: &str) -> Result<ImportResult> {
    let text = text.trim_start_matches('\u{feff}');
    match format {
        Format::BitwardenJson => import_bitwarden_json(text),
        _ => import_csv(format, text),
    }
}

#[derive(Default)]
struct Columns {
    title: Option<usize>,
    url: Option<usize>,
    username: Option<usize>,
    password: Option<usize>,
    notes: Option<usize>,
    totp: Option<usize>,
    folder: Option<usize>,
    favorite: Option<usize>,
    tags: Option<usize>,
    kind: Option<usize>,
}

fn find_columns(headers: &csv::StringRecord) -> Columns {
    let norm: Vec<String> = headers.iter().map(|h| h.trim().to_ascii_lowercase().replace(['-', ' '], "_")).collect();
    let find = |names: &[&str]| names.iter().find_map(|n| norm.iter().position(|h| h == n));
    Columns {
        title: find(&["name", "title", "item_name"]),
        url: find(&["url", "login_uri", "website", "uri", "urls", "login_url"]),
        username: find(&["username", "login_username", "user", "email", "login", "user_name"]),
        password: find(&["password", "login_password", "pass"]),
        notes: find(&["note", "notes", "extra", "comments"]),
        totp: find(&["totp", "login_totp", "otpauth", "one_time_password", "otp"]),
        folder: find(&["folder", "grouping", "group", "vault"]),
        favorite: find(&["favorite", "fav", "favourite"]),
        tags: find(&["tags", "tag"]),
        kind: find(&["type"]),
    }
}

fn import_csv(format: Format, text: &str) -> Result<ImportResult> {
    let mut rdr = csv::ReaderBuilder::new().flexible(true).from_reader(text.as_bytes());
    let headers = rdr.headers().map_err(|e| Error::Parse(e.to_string()))?.clone();
    let cols = find_columns(&headers);
    if cols.password.is_none() && cols.url.is_none() && cols.notes.is_none() {
        return Err(Error::Parse("could not find password/url/notes columns in CSV header".into()));
    }

    let mut out = ImportResult::default();
    for (i, rec) in rdr.records().enumerate() {
        let row = i + 2; // header is row 1
        let rec = match rec {
            Ok(r) => r,
            Err(e) => {
                out.skipped.push(format!("row {row}: {e}"));
                continue;
            }
        };
        let get = |c: Option<usize>| c.and_then(|c| rec.get(c)).map(|s| s.trim().to_string()).unwrap_or_default();

        let url_field = get(cols.url);
        let username = get(cols.username);
        let password = get(cols.password);
        let notes = get(cols.notes);
        let totp = get(cols.totp);
        let kind = get(cols.kind).to_ascii_lowercase();
        let mut title = get(cols.title);

        let is_note = (format == Format::LastPass && url_field == "http://sn")
            || (format == Format::Bitwarden && kind == "note")
            || (password.is_empty() && username.is_empty() && url_field.is_empty() && !notes.is_empty());

        let urls: Vec<UrlEntry> = if is_note {
            vec![]
        } else {
            url_field
                .split([',', '\n'])
                .map(str::trim)
                .filter(|u| !u.is_empty())
                .map(|u| UrlEntry { url: u.to_string(), ..Default::default() })
                .collect()
        };

        if !is_note && password.is_empty() && urls.is_empty() && username.is_empty() {
            out.skipped.push(format!("row {row}: empty"));
            continue;
        }
        if title.is_empty() {
            title = urls
                .first()
                .and_then(|u| matching::parse(&u.url))
                .and_then(|p| p.registrable_domain.or(Some(p.host)))
                .unwrap_or_else(|| "Imported item".into());
        }

        let data = if is_note {
            ItemData::SecureNote {}
        } else {
            ItemData::Login { username, password, urls, totp: (!totp.is_empty()).then_some(totp) }
        };
        let tags = get(cols.tags)
            .split([',', ';'])
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(String::from)
            .collect();
        let fav = get(cols.favorite);
        out.items.push(ImportedItem {
            item: Item {
                title,
                data,
                notes,
                tags,
                custom_fields: vec![],
                password_history: vec![],
                attachments: vec![],
                expires_at: None,
            },
            folder: Some(get(cols.folder)).filter(|f| !f.is_empty()),
            favorite: matches!(fav.to_ascii_lowercase().as_str(), "1" | "true" | "yes"),
        });
    }
    Ok(out)
}

#[derive(Deserialize)]
struct BwExport {
    #[serde(default)]
    encrypted: bool,
    #[serde(default)]
    folders: Vec<BwFolder>,
    #[serde(default)]
    items: Vec<BwItem>,
}

#[derive(Deserialize)]
struct BwFolder {
    id: String,
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct BwItem {
    #[serde(rename = "type")]
    kind: u8,
    #[serde(default)]
    name: String,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    favorite: bool,
    #[serde(default)]
    folder_id: Option<String>,
    #[serde(default)]
    login: Option<BwLogin>,
    #[serde(default)]
    fields: Option<Vec<BwField>>,
}

#[derive(Deserialize)]
struct BwLogin {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    totp: Option<String>,
    #[serde(default)]
    uris: Option<Vec<BwUri>>,
}

#[derive(Deserialize)]
struct BwUri {
    #[serde(default)]
    uri: Option<String>,
}

#[derive(Deserialize)]
struct BwField {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(rename = "type", default)]
    kind: u8,
}

fn import_bitwarden_json(text: &str) -> Result<ImportResult> {
    let ex: BwExport = serde_json::from_str(text)?;
    if ex.encrypted {
        return Err(Error::Invalid("encrypted Bitwarden exports are not supported; export as unencrypted JSON".into()));
    }
    let mut out = ImportResult::default();
    for (i, it) in ex.items.into_iter().enumerate() {
        let data = match (it.kind, it.login) {
            (1, Some(l)) => ItemData::Login {
                username: l.username.unwrap_or_default(),
                password: l.password.unwrap_or_default(),
                urls: l
                    .uris
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|u| u.uri)
                    .map(|url| UrlEntry { url, ..Default::default() })
                    .collect(),
                totp: l.totp.filter(|t| !t.is_empty()),
            },
            (2, _) => ItemData::SecureNote {},
            (k, _) => {
                out.skipped.push(format!("item {}: unsupported Bitwarden type {k} ({})", i + 1, it.name));
                continue;
            }
        };
        let folder = it
            .folder_id
            .and_then(|fid| ex.folders.iter().find(|f| f.id == fid).map(|f| f.name.clone()));
        out.items.push(ImportedItem {
            item: Item {
                title: if it.name.is_empty() { "Imported item".into() } else { it.name },
                data,
                notes: it.notes.unwrap_or_default(),
                tags: vec![],
                custom_fields: it
                    .fields
                    .unwrap_or_default()
                    .into_iter()
                    .map(|f| CustomField {
                        name: f.name.unwrap_or_default(),
                        value: f.value.unwrap_or_default(),
                        kind: if f.kind == 1 { FieldKind::Hidden } else { FieldKind::Text },
                    })
                    .collect(),
                password_history: vec![],
                attachments: vec![],
                expires_at: None,
            },
            folder,
            favorite: it.favorite,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_csv() {
        let csv = "name,url,username,password,note\n\
                   github.com,https://github.com/login,alice,pa55,\n\
                   ,https://accounts.google.com/,bob@x.com,\"p,w\"\"x\",my note\n";
        let r = import(Format::Chrome, csv).unwrap();
        assert_eq!(r.items.len(), 2);
        assert_eq!(r.items[1].item.title, "google.com");
        match &r.items[1].item.data {
            ItemData::Login { password, .. } => assert_eq!(password, "p,w\"x"),
            _ => panic!(),
        }
        assert_eq!(r.items[1].item.notes, "my note");
    }

    #[test]
    fn chrome_500_rows() {
        let mut csv = String::from("name,url,username,password,note\n");
        for i in 0..500 {
            csv.push_str(&format!("site{i}.com,https://site{i}.com/login,user{i},pw{i},\n"));
        }
        let r = import(Format::Chrome, &csv).unwrap();
        assert_eq!(r.items.len(), 500);
        assert!(r.skipped.is_empty());
    }

    #[test]
    fn lastpass_secure_note_and_folder() {
        let csv = "url,username,password,totp,extra,name,grouping,fav\n\
                   http://sn,,,,secret text,Wifi,Office,1\n\
                   https://x.com,u,p,,,X,Social,0\n";
        let r = import(Format::LastPass, csv).unwrap();
        assert!(matches!(r.items[0].item.data, ItemData::SecureNote {}));
        assert_eq!(r.items[0].folder.as_deref(), Some("Office"));
        assert!(r.items[0].favorite);
    }

    #[test]
    fn bitwarden_csv_multiple_uris() {
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
                   Work,1,login,AWS,,,0,\"https://aws.amazon.com,https://signin.aws.amazon.com\",root,pw,JBSWY3DPEHPK3PXP\n";
        let r = import(Format::Bitwarden, csv).unwrap();
        match &r.items[0].item.data {
            ItemData::Login { urls, totp, .. } => {
                assert_eq!(urls.len(), 2);
                assert_eq!(totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn bitwarden_json() {
        let json = r#"{"encrypted":false,"folders":[{"id":"f1","name":"Clients"}],"items":[
            {"type":1,"name":"Acme","folderId":"f1","favorite":true,"notes":"n",
             "login":{"username":"u","password":"p","uris":[{"uri":"https://acme.com"}]},
             "fields":[{"name":"PIN","value":"1234","type":1}]},
            {"type":2,"name":"Note","notes":"text"},
            {"type":3,"name":"Card"}]}"#;
        let r = import(Format::BitwardenJson, json).unwrap();
        assert_eq!(r.items.len(), 2);
        assert_eq!(r.items[0].folder.as_deref(), Some("Clients"));
        assert_eq!(r.items[0].item.custom_fields[0].kind, FieldKind::Hidden);
        assert_eq!(r.skipped.len(), 1);
    }

    #[test]
    fn onepassword_csv() {
        let csv = "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n\
                   Slack,https://slack.com,me,pw,,false,false,\"work,chat\",\n";
        let r = import(Format::OnePassword, csv).unwrap();
        assert_eq!(r.items[0].item.tags, vec!["work", "chat"]);
    }

    #[test]
    fn bad_header() {
        assert!(import(Format::Generic, "a,b,c\n1,2,3\n").is_err());
    }
}
