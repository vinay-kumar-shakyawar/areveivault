//! Security dashboard, computed entirely client-side over decrypted items.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::item::{Item, ItemData};
use crate::{matching, strength};

/// Sites known to support 2FA (small bundled snapshot; extend via 2fa.directory data).
const TWO_FA_DOMAINS: &[&str] = &[
    "google.com", "github.com", "gitlab.com", "amazon.com", "aws.amazon.com", "microsoft.com", "live.com",
    "office.com", "apple.com", "facebook.com", "instagram.com", "twitter.com", "x.com", "linkedin.com",
    "slack.com", "atlassian.net", "atlassian.com", "dropbox.com", "cloudflare.com", "digitalocean.com",
    "godaddy.com", "namecheap.com", "stripe.com", "paypal.com", "shopify.com", "wordpress.com", "heroku.com",
    "vercel.com", "netlify.com", "zoom.us", "notion.so", "figma.com", "hubspot.com", "mailchimp.com",
    "salesforce.com", "bitbucket.org", "npmjs.com", "docker.com", "azure.com", "hetzner.com", "ovh.com",
    "linode.com", "vultr.com", "twilio.com", "sendgrid.com", "zoho.com", "canva.com", "squarespace.com",
    "wix.com", "tiktok.com", "pinterest.com", "reddit.com", "discord.com", "adobe.com",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Finding {
    pub item_id: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Report {
    pub weak: Vec<Finding>,
    pub reused: Vec<Finding>,
    pub old: Vec<Finding>,
    pub missing_2fa: Vec<Finding>,
    pub expiring: Vec<Finding>,
    pub total_logins: usize,
}

pub struct ReportInput<'a> {
    pub id: &'a str,
    pub item: &'a Item,
    /// Unix seconds of last modification (from server metadata).
    pub updated_at: i64,
}

const OLD_AFTER_SECS: i64 = 365 * 24 * 3600;
const EXPIRING_WITHIN_DAYS: i64 = 30;

pub fn report(items: &[ReportInput], now: i64) -> Report {
    let mut r = Report::default();
    let mut by_hash: HashMap<[u8; 32], Vec<&str>> = HashMap::new();

    for inp in items {
        let it = inp.item;
        if let Some(pw) = it.data.primary_password().filter(|p| !p.is_empty()) {
            r.total_logins += 1;
            let s = strength::estimate(pw, &[it.title.as_str(), it.data.username().unwrap_or("")]);
            if s.score < 3 {
                r.weak.push(Finding { item_id: inp.id.into(), detail: format!("strength {}/4", s.score) });
            }
            by_hash.entry(Sha256::digest(pw.as_bytes()).into()).or_default().push(inp.id);
            if now - inp.updated_at > OLD_AFTER_SECS {
                r.old.push(Finding {
                    item_id: inp.id.into(),
                    detail: format!("unchanged for {} days", (now - inp.updated_at) / 86400),
                });
            }
        }
        if let ItemData::Login { urls, totp, .. } = &it.data {
            if totp.as_deref().unwrap_or("").is_empty() {
                let supports = urls.iter().filter_map(|u| matching::parse(&u.url)).any(|p| {
                    TWO_FA_DOMAINS
                        .iter()
                        .any(|d| p.registrable_domain.as_deref() == Some(*d) || p.host == *d || p.host.ends_with(&format!(".{d}")))
                });
                if supports {
                    r.missing_2fa.push(Finding { item_id: inp.id.into(), detail: "site supports 2FA".into() });
                }
            }
        }
        if let Some(days) = it.expires_at.as_deref().and_then(|d| days_until(d, now)) {
            if days <= EXPIRING_WITHIN_DAYS {
                let detail = if days < 0 { format!("expired {} days ago", -days) } else { format!("expires in {days} days") };
                r.expiring.push(Finding { item_id: inp.id.into(), detail });
            }
        }
    }
    for ids in by_hash.values().filter(|v| v.len() > 1) {
        for id in ids {
            r.reused.push(Finding { item_id: (*id).into(), detail: format!("used in {} items", ids.len()) });
        }
    }
    r.reused.sort_by(|a, b| a.item_id.cmp(&b.item_id));
    r
}

/// Days from `now` until an ISO `YYYY-MM-DD` date (negative if past).
fn days_until(date: &str, now: i64) -> Option<i64> {
    let mut parts = date.get(..10)?.split('-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: i64 = parts.next()?.parse().ok()?;
    let d: i64 = parts.next()?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    // Days-from-civil (Howard Hinnant).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days - now.div_euclid(86400))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::UrlEntry;

    fn login(pw: &str, url: &str) -> Item {
        Item {
            title: "t".into(),
            data: ItemData::Login {
                username: "u".into(),
                password: pw.into(),
                urls: vec![UrlEntry { url: url.into(), ..Default::default() }],
                totp: None,
            },
            notes: String::new(),
            tags: vec![],
            custom_fields: vec![],
            password_history: vec![],
            attachments: vec![],
            expires_at: None,
        }
    }

    #[test]
    fn findings() {
        let now = 1_800_000_000;
        let strong = "vT7#qL9!mZ2@wX4$";
        let a = login("password1", "https://github.com");
        let b = login(strong, "https://example.org");
        let c = login(strong, "https://example.net");
        let mut d = login("Zq8!rT6#yU3$kP0@", "https://example.com");
        d.expires_at = Some("2027-01-20".into()); // ~5 days after `now`
        let items = [
            ReportInput { id: "a", item: &a, updated_at: now - 400 * 86400 },
            ReportInput { id: "b", item: &b, updated_at: now },
            ReportInput { id: "c", item: &c, updated_at: now },
            ReportInput { id: "d", item: &d, updated_at: now },
        ];
        let r = report(&items, now);
        assert_eq!(r.total_logins, 4);
        assert_eq!(r.weak.iter().map(|f| f.item_id.as_str()).collect::<Vec<_>>(), ["a"]);
        assert_eq!(r.reused.iter().map(|f| f.item_id.as_str()).collect::<Vec<_>>(), ["b", "c"]);
        assert_eq!(r.old.len(), 1);
        assert_eq!(r.missing_2fa.iter().map(|f| f.item_id.as_str()).collect::<Vec<_>>(), ["a"]);
        assert_eq!(r.expiring.len(), 1);
    }

    #[test]
    fn civil_days() {
        assert_eq!(days_until("1970-01-01", 0), Some(0));
        assert_eq!(days_until("1970-01-11", 86400), Some(9));
        assert_eq!(days_until("2000-03-01", 0), Some(11017));
        assert_eq!(days_until("bad", 0), None);
    }
}
