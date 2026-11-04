//! URL matching for autofill and phishing heuristics (architecture §13.3).
//!
//! Matching uses the registrable domain (eTLD+1) from the Public Suffix List,
//! including the private section, so `alice.github.io` never matches `bob.github.io`.

use serde::{Deserialize, Serialize};
use unicode_security::confusable_detection::skeleton;

use crate::item::{MatchMode, UrlEntry};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageInfo {
    pub scheme: String,
    /// ASCII (punycode) host, lowercase.
    pub host: String,
    pub registrable_domain: Option<String>,
    pub port: Option<u16>,
}

/// Parse a page or saved URL. Saved URLs without a scheme are treated as https.
pub fn parse(input: &str) -> Option<PageInfo> {
    let input = input.trim();
    let with_scheme = if input.contains("://") { input.to_string() } else { format!("https://{input}") };
    let u = url::Url::parse(&with_scheme).ok()?;
    let host = u.host_str()?.trim_end_matches('.').to_ascii_lowercase();
    let registrable_domain = registrable_domain(&host);
    Some(PageInfo { scheme: u.scheme().to_string(), host, registrable_domain, port: u.port() })
}

pub fn registrable_domain(host: &str) -> Option<String> {
    if host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('[') {
        return Some(host.to_string());
    }
    if host == "localhost" {
        return Some(host.into());
    }
    psl::domain_str(host).map(|d| d.to_string())
}

/// Does a saved URL entry match the page the user is on?
pub fn url_matches(entry: &UrlEntry, page_url: &str) -> bool {
    let (Some(saved), Some(page)) = (parse(&entry.url), parse(page_url)) else {
        return false;
    };
    // Only web schemes are fillable.
    if !matches!(page.scheme.as_str(), "https" | "http") {
        return false;
    }
    match entry.match_mode {
        MatchMode::Never => false,
        MatchMode::Domain => saved.registrable_domain.is_some() && saved.registrable_domain == page.registrable_domain,
        MatchMode::Host => saved.host == page.host && saved.port == page.port,
        MatchMode::Exact => {
            let s = normalize_exact(&entry.url);
            let p = normalize_exact(page_url);
            matches!((s, p), (Some(s), Some(p)) if p.starts_with(&s))
        }
    }
}

fn normalize_exact(input: &str) -> Option<String> {
    let with_scheme = if input.contains("://") { input.to_string() } else { format!("https://{input}") };
    let mut u = url::Url::parse(&with_scheme).ok()?;
    u.set_query(None);
    u.set_fragment(None);
    Some(u.to_string())
}

/// True when a saved https credential would be sent to a plain-http page.
pub fn is_insecure_downgrade(entry: &UrlEntry, page_url: &str) -> bool {
    matches!((parse(&entry.url), parse(page_url)), (Some(s), Some(p)) if s.scheme == "https" && p.scheme == "http")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LookalikeWarning {
    pub page_domain: String,
    pub imitates: String,
    pub reason: String,
}

fn label(domain: &str) -> &str {
    domain.split('.').next().unwrap_or(domain)
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for i in 1..=a.len() {
        let mut cur = vec![i; b.len() + 1];
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
        }
        prev = cur;
    }
    prev[b.len()]
}

/// Detects a page that imitates a domain the user has credentials for.
/// `known` are registrable domains from the vault. Exact matches are never lookalikes.
pub fn detect_lookalike(page_url: &str, known: &[String]) -> Option<LookalikeWarning> {
    let page = parse(page_url)?;
    let page_domain = page.registrable_domain.clone()?;
    if known.iter().any(|k| k == &page_domain) {
        return None;
    }
    let (page_unicode, idna_ok) = idna::domain_to_unicode(&page_domain);
    let page_skeleton: String = skeleton(&page_unicode).collect();
    let page_label = label(&page_domain);
    let is_idn = page_domain.split('.').any(|l| l.starts_with("xn--")) || idna_ok.is_err();

    for k in known {
        let (k_unicode, _) = idna::domain_to_unicode(k);
        let k_skeleton: String = skeleton(&k_unicode).collect();
        let warn = |reason: &str| {
            Some(LookalikeWarning { page_domain: page_unicode.clone(), imitates: k.clone(), reason: reason.into() })
        };
        if page_skeleton == k_skeleton {
            return warn("uses look-alike characters");
        }
        // `arevei.com.evil.io`, `arevei-com.login.io`: the known domain embedded in another site's host.
        let k_label = label(k);
        if k_label.len() >= 4 && page.host.contains(k.as_str()) {
            return warn("contains the real domain name inside a different site");
        }
        if k_label.len() >= 5 && page_label != k_label && levenshtein(page_label, k_label) <= 1 {
            return warn("is one character away from a saved site");
        }
        if is_idn && k_label.len() >= 4 && page_skeleton.contains(&skeleton(k_label).collect::<String>()) {
            return warn("is an internationalized domain resembling a saved site");
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(url: &str, mode: MatchMode) -> UrlEntry {
        UrlEntry { url: url.into(), match_mode: mode, allowed_frames: vec![] }
    }

    #[test]
    fn domain_matching() {
        let d = e("https://accounts.example.co.uk/login", MatchMode::Domain);
        assert!(url_matches(&d, "https://www.example.co.uk/"));
        assert!(!url_matches(&d, "https://example.com/"));
        assert!(!url_matches(&d, "https://example.co.uk.evil.com/"));
        assert!(!url_matches(&d, "ftp://example.co.uk/"));
    }

    #[test]
    fn psl_private_section() {
        let d = e("https://alice.github.io", MatchMode::Domain);
        assert!(url_matches(&d, "https://alice.github.io/repo"));
        assert!(!url_matches(&d, "https://bob.github.io/"));
    }

    #[test]
    fn host_and_exact() {
        let h = e("https://admin.acme.com", MatchMode::Host);
        assert!(url_matches(&h, "https://admin.acme.com/x"));
        assert!(!url_matches(&h, "https://www.acme.com/"));
        let x = e("https://acme.com/wp-admin", MatchMode::Exact);
        assert!(url_matches(&x, "https://acme.com/wp-admin/login.php?x=1"));
        assert!(!url_matches(&x, "https://acme.com/"));
        assert!(!url_matches(&e("https://acme.com", MatchMode::Never), "https://acme.com"));
    }

    #[test]
    fn scheme_less_saved_url() {
        assert!(url_matches(&e("acme.com", MatchMode::Domain), "https://login.acme.com"));
    }

    #[test]
    fn downgrade() {
        let d = e("https://acme.com", MatchMode::Domain);
        assert!(is_insecure_downgrade(&d, "http://acme.com/login"));
        assert!(!is_insecure_downgrade(&d, "https://acme.com/login"));
    }

    #[test]
    fn lookalikes() {
        let known = vec!["arevei.com".to_string(), "paypal.com".to_string(), "github.com".to_string()];
        assert!(detect_lookalike("https://arevei.com/x", &known).is_none());
        assert!(detect_lookalike("https://unrelated.org", &known).is_none());
        // Typosquat.
        assert!(detect_lookalike("https://arevel.com", &known).is_some());
        assert!(detect_lookalike("https://paypa1.com", &known).is_some());
        // Cyrillic 'а' (U+0430) homograph.
        assert!(detect_lookalike("https://\u{0430}revei.com", &known).is_some());
        // Embedded in another registrable domain.
        assert!(detect_lookalike("https://arevei.com.evil.io/login", &known).is_some());
        assert!(detect_lookalike("https://github.com-login.net", &known).is_some());
    }
}
