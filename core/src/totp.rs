//! HOTP (RFC 4226) / TOTP (RFC 6238) and `otpauth://` URI handling.
//! Used client-side for vault authenticators and server-side for account 2FA.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    pub fn parse(s: &str) -> Result<Self> {
        match s.to_ascii_uppercase().replace('-', "").as_str() {
            "SHA1" | "" => Ok(Algorithm::Sha1),
            "SHA256" => Ok(Algorithm::Sha256),
            "SHA512" => Ok(Algorithm::Sha512),
            _ => Err(Error::Invalid("unsupported TOTP algorithm".into())),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub struct TotpConfig {
    pub issuer: String,
    pub account: String,
    /// Base32 secret (normalized, no padding).
    pub secret: String,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
}

impl std::fmt::Debug for TotpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TotpConfig").field("issuer", &self.issuer).field("account", &self.account).finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TotpCode {
    pub code: String,
    pub remaining: u64,
    pub period: u64,
}

pub fn decode_base32(secret: &str) -> Result<Zeroizing<Vec<u8>>> {
    let cleaned: String = secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if cleaned.is_empty() {
        return Err(Error::Invalid("empty TOTP secret".into()));
    }
    base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &cleaned)
        .map(Zeroizing::new)
        .ok_or_else(|| Error::Invalid("TOTP secret is not valid base32".into()))
}

pub fn generate_secret() -> String {
    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &crate::keys::random_bytes::<20>())
}

fn hmac_digest(alg: Algorithm, key: &[u8], msg: &[u8]) -> Vec<u8> {
    macro_rules! run {
        ($h:ty) => {{
            let mut m = <Hmac<$h> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
            m.update(msg);
            m.finalize().into_bytes().to_vec()
        }};
    }
    match alg {
        Algorithm::Sha1 => run!(sha1::Sha1),
        Algorithm::Sha256 => run!(sha2::Sha256),
        Algorithm::Sha512 => run!(sha2::Sha512),
    }
}

pub fn hotp(key: &[u8], counter: u64, digits: u32, alg: Algorithm) -> String {
    let h = hmac_digest(alg, key, &counter.to_be_bytes());
    let offset = (h[h.len() - 1] & 0x0f) as usize;
    let bin = ((h[offset] as u32 & 0x7f) << 24)
        | ((h[offset + 1] as u32) << 16)
        | ((h[offset + 2] as u32) << 8)
        | (h[offset + 3] as u32);
    let modulo = 10u64.pow(digits);
    format!("{:0width$}", bin as u64 % modulo, width = digits as usize)
}

impl TotpConfig {
    pub fn new(secret: &str) -> Result<Self> {
        decode_base32(secret)?;
        Ok(TotpConfig {
            issuer: String::new(),
            account: String::new(),
            secret: normalize_secret(secret),
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
        })
    }

    pub fn validate(&self) -> Result<()> {
        decode_base32(&self.secret)?;
        if !(6..=8).contains(&self.digits) {
            return Err(Error::Invalid("TOTP digits must be 6-8".into()));
        }
        if self.period == 0 || self.period > 600 {
            return Err(Error::Invalid("TOTP period out of range".into()));
        }
        Ok(())
    }

    pub fn code_at(&self, unix: u64) -> Result<TotpCode> {
        self.validate()?;
        let key = decode_base32(&self.secret)?;
        Ok(TotpCode {
            code: hotp(&key, unix / self.period, self.digits, self.algorithm),
            remaining: self.period - (unix % self.period),
            period: self.period,
        })
    }

    /// Verify with ±`window` steps of clock skew. Returns the matched time step
    /// so the caller can reject replays of the same step.
    pub fn verify(&self, code: &str, unix: u64, window: u64) -> Option<u64> {
        let key = decode_base32(&self.secret).ok()?;
        let step = unix / self.period;
        for s in step.saturating_sub(window)..=step + window {
            let candidate = hotp(&key, s, self.digits, self.algorithm);
            if subtle::ConstantTimeEq::ct_eq(candidate.as_bytes(), code.trim().as_bytes()).into() {
                return Some(s);
            }
        }
        None
    }

    /// Accepts `otpauth://totp/...` URIs or a bare base32 secret.
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        if !input.to_ascii_lowercase().starts_with("otpauth://") {
            return Self::new(input);
        }
        let url = url::Url::parse(input).map_err(|_| Error::Invalid("invalid otpauth URI".into()))?;
        if url.host_str().map(|h| h.to_ascii_lowercase()) != Some("totp".into()) {
            return Err(Error::Invalid("only TOTP (not HOTP) URIs are supported".into()));
        }
        let label = percent_decode(url.path().trim_start_matches('/'));
        let (label_issuer, account) = match label.split_once(':') {
            Some((i, a)) => (i.trim().to_string(), a.trim().to_string()),
            None => (String::new(), label.trim().to_string()),
        };
        let mut cfg = TotpConfig {
            issuer: label_issuer,
            account,
            secret: String::new(),
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
        };
        for (k, v) in url.query_pairs() {
            match k.to_ascii_lowercase().as_str() {
                "secret" => cfg.secret = normalize_secret(&v),
                "issuer" => cfg.issuer = v.to_string(),
                "algorithm" => cfg.algorithm = Algorithm::parse(&v)?,
                "digits" => cfg.digits = v.parse().map_err(|_| Error::Invalid("digits".into()))?,
                "period" => cfg.period = v.parse().map_err(|_| Error::Invalid("period".into()))?,
                _ => {}
            }
        }
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn to_uri(&self) -> String {
        let label = if self.issuer.is_empty() {
            self.account.clone()
        } else {
            format!("{}:{}", self.issuer, self.account)
        };
        let mut u = url::Url::parse("otpauth://totp/").unwrap();
        u.set_path(&label);
        u.query_pairs_mut()
            .append_pair("secret", &self.secret)
            .append_pair("issuer", &self.issuer)
            .append_pair("algorithm", match self.algorithm {
                Algorithm::Sha1 => "SHA1",
                Algorithm::Sha256 => "SHA256",
                Algorithm::Sha512 => "SHA512",
            })
            .append_pair("digits", &self.digits.to_string())
            .append_pair("period", &self.period.to_string());
        u.to_string()
    }
}

fn normalize_secret(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

fn percent_decode(s: &str) -> String {
    url::form_urlencoded::parse(format!("x={}", s.replace('+', "%2B")).as_bytes())
        .next()
        .map(|(_, v)| v.into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4226_hotp_vectors() {
        let key = b"12345678901234567890";
        let expected = [
            "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489",
        ];
        for (c, e) in expected.iter().enumerate() {
            assert_eq!(hotp(key, c as u64, 6, Algorithm::Sha1), *e);
        }
    }

    #[test]
    fn rfc6238_totp_vectors() {
        let k1 = b"12345678901234567890";
        let k256 = b"12345678901234567890123456789012";
        let k512 = b"1234567890123456789012345678901234567890123456789012345678901234";
        let cases: &[(u64, &str, &str, &str)] = &[
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        for &(t, s1, s256, s512) in cases {
            assert_eq!(hotp(k1, t / 30, 8, Algorithm::Sha1), s1, "sha1 t={t}");
            assert_eq!(hotp(k256, t / 30, 8, Algorithm::Sha256), s256, "sha256 t={t}");
            assert_eq!(hotp(k512, t / 30, 8, Algorithm::Sha512), s512, "sha512 t={t}");
        }
    }

    #[test]
    fn google_authenticator_compatible_uri() {
        // Base32 of "12345678901234567890" is GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ.
        let cfg = TotpConfig::parse(
            "otpauth://totp/ACME%20Co:john.doe@email.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30",
        )
        .unwrap();
        assert_eq!(cfg.issuer, "ACME Co");
        assert_eq!(cfg.account, "john.doe@email.com");
        // 6-digit truncation of RFC 6238 vector (94287082 → 287082).
        assert_eq!(cfg.code_at(59).unwrap().code, "287082");
        assert_eq!(cfg.code_at(59).unwrap().remaining, 1);

        let again = TotpConfig::parse(&cfg.to_uri()).unwrap();
        assert_eq!(again, cfg);
    }

    #[test]
    fn bare_secret_with_spaces() {
        let cfg = TotpConfig::parse("gezd gnbv gy3t qojq gezd gnbv gy3t qojq").unwrap();
        assert_eq!(cfg.code_at(59).unwrap().code, "287082");
    }

    #[test]
    fn verify_window() {
        let cfg = TotpConfig::new(&generate_secret()).unwrap();
        let now = 1_700_000_000;
        let code = cfg.code_at(now - 30).unwrap().code;
        assert!(cfg.verify(&code, now, 1).is_some());
        assert!(cfg.verify(&code, now + 60, 1).is_none());
    }

    #[test]
    fn rejects_bad_input() {
        assert!(TotpConfig::parse("not base32 !!!").is_err());
        assert!(TotpConfig::parse("otpauth://hotp/x?secret=GEZDGNBV").is_err());
        assert!(TotpConfig::parse("otpauth://totp/x?secret=GEZDGNBV&digits=12").is_err());
    }
}
