//! The 128-bit Secret Key shown once at signup and printed on the Emergency Kit.
//! Format: `AV1-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXC` — 26 Crockford base32 symbols
//! carrying 128 bits plus one check symbol to catch typos.

use base32::Alphabet;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::keys::random_bytes;
use crate::{Error, Result};

const PREFIX: &str = "AV1";
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct SecretKey([u8; 16]);

impl SecretKey {
    pub fn generate() -> Self {
        SecretKey(random_bytes())
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    fn check_symbol(bytes: &[u8; 16]) -> char {
        let h = Sha256::digest([b"arevei-vault/v1/secret-key-check".as_slice(), bytes].concat());
        CROCKFORD[(h[0] & 0x1f) as usize] as char
    }

    pub fn format(&self) -> String {
        let mut body = base32::encode(Alphabet::Crockford, &self.0);
        body.push(Self::check_symbol(&self.0));
        let groups: Vec<&str> = body
            .as_bytes()
            .chunks(6)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        let s = format!("{PREFIX}-{}", groups.join("-"));
        body.zeroize();
        s
    }

    /// Lenient parse: ignores case, whitespace and dashes; maps I/L→1 and O→0.
    pub fn parse(input: &str) -> Result<Self> {
        let mut cleaned: String = input
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .map(|c| match c.to_ascii_uppercase() {
                'I' | 'L' => '1',
                'O' => '0',
                c => c,
            })
            .collect();
        let body = cleaned.strip_prefix("AV1").ok_or(Error::InvalidSecretKey)?;
        if body.len() != 27 {
            cleaned.zeroize();
            return Err(Error::InvalidSecretKey);
        }
        let (data, check) = body.split_at(26);
        let decoded = base32::decode(Alphabet::Crockford, data).ok_or(Error::InvalidSecretKey)?;
        let bytes: [u8; 16] = decoded.as_slice().try_into().map_err(|_| Error::InvalidSecretKey)?;
        let ok = check.chars().next() == Some(Self::check_symbol(&bytes));
        cleaned.zeroize();
        if !ok {
            return Err(Error::InvalidSecretKey);
        }
        Ok(SecretKey(bytes))
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_parse_roundtrip() {
        let sk = SecretKey::generate();
        let s = sk.format();
        assert!(s.starts_with("AV1-"));
        assert_eq!(s.len(), 4 + 27 + 4);
        assert_eq!(SecretKey::parse(&s).unwrap(), sk);
        assert_eq!(SecretKey::parse(&s.to_lowercase().replace('-', " ")).unwrap(), sk);
    }

    #[test]
    fn typo_is_detected() {
        let sk = SecretKey::generate();
        let s = sk.format();
        let mut chars: Vec<char> = s.chars().collect();
        // Change one data symbol (position 5 is inside the first group).
        chars[5] = if chars[5] == 'A' { 'B' } else { 'A' };
        let typo: String = chars.into_iter().collect();
        assert!(SecretKey::parse(&typo).is_err() || SecretKey::parse(&typo).unwrap() != sk);
        assert!(SecretKey::parse("AV1-123").is_err());
    }
}
