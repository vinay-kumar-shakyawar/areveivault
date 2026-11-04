//! Base64 helpers and serde adapters. All binary on the wire is standard base64.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

pub fn b64(data: &[u8]) -> String {
    STANDARD.encode(data)
}

pub fn unb64(s: &str) -> crate::Result<Vec<u8>> {
    Ok(STANDARD.decode(s.trim())?)
}

pub fn unb64_array<const N: usize>(s: &str) -> crate::Result<[u8; N]> {
    unb64(s)?
        .try_into()
        .map_err(|_| crate::Error::Parse(format!("expected {N} bytes")))
}

/// `#[serde(with = "crate::encoding::b64_serde")]` for `Vec<u8>` fields.
pub mod b64_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::b64(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        super::unb64(&s).map_err(serde::de::Error::custom)
    }
}

/// Builds associated data: a domain-separated, length-prefixed list of parts.
/// Binding ids/versions here is what stops a server from swapping ciphertexts
/// between objects or slots (architecture §5).
pub struct Aad(Vec<u8>);

impl Aad {
    pub fn new(object_type: &str) -> Self {
        let mut a = Aad(Vec::with_capacity(128));
        a = a.part(b"arevei-vault/v1");
        a.part(object_type.as_bytes())
    }

    pub fn part(mut self, bytes: &[u8]) -> Self {
        self.0.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        self.0.extend_from_slice(bytes);
        self
    }

    pub fn str(self, s: &str) -> Self {
        self.part(s.as_bytes())
    }

    pub fn u64(self, n: u64) -> Self {
        self.part(&n.to_be_bytes())
    }

    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}
