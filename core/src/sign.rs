//! Ed25519 signatures: key grants, membership certificates (architecture §8.2).

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::encoding::{b64, unb64, unb64_array, Aad};
use crate::{Error, Result};

pub fn generate_signing_key() -> (Zeroizing<[u8; 32]>, [u8; 32]) {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    (Zeroizing::new(sk.to_bytes()), sk.verifying_key().to_bytes())
}

pub fn verifying_key(sk: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(sk).verifying_key().to_bytes()
}

pub fn sign(sk: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(sk).sign(msg).to_bytes()
}

pub fn verify(pk: &[u8; 32], msg: &[u8], sig: &[u8]) -> Result<()> {
    let vk = VerifyingKey::from_bytes(pk).map_err(|_| Error::BadSignature)?;
    let sig: [u8; 64] = sig.try_into().map_err(|_| Error::BadSignature)?;
    vk.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&sig))
        .map_err(|_| Error::BadSignature)
}

/// Human-comparable fingerprint for out-of-band verification, e.g. `3F2A 91C0 ...`.
pub fn fingerprint(public_key: &[u8]) -> String {
    let h = Sha256::digest([b"arevei-vault/v1/fingerprint".as_slice(), public_key].concat());
    hex::encode_upper(&h[..16])
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Binds a user's identity to their public keys, signed by the org signing key.
/// Clients verify this before wrapping any vault key to a colleague, so a
/// malicious server cannot substitute its own public key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MembershipCert {
    pub org_id: String,
    pub user_id: String,
    pub email: String,
    pub x25519: String,
    pub ed25519: String,
    pub issued_at: i64,
    pub issuer_id: String,
    pub signature: String,
}

impl MembershipCert {
    fn message(&self) -> Vec<u8> {
        Aad::new("membership-cert")
            .str(&self.org_id)
            .str(&self.user_id)
            .str(&self.email.to_lowercase())
            .str(&self.x25519)
            .str(&self.ed25519)
            .u64(self.issued_at as u64)
            .str(&self.issuer_id)
            .bytes()
            .to_vec()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        org_id: &str,
        user_id: &str,
        email: &str,
        x25519: &str,
        ed25519: &str,
        issued_at: i64,
        issuer_id: &str,
        org_sign_sk: &[u8; 32],
    ) -> Self {
        let mut c = MembershipCert {
            org_id: org_id.into(),
            user_id: user_id.into(),
            email: email.to_lowercase(),
            x25519: x25519.into(),
            ed25519: ed25519.into(),
            issued_at,
            issuer_id: issuer_id.into(),
            signature: String::new(),
        };
        c.signature = b64(&sign(org_sign_sk, &c.message()));
        c
    }

    pub fn verify(&self, org_sign_pk: &[u8; 32]) -> Result<()> {
        verify(org_sign_pk, &self.message(), &unb64(&self.signature)?)
    }

    pub fn x25519_bytes(&self) -> Result<[u8; 32]> {
        unb64_array(&self.x25519)
    }

    pub fn ed25519_bytes(&self) -> Result<[u8; 32]> {
        unb64_array(&self.ed25519)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8032 §7.1 Test 1 (empty message).
    #[test]
    fn rfc8032_vector() {
        let sk: [u8; 32] = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            hex::encode(verifying_key(&sk)),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        assert_eq!(
            hex::encode(sign(&sk, b"")),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
    }

    #[test]
    fn cert_verifies_and_rejects_tampering() {
        let (org_sk, org_pk) = generate_signing_key();
        let cert = MembershipCert::issue("org", "u1", "A@arevei.com", "eA==", "eQ==", 1, "admin", &org_sk);
        assert_eq!(cert.email, "a@arevei.com");
        cert.verify(&org_pk).unwrap();

        let mut swapped = cert.clone();
        swapped.x25519 = "ZZ==".into();
        assert!(swapped.verify(&org_pk).is_err());

        let (_, other_pk) = generate_signing_key();
        assert!(cert.verify(&other_pk).is_err());
    }

    #[test]
    fn fingerprint_is_stable_and_grouped() {
        let f = fingerprint(&[1, 2, 3]);
        assert_eq!(f, fingerprint(&[1, 2, 3]));
        assert_eq!(f.split(' ').count(), 8);
    }
}
