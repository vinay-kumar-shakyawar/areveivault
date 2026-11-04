//! Two-secret key derivation (architecture §4.2):
//!
//! ```text
//! K_pw     = Argon2id(NFKD(master_password), salt, m, t, p)
//! K_sk     = HKDF-SHA256(SecretKey, salt, "arevei-vault/v1/secret-key")
//! K_master = K_pw XOR K_sk
//! K_auth   = HKDF(K_master, "arevei-vault/v1/opaque-password")   -> OPAQUE input
//! AUK      = HKDF(K_master, "arevei-vault/v1/account-unlock-key") -> wraps ASK
//! ```

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::keys::SymKey;
use crate::secret_key::SecretKey;
use crate::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Argon2id memory cost in KiB.
    pub m_kib: u32,
    /// Iterations.
    pub t: u32,
    /// Parallelism (WASM is single-threaded, so 1).
    pub p: u32,
}

impl KdfParams {
    /// Clients refuse anything weaker than this regardless of what the server sends.
    pub const MIN: KdfParams = KdfParams { m_kib: 64 * 1024, t: 3, p: 1 };
    pub const DEFAULT: KdfParams = KdfParams { m_kib: 64 * 1024, t: 3, p: 1 };
    /// Upper bounds stop a malicious server from making clients allocate unbounded memory.
    const MAX_M_KIB: u32 = 1024 * 1024;
    const MAX_T: u32 = 20;
    const MAX_P: u32 = 8;

    pub fn validate(&self) -> Result<()> {
        if self.m_kib < Self::MIN.m_kib || self.t < Self::MIN.t || self.p < Self::MIN.p {
            return Err(Error::WeakKdfParams);
        }
        if self.m_kib > Self::MAX_M_KIB || self.t > Self::MAX_T || self.p > Self::MAX_P {
            return Err(Error::Invalid("KDF parameters out of range".into()));
        }
        Ok(())
    }
}

pub struct Derived {
    pub k_auth: Zeroizing<[u8; 32]>,
    pub auk: SymKey,
}

pub fn derive(password: &str, secret_key: &SecretKey, salt: &[u8; 16], params: KdfParams) -> Result<Derived> {
    params.validate()?;
    derive_unchecked(password, secret_key, salt, params)
}

/// Same as [`derive`] without the parameter floor. Only for tests and for
/// verifying published vectors; never exposed to the WASM boundary.
pub(crate) fn derive_unchecked(
    password: &str,
    secret_key: &SecretKey,
    salt: &[u8; 16],
    params: KdfParams,
) -> Result<Derived> {
    let k_pw = argon2id(password, salt, params)?;

    let mut k_sk = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), secret_key.as_bytes())
        .expand(b"arevei-vault/v1/secret-key", &mut *k_sk)
        .expect("32 bytes is a valid HKDF output length");

    let mut k_master = Zeroizing::new([0u8; 32]);
    for i in 0..32 {
        k_master[i] = k_pw[i] ^ k_sk[i];
    }

    let hk = Hkdf::<Sha256>::from_prk(&*k_master).expect("32-byte PRK is valid");
    let mut k_auth = Zeroizing::new([0u8; 32]);
    hk.expand(b"arevei-vault/v1/opaque-password", &mut *k_auth).unwrap();
    let mut auk = Zeroizing::new([0u8; 32]);
    hk.expand(b"arevei-vault/v1/account-unlock-key", &mut *auk).unwrap();

    Ok(Derived { k_auth, auk: SymKey::from_bytes(*auk) })
}

pub fn argon2id(password: &str, salt: &[u8], params: KdfParams) -> Result<Zeroizing<[u8; 32]>> {
    let normalized = Zeroizing::new(password.nfkd().collect::<String>());
    let p = Params::new(params.m_kib, params.t, params.p, Some(32))
        .map_err(|_| Error::Invalid("argon2 params".into()))?;
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
        .hash_password_into(normalized.as_bytes(), salt, &mut *out)
        .map_err(|_| Error::Invalid("argon2".into()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::ParamsBuilder;

    const FAST: KdfParams = KdfParams { m_kib: 64, t: 1, p: 1 };

    #[test]
    fn floor_is_enforced() {
        let sk = SecretKey::generate();
        assert!(matches!(derive("pw", &sk, &[0; 16], FAST), Err(Error::WeakKdfParams)));
        assert!(KdfParams { m_kib: 1 << 30, t: 3, p: 1 }.validate().is_err());
        assert!(KdfParams::DEFAULT.validate().is_ok());
    }

    #[test]
    fn both_secrets_matter() {
        let sk1 = SecretKey::generate();
        let sk2 = SecretKey::generate();
        let salt = [7u8; 16];
        let a = derive_unchecked("pw", &sk1, &salt, FAST).unwrap();
        let b = derive_unchecked("pw", &sk1, &salt, FAST).unwrap();
        let c = derive_unchecked("pw", &sk2, &salt, FAST).unwrap();
        let d = derive_unchecked("pw2", &sk1, &salt, FAST).unwrap();
        assert_eq!(a.auk, b.auk);
        assert_eq!(*a.k_auth, *b.k_auth);
        assert_ne!(a.auk, c.auk);
        assert_ne!(a.auk, d.auk);
        // The OPAQUE input and the unlock key are independent.
        assert_ne!(&*a.k_auth, a.auk.as_bytes());
    }

    #[test]
    fn unicode_is_normalized() {
        let sk = SecretKey::generate();
        // "é" precomposed vs. "e" + combining acute.
        let a = derive_unchecked("caf\u{e9}", &sk, &[1; 16], FAST).unwrap();
        let b = derive_unchecked("cafe\u{301}", &sk, &[1; 16], FAST).unwrap();
        assert_eq!(a.auk, b.auk);
    }

    #[test]
    fn default_params_work() {
        let sk = SecretKey::generate();
        assert!(derive("correct horse battery staple", &sk, &[3; 16], KdfParams::DEFAULT).is_ok());
    }

    /// RFC 9106 §5.3 Argon2id test vector, run through the same `argon2` crate.
    #[test]
    fn rfc9106_argon2id_vector() {
        let params = ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .data(argon2::AssociatedData::new(&[0x04; 12]).unwrap())
            .output_len(32)
            .build()
            .unwrap();
        let a = Argon2::new_with_secret(&[0x03; 8], Algorithm::Argon2id, Version::V0x13, params).unwrap();
        let mut out = [0u8; 32];
        a.hash_password_into(&[0x01; 32], &[0x02; 16], &mut out).unwrap();
        assert_eq!(
            hex::encode(out),
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"
        );
    }

    /// RFC 5869 Test Case 1 (HKDF-SHA256).
    #[test]
    fn rfc5869_hkdf_vector() {
        let ikm = [0x0b; 22];
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let mut okm = [0u8; 42];
        Hkdf::<Sha256>::new(Some(&salt), &ikm).expand(&info, &mut okm).unwrap();
        assert_eq!(
            hex::encode(okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }
}
