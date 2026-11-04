//! The user's keyset (architecture §4.3): ASK wrapped by AUK; private keys and
//! the Personal Vault Key wrapped by ASK. Only `EncryptedKeyset` ever leaves the client.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::encoding::{b64, unb64, unb64_array, Aad};
use crate::envelope;
use crate::kdf::KdfParams;
use crate::keys::SymKey;
use crate::{share, sign, Error, Result};

const PRIVATE_BUNDLE_VERSION: u8 = 1;

pub struct UnlockedKeyset {
    pub user_id: String,
    pub ask: SymKey,
    pub enc_sk: Zeroizing<[u8; 32]>,
    pub sign_sk: Zeroizing<[u8; 32]>,
    pub personal_vault_key: SymKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PublicKeys {
    pub x25519: String,
    pub ed25519: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EncryptedKeyset {
    pub version: u32,
    pub user_id: String,
    pub kdf: KdfParams,
    pub salt: String,
    pub wrapped_ask: String,
    pub private_keys: String,
    pub public_keys: PublicKeys,
}

fn ask_aad(user_id: &str, kdf: &KdfParams, salt: &[u8]) -> Vec<u8> {
    // KDF params and salt are bound here so a server cannot downgrade them (§4.2).
    Aad::new("keyset-ask")
        .str(user_id)
        .u64(kdf.m_kib as u64)
        .u64(kdf.t as u64)
        .u64(kdf.p as u64)
        .part(salt)
        .bytes()
        .to_vec()
}

fn private_aad(user_id: &str, public: &PublicKeys) -> Vec<u8> {
    Aad::new("keyset-private")
        .str(user_id)
        .str(&public.x25519)
        .str(&public.ed25519)
        .bytes()
        .to_vec()
}

fn ask_wrap_aad(user_id: &str, context: &str) -> Vec<u8> {
    Aad::new("ask-wrap").str(user_id).str(context).bytes().to_vec()
}

impl UnlockedKeyset {
    pub fn generate(user_id: &str) -> Self {
        let (enc_sk, _) = share::generate_keypair();
        let (sign_sk, _) = sign::generate_signing_key();
        UnlockedKeyset {
            user_id: user_id.into(),
            ask: SymKey::generate(),
            enc_sk,
            sign_sk,
            personal_vault_key: SymKey::generate(),
        }
    }

    pub fn public_keys(&self) -> PublicKeys {
        PublicKeys {
            x25519: b64(&share::public_from_private(&self.enc_sk).expect("valid generated key")),
            ed25519: b64(&sign::verifying_key(&self.sign_sk)),
        }
    }

    fn private_bundle(&self) -> Zeroizing<Vec<u8>> {
        let mut v = Zeroizing::new(Vec::with_capacity(97));
        v.push(PRIVATE_BUNDLE_VERSION);
        v.extend_from_slice(&*self.enc_sk);
        v.extend_from_slice(&*self.sign_sk);
        v.extend_from_slice(self.personal_vault_key.as_bytes());
        v
    }

    pub fn encrypt(&self, auk: &SymKey, kdf: KdfParams, salt: &[u8; 16]) -> EncryptedKeyset {
        let public_keys = self.public_keys();
        EncryptedKeyset {
            version: 1,
            user_id: self.user_id.clone(),
            kdf,
            salt: b64(salt),
            wrapped_ask: b64(&envelope::seal(auk, self.ask.as_bytes(), &ask_aad(&self.user_id, &kdf, salt))),
            private_keys: b64(&envelope::seal(
                &self.ask,
                &self.private_bundle(),
                &private_aad(&self.user_id, &public_keys),
            )),
            public_keys,
        }
    }

    /// Wrap a copy of the ASK under another key (passkey PRF, device key).
    pub fn wrap_ask(&self, key: &SymKey, context: &str) -> String {
        b64(&envelope::seal(key, self.ask.as_bytes(), &ask_wrap_aad(&self.user_id, context)))
    }

    /// Serialize for in-memory session storage (extension `storage.session`).
    pub fn to_session_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut v = Zeroizing::new(Vec::new());
        v.extend_from_slice(self.ask.as_bytes());
        v.extend_from_slice(&self.private_bundle());
        v.extend_from_slice(self.user_id.as_bytes());
        v
    }

    pub fn from_session_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 32 + 97 {
            return Err(Error::Format);
        }
        let ask = SymKey::from_slice(&b[..32])?;
        let ks = Self::from_bundle(String::from_utf8(b[129..].to_vec()).map_err(|_| Error::Format)?, ask, &b[32..129])?;
        Ok(ks)
    }

    fn from_bundle(user_id: String, ask: SymKey, bundle: &[u8]) -> Result<Self> {
        if bundle.len() != 97 || bundle[0] != PRIVATE_BUNDLE_VERSION {
            return Err(Error::Format);
        }
        Ok(UnlockedKeyset {
            user_id,
            ask,
            enc_sk: Zeroizing::new(bundle[1..33].try_into().unwrap()),
            sign_sk: Zeroizing::new(bundle[33..65].try_into().unwrap()),
            personal_vault_key: SymKey::from_slice(&bundle[65..97])?,
        })
    }
}

impl EncryptedKeyset {
    pub fn salt_bytes(&self) -> Result<[u8; 16]> {
        unb64_array(&self.salt)
    }

    pub fn decrypt(&self, auk: &SymKey) -> Result<UnlockedKeyset> {
        self.kdf.validate()?;
        let salt = self.salt_bytes()?;
        let ask_bytes = envelope::open(auk, &unb64(&self.wrapped_ask)?, &ask_aad(&self.user_id, &self.kdf, &salt))?;
        self.finish_unlock(SymKey::from_slice(&ask_bytes)?)
    }

    /// Unlock with an ASK copy wrapped by another key (see `wrap_ask`).
    pub fn decrypt_with_wrapped_ask(&self, key: &SymKey, wrapped: &str, context: &str) -> Result<UnlockedKeyset> {
        let ask_bytes = envelope::open(key, &unb64(wrapped)?, &ask_wrap_aad(&self.user_id, context))?;
        self.finish_unlock(SymKey::from_slice(&ask_bytes)?)
    }

    fn finish_unlock(&self, ask: SymKey) -> Result<UnlockedKeyset> {
        let bundle = envelope::open(
            &ask,
            &unb64(&self.private_keys)?,
            &private_aad(&self.user_id, &self.public_keys),
        )?;
        let ks = UnlockedKeyset::from_bundle(self.user_id.clone(), ask, &bundle)?;
        // Public keys stored next to the ciphertext must match the private keys.
        if ks.public_keys() != self.public_keys {
            return Err(Error::Decrypt);
        }
        Ok(ks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let ks = UnlockedKeyset::generate("user-1");
        let auk = SymKey::generate();
        let enc = ks.encrypt(&auk, KdfParams::DEFAULT, &[9; 16]);
        let back = enc.decrypt(&auk).unwrap();
        assert_eq!(back.ask, ks.ask);
        assert_eq!(*back.enc_sk, *ks.enc_sk);
        assert_eq!(back.personal_vault_key, ks.personal_vault_key);
        assert!(enc.decrypt(&SymKey::generate()).is_err());
    }

    #[test]
    fn kdf_downgrade_is_detected() {
        let ks = UnlockedKeyset::generate("u");
        let auk = SymKey::generate();
        let strong = KdfParams { m_kib: 128 * 1024, t: 4, p: 1 };
        let mut enc = ks.encrypt(&auk, strong, &[1; 16]);
        // Server rewrites params to the (still-valid) floor: AAD mismatch.
        enc.kdf = KdfParams::MIN;
        assert!(enc.decrypt(&auk).is_err());
        // Server rewrites below the floor: rejected before decrypting.
        enc.kdf = KdfParams { m_kib: 1024, t: 1, p: 1 };
        assert!(matches!(enc.decrypt(&auk), Err(Error::WeakKdfParams)));
    }

    #[test]
    fn public_key_substitution_is_detected() {
        let ks = UnlockedKeyset::generate("u");
        let other = UnlockedKeyset::generate("u");
        let auk = SymKey::generate();
        let mut enc = ks.encrypt(&auk, KdfParams::DEFAULT, &[1; 16]);
        enc.public_keys = other.public_keys();
        assert!(enc.decrypt(&auk).is_err());
    }

    #[test]
    fn wrapped_ask_and_session_bytes() {
        let ks = UnlockedKeyset::generate("u");
        let auk = SymKey::generate();
        let enc = ks.encrypt(&auk, KdfParams::DEFAULT, &[1; 16]);
        let device = SymKey::generate();
        let w = ks.wrap_ask(&device, "passkey:cred-1");
        assert!(enc.decrypt_with_wrapped_ask(&device, &w, "passkey:cred-1").is_ok());
        assert!(enc.decrypt_with_wrapped_ask(&device, &w, "passkey:cred-2").is_err());

        let s = UnlockedKeyset::from_session_bytes(&ks.to_session_bytes()).unwrap();
        assert_eq!(s.user_id, "u");
        assert_eq!(s.ask, ks.ask);
    }
}
