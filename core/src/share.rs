//! Key sharing with HPKE (RFC 9180, base mode,
//! DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305) plus signed grants.

use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::encoding::{b64, unb64, Aad};
use crate::keys::SymKey;
use crate::sign;
use crate::{Error, Result};

type Kem = X25519HkdfSha256;
const ENCAPPED_LEN: usize = 32;

pub fn generate_keypair() -> (Zeroizing<[u8; 32]>, [u8; 32]) {
    let (sk, pk) = Kem::gen_keypair(&mut rand::rngs::OsRng);
    let skb: [u8; 32] = sk.to_bytes().into();
    (Zeroizing::new(skb), pk.to_bytes().into())
}

pub fn public_from_private(sk: &[u8; 32]) -> Result<[u8; 32]> {
    let sk = <Kem as KemTrait>::PrivateKey::from_bytes(sk).map_err(|_| Error::Format)?;
    Ok(Kem::sk_to_pk(&sk).to_bytes().into())
}

/// HPKE-seal arbitrary bytes to a recipient public key. Output: enc || ciphertext.
pub fn seal_to(recipient_pk: &[u8; 32], info: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let pk = <Kem as KemTrait>::PublicKey::from_bytes(recipient_pk).map_err(|_| Error::Format)?;
    let (enc, ct) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, Kem, _>(
        &OpModeS::Base,
        &pk,
        info,
        plaintext,
        b"",
        &mut rand::rngs::OsRng,
    )
    .map_err(|_| Error::Format)?;
    Ok([enc.to_bytes().as_slice(), &ct].concat())
}

pub fn open_from(sk: &[u8; 32], info: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if data.len() < ENCAPPED_LEN {
        return Err(Error::Format);
    }
    let sk = <Kem as KemTrait>::PrivateKey::from_bytes(sk).map_err(|_| Error::Format)?;
    let enc = <Kem as KemTrait>::EncappedKey::from_bytes(&data[..ENCAPPED_LEN]).map_err(|_| Error::Format)?;
    hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeR::Base,
        &sk,
        &enc,
        info,
        &data[ENCAPPED_LEN..],
        b"",
    )
    .map(Zeroizing::new)
    .map_err(|_| Error::Decrypt)
}

/// A symmetric key (vault key, client key, org admin key) wrapped to one member.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeyGrant {
    /// Id of the vault / client / org keyring this key belongs to.
    pub keyring_id: String,
    pub key_version: u32,
    pub recipient_id: String,
    pub grantor_id: String,
    /// HPKE enc || ciphertext, base64.
    pub wrapped: String,
    /// Ed25519 signature by the grantor, base64.
    pub signature: String,
}

fn grant_info(keyring_id: &str, key_version: u32, recipient_id: &str) -> Vec<u8> {
    Aad::new("key-grant")
        .str(keyring_id)
        .u64(key_version as u64)
        .str(recipient_id)
        .bytes()
        .to_vec()
}

fn grant_sig_message(g: &KeyGrant, wrapped: &[u8]) -> Vec<u8> {
    Aad::new("key-grant-sig")
        .str(&g.keyring_id)
        .u64(g.key_version as u64)
        .str(&g.recipient_id)
        .str(&g.grantor_id)
        .part(wrapped)
        .bytes()
        .to_vec()
}

impl KeyGrant {
    pub fn create(
        key: &SymKey,
        keyring_id: &str,
        key_version: u32,
        recipient_id: &str,
        recipient_pk: &[u8; 32],
        grantor_id: &str,
        grantor_sign_sk: &[u8; 32],
    ) -> Result<Self> {
        let wrapped = seal_to(recipient_pk, &grant_info(keyring_id, key_version, recipient_id), key.as_bytes())?;
        let mut g = KeyGrant {
            keyring_id: keyring_id.into(),
            key_version,
            recipient_id: recipient_id.into(),
            grantor_id: grantor_id.into(),
            wrapped: b64(&wrapped),
            signature: String::new(),
        };
        g.signature = b64(&sign::sign(grantor_sign_sk, &grant_sig_message(&g, &wrapped)));
        Ok(g)
    }

    /// Verifies the grantor's signature (when their verified key is known) and unwraps.
    pub fn open(&self, my_id: &str, my_enc_sk: &[u8; 32], grantor_pk: Option<&[u8; 32]>) -> Result<SymKey> {
        if self.recipient_id != my_id {
            return Err(Error::Invalid("grant is for another user".into()));
        }
        let wrapped = unb64(&self.wrapped)?;
        if let Some(pk) = grantor_pk {
            sign::verify(pk, &grant_sig_message(self, &wrapped), &unb64(&self.signature)?)?;
        }
        let key = open_from(my_enc_sk, &grant_info(&self.keyring_id, self.key_version, my_id), &wrapped)?;
        SymKey::from_slice(&key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7748 §6.1: Alice's X25519 public key from her private key.
    #[test]
    fn rfc7748_x25519_vector() {
        let sk: [u8; 32] = hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
            .unwrap()
            .try_into()
            .unwrap();
        assert_eq!(
            hex::encode(public_from_private(&sk).unwrap()),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
    }

    #[test]
    fn grant_roundtrip_and_binding() {
        let (bob_sk, bob_pk) = generate_keypair();
        let (alice_sign, alice_vk) = sign::generate_signing_key();
        let vk = SymKey::generate();
        let g = KeyGrant::create(&vk, "vault-1", 2, "bob", &bob_pk, "alice", &alice_sign).unwrap();

        assert_eq!(g.open("bob", &bob_sk, Some(&alice_vk)).unwrap(), vk);

        // Server relabels the grant to a different vault or version: fails.
        let mut relabeled = g.clone();
        relabeled.keyring_id = "vault-2".into();
        assert!(relabeled.open("bob", &bob_sk, None).is_err());
        let mut rever = g.clone();
        rever.key_version = 1;
        assert!(rever.open("bob", &bob_sk, None).is_err());

        // Forged grantor: signature check fails.
        let (_, mallory_vk) = sign::generate_signing_key();
        assert!(g.open("bob", &bob_sk, Some(&mallory_vk)).is_err());

        // Someone else's private key cannot open it.
        let (eve_sk, _) = generate_keypair();
        assert!(g.open("bob", &eve_sk, None).is_err());
    }
}
