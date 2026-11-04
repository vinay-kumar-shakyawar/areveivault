//! Versioned XChaCha20-Poly1305 envelope (architecture §5).
//!
//! ```text
//! [0]      format version (0x01)
//! [1]      algorithm id   (0x01 = XChaCha20-Poly1305)
//! [2..18]  key id         (SymKey::id of the encrypting key)
//! [18..42] nonce          (24 random bytes)
//! [42..]   ciphertext || tag
//! ```
//! The header is itself authenticated (prepended to the caller's associated data).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::keys::{random_bytes, SymKey};
use crate::{Error, Result};

pub const VERSION: u8 = 1;
pub const ALG_XCHACHA20POLY1305: u8 = 1;
pub const HEADER_LEN: usize = 2 + 16 + 24;
pub const TAG_LEN: usize = 16;

pub fn seal(key: &SymKey, plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    seal_with_nonce(key, plaintext, aad, random_bytes::<24>())
}

fn seal_with_nonce(key: &SymKey, plaintext: &[u8], aad: &[u8], nonce: [u8; 24]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + plaintext.len() + TAG_LEN);
    out.push(VERSION);
    out.push(ALG_XCHACHA20POLY1305);
    out.extend_from_slice(&key.id());
    out.extend_from_slice(&nonce);

    let full_aad = [&out[..], aad].concat();
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad: &full_aad })
        .expect("XChaCha20-Poly1305 encryption cannot fail for in-memory buffers");
    out.extend_from_slice(&ct);
    out
}

pub fn open(key: &SymKey, envelope: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if envelope.len() < HEADER_LEN + TAG_LEN {
        return Err(Error::Format);
    }
    if envelope[0] != VERSION || envelope[1] != ALG_XCHACHA20POLY1305 {
        return Err(Error::Format);
    }
    let header = &envelope[..HEADER_LEN];
    let nonce = &envelope[18..HEADER_LEN];
    let full_aad = [header, aad].concat();
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: &envelope[HEADER_LEN..], aad: &full_aad })
        .map(Zeroizing::new)
        .map_err(|_| Error::Decrypt)
}

/// Key id recorded in an envelope, used to select among key versions.
pub fn key_id(envelope: &[u8]) -> Result<[u8; 16]> {
    if envelope.len() < HEADER_LEN {
        return Err(Error::Format);
    }
    Ok(envelope[2..18].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn roundtrip_and_header() {
        let k = SymKey::generate();
        let env = seal(&k, b"hello", b"ctx");
        assert_eq!(env[0], VERSION);
        assert_eq!(key_id(&env).unwrap(), k.id());
        assert_eq!(&open(&k, &env, b"ctx").unwrap()[..], b"hello");
    }

    #[test]
    fn wrong_key_or_aad_fails() {
        let k = SymKey::generate();
        let env = seal(&k, b"secret", b"item:1");
        assert!(matches!(open(&SymKey::generate(), &env, b"item:1"), Err(Error::Decrypt)));
        assert!(matches!(open(&k, &env, b"item:2"), Err(Error::Decrypt)));
    }

    #[test]
    fn nonces_are_unique() {
        let k = SymKey::generate();
        let a = seal(&k, b"x", b"");
        let b = seal(&k, b"x", b"");
        assert_ne!(a[18..42], b[18..42]);
    }

    proptest! {
        // Flipping any single bit anywhere (header, nonce, ciphertext, tag) must fail.
        #[test]
        fn any_bit_flip_is_rejected(
            msg in proptest::collection::vec(any::<u8>(), 0..256),
            pos in any::<prop::sample::Index>(),
            bit in 0u8..8
        ) {
            let k = SymKey::generate();
            let mut env = seal(&k, &msg, b"aad");
            let i = pos.index(env.len());
            env[i] ^= 1 << bit;
            prop_assert!(open(&k, &env, b"aad").is_err());
        }
    }

    /// draft-irtf-cfrg-xchacha-03 §A.3.1 AEAD_XChaCha20_Poly1305 test vector,
    /// exercised through the same crate primitive the envelope uses.
    #[test]
    fn xchacha_draft_vector() {
        let key: [u8; 32] = hex::decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .unwrap()
            .try_into()
            .unwrap();
        let nonce = hex::decode("404142434445464748494a4b4c4d4e4f5051525354555657").unwrap();
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected_ct = "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e";
        let expected_tag = "c0875924c1c7987947deafd8780acf49";
        let cipher = XChaCha20Poly1305::new(&key.into());
        let out = cipher
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: pt, aad: &aad })
            .unwrap();
        assert_eq!(hex::encode(&out[..out.len() - 16]), expected_ct);
        assert_eq!(hex::encode(&out[out.len() - 16..]), expected_tag);
    }
}
