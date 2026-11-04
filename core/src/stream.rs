//! Attachment encryption: STREAM construction (XChaCha20-Poly1305, BE32 counter)
//! over 64 KiB chunks. Resists truncation, reordering and chunk splicing.
//!
//! Format: version(1) || key id(16) || nonce prefix(19) || chunk*  (each chunk = ct || tag)

use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::aead::{KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;

use crate::encoding::Aad;
use crate::keys::{random_bytes, SymKey};
use crate::{Error, Result};

pub const CHUNK: usize = 64 * 1024;
const VERSION: u8 = 1;
const HEADER: usize = 1 + 16 + 19;
pub const MAX_FILE: usize = 10 * 1024 * 1024;

fn aad(attachment_id: &str) -> Vec<u8> {
    Aad::new("attachment").str(attachment_id).bytes().to_vec()
}

pub fn encrypt(key: &SymKey, attachment_id: &str, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() > MAX_FILE {
        return Err(Error::Invalid("file exceeds 10 MB".into()));
    }
    let nonce = random_bytes::<19>();
    let aad = aad(attachment_id);
    let mut out = Vec::with_capacity(HEADER + data.len() + (data.len() / CHUNK + 1) * 16);
    out.push(VERSION);
    out.extend_from_slice(&key.id());
    out.extend_from_slice(&nonce);

    let mut enc = EncryptorBE32::from_aead(XChaCha20Poly1305::new(key.as_bytes().into()), nonce.as_slice().into());
    let mut chunks = data.chunks(CHUNK).peekable();
    if chunks.peek().is_none() {
        out.extend(enc.encrypt_last(Payload { msg: &[], aad: &aad }).map_err(|_| Error::Format)?);
        return Ok(out);
    }
    while let Some(c) = chunks.next() {
        if chunks.peek().is_some() {
            out.extend(enc.encrypt_next(Payload { msg: c, aad: &aad }).map_err(|_| Error::Format)?);
        } else {
            out.extend(enc.encrypt_last(Payload { msg: c, aad: &aad }).map_err(|_| Error::Format)?);
            break;
        }
    }
    Ok(out)
}

pub fn decrypt(key: &SymKey, attachment_id: &str, data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < HEADER + 16 || data[0] != VERSION {
        return Err(Error::Format);
    }
    let aad = aad(attachment_id);
    let mut dec =
        DecryptorBE32::from_aead(XChaCha20Poly1305::new(key.as_bytes().into()), data[17..HEADER].into());
    let body = &data[HEADER..];
    let mut out = Vec::with_capacity(body.len());
    let mut chunks = body.chunks(CHUNK + 16).peekable();
    while let Some(c) = chunks.next() {
        if chunks.peek().is_some() {
            out.extend(dec.decrypt_next(Payload { msg: c, aad: &aad }).map_err(|_| Error::Decrypt)?);
        } else {
            out.extend(dec.decrypt_last(Payload { msg: c, aad: &aad }).map_err(|_| Error::Decrypt)?);
            break;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_sizes() {
        let k = SymKey::generate();
        for size in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK + 17] {
            let data: Vec<u8> = (0..size).map(|i| i as u8).collect();
            let ct = encrypt(&k, "a1", &data).unwrap();
            assert_eq!(decrypt(&k, "a1", &ct).unwrap(), data, "size {size}");
        }
    }

    #[test]
    fn truncation_and_context_detected() {
        let k = SymKey::generate();
        let data = vec![7u8; 3 * CHUNK];
        let ct = encrypt(&k, "a1", &data).unwrap();
        // Drop the final chunk: the new last chunk was not encrypted as "last".
        let truncated = &ct[..HEADER + 2 * (CHUNK + 16)];
        assert!(decrypt(&k, "a1", truncated).is_err());
        assert!(decrypt(&k, "a2", &ct).is_err());
        assert!(decrypt(&SymKey::generate(), "a1", &ct).is_err());
    }

    #[test]
    fn size_limit() {
        assert!(encrypt(&SymKey::generate(), "a", &vec![0; MAX_FILE + 1]).is_err());
    }
}
