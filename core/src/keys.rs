use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A 256-bit symmetric key. Zeroized on drop; never `Debug`-printed.
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq, Eq)]
pub struct SymKey([u8; 32]);

impl SymKey {
    pub fn generate() -> Self {
        let mut k = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut k);
        SymKey(k)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        SymKey(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> crate::Result<Self> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| crate::Error::Invalid("key must be 32 bytes".into()))?;
        Ok(SymKey(arr))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Public identifier for this key (16 bytes). A hash of a uniformly random
    /// 256-bit key reveals nothing about it; used to pick the right key version.
    pub fn id(&self) -> [u8; 16] {
        let mut h = Sha256::new();
        h.update(b"arevei-vault/v1/key-id");
        h.update(self.0);
        let out = h.finalize();
        out[..16].try_into().unwrap()
    }
}

impl std::fmt::Debug for SymKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SymKey(<redacted>)")
    }
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}
