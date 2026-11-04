//! Arevei Vault core: all cryptography, vault logic and data models.
//!
//! Every client (web via WASM, extension via WASM, iOS via UniFFI) and the server
//! (OPAQUE + TOTP for account 2FA only) link this crate, so encryption behaves
//! identically everywhere. See `docs/architecture.md` §4–§5.

pub mod encoding;
pub mod engine;
pub mod envelope;
pub mod error;
pub mod export;
pub mod generator;
pub mod import;
pub mod item;
pub mod kdf;
pub mod keys;
pub mod keyset;
pub mod matching;
pub mod opaque;
pub mod padding;
pub mod qr;
pub mod secret_key;
pub mod security;
pub mod share;
pub mod sign;
pub mod strength;
pub mod stream;
pub mod totp;

#[cfg(feature = "wasm")]
pub mod wasm;

pub use error::{Error, Result};
