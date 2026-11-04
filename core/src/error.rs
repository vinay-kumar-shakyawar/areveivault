use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    /// Authentication failed: wrong key, tampered ciphertext, or mismatched context.
    /// Deliberately carries no detail.
    #[error("decryption failed")]
    Decrypt,
    #[error("unsupported format or version")]
    Format,
    #[error("key derivation parameters are below the security floor")]
    WeakKdfParams,
    #[error("invalid secret key")]
    InvalidSecretKey,
    #[error("signature verification failed")]
    BadSignature,
    #[error("vault is locked")]
    Locked,
    #[error("not found: {0}")]
    NotFound(String),
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("authentication protocol error")]
    Opaque,
    #[error("parse error: {0}")]
    Parse(String),
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Parse(e.to_string())
    }
}

impl From<base64::DecodeError> for Error {
    fn from(_: base64::DecodeError) -> Self {
        Error::Parse("invalid base64".into())
    }
}
