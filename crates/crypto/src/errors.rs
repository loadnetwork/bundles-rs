use thiserror::Error;

/// Error type shared across the `crypto` crate.
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("invalid signature length: expected {expected}, got {actual}")]
    InvalidSignatureLength { expected: usize, actual: usize },

    #[error("invalid key format: {0}")]
    InvalidKeyFormat(String),

    #[error("signature verification failed")]
    VerificationFailed,

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),

    #[error("missing private key")]
    MissingPrivateKey,
}

pub type Result<T> = std::result::Result<T, Error>;
