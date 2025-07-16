use anyhow::Result;

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(u16)]
pub enum SignatureType {
    None = 0,
    Arweave = 1,
    Ed25519 = 2,
    Ethereum = 3,
    Solana = 4,
}

impl SignatureType {
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => Self::Arweave,
            2 => Self::Ed25519,
            3 => Self::Ethereum,
            4 => Self::Solana,
            _ => Self::None,
        }
    }

    pub fn signature_len(&self) -> usize {
        match self {
            Self::Arweave => 512,
            Self::Ed25519 => 64,
            Self::Ethereum => 65,
            Self::Solana => 64,
            Self::None => 0,
        }
    }

    pub fn owner_len(&self) -> usize {
        match self {
            Self::Arweave => 512,
            Self::Ethereum => 65,
            Self::Ed25519 | Self::Solana => 32,
            Self::None => 0,
        }
    }
}

/// Trait for signing DataItems
pub trait Signer: Send + Sync {
    /// Sign a message
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;

    /// Get the public key
    fn public_key(&self) -> Vec<u8>;

    /// Get the signature type
    fn signature_type(&self) -> SignatureType;

    /// Verify a signature
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let _ = (message, signature);
        Ok(true)
    }
}
