use anyhow::Result;

use std::array::TryFromSliceError;

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

    pub fn signature_length(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Arweave => 512,
            Self::Ed25519 => 64,
            Self::Ethereum => 65,
            Self::Solana => 64,
        }
    }

    pub fn public_key_length(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Arweave => 512,
            Self::Ed25519 => 32,
            Self::Ethereum => 65,
            Self::Solana => 32,
        }
    }
}
/*
pub trait Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error>;
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool;
    fn public_key(&self) -> Result<Base64, Error>;
    fn wallet_address(&self) -> String;
}

pub trait Signer: Send + Sync {
    fn sign(&self, message: Bytes) -> Result<Bytes, BundlerError>;
    fn sig_type(&self) -> SignerMap;
    fn get_sig_length(&self) -> u16;
    fn get_pub_length(&self) -> u16;
    fn pub_key(&self) -> Bytes;
}
*/

/// Trait for signing DataItems
pub trait Signer: Send + Sync {
    /// Sign a message
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;

    /// Get the public key
    fn public_key(&self) -> Vec<u8>;

    /// Get the signature type
    fn signature_type(&self) -> SignatureType;

    /// Verify a signature (optional, for testing)
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let _ = (message, signature);
        Ok(true) // Default implementation
    }
}
