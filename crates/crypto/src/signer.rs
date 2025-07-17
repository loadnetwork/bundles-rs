use anyhow::{Result, anyhow};
use sha2::Sha256;

use crate::{arweave, ed25519, ethereum, solana};

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

impl SignatureType {
    /// Verify a signature given the public key bytes.
    pub fn verify(&self, owner: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
        match self {
            SignatureType::Arweave => {
                use rsa::{
                    BigUint, RsaPublicKey,
                    pss::{Signature, VerifyingKey},
                    signature::Verifier,
                };

                if owner.len() != 512 || signature.len() != 512 {
                    return Ok(false);
                }

                let n = BigUint::from_bytes_be(owner);
                let e = BigUint::from(65537u32);
                let pk = RsaPublicKey::new(n, e)?;
                let verifier = VerifyingKey::<Sha256>::new_with_salt_len(pk, 32);
                let sig = Signature::try_from(signature)?;
                Ok(verifier.verify(message, &sig).is_ok())
            }
            SignatureType::Ed25519 | SignatureType::Solana => {
                use ed25519_dalek::{Signature, Verifier, VerifyingKey};

                if owner.len() != 32 || signature.len() != 64 {
                    return Ok(false);
                }
                let vk = VerifyingKey::from_bytes(
                    owner.try_into().map_err(|_| anyhow!("invalid owner length"))?,
                )?;
                let sig = Signature::from_bytes(
                    signature.try_into().map_err(|_| anyhow!("invalid signature length"))?,
                );
                Ok(vk.verify(message, &sig).is_ok())
            }
            SignatureType::Ethereum => {
                use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};

                if owner.len() != 65 || signature.len() != 65 {
                    return Ok(false);
                }
                let vk = VerifyingKey::from_sec1_bytes(owner)?;
                let msg_hash = crate::ethereum::EthereumSigner::eth_message_hash(message);
                let recovery_id = RecoveryId::try_from(signature[64].wrapping_sub(27))
                    .map_err(|_| anyhow!("Invalid recovery id"))?;
                let sig = K256Signature::from_slice(&signature[..64])?;
                let recovered = VerifyingKey::recover_from_prehash(&msg_hash, &sig, recovery_id)?;
                Ok(recovered == vk)
            }
            SignatureType::None => Ok(false),
        }
    }
}
