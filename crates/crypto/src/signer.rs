use crate::errors::*;
use sha2::Sha256;

/// Supported signature algorithms.
///
/// The numeric representation is **ABI‑stable** – do **not** reorder!  New
/// variants must be appended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum SignatureType {
    /// No signature (placeholder)
    None = 0,
    /// Arweave RSA‑PSS 4096/SHA‑256
    Arweave = 1,
    /// Ed25519 (RFC 8032)
    Ed25519 = 2,
    /// Ethereum secp256k1 (ETH‑signed message prefix)
    Ethereum = 3,
}

impl SignatureType {
    /// Create a [`SignatureType`] from its wire‑format representation.
    pub const fn from_u16(value: u16) -> Self {
        match value {
            1 => Self::Arweave,
            2 => Self::Ed25519,
            3 => Self::Ethereum,
            _ => Self::None,
        }
    }

    /// Expected byte‑length of the raw signature for this algorithm.
    pub const fn signature_len(self) -> usize {
        match self {
            Self::Arweave => 512,
            Self::Ed25519 => 64,
            Self::Ethereum => 65,
            Self::None => 0,
        }
    }

    /// Expected byte‑length of the public key/owner field for this algorithm.
    pub const fn owner_len(self) -> usize {
        match self {
            Self::Arweave => 512, // RSA modulus n
            Self::Ethereum => 65, // uncompressed (secp256k1)
            Self::Ed25519 => 32,
            Self::None => 0,
        }
    }

    /// Verify `signature` over `message` with `owner`.
    ///
    /// * `owner`    – serialized public key in the format expected by the corresponding algorithm
    ///   (see [`owner_len`]).
    /// * `message`  – raw message bytes (pre‑hashing handled internally if required by the
    ///   algorithm).
    /// * `signature` – raw signature bytes.
    pub fn verify(&self, owner: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
        match self {
            /* -------------------------------------------------  Arweave  --- */
            SignatureType::Arweave => {
                use rsa::{
                    BigUint, RsaPublicKey,
                    pss::{Signature as PssSig, VerifyingKey},
                    signature::Verifier,
                };

                if owner.len() != 512 || signature.len() != 512 {
                    return Ok(false);
                }

                let n = BigUint::from_bytes_be(owner);
                let pk = RsaPublicKey::new(n, BigUint::from(65_537u32))
                    .map_err(|e| Error::InvalidKeyFormat(e.to_string()))?;
                let sig = PssSig::try_from(signature).map_err(|_| {
                    Error::InvalidSignatureLength { expected: 512, actual: signature.len() }
                })?;

                let salt_lengths = [32, 478];

                for &salt_len in &salt_lengths {
                    let verifier = VerifyingKey::<Sha256>::new_with_salt_len(pk.clone(), salt_len);
                    if verifier.verify(message, &sig).is_ok() {
                        return Ok(true);
                    }
                }

                Ok(false)
            }
            SignatureType::Ed25519 => {
                use ed25519_dalek::{Signature, Verifier, VerifyingKey};

                if owner.len() != 32 || signature.len() != 64 {
                    return Ok(false);
                }

                let vk = VerifyingKey::from_bytes(<&[u8; 32]>::try_from(owner).unwrap())
                    .map_err(|e| Error::InvalidKeyFormat(e.to_string()))?;
                let sig = Signature::from_bytes(<&[u8; 64]>::try_from(signature).unwrap());

                Ok(vk.verify(message, &sig).is_ok())
            }
            SignatureType::Ethereum => {
                use k256::ecdsa::{RecoveryId, Signature as KSig, VerifyingKey};

                if owner.len() != 65 || signature.len() != 65 {
                    return Ok(false);
                }

                let vk = VerifyingKey::from_sec1_bytes(owner)
                    .map_err(|e| Error::InvalidKeyFormat(e.to_string()))?;

                let msg_hash = crate::ethereum::EthereumSigner::eth_message_hash(message);

                let recovery_id = RecoveryId::try_from(signature[64].wrapping_sub(27))
                    .map_err(|_| Error::InvalidKeyFormat("invalid recovery id".into()))?;

                let sig = KSig::from_slice(&signature[..64]).map_err(|_| {
                    Error::InvalidSignatureLength { expected: 64, actual: signature.len() }
                })?;

                let recovered = VerifyingKey::recover_from_prehash(&msg_hash, &sig, recovery_id)
                    .map_err(|_| Error::VerificationFailed)?;

                Ok(recovered == vk)
            }
            SignatureType::None => Ok(false),
        }
    }
}

/// Abstraction over a concrete signing key.
///
/// Implementations must be **thread‑safe** (`Send + Sync`) so that they can be
/// put behind an `Arc<dyn Signer>`.
pub trait Signer: Send + Sync {
    /// Sign `message`, returning the raw signature bytes.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;

    /// Return the encoded public key for this signer.
    fn public_key(&self) -> Vec<u8>;

    /// Identify the signature algorithm used by this signer.
    fn signature_type(&self) -> SignatureType;

    /// Verify `signature` was produced by this [`Signer`] over `message`.
    ///
    /// A default implementation is provided that delegates to
    /// [`SignatureType::verify`].  Override only for specialised
    /// implementations (e.g. hardware HSMs that can verify internally).
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        self.signature_type().verify(&self.public_key(), message, signature)
    }
}
