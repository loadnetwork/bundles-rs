// ─────────────────────────────────────────────────────────────────────────────
// src/solana.rs — idiomatic Solana signer built on top of `Ed25519Core`
// ─────────────────────────────────────────────────────────────────────────────
//! Convenience wrapper that exposes Solana‑style Base58 utilities while
//! delegating all cryptographic operations to [`Ed25519Core`].
//!
//! A **Solana account keypair** is just a raw Ed25519 keypair where:
//! * the 32‑byte private key is an Ed25519 *seed* (not the expanded 64‑byte secret scalar+prefix —
//!   this matches `ed25519_dalek::SigningKey`), and
//! * the public key is the Ed25519 point `A = s·B`.
//!
//! CLI tools (`solana-keygen`, `solana-wallet`, JSON RPC) encode both the
//! private seed and the public key using **Base58**.  Common patterns are:
//! * 32‑byte seed → Base58 (private key only)
//! * 64‑byte seed||pubkey → Base58 (full keypair)
//! * 32‑byte pubkey → Base58 (address / account id)
//!
//! This module therefore adds:
//! * `from_base58` – detect 32 vs 64 bytes and construct appropriately
//! * `to_base58_keypair`, `to_base58_public` helpers
//! * `address()` alias for the public key Base58 string
//!
//! The struct implements the project‑wide [`Signer`] trait, so it can plug
//! into generic signing code alongside Ethereum/Arweave/etc.

use bs58;
use ed25519_dalek::{Signature, Verifier};

use crate::{
    ed25519::{Ed25519Core, KEYPAIR_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH},
    errors::{Error, Result},
    signer::{SignatureType, Signer},
};

#[derive(Clone, Debug)]
pub struct SolanaSigner(Ed25519Core);

impl SolanaSigner {
    /// Wrap an existing [`Ed25519Core`].
    #[inline]
    pub fn from_core(core: Ed25519Core) -> Self {
        Self(core)
    }

    /// Generate a fresh random Solana keypair using OS entropy.
    #[inline]
    pub fn random() -> Self {
        Self(Ed25519Core::random())
    }

    /// Construct from a 32‑byte private seed.
    #[inline]
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(Ed25519Core::from_secret_bytes(bytes)?))
    }

    /// Construct from a 64‑byte `secret || public` concatenation.
    #[inline]
    pub fn from_keypair_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(Ed25519Core::from_keypair_bytes(bytes)?))
    }

    /// Construct from a Base58 string (either 32‑ or 64‑byte encoding).
    pub fn from_base58(b58: &str) -> Result<Self> {
        let decoded =
            bs58::decode(b58).into_vec().map_err(|e| Error::InvalidKeyFormat(e.to_string()))?;
        match decoded.len() {
            SECRET_KEY_LENGTH => Self::from_secret_bytes(&decoded),
            KEYPAIR_LENGTH => Self::from_keypair_bytes(&decoded),
            n => Err(Error::InvalidKeyLength { expected: SECRET_KEY_LENGTH, actual: n }),
        }
    }

    /// Raw 64‑byte `secret || public` keypair.
    #[inline]
    pub fn to_keypair_bytes(&self) -> [u8; KEYPAIR_LENGTH] {
        self.0.to_keypair_bytes()
    }

    /// Base58‑encoded 64‑byte keypair (same format as `solana-keygen` output).
    #[inline]
    pub fn to_base58_keypair(&self) -> String {
        bs58::encode(self.to_keypair_bytes()).into_string()
    }

    /// Base58‑encoded public key (account address).
    #[inline]
    pub fn to_base58_public(&self) -> String {
        bs58::encode(self.public_key()).into_string()
    }

    /// Alias for `to_base58_public` for readability.
    #[inline]
    pub fn address(&self) -> String {
        self.to_base58_public()
    }

    #[inline(always)]
    pub fn public_key(&self) -> Vec<u8> {
        self.0.public().as_bytes().to_vec()
    }

    #[inline(always)]
    pub fn verifying_key(&self) -> &ed25519_dalek::VerifyingKey {
        self.0.public()
    }
}

impl Signer for SolanaSigner {
    #[inline(always)]
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        Ok(self.0.sign(message).to_bytes().to_vec())
    }

    #[inline(always)]
    fn public_key(&self) -> Vec<u8> {
        self.public_key()
    }

    /// Uses the same Ed25519 variant as raw Ed25519Signers.
    #[inline(always)]
    fn signature_type(&self) -> SignatureType {
        SignatureType::Ed25519
    }

    #[inline(always)]
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        if signature.len() != SIGNATURE_LENGTH {
            return Err(Error::InvalidKeyLength {
                expected: SECRET_KEY_LENGTH,
                actual: signature.len(),
            });
        }
        let sig = Signature::from_bytes(<&[u8; SIGNATURE_LENGTH]>::try_from(signature).unwrap());
        Ok(self.0.public().verify(message, &sig).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rayon::prelude::*;

    // ───────── original six cases ─────────

    #[test]
    fn test_solana_sign_verify() {
        let signer = SolanaSigner::random();
        let message = b"Hello, Solana!";
        let signature = signer.sign(message).unwrap();
        assert_eq!(signature.len(), SIGNATURE_LENGTH);
        assert!(signer.verify(message, &signature).unwrap());
        assert!(!signer.verify(b"Wrong message", &signature).unwrap());
    }

    #[test]
    fn test_solana_address() {
        let signer = SolanaSigner::random();
        let address = signer.address();
        let decoded = bs58::decode(&address).into_vec().unwrap();
        assert_eq!(decoded, signer.public_key());
    }

    #[test]
    fn test_base58_import_export() {
        let signer1 = SolanaSigner::random();
        let base58_keypair = signer1.to_base58_keypair();
        let signer2 = SolanaSigner::from_base58(&base58_keypair).unwrap();
        assert_eq!(signer1.public_key(), signer2.public_key());
        let message = b"Test message";
        let sig1 = signer1.sign(message).unwrap();
        let sig2 = signer2.sign(message).unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_solana_keypair_format() {
        let signer = SolanaSigner::random();
        let keypair_bytes = signer.to_keypair_bytes();
        assert_eq!(keypair_bytes.len(), KEYPAIR_LENGTH);
        // first 32 bytes recreate the signer
        let signer_from_private =
            SolanaSigner::from_secret_bytes(&keypair_bytes[..SECRET_KEY_LENGTH]).unwrap();
        assert_eq!(signer.public_key(), signer_from_private.public_key());
        // last 32 bytes are the public key
        assert_eq!(&keypair_bytes[SECRET_KEY_LENGTH..], signer.public_key().as_slice());
    }

    #[test]
    fn test_known_solana_key() {
        let secret_key = [
            56, 145, 181, 23, 218, 26, 101, 183, 229, 69, 179, 206, 105, 157, 65, 245, 11, 28, 178,
            159, 206, 232, 22, 51, 217, 166, 211, 232, 97, 138, 208, 156,
        ];
        let signer = SolanaSigner::from_secret_bytes(&secret_key).unwrap();
        let address = signer.address();
        assert_eq!(signer.public_key().len(), 32);
        assert!(!address.is_empty());
        let msg = b"Solana test";
        let sig = signer.sign(msg).unwrap();
        assert!(signer.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_from_base58_private_key() {
        let signer1 = SolanaSigner::random();
        let private_key_b58 =
            bs58::encode(&signer1.to_keypair_bytes()[..SECRET_KEY_LENGTH]).into_string();
        let signer2 = SolanaSigner::from_base58(&private_key_b58).unwrap();
        assert_eq!(signer1.public_key(), signer2.public_key());
    }

    // ───────── new extras for robustness ─────────

    #[test]
    fn deterministic_from_secret() {
        let secret = [7u8; SECRET_KEY_LENGTH];
        let s1 = SolanaSigner::from_secret_bytes(&secret).unwrap();
        let s2 = SolanaSigner::from_secret_bytes(&secret).unwrap();
        assert_eq!(s1.public_key(), s2.public_key());
    }

    #[test]
    fn concurrency_stress() {
        let signer = SolanaSigner::random();
        (0..1_000usize).into_par_iter().for_each(|i| {
            let msg = i.to_le_bytes();
            let sig = signer.sign(&msg).unwrap();
            assert!(signer.verify(&msg, &sig).unwrap());
        });
    }
}
