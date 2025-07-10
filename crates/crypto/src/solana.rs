use anyhow::{Result, anyhow};
use bs58;
use ed25519_dalek::{Signature, Signer as DalekSigner, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

use crate::signer::{SignatureType, Signer};

#[derive(Clone)]
pub struct SolanaSigner {
    signing_key: SigningKey,
}

impl SolanaSigner {
    /// Construct from a raw 32-byte `SigningKey` (Ed25519 seed).
    pub fn new(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    pub fn from_bytes(secret_key: &[u8]) -> Result<Self> {
        let key: &[u8; 32] =
            secret_key.try_into().map_err(|_| anyhow!("secret key length not equal 32"))?;
        Ok(Self { signing_key: SigningKey::from_bytes(key) })
    }

    pub fn random() -> Self {
        Self { signing_key: SigningKey::generate(&mut OsRng) }
    }

    pub fn from_keypair_bytes(bytes: &[u8]) -> Result<Self> {
        anyhow::ensure!(bytes.len() == 64, "Expected 64-byte keypair");
        Self::from_bytes(&bytes[..32])
    }

    pub fn from_base58(base58_key: &str) -> Result<Self> {
        let bytes = bs58::decode(base58_key)
            .into_vec()
            .map_err(|e| anyhow!("invalid base58 string: {}", e))?;

        match bytes.len() {
            32 => Self::from_bytes(&bytes),
            64 => Self::from_keypair_bytes(&bytes),
            n => Err(anyhow!("expected 32 or 64 bytes, got {}", n)),
        }
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    pub fn address(&self) -> String {
        bs58::encode(self.verifying_key().as_bytes()).into_string()
    }

    pub fn to_keypair_bytes(&self) -> [u8; 64] {
        let secret = self.signing_key.to_bytes();
        let public = self.verifying_key().to_bytes();

        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&secret);
        out[32..].copy_from_slice(&public);
        out
    }

    pub fn to_base58_keypair(&self) -> String {
        bs58::encode(self.to_keypair_bytes()).into_string()
    }

    pub fn public_key_base58(&self) -> String {
        self.address()
    }
}

impl Signer for SolanaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        Ok(self.signing_key.sign(message).to_bytes().into())
    }

    fn public_key(&self) -> Vec<u8> {
        self.verifying_key().as_bytes().to_vec()
    }

    fn signature_type(&self) -> SignatureType {
        SignatureType::Solana
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let sig_bytes: &[u8; 64] =
            signature.try_into().map_err(|_| anyhow!("Expected 64-byte Ed25519 signature"))?;
        let sig = Signature::from_bytes(sig_bytes);
        Ok(self.verifying_key().verify(message, &sig).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solana_sign_verify() {
        let signer = SolanaSigner::random();
        let message = b"Hello, Solana!";

        let signature = signer.sign(message).unwrap();
        assert_eq!(signature.len(), 64);

        let public_key = signer.public_key();
        assert_eq!(public_key.len(), 32);

        assert!(signer.verify(message, &signature).unwrap());
        assert!(!signer.verify(b"Wrong message", &signature).unwrap());
    }

    #[test]
    fn test_solana_address() {
        let signer = SolanaSigner::random();
        let address = signer.address();

        // Solana addresses are base58-encoded 32-byte public keys
        let decoded = bs58::decode(&address).into_vec().unwrap();
        assert_eq!(decoded.len(), 32);
        assert_eq!(decoded, signer.public_key());
    }

    #[test]
    fn test_base58_import_export() {
        let signer1 = SolanaSigner::random();

        // Export and reimport via base58
        let base58_keypair = signer1.to_base58_keypair();
        let signer2 = SolanaSigner::from_base58(&base58_keypair).unwrap();

        // Should have same keys
        assert_eq!(signer1.public_key(), signer2.public_key());

        // Test message signing produces same result
        let message = b"Test message";
        let sig1 = signer1.sign(message).unwrap();
        let sig2 = signer2.sign(message).unwrap();
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_solana_keypair_format() {
        let signer = SolanaSigner::random();
        let keypair_bytes = signer.to_keypair_bytes();
        assert_eq!(keypair_bytes.len(), 64);

        // First 32 bytes are private key
        let private_key = &keypair_bytes[..32];
        let signer_from_private = SolanaSigner::from_bytes(private_key).unwrap();
        assert_eq!(signer.public_key(), signer_from_private.public_key());

        // Last 32 bytes are public key
        let public_key = &keypair_bytes[32..];
        assert_eq!(public_key, signer.public_key());
    }

    #[test]
    fn test_known_solana_key() {
        // Test with a known Solana keypair
        let secret_key = [
            56, 145, 181, 23, 218, 26, 101, 183, 229, 69, 179, 206, 105, 157, 65, 245, 11, 28, 178,
            159, 206, 232, 22, 51, 217, 166, 211, 232, 97, 138, 208, 156,
        ];

        let signer = SolanaSigner::from_bytes(&secret_key).unwrap();
        let address = signer.address();

        // Verify the public key and address generation
        assert_eq!(signer.public_key().len(), 32);
        assert!(!address.is_empty());

        // Test signing
        let msg = b"Solana test message";
        let sig = signer.sign(msg).unwrap();
        assert!(signer.verify(msg, &sig).unwrap());
    }

    #[test]
    fn test_from_base58_private_key() {
        // Generate a key and export just the private key
        let signer1 = SolanaSigner::random();
        let private_key_base58 = bs58::encode(&signer1.signing_key.to_bytes()).into_string();

        // Import from base58 private key
        let signer2 = SolanaSigner::from_base58(&private_key_base58).unwrap();
        assert_eq!(signer1.public_key(), signer2.public_key());
    }
}
