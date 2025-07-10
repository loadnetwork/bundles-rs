use anyhow::{Result, anyhow};
use ed25519_dalek::{Signature, Signer as DalekSigner, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

use crate::signer::{SignatureType, Signer};

#[derive(Clone)]
pub struct Ed25519Signer {
    signing_key: SigningKey,
}

impl Ed25519Signer {
    /// Create from a `SigningKey`
    pub fn new(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    /// Create from 32-byte secret key
    pub fn from_bytes(secret_key: &[u8]) -> Result<Self> {
        let key: &[u8; 32] =
            secret_key.try_into().map_err(|_| anyhow!("Invalid secret key length"))?;
        let signing_key = SigningKey::from_bytes(key);
        Ok(Self { signing_key })
    }

    /// Generate a new random key
    pub fn random() -> Self {
        let mut csprng = OsRng;

        let signing_key = SigningKey::generate(&mut csprng);
        Self { signing_key }
    }

    /// Create from a 64-byte keypair (secret + public)
    pub fn from_keypair_bytes(bytes: &[u8]) -> Result<Self> {
        anyhow::ensure!(bytes.len() == 64, "Keypair must be 64 bytes");
        Self::from_bytes(&bytes[..32])
    }

    /// Get the verifying key
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Export as 64-byte keypair (secret + public)
    pub fn to_keypair_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&self.signing_key.to_bytes()); // secret
        bytes.extend_from_slice(self.verifying_key().as_bytes()); // public
        bytes
    }
}

impl Signer for Ed25519Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let signature = self.signing_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }

    fn public_key(&self) -> Vec<u8> {
        self.verifying_key().as_bytes().to_vec()
    }

    fn signature_type(&self) -> SignatureType {
        SignatureType::Ed25519
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        let sig = Signature::from_bytes(
            signature.try_into().map_err(|_| anyhow!("Invalid signature length"))?,
        );
        Ok(self.verifying_key().verify(message, &sig).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_sign_verify() {
        let signer = Ed25519Signer::random();
        let message = b"Hello, world!";

        let signature = signer.sign(message).unwrap();
        assert_eq!(signature.len(), 64);

        let public_key = signer.public_key();
        assert_eq!(public_key.len(), 32);

        assert!(signer.verify(message, &signature).unwrap());

        // Wrong message should fail
        assert!(!signer.verify(b"Wrong message", &signature).unwrap());
    }

    #[test]
    fn test_from_bytes() {
        // Test vector from ed25519-dalek tests
        let secret_key = [
            62, 70, 27, 163, 92, 182, 11, 3, 77, 234, 98, 4, 11, 127, 79, 228, 243, 187, 150, 73,
            201, 137, 76, 22, 85, 251, 152, 2, 241, 42, 72, 54,
        ];

        let signer = Ed25519Signer::from_bytes(&secret_key).unwrap();
        let public_key = signer.public_key();

        // Expected public key from the test
        let expected_public_key = [
            130, 39, 155, 15, 62, 76, 188, 63, 124, 122, 26, 251, 233, 253, 225, 220, 14, 41, 166,
            120, 108, 35, 254, 77, 160, 83, 172, 58, 219, 42, 86, 120,
        ];

        assert_eq!(public_key, expected_public_key);
    }

    #[test]
    fn test_keypair_format() {
        let signer = Ed25519Signer::random();
        let keypair_bytes = signer.to_keypair_bytes();
        assert_eq!(keypair_bytes.len(), 64);

        // Round trip
        let signer2 = Ed25519Signer::from_keypair_bytes(&keypair_bytes).unwrap();
        assert_eq!(signer.public_key(), signer2.public_key());

        // Test message signing produces same result
        let message = b"Test message";
        let sig1 = signer.sign(message).unwrap();
        let sig2 = signer2.sign(message).unwrap();
        assert_eq!(sig1, sig2);
    }
}
