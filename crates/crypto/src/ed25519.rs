#![allow(clippy::result_large_err)]

use core::fmt;

use anyhow::bail;
use ed25519_dalek::{Signature, Signer as DalekSigner, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use rand_core::CryptoRngCore;

use crate::{
    errors::{Error, Result},
    signer::{SignatureType, Signer},
};

/// Length of an Ed25519 secret key in bytes.
pub const SECRET_KEY_LENGTH: usize = 32;
/// Length of an Ed25519 public key in bytes.
pub const PUBLIC_KEY_LENGTH: usize = 32;
/// Length of an Ed25519 signature in bytes.
pub const SIGNATURE_LENGTH: usize = 64;
/// Length of a concatenated `secret || public` keypair in bytes.
pub const KEYPAIR_LENGTH: usize = SECRET_KEY_LENGTH + PUBLIC_KEY_LENGTH;

/// Core key‑handling struct
#[derive(Clone)]
pub struct Ed25519Core {
    secret: SigningKey,
    public: VerifyingKey,
}

impl fmt::Debug for Ed25519Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ed25519Core {{ public: {:?} }}", self.public)
    }
}

impl Ed25519Core {
    /// Construct from an existing [`SigningKey`].
    pub fn new(signing_key: SigningKey) -> Self {
        let public = signing_key.verifying_key();
        Self { secret: signing_key, public }
    }

    /// Construct from raw 32‑byte secret key.
    pub fn from_secret_bytes(secret: &[u8]) -> Result<Self> {
        if secret.len() != SECRET_KEY_LENGTH {
            return Err(Error::InvalidKeyLength {
                expected: SECRET_KEY_LENGTH,
                actual: secret.len(),
            });
        }
        let secret = SigningKey::from_bytes(<&[u8; SECRET_KEY_LENGTH]>::try_from(secret).unwrap());
        Ok(Self::new(secret))
    }

    /// Construct from raw `secret || public` concatenation.
    pub fn from_keypair_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KEYPAIR_LENGTH {
            return Err(Error::InvalidKeyLength { expected: KEYPAIR_LENGTH, actual: bytes.len() });
        }
        Self::from_secret_bytes(&bytes[..SECRET_KEY_LENGTH])
    }

    /// Generate using a caller‑supplied CSPRNG (helpful for tests).
    pub fn generate_with<R: CryptoRngCore + ?Sized>(rng: &mut R) -> Self {
        Self::new(SigningKey::generate(rng))
    }

    /// Convenient random generator using `OsRng`.
    pub fn random() -> Self {
        Self::generate_with(&mut OsRng)
    }

    #[inline(always)]
    pub fn public(&self) -> &VerifyingKey {
        &self.public
    }

    #[inline(always)]
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.secret.sign(msg)
    }

    /// Sign without allocating by writing into the provided buffer.
    #[inline(always)]
    pub fn sign_into(&self, msg: &[u8], out: &mut [u8; SIGNATURE_LENGTH]) {
        let sig = self.sign(msg).to_bytes();
        out.copy_from_slice(&sig);
    }

    /// Serialise as `secret || public`.
    pub fn to_keypair_bytes(&self) -> [u8; KEYPAIR_LENGTH] {
        let mut out = [0u8; KEYPAIR_LENGTH];
        out[..SECRET_KEY_LENGTH].copy_from_slice(&self.secret.to_bytes());
        out[SECRET_KEY_LENGTH..].copy_from_slice(self.public.as_bytes());
        out
    }
}

/// High‑level `Signer` wrapper
#[derive(Clone, Debug)]
pub struct Ed25519Signer(Ed25519Core);

impl Ed25519Signer {
    pub fn from_core(core: Ed25519Core) -> Self {
        Self(core)
    }

    pub fn random() -> Self {
        Self(Ed25519Core::random())
    }

    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(Ed25519Core::from_secret_bytes(bytes)?))
    }

    pub fn from_keypair_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self(Ed25519Core::from_keypair_bytes(bytes)?))
    }

    pub fn to_keypair_bytes(&self) -> [u8; KEYPAIR_LENGTH] {
        self.0.to_keypair_bytes()
    }

    #[inline(always)]
    pub fn verifying_key(&self) -> &VerifyingKey {
        self.0.public()
    }
}

impl Signer for Ed25519Signer {
    #[inline(always)]
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        Ok(self.0.sign(message).to_bytes().to_vec())
    }

    #[inline(always)]
    fn public_key(&self) -> Vec<u8> {
        self.0.public().as_bytes().to_vec()
    }

    #[inline(always)]
    fn signature_type(&self) -> SignatureType {
        SignatureType::Ed25519
    }

    #[inline(always)]
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        if signature.len() != SIGNATURE_LENGTH {
            return Err(Error::InvalidSignatureLength {
                expected: SIGNATURE_LENGTH,
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

    #[test]
    fn roundtrip_sign_verify() {
        let signer = Ed25519Signer::random();
        let msg = b"test-msg";
        let sig = signer.sign(msg).unwrap();
        assert!(signer.verify(msg, &sig).unwrap());
    }

    #[test]
    fn keypair_serialisation_roundtrip() {
        let signer = Ed25519Signer::random();
        let bytes = signer.to_keypair_bytes();
        let signer2 = Ed25519Signer::from_keypair_bytes(&bytes).unwrap();
        assert_eq!(signer.public_key(), signer2.public_key());
        let sig = signer.sign(b"hello").unwrap();
        assert!(signer2.verify(b"hello", &sig).unwrap());
    }

    #[test]
    fn deterministic_from_secret() {
        let secret = [42u8; SECRET_KEY_LENGTH];
        let signer1 = Ed25519Signer::from_secret_bytes(&secret).unwrap();
        let signer2 = Ed25519Signer::from_secret_bytes(&secret).unwrap();
        assert_eq!(signer1.public_key(), signer2.public_key());
    }

    #[test]
    fn concurrency() {
        let signer = Ed25519Signer::random();
        (0..1000usize).into_par_iter().for_each(|i| {
            let msg = i.to_le_bytes();
            let sig = signer.sign(&msg).unwrap();
            assert!(signer.verify(&msg, &sig).unwrap());
        });
    }
}
