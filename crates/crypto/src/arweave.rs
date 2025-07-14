use anyhow::{Result, anyhow};
use rsa::{
    pss::{BlindedSigningKey, VerifyingKey}, 
    sha2::Sha256, 
    signature::{RandomizedSigner, Verifier as _}, 
    traits::{PrivateKeyParts, PublicKeyParts}, 
    RsaPrivateKey, RsaPublicKey
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use rand::rngs::OsRng;

use crate::signer::{SignatureType, Signer};

const SALT_LEN: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkAuth {
    pub kty: String,
    pub n: String,
    pub e: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub q: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dq: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qi: Option<String>,
}

pub struct ArweaveSigner {
    private_key: Option<RsaPrivateKey>,
    public_key: RsaPublicKey,
}

impl ArweaveSigner {
    pub fn new(private_key: RsaPrivateKey) -> Self {
        let public_key = RsaPublicKey::from(&private_key);
        Self {
            private_key: Some(private_key),
            public_key,
        }
    }

    pub fn from_public_key(public_key: RsaPublicKey) -> Self {
        Self {
            private_key: None,
            public_key,
        }
    }

    pub fn random() -> Result<Self> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 4096)?;
        Ok(Self::new(private_key))
    }

    pub fn from_jwk(jwk: &JwkAuth) -> Result<Self> {
        if jwk.kty != "RSA" {
            return Err(anyhow!("Invalid key type: expected RSA, got {}", jwk.kty));
        }

        let n = URL_SAFE_NO_PAD.decode(&jwk.n)?;
        let e = URL_SAFE_NO_PAD.decode(&jwk.e)?;

        let n_biguint = rsa::BigUint::from_bytes_be(&n);
        let e_biguint = rsa::BigUint::from_bytes_be(&e);

        // Check if we have private key components
        if let (Some(d), Some(p), Some(q)) = (&jwk.d, &jwk.p, &jwk.q) {
            let d = URL_SAFE_NO_PAD.decode(d)?;
            let p = URL_SAFE_NO_PAD.decode(p)?;
            let q = URL_SAFE_NO_PAD.decode(q)?;

            let d_biguint = rsa::BigUint::from_bytes_be(&d);
            let primes = vec![
                rsa::BigUint::from_bytes_be(&p),
                rsa::BigUint::from_bytes_be(&q),
            ];

            let mut private_key = RsaPrivateKey::from_components(
                n_biguint,
                e_biguint,
                d_biguint,
                primes,
            )?;
            
            // Validate the key
            private_key.validate()?;
            
            // Precompute CRT parameters if missing
            if jwk.dp.is_none() || jwk.dq.is_none() || jwk.qi.is_none() {
                private_key.precompute()?;
            }

            Ok(Self::new(private_key))
        } else {
            // Public key only
            let public_key = RsaPublicKey::new(n_biguint, e_biguint)?;
            Ok(Self::from_public_key(public_key))
        }
    }

    pub fn from_jwk_str(jwk_str: &str) -> Result<Self> {
        let jwk: JwkAuth = serde_json::from_str(jwk_str)?;
        Self::from_jwk(&jwk)
    }

    pub fn from_jwk_file(path: &str) -> Result<Self> {
        let jwk_str = std::fs::read_to_string(path)?;
        Self::from_jwk_str(&jwk_str)
    }

    pub fn to_jwk(&self) -> Result<JwkAuth> {
        let n = URL_SAFE_NO_PAD.encode(self.public_key.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(self.public_key.e().to_bytes_be());

        if let Some(private_key) = &self.private_key {
            let d = URL_SAFE_NO_PAD.encode(private_key.d().to_bytes_be());
            
            let primes = private_key.primes();
            let p = URL_SAFE_NO_PAD.encode(primes[0].to_bytes_be());
            let q = URL_SAFE_NO_PAD.encode(primes[1].to_bytes_be());

            // Note: qi is unsigned in RFC 7517
            let dp = private_key.dp()
                .map(|v| URL_SAFE_NO_PAD.encode(v.to_bytes_be()));
            let dq = private_key.dq()
                .map(|v| URL_SAFE_NO_PAD.encode(v.to_bytes_be()));
            let qi = private_key.qinv()
                .map(|v| URL_SAFE_NO_PAD.encode(v.to_bytes_be()));

            Ok(JwkAuth {
                kty: "RSA".to_string(),
                n,
                e,
                d: Some(d),
                p: Some(p),
                q: Some(q),
                dp,
                dq,
                qi,
            })
        } else {
            Ok(JwkAuth {
                kty: "RSA".to_string(),
                n,
                e,
                d: None,
                p: None,
                q: None,
                dp: None,
                dq: None,
                qi: None,
            })
        }
    }

    /// Return exactly 512 bytes (left-padded with 0s)
    pub fn owner_bytes(&self) -> [u8; 512] {
        let mut out = [0u8; 512];
        let n_bytes = self.public_key.n().to_bytes_be();
        let start = 512_usize.saturating_sub(n_bytes.len());
        out[start..].copy_from_slice(&n_bytes);
        out
    }

    /// Get Arweave address (base64url SHA-256 of the padded owner)
    pub fn address(&self) -> String {
        let owner = self.owner_bytes();
        let hash = sha2::Sha256::digest(&owner);
        URL_SAFE_NO_PAD.encode(hash)
    }

    fn create_signing_key(private_key: &RsaPrivateKey) -> Result<BlindedSigningKey<Sha256>> {
        Ok(BlindedSigningKey::<Sha256>::new_with_salt_len(
            private_key.clone(),
            SALT_LEN,
        ))
    }

    fn create_verifying_key(public_key: &RsaPublicKey) -> Result<VerifyingKey<Sha256>> {
        Ok(VerifyingKey::<Sha256>::new_with_salt_len(
            public_key.clone(),
            SALT_LEN,
        ))
    }
}

impl Signer for ArweaveSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let private_key = self.private_key.as_ref()
            .ok_or_else(|| anyhow!("No private key available for signing"))?;

        let signing_key = Self::create_signing_key(private_key)?;
        let mut rng = OsRng;
        let signature = signing_key.sign_with_rng(&mut rng, message);
        
        // Ensure exactly 512 bytes
        let sig_bytes = signature.to_bytes();
        if sig_bytes.len() != 512 {
            return Err(anyhow!("Invalid signature length: expected 512, got {}", sig_bytes.len()));
        }
        
        Ok(sig_bytes.to_vec())
    }

    fn public_key(&self) -> Vec<u8> {
        self.owner_bytes().to_vec()
    }

    fn signature_type(&self) -> SignatureType {
        SignatureType::Arweave
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        if signature.len() != 512 {
            return Ok(false);
        }

        let verifying_key = Self::create_verifying_key(&self.public_key)?;
        let sig = rsa::pss::Signature::try_from(signature)?;
        
        Ok(verifying_key.verify(message, &sig).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arweave_sign_verify() {
        let signer = ArweaveSigner::random().unwrap();
        let message = b"Hello, Arweave!";

        let signature = signer.sign(message).unwrap();
        assert_eq!(signature.len(), 512);

        let public_key = signer.public_key();
        assert_eq!(public_key.len(), 512);

        assert!(signer.verify(message, &signature).unwrap());
        assert!(!signer.verify(b"Wrong message", &signature).unwrap());
    }

    #[test]
    fn test_jwk_roundtrip() {
        let signer1 = ArweaveSigner::random().unwrap();
        let jwk = signer1.to_jwk().unwrap();
        let signer2 = ArweaveSigner::from_jwk(&jwk).unwrap();

        // Should have same public keys
        assert_eq!(signer1.public_key(), signer2.public_key());
        assert_eq!(signer1.address(), signer2.address());

        // Test signing
        let message = b"Test message";
        let sig1 = signer1.sign(message).unwrap();
        assert!(signer2.verify(message, &sig1).unwrap());
    }

    #[test]
    fn test_arweave_address() {
        let signer = ArweaveSigner::random().unwrap();
        let address = signer.address();
        
        // Arweave addresses are base64url encoded SHA-256 hashes
        assert!(!address.contains('+'));
        assert!(!address.contains('/'));
        assert!(!address.contains('='));
    }

    #[test]
    fn test_owner_bytes_padding() {
        let signer = ArweaveSigner::random().unwrap();
        let owner = signer.owner_bytes();
        
        assert_eq!(owner.len(), 512);
        
        // Check that it's properly padded (starts with zeros if needed)
        let n_bytes = signer.public_key.n().to_bytes_be();
        if n_bytes.len() < 512 {
            for i in 0..(512 - n_bytes.len()) {
                assert_eq!(owner[i], 0, "Padding should be zeros");
            }
        }
    }
}