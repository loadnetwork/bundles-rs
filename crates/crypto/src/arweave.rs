use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::rngs::OsRng;
use rsa::{
    BigUint, RsaPrivateKey, RsaPublicKey,
    pss::{BlindedSigningKey, Signature as PssSignature, VerifyingKey},
    sha2::Sha256,
    signature::{RandomizedSigner, SignatureEncoding, Verifier as _},
    traits::{PrivateKeyParts, PublicKeyParts},
};
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::{
    errors::{Error, Result},
    signer::{SignatureType, Signer},
};

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
        Self { private_key: Some(private_key), public_key }
    }

    pub fn from_public_key(public_key: RsaPublicKey) -> Self {
        Self { private_key: None, public_key }
    }

    pub fn random() -> Result<Self> {
        let mut rng = OsRng;
        let pk = RsaPrivateKey::new(&mut rng, 4096).map_err(|e| Error::Other(e.into()))?;
        Ok(Self::new(pk))
    }

    pub fn from_jwk(jwk: &JwkAuth) -> Result<Self> {
        if jwk.kty != "RSA" {
            return Err(Error::InvalidKeyFormat("expected RSA key type".into()));
        }

        let n =
            URL_SAFE_NO_PAD.decode(&jwk.n).map_err(|e| Error::InvalidKeyFormat(e.to_string()))?;
        let e =
            URL_SAFE_NO_PAD.decode(&jwk.e).map_err(|e| Error::InvalidKeyFormat(e.to_string()))?;

        let n_big = BigUint::from_bytes_be(&n);
        let e_big = BigUint::from_bytes_be(&e);

        if let (Some(d), Some(p), Some(q)) = (&jwk.d, &jwk.p, &jwk.q) {
            let d =
                URL_SAFE_NO_PAD.decode(d).map_err(|e| Error::InvalidKeyFormat(e.to_string()))?;
            let p =
                URL_SAFE_NO_PAD.decode(p).map_err(|e| Error::InvalidKeyFormat(e.to_string()))?;
            let q =
                URL_SAFE_NO_PAD.decode(q).map_err(|e| Error::InvalidKeyFormat(e.to_string()))?;

            let d_big = BigUint::from_bytes_be(&d);
            let primes = vec![BigUint::from_bytes_be(&p), BigUint::from_bytes_be(&q)];

            let mut pk = RsaPrivateKey::from_components(n_big, e_big, d_big, primes)
                .map_err(|e| Error::InvalidKeyFormat(e.to_string()))?;

            pk.validate().map_err(|e| Error::InvalidKeyFormat(e.to_string()))?;
            if jwk.dp.is_none() || jwk.dq.is_none() || jwk.qi.is_none() {
                pk.precompute().map_err(|e| Error::InvalidKeyFormat(e.to_string()))?;
            }

            Ok(Self::new(pk))
        } else {
            let pub_key = RsaPublicKey::new(n_big, e_big)
                .map_err(|e| Error::InvalidKeyFormat(e.to_string()))?;
            Ok(Self::from_public_key(pub_key))
        }
    }

    pub fn from_jwk_str(s: &str) -> Result<Self> {
        let jwk: JwkAuth =
            serde_json::from_str(s).map_err(|e| Error::InvalidKeyFormat(e.to_string()))?;
        Self::from_jwk(&jwk)
    }

    pub fn from_jwk_file(path: &str) -> Result<Self> {
        let jwk_str = std::fs::read_to_string(path)?;
        Self::from_jwk_str(&jwk_str)
    }

    pub fn to_jwk(&self) -> Result<JwkAuth> {
        let n = URL_SAFE_NO_PAD.encode(self.public_key.n().to_bytes_be());
        let e = URL_SAFE_NO_PAD.encode(self.public_key.e().to_bytes_be());

        if let Some(pk) = &self.private_key {
            let d = URL_SAFE_NO_PAD.encode(pk.d().to_bytes_be());
            let ps = pk.primes();
            let p = URL_SAFE_NO_PAD.encode(ps[0].to_bytes_be());
            let q = URL_SAFE_NO_PAD.encode(ps[1].to_bytes_be());

            let dp = pk.dp().map(|v| URL_SAFE_NO_PAD.encode(v.to_bytes_be()));
            let dq = pk.dq().map(|v| URL_SAFE_NO_PAD.encode(v.to_bytes_be()));

            let qi = pk.qinv().map(|v| URL_SAFE_NO_PAD.encode(v.to_bytes_be().1));

            Ok(JwkAuth { kty: "RSA".into(), n, e, d: Some(d), p: Some(p), q: Some(q), dp, dq, qi })
        } else {
            Ok(JwkAuth {
                kty: "RSA".into(),
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

    pub fn owner_bytes(&self) -> [u8; 512] {
        let mut out = [0u8; 512];
        let n_be = self.public_key.n().to_bytes_be();
        out[512 - n_be.len()..].copy_from_slice(&n_be);
        out
    }

    pub fn address(&self) -> String {
        let hash = Sha256::digest(&self.owner_bytes());
        URL_SAFE_NO_PAD.encode(hash)
    }

    fn signing_key(pk: &RsaPrivateKey) -> Result<BlindedSigningKey<Sha256>> {
        Ok(BlindedSigningKey::<Sha256>::new_with_salt_len(pk.clone(), SALT_LEN))
    }

    fn verifying_key(owner: &[u8]) -> Result<VerifyingKey<Sha256>> {
        if owner.len() != 512 {
            return Err(Error::InvalidKeyLength { expected: 512, actual: owner.len() });
        }
        let n = BigUint::from_bytes_be(owner);
        let pk = RsaPublicKey::new(n, BigUint::from(65_537u32))
            .map_err(|e| Error::InvalidKeyFormat(e.to_string()))?;
        Ok(VerifyingKey::<Sha256>::new_with_salt_len(pk, SALT_LEN))
    }
}

impl Signer for ArweaveSigner {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let pk = self.private_key.as_ref().ok_or(Error::MissingPrivateKey)?;

        let signer = Self::signing_key(pk)?;

        let mut rng = OsRng;
        let sig = signer.sign_with_rng(&mut rng, msg);
        let bytes = sig.to_bytes();

        if bytes.len() != 512 {
            return Err(Error::InvalidSignatureLength { expected: 512, actual: bytes.len() });
        }
        Ok(bytes.to_vec())
    }

    fn public_key(&self) -> Vec<u8> {
        self.owner_bytes().to_vec()
    }

    fn signature_type(&self) -> SignatureType {
        SignatureType::Arweave
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<bool> {
        if sig.len() != 512 {
            return Ok(false);
        }
        let verifier = Self::verifying_key(&self.public_key())?;
        let sig = PssSignature::try_from(sig)
            .map_err(|_| Error::InvalidSignatureLength { expected: 512, actual: sig.len() })?;

        Ok(verifier.verify(msg, &sig).is_ok())
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
