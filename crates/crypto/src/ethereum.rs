use k256::ecdsa::{Signature as K256Signature, SigningKey, VerifyingKey};

use rand::rngs::OsRng;
use sha3::{Digest, Keccak256};

use crate::{
    errors::{Error, Result},
    signer::{SignatureType, Signer},
};

#[derive(Clone)]
pub struct EthereumSigner {
    signing_key: SigningKey,
}

impl EthereumSigner {
    /// Create from a SigningKey
    pub fn new(signing_key: SigningKey) -> Self {
        Self { signing_key }
    }

    /// Create from 32-bytes private key
    pub fn from_bytes(private_key: &[u8]) -> Result<Self> {
        let key: &[u8; 32] = private_key
            .try_into()
            .map_err(|_| Error::InvalidKeyLength { expected: 32, actual: private_key.len() })?;

        let signing_key = SigningKey::from_bytes(key.into()).map_err(|e| Error::Other(e.into()))?;
        Ok(Self { signing_key })
    }

    /// Generate a new key
    pub fn random() -> Result<Self> {
        let signing_key = SigningKey::random(&mut OsRng);
        Ok(Self { signing_key })
    }

    /// Get the verifying key
    pub fn verifying_key(&self) -> VerifyingKey {
        *self.signing_key.verifying_key()
    }

    /// Return the uncompressed public key bytes (0x04-prefixed)
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.verifying_key().to_encoded_point(false).as_bytes().to_vec()
    }

    /// Get Ethereum address (last 20 bytes of keccak256(public_key))
    pub fn address(&self) -> [u8; 20] {
        let pubkey = self.verifying_key().to_encoded_point(false);
        let pubkey = &pubkey.as_bytes()[1..]; // Skip the 0x04 prefix

        let mut hasher = Keccak256::new();
        hasher.update(pubkey);
        let hash = hasher.finalize();

        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..]);
        address
    }

    /// Format Ethereum address as hex string with 0x prefix
    pub fn address_string(&self) -> String {
        format!("0x{}", hex::encode(self.address()))
    }

    /// Create Ethereum signed message hash
    /// Following the format: "\x19Ethereum Signed Message:\n" + len(message) + message
    pub fn eth_message_hash(message: &[u8]) -> [u8; 32] {
        let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
        let mut hasher = Keccak256::new();
        hasher.update(prefix.as_bytes());
        hasher.update(message);

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize());
        hash
    }
}

impl Signer for EthereumSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let msg_hash = Self::eth_message_hash(message);

        let (signature, recovery_id) = self
            .signing_key
            .sign_prehash_recoverable(&msg_hash)
            .map_err(|e| Error::Other(e.into()))?;
        let mut eth_sig = Vec::with_capacity(65);
        eth_sig.extend_from_slice(&signature.to_bytes());
        eth_sig.push(recovery_id.to_byte() + 27);
        Ok(eth_sig)
    }

    fn public_key(&self) -> Vec<u8> {
        self.verifying_key().to_encoded_point(false).as_bytes().to_vec()
    }

    fn signature_type(&self) -> SignatureType {
        SignatureType::Ethereum
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        if signature.len() != 65 {
            return Err(Error::InvalidSignatureLength { expected: 65, actual: signature.len() });
        }

        let r_s = &signature[..64];
        let v = signature[64];

        let msg_hash = Self::eth_message_hash(message);
        let recovery_id = k256::ecdsa::RecoveryId::try_from(v.wrapping_sub(27))
            .map_err(|e| Error::Other(e.into()))?;

        let sig = K256Signature::from_slice(r_s).map_err(|e| Error::Other(e.into()))?;
        let recovered_key = VerifyingKey::recover_from_prehash(&msg_hash, &sig, recovery_id)
            .map_err(|e| Error::Other(e.into()))?;

        Ok(recovered_key == self.verifying_key())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_ethereum_sign_verify() {
        let signer = EthereumSigner::random().unwrap();
        let message = b"Hello, Ethereum!";

        let signature = signer.sign(message).unwrap();
        assert_eq!(signature.len(), 65);

        let public_key = signer.public_key();
        assert_eq!(public_key.len(), 65);
        assert_eq!(public_key[0], 0x04);
        assert!(signer.verify(message, &signature).unwrap());
        assert!(!signer.verify(b"wron msg", &signature).unwrap());
    }

    #[test]
    fn test_ethereum_address() {
        // Test with known key

        let private_key = hex!("0000000000000000000000000000000000000000000000000000000000000001");
        let signer = EthereumSigner::from_bytes(&private_key).unwrap();

        // Expected address for this private key
        let expected_address = hex!("7e5f4552091a69125d5dfcb7b8c2659029395bdf");
        assert_eq!(signer.address(), expected_address);

        let addr_string = signer.address_string();
        assert_eq!(addr_string, "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf");
    }

    #[test]
    fn test_message_hash() {
        let message = b"test";
        let hash = EthereumSigner::eth_message_hash(message);

        let expected = hex!("4a5c5d454721bbbb25540c3317521e71c373ae36458f960d2ad46ef088110e95");
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_known_signature() {
        // Test vector from a known Ethereum implementation
        let private_key = hex!("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318");
        let signer = EthereumSigner::from_bytes(&private_key).unwrap();

        let message = b"Example `personal_sign` message";
        let signature = signer.sign(message).unwrap();

        // Verify the signature structure
        assert_eq!(signature.len(), 65);
        let v = signature[64];
        assert!(v == 27 || v == 28); // Valid recovery IDs

        // Verify it can be verified
        assert!(signer.verify(message, &signature).unwrap());
    }
}
