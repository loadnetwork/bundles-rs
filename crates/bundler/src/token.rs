use crypto::signer::SignatureType;

pub(crate) fn token_ticker(sign_type: SignatureType) -> Option<String> {
    match sign_type {
        SignatureType::Arweave => Some("arweave".to_string()),
        SignatureType::Ethereum => Some("ethereum".to_string()),
        SignatureType::Ed25519 => Some("solana".to_string()),
        _ => None
    }
}