#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SignatureType {
    None = 0,
    Arweave = 1,
    Ed25519 = 2,
    Ethereum = 3,
    Solana = 4,
}

impl From<u16> for SignatureType {
    fn from(t: u16) -> Self {
        match t {
            1 => SignatureType::Arweave,
            2 => SignatureType::Ed25519,
            3 => SignatureType::Ethereum,
            4 => SignatureType::Solana,
            _ => SignatureType::None,
        }
    }
}
