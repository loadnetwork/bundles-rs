#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SignatureType {
    Arweave = 1,
    Ed25519 = 2,
    Ethereum = 3,
    Solana = 4,
}
