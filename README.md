<p align="center">
  <a href="https://load.network">
    <img src="https://gateway.load.rs/bundle/0x83cf4417880af0d2df56ce04ecfc108ea4ee940e8fb81400e31ab81571e28d21/0">
  </a>
</p>

## About
A Rust SDK for creating, signing, and managing [ANS-104 dataitems](https://github.com/ArweaveTeam/arweave-standards/blob/master/ans/ANS-104.md).

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
# main library
bundles_rs = { git = "https://github.com/loadnetwork/bundles-rs", version = "0.1.0" }

# use individual crates
ans104 = { git = "https://github.com/loadnetwork/bundles-rs", version = "0.1.0" }
crypto = { git = "https://github.com/loadnetwork/bundles-rs", version = "0.1.0" }
```
### Dev setup

```bash
git clone https://github.com/loadnetwork/bundles-rs.git
cd bundles-rs
cargo clippy --workspace --lib --examples --tests --benches --locked --all-features
cargo +nightly fmt
cargo check --all
```

### Supported Signers

| Blockchain | Signature Type |
|:------------:|:----------------:|
| Arweave    | RSA-PSS        |
| Ethereum   | secp256k1      |
| Solana     | Ed25519   (with base58 solana flavoring)     |
| -    |   Ed25519Core (raw Ed25519) |

### Regarding Tags

This ANS-104 dataitems client fully implements the ANS-104 specification as-is

| Constraint | bundles-rs | [Spec](https://github.com/ArweaveTeam/arweave-standards/blob/master/ans/ANS-104.md) | [arbundles js](https://github.com/DHA-Team/arbundles) | [HyperBEAM ar_bundles](https://github.com/permaweb/HyperBEAM/blob/edge/src/ar_bundles.erl) |
|:------------:|:-------:|:------:|:------------:|:-----------:|
| Maximum tags per data item | <= 128 tags | <= 128 tags | <= 128 tags | No max tags | 
| Tag name max size | 1024 bytes | 1024 bytes | all KEYS+VALS <= 4096 bytes | Can have empty strings | Key+Val <=4 4096 bytes |
| Tag value max size | 3072 bytes | 3072 bytes | Can have empty strings | Val <= 3072 bytes | Can have empty strings |
| Empty names/values | non empty strings | non empty strings | Can have empty strings | Can have empty strings | + verify that HB never spawned > 4096 bytes |

> Special thanks for [@nikooo777](https://github.com/nikooo777) for compiling this list. `bundles-rs` has been added to the compiled list.

## Usage Examples

### Quick start

```rust
use bundles_rs::{
    ans104::{data_item::DataItem, tags::Tag},
    crypto::ethereum::EthereumSigner,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // create a signer
    let signer = EthereumSigner::random()?;
    
    // create tags (metadata)
    let tags = vec![
        Tag::new("Content-Type", "text/plain"),
        Tag::new("App-Name", "Load-Network"),
    ];
    
    // create and sign a dataitem
    let data = b"Hello World Arweave!".to_vec();
    // first None for Target and the second for Anchor
    // let target = [0u8; 32]; -- 32-byte target address
    // let anchor = b"unique-anchor".to_vec(); -- max 32 bytes
    let item = DataItem::build_and_sign(&signer, None, None, tags, data)?;
    
    // get the dataitem id
    let id = hex::encode(item.id());
    println!("dataitem hex id: {}", id);
    
    // serialize for upload
    let bytes = item.to_bytes()?;
    println!("Ready to upload {} bytes", bytes.len());
    
    Ok(())
}
```

#### Or for basic signed dataitem

```rust
use bundles_rs::ans104::{data_item::DataItem, tags::Tag};

// create unsigned data item
let tags = vec![Tag::new("Content-Type", "application/json")];
let data = br#"{"message": "Hello World"}"#.to_vec();
let mut item = DataItem::new(None, None, tags, data)?;

// sign dataitem
item.sign(&signer)?;
```

### Working with signers


### Ethereum Signer

```rust
use bundles_rs::crypto::ethereum::EthereumSigner;

// Generate random key
let signer = EthereumSigner::random()?;

// From private key bytes
let private_key = hex::decode("your_private_key_hex")?;
let signer = EthereumSigner::from_bytes(&private_key)?;

// Get Ethereum address
let address = signer.address_string();
println!("Ethereum address: {}", address);
```

### Solana Signer

```rust
use bundles_rs::crypto::solana::SolanaSigner;

// Generate random keypair
let signer = SolanaSigner::random();

// From Base58 private key (like solana-keygen)
let signer = SolanaSigner::from_base58("your_base58_private_key")?;

// From 32-byte secret
let secret = [0u8; 32]; // your secret bytes
let signer = SolanaSigner::from_secret_bytes(&secret)?;

// Get Solana address
let address = signer.address();
println!("Solana address: {}", address);
```

### Ed25519Core Signer

```rust
use bundles_rs::crypto::ed25519::Ed25519Core;

// Generate random
let signer = Ed25519Core::random();

// From seed bytes
let seed = [0u8; 32];
let signer = Ed25519Core::from_secret_bytes(&seed)?;
```

### Verification

### Manual

```rust
// Verify signature and structure
item.verify()?;

// Manual verification steps
assert_eq!(item.signature.len(), item.signature_type.signature_len());
assert_eq!(item.owner.len(), item.signature_type.owner_len());
```

### With Signer

```rust
let message = item.signing_message();
let is_valid = signer.verify(&message, &item.signature)?;
assert!(is_valid);
```

### Upload to Bundling services (e.g. Turbo)

```rust
use reqwest::Client;

async fn upload_to_turbo(item: &DataItem) -> Result<String, Box<dyn std::error::Error>> {
    let client = Client::new();
    let bytes = item.to_bytes()?;
    
    let response = client
        .post("https://turbo.ardrive.io/tx/solana")
        .header("Content-Type", "application/octet-stream")
        .body(bytes)
        .send()
        .await?;
    
    if response.status().is_success() {
        let tx_id = response.text().await?;
        Ok(tx_id)
    } else {
        Err(format!("Upload failed: {}", response.status()).into())
    }
}
```

For fully detailed dataitem upload example, checkout this [example](./examples/upload/).