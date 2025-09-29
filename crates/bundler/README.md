## About
`bundler` crate is Rust SDK to interact with Arweave (ANS-104) bundling services. This crate is designed to be backward compatible with existing bundling services and fine tuned for [Turbo](https://turbo.ardrive.io/)

> The offchain bundling service (Load S3), introduced in SDK v3, only supports the `send_transaction()` method. Its Fast Finality Indexes resolve only DataItems signed with Arweave key.

## Installation

```toml
[dependencies]
# main library
bundles_rs = { git = "https://github.com/loadnetwork/bundles-rs", branch = "main" }

# bundler only
bundler = { git = "https://github.com/loadnetwork/bundles-rs", branch = "main" }
```
### Imports

```rust
use bundles_rs::bundler::BundlerClient;
use bundles_rs::ans104::{data_item::DataItem, tags::Tag};
use bundles_rs::crypto::solana::SolanaSigner;
```

## Usage Example

### Send Transaction (Solana)

```rust
let client = BundlerClient::new().url("https://upload.ardrive.io").build().unwrap();
let signer = SolanaSigner::random();
let tags = vec![Tag::new("content-type", "text/plain")];
let dataitem = DataItem::build_and_sign(&signer, None, None, tags, b"hello world".to_vec()).unwrap();

let tx = client.send_transaction(dataitem).await.unwrap();
println!("tx: {:?}", tx);
```

### Send Transaction (Turbo)

```rust
let client = BundlerClient::turbo().build().unwrap();
let signer = SolanaSigner::random();
let tags = vec![Tag::new("content-type", "text/plain")];
let dataitem = DataItem::build_and_sign(&signer, None, None, tags, b"hello world turbo".to_vec()).unwrap();

let tx = client.send_transaction(dataitem).await.unwrap();
println!("tx: {:?}", tx);
```

### Send Transaction (Load S3 - offchain)

```rust
let client = BundlerClient::offchain().build().unwrap();
// the data_caches/fast_finality_indexes only support AR signatures for now
let signer = ArweaveSigner::random();
let tags = vec![Tag::new("content-type", "text/plain")];
let dataitem = DataItem::build_and_sign(&signer, None, None, tags, b"hello world LS3".to_vec()).unwrap();

let tx = client.send_transaction(dataitem).await.unwrap();
println!("tx: {:?}", tx);
```

### Get Default Client Info

```rust
let client = BundlerClient::default().build().unwrap();
let info = client.info().await.unwrap();
println!("{:?}", info);
```

### Get Turbo Client Info

```rust
let client = BundlerClient::turbo().build().unwrap();
let info = client.info().await.unwrap();
println!("{:?}", info);
```

### Get Price for Bytes (Turbo)

```rust
let client = BundlerClient::turbo().build().unwrap();
let price = client.bytes_price(99999).await.unwrap();
println!("{:?}", price);
```

### Get Rates (Turbo)

```rust
let client = BundlerClient::turbo().build().unwrap();
let rates = client.get_rates().await.unwrap();
println!("{:?}", rates);
```

### Check Transaction Status (Turbo)

```rust
let client = BundlerClient::turbo().build().unwrap();
let status = client.status("w5n6r6PvqBRph2or4WiyjLumL9HE-IR_JgEcnct_3b0").await.unwrap();
println!("{:?}", status);
```

## Turbo API References:

* upload api: https://upload.ardrive.io/api-docs
* payment api: https://payment.ardrive.io/api-docs

## Load S3 Upload Service API References:
* loaded-turbo-api: https://github.com/loadnetwork/loaded-turbo-api