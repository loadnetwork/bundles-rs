## About

`references` is a small Rust SDK for reading `reference@1.0` values and namespace
names, plus setting a new `reference-value` for an existing reference.

It mirrors the JS `@permaweb/references` [SDK](https://github.com/permaweb/permaweb-references) functionalities.

## Installation

```toml
[dependencies]
# main library
bundles_rs = { git = "https://github.com/permaweb/bundles-rs", branch = "main" }

# references only
references = { git = "https://github.com/permaweb/bundles-rs", branch = "main" }
```

## Imports

```rust
use bundles_rs::crypto::arweave::ArweaveSigner;
use bundles_rs::references::{
    ReferenceClient, UpdateReferenceOptions, PHASE2_BOOTSTRAP_OWNER, PHASE2_NAMESPACE,
};
```

## Usage

### Resolve Name

```rust
let client = ReferenceClient::new();
let value = client.resolve_name("ao").await.unwrap();
println!("value: {:?}", value);
```

### Read Name With Metadata

```rust
let client = ReferenceClient::new();
let name = client.get_name("ao").await.unwrap().unwrap();

println!("name: {}", name.name);
println!("reference id: {}", name.reference_id);
println!("authority: {:?}", name.authority);
println!("timestamp: {}", name.timestamp);
println!("source: {:?}", name.source);
println!("value: {:?}", name.value);
```

### Resolve Reference

```rust
let client = ReferenceClient::new();
let value = client.resolve_reference("REFERENCE_ID").await.unwrap();
println!("value: {:?}", value);
```

### Set Existing Reference Value

```rust
let signer = ArweaveSigner::random().unwrap();
let client = ReferenceClient::new();

let tx = client
    .update_reference(
        &signer,
        "REFERENCE_ID",
        UpdateReferenceOptions {
            value: Some("NEW_TARGET_TX_ID".to_string()),
            timestamp: None,
        },
    )
    .await
    .unwrap();

println!("set tx: {}", tx.id);
```

`update_reference` checks the current reference authority before posting. For
non-Arweave signers, pass the authority address explicitly:

```rust
let tx = client
    .update_reference_as(
        &signer,
        "AUTHORITY_ADDRESS",
        "REFERENCE_ID",
        UpdateReferenceOptions {
            value: Some("NEW_TARGET_TX_ID".to_string()),
            timestamp: Some(1_717_000_000_001),
        },
    )
    .await
    .unwrap();
```

### Read Reference With Metadata

```rust
let client = ReferenceClient::new();
let reference = client.get_reference("REFERENCE_ID").await.unwrap().unwrap();

println!("authority: {:?}", reference.authority);
println!("timestamp: {}", reference.timestamp);
println!("source: {:?}", reference.source);
println!("value: {:?}", reference.value);
```

### Custom Gateway or Bundler

```rust
use bundles_rs::bundler::BundlerClient;
use bundles_rs::references::{ReferenceClient, PHASE2_NAMESPACE};

let client = ReferenceClient::with_gateway("https://arweave.net")
    .graphql("https://arweave.net/graphql")
    .namespace(PHASE2_NAMESPACE)
    .bundler(BundlerClient::default());
```

## Low-Level Helpers

```rust
use bundles_rs::references::{build_set_tags, BuildSetOptions};

let set_tags = build_set_tags(BuildSetOptions {
    reference_id: "REFERENCE_ID".to_string(),
    value: Some("NEW_TARGET_TX_ID".to_string()),
    timestamp: 2,
});
```

## Trusted Bootstrap Publisher

the phase-2 `Permaweb Names` namespace root and trusted bootstrap publisher as:

```rust
use bundles_rs::references::{PHASE2_BOOTSTRAP_OWNER, PHASE2_NAMESPACE};

assert_eq!(
    PHASE2_BOOTSTRAP_OWNER,
    "uAaRGha_a1ni_VjLf9Be2SFB7NJw1PWnjevdfeuJ_7c"
);
assert_eq!(
    PHASE2_NAMESPACE,
    "w0eqd43OMzzXr-5yhFC-LkgifQqih8YEPb4mLt6VSZo"
);
```
