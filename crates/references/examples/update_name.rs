//! Update the `reference-value` for an existing named reference.

use anyhow::{Context, Result};
use crypto::arweave::ArweaveSigner;
use references::{ReferenceClient, UpdateReferenceOptions};

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let name = args.next().context("missing Permaweb Name value")?;
    let value = args.next().context("missing new reference-value argument")?;
    let wallet = args.next().unwrap_or_else(|| "wallet.json".to_string());

    let signer = ArweaveSigner::from_jwk_file(&wallet)
        .with_context(|| format!("failed to load wallet from {wallet}"))?;
    let client = ReferenceClient::new();
    let resolved = client
        .get_name(&name)
        .await?
        .with_context(|| format!("name not found: {name}"))?;

    println!("name={}", resolved.name);
    println!("reference_id={}", resolved.reference_id);
    println!("current_value={}", resolved.value);
    println!("authority={:?}", resolved.authority);
    println!("signer={}", signer.address());

    let tx = client
        .update_reference(
            &signer,
            &resolved.reference_id,
            UpdateReferenceOptions { value: Some(value), timestamp: None },
        )
        .await?;

    println!("set_tx={}", tx.id);
    Ok(())
}
