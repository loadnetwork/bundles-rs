/*!  -------------------------------------------------------------------------
Arweave upload -> trust-neutral verification demo (auditor perspective)

    • step 1  upload blob through Turbo/Irys
    • step 2  learn bundle tx via GraphQL  (`bundledIn`)
    • step 3  wait until tx is mined       (`/tx/:id/status`)
    • step 4  header-only membership check (Range: 0-headerLen-1)
    • step 5  deep-hash + signature check  (uses local DataItem bytes
                                             OR range-fetch if --download-item)
    • step 6  tx-level Merkle path         (`/tx/:id/offset`)  <-- proof of block inclusion

All hashes / sig types follow ANS-104 + core-node 2.9.4.1:
    deep-hash = SHA-384  ▶︎ Ed25519 / RSA / secp256k1
    item_id   = SHA-256(signature)

Links:
  − ANS-104 spec   https://github.com/ArweaveTeam/arweave-standards/blob/master/ans/ANS-104.md
  − Core node rel. https://github.com/ArweaveTeam/arweave/releases
--------------------------------------------------------------------------- */

use anyhow::{Result, anyhow};
// use bundles_rs::{BundlrBuilder, currency::solana::SolanaBuilder, tags::Tag};

use clap::Parser;
use reqwest::Client;
use serde_json::Value;
use tokio::time::{Duration, sleep};

use apache_avro::{Reader, Schema};
use base64::{Engine as _, engine::general_purpose};
use ed25519_dalek::{Signature as EdSig, Verifier, VerifyingKey as EdPk};
use k256::{
    ecdsa::{
        RecoveryId, Signature as SecpSignature, VerifyingKey as SecpVerifyingKey,
        signature::Verifier as SecpVerifier,
    },
    elliptic_curve::sec1::ToEncodedPoint,
};
use num_bigint::BigUint;
use rsa::{RsaPublicKey, pkcs1v15::Pkcs1v15Sign};

use sha2::{Digest, Sha256, Sha384};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

use bundles_rs::ans104::{tags::Tag, *};

const GATEWAY: &str = "https://arweave.net";
const BUNDLR: &str = "https://turbo.ardrive.io";

#[derive(Parser)]
#[command(author, version, about)]
struct Opts {
    #[arg(long, value_name = "FILE", conflicts_with = "verify")]
    blob: Option<String>,

    #[arg(long, value_name = "TX_ID", conflicts_with = "blob")]
    verify: Option<String>,

    #[arg(long, default_value_t = 128)]
    concurrency: usize,

    #[arg(long, default_value_t = 1)]
    confirmations: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    let opts = Opts::parse();

    match (&opts.blob, &opts.verify) {
        /* upload + end-to-end proof ----------------------------------- */
        (Some(path), None) => {
            let blob = std::fs::read(path)?;
            let irys_pk =
                std::env::var("SOLANA_PK").expect("set SOLANA_PK with your Turbo/Irys Solana key");

            let (item_id, di) = upload_and_save(&blob, &irys_pk).await?;
            println!("✔ uploaded — item_id={item_id}");
        }
        _ => return Err(anyhow!("use either --blob <file> or --verify <tx_id>")),
    }

    Ok(())
}

/* -------------------------------- helpers ---------------------------------- */

// async fn upload_and_save(blob: &[u8], irys_pk: &str) -> Result<(String, Vec<u8>)> {
//     let tags = vec![
//         Tag::new("Content-Type", "application/octet-stream"),
//         Tag::new("Prototype", "Trustless verification v0"),
//     ];

//     let mut tx = bundles_rs::ans104::data_item::DataItem::new((blob.to_vec(), tags.clone()))?;

//     bundlr.sign_transaction(&mut tx).await?;

//     let data_item_bytes = tx.clone().as_bytes()?;

//     println!("transaction created and signed");
//     // Debug: inspect the transaction structure
//     println!("Transaction size: {} bytes", data_item_bytes.len());
//     println!(
//         "First 100 bytes: {:?}",
//         &data_item_bytes[..100.min(data_item_bytes.len())]
//     );

//     let res: Value = bundlr.send_transaction(tx).await?;
//     let item_id = res["id"].as_str().ok_or(anyhow!("no id"))?.to_owned();

//         //
//     let client = reqwest::Client::new();
//     let res = client
//         .post("https://turbo.ardrive.io")
//         .body(data_item_bytes)
//         .send()
//         .await?;
//         println!("transaction uploaded to bundler {item_id}");

//     Ok((item_id, data_item_bytes))
// }

async fn upload_and_save(blob: &[u8], irys_pk: &str) -> Result<(String, Vec<u8>)> {
    use bundles_rs::{
        ans104::{data_item::DataItem, tags::Tag},
        crypto::{signer::Signer, solana::SolanaSigner},
    };

    // Tags for the upload
    let tags = vec![
        Tag::new("Content-Type", "application/octet-stream"),
        Tag::new("Prototype", "Trustless verification v0"),
    ];

    // Create Solana signer
    let key = SolanaSigner::from_base58(irys_pk)?;

    let signer = SolanaSigner::from_base58(irys_pk)?; // Concrete type
    let item = DataItem::build_and_sign(&signer, None, None, tags, blob.to_vec())?;

    let data_item_bytes = item.to_bytes()?; // serializes & verifies structure

    println!("transaction created and signed");
    println!("Transaction size: {} bytes", data_item_bytes.len());
    println!("First 100 bytes: {:?}", &data_item_bytes[..100.min(data_item_bytes.len())]);

    // Upload to the Bundlr node
    let client = reqwest::Client::new();
    use reqwest::Url;

    let currency_id = 2; // Solana is 2 per your SignatureType enum

    let url = Url::parse(BUNDLR)?
        .join(&format!("tx/{}", currency_id))
        .map_err(|e| anyhow!("invalid upload URL: {}", e))?;

    let client = reqwest::Client::new();
    let res = client
        .post(url)
        .header("Content-Type", "application/octet-stream")
        .body(data_item_bytes.clone())
        .send()
        .await?;

    /*

                       .join(&format!("tx/{}", self.currency.get_type()))
               .map_err(|err| BundlrError::ParseError(err.to_string()))?,
       )
       .header("Content-Type", "application/octet-stream")
       .body(tx)
    */
    if !res.status().is_success() {
        return Err(anyhow!("upload failed: {}", res.status()));
    }

    let json: Value = res.json().await?;
    let item_id =
        json["id"].as_str().ok_or_else(|| anyhow!("missing `id` in response"))?.to_string();

    println!("transaction uploaded to bundler {item_id}");

    Ok((item_id, data_item_bytes))
}
