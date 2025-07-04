use anyhow::{Result, anyhow};
use bundles_rs::{
    ans104::{data_item::DataItem, tags::Tag},
    crypto::solana::SolanaSigner,
};
use clap::Parser;

const BUNDLR: &str = "https://turbo.ardrive.io/tx/solana";

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
        (Some(path), None) => {
            let blob = std::fs::read(path)?;
            let sk = std::env::var("SOLANA_PK").expect("set SOLANA_PK with your Turbo Solana key");

            let (item_id, _) = upload_and_save(&blob, &sk).await?;
            println!("✔ uploaded — item_id={item_id}");
        }
        _ => return Err(anyhow!("use either --blob <file> or --verify <tx_id>")),
    }

    Ok(())
}
async fn upload_and_save(blob: &[u8], sk: &str) -> Result<(String, Vec<u8>)> {
    let tags = vec![
        Tag::new("Content-Type", "application/octet-stream"),
        Tag::new("Prototype", "Trustless verification v0"),
    ];

    let signer = SolanaSigner::from_base58(sk)?;

    let pub_key = signer.public_key();
    println!("Signer public key: {} bytes", pub_key.len());
    println!("Public key (base58): {}", bs58::encode(&pub_key).into_string());

    let item = DataItem::build_and_sign(&signer, None, None, tags.clone(), blob.to_vec())?;
    let item_bytes = item.to_bytes()?;

    let client = reqwest::Client::new();

    println!("\n=== Testing {BUNDLR} ===");

    let res = client
        .post(BUNDLR)
        .header("Content-Type", "application/octet-stream")
        .body(item_bytes.clone())
        .send()
        .await?;

    let res_status = res.status();

    println!("Response: {}", res.status());
    if res.status().is_success() {
        let text = res.text().await?;
        println!("Success! Response: {text}");
        return Ok((text, item_bytes));
    } else {
        let error = res.text().await?;
        println!("Error: {error}");
    }

    Err(anyhow!("Upload failed with status: {}", res_status))
}
