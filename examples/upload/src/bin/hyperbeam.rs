use anyhow::{Result, anyhow};
use bundles_rs::{
    ans104::{data_item::DataItem, tags::Tag},
    bundler::client::BundlerClient,
    crypto::arweave::ArweaveSigner,
};
use clap::Parser;

#[derive(Parser)]
#[command(author, version, about)]
struct Opts {
    #[arg(long, value_name = "FILE")]
    blob: String,

    #[arg(long, default_value = "wallet.json")]
    wallet: String,

    #[arg(long, default_value = "https://lapee.hyperzine.xyz")]
    node: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    let opts = Opts::parse();
    let blob = std::fs::read(&opts.blob).map_err(|error| anyhow!("read {}: {error}", opts.blob))?;
    let signer = ArweaveSigner::from_jwk_file(&opts.wallet)?;
    let tags = vec![Tag::new("Content-Type", "text/plain")];
    let item = DataItem::build_and_sign(&signer, None, None, tags, blob)?;
    let tx = BundlerClient::hyperbeam()
        .url(&opts.node)
        .auto_fund(signer)
        .build()?
        .send_transaction(item)
        .await?;

    println!("uploaded: item_id={}", tx.id);
    println!("Bundler link: {}/{}", opts.node.trim_end_matches('/'), tx.id);
    println!("Arweave URL: https://arweave.net/{}", tx.id);

    Ok(())
}
