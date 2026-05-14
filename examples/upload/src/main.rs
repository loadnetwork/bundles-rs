use anyhow::{Result, anyhow};
use bundles_rs::{
    ans104::{data_item::DataItem, tags::Tag},
    bundler::{
        client::BundlerClient,
        hb_funding::{
            DEFAULT_AO_STATE_URL, DEFAULT_AO_TOKEN_ID, DEFAULT_DEPOSIT_IMPORT_PATH,
            DEFAULT_LEDGER_ROUTE, DEFAULT_MU_URL, DepositImport, ao_deposit_address,
            import_deposit, ledger_balance, quote_ar_bytes, send_ao_message, sign_ao_transfer,
            wait_for_assignment_slot,
        },
    },
    crypto::arweave::ArweaveSigner,
    crypto::solana::SolanaSigner,
};
use clap::Parser;
use std::time::Duration;

const BUNDLR: &str = "https://turbo.ardrive.io/tx/solana";

#[derive(Parser)]
#[command(author, version, about)]
struct Opts {
    #[arg(long, value_name = "FILE", conflicts_with = "verify")]
    blob: Option<String>,

    #[arg(long, value_name = "TX_ID", conflicts_with = "blob")]
    verify: Option<String>,

    #[arg(long)]
    hyperbeam: bool,

    #[arg(long, default_value = "wallet.json")]
    wallet: String,

    #[arg(long, default_value = "https://lapee.hyperzine.xyz")]
    node: String,

    #[arg(long)]
    auto_fund: bool,

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

            if opts.hyperbeam {
                let id = upload_hyperbeam(&blob, &opts).await?;
                println!("✔ uploaded — item_id={id}");
                println!("Bundler link: {}/{}", opts.node.trim_end_matches('/'), id);
                println!("Arweave URL: https://arweave.net/{id}");
                return Ok(());
            }

            let sk = std::env::var("SOLANA_PK").expect("set SOLANA_PK with your Turbo Solana key");

            let (item_id, _) = upload_and_save(&blob, &sk).await?;
            println!("✔ uploaded — item_id={item_id}");
        }
        _ => return Err(anyhow!("use either --blob <file> or --verify <tx_id>")),
    }

    Ok(())
}

async fn upload_hyperbeam(blob: &[u8], opts: &Opts) -> Result<String> {
    let signer = ArweaveSigner::from_jwk_file(&opts.wallet)?;
    let tags = vec![Tag::new("Content-Type", "application/octet-stream")];
    let item = DataItem::build_and_sign(&signer, None, None, tags, blob.to_vec())?;
    let item_size = item.to_bytes()?.len() as u64;

    let client = reqwest::Client::new();

    if opts.auto_fund {
        auto_fund_hyperbeam(client.clone(), &opts.node, &signer, item_size).await?;
    }

    let response =
        BundlerClient::hyperbeam().url(&opts.node).build()?.send_transaction(item).await?;

    Ok(response.id)
}

async fn auto_fund_hyperbeam(
    client: reqwest::Client,
    node_url: &str,
    signer: &ArweaveSigner,
    item_size: u64,
) -> Result<()> {
    let recipient = signer.address();
    let required = quote_ar_bytes(client.clone(), node_url, item_size).await?;
    let before = ledger_balance(client.clone(), node_url, DEFAULT_LEDGER_ROUTE, &recipient).await?;

    if before >= required {
        println!("HyperBEAM credit ok: {before} >= {required}");
        return Ok(());
    }

    let quantity = required - before;
    let deposit_address = ao_deposit_address(client.clone(), node_url).await?;
    println!("Funding HyperBEAM ledger: {quantity} AO base units");

    let transfer = sign_ao_transfer(signer, DEFAULT_AO_TOKEN_ID, quantity, &deposit_address)?;
    let message_id = send_ao_message(client.clone(), DEFAULT_MU_URL, transfer).await?;
    println!("AO transfer message: {message_id}");

    let slot = wait_for_assignment_slot(
        client.clone(),
        DEFAULT_AO_STATE_URL,
        DEFAULT_AO_TOKEN_ID,
        &message_id,
        Duration::from_secs(5),
        Duration::from_secs(360),
    )
    .await?;
    println!("AO assignment slot: {slot}");

    import_deposit(
        client.clone(),
        node_url,
        DepositImport {
            import_path: DEFAULT_DEPOSIT_IMPORT_PATH,
            message_id: &message_id,
            quantity,
            recipient: &recipient,
            sender: &recipient,
            slot: &slot,
            token_id: DEFAULT_AO_TOKEN_ID,
        },
    )
    .await?;

    let after = ledger_balance(client, node_url, DEFAULT_LEDGER_ROUTE, &recipient).await?;
    println!("HyperBEAM credit after import: {after}");

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
