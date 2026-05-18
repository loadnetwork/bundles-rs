use std::path::PathBuf;

use anyhow::{Result, anyhow};
use bundles_rs::{ans104::data_item::DataItem, bundler::client::BundlerClient};
use clap::Parser;

#[derive(Parser)]
#[command(author, version, about)]
struct Opts {
    #[arg(long, default_value = "items")]
    items_dir: PathBuf,
    // default temporary public good, use your hyperbeam bundler instead
    #[arg(long, default_value = "https://bundler.mystical.computer/")]
    node: String,

    #[arg(long)]
    verify_only: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    let opts = Opts::parse();
    let paths = item_paths(&opts.items_dir)?;

    if opts.verify_only {
        let mut failed = 0usize;
        for path in paths {
            match read_verified_item(&path) {
                Ok((id, _)) => println!("{} -> {}", path.display(), id),
                Err(error) => {
                    failed += 1;
                    println!("{} -> {error}", path.display());
                }
            }
        }

        if failed > 0 {
            return Err(anyhow!("{failed} item(s) failed verification"));
        }

        return Ok(());
    }

    let client = BundlerClient::hyperbeam().url(&opts.node).build()?;
    for path in paths {
        let (id, item) = read_verified_item(&path)?;
        let tx = client.clone().send_transaction(item).await?;
        if tx.id != id {
            return Err(anyhow!("expected {id}, got {}", tx.id));
        }

        println!("{} -> {}", path.display(), tx.id);
    }

    Ok(())
}

fn item_paths(dir: &PathBuf) -> Result<Vec<PathBuf>> {
    let mut paths = std::fs::read_dir(dir)
        .map_err(|error| anyhow!("read {}: {error}", dir.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|error| anyhow!("read {}: {error}", dir.display()))?;

    paths.retain(|path| path.extension().and_then(|ext| ext.to_str()) == Some("bin"));
    paths.sort();

    if paths.is_empty() {
        return Err(anyhow!("no .bin items found in {}", dir.display()));
    }

    Ok(paths)
}

fn read_verified_item(path: &PathBuf) -> Result<(String, DataItem)> {
    let raw = std::fs::read(path).map_err(|error| anyhow!("read {}: {error}", path.display()))?;
    let item =
        DataItem::from_bytes(&raw).map_err(|error| anyhow!("parse {}: {error}", path.display()))?;
    item.verify().map_err(|error| anyhow!("verify {}: {error}", path.display()))?;

    Ok((item.arweave_id(), item))
}
