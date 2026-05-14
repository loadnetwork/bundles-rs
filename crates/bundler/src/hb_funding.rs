//! HyperBEAM AO funding helpers.

use std::time::{Duration, Instant};

use ans104::{data_item::DataItem, tags::Tag};
use anyhow::{Error, anyhow};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use crypto::{arweave::ArweaveSigner, signer::Signer};
use reqwest::{Client, Url};
use serde_json::Value;

use crate::hyperbeam::hb_path_url;

/// Default AO token process used by the HyperBEAM AO payment profile.
pub const DEFAULT_AO_TOKEN_ID: &str = "0syT13r0s0tgPmIed95bJnuSqaD29HQNN8D3ElLSrsc";
/// Default AO message unit used by aoconnect legacy mode.
pub const DEFAULT_MU_URL: &str = "https://mu.ao-testnet.xyz/";
/// Default AO state endpoint used to locate the assignment slot.
pub const DEFAULT_AO_STATE_URL: &str = "https://state.forward.computer";
/// Default HyperBEAM ledger route.
pub const DEFAULT_LEDGER_ROUTE: &str = "/ledger~node-process@1.0";
/// Default HyperBEAM deposit import route.
pub const DEFAULT_DEPOSIT_IMPORT_PATH: &str = "/~ao-payment@1.0/ingest";
/// HyperBEAM quote route for AR byte pricing.
pub const BYTE_PRICE_QUOTE_PATH: &str = "/~arweave-byte-pricing@1.0/quote";
/// HyperBEAM AO deposit address route.
pub const AO_DEPOSIT_ADDRESS_PATH: &str = "/~meta@1.0/info/address";

/// Create the signed AO token transfer message used by HyperBEAM auto-funding.
pub fn sign_ao_transfer<S: Signer>(
    signer: &S,
    token_id: &str,
    quantity: u128,
    deposit_address: &str,
) -> Result<DataItem, Error> {
    let target = decode_target(token_id)?;
    let tags = vec![
        Tag::new("Action", "Transfer"),
        Tag::new("Quantity", quantity.to_string()),
        Tag::new("Recipient", deposit_address),
        Tag::new("Content-Type", "text/plain"),
        Tag::new("SDK", "aoconnect"),
        Tag::new("Data-Protocol", "ao"),
        Tag::new("Variant", "ao.TN.1"),
        Tag::new("Type", "Message"),
    ];

    DataItem::build_and_sign(signer, Some(target), None, tags, b" ".to_vec())
}

/// Send a signed AO message to MU and return its message id.
pub async fn send_ao_message(
    client: Client,
    mu_url: &str,
    signed_message: DataItem,
) -> Result<String, Error> {
    let message_id = signed_message.arweave_id();
    let response = client
        .post(mu_url)
        .header("Content-Type", "application/octet-stream")
        .header("Accept", "application/json")
        .body(signed_message.to_bytes()?)
        .send()
        .await?;

    if !response.status().is_success() {
        return Err(anyhow!("AO message submit failed: {}", response_preview(response).await));
    }

    Ok(message_id)
}

/// Poll AO state until the message assignment slot is visible.
pub async fn wait_for_assignment_slot(
    client: Client,
    state_url: &str,
    process_id: &str,
    message_id: &str,
    poll_interval: Duration,
    timeout: Duration,
) -> Result<String, Error> {
    let from_slot = current_slot(client.clone(), state_url, process_id).await?.saturating_sub(5);
    let deadline = Instant::now() + timeout;

    while Instant::now() < deadline {
        let to_slot = current_slot(client.clone(), state_url, process_id).await? + 20;
        let url = format!(
            "{}/{}~process@1.0/schedule?from={}&to={}&accept=application/aos-2",
            state_url.trim_end_matches('/'),
            process_id,
            from_slot,
            to_slot
        );
        let response = client.get(url).send().await?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "AO schedule request failed: {}",
                response_preview(response).await
            ));
        }

        if let Some(slot) = assignment_slot(&response.json().await?, message_id) {
            return Ok(slot);
        }

        tokio::time::sleep(poll_interval).await;
    }

    Err(anyhow!("AO message did not appear in schedule: {}", message_id))
}

/// Import an AO transfer into the HyperBEAM node's local payment ledger.
pub async fn import_deposit(
    client: Client,
    node_url: &str,
    request: DepositImport<'_>,
) -> Result<(), Error> {
    let mut url = Url::parse(&hb_path_url(node_url, request.import_path))?;
    url.query_pairs_mut()
        .append_pair("token", request.token_id)
        .append_pair("deposit-address", request.deposit_address)
        .append_pair("message-id", request.message_id)
        .append_pair("quantity", &request.quantity.to_string())
        .append_pair("recipient", request.recipient)
        .append_pair("sender", request.sender)
        .append_pair("slot", request.slot);

    let response = client.post(url).send().await?;
    if !response.status().is_success() {
        return Err(anyhow!("Deposit import failed: {}", response_preview(response).await));
    }

    Ok(())
}

/// Ensure enough local HyperBEAM AO ledger credit exists for an upload.
pub async fn auto_fund_upload(
    client: Client,
    node_url: &str,
    signer: &ArweaveSigner,
    upload_size: u64,
) -> Result<(), Error> {
    let recipient = signer.address();
    let required = quote_ar_bytes(client.clone(), node_url, upload_size).await?;
    let before = ledger_balance(client.clone(), node_url, DEFAULT_LEDGER_ROUTE, &recipient).await?;

    if before >= required {
        return Ok(());
    }

    let quantity = required - before;
    let deposit_address = ao_deposit_address(client.clone(), node_url).await?;
    let transfer = sign_ao_transfer(signer, DEFAULT_AO_TOKEN_ID, quantity, &deposit_address)?;
    let message_id = send_ao_message(client.clone(), DEFAULT_MU_URL, transfer).await?;
    let slot = wait_for_assignment_slot(
        client.clone(),
        DEFAULT_AO_STATE_URL,
        DEFAULT_AO_TOKEN_ID,
        &message_id,
        Duration::from_secs(5),
        Duration::from_secs(360),
    )
    .await?;

    import_deposit(
        client,
        node_url,
        DepositImport {
            import_path: DEFAULT_DEPOSIT_IMPORT_PATH,
            deposit_address: &deposit_address,
            message_id: &message_id,
            quantity,
            recipient: &recipient,
            sender: &recipient,
            slot: &slot,
            token_id: DEFAULT_AO_TOKEN_ID,
        },
    )
    .await
}

/// Deposit import request fields.
#[derive(Debug, Clone, Copy)]
pub struct DepositImport<'a> {
    /// Deposit import path on the HyperBEAM node.
    pub import_path: &'a str,
    /// AO token deposit address.
    pub deposit_address: &'a str,
    /// AO transfer message id.
    pub message_id: &'a str,
    /// Imported quantity in AO base units.
    pub quantity: u128,
    /// Local ledger recipient address.
    pub recipient: &'a str,
    /// AO transfer sender address.
    pub sender: &'a str,
    /// AO assignment slot nonce.
    pub slot: &'a str,
    /// AO token process id.
    pub token_id: &'a str,
}

/// Get the HyperBEAM AO deposit address.
pub async fn ao_deposit_address(client: Client, node_url: &str) -> Result<String, Error> {
    let response = client.get(hb_path_url(node_url, AO_DEPOSIT_ADDRESS_PATH)).send().await?;
    if !response.status().is_success() {
        return Err(anyhow!(
            "AO deposit address request failed: {}",
            response_preview(response).await
        ));
    }

    Ok(response.text().await?.trim().to_string())
}

/// Get the local HyperBEAM ledger balance for an address.
pub async fn ledger_balance(
    client: Client,
    node_url: &str,
    ledger_route: &str,
    address: &str,
) -> Result<u128, Error> {
    let path = format!("{}/now/balance/{}", ledger_route.trim_end_matches('/'), address);
    let response = client.get(hb_path_url(node_url, &path)).send().await?;

    if response.status().as_u16() == 404 {
        return Ok(0);
    }

    if !response.status().is_success() {
        return Err(anyhow!("Ledger balance request failed: {}", response_preview(response).await));
    }

    Ok(response.text().await?.trim().parse()?)
}

/// Quote HyperBEAM AR byte upload cost in AO base units.
pub async fn quote_ar_bytes(client: Client, node_url: &str, bytes: u64) -> Result<u128, Error> {
    let mut url = Url::parse(&hb_path_url(node_url, BYTE_PRICE_QUOTE_PATH))?;
    url.query_pairs_mut()
        .append_pair("amount", &bytes.to_string())
        .append_pair("resource", "arweave-bytes");

    let response = client.get(url).send().await?;
    if !response.status().is_success() {
        return Err(anyhow!("Byte quote request failed: {}", response_preview(response).await));
    }

    parse_amount(&response.text().await?)
}

fn decode_target(target: &str) -> Result<[u8; 32], Error> {
    let bytes = URL_SAFE_NO_PAD.decode(target)?;
    if bytes.len() != 32 {
        return Err(anyhow!("AO target must decode to 32 bytes"));
    }

    let mut out = [0; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

async fn current_slot(client: Client, state_url: &str, process_id: &str) -> Result<u64, Error> {
    let url =
        format!("{}/{}~process@1.0/slot/current", state_url.trim_end_matches('/'), process_id);
    let response = client.get(url).send().await?;

    if !response.status().is_success() {
        return Err(anyhow!(
            "AO current slot request failed: {}",
            response_preview(response).await
        ));
    }

    let text = response.text().await?;
    text.split(|ch: char| !ch.is_ascii_digit())
        .find(|part| !part.is_empty())
        .ok_or_else(|| anyhow!("Could not parse AO current slot: {}", text))?
        .parse()
        .map_err(Into::into)
}

fn assignment_slot(schedule: &Value, message_id: &str) -> Option<String> {
    schedule.get("edges")?.as_array()?.iter().find_map(|edge| {
        let node = edge.get("node")?;
        if node.get("message")?.get("Id")?.as_str()? != message_id {
            return None;
        }

        node.get("assignment")?
            .get("Tags")?
            .as_array()?
            .iter()
            .find(|tag| tag.get("name").and_then(Value::as_str) == Some("Nonce"))?
            .get("value")?
            .as_str()
            .map(ToString::to_string)
    })
}

fn parse_amount(body: &str) -> Result<u128, Error> {
    if let Ok(amount) = body.trim().parse() {
        return Ok(amount);
    }

    let json: Value = serde_json::from_str(body)?;
    for key in ["amount", "price", "quantity", "winc", "value"] {
        if let Some(value) = json.get(key) {
            if let Some(text) = value.as_str() {
                return Ok(text.parse()?);
            }
            if let Some(number) = value.as_u64() {
                return Ok(number.into());
            }
        }
    }

    Err(anyhow!("Could not parse quote amount"))
}

async fn response_preview(response: reqwest::Response) -> String {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    let preview = body.split_whitespace().collect::<Vec<_>>().join(" ");

    if preview.is_empty() {
        status.to_string()
    } else {
        format!("{}: {}", status, preview.chars().take(300).collect::<String>())
    }
}
