use ans104::data_item::DataItem;
use anyhow::{Error, anyhow};
use rand::seq::SliceRandom;
use reqwest::Client;
use serde_json::Map;
use serde_json::Value;

use crate::api::SendTransactionResponse;

pub(crate) const DEFAULT_HYPERBEAM_UPLOAD_PATH: &str = "/~bundler@1.0/item?codec-device=ans104@1.0";
pub(crate) const HYPERBEAM_NODE_ADDRESS_PATH: &str = "/~meta@1.0/info/address";
pub(crate) const DEFAULT_ARWEAVE_GATEWAY: &str = "https://arweave.net";
pub(crate) const DEFAULT_PERMAWEBOS_BUNDLER_ENDPOINT: &str = "https://push-9.forward.computer";
pub(crate) const DEFAULT_PERMAWEBOS_BUNDLER_STAKING_PROCESS_ID: &str =
    "Xv7dvev8_dJVwW7k_VGGdHpRqWpgSCgK4vzJmnBkg5M";
const EXCLUDED_PERMAWEBOS_BUNDLER_URLS: &[&str] = &["https://dev-1.forward.computer"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivePermawebOSBundler {
    pub(crate) address: String,
    pub(crate) owner: String,
    pub(crate) ring: String,
    pub(crate) stake: Option<String>,
    pub(crate) url: String,
}

pub(crate) fn hb_path_url(base: &str, path: &str) -> String {
    format!("{}/{}", base.trim_end_matches('/'), path.trim_start_matches('/'))
}

async fn get_operator_address(base_url: &str, client: Client) -> Result<String, Error> {
    let url = hb_path_url(base_url, HYPERBEAM_NODE_ADDRESS_PATH);
    let response = client.get(&url).send().await?;
    if !response.status().is_success() {
        return Err(anyhow!(
            "HyperBEAM bundler address check failed with HTTP {}",
            response.status()
        ));
    }
    let node_address = response.text().await?.trim().to_string();
    if node_address.is_empty() {
        return Err(anyhow!("HyperBEAM bundler address check returned an empty address"));
    }
    Ok(node_address)
}

async fn get_wallet_ar_balance(address: &str, client: Client) -> Result<u128, Error> {
    let url = format!("{DEFAULT_ARWEAVE_GATEWAY}/wallet/{address}/balance");
    let response = client.get(&url).send().await?;
    if !response.status().is_success() {
        return Err(anyhow!(
            "HyperBEAM bundler AR balance check failed with HTTP {}",
            response.status()
        ));
    }
    let balance = response.text().await?.trim().to_string();
    Ok(balance.parse::<u128>()?)
}

pub(crate) async fn get_operator_balance(base_url: &str, client: Client) -> Result<u128, Error> {
    let address = get_operator_address(base_url, client.clone()).await?;
    let balance = get_wallet_ar_balance(&address, client).await?;
    if balance == 0 {
        return Err(anyhow!(
            "HyperBEAM bundler wallet {} has 0 AR; upload aborted because the node cannot seed data to Arweave.",
            address
        ));
    }
    Ok(balance)
}

pub(crate) async fn select_bundler(
    client: Client,
    endpoint: Option<&str>,
    pid: Option<&str>,
) -> Result<String, Error> {
    let mut uploaders = discover_bundlers(client.clone(), endpoint, pid).await?;
    uploaders.shuffle(&mut rand::thread_rng());

    let mut failures = Vec::new();
    for uploader in uploaders {
        match get_operator_balance(&uploader.url, client.clone()).await {
            Ok(_) => return Ok(uploader.url),
            Err(error) => {
                failures.push(format!("{}: {}", uploader.url, clean_error_message(&error)))
            }
        }
    }

    Err(anyhow!(
        "No active HyperBEAM uploaders with spendable AR found.{}",
        if failures.is_empty() { String::new() } else { format!("\n{}", failures.join("\n")) }
    ))
}

pub(crate) async fn discover_bundlers(
    client: Client,
    endpoint: Option<&str>,
    pid: Option<&str>,
) -> Result<Vec<ActivePermawebOSBundler>, Error> {
    let active = fetch_bundler_state_map(client.clone(), "active", endpoint, pid).await?;
    let registered = fetch_bundler_state_map(client, "registered", endpoint, pid).await?;
    let mut bundlers = Vec::new();

    for (owner, record) in active {
        if is_ao_metadata_key(&owner) {
            continue;
        }
        let Some(active_record) = record.as_object() else {
            continue;
        };
        let ring = normalize_scalar(active_record.get("ring"));
        if ring.is_empty() {
            continue;
        }
        let address = get_bundler_address(active_record);
        if address.is_empty() {
            continue;
        }
        let registered_record = registered.get(&address).and_then(Value::as_object);
        let url = normalize_bundler_url(&normalize_scalar(
            registered_record.and_then(|record| record.get("location")),
        ));
        if url.is_empty() || is_excluded_bundler_url(&url) {
            continue;
        }
        let stake = normalize_scalar(active_record.get("stake"));
        bundlers.push(ActivePermawebOSBundler {
            address,
            owner,
            ring,
            stake: (!stake.is_empty()).then_some(stake),
            url,
        });
    }

    bundlers.sort_by(|a, b| a.ring.cmp(&b.ring).then_with(|| a.url.cmp(&b.url)));
    Ok(bundlers)
}

async fn fetch_bundler_state_map(
    client: Client,
    path: &str,
    endpoint: Option<&str>,
    pid: Option<&str>,
) -> Result<Map<String, Value>, Error> {
    let value = fetch_bundler_state_value(client, path, endpoint, pid).await?;
    Ok(value.as_object().map(strip_ao_metadata).unwrap_or_default())
}

async fn fetch_bundler_state_value(
    client: Client,
    path: &str,
    endpoint: Option<&str>,
    pid: Option<&str>,
) -> Result<Value, Error> {
    let response = client
        .get(bundler_compute_url(path, endpoint, pid))
        .header("accept", "text/plain, application/json, */*")
        .header("accept-bundle", "true")
        .send()
        .await?;
    let status = response.status();
    let text = response.text().await?;
    if !status.is_success() {
        return Err(anyhow!("PermawebOS Bundler state fetch failed with HTTP {status}: {path}"));
    }
    if normalize_not_found(&text) {
        return Ok(Value::Null);
    }
    let parsed = parse_json(&text).unwrap_or_else(|| Value::String(text.trim().to_string()));
    if parsed.get("body") == Some(&Value::String("not_found".to_string()))
        || parsed.get("status").and_then(Value::as_u64) == Some(404)
    {
        return Ok(Value::Null);
    }
    if let Some(body) = parsed.get("body") {
        if let Some(body) = body.as_str() {
            return Ok(parse_json(body).unwrap_or_else(|| Value::String(body.to_string())));
        }
        return Ok(body.clone());
    }
    Ok(parsed.as_object().map(strip_ao_metadata).map(Value::Object).unwrap_or(parsed))
}

fn bundler_compute_url(path: &str, endpoint: Option<&str>, pid: Option<&str>) -> String {
    let endpoint = endpoint.unwrap_or(DEFAULT_PERMAWEBOS_BUNDLER_ENDPOINT).trim_end_matches('/');
    let pid = pid.unwrap_or(DEFAULT_PERMAWEBOS_BUNDLER_STAKING_PROCESS_ID);
    format!("{endpoint}/{pid}/compute/{path}?require-codec=application/json&accept-bundle=true")
}

fn get_bundler_address(record: &Map<String, Value>) -> String {
    normalize_scalar(
        record
            .get("lapee_address")
            .or_else(|| record.get("lapeeAddress"))
            .or_else(|| record.get("lapee-address")),
    )
}

fn normalize_bundler_url(value: &str) -> String {
    let value = value.trim();
    let lower = value.to_ascii_lowercase();
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        return String::new();
    }
    value.trim_end_matches('/').to_string()
}

fn is_excluded_bundler_url(url: &str) -> bool {
    EXCLUDED_PERMAWEBOS_BUNDLER_URLS.iter().any(|excluded| excluded.eq_ignore_ascii_case(url))
}

fn normalize_scalar(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(value)) => value.trim().to_string(),
        Some(Value::Number(value)) => value.to_string(),
        Some(Value::Bool(value)) => value.to_string(),
        _ => String::new(),
    }
}

fn strip_ao_metadata(value: &Map<String, Value>) -> Map<String, Value> {
    value
        .iter()
        .filter(|(key, _)| !is_ao_metadata_key(key))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn is_ao_metadata_key(key: &str) -> bool {
    matches!(key, "ao-result" | "ao-types" | "commitments" | "status") || key.ends_with("+link")
}

fn parse_json(text: &str) -> Option<Value> {
    let trimmed = text.trim();
    if trimmed.is_empty() || (!trimmed.starts_with('{') && !trimmed.starts_with('[')) {
        return None;
    }
    serde_json::from_str(trimmed).ok()
}

fn normalize_not_found(text: &str) -> bool {
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed == "not_found" {
        return true;
    }
    if trimmed.contains("<title>404 - Page not found.</title>") {
        return true;
    }
    let Some(parsed) = parse_json(trimmed) else {
        return false;
    };
    parsed.get("status").and_then(Value::as_u64) == Some(404)
        || parsed.get("body") == Some(&Value::String("not_found".to_string()))
}

fn clean_error_message(error: &Error) -> String {
    error.to_string().split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(crate) async fn send_transaction(
    http_client: Client,
    base_url: String,
    upload_path: String,
    signed_dataitem: DataItem,
) -> Result<SendTransactionResponse, Error> {
    let local_id = signed_dataitem.arweave_id();
    let raw = signed_dataitem.to_bytes()?;

    let response = http_client
        .post(hb_path_url(&base_url, &upload_path))
        .header("Content-Type", "application/octet-stream")
        .body(raw)
        .send()
        .await?;

    let status = response.status();
    let header_id =
        response.headers().get("id").and_then(|value| value.to_str().ok()).map(ToString::to_string);
    let body = response.text().await.unwrap_or_default();

    if !status.is_success() {
        let preview = body.split_whitespace().collect::<Vec<_>>().join(" ");
        return Err(anyhow!(
            "hyperbeam upload failed: {}{}",
            status,
            if preview.is_empty() {
                String::new()
            } else {
                format!(": {}", preview.chars().take(300).collect::<String>())
            }
        ));
    }

    let body_id = serde_json::from_str::<Value>(&body).ok().and_then(|json| {
        json.get("id")
            .or_else(|| json.get("body").and_then(|body| body.get("id")))
            .and_then(|id| id.as_str())
            .map(ToString::to_string)
    });

    Ok(SendTransactionResponse {
        id: header_id.or(body_id).unwrap_or(local_id),
        ..SendTransactionResponse::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_bundler_compute_url_defaults() {
        assert_eq!(
            bundler_compute_url("active", None, None),
            format!(
                "{}/{}/compute/active?require-codec=application/json&accept-bundle=true",
                DEFAULT_PERMAWEBOS_BUNDLER_ENDPOINT, DEFAULT_PERMAWEBOS_BUNDLER_STAKING_PROCESS_ID
            )
        );
    }

    #[test]
    fn test_extracts_bundler_address_variants() {
        let lapee_address = json!({ "lapee_address": "addr-1" }).as_object().unwrap().clone();
        let camel = json!({ "lapeeAddress": "addr-2" }).as_object().unwrap().clone();
        let kebab = json!({ "lapee-address": "addr-3" }).as_object().unwrap().clone();

        assert_eq!(get_bundler_address(&lapee_address), "addr-1");
        assert_eq!(get_bundler_address(&camel), "addr-2");
        assert_eq!(get_bundler_address(&kebab), "addr-3");
    }

    #[test]
    fn test_normalizes_and_filters_bundler_urls() {
        assert_eq!(normalize_bundler_url(" https://node.example/ "), "https://node.example");
        assert_eq!(normalize_bundler_url(" HTTPS://node.example/ "), "HTTPS://node.example");
        assert_eq!(normalize_bundler_url("node.example"), "");
        assert!(is_excluded_bundler_url("https://dev-1.forward.computer"));
    }

    #[test]
    fn test_strips_ao_metadata() {
        let value = json!({
            "owner": { "ring": "gold" },
            "ao-result": "ok",
            "status": 200,
            "owner+link": "ignored"
        })
        .as_object()
        .unwrap()
        .clone();

        let stripped = strip_ao_metadata(&value);
        assert!(stripped.contains_key("owner"));
        assert!(!stripped.contains_key("ao-result"));
        assert!(!stripped.contains_key("status"));
        assert!(!stripped.contains_key("owner+link"));
    }
}
