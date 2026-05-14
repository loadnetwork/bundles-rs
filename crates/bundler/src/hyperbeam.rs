use ans104::data_item::DataItem;
use anyhow::{Error, anyhow};
use reqwest::Client;
use serde_json::Value;

use crate::api::SendTransactionResponse;

pub(crate) const DEFAULT_HYPERBEAM_UPLOAD_PATH: &str = "/~bundler@1.0/item?codec-device=ans104@1.0";

pub(crate) fn upload_url(base: &str, path: &str) -> String {
    format!("{}/{}", base.trim_end_matches('/'), path.trim_start_matches('/'))
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
        .post(upload_url(&base_url, &upload_path))
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
