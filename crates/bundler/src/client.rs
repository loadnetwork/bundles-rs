use crate::{api::SendTransactionResponse, token::token_ticker};
use ans104::data_item::DataItem;
use anyhow::{Error, anyhow};
use reqwest::{Client, ClientBuilder};

/// HTTP client for uploading data items to Arweave bundler endpoints.
#[derive(Debug, Clone)]
pub struct BundlerClient {
    /// The base URL of the bundling service, defaults to "https://upload.ardrive.io".
    pub url: Option<String>,
    /// HTTP client for bundling service requests.
    pub http_client: Option<Client>,
}

impl Default for BundlerClient {
    fn default() -> Self {
        Self { url: Some("https://upload.ardrive.io".to_string()), http_client: None }
    }
}

impl BundlerClient {
    /// Creates a new bundler client builder.
    pub const fn new() -> Self {
        Self { url: None, http_client: None }
    }
    /// Sets the base URL of the bundler service.
    pub fn url(mut self, url: &str) -> Self {
        self.url = Some(url.to_string());
        self
    }
    /// Builds the bundling client with the set configuration.
    pub fn build(mut self) -> Result<Self, Error> {
        let _url = self
            .clone()
            .url
            .ok_or_else(|| "url not provided".to_string())
            .map_err(|e| anyhow!(e))?;
        let client = ClientBuilder::new().build()?;
        self.http_client = Some(client);
        Ok(self)
    }
    /// Sends a signed Dataitem to the configured bundling service client.
    pub async fn send_transaction(
        self,
        signed_dataitem: DataItem,
    ) -> Result<SendTransactionResponse, Error> {
        let token = token_ticker(signed_dataitem.signature_type)
            .ok_or("error invalid signature type")
            .map_err(|e| anyhow!(e.to_string()))?;
        let response = self
            .http_client
            .ok_or("http client error")
            .map_err(|e| anyhow!(e.to_string()))?
            .post(format!("{}/v1/tx/{}", self.url.unwrap(), token))
            .header("Content-Type", "application/octet-stream")
            .body(signed_dataitem.to_bytes()?)
            .send()
            .await?;

        if response.status().is_success() {
            let tx: SendTransactionResponse = response.json().await?;
            Ok(tx)
        } else {
            Err(anyhow!(response.status().to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ans104::{data_item::DataItem, tags::Tag};
    use crypto::solana::SolanaSigner;

    #[tokio::test]
    async fn test_send_transaction_solana() {
        let client = BundlerClient::new().url("https://upload.ardrive.io").build().unwrap();
        let signer = SolanaSigner::random();
        let tags = vec![Tag::new("content-type", "text/plain")];
        let dataitem =
            DataItem::build_and_sign(&signer, None, None, tags, "hello world".as_bytes().to_vec())
                .unwrap();

        let tx = client.send_transaction(dataitem).await.unwrap();
        println!("tx: {:?}", tx);
    }
}
