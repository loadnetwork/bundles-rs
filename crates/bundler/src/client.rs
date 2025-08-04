use crate::{
    api::{
        BundlerInfoResponse, BytePriceWincResponse, DataitemStatusResponse, RatesResponse,
        SendTransactionResponse, get_payment_url,
    },
    token::token_ticker,
};
use ans104::data_item::DataItem;
use anyhow::{Error, anyhow};
use reqwest::{Client, ClientBuilder};

pub(crate) const DEFAULT_BUNDLER_URL: &str = "https://upload.ardrive.io/v1";
pub(crate) const DEFAULT_TURBO_PAYMENT_URL: &str = "https://payment.ardrive.io/v1";

/// HTTP client for uploading data items to Arweave bundler endpoints.
#[derive(Debug, Clone)]
pub struct BundlerClient {
    /// The base URL of the bundling service, defaults to DEFAULT_BUNDLER_URL.
    pub url: Option<String>,
    /// The payment URL if of the bundling service, it's required only for Turbo
    /// bundling service setup given their API architecture: https://payment.ardrive.io/api-docs
    pub payment_url: Option<String>,
    /// HTTP client for bundling service requests.
    pub http_client: Option<Client>,
    /// Internal flag for Turbo distinction
    pub(crate) _is_turbo: bool,
}

impl Default for BundlerClient {
    fn default() -> Self {
        Self {
            url: Some(DEFAULT_BUNDLER_URL.to_string()),
            http_client: None,
            payment_url: Some(DEFAULT_TURBO_PAYMENT_URL.to_string()),
            _is_turbo: true,
        }
    }
}

impl BundlerClient {
    /// Creates a new bundler client builder.
    pub const fn new() -> Self {
        Self { url: None, http_client: None, payment_url: None, _is_turbo: false }
    }
    /// Return a BundlerClient instance with Turbo configuration
    /// Given the current design, turbo is the default.
    pub fn turbo() -> Self {
        BundlerClient::default()
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

        // check turbo's payment url
        if self._is_turbo {
            let _payment_url = self
                .clone()
                .payment_url
                .ok_or_else(|| "turbo payment url not provided".to_string())
                .map_err(|e| anyhow!(e))?;
        }

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
            .post(format!("{}/tx/{}", self.url.unwrap_or(DEFAULT_BUNDLER_URL.to_string()), token))
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
    /// Get the public info of the bundling service.
    pub async fn info(self) -> Result<BundlerInfoResponse, Error> {
        let url = get_payment_url(&self)?;
        let request = self
            .http_client
            .ok_or("http client error")
            .map_err(|e| anyhow!(e.to_string()))?
            .get(format!("{}/info", url))
            .send()
            .await?;

        if request.status().is_success() {
            let info: BundlerInfoResponse = request.json().await?;
            Ok(info)
        } else {
            Err(anyhow!(request.status().to_string()))
        }
    }
    /// Get the current amount of winc it will cost to upload a given byte count worth of data items
    pub async fn bytes_price(self, byte_count: u64) -> Result<BytePriceWincResponse, Error> {
        let payment_url = get_payment_url(&self)?;

        let request = self
            .http_client
            .ok_or("http client error")
            .map_err(|e| anyhow!(e.to_string()))?
            .get(format!("{}/price/bytes/{}", payment_url, byte_count))
            .send()
            .await?;

        if request.status().is_success() {
            let price: BytePriceWincResponse = request.json().await?;
            Ok(price)
        } else {
            Err(anyhow!(request.status().to_string()))
        }
    }
    /// TURBO ONLY
    /// Get the status of a given dataitem id
    pub async fn status(self, id: &str) -> Result<DataitemStatusResponse, Error> {
        if !self._is_turbo {
            return  Ok(DataitemStatusResponse::default());
        }

        let request = self
            .http_client
            .ok_or("http client error")
            .map_err(|e| anyhow!(e.to_string()))?
            .get(format!(
                "{}/tx/{}/status",
                self.url.unwrap_or(DEFAULT_BUNDLER_URL.to_string()),
                id
            ))
            .send()
            .await?;

        if request.status().is_success() {
            let status: DataitemStatusResponse = request.json().await?;
            Ok(status)
        } else {
            Err(anyhow!(request.status().to_string()))
        }
    }

    /// TURBO ONLY
    /// Get the supported fiat currency conversion rates for 1GB of storage based on current market
    /// prices.
    pub async fn get_rates(self) -> Result<RatesResponse, Error> {
        if !self._is_turbo {
            return Ok(RatesResponse::default());
        }

        let request = self
            .http_client
            .ok_or("http client error")
            .map_err(|e| anyhow!(e.to_string()))?
            .get(format!("{}/rates", DEFAULT_TURBO_PAYMENT_URL))
            .send()
            .await?;

        if request.status().is_success() {
            let rates: RatesResponse = request.json().await?;
            Ok(rates)
        } else {
            Err(anyhow!(request.status().to_string()))
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
        assert_eq!(tx.id.len(), 43);
    }

    #[tokio::test]
    async fn test_send_transaction_solana_turbo() {
        let client = BundlerClient::turbo().build().unwrap();
        let signer = SolanaSigner::random();
        let tags = vec![Tag::new("content-type", "text/plain")];
        let dataitem = DataItem::build_and_sign(
            &signer,
            None,
            None,
            tags,
            "hello world turbo".as_bytes().to_vec(),
        )
        .unwrap();

        let tx = client.send_transaction(dataitem).await.unwrap();
        println!("tx: {:?}", tx);
        assert_eq!(tx.id.len(), 43);
    }

    #[tokio::test]
    async fn test_default_and_info() {
        let client = BundlerClient::default().build().unwrap();
        let info = client.info().await.unwrap();
        println!("{:?}", info);
        assert_eq!(info.gateway, "https://arweave.net/");
    }

    #[tokio::test]
    async fn test_turbo_info() {
        let client = BundlerClient::turbo().build().unwrap();
        let info = client.info().await.unwrap();
        println!("{:?}", info);
        assert_eq!(info.gateway, "https://arweave.net/");
    }

    #[tokio::test]
    async fn test_turbo_bytes_price_winc() {
        let client = BundlerClient::turbo().build().unwrap();
        let price = client.bytes_price(99999).await.unwrap();
        println!("{:?}", price);
        assert_ne!(price.winc, "0".to_string());
    }

    #[tokio::test]
    async fn test_turbo_rates() {
        let client = BundlerClient::turbo().build().unwrap();
        let rates = client.get_rates().await.unwrap();
        println!("{:?}", rates);
        assert_ne!(rates.winc, "0".to_string());
    }

    #[tokio::test]
    async fn test_turbo_tx_status() {
        let client = BundlerClient::turbo().build().unwrap();
        let status = client.status("w5n6r6PvqBRph2or4WiyjLumL9HE-IR_JgEcnct_3b0").await.unwrap();
        println!("{:?}", status);
        assert_eq!(status.status, "CONFIRMED".to_string());
    }
}
