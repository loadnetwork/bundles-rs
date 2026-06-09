use crate::{
    api::{
        BundlerInfoResponse, BytePriceWincResponse, DataitemStatusResponse, RatesResponse,
        SendTransactionResponse, get_payment_url,
    },
    hb_funding, hyperbeam,
    token::token_ticker,
};
use ans104::data_item::DataItem;
use anyhow::{Error, anyhow};
use crypto::arweave::ArweaveSigner;
use reqwest::{Client, ClientBuilder};
use std::{fmt, sync::Arc};

pub(crate) const DEFAULT_BUNDLER_URL: &str = "https://up.arweave.net";
pub(crate) const DEFAULT_TURBO_BUNDLER_URL: &str = "https://upload.ardrive.io/v1";
pub(crate) const DEFAULT_TURBO_PAYMENT_URL: &str = "https://payment.ardrive.io/v1";

/// HTTP client for uploading data items to Arweave bundler endpoints.
#[derive(Clone)]
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
    /// Internal flag for HyperBEAM bundler uploads.
    pub(crate) _is_hyperbeam: bool,
    /// HyperBEAM bundler upload route.
    pub(crate) hyperbeam_upload_path: Option<String>,
    /// PermawebOS endpoint used to discover active HyperBEAM bundler uploaders.
    pub(crate) hyperbeam_selection_endpoint: Option<String>,
    /// PermawebOS staking process ID used to discover active HyperBEAM bundler uploaders.
    pub(crate) hyperbeam_selection_process_id: Option<String>,
    /// Arweave signer used to auto-fund HyperBEAM AO ledger credit.
    pub(crate) hyperbeam_auto_fund_signer: Option<Arc<ArweaveSigner>>,
}

impl fmt::Debug for BundlerClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BundlerClient")
            .field("url", &self.url)
            .field("payment_url", &self.payment_url)
            .field("http_client", &self.http_client)
            .field("_is_turbo", &self._is_turbo)
            .field("_is_hyperbeam", &self._is_hyperbeam)
            .field("hyperbeam_upload_path", &self.hyperbeam_upload_path)
            .field("hyperbeam_selection_endpoint", &self.hyperbeam_selection_endpoint)
            .field("hyperbeam_selection_process_id", &self.hyperbeam_selection_process_id)
            .field("hyperbeam_auto_fund", &self.hyperbeam_auto_fund_signer.is_some())
            .finish()
    }
}

impl Default for BundlerClient {
    fn default() -> Self {
        Self {
            url: Some(DEFAULT_BUNDLER_URL.to_string()),
            http_client: None,
            payment_url: None,
            _is_turbo: false,
            _is_hyperbeam: false,
            hyperbeam_upload_path: None,
            hyperbeam_selection_endpoint: None,
            hyperbeam_selection_process_id: None,
            hyperbeam_auto_fund_signer: None,
        }
    }
}

impl BundlerClient {
    /// Creates a new bundler client builder.
    pub const fn new() -> Self {
        Self {
            url: None,
            http_client: None,
            payment_url: None,
            _is_turbo: false,
            _is_hyperbeam: false,
            hyperbeam_upload_path: None,
            hyperbeam_selection_endpoint: None,
            hyperbeam_selection_process_id: None,
            hyperbeam_auto_fund_signer: None,
        }
    }
    /// Return a BundlerClient instance with Turbo configuration
    pub fn turbo() -> Self {
        Self {
            url: Some(DEFAULT_TURBO_BUNDLER_URL.to_string()),
            http_client: None,
            payment_url: Some(DEFAULT_TURBO_PAYMENT_URL.to_string()),
            _is_turbo: true,
            _is_hyperbeam: false,
            hyperbeam_upload_path: None,
            hyperbeam_selection_endpoint: None,
            hyperbeam_selection_process_id: None,
            hyperbeam_auto_fund_signer: None,
        }
    }
    /// Return a BundlerClient instance configured for HyperBEAM bundler uploads.
    pub fn hyperbeam() -> Self {
        Self {
            url: None,
            payment_url: None,
            http_client: None,
            _is_turbo: false,
            _is_hyperbeam: true,
            hyperbeam_upload_path: Some(hyperbeam::DEFAULT_HYPERBEAM_UPLOAD_PATH.to_string()),
            hyperbeam_selection_endpoint: None,
            hyperbeam_selection_process_id: None,
            hyperbeam_auto_fund_signer: None,
        }
    }
    /// Sets the base URL of the bundler service.
    pub fn url(mut self, url: &str) -> Self {
        self.url = Some(url.to_string());
        self
    }
    /// Sets the HyperBEAM bundler upload route.
    pub fn hyperbeam_upload_path(mut self, upload_path: &str) -> Self {
        self.hyperbeam_upload_path = Some(upload_path.to_string());
        self
    }
    /// Sets the PermawebOS endpoint used to auto-select HyperBEAM bundler uploaders.
    pub fn hyperbeam_selection_endpoint(mut self, endpoint: &str) -> Self {
        self.hyperbeam_selection_endpoint = Some(endpoint.to_string());
        self
    }
    /// Sets the PermawebOS staking process ID used to auto-select HyperBEAM bundler uploaders.
    pub fn hyperbeam_selection_process_id(mut self, process_id: &str) -> Self {
        self.hyperbeam_selection_process_id = Some(process_id.to_string());
        self
    }
    /// Enables HyperBEAM AO ledger auto-funding before upload.
    pub fn auto_fund(mut self, signer: ArweaveSigner) -> Self {
        self.hyperbeam_auto_fund_signer = Some(Arc::new(signer));
        self
    }
    /// Builds the bundling client with the set configuration.
    pub fn build(self) -> Result<Self, Error> {
        if !self._is_hyperbeam {
            let _url = self
                .clone()
                .url
                .ok_or_else(|| "url not provided".to_string())
                .map_err(|e| anyhow!(e))?;
        }

        // check turbo's payment url
        if self._is_turbo {
            let _payment_url = self
                .clone()
                .payment_url
                .ok_or_else(|| "turbo payment url not provided".to_string())
                .map_err(|e| anyhow!(e))?;
        }

        let client = ClientBuilder::new().build()?;
        Ok(Self {
            url: self.url,
            payment_url: self.payment_url,
            _is_turbo: self._is_turbo,
            _is_hyperbeam: self._is_hyperbeam,
            hyperbeam_upload_path: self.hyperbeam_upload_path,
            hyperbeam_selection_endpoint: self.hyperbeam_selection_endpoint,
            hyperbeam_selection_process_id: self.hyperbeam_selection_process_id,
            hyperbeam_auto_fund_signer: self.hyperbeam_auto_fund_signer,
            http_client: Some(client),
        })
    }
    /// Sends a signed Dataitem to the configured bundling service client.
    pub async fn send_transaction(
        self,
        signed_dataitem: DataItem,
    ) -> Result<SendTransactionResponse, Error> {
        if self._is_hyperbeam {
            let http_client =
                self.http_client.ok_or("http client error").map_err(|e| anyhow!(e.to_string()))?;
            let url = match self.url {
                Some(url) => url,
                None => {
                    hyperbeam::select_bundler(
                        http_client.clone(),
                        self.hyperbeam_selection_endpoint.as_deref(),
                        self.hyperbeam_selection_process_id.as_deref(),
                    )
                    .await?
                }
            };

            if let Some(signer) = self.hyperbeam_auto_fund_signer {
                hb_funding::auto_fund_upload(
                    http_client.clone(),
                    &url,
                    signer.as_ref(),
                    signed_dataitem.to_bytes()?.len() as u64,
                )
                .await?;
            }

            return hyperbeam::send_transaction(
                http_client,
                url,
                self.hyperbeam_upload_path
                    .unwrap_or_else(|| hyperbeam::DEFAULT_HYPERBEAM_UPLOAD_PATH.to_string()),
                signed_dataitem,
            )
            .await;
        }

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
    pub async fn info(&self) -> Result<BundlerInfoResponse, Error> {
        let url = get_payment_url(&self)?;
        let request = self
            .http_client
            .clone()
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
    pub async fn bytes_price(&self, byte_count: u64) -> Result<BytePriceWincResponse, Error> {
        let payment_url = get_payment_url(&self)?;

        let request = self
            .clone()
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
    pub async fn status(&self, id: &str) -> Result<DataitemStatusResponse, Error> {
        if !self._is_turbo {
            return Ok(DataitemStatusResponse::default());
        }

        let request = self
            .clone()
            .http_client
            .ok_or("http client error")
            .map_err(|e| anyhow!(e.to_string()))?
            .get(format!(
                "{}/tx/{}/status",
                self.clone().url.unwrap_or(DEFAULT_BUNDLER_URL.to_string()),
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
    pub async fn get_rates(&self) -> Result<RatesResponse, Error> {
        if !self._is_turbo {
            return Ok(RatesResponse::default());
        }

        let request = self
            .clone()
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
    use crypto::{arweave::ArweaveSigner, solana::SolanaSigner};

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
    async fn test_send_transaction_arweave_up() {
        let client = BundlerClient::new().url("https://up.arweave.net").build().unwrap();
        let signer = ArweaveSigner::random().unwrap();
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
    async fn test_default_client() {
        let client = BundlerClient::default().build().unwrap();
        assert_eq!(client.url.as_deref(), Some(DEFAULT_BUNDLER_URL));
        assert_eq!(client.payment_url, None);
        assert!(!client._is_turbo);
    }

    #[tokio::test]
    async fn test_hyperbeam_client_builds_without_url() {
        let client = BundlerClient::hyperbeam().build().unwrap();
        assert_eq!(client.url, None);
        assert!(client._is_hyperbeam);
    }

    #[tokio::test]
    async fn test_turbo_info() {
        let client = BundlerClient::turbo().build().unwrap();
        let info = client.info().await.unwrap();
        println!("{:?}", info);
        assert_eq!(info.gateway, "https://turbo-gateway.com/");
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
        assert_eq!(status.status, "FINALIZED".to_string());
    }
}
