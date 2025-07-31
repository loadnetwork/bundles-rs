use anyhow::{Error, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::client::BundlerClient;

/// Response from a successful upload transaction upload to a bundler service.
/// The API response structure is according to Turbo's bundler https://upload.ardrive.io/api-docs
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendTransactionResponse {
    /// DataItem ID
    pub id: String,
    /// Creation unix timestamp
    pub timestamp: u64,
    /// DataItem fee in Arweave's winc unit
    pub winc: String,
    /// Bundle version
    pub version: String,
    /// Bundling service Arweave height deadline to settle the DataItem
    pub deadline_height: u64,
    /// Bundling service optimistic caching gateways
    pub data_caches: Vec<String>,
    /// Bundling service indexing gateways
    pub fast_finality_indexes: Vec<String>,
    /// Bundler public key
    pub public: String,
    /// Signed Dataitem signature
    pub signature: String,
    /// DataItem owner, signer
    pub owner: String,
}

/// Response of the /info endpoint of the bundling service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BundlerInfoResponse {
    /// Bundler version
    pub version: String,
    /// Bundler addresses list
    pub addresses: HashMap<String, String>,
    /// Bundler's gateway
    pub gateway: String,
    /// Bundler's dataitems size complete cost subsidizing
    pub free_upload_limit_bytes: u64,
}

/// Response of the /price/bytes/:bytesCount payment endpoint of the bundling service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BytePriceWincResponse {
    /// Price in winc (1e12 AR)
    pub winc: String,
    /// Adjustments settings array
    pub adjustments: Vec<Adjustment>,
}

/// Adjustment structure for BytePriceWincResponse
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Adjustment {
    /// Adjustment name
    pub name: String,
    /// Adjustment description
    pub description: String,
    /// Adjustment op magnitude
    pub operator_magnitude: String,
    /// Adjustment operator
    pub operator: String,
    /// Adjustment amount
    pub adjustment_amount: String,
    /// Adjustment promo code
    pub promo_code: String,
}

pub(crate) fn get_payment_url(client: &BundlerClient) -> Result<String, Error> {
    if client._is_turbo {
        client
            .clone()
            .payment_url
            .ok_or_else(|| "turbo payment url not provided".to_string())
            .map_err(|e| anyhow!(e))
    } else {
        client
            .clone()
            .url
            .ok_or_else(|| "bundling service url not provided".to_string())
            .map_err(|e| anyhow!(e))
    }
}
