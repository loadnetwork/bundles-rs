use serde::{Deserialize, Serialize};

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
