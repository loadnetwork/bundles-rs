use serde::{Deserialize, Serialize};



#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendTransactionResponse {
    pub id: String,
    pub timestamp: u64,
    pub winc: String,
    pub version: String,
    pub deadline_height: u64,
    pub data_caches: Vec<String>,
    pub fast_finality_indexes: Vec<String>,
    pub public: String,
    pub signature: String,
    pub owner: String
}