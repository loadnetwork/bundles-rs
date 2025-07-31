use ans104::data_item::DataItem;
use anyhow::{anyhow, Error};
use reqwest::{Client, ClientBuilder};
use crate::token::token_ticker;


#[derive(Debug, Clone)]
pub struct BundlerClient {
    pub url: Option<String>,
    pub http_client: Option<Client>

}

impl BundlerClient {
    pub fn new() -> Self {
        Self { url: None, http_client: None }
    }

    pub fn url(mut self, url: &str) -> Self {
        self.url = Some(url.to_string());
        self
    } 

    pub fn build(mut self) -> Result<Self, Error> {
        let _url = self.clone().url.ok_or_else(|| "url not provided".to_string()).map_err(|e| anyhow!(e))?;        
        let client = ClientBuilder::new().build()?;
        self.http_client = Some(client);
        Ok(self)
    }

    pub async fn send_transaction(self, signed_dataitem: DataItem) -> Result<String, Error> {

        let token = token_ticker(signed_dataitem.signature_type).ok_or("error invalid signature type").map_err(|e| anyhow!((e.to_string())))?;
        let response = self.http_client.ok_or_else(|| "http client error").map_err(|e| anyhow!(e.to_string()))?
            .post(format!("{}/v1/tx/{}", self.url.unwrap(), token))
            .header("Content-Type", "application/octet-stream")
            .body(signed_dataitem.to_bytes()?)
            .send()
            .await?;
        
        if response.status().is_success() {
            let tx_id = response.text().await?;
            Ok(tx_id)
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
        let dataitem = DataItem::build_and_sign(&signer, None, None, tags, "hello world".as_bytes().to_vec()).unwrap();

        let txid = client.send_transaction(dataitem).await.unwrap();
        println!("txid: {}", txid);
    }
}
