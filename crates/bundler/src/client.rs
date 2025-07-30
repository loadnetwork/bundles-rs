use anyhow::{anyhow, Error};
use crypto::signer::{SignatureType, Signer};
use reqwest::{Client, ClientBuilder};

#[derive(Debug, Clone)]
pub struct BundlerClient {
    pub url: Option<String>,
    pub signer: Option<SignatureType>,
    pub http_client: Option<Client>

}

impl BundlerClient {
    pub fn new() -> Self {
        Self { url: None, signer: None, http_client: None }
    }

    pub fn url(mut self, url: String) -> Self {
        self.url = Some(url);
        self
    } 

    pub fn signer(mut self, signer: SignatureType) -> Self {
        self.signer = Some(signer);
        self
    }

    pub fn build(mut self) -> Result<Self, Error> {
        let _signer = self.clone().signer.ok_or_else(|| "signer not provided".to_string()).map_err(|e| anyhow!(e))?;
        let _url = self.clone().url.ok_or_else(|| "url not provided".to_string()).map_err(|e| anyhow!(e))?;        
        let client = ClientBuilder::new().build()?;
        self.http_client = Some(client);
        Ok(self)
    }
}