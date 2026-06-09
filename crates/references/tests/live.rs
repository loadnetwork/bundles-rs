//! Ignored live gateway tests for reference namespace resolution.

use references::ReferenceClient;

#[tokio::test]
#[ignore = "live Arweave gateway test"]
async fn resolve_darwin_name() {
    let value = ReferenceClient::new().resolve_name("ao").await.unwrap();
    println!("ao={value}");
    assert!(value.is_string(), "ao should resolve to a string value");
}
