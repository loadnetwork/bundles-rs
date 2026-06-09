//! Utilities for `reference@1.0` messages.

use ans104::{data_item::DataItem, tags::Tag};
use anyhow::{Error, anyhow};
use bundler::{BundlerClient, SendTransactionResponse};
use crypto::{arweave::ArweaveSigner, signer::Signer};
use reqwest::Client;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::{
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

/// The AO-Core device string for reference messages.
pub const DEVICE: &str = "reference@1.0";

/// Default Arweave gateway used for GraphQL reads.
pub const DEFAULT_GATEWAY: &str = "https://arweave.net";

/// Trusted phase-2 bootstrap publisher used by `names-sdk`.
///
/// This matters for namespace and wallet-wide discovery flows where reference inits may be
/// published by a trusted bootstrap process on behalf of an authority. Direct reference
/// resolution does not require trusting this address.
pub const PHASE2_BOOTSTRAP_OWNER: &str = "uAaRGha_a1ni_VjLf9Be2SFB7NJw1PWnjevdfeuJ_7c";

/// Default phase-2 namespace root reference from `names-sdk`.
pub const PHASE2_NAMESPACE: &str = "w0eqd43OMzzXr-5yhFC-LkgifQqih8YEPb4mLt6VSZo";

const MAX_NAMESPACE_REFERENCE_DEPTH: usize = 10;

/// Address string used as a reference authority or committer.
pub type Address = String;

/// A `reference@1.0` message reconstructed from scalar tags.
pub type ReferenceMessage = Map<String, Value>;

/// A candidate `set` message plus committer and position metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Reconstructed reference message.
    pub message: ReferenceMessage,
    /// Transaction owners that committed this message.
    pub committers: Vec<Address>,
    /// Data-layer block height.
    pub block: u64,
    /// Position within the discovered ordered stream.
    pub index: usize,
    /// Optional transaction id.
    pub id: Option<String>,
}

/// Current folded reference state.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedState {
    /// Winning message.
    pub message: ReferenceMessage,
    /// Winning timestamp.
    pub timestamp: u64,
    /// Whether the winning message is the init or a set.
    pub source: ReferenceSource,
}

/// Source of a resolved reference state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceSource {
    /// The initial reference message won.
    Init,
    /// A later set message won.
    Set,
}

/// A fetched reference value with metadata.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedReference {
    /// Reference id.
    pub id: String,
    /// Reference authority.
    pub authority: Option<Address>,
    /// Effective reference value.
    pub value: Value,
    /// Winning timestamp.
    pub timestamp: u64,
    /// Winning source.
    pub source: ReferenceSource,
}

/// A namespace name resolved to its current reference state.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedName {
    /// Namespace name.
    pub name: String,
    /// Reference id mapped by the namespace.
    pub reference_id: String,
    /// Reference authority.
    pub authority: Option<Address>,
    /// Effective reference value.
    pub value: Value,
    /// Winning timestamp.
    pub timestamp: u64,
    /// Winning source.
    pub source: ReferenceSource,
}

/// A parsed Arweave manifest namespace.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Namespace {
    /// Name to reference id.
    pub names: HashMap<String, String>,
    /// Reference id to name.
    pub by_reference: HashMap<String, String>,
}

/// A fetched init message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedMessage {
    /// Reconstructed message.
    pub message: ReferenceMessage,
    /// Transaction committers.
    pub committers: Vec<Address>,
    /// Block height, or zero when unavailable.
    pub block: u64,
}

/// Options for creating a set message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildSetOptions {
    /// Reference id being updated.
    pub reference_id: String,
    /// New reference value.
    pub value: Option<String>,
    /// Set timestamp.
    pub timestamp: u64,
}

/// Options for updating an existing reference value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpdateReferenceOptions {
    /// New reference value.
    pub value: Option<String>,
    /// Set timestamp. When omitted, uses max(now, current timestamp + 1).
    pub timestamp: Option<u64>,
}

/// Client for reference GraphQL reads and bundler writes.
#[derive(Debug, Clone)]
pub struct ReferenceClient {
    gateway: String,
    graphql: String,
    bundler: BundlerClient,
    namespace: Option<String>,
    http_client: Client,
}

impl Default for ReferenceClient {
    fn default() -> Self {
        Self::new()
    }
}

impl ReferenceClient {
    /// Create a client using `https://arweave.net` and the default bundler.
    #[must_use]
    pub fn new() -> Self {
        Self::with_gateway(DEFAULT_GATEWAY)
    }

    /// Create a client for a custom gateway. GraphQL defaults to `${gateway}/graphql`.
    #[must_use]
    pub fn with_gateway(gateway: &str) -> Self {
        let gateway = trim_trailing_slashes(gateway);
        Self {
            graphql: format!("{gateway}/graphql"),
            gateway,
            bundler: BundlerClient::default(),
            namespace: Some(PHASE2_NAMESPACE.to_string()),
            http_client: Client::new(),
        }
    }

    /// Override the GraphQL endpoint.
    #[must_use]
    pub fn graphql(mut self, graphql: &str) -> Self {
        self.graphql = graphql.to_string();
        self
    }

    /// Override the upload bundler client.
    #[must_use]
    pub fn bundler(mut self, bundler: BundlerClient) -> Self {
        self.bundler = bundler;
        self
    }

    /// Override the namespace root reference or manifest id.
    #[must_use]
    pub fn namespace(mut self, namespace: &str) -> Self {
        self.namespace = Some(namespace.to_string());
        self
    }

    /// Disable namespace name resolution.
    #[must_use]
    pub fn without_namespace(mut self) -> Self {
        self.namespace = None;
        self
    }

    /// Return the configured gateway base URL.
    #[must_use]
    pub fn gateway(&self) -> &str {
        &self.gateway
    }

    /// Return the configured GraphQL endpoint.
    #[must_use]
    pub fn graphql_endpoint(&self) -> &str {
        &self.graphql
    }

    /// Read a reference init and fold its candidate sets to current state.
    pub async fn get_reference(
        &self,
        reference_id: &str,
    ) -> Result<Option<ResolvedReference>, Error> {
        let Some(init) = self.fetch_message_by_id(reference_id).await? else {
            return Ok(None);
        };
        if string_field(&init.message, "device") != Some(DEVICE) || !is_init(&init.message) {
            return Ok(None);
        }

        let authority = authority_of(&init.message, &init.committers);
        let candidates = self.discover_sets(reference_id, authority.as_deref()).await?;
        let state = current_state(init.message, authority.as_deref(), candidates);
        Ok(Some(ResolvedReference {
            id: reference_id.to_string(),
            authority,
            value: effective_value(&state.message),
            timestamp: state.timestamp,
            source: state.source,
        }))
    }

    /// Resolve a reference to its effective value.
    pub async fn resolve_reference(&self, reference_id: &str) -> Result<Value, Error> {
        self.get_reference(reference_id)
            .await?
            .map(|reference| reference.value)
            .ok_or_else(|| anyhow!("reference not found: {reference_id}"))
    }

    /// Resolve a namespace name to its current reference state.
    pub async fn get_name(&self, name: &str) -> Result<Option<ResolvedName>, Error> {
        let Some(namespace) = self.load_namespace().await? else {
            return Ok(None);
        };
        let Some(reference_id) = namespace.names.get(name) else {
            return Ok(None);
        };
        let Some(reference) = self.get_reference(reference_id).await? else {
            return Ok(None);
        };
        Ok(Some(ResolvedName {
            name: name.to_string(),
            reference_id: reference_id.clone(),
            authority: reference.authority,
            value: reference.value,
            timestamp: reference.timestamp,
            source: reference.source,
        }))
    }

    /// Resolve a namespace name to its effective reference value.
    pub async fn resolve_name(&self, name: &str) -> Result<Value, Error> {
        self.get_name(name)
            .await?
            .map(|reference| reference.value)
            .ok_or_else(|| anyhow!("name not found: {name}"))
    }

    /// Fetch a raw init or set message by transaction id.
    pub async fn fetch_message_by_id(&self, id: &str) -> Result<Option<FetchedMessage>, Error> {
        let data = self.gql_request(build_tx_query(id)).await?;
        let Some(node) = data.get("transaction") else {
            return Ok(None);
        };
        if node.is_null() {
            return Ok(None);
        }
        let node: GqlNode = serde_json::from_value(node.clone())?;
        Ok(Some(FetchedMessage {
            message: tags_to_message(node.tags.unwrap_or_default()),
            committers: node.owner.and_then(|owner| owner.address).into_iter().collect(),
            block: node.block.and_then(|block| block.height).unwrap_or(0),
        }))
    }

    /// Discover candidate `set` messages for a reference.
    pub async fn discover_sets(
        &self,
        reference_id: &str,
        authority: Option<&str>,
    ) -> Result<Vec<Candidate>, Error> {
        let mut out = Vec::new();
        let mut after = None;
        let mut index = 0;

        for _ in 0..100 {
            let data = self
                .gql_request(build_set_query(reference_id, authority, 0, 100, after.as_deref()))
                .await?;
            let page = data.get("transactions").and_then(|value| value.get("pageInfo"));
            let has_next_page = page
                .and_then(|value| value.get("hasNextPage"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let edges = data
                .get("transactions")
                .and_then(|value| value.get("edges"))
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();

            if edges.is_empty() {
                break;
            }

            for edge in edges {
                after = edge.get("cursor").and_then(Value::as_str).map(ToOwned::to_owned);
                let Some(node) = edge.get("node") else {
                    continue;
                };
                let node: GqlNode = serde_json::from_value(node.clone())?;
                let candidate = node_to_candidate(node, index);
                index += 1;
                if has_compatible_reference_device(&candidate.message)
                    && string_field(&candidate.message, "reference-id") == Some(reference_id)
                {
                    out.push(candidate);
                }
            }

            if !has_next_page {
                break;
            }
        }

        Ok(out)
    }

    /// Set a new value for an existing reference using an Arweave signer.
    ///
    /// The signer address must match the reference authority.
    pub async fn update_reference(
        &self,
        signer: &ArweaveSigner,
        reference_id: &str,
        opts: UpdateReferenceOptions,
    ) -> Result<SendTransactionResponse, Error> {
        self.update_reference_as(signer, &signer.address(), reference_id, opts).await
    }

    /// Set a new value for an existing reference with an explicitly supplied authority address.
    ///
    /// Use this for non-Arweave signers or custom signer implementations. The supplied authority
    /// is checked against the current reference authority before posting the set message.
    pub async fn update_reference_as<S: Signer>(
        &self,
        signer: &S,
        authority: &str,
        reference_id: &str,
        opts: UpdateReferenceOptions,
    ) -> Result<SendTransactionResponse, Error> {
        let current = self
            .get_reference(reference_id)
            .await?
            .ok_or_else(|| anyhow!("reference not found: {reference_id}"))?;
        if current.authority.as_deref() != Some(authority) {
            return Err(anyhow!("signer is not reference authority for {reference_id}"));
        }
        let timestamp =
            opts.timestamp.unwrap_or_else(|| current_timestamp().max(current.timestamp + 1));
        let tags = build_set_tags(BuildSetOptions {
            reference_id: reference_id.to_string(),
            value: opts.value,
            timestamp,
        });
        self.send_signed_tags(signer, tags).await
    }

    async fn send_signed_tags<S: Signer>(
        &self,
        signer: &S,
        tags: Vec<Tag>,
    ) -> Result<SendTransactionResponse, Error> {
        let dataitem = DataItem::build_and_sign(signer, None, None, tags, b" ".to_vec())?;
        self.bundler.clone().build()?.send_transaction(dataitem).await
    }

    async fn load_namespace(&self) -> Result<Option<Namespace>, Error> {
        let Some(namespace) = &self.namespace else {
            return Ok(None);
        };
        let manifest_id = self.resolve_namespace_manifest_id(namespace).await?;
        Ok(Some(parse_namespace(&self.fetch_raw(&manifest_id).await?)?))
    }

    async fn resolve_namespace_manifest_id(&self, namespace: &str) -> Result<String, Error> {
        let mut current = namespace.to_string();
        let mut seen = Vec::<String>::new();
        for depth in 0..MAX_NAMESPACE_REFERENCE_DEPTH {
            if seen.iter().any(|seen| seen == &current) {
                return Err(anyhow!("namespace reference cycle detected: {current}"));
            }
            seen.push(current.clone());

            let Some(next) = self.resolve_trusted_namespace_reference(&current, depth == 0).await?
            else {
                return Ok(current);
            };
            current = next;
        }
        Err(anyhow!("namespace reference chain is too deep: {namespace}"))
    }

    async fn resolve_trusted_namespace_reference(
        &self,
        reference_id: &str,
        is_root: bool,
    ) -> Result<Option<String>, Error> {
        let Some(init) = self.fetch_message_by_id(reference_id).await? else {
            return Ok(None);
        };
        if string_field(&init.message, "device") != Some(DEVICE) || !is_init(&init.message) {
            return Ok(None);
        }

        let owner = init.committers.first().map(String::as_str);
        let authority = authority_of(&init.message, &init.committers);
        if owner != Some(PHASE2_BOOTSTRAP_OWNER)
            || authority.as_deref() != Some(PHASE2_BOOTSTRAP_OWNER)
        {
            let kind = if is_root { "root" } else { "reference" };
            return Err(anyhow!(
                "namespace {kind} is not owned by trusted bootstrap publisher: {reference_id}"
            ));
        }

        let candidates = self.discover_sets(reference_id, Some(PHASE2_BOOTSTRAP_OWNER)).await?;
        let state = current_state(init.message, Some(PHASE2_BOOTSTRAP_OWNER), candidates);
        match effective_value(&state.message) {
            Value::String(value) => Ok(Some(value)),
            _ => {
                let kind = if is_root { "root" } else { "reference" };
                Err(anyhow!("namespace {kind} does not resolve to a manifest id: {reference_id}"))
            }
        }
    }

    async fn fetch_raw(&self, id: &str) -> Result<String, Error> {
        let response = self
            .http_client
            .get(format!("{}/raw/{}", self.gateway, id))
            .header("accept", "application/json")
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(anyhow!("raw fetch failed: {} for {}", response.status(), id));
        }
        Ok(response.text().await?)
    }

    async fn gql_request(&self, query: String) -> Result<Value, Error> {
        #[derive(Deserialize)]
        struct GraphqlResponse {
            data: Option<Value>,
            errors: Option<Value>,
        }

        let response = self
            .http_client
            .post(&self.graphql)
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .json(&json!({ "query": query }))
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(anyhow!("GraphQL request failed: {}", response.status()));
        }
        let body: GraphqlResponse = response.json().await?;
        if let Some(errors) = body.errors {
            return Err(anyhow!("GraphQL error: {}", errors));
        }
        Ok(body.data.unwrap_or(Value::Null))
    }
}

/// Build tags for a reference set.
#[must_use]
pub fn build_set_tags(opts: BuildSetOptions) -> Vec<Tag> {
    let mut tags = vec![
        Tag::new("reference-id", opts.reference_id),
        Tag::new("timestamp", opts.timestamp.to_string()),
    ];
    if let Some(value) = opts.value {
        tags.push(Tag::new("reference-value", value));
    }
    tags
}

/// Parse an Arweave manifest into name/reference indexes.
pub fn parse_namespace(text: &str) -> Result<Namespace, Error> {
    let doc: Value = serde_json::from_str(text)?;
    let mut namespace = Namespace::default();
    let Some(paths) = doc.get("paths").and_then(Value::as_object) else {
        return Ok(namespace);
    };
    for (name, entry) in paths {
        let id = entry
            .as_object()
            .and_then(|entry| entry.get("id"))
            .and_then(Value::as_str)
            .or_else(|| entry.as_str());
        if let Some(id) = id {
            namespace.names.insert(name.clone(), id.to_string());
            namespace.by_reference.insert(id.to_string(), name.clone());
        }
    }
    Ok(namespace)
}

/// Build a minimal downstream-reference pointer.
#[must_use]
pub fn build_pointer(reference_id: &str) -> ReferenceMessage {
    let mut message = ReferenceMessage::new();
    message.insert("device".to_string(), Value::String(DEVICE.to_string()));
    message.insert("reference-id".to_string(), Value::String(reference_id.to_string()));
    message
}

/// Reconstruct a message from scalar tags.
#[must_use]
pub fn tags_to_message(tags: Vec<Tag>) -> ReferenceMessage {
    tags.into_iter().map(|tag| (tag.name, Value::String(tag.value))).collect()
}

/// Return true if a message is an init.
#[must_use]
pub fn is_init(message: &ReferenceMessage) -> bool {
    !message.contains_key("reference-id")
}

/// A message's reference id is its `reference-id` key, or the committed id for inits.
#[must_use]
pub fn reference_id_of(message: &ReferenceMessage, committed_id: Option<&str>) -> Option<String> {
    string_field(message, "reference-id").or(committed_id).map(ToOwned::to_owned)
}

/// The authority is the init's `authority`, or its first committer.
#[must_use]
pub fn authority_of(init: &ReferenceMessage, committers: &[Address]) -> Option<Address> {
    string_field(init, "authority").map(ToOwned::to_owned).or_else(|| committers.first().cloned())
}

/// Numeric timestamp, with missing or invalid values treated as zero.
#[must_use]
pub fn timestamp_of(message: &ReferenceMessage) -> u64 {
    match message.get("timestamp") {
        Some(Value::Number(number)) => number.as_u64().unwrap_or(0),
        Some(Value::String(value)) => value.parse().unwrap_or(0),
        _ => 0,
    }
}

/// Effective value: `reference-value` if present, otherwise the message itself.
#[must_use]
pub fn effective_value(message: &ReferenceMessage) -> Value {
    message.get("reference-value").cloned().unwrap_or_else(|| Value::Object(message.clone()))
}

/// Fold candidate sets over an init using authority, timestamp, and data-layer order.
#[must_use]
pub fn current_state(
    init: ReferenceMessage,
    authority: Option<&str>,
    mut candidates: Vec<Candidate>,
) -> ResolvedState {
    let mut state = ResolvedState {
        timestamp: timestamp_of(&init),
        message: init,
        source: ReferenceSource::Init,
    };
    candidates.sort_by_key(|candidate| (candidate.block, candidate.index));
    for candidate in candidates {
        let Some(authority) = authority else {
            continue;
        };
        if !candidate.committers.iter().any(|committer| committer == authority) {
            continue;
        }
        let timestamp = timestamp_of(&candidate.message);
        if timestamp > state.timestamp {
            state = ResolvedState {
                message: candidate.message,
                timestamp,
                source: ReferenceSource::Set,
            };
        }
    }
    state
}

/// Build the GraphQL query for a reference's set messages.
#[must_use]
pub fn build_set_query(
    reference_id: &str,
    authority: Option<&str>,
    min_block: u64,
    first: usize,
    after: Option<&str>,
) -> String {
    let owners =
        authority.map(|authority| format!("owners: {}, ", json!([authority]))).unwrap_or_default();
    let after_arg = after.map(|after| format!(", after: {}", json!(after))).unwrap_or_default();
    format!(
        r#"query {{
  transactions(
    {owners}tags: [
      {{ name: "reference-id", values: {} }}
    ],
    block: {{ min: {min_block} }},
    sort: HEIGHT_ASC,
    first: {first}{after_arg}
  ) {{
    pageInfo {{ hasNextPage }}
    edges {{ cursor node {{ id owner {{ address }} tags {{ name value }} block {{ height }} }} }}
  }}
}}"#,
        json!([reference_id])
    )
}

/// Build the GraphQL query for a single transaction.
#[must_use]
pub fn build_tx_query(id: &str) -> String {
    format!(
        r#"query {{ transaction(id: {}) {{ id owner {{ address }} tags {{ name value }} block {{ height }} }} }}"#,
        json!(id)
    )
}

fn node_to_candidate(node: GqlNode, index: usize) -> Candidate {
    Candidate {
        message: tags_to_message(node.tags.unwrap_or_default()),
        committers: node.owner.and_then(|owner| owner.address).into_iter().collect(),
        block: node.block.and_then(|block| block.height).unwrap_or(u64::MAX),
        index,
        id: Some(node.id),
    }
}

fn has_compatible_reference_device(message: &ReferenceMessage) -> bool {
    string_field(message, "device").is_none_or(|device| device == DEVICE)
}

fn string_field<'a>(message: &'a ReferenceMessage, key: &str) -> Option<&'a str> {
    message.get(key).and_then(Value::as_str)
}

fn trim_trailing_slashes(value: &str) -> String {
    value.trim_end_matches('/').to_string()
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[derive(Debug, Clone, Deserialize)]
struct GqlNode {
    id: String,
    owner: Option<GqlOwner>,
    tags: Option<Vec<Tag>>,
    block: Option<GqlBlock>,
}

#[derive(Debug, Clone, Deserialize)]
struct GqlOwner {
    address: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct GqlBlock {
    height: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUTHORITY: &str = "authority-addr";
    const IMPOSTER: &str = "imposter-addr";

    fn init(extra: &[(&str, Value)]) -> ReferenceMessage {
        let mut message = ReferenceMessage::new();
        message.insert("device".to_string(), Value::String(DEVICE.to_string()));
        message.insert("timestamp".to_string(), Value::String("1".to_string()));
        for (key, value) in extra {
            message.insert((*key).to_string(), value.clone());
        }
        message
    }

    fn set_candidate(
        timestamp: u64,
        value: Value,
        block: u64,
        index: usize,
        committer: &str,
    ) -> Candidate {
        let mut message = ReferenceMessage::new();
        message.insert("device".to_string(), Value::String(DEVICE.to_string()));
        message.insert("reference-id".to_string(), Value::String("R".to_string()));
        message.insert("timestamp".to_string(), Value::String(timestamp.to_string()));
        message.insert("reference-value".to_string(), value);
        Candidate { message, committers: vec![committer.to_string()], block, index, id: None }
    }

    #[test]
    fn build_set_requires_reference_id_and_timestamp() {
        let tags = build_set_tags(BuildSetOptions {
            reference_id: "REF".to_string(),
            value: Some("TARGET".to_string()),
            timestamp: 11,
        });
        let message = tags_to_message(tags);
        assert_eq!(string_field(&message, "reference-id"), Some("REF"));
        assert_eq!(string_field(&message, "timestamp"), Some("11"));
        assert_eq!(string_field(&message, "reference-value"), Some("TARGET"));
    }

    #[test]
    fn parse_namespace_indexes_names_and_references() {
        let namespace = parse_namespace(
            r#"{
                "manifest": "arweave/paths",
                "paths": {
                    "alice": { "id": "REF_alice" },
                    "bob": "REF_bob",
                    "ignored": { "not_id": "x" }
                }
            }"#,
        )
        .unwrap();

        assert_eq!(namespace.names.get("alice").map(String::as_str), Some("REF_alice"));
        assert_eq!(namespace.names.get("bob").map(String::as_str), Some("REF_bob"));
        assert_eq!(namespace.by_reference.get("REF_alice").map(String::as_str), Some("alice"));
        assert!(!namespace.names.contains_key("ignored"));
    }

    #[test]
    fn current_state_returns_init_when_no_set_applies() {
        let state = current_state(
            init(&[("reference-value", json!({ "x": "orig" }))]),
            Some(AUTHORITY),
            vec![set_candidate(99, json!({ "x": "bad" }), 100, 0, IMPOSTER)],
        );
        assert_eq!(state.source, ReferenceSource::Init);
        assert_eq!(effective_value(&state.message), json!({ "x": "orig" }));
    }

    #[test]
    fn current_state_returns_latest_authorized_set() {
        let candidates = vec![
            set_candidate(5, json!({ "x": "new" }), 100, 0, AUTHORITY),
            set_candidate(3, json!({ "x": "old" }), 101, 0, AUTHORITY),
        ];
        let state = current_state(init(&[]), Some(AUTHORITY), candidates);
        assert_eq!(state.source, ReferenceSource::Set);
        assert_eq!(effective_value(&state.message), json!({ "x": "new" }));
    }

    #[test]
    fn equal_timestamps_keep_earliest_data_layer_position() {
        let early = set_candidate(5, json!({ "x": "early" }), 100, 0, AUTHORITY);
        let late = set_candidate(5, json!({ "x": "late" }), 100, 1, AUTHORITY);
        let state = current_state(init(&[]), Some(AUTHORITY), vec![late, early]);
        assert_eq!(effective_value(&state.message), json!({ "x": "early" }));
    }

    #[test]
    fn effective_value_falls_back_to_message() {
        let message = init(&[("foo", Value::String("bar".to_string()))]);
        assert_eq!(effective_value(&message), Value::Object(message));
    }

    #[test]
    fn queries_match_reference_discovery_shape() {
        let set_query = build_set_query("REF", Some("AUTH"), 0, 100, Some("cursor"));
        assert!(set_query.contains(r#"owners: ["AUTH"]"#));
        assert!(set_query.contains(r#"{ name: "reference-id", values: ["REF"] }"#));
        assert!(set_query.contains(r#"after: "cursor""#));

        let tx_query = build_tx_query("REF");
        assert!(tx_query.contains(r#"transaction(id: "REF")"#));
    }
}
