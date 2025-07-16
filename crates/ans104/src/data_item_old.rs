use anyhow::Error;
use bytes::Bytes;
use crypto::signer::Signer;
use futures::Stream;
use std::pin::Pin;

use crate::tags::{self, Tag};

//*
/// DataItem Format
/// A DataItem is a binary encoded object that has similar properties to a transaction
///
/// | Field               | Description                                    | Encoding | Length (in bytes)         | Optional           |
/// | ------------------- | ---------------------------------------------- | -------- | ------------------------- | ------------------ |
/// | signature type      | Type of key format used for the signature      | Binary   | 2                         | :x:                |
/// | signature           | A signature produced by owner                  | Binary   | Depends on signature type | :x:                |
/// | owner               | The public key of the owner                    | Binary   | 512                       | :x:                |
/// | target              | An address that this DataItem is being sent to | Binary   | 32 (+ presence byte)      | :heavy_check_mark: |
/// | anchor              | A value to prevent replay attacks              | Binary   | 32 (+ presence byte)      | :heavy_check_mark: |
/// | number of tags      | Number of tags                                 | Binary   | 8                         | :x:                |
/// | number of tag bytes | Number of bytes used for tags                  | Binary   | 8                         | :x:                |
/// | tags                | An avro array of tag objects                   | Binary   | Variable                  | :x:                |
/// | data                | The data contents                              | Binary   | Variable                  | :x:                |
/// A `DataItem` is a binary-encoded object with semantics similar to a blockchain transaction:
///
/// - it is signed by an owner key
/// - it may carry an optional target address or anchor value
/// - it can carry arbitrary tags (as an Avro-encoded array)
/// - it finally carries the raw payload data
#[derive(Debug, Clone)]
pub struct DataItem {
    /// Type of key format used for the signature.
    ///
    /// **Encoding:** raw binary  
    /// **Length:** exactly 2 bytes  
    pub signature_type: crypto::signer::SignatureType,

    /// A cryptographic signature produced by the owner over the rest of the item.
    ///
    /// **Encoding:** raw binary  
    /// **Length:** variable, depends on `signature_type`  
    pub signature: Vec<u8>,

    /// The public key of the owner.
    ///
    /// **Encoding:** raw binary  
    /// **Length:** exactly 512 bytes  
    pub owner: Vec<u8>,

    /// An optional 32-byte address that this item is being sent to.
    ///
    /// **Encoding:** presence byte (0 or 1) + up to 32 raw bytes  
    /// **Length:** 1 + 32 bytes when present  
    pub target: Option<Vec<u8>>,

    /// An optional 32-byte anchor value (used e.g. to prevent replay attacks).
    ///
    /// **Encoding:** presence byte (0 or 1) + up to 32 raw bytes  
    /// **Length:** 1 + 32 bytes when present  
    pub anchor: Option<Vec<u8>>,

    /// An Avro-encoded array of tag objects.
    ///
    /// Each tag is typically a key/value pair; the Avro schema is:
    /// ```avro
    /// {
    ///   "type": "record",
    ///   "name": "Tag",
    ///   "fields": [
    ///     {"name": "name", "type": "bytes"},
    ///     {"name": "value", "type": "bytes"}
    ///   ]
    /// }
    /// ```
    ///
    /// **Encoding:** Avro binary block format  
    /// **Length:** variable (see `number_of_tag_bytes`)  
    pub tags: Vec<tags::Tag>,

    /// The raw payload data of this item.
    ///
    /// **Encoding:** raw binary  
    /// **Length:** variable  
    pub data: Vec<u8>,
}

pub enum DataItemData {
    Bytes(Vec<u8>),
    Stream(Pin<Box<dyn Stream<Item = Result<Bytes, Error>> + Send>>),
}

impl DataItem {
    fn new(tags: Vec<Tag>, data: Vec<u8>) -> Self {
        Self {
            signature: Default::default(),
            signature_type: crypto::signer::SignatureType::None,
            owner: Default::default(),
            target: Default::default(),
            anchor: Default::default(),
            tags,
            data,
        }
    }
}
