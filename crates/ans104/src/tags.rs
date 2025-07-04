/// Tags
use anyhow::Result;
use apache_avro::{Schema, from_avro_datum, to_avro_datum};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

const MAX_TAGS: usize = 128;
const MAX_NAME_LEN: usize = 1024;
const MAX_VALUE_LEN: usize = 3072;

/// Avro schema for a tag array of {name:string, value:string}
static TAG_ARRAY_SCHEMA: Lazy<Schema> = Lazy::new(|| {
    Schema::parse_str(
        r#"{
            "type": "array",
            "items": {
                "type": "record",
                "name": "Tag",
                "fields": [
                    {"name": "name", "type": "string"},
                    {"name": "value", "type": "string"}
                ]
            }
        }"#,
    )
    .expect("valid ANS104 tag schema")
});

/// A single Key/Value tag.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Tag {
    pub name: String,
    pub value: String,
}

impl Tag {
    /// Construct a new Tag
    pub fn new<N: Into<String>, V: Into<String>>(name: N, value: V) -> Self {
        Self { name: name.into(), value: value.into() }
    }
}

pub fn encode_tags(tags: &[Tag]) -> Result<Vec<u8>> {
    if tags.is_empty() {
        return Ok(vec![]);
    }
    validate_tags(tags)?;

    let value = apache_avro::to_value(tags)?;
    Ok(to_avro_datum(&TAG_ARRAY_SCHEMA, value)?)
}

pub fn decode_tags(bytes: &[u8]) -> Result<Vec<Tag>> {
    if bytes.is_empty() {
        return Ok(vec![]);
    }

    let value = from_avro_datum(&TAG_ARRAY_SCHEMA, &mut &bytes[..], Some(&TAG_ARRAY_SCHEMA))?;
    Ok(apache_avro::from_value(&value)?)
}

/// Validate tags according to ANS-104 constraints
pub fn validate_tags(tags: &[Tag]) -> Result<()> {
    anyhow::ensure!(tags.len() <= MAX_TAGS, "too many tags (>{})", MAX_TAGS);

    for tag in tags {
        anyhow::ensure!(!tag.name.is_empty(), "empty tag name");
        anyhow::ensure!(!tag.value.is_empty(), "empty tag value");
        anyhow::ensure!(tag.name.len() <= MAX_NAME_LEN, "tag name >{} bytes", MAX_NAME_LEN);
        anyhow::ensure!(tag.value.len() <= MAX_VALUE_LEN, "tag value >{} bytes", MAX_VALUE_LEN);
    }

    Ok(())
}

/// Parse tags from raw Avro binary format (without file headers)
/// Returns number of tags parsed, and ensures ANS-104 constraints.
pub fn verify_tags_raw_avro(tags: &[u8]) -> Result<usize> {
    if tags.is_empty() {
        return Ok(0);
    }

    let mut cursor = 0;
    let mut count = 0;

    // Read first block count
    let (mut block_count, mut read) = decode_zigzag_varint(&tags[cursor..])?;
    cursor += read;

    while block_count > 0 {
        for _ in 0..block_count {
            // parse name
            let (name_len, r) = decode_zigzag_varint(&tags[cursor..])?;
            cursor += r;
            anyhow::ensure!(cursor + name_len <= tags.len(), "name overflow");
            let name = &tags[cursor..cursor + name_len];
            cursor += name_len;

            // parse value
            let (value_len, r) = decode_zigzag_varint(&tags[cursor..])?;
            cursor += r;
            anyhow::ensure!(cursor + value_len <= tags.len(), "value overflow");
            let value = &tags[cursor..cursor + value_len];
            cursor += value_len;

            // Validate ANS-104 tag constraints
            anyhow::ensure!(!name.is_empty(), "empty tag key");
            anyhow::ensure!(!value.is_empty(), "empty tag value");
            anyhow::ensure!(name.len() <= MAX_NAME_LEN, "tag key >{}", MAX_NAME_LEN);
            anyhow::ensure!(value.len() <= MAX_VALUE_LEN, "tag value >{}", MAX_VALUE_LEN);

            count += 1;
            anyhow::ensure!(count <= MAX_TAGS, "too many tags (>{})", MAX_TAGS);
        }

        // read next block count
        let (next_count, r) = decode_zigzag_varint(&tags[cursor..])?;
        cursor += r;
        block_count = next_count;
    }
    // Check for array end marker (0)
    if cursor < tags.len() && tags[cursor] == 0 {
        cursor += 1;
    }

    Ok(count)
}

/// Decode a zigzag-encoded varint (Avro long).
/// Returns (value, bytes_read).
fn decode_zigzag_varint(bytes: &[u8]) -> Result<(usize, usize)> {
    let mut value = 0u64;
    let mut shift = 0;
    let mut cursor = 0;

    loop {
        anyhow::ensure!(cursor < bytes.len(), "varint overflow");
        let byte = bytes[cursor];
        cursor += 1;
        value |= ((byte & 0x7F) as u64) << shift;

        if byte & 0x80 == 0 {
            break;
        }

        shift += 7;
        anyhow::ensure!(shift < 64, "varint too large");
    }

    let decoded = if value & 1 == 0 { (value >> 1) as i64 } else { -(((value >> 1) as i64) + 1) };

    anyhow::ensure!(decoded >= 0, "negative length in tags");

    Ok((decoded as usize, cursor))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_empty() {
        let tags: Vec<Tag> = vec![];
        assert_eq!(encode_tags(&tags).unwrap(), Vec::<u8>::new());
        assert_eq!(decode_tags(&[]).unwrap(), tags);
        assert_eq!(verify_tags_raw_avro(&[]).unwrap(), 0);
    }

    #[test]
    fn single_tag() {
        let tags = vec![Tag::new("key", "value")];
        let buf = encode_tags(&tags).unwrap();
        assert_eq!(verify_tags_raw_avro(&buf).unwrap(), 1);
        assert_eq!(decode_tags(&buf).unwrap(), tags);
    }

    #[test]
    fn multiple_tags() {
        let tags = vec![Tag::new("k1", "v1"), Tag::new("k2", "v2"), Tag::new("k3", "v3")];
        let buf = encode_tags(&tags).unwrap();
        assert_eq!(verify_tags_raw_avro(&buf).unwrap(), tags.len());
        assert_eq!(decode_tags(&buf).unwrap(), tags);
    }

    #[test]
    fn validate_constraints() {
        // Too many tags
        let too_many: Vec<Tag> =
            (0..(MAX_TAGS + 1)).map(|i| Tag::new(format!("k{}", i), "v")).collect();
        assert!(validate_tags(&too_many).is_err());

        // Empty name
        assert!(validate_tags(&[Tag::new("", "v")]).is_err());
        // Empty value
        assert!(validate_tags(&[Tag::new("k", "")]).is_err());
        // Name too long
        assert!(validate_tags(&[Tag::new("a".repeat(MAX_NAME_LEN + 1), "v")]).is_err());
        // Value too long
        assert!(validate_tags(&[Tag::new("k", "b".repeat(MAX_VALUE_LEN + 1))]).is_err());
    }

    #[test]
    fn unicode_tags() {
        let tags = vec![Tag::new("こんにちは", "世界"), Tag::new("emoji", "🚀🌟")];
        let buf = encode_tags(&tags).unwrap();
        assert_eq!(verify_tags_raw_avro(&buf).unwrap(), tags.len());
        assert_eq!(decode_tags(&buf).unwrap(), tags);
    }

    #[test]
    fn raw_avro_format() {
        // Manual Avro array: [ {name:"n", value:"v"} ]
        let raw = vec![
            0x02, // count 1
            0x02, b'n', // len 1 <<1=2, 'n'
            0x02, b'v', // len 1<<1=2, 'v'
            0x00, // end
        ];
        assert_eq!(verify_tags_raw_avro(&raw).unwrap(), 1);
        assert_eq!(decode_tags(&raw).unwrap(), vec![Tag::new("n", "v")]);
    }

    #[test]
    fn zigzag_varint() {
        let cases = vec![
            (0, vec![0x00]),
            (1, vec![0x02]),
            (2, vec![0x04]),
            (127, vec![0xFE, 0x01]),
            (128, vec![0x80, 0x02]),
        ];
        for (exp, bytes) in cases {
            let (dec, len) = decode_zigzag_varint(&bytes).unwrap();
            assert_eq!(dec, exp);
            assert_eq!(len, bytes.len());
        }
    }
}
