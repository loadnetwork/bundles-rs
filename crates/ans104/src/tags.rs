/// Tags
use anyhow::Result;
use serde::{Deserialize, Serialize};

//TODO: impl Serialize, Deserialize

const AVRO_SCHEMA: &str = r#"{
  "type": "array",
  "items": {
    "type": "record",
    "name": "Tag",
    "fields": [
      { "name": "name", "type": "bytes" },
      { "name": "value", "type": "bytes" }
    ]
  }
}"#;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Tag {
    pub name: String,
    pub value: String,
}

/// Parse tags from raw Avro binary format (without file headers)
/// This matches the bundler SDK's encoding using strings
fn verify_tags_raw_avro(tags_slice: &[u8]) -> Result<usize> {
    if tags_slice.is_empty() {
        return Ok(0);
    }

    let mut cursor = 0;
    let mut count = 0;

    // Read array length (zigzag encoded)
    let (array_len, bytes_read) = decode_zigzag_varint(&tags_slice[cursor..])?;
    cursor += bytes_read;

    println!("Decoded array length: {}", array_len);

    if array_len == 0 {
        return Ok(0);
    }

    // Read each tag record
    for i in 0..array_len {
        // Each tag is a record with two string fields

        // Read name string
        let (name_len, bytes_read) = decode_zigzag_varint(&tags_slice[cursor..])?;
        cursor += bytes_read;

        anyhow::ensure!(cursor + name_len <= tags_slice.len(), "name overflow");
        let name = &tags_slice[cursor..cursor + name_len];
        cursor += name_len;

        // Read value string
        let (value_len, bytes_read) = decode_zigzag_varint(&tags_slice[cursor..])?;
        cursor += bytes_read;

        anyhow::ensure!(cursor + value_len <= tags_slice.len(), "value overflow");
        let value = &tags_slice[cursor..cursor + value_len];
        cursor += value_len;

        println!(
            "Tag {}: name='{}', value='{}'",
            i,
            String::from_utf8_lossy(name),
            String::from_utf8_lossy(value)
        );

        // Validate ANS-104 tag constraints
        anyhow::ensure!(!name.is_empty(), "empty tag key");
        anyhow::ensure!(!value.is_empty(), "empty tag value");
        anyhow::ensure!(name.len() <= 1024, "tag key >1024");
        anyhow::ensure!(value.len() <= 3072, "tag value >3072");

        count += 1;
        anyhow::ensure!(count <= 128, "too many tags (>128)");
    }

    // Check for array end marker (0)
    if cursor < tags_slice.len() && tags_slice[cursor] == 0 {
        cursor += 1;
    }

    Ok(count)
}

/// Decode a zigzag-encoded varint from Avro format
/// Avro uses variable-length integers with zigzag encoding for efficient storage
fn decode_zigzag_varint(bytes: &[u8]) -> Result<(usize, usize)> {
    let mut value = 0u64;
    let mut shift = 0;
    let mut cursor = 0;

    // Read varint bytes (continuation bit in MSB)
    loop {
        anyhow::ensure!(cursor < bytes.len(), "varint overflow");
        let byte = bytes[cursor];
        cursor += 1;

        // Take lower 7 bits and add to value
        value |= ((byte & 0x7F) as u64) << shift;

        // If MSB is 0, this is the last byte
        if byte & 0x80 == 0 {
            break;
        }

        shift += 7;
        anyhow::ensure!(shift < 64, "varint too large");
    }

    // Decode zigzag encoding:
    // 0 -> 0, 1 -> -1, 2 -> 1, 3 -> -2, 4 -> 2, etc.
    let decoded = if value & 1 == 0 { (value >> 1) as i64 } else { -(((value >> 1) as i64) + 1) };

    // For lengths, we expect positive values
    anyhow::ensure!(decoded >= 0, "negative length in tags");

    Ok((decoded as usize, cursor))
}
