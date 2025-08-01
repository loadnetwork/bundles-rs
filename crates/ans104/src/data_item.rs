//! Binary data‑item (ANS‑104) implementation.

use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use sha2::{Digest, Sha256};

use crate::{
    deep_hash::{DeepHash, deep_hash_sync},
    tags,
    tags::Tag,
};
use crypto::signer::{SignatureType, Signer};

use std::io::Read;

/// Binary‑encoded data‑item.
#[derive(Debug, Clone)]
pub struct DataItem {
    pub signature_type: SignatureType,
    pub signature: Vec<u8>,
    pub owner: Vec<u8>,
    pub target: Option<[u8; 32]>,
    pub anchor: Option<Vec<u8>>, // max 32 bytes
    pub tags: Vec<Tag>,
    pub data: Vec<u8>,
}

impl DataItem {
    /// Create an **unsigned** item (target / anchor may be `None`).
    pub fn new(
        target: Option<[u8; 32]>,
        anchor: Option<Vec<u8>>,
        tags: Vec<Tag>,
        data: Vec<u8>,
    ) -> Result<Self> {
        tags::validate_tags(&tags)?;
        let anchor = match anchor {
            Some(a) => {
                anyhow::ensure!(a.len() <= 32, "anchor > 32 bytes");
                let mut padded = vec![0u8; 32];
                padded[..a.len()].copy_from_slice(&a);
                Some(padded)
            }
            None => None,
        };

        Ok(Self {
            signature_type: SignatureType::None,
            signature: Vec::new(),
            owner: Vec::new(),
            target,
            anchor,
            tags,
            data,
        })
    }

    /// Convenience: build **and sign** in one call.
    pub fn build_and_sign<S: Signer>(
        signer: &S,
        target: Option<[u8; 32]>,
        anchor: Option<Vec<u8>>,
        tags: Vec<Tag>,
        data: Vec<u8>,
    ) -> Result<Self> {
        let mut item = Self::new(target, anchor, tags, data)?;
        item.sign(signer)?;
        Ok(item)
    }
    /// Compute the SHA‑384 deep‑hash message that must be signed.
    pub fn signing_message(&self) -> [u8; 48] {
        let target_bytes = self.target.map(|x| x.to_vec()).unwrap_or_default();
        let anchor_bytes = self.anchor.as_ref().map(|a| a.to_vec()).unwrap_or_default();
        let tags_bytes = tags::encode_tags(&self.tags).expect("tags already validated");

        let signature_type = (self.signature_type as u16).to_string();

        let dh = DeepHash::List(vec![
            DeepHash::Blob(b"dataitem"),
            DeepHash::Blob(b"1"),
            DeepHash::Blob(&signature_type.as_bytes()),
            DeepHash::Blob(&self.owner),
            DeepHash::Blob(&target_bytes),
            DeepHash::Blob(&anchor_bytes),
            DeepHash::Blob(&tags_bytes),
            DeepHash::Blob(&self.data),
        ]);

        deep_hash_sync(&dh)
    }

    /// Sign the data‑item in‑place.
    pub fn sign<S: Signer>(&mut self, signer: &S) -> Result<()> {
        self.signature_type = signer.signature_type();
        self.owner = signer.public_key();
        let message = self.signing_message();
        self.signature = signer.sign(&message)?;

        anyhow::ensure!(
            self.signature.len() == self.signature_type.signature_len(),
            "signature length mismatch ({})",
            self.signature.len()
        );
        anyhow::ensure!(
            self.owner.len() == self.signature_type.owner_len(),
            "owner length mismatch ({})",
            self.owner.len()
        );
        Ok(())
    }

    /// Verify the signature and structural constraints.
    pub fn verify(&self) -> Result<()> {
        // 1. length checks
        tags::validate_tags(&self.tags)?;
        if let Some(a) = &self.anchor {
            anyhow::ensure!(a.len() <= 32, "anchor > 32 bytes");
        }
        anyhow::ensure!(
            self.signature.len() == self.signature_type.signature_len(),
            "invalid signature length"
        );
        anyhow::ensure!(
            self.owner.len() == self.signature_type.owner_len(),
            "invalid owner length"
        );

        // 2. cryptographic verification (if supported)
        let message = self.signing_message();
        anyhow::ensure!(
            self.signature_type.verify(&self.owner, &message, &self.signature)?,
            "bad signature"
        );

        // 3. id check (sha‑256(sig) == id) for Arweave compatibility
        anyhow::ensure!(self.id() == Sha256::digest(&self.signature)[..], "id mismatch");

        Ok(())
    }

    /// The 32‑byte content‑id (sha‑256 of signature).
    pub fn id(&self) -> [u8; 32] {
        Sha256::digest(&self.signature).into()
    }

    pub fn arweave_id(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.id())
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.verify()?;

        let mut out = Vec::with_capacity(
            2 + self.signature.len()
            + self.owner.len()
            + 1 + self.target.map(|_| 32).unwrap_or(0)
            + 1 + self.anchor.as_ref().map(|_| 32).unwrap_or(0)
            + 16
            + 1024 // estimate for tags
            + self.data.len(),
        );

        out.write_u16::<byteorder::LittleEndian>(self.signature_type as u16)?;

        out.extend_from_slice(&self.signature);

        out.extend_from_slice(&self.owner);

        match self.target {
            Some(target) => {
                out.push(1); // presence byte
                out.extend_from_slice(&target); // already 32 bytes
            }
            None => out.push(0), // presence byte
        }

        match &self.anchor {
            Some(anchor) => {
                anyhow::ensure!(anchor.len() == 32, "anchor must be exactly 32 bytes");
                out.push(1); // presence byte
                out.extend_from_slice(anchor);
            }
            None => out.push(0), // presence byte
        }

        // tags (LITTLE-endian for counts)
        let tags_bin = tags::encode_tags(&self.tags)?;
        out.write_u64::<LittleEndian>(self.tags.len() as u64)?;
        out.write_u64::<LittleEndian>(tags_bin.len() as u64)?;
        out.extend_from_slice(&tags_bin);

        // data
        out.extend_from_slice(&self.data);

        Ok(out)
    }

    /// Parse a binary data‑item (zero‑allocation where possible).
    pub fn from_bytes(mut b: &[u8]) -> Result<Self> {
        let signature_type = SignatureType::from_u16(b.read_u16::<byteorder::LittleEndian>()?);

        let mut sig = vec![0u8; signature_type.signature_len()];
        b.read_exact(&mut sig)?;

        let mut owner = vec![0u8; signature_type.owner_len()];
        b.read_exact(&mut owner)?;

        // target
        let target = match b.read_u8()? {
            1 => {
                let mut t = [0u8; 32];
                b.read_exact(&mut t)?;
                Some(t)
            }
            0 => None,
            _ => anyhow::bail!("bad target presence byte"),
        };

        // anchor
        let anchor = match b.read_u8()? {
            1 => {
                let mut a = [0u8; 32];
                b.read_exact(&mut a)?;
                Some(a.to_vec())
            }
            0 => None,
            _ => anyhow::bail!("bad anchor presence byte"),
        };

        // tags
        let tag_count = b.read_u64::<LittleEndian>()? as usize;
        let tag_bytes = b.read_u64::<LittleEndian>()? as usize;
        let mut tagbuf = vec![0u8; tag_bytes];

        b.read_exact(&mut tagbuf)?;
        let parsed = tags::verify_tags_raw_avro(&tagbuf)?;
        anyhow::ensure!(parsed == tag_count, "tag count mismatch");

        let tags = tags::decode_tags(&tagbuf)?;
        tags::validate_tags(&tags)?; // NEW – validate the decoded Vec<Tag>

        // data (whatever remains)
        let mut data = Vec::new();
        b.read_to_end(&mut data)?;

        let item = Self { signature_type, signature: sig, owner, target, anchor, tags, data };
        item.verify()?;
        Ok(item)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::ethereum::EthereumSigner;

    #[test]
    fn roundtrip() {
        let signer = EthereumSigner::random().unwrap();
        let tags = vec![Tag::new("Content-Type", "text/plain")];
        let payload = b"hello ans104".to_vec();

        let item = DataItem::build_and_sign(&signer, None, None, tags, payload).expect("signed OK");

        let bytes = item.to_bytes().expect("serialised");
        let back = DataItem::from_bytes(&bytes).expect("parsed");
        assert_eq!(item.id(), back.id());
        assert_eq!(item.data, back.data);
        assert_eq!(item.arweave_id(), URL_SAFE_NO_PAD.encode(item.id()));
        assert_eq!(item.arweave_id().len(), 43);
    }
}
