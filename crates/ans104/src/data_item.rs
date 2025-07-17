//! Binary data‑item (ANS‑104) implementation.

use anyhow::{Context, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use sha2::{Digest, Sha256};

use crate::{
    deep_hash::{DeepHash, deep_hash_sync},
    tags,
    tags::Tag,
};
use crypto::signer::{SignatureType, Signer};
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
    /* ------------------------------------------------------------------ */
    /* Builders */
    /* ------------------------------------------------------------------ */

    /// Create an **unsigned** item (target / anchor may be `None`).
    pub fn new(
        target: Option<[u8; 32]>,
        anchor: Option<Vec<u8>>,
        tags: Vec<Tag>,
        data: Vec<u8>,
    ) -> Result<Self> {
        tags::validate_tags(&tags)?;
        if let Some(a) = &anchor {
            anyhow::ensure!(a.len() <= 32, "anchor > 32 bytes");
        }

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

    /* ------------------------------------------------------------------ */
    /* Signing / verifying */
    /* ------------------------------------------------------------------ */

    /// Compute the SHA‑384 deep‑hash message that must be signed.
    fn signing_message(&self) -> [u8; 48] {
        let target_bytes = self.target.map(|x| x.to_vec()).unwrap_or_default();
        let anchor_bytes = match &self.anchor {
            Some(a) => {
                let mut tmp = [0u8; 32];
                tmp[..a.len()].copy_from_slice(a);
                tmp.to_vec()
            }
            None => vec![],
        };
        let tags_bytes = tags::encode_tags(&self.tags).expect("tags already validated");

        let signature_type = self.signature_type.clone() as u16;
        let signature_type = signature_type.to_string();
        
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

        // 2. cryptographic verification (if we have an implementation for it)
        let message = self.signing_message();
        if let Some(verifier) = crypto::signer::verifier_for(&self.signature_type, &self.owner) {
            anyhow::ensure!(verifier(&message, &self.signature)?, "bad signature");
        }

        // 3. id check (sha‑256(sig) == id) for Arweave compatibility
        anyhow::ensure!(self.id() == Sha256::digest(&self.signature)[..], "id mismatch");

        Ok(())
    }

    /// The 32‑byte content‑id (sha‑256 of signature).
    pub fn id(&self) -> [u8; 32] {
        Sha256::digest(&self.signature).into()
    }

    /* ------------------------------------------------------------------ */
    /* Serialisation / deserialisation */
    /* ------------------------------------------------------------------ */

    /// Convert to the binary form described in §4 of ANS‑104.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.verify()?; // safety

        let mut out = Vec::with_capacity(
            2 + self.signature.len()
                + self.owner.len()
                + 1
                + 32
                + 1
                + 32
                + 8
                + 8
                + self.tags.len() * 128
                + self.data.len(),
        );

        // signature‑type (u16, big‑endian)
        out.write_u16::<byteorder::BigEndian>(self.signature_type as u16)?;

        // signature
        out.extend_from_slice(&self.signature);

        // owner
        out.extend_from_slice(&self.owner);

        // target
        match self.target {
            Some(target) => {
                out.push(1);
                out.extend_from_slice(&target);
            }
            None => out.push(0),
        }

        // anchor
        match &self.anchor {
            Some(anchor) => {
                out.push(1);
                let mut padded = [0u8; 32];
                padded[..anchor.len()].copy_from_slice(anchor);
                out.extend_from_slice(&padded);
            }
            None => out.push(0),
        }

        // tags
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
        use std::io::Cursor;

        let signature_type = SignatureType::from_u16(b.read_u16::<byteorder::BigEndian>()?);

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
        tags::validate_tags(&tagbuf)?;
        let tags = tags::decode_tags(&tagbuf)?;
        anyhow::ensure!(tag_count == tags.len(), "tag count mismatch");

        // data (whatever remains)
        let mut data = Vec::new();
        b.read_to_end(&mut data)?;

        let item = Self { signature_type, signature: sig, owner, target, anchor, tags, data };
        item.verify()?;
        Ok(item)
    }
}

/* ---------------------------------------------------------------------- */
/* Unit‑tests */
/* ---------------------------------------------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::ethereum::EthereumSigner;

    #[test]
    fn roundtrip() {
        let signer = EthereumSigner::random().unwrap();
        let tags = vec![Tag::new("Content-Type", "text/plain").unwrap()];
        let payload = b"hello ans104".to_vec();

        let item = DataItem::build_and_sign(&signer, None, None, tags, payload).expect("signed OK");

        let bytes = item.to_bytes().expect("serialised");
        let back = DataItem::from_bytes(&bytes).expect("parsed");
        assert_eq!(item.id(), back.id());
        assert_eq!(item.data, back.data);
    }
}
