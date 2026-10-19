//! Contact card import/export: JSON, and gzip+base64 "share string". Interoperable with the TS
//! `exportContactCompressed` / `importContactCompressed` (fflate gzip + standard base64 of the
//! card JSON). Decompression is size-capped because the input is untrusted.

use std::io::{Read, Write};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use majik_contact::{MajikContact, MajikContactCard, MajikContactMeta, SerializedMajikContact};

use super::error::{ContactManagerError, Result};

/// A card is a few KB (ML-KEM + ML-DSA public keys). Anything near this cap is not a card.
pub const MAX_DECOMPRESSED_BYTES: u64 = 1024 * 1024;

fn merr(msg: impl Into<String>) -> ContactManagerError {
    ContactManagerError::Manager(msg.into())
}

pub fn card_to_json(contact: &MajikContact, pretty: bool) -> Result<String> {
    let card = contact.to_contact_card();
    Ok(if pretty {
        serde_json::to_string_pretty(&card)?
    } else {
        serde_json::to_string(&card)?
    })
}

/// Build a contact from a shared card. Only the label is imported as metadata.
pub fn contact_from_card(card: MajikContactCard) -> Result<MajikContact> {
    if card.id.is_empty()
        || card.public_key.is_empty()
        || card.fingerprint.is_empty()
        || card.ml_key.is_empty()
    {
        return Err(merr("Invalid contact JSON"));
    }
    let serialized = SerializedMajikContact {
        id: card.id,
        fingerprint: card.fingerprint,
        meta: Some(MajikContactMeta {
            label: Some(card.label),
            ..Default::default()
        }),
        public_key_base64: card.public_key,
        ml_key: card.ml_key,
        majikah_registered: None,
        ed_public_key_base64: card.ed_public_key_base64,
        ml_dsa_public_key_base64: card.ml_dsa_public_key_base64,
    };
    Ok(MajikContact::from_json(serialized)?)
}

pub fn contact_from_card_json(json: &str) -> Result<MajikContact> {
    let card: MajikContactCard = serde_json::from_str(json)?;
    contact_from_card(card)
}

pub fn export_compressed(contact: &MajikContact) -> Result<String> {
    let json = card_to_json(contact, false)?;
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    enc.write_all(json.as_bytes())
        .map_err(|e| merr(format!("gzip failed: {e}")))?;
    let bytes = enc.finish().map_err(|e| merr(format!("gzip failed: {e}")))?;
    Ok(STANDARD.encode(bytes))
}

pub fn import_compressed(base64_str: &str) -> Result<MajikContact> {
    let compressed = STANDARD
        .decode(base64_str.trim())
        .map_err(|e| merr(format!("Invalid base64: {e}")))?;
    let mut out = Vec::new();
    GzDecoder::new(&compressed[..])
        .take(MAX_DECOMPRESSED_BYTES + 1)
        .read_to_end(&mut out)
        .map_err(|e| merr(format!("Invalid compressed contact: {e}")))?;
    if out.len() as u64 > MAX_DECOMPRESSED_BYTES {
        return Err(merr("Compressed contact exceeds the size limit"));
    }
    let json = String::from_utf8(out).map_err(|_| merr("Contact is not valid UTF-8"))?;
    contact_from_card_json(&json)
}
