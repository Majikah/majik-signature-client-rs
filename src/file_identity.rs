//! Bridges `majik-key` and `majik-file`: building a `MajikFileIdentity` from an unlocked key, and
//! the encrypt/decrypt envelope used by logs and stamps.
//!
//! `majik-key` stores the ML-KEM-768 secret in the same 2400-byte expanded form `majik-file`
//! expects, so no conversion is needed.

use majik_file::{
    array_to_base64, base64_to_array, MajikFile, MajikFileCreateOptions, MajikFileDecryptIdentity,
    MajikFileIdentity, MajikFileJson,
};
use majik_key::{KeyId, MajikKey};

use crate::error::{Result, SignatureClientError};

/// Requires the key to be unlocked and to hold ML-KEM material.
pub fn identity_from_key(key: &MajikKey) -> Result<MajikFileIdentity> {
    if key.is_locked() {
        return Err(SignatureClientError::Key(
            majik_key_client::KeyClientError::UnlockRequired(key.id().to_string()),
        ));
    }
    let no_kem = |e: &dyn std::fmt::Display| {
        SignatureClientError::Invalid(format!(
            "Account \"{}\" has no ML-KEM keys ({e}). Re-import via \
             importAccountFromMnemonicBackup() to enable stamp and log encryption.",
            key.id()
        ))
    };
    let secret = key
        .get_private_key(KeyId::MlKem768)
        .map_err(|e| no_kem(&e))?;
    let public = key
        .get_public_key(KeyId::MlKem768)
        .map_err(|e| no_kem(&e))?;
    Ok(MajikFileIdentity {
        public_key: key.public_key_base64().to_string(),
        fingerprint: key.fingerprint().to_string(),
        ml_kem_public_key: public,
        ml_kem_secret_key: secret,
    })
}

/// A sealed `.mjkb` envelope: base64 binary + its `MajikFileJSON`.
#[derive(Debug, Clone)]
pub struct EncryptedEnvelope {
    pub data_base64: String,
    pub file_json: MajikFileJson,
}

pub fn encrypt_envelope(
    data: &[u8],
    identity: &MajikFileIdentity,
    original_name: Option<&str>,
    mime_type: Option<&str>,
) -> Result<EncryptedEnvelope> {
    let mut options = MajikFileCreateOptions::new(
        data.to_vec(),
        identity.fingerprint.clone(),
        identity.clone(),
    );
    options.original_name = original_name.map(str::to_string);
    options.mime_type = mime_type.map(str::to_string);
    let file = MajikFile::create(options)?;
    let file_json = file.to_json()?;
    let binary = file.to_binary_bytes()?;
    Ok(EncryptedEnvelope {
        data_base64: array_to_base64(binary),
        file_json,
    })
}

pub fn decrypt_envelope(data_base64: &str, identity: &MajikFileIdentity) -> Result<Vec<u8>> {
    let binary = base64_to_array(data_base64)?;
    Ok(MajikFile::decrypt(
        &binary,
        MajikFileDecryptIdentity::from(identity),
        None,
    )?)
}
