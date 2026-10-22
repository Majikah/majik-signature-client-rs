//! Error type for the signature client.

use crate::contacts::ContactManagerError;
use majik_cjson::MajikCjsonError;
use majik_file::MajikFileError;
use majik_key_client::KeyClientError;
use majik_signature::MajikSignatureError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignatureClientError {
    #[error(transparent)]
    Key(#[from] KeyClientError),

    #[error(transparent)]
    Contacts(#[from] ContactManagerError),

    #[error(transparent)]
    Signature(#[from] MajikSignatureError),

    #[error(transparent)]
    File(#[from] MajikFileError),

    #[error(transparent)]
    Cjson(#[from] MajikCjsonError),

    /// A file argument could not be loaded or written. `kind` is stable for the TS side:
    /// `fileNotFound`, `fileNotAFile`, `fileUnreadable`, `fileEmpty`, `fileTooLarge`,
    /// `fileInvalid`, `fileExists`, `fileWriteFailed`.
    #[error("{message}")]
    FileInput { kind: &'static str, message: String },

    #[error("Log error: {0}")]
    Log(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("{0}")]
    Invalid(String),

    #[error("No active account -- set an active account first")]
    NoActiveAccount,

    #[error("Account not found in own accounts: \"{0}\"")]
    OwnAccountNotFound(String),

    #[error("client state is unavailable: a lock was poisoned")]
    Poisoned,
}

pub type Result<T> = std::result::Result<T, SignatureClientError>;

impl SignatureClientError {
    /// Stable machine-readable discriminant for the TS side. Key-client errors keep the kind they
    /// already have (`unlockRequired`, `duplicateAccount`, ...).
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Key(e) => e.kind(),
            Self::Contacts(e) => e.kind(),
            Self::Signature(_) => "signature",
            Self::File(_) => "file",
            Self::Cjson(_) => "cjson",
            Self::FileInput { kind, .. } => kind,
            Self::Log(_) => "log",
            Self::Storage(_) => "storage",
            Self::Invalid(_) => "invalid",
            Self::NoActiveAccount => "noActiveAccount",
            Self::OwnAccountNotFound(_) => "ownAccountNotFound",
            Self::Poisoned => "poisoned",
        }
    }
}

impl From<rusqlite::Error> for SignatureClientError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Storage(e.to_string())
    }
}

impl From<serde_json::Error> for SignatureClientError {
    fn from(e: serde_json::Error) -> Self {
        Self::Storage(format!("JSON error: {e}"))
    }
}

/// Serialises as `{ "kind": "...", "message": "..." }` so Tauri commands can return it directly.
impl serde::Serialize for SignatureClientError {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("SignatureClientError", 2)?;
        st.serialize_field("kind", self.kind())?;
        st.serialize_field("message", &self.to_string())?;
        st.end()
    }
}
