//! Errors for the contact layer. The TS code has three classes (directory / group manager /
//! manager); here they are variants so callers match one type.

use majik_contact::{MajikContactError, MajikContactGroupError};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ContactManagerError {
    #[error("{0}")]
    Directory(String),

    #[error("{0}")]
    Groups(String),

    #[error("{0}")]
    Manager(String),

    #[error(transparent)]
    Contact(#[from] MajikContactError),

    #[error(transparent)]
    Group(#[from] MajikContactGroupError),

    #[error("Storage error: {0}")]
    Storage(String),
}

pub type Result<T> = std::result::Result<T, ContactManagerError>;

impl ContactManagerError {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Directory(_) => "directory",
            Self::Groups(_) => "groups",
            Self::Manager(_) => "manager",
            Self::Contact(_) => "contact",
            Self::Group(_) => "group",
            Self::Storage(_) => "storage",
        }
    }
}

impl From<rusqlite::Error> for ContactManagerError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Storage(e.to_string())
    }
}

impl From<serde_json::Error> for ContactManagerError {
    fn from(e: serde_json::Error) -> Self {
        Self::Storage(format!("JSON error: {e}"))
    }
}

/// Serialises as `{ "kind": "...", "message": "..." }` so Tauri commands can return it directly.
impl serde::Serialize for ContactManagerError {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("ContactManagerError", 2)?;
        st.serialize_field("kind", self.kind())?;
        st.serialize_field("message", &self.to_string())?;
        st.end()
    }
}
