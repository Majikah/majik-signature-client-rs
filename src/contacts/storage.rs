//! Repository traits (TS `MajikContactStorageAdapter` / `MajikContactGroupStorageAdapter`).
//! The dynamic `query({ where, orderBy })` is intentionally not ported: nothing in the manager
//! uses it, and building SQL from caller-supplied column names is not worth carrying over.

use majik_contact::{SerializedMajikContact, SerializedMajikContactGroup};

use super::error::Result;

pub trait ContactRepo: Send + Sync {
    fn save(&self, contact: &SerializedMajikContact) -> Result<()>;
    fn get_by_id(&self, id: &str) -> Result<Option<SerializedMajikContact>>;
    /// Insertion (rowid) order.
    fn list(&self) -> Result<Vec<SerializedMajikContact>>;
    fn remove(&self, id: &str) -> Result<bool>;
    fn clear(&self) -> Result<()>;
    fn count(&self) -> Result<usize>;
    fn exists(&self, id: &str) -> Result<bool>;
    fn bulk_save(&self, contacts: &[SerializedMajikContact]) -> Result<()>;
    fn bulk_remove(&self, ids: &[String]) -> Result<()>;
}

pub trait GroupRepo: Send + Sync {
    fn save(&self, group: &SerializedMajikContactGroup) -> Result<()>;
    fn get_by_id(&self, id: &str) -> Result<Option<SerializedMajikContactGroup>>;
    fn list(&self) -> Result<Vec<SerializedMajikContactGroup>>;
    fn remove(&self, id: &str) -> Result<bool>;
    fn clear(&self) -> Result<()>;
    fn count(&self) -> Result<usize>;
    fn exists(&self, id: &str) -> Result<bool>;
    fn bulk_save(&self, groups: &[SerializedMajikContactGroup]) -> Result<()>;
    fn bulk_remove(&self, ids: &[String]) -> Result<()>;
}
