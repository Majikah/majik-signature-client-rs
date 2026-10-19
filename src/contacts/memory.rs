//! In-memory repositories (tests; TS `InMemory*Adapter`).

use std::sync::{Mutex, MutexGuard};

use majik_contact::{SerializedMajikContact, SerializedMajikContactGroup};

use super::error::{ContactManagerError, Result};
use super::storage::{ContactRepo, GroupRepo};

fn lock<T>(m: &Mutex<T>) -> Result<MutexGuard<'_, T>> {
    m.lock()
        .map_err(|_| ContactManagerError::Storage("in-memory store mutex poisoned".into()))
}

#[derive(Default)]
pub struct MemoryContactRepo {
    rows: Mutex<Vec<SerializedMajikContact>>,
}

impl MemoryContactRepo {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ContactRepo for MemoryContactRepo {
    fn save(&self, c: &SerializedMajikContact) -> Result<()> {
        let mut rows = lock(&self.rows)?;
        // INSERT OR REPLACE semantics: a replaced row moves to the end.
        rows.retain(|r| r.id != c.id);
        rows.push(c.clone());
        Ok(())
    }
    fn get_by_id(&self, id: &str) -> Result<Option<SerializedMajikContact>> {
        Ok(lock(&self.rows)?.iter().find(|r| r.id == id).cloned())
    }
    fn list(&self) -> Result<Vec<SerializedMajikContact>> {
        Ok(lock(&self.rows)?.clone())
    }
    fn remove(&self, id: &str) -> Result<bool> {
        let mut rows = lock(&self.rows)?;
        let before = rows.len();
        rows.retain(|r| r.id != id);
        Ok(rows.len() != before)
    }
    fn clear(&self) -> Result<()> {
        lock(&self.rows)?.clear();
        Ok(())
    }
    fn count(&self) -> Result<usize> {
        Ok(lock(&self.rows)?.len())
    }
    fn exists(&self, id: &str) -> Result<bool> {
        Ok(lock(&self.rows)?.iter().any(|r| r.id == id))
    }
    fn bulk_save(&self, contacts: &[SerializedMajikContact]) -> Result<()> {
        for c in contacts {
            self.save(c)?;
        }
        Ok(())
    }
    fn bulk_remove(&self, ids: &[String]) -> Result<()> {
        for id in ids {
            self.remove(id)?;
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct MemoryGroupRepo {
    rows: Mutex<Vec<SerializedMajikContactGroup>>,
}

impl MemoryGroupRepo {
    pub fn new() -> Self {
        Self::default()
    }
}

impl GroupRepo for MemoryGroupRepo {
    fn save(&self, g: &SerializedMajikContactGroup) -> Result<()> {
        let mut rows = lock(&self.rows)?;
        rows.retain(|r| r.id != g.id);
        rows.push(g.clone());
        Ok(())
    }
    fn get_by_id(&self, id: &str) -> Result<Option<SerializedMajikContactGroup>> {
        Ok(lock(&self.rows)?.iter().find(|r| r.id == id).cloned())
    }
    fn list(&self) -> Result<Vec<SerializedMajikContactGroup>> {
        Ok(lock(&self.rows)?.clone())
    }
    fn remove(&self, id: &str) -> Result<bool> {
        let mut rows = lock(&self.rows)?;
        let before = rows.len();
        rows.retain(|r| r.id != id);
        Ok(rows.len() != before)
    }
    fn clear(&self) -> Result<()> {
        lock(&self.rows)?.clear();
        Ok(())
    }
    fn count(&self) -> Result<usize> {
        Ok(lock(&self.rows)?.len())
    }
    fn exists(&self, id: &str) -> Result<bool> {
        Ok(lock(&self.rows)?.iter().any(|r| r.id == id))
    }
    fn bulk_save(&self, groups: &[SerializedMajikContactGroup]) -> Result<()> {
        for g in groups {
            self.save(g)?;
        }
        Ok(())
    }
    fn bulk_remove(&self, ids: &[String]) -> Result<()> {
        for id in ids {
            self.remove(id)?;
        }
        Ok(())
    }
}
