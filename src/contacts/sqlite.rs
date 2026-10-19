//! SQLite repositories over the app's shared `Arc<Mutex<rusqlite::Connection>>` (the same handle
//! type `majik-key-client` uses, so one SQLCipher connection serves both). Column mapping and
//! `INSERT OR REPLACE` semantics match the TS `SQLiteContactAdapter` / `SQLiteContactGroupAdapter`.
//! Synchronous: call from async Tauri commands through `spawn_blocking`.

use std::sync::{Arc, Mutex, MutexGuard};

use majik_contact::{SerializedMajikContact, SerializedMajikContactGroup};
use rusqlite::{params, Connection, OptionalExtension};

use super::error::{ContactManagerError, Result};
use super::schema::{SCHEMA_MAJIK_CONTACTS, SCHEMA_MAJIK_CONTACT_GROUPS};
use super::storage::{ContactRepo, GroupRepo};

pub type SharedConnection = Arc<Mutex<Connection>>;

fn lock(conn: &SharedConnection) -> Result<MutexGuard<'_, Connection>> {
    conn.lock()
        .map_err(|_| ContactManagerError::Storage("SQLite connection mutex poisoned".into()))
}

/// Idempotent. Creates `majik_contacts` and `majik_contact_groups` if missing.
pub fn init_schema(conn: &SharedConnection) -> Result<()> {
    let guard = lock(conn)?;
    guard.execute_batch(SCHEMA_MAJIK_CONTACTS)?;
    guard.execute_batch(SCHEMA_MAJIK_CONTACT_GROUPS)?;
    Ok(())
}

// ─── Contacts ────────────────────────────────────────────────────────────────

pub struct SqliteContactRepo {
    conn: SharedConnection,
}

impl SqliteContactRepo {
    pub fn new(conn: SharedConnection) -> Self {
        Self { conn }
    }
}

fn upsert_contact(conn: &Connection, c: &SerializedMajikContact) -> Result<()> {
    let json = serde_json::to_string(c)?;
    let label = c.meta.as_ref().and_then(|m| m.label.clone());
    let created_at = c.meta.as_ref().and_then(|m| m.created_at.clone());
    let updated_at = c.meta.as_ref().and_then(|m| m.updated_at.clone());
    conn.execute(
        "INSERT OR REPLACE INTO majik_contacts \
         (id, json, fingerprint, label, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![c.id, json, c.fingerprint, label, created_at, updated_at],
    )?;
    Ok(())
}

fn parse_contact(id: &str, json: &str) -> Result<SerializedMajikContact> {
    serde_json::from_str(json)
        .map_err(|e| ContactManagerError::Storage(format!("Malformed contact row \"{id}\": {e}")))
}

impl ContactRepo for SqliteContactRepo {
    fn save(&self, c: &SerializedMajikContact) -> Result<()> {
        let g = lock(&self.conn)?;
        upsert_contact(&g, c)
    }

    fn get_by_id(&self, id: &str) -> Result<Option<SerializedMajikContact>> {
        let g = lock(&self.conn)?;
        let row: Option<String> = g
            .query_row(
                "SELECT json FROM majik_contacts WHERE id = ?1",
                params![id],
                |r| r.get::<_, String>(0),
            )
            .optional()?;
        match row {
            Some(json) => Ok(Some(parse_contact(id, &json)?)),
            None => Ok(None),
        }
    }

    fn list(&self) -> Result<Vec<SerializedMajikContact>> {
        let g = lock(&self.conn)?;
        let mut stmt = g.prepare("SELECT id, json FROM majik_contacts ORDER BY rowid")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (id, json) = row?;
            out.push(parse_contact(&id, &json)?);
        }
        Ok(out)
    }

    fn remove(&self, id: &str) -> Result<bool> {
        let g = lock(&self.conn)?;
        Ok(g.execute("DELETE FROM majik_contacts WHERE id = ?1", params![id])? > 0)
    }

    fn clear(&self) -> Result<()> {
        lock(&self.conn)?.execute("DELETE FROM majik_contacts", [])?;
        Ok(())
    }

    fn count(&self) -> Result<usize> {
        let g = lock(&self.conn)?;
        let n: i64 = g.query_row("SELECT COUNT(*) FROM majik_contacts", [], |r| r.get(0))?;
        Ok(n as usize)
    }

    fn exists(&self, id: &str) -> Result<bool> {
        let g = lock(&self.conn)?;
        let found: Option<i64> = g
            .query_row(
                "SELECT 1 FROM majik_contacts WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    fn bulk_save(&self, contacts: &[SerializedMajikContact]) -> Result<()> {
        if contacts.is_empty() {
            return Ok(());
        }
        let mut g = lock(&self.conn)?;
        let tx = g.transaction()?;
        for c in contacts {
            upsert_contact(&tx, c)?;
        }
        tx.commit()?;
        Ok(())
    }

    fn bulk_remove(&self, ids: &[String]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let mut g = lock(&self.conn)?;
        let tx = g.transaction()?;
        for id in ids {
            tx.execute("DELETE FROM majik_contacts WHERE id = ?1", params![id])?;
        }
        tx.commit()?;
        Ok(())
    }
}

// ─── Groups ──────────────────────────────────────────────────────────────────

pub struct SqliteGroupRepo {
    conn: SharedConnection,
}

impl SqliteGroupRepo {
    pub fn new(conn: SharedConnection) -> Self {
        Self { conn }
    }
}

fn upsert_group(conn: &Connection, grp: &SerializedMajikContactGroup) -> Result<()> {
    let json = serde_json::to_string(grp)?;
    conn.execute(
        "INSERT OR REPLACE INTO majik_contact_groups \
         (id, json, name, created_at, updated_at, is_system) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            grp.id,
            json,
            grp.meta.name,
            grp.meta.created_at,
            grp.meta.updated_at,
            if grp.is_system { 1i64 } else { 0i64 }
        ],
    )?;
    Ok(())
}

fn parse_group(id: &str, json: &str) -> Result<SerializedMajikContactGroup> {
    serde_json::from_str(json)
        .map_err(|e| ContactManagerError::Storage(format!("Malformed group row \"{id}\": {e}")))
}

impl GroupRepo for SqliteGroupRepo {
    fn save(&self, grp: &SerializedMajikContactGroup) -> Result<()> {
        let g = lock(&self.conn)?;
        upsert_group(&g, grp)
    }

    fn get_by_id(&self, id: &str) -> Result<Option<SerializedMajikContactGroup>> {
        let g = lock(&self.conn)?;
        let row: Option<String> = g
            .query_row(
                "SELECT json FROM majik_contact_groups WHERE id = ?1",
                params![id],
                |r| r.get::<_, String>(0),
            )
            .optional()?;
        match row {
            Some(json) => Ok(Some(parse_group(id, &json)?)),
            None => Ok(None),
        }
    }

    fn list(&self) -> Result<Vec<SerializedMajikContactGroup>> {
        let g = lock(&self.conn)?;
        let mut stmt = g.prepare("SELECT id, json FROM majik_contact_groups ORDER BY rowid")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (id, json) = row?;
            out.push(parse_group(&id, &json)?);
        }
        Ok(out)
    }

    fn remove(&self, id: &str) -> Result<bool> {
        let g = lock(&self.conn)?;
        Ok(g.execute(
            "DELETE FROM majik_contact_groups WHERE id = ?1",
            params![id],
        )? > 0)
    }

    fn clear(&self) -> Result<()> {
        lock(&self.conn)?.execute("DELETE FROM majik_contact_groups", [])?;
        Ok(())
    }

    fn count(&self) -> Result<usize> {
        let g = lock(&self.conn)?;
        let n: i64 = g.query_row("SELECT COUNT(*) FROM majik_contact_groups", [], |r| {
            r.get(0)
        })?;
        Ok(n as usize)
    }

    fn exists(&self, id: &str) -> Result<bool> {
        let g = lock(&self.conn)?;
        let found: Option<i64> = g
            .query_row(
                "SELECT 1 FROM majik_contact_groups WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }

    fn bulk_save(&self, groups: &[SerializedMajikContactGroup]) -> Result<()> {
        if groups.is_empty() {
            return Ok(());
        }
        let mut g = lock(&self.conn)?;
        let tx = g.transaction()?;
        for grp in groups {
            upsert_group(&tx, grp)?;
        }
        tx.commit()?;
        Ok(())
    }

    fn bulk_remove(&self, ids: &[String]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let mut g = lock(&self.conn)?;
        let tx = g.transaction()?;
        for id in ids {
            tx.execute(
                "DELETE FROM majik_contact_groups WHERE id = ?1",
                params![id],
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}
