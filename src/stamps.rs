//! Signature stamps: images/audio/video/text assets encrypted to the owner's ML-KEM key as
//! `MajikFile` envelopes. Port of `MajikSignatureStamp` + `MajikSignatureStampManager` + the
//! stamp storage adapters. Same `majik_signature_stamps` table as the TS SQL adapter.
//!
//! Plaintext only ever exists in `decrypted` (zeroized on lock/drop); what is persisted is the
//! `.mjkb` binary, base64 encoded.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use indexmap::IndexMap;
use majik_file::{
    array_to_base64, base64_to_array, MajikFile, MajikFileCreateOptions, MajikFileDecryptIdentity,
    MajikFileIdentity, MajikFileJson,
};
use majik_key::MajikKey;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Result, SignatureClientError};
use crate::file_identity::identity_from_key;
use crate::logs::types::now_iso;

pub type SharedConnection = Arc<Mutex<Connection>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StampAssetKind {
    Image,
    Audio,
    Video,
    Text,
}

impl StampAssetKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Image => "image",
            Self::Audio => "audio",
            Self::Video => "video",
            Self::Text => "text",
        }
    }
}

/// Persisted / wire form (TS `MajikSignatureStampJSON`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StampJson {
    pub id: String,
    pub kind: StampAssetKind,
    pub name: String,
    pub mime_type: Option<String>,
    /// Plaintext size, before encryption.
    pub size_bytes: u64,
    /// Fingerprint of the key that can decrypt this stamp.
    pub fingerprint: String,
    /// Base64 `.mjkb` binary.
    pub data: String,
    pub timestamp: String,
    pub last_update: String,
    pub file_json: MajikFileJson,
}

/// Everything about a stamp except its content: safe for events and lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StampMeta {
    pub id: String,
    pub kind: StampAssetKind,
    pub name: String,
    pub mime_type: Option<String>,
    pub size_bytes: u64,
    pub fingerprint: String,
    pub timestamp: String,
    pub last_update: String,
}

pub struct CreateStamp<'a> {
    pub data: Vec<u8>,
    pub identity: &'a MajikFileIdentity,
    pub kind: StampAssetKind,
    pub name: String,
    pub mime_type: Option<String>,
    pub id: Option<String>,
}

#[derive(Clone)]
pub struct MajikSignatureStamp {
    id: String,
    kind: StampAssetKind,
    name: String,
    mime_type: Option<String>,
    size_bytes: u64,
    fingerprint: String,
    timestamp: String,
    last_update: String,
    file_json: MajikFileJson,
    encrypted: Vec<u8>,
    decrypted: Option<Zeroizing<Vec<u8>>>,
}

impl std::fmt::Debug for MajikSignatureStamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MajikSignatureStamp")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("name", &self.name)
            .field("fingerprint", &self.fingerprint)
            .field("decrypted", &self.decrypted.is_some())
            .finish()
    }
}

impl MajikSignatureStamp {
    pub fn create(options: CreateStamp<'_>) -> Result<Self> {
        if options.data.is_empty() {
            return Err(SignatureClientError::Invalid(
                "MajikSignatureStamp.create: data is required".into(),
            ));
        }
        let name = options.name.trim().to_string();
        if name.is_empty() {
            return Err(SignatureClientError::Invalid(
                "MajikSignatureStamp.create: name is required".into(),
            ));
        }
        let identity = options.identity;
        let mut file_options = MajikFileCreateOptions::new(
            options.data,
            identity.fingerprint.clone(),
            identity.clone(),
        );
        file_options.original_name = Some(name.clone());
        file_options.mime_type = options.mime_type;
        file_options.id = options.id;
        let file = MajikFile::create(file_options)?;
        let file_json = file.to_json()?;
        let encrypted = file.to_binary_bytes()?.to_vec();
        let now = now_iso();
        Ok(Self {
            id: file_json.id.clone(),
            kind: options.kind,
            name,
            mime_type: file_json.mime_type.clone(),
            size_bytes: file_json.size_original,
            fingerprint: identity.fingerprint.clone(),
            timestamp: file_json.timestamp.clone().unwrap_or_else(|| now.clone()),
            last_update: file_json.last_update.clone().unwrap_or(now),
            file_json,
            encrypted,
            decrypted: None,
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn kind(&self) -> StampAssetKind {
        self.kind
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn mime_type(&self) -> Option<&str> {
        self.mime_type.as_deref()
    }
    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
    pub fn timestamp(&self) -> &str {
        &self.timestamp
    }
    pub fn last_update(&self) -> &str {
        &self.last_update
    }

    pub fn meta(&self) -> StampMeta {
        StampMeta {
            id: self.id.clone(),
            kind: self.kind,
            name: self.name.clone(),
            mime_type: self.mime_type.clone(),
            size_bytes: self.size_bytes,
            fingerprint: self.fingerprint.clone(),
            timestamp: self.timestamp.clone(),
            last_update: self.last_update.clone(),
        }
    }

    pub fn rename(&mut self, new_name: &str) -> Result<()> {
        let trimmed = new_name.trim();
        if trimmed.is_empty() {
            return Err(SignatureClientError::Invalid(
                "rename: name must be non-empty".into(),
            ));
        }
        self.name = trimmed.to_string();
        self.last_update = now_iso();
        Ok(())
    }

    pub fn to_json(&self) -> StampJson {
        StampJson {
            id: self.id.clone(),
            kind: self.kind,
            name: self.name.clone(),
            mime_type: self.mime_type.clone(),
            size_bytes: self.size_bytes,
            fingerprint: self.fingerprint.clone(),
            data: array_to_base64(&self.encrypted),
            timestamp: self.timestamp.clone(),
            last_update: self.last_update.clone(),
            file_json: self.file_json.clone(),
        }
    }

    pub fn from_json(json: StampJson) -> Result<Self> {
        if json.id.is_empty() || json.fingerprint.is_empty() {
            return Err(SignatureClientError::Invalid(
                "stamp JSON is missing its id or fingerprint".into(),
            ));
        }
        Ok(Self {
            encrypted: base64_to_array(&json.data)?,
            id: json.id,
            kind: json.kind,
            name: json.name,
            mime_type: json.mime_type,
            size_bytes: json.size_bytes,
            fingerprint: json.fingerprint,
            timestamp: json.timestamp,
            last_update: json.last_update,
            file_json: json.file_json,
            decrypted: None,
        })
    }

    /// Decrypt without caching the plaintext on the stamp.
    pub fn decrypt_content<'a>(
        &self,
        identity: impl Into<MajikFileDecryptIdentity<'a>>,
    ) -> Result<Vec<u8>> {
        Ok(MajikFile::decrypt(&self.encrypted, identity, None)?)
    }

    /// Decrypt and keep the plaintext in memory until `lock()` (TS `decryptHydrate`).
    pub fn decrypt_hydrate<'a>(
        &mut self,
        identity: impl Into<MajikFileDecryptIdentity<'a>>,
    ) -> Result<()> {
        let bytes = MajikFile::decrypt(&self.encrypted, identity, None)?;
        self.decrypted = Some(Zeroizing::new(bytes));
        Ok(())
    }

    pub fn decrypted_bytes(&self) -> Option<&[u8]> {
        self.decrypted.as_deref().map(|v| v.as_slice())
    }

    /// Wipe the cached plaintext. Returns whether there was any.
    pub fn lock(&mut self) -> bool {
        self.decrypted.take().is_some()
    }
}

// ─── Storage ─────────────────────────────────────────────────────────────────

pub trait StampRepo: Send + Sync {
    fn save(&self, stamp: &StampJson) -> Result<()>;
    fn bulk_save(&self, stamps: &[StampJson]) -> Result<()>;
    fn get_by_id(&self, id: &str) -> Result<Option<StampJson>>;
    fn list(&self) -> Result<Vec<StampJson>>;
    fn list_by_fingerprint(&self, fingerprint: &str) -> Result<Vec<StampJson>>;
    fn remove(&self, id: &str) -> Result<bool>;
    fn bulk_remove(&self, ids: &[String]) -> Result<()>;
    fn clear(&self) -> Result<()>;
    fn count(&self) -> Result<usize>;
    fn exists(&self, id: &str) -> Result<bool>;
}

fn poisoned<T>(_: std::sync::PoisonError<T>) -> SignatureClientError {
    SignatureClientError::Poisoned
}

#[derive(Default)]
pub struct MemoryStampRepo {
    rows: Mutex<Vec<StampJson>>,
}

impl MemoryStampRepo {
    pub fn new() -> Self {
        Self::default()
    }
}

impl StampRepo for MemoryStampRepo {
    fn save(&self, stamp: &StampJson) -> Result<()> {
        let mut rows = self.rows.lock().map_err(poisoned)?;
        rows.retain(|r| r.id != stamp.id);
        rows.push(stamp.clone());
        Ok(())
    }
    fn bulk_save(&self, stamps: &[StampJson]) -> Result<()> {
        for s in stamps {
            self.save(s)?;
        }
        Ok(())
    }
    fn get_by_id(&self, id: &str) -> Result<Option<StampJson>> {
        Ok(self.rows.lock().map_err(poisoned)?.iter().find(|r| r.id == id).cloned())
    }
    fn list(&self) -> Result<Vec<StampJson>> {
        Ok(self.rows.lock().map_err(poisoned)?.clone())
    }
    fn list_by_fingerprint(&self, fingerprint: &str) -> Result<Vec<StampJson>> {
        Ok(self
            .rows
            .lock()
            .map_err(poisoned)?
            .iter()
            .filter(|r| r.fingerprint == fingerprint)
            .cloned()
            .collect())
    }
    fn remove(&self, id: &str) -> Result<bool> {
        let mut rows = self.rows.lock().map_err(poisoned)?;
        let before = rows.len();
        rows.retain(|r| r.id != id);
        Ok(rows.len() != before)
    }
    fn bulk_remove(&self, ids: &[String]) -> Result<()> {
        let mut rows = self.rows.lock().map_err(poisoned)?;
        rows.retain(|r| !ids.contains(&r.id));
        Ok(())
    }
    fn clear(&self) -> Result<()> {
        self.rows.lock().map_err(poisoned)?.clear();
        Ok(())
    }
    fn count(&self) -> Result<usize> {
        Ok(self.rows.lock().map_err(poisoned)?.len())
    }
    fn exists(&self, id: &str) -> Result<bool> {
        Ok(self.rows.lock().map_err(poisoned)?.iter().any(|r| r.id == id))
    }
}

pub const TABLE_STAMPS: &str = "majik_signature_stamps";

pub const SCHEMA_STAMPS: &str = "
CREATE TABLE IF NOT EXISTS majik_signature_stamps (
  id TEXT PRIMARY KEY,
  json TEXT NOT NULL,
  kind TEXT NOT NULL,
  name TEXT NOT NULL,
  mime_type TEXT,
  size_bytes INTEGER NOT NULL,
  fingerprint TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_majik_signature_stamps_kind
ON majik_signature_stamps(kind);

CREATE INDEX IF NOT EXISTS idx_majik_signature_stamps_fingerprint
ON majik_signature_stamps(fingerprint);

CREATE INDEX IF NOT EXISTS idx_majik_signature_stamps_updated_at
ON majik_signature_stamps(updated_at);
";

pub fn init_stamp_schema(conn: &SharedConnection) -> Result<()> {
    let guard = conn.lock().map_err(poisoned)?;
    guard.execute_batch(SCHEMA_STAMPS)?;
    Ok(())
}

pub struct SqliteStampRepo {
    conn: SharedConnection,
}

impl SqliteStampRepo {
    pub fn new(conn: SharedConnection) -> Self {
        Self { conn }
    }
    fn lock(&self) -> Result<MutexGuard<'_, Connection>> {
        self.conn.lock().map_err(poisoned)
    }
}

fn upsert_stamp(conn: &Connection, s: &StampJson) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO majik_signature_stamps \
         (id, json, kind, name, mime_type, size_bytes, fingerprint, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            s.id,
            serde_json::to_string(s)?,
            s.kind.as_str(),
            s.name,
            s.mime_type,
            s.size_bytes as i64,
            s.fingerprint,
            s.timestamp,
            s.last_update
        ],
    )?;
    Ok(())
}

fn parse_stamp(id: &str, json: &str) -> Result<StampJson> {
    serde_json::from_str(json)
        .map_err(|e| SignatureClientError::Storage(format!("Malformed stamp row \"{id}\": {e}")))
}

impl StampRepo for SqliteStampRepo {
    fn save(&self, stamp: &StampJson) -> Result<()> {
        upsert_stamp(&*self.lock()?, stamp)
    }

    fn bulk_save(&self, stamps: &[StampJson]) -> Result<()> {
        if stamps.is_empty() {
            return Ok(());
        }
        let mut g = self.lock()?;
        let tx = g.transaction()?;
        for s in stamps {
            upsert_stamp(&tx, s)?;
        }
        tx.commit()?;
        Ok(())
    }

    fn get_by_id(&self, id: &str) -> Result<Option<StampJson>> {
        let g = self.lock()?;
        let row: Option<String> = g
            .query_row(
                "SELECT json FROM majik_signature_stamps WHERE id = ?1",
                params![id],
                |r| r.get::<_, String>(0),
            )
            .optional()?;
        match row {
            Some(json) => Ok(Some(parse_stamp(id, &json)?)),
            None => Ok(None),
        }
    }

    fn list(&self) -> Result<Vec<StampJson>> {
        let g = self.lock()?;
        let mut stmt = g.prepare("SELECT id, json FROM majik_signature_stamps ORDER BY rowid")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (id, json) = row?;
            out.push(parse_stamp(&id, &json)?);
        }
        Ok(out)
    }

    fn list_by_fingerprint(&self, fingerprint: &str) -> Result<Vec<StampJson>> {
        let g = self.lock()?;
        let mut stmt = g.prepare(
            "SELECT id, json FROM majik_signature_stamps WHERE fingerprint = ?1 ORDER BY rowid",
        )?;
        let rows = stmt.query_map(params![fingerprint], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, json) = row?;
            out.push(parse_stamp(&id, &json)?);
        }
        Ok(out)
    }

    fn remove(&self, id: &str) -> Result<bool> {
        Ok(self
            .lock()?
            .execute("DELETE FROM majik_signature_stamps WHERE id = ?1", params![id])?
            > 0)
    }

    fn bulk_remove(&self, ids: &[String]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let mut g = self.lock()?;
        let tx = g.transaction()?;
        for id in ids {
            tx.execute("DELETE FROM majik_signature_stamps WHERE id = ?1", params![id])?;
        }
        tx.commit()?;
        Ok(())
    }

    fn clear(&self) -> Result<()> {
        self.lock()?.execute("DELETE FROM majik_signature_stamps", [])?;
        Ok(())
    }

    fn count(&self) -> Result<usize> {
        let n: i64 = self
            .lock()?
            .query_row("SELECT COUNT(*) FROM majik_signature_stamps", [], |r| r.get(0))?;
        Ok(n as usize)
    }

    fn exists(&self, id: &str) -> Result<bool> {
        let found: Option<i64> = self
            .lock()?
            .query_row(
                "SELECT 1 FROM majik_signature_stamps WHERE id = ?1",
                params![id],
                |r| r.get(0),
            )
            .optional()?;
        Ok(found.is_some())
    }
}

// ─── Manager ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkippedStamp {
    pub id: String,
    pub reason: String,
}

pub struct StampManager {
    cache: IndexMap<String, MajikSignatureStamp>,
    decrypt_errors: HashMap<String, String>,
    repo: Box<dyn StampRepo>,
}

impl StampManager {
    pub fn new(repo: Box<dyn StampRepo>) -> Self {
        Self {
            cache: IndexMap::new(),
            decrypt_errors: HashMap::new(),
            repo,
        }
    }

    pub fn in_memory() -> Self {
        Self::new(Box::new(MemoryStampRepo::new()))
    }

    fn cache_rows(&mut self, rows: Vec<StampJson>) -> Vec<SkippedStamp> {
        let mut skipped = Vec::new();
        for json in rows {
            let id = json.id.clone();
            match MajikSignatureStamp::from_json(json) {
                Ok(stamp) => {
                    self.cache.insert(stamp.id.clone(), stamp);
                }
                Err(e) => skipped.push(SkippedStamp {
                    id,
                    reason: e.to_string(),
                }),
            }
        }
        skipped
    }

    pub fn hydrate(&mut self) -> Result<Vec<SkippedStamp>> {
        self.cache.clear();
        let rows = self.repo.list()?;
        Ok(self.cache_rows(rows))
    }

    /// Load one account's stamps. With `key` (which must be unlocked) each stamp is also
    /// decrypted into memory; stamps that fail to decrypt are left out of the cache and their
    /// reason is available from [`decrypt_error`](Self::decrypt_error).
    pub fn hydrate_for_fingerprint(
        &mut self,
        fingerprint: &str,
        key: Option<&MajikKey>,
    ) -> Result<Vec<SkippedStamp>> {
        self.cache.clear();
        self.decrypt_errors.clear();
        let rows = self.repo.list_by_fingerprint(fingerprint)?;
        let mut parsed = IndexMap::new();
        let mut skipped = Vec::new();
        for json in rows {
            let id = json.id.clone();
            match MajikSignatureStamp::from_json(json) {
                Ok(s) => {
                    parsed.insert(s.id.clone(), s);
                }
                Err(e) => skipped.push(SkippedStamp {
                    id,
                    reason: e.to_string(),
                }),
            }
        }
        let Some(key) = key else {
            self.cache = parsed;
            return Ok(skipped);
        };
        let identity = identity_from_key(key)?;
        for (id, mut stamp) in parsed {
            match stamp.decrypt_hydrate(&identity) {
                Ok(()) => {
                    self.cache.insert(id, stamp);
                }
                Err(e) => {
                    self.decrypt_errors.insert(id, e.to_string());
                }
            }
        }
        Ok(skipped)
    }

    pub fn decrypt_error(&self, id: &str) -> Option<&str> {
        self.decrypt_errors.get(id).map(String::as_str)
    }

    /// Wipe every cached plaintext. Returns how many stamps had one.
    pub fn lock_all(&mut self) -> usize {
        self.cache.values_mut().map(|s| s.lock()).filter(|b| *b).count()
    }

    pub fn to_json(&self) -> Result<Vec<StampJson>> {
        self.repo.list()
    }

    pub fn bulk_restore_from_json(&mut self, data: &[StampJson]) -> Result<Vec<SkippedStamp>> {
        self.repo.bulk_save(data)?;
        self.hydrate()
    }

    pub fn create(&mut self, options: CreateStamp<'_>) -> Result<MajikSignatureStamp> {
        let stamp = MajikSignatureStamp::create(options)?;
        self.repo.save(&stamp.to_json())?;
        self.cache.insert(stamp.id.clone(), stamp.clone());
        Ok(stamp)
    }

    pub fn save(&mut self, stamp: MajikSignatureStamp) -> Result<()> {
        self.repo.save(&stamp.to_json())?;
        self.cache.insert(stamp.id.clone(), stamp);
        Ok(())
    }

    pub fn load(&mut self, id: &str) -> Result<Option<&MajikSignatureStamp>> {
        if !self.cache.contains_key(id) {
            match self.repo.get_by_id(id)? {
                Some(json) => {
                    let stamp = MajikSignatureStamp::from_json(json)?;
                    self.cache.insert(stamp.id.clone(), stamp);
                }
                None => return Ok(None),
            }
        }
        Ok(self.cache.get(id))
    }

    fn require(&mut self, id: &str) -> Result<&mut MajikSignatureStamp> {
        self.load(id)?;
        self.cache
            .get_mut(id)
            .ok_or_else(|| SignatureClientError::Invalid(format!("Stamp not found: {id}")))
    }

    pub fn get_or_err(&mut self, id: &str) -> Result<&MajikSignatureStamp> {
        Ok(self.require(id)?)
    }

    pub fn get(&self, id: &str) -> Option<&MajikSignatureStamp> {
        self.cache.get(id)
    }

    pub fn load_all(&mut self) -> Result<Vec<&MajikSignatureStamp>> {
        for json in self.repo.list()? {
            if !self.cache.contains_key(&json.id) {
                if let Ok(stamp) = MajikSignatureStamp::from_json(json) {
                    self.cache.insert(stamp.id.clone(), stamp);
                }
            }
        }
        Ok(self.cache.values().collect())
    }

    pub fn delete(&mut self, id: &str) -> Result<()> {
        self.repo.remove(id)?;
        self.cache.shift_remove(id);
        Ok(())
    }

    pub fn bulk_remove(&mut self, ids: &[String]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        self.repo.bulk_remove(ids)?;
        for id in ids {
            self.cache.shift_remove(id.as_str());
        }
        Ok(())
    }

    pub fn has(&self, id: &str) -> Result<bool> {
        if self.cache.contains_key(id) {
            return Ok(true);
        }
        self.repo.exists(id)
    }

    pub fn list(&self) -> Vec<&MajikSignatureStamp> {
        self.cache.values().collect()
    }

    pub fn list_by_kind(&self, kind: StampAssetKind) -> Vec<&MajikSignatureStamp> {
        self.cache.values().filter(|s| s.kind == kind).collect()
    }

    pub fn list_by_fingerprint(&self, fingerprint: &str) -> Vec<&MajikSignatureStamp> {
        self.cache
            .values()
            .filter(|s| s.fingerprint == fingerprint)
            .collect()
    }

    pub fn rename(&mut self, id: &str, new_name: &str) -> Result<MajikSignatureStamp> {
        let stamp = self.require(id)?;
        stamp.rename(new_name)?;
        let json = stamp.to_json();
        let updated = stamp.clone();
        self.repo.save(&json)?;
        Ok(updated)
    }

    /// Re-encrypt `data` under `identity`, keeping the stamp's id, kind and name.
    pub fn replace_content(
        &mut self,
        id: &str,
        data: Vec<u8>,
        identity: &MajikFileIdentity,
        mime_type: Option<String>,
    ) -> Result<MajikSignatureStamp> {
        let existing = self.require(id)?;
        let replacement = MajikSignatureStamp::create(CreateStamp {
            data,
            identity,
            kind: existing.kind,
            name: existing.name.clone(),
            mime_type: mime_type.or_else(|| existing.mime_type.clone()),
            id: Some(existing.id.clone()),
        })?;
        self.repo.save(&replacement.to_json())?;
        self.cache.insert(replacement.id.clone(), replacement.clone());
        Ok(replacement)
    }

    pub fn decrypt_content(&mut self, id: &str, identity: &MajikFileIdentity) -> Result<Vec<u8>> {
        self.require(id)?.decrypt_content(identity)
    }

    pub fn clear(&mut self) -> Result<()> {
        self.repo.clear()?;
        self.cache.clear();
        self.decrypt_errors.clear();
        Ok(())
    }
}
