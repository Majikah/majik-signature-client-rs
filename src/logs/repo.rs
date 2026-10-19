//! Log repositories (TS `HistoryLogStorageAdapter` / `UserActivityLogStorageAdapter`): one trait,
//! an in-memory implementation, and a SQLite implementation written once for both entry kinds.
//! Table and column layout matches the TS `history_logs` / `user_activity_logs` tables.

use std::sync::{Arc, Mutex, MutexGuard};

use rusqlite::types::Value as SqlValue;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension};
use serde::de::DeserializeOwned;
use serde::Serialize;

use super::types::{HistoryLog, LogRecord, UserActivityLog};
use crate::error::{Result, SignatureClientError};

pub type SharedConnection = Arc<Mutex<Connection>>;

pub trait LogRepo<T>: Send + Sync {
    fn save(&self, entry: &T) -> Result<()>;
    fn bulk_save(&self, entries: &[T]) -> Result<()>;
    fn get_by_id(&self, id: &str) -> Result<Option<T>>;
    /// Insertion (rowid) order.
    fn list(&self) -> Result<Vec<T>>;
    fn list_by_fingerprint(&self, fingerprint: &str) -> Result<Vec<T>>;
    fn remove(&self, id: &str) -> Result<bool>;
    fn bulk_remove(&self, ids: &[String]) -> Result<()>;
    fn clear(&self) -> Result<()>;
    fn count(&self) -> Result<usize>;
    fn exists(&self, id: &str) -> Result<bool>;
}

// ─── In-memory ───────────────────────────────────────────────────────────────

pub struct MemoryLogRepo<T> {
    rows: Mutex<Vec<T>>,
}

impl<T> Default for MemoryLogRepo<T> {
    fn default() -> Self {
        Self {
            rows: Mutex::new(Vec::new()),
        }
    }
}

impl<T> MemoryLogRepo<T> {
    pub fn new() -> Self {
        Self::default()
    }
}

fn mem_lock<T>(m: &Mutex<T>) -> Result<MutexGuard<'_, T>> {
    m.lock().map_err(|_| SignatureClientError::Poisoned)
}

impl<T: LogRecord> LogRepo<T> for MemoryLogRepo<T> {
    fn save(&self, entry: &T) -> Result<()> {
        let mut rows = mem_lock(&self.rows)?;
        rows.retain(|r| r.id() != entry.id());
        rows.push(entry.clone());
        Ok(())
    }
    fn bulk_save(&self, entries: &[T]) -> Result<()> {
        for e in entries {
            self.save(e)?;
        }
        Ok(())
    }
    fn get_by_id(&self, id: &str) -> Result<Option<T>> {
        Ok(mem_lock(&self.rows)?.iter().find(|r| r.id() == id).cloned())
    }
    fn list(&self) -> Result<Vec<T>> {
        Ok(mem_lock(&self.rows)?.clone())
    }
    fn list_by_fingerprint(&self, fingerprint: &str) -> Result<Vec<T>> {
        Ok(mem_lock(&self.rows)?
            .iter()
            .filter(|r| r.fingerprint() == Some(fingerprint))
            .cloned()
            .collect())
    }
    fn remove(&self, id: &str) -> Result<bool> {
        let mut rows = mem_lock(&self.rows)?;
        let before = rows.len();
        rows.retain(|r| r.id() != id);
        Ok(rows.len() != before)
    }
    fn bulk_remove(&self, ids: &[String]) -> Result<()> {
        let mut rows = mem_lock(&self.rows)?;
        rows.retain(|r| !ids.iter().any(|i| i == r.id()));
        Ok(())
    }
    fn clear(&self) -> Result<()> {
        mem_lock(&self.rows)?.clear();
        Ok(())
    }
    fn count(&self) -> Result<usize> {
        Ok(mem_lock(&self.rows)?.len())
    }
    fn exists(&self, id: &str) -> Result<bool> {
        Ok(mem_lock(&self.rows)?.iter().any(|r| r.id() == id))
    }
}

// ─── SQLite ──────────────────────────────────────────────────────────────────

pub const TABLE_HISTORY_LOGS: &str = "history_logs";
pub const TABLE_USER_ACTIVITY_LOGS: &str = "user_activity_logs";

pub const SCHEMA_HISTORY_LOGS: &str = "
CREATE TABLE IF NOT EXISTS history_logs (
  id TEXT PRIMARY KEY,
  json TEXT NOT NULL,
  reference_id TEXT NOT NULL,
  type TEXT NOT NULL,
  fingerprint TEXT,
  version INTEGER NOT NULL,
  timestamp TEXT NOT NULL,
  historyType TEXT NOT NULL,
  status TEXT NOT NULL,
  source TEXT NOT NULL,
  network TEXT,
  transactionId TEXT
);

CREATE INDEX IF NOT EXISTS idx_history_logs_reference_id ON history_logs(reference_id);
CREATE INDEX IF NOT EXISTS idx_history_logs_fingerprint ON history_logs(fingerprint);
CREATE INDEX IF NOT EXISTS idx_history_logs_history_type ON history_logs(historyType);
CREATE INDEX IF NOT EXISTS idx_history_logs_status ON history_logs(status);
CREATE INDEX IF NOT EXISTS idx_history_logs_timestamp ON history_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_history_logs_fingerprint_history_type ON history_logs(fingerprint, historyType);
";

pub const SCHEMA_USER_ACTIVITY_LOGS: &str = "
CREATE TABLE IF NOT EXISTS user_activity_logs (
  id TEXT PRIMARY KEY,
  json TEXT NOT NULL,
  reference_id TEXT NOT NULL,
  type TEXT NOT NULL,
  fingerprint TEXT,
  version INTEGER NOT NULL,
  timestamp TEXT NOT NULL,
  action TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_user_activity_logs_reference_id ON user_activity_logs(reference_id);
CREATE INDEX IF NOT EXISTS idx_user_activity_logs_fingerprint ON user_activity_logs(fingerprint);
CREATE INDEX IF NOT EXISTS idx_user_activity_logs_action ON user_activity_logs(action);
CREATE INDEX IF NOT EXISTS idx_user_activity_logs_timestamp ON user_activity_logs(timestamp);
";

/// Idempotent. Creates both log tables if missing.
pub fn init_log_schema(conn: &SharedConnection) -> Result<()> {
    let guard = lock(conn)?;
    guard.execute_batch(SCHEMA_HISTORY_LOGS)?;
    guard.execute_batch(SCHEMA_USER_ACTIVITY_LOGS)?;
    Ok(())
}

fn lock(conn: &SharedConnection) -> Result<MutexGuard<'_, Connection>> {
    conn.lock().map_err(|_| SignatureClientError::Poisoned)
}

/// How an entry kind maps onto its SQL table: the seven shared columns plus per-kind extras.
pub trait LogRow: LogRecord + Serialize + DeserializeOwned {
    const TABLE: &'static str;
    const EXTRA_COLUMNS: &'static [&'static str];
    fn reference_id(&self) -> &str;
    fn log_type(&self) -> &str;
    fn version(&self) -> u32;
    fn extra_values(&self) -> Vec<SqlValue>;
}

fn enum_text<T: Serialize>(v: &T) -> SqlValue {
    match serde_json::to_value(v) {
        Ok(serde_json::Value::String(s)) => SqlValue::Text(s),
        _ => SqlValue::Null,
    }
}

fn opt_text(v: &Option<String>) -> SqlValue {
    match v {
        Some(s) => SqlValue::Text(s.clone()),
        None => SqlValue::Null,
    }
}

impl LogRow for HistoryLog {
    const TABLE: &'static str = TABLE_HISTORY_LOGS;
    const EXTRA_COLUMNS: &'static [&'static str] =
        &["historyType", "status", "source", "network", "transactionId"];
    fn reference_id(&self) -> &str {
        &self.reference_id
    }
    fn log_type(&self) -> &str {
        &self.log_type
    }
    fn version(&self) -> u32 {
        self.version
    }
    fn extra_values(&self) -> Vec<SqlValue> {
        vec![
            enum_text(&self.history_type),
            enum_text(&self.status),
            enum_text(&self.source),
            match &self.network {
                Some(n) => enum_text(n),
                None => SqlValue::Null,
            },
            opt_text(&self.transaction_id),
        ]
    }
}

impl LogRow for UserActivityLog {
    const TABLE: &'static str = TABLE_USER_ACTIVITY_LOGS;
    const EXTRA_COLUMNS: &'static [&'static str] = &["action"];
    fn reference_id(&self) -> &str {
        &self.reference_id
    }
    fn log_type(&self) -> &str {
        &self.log_type
    }
    fn version(&self) -> u32 {
        self.version
    }
    fn extra_values(&self) -> Vec<SqlValue> {
        vec![enum_text(&self.action)]
    }
}

pub struct SqliteLogRepo<T: LogRow> {
    conn: SharedConnection,
    insert_sql: String,
    _marker: std::marker::PhantomData<fn() -> T>,
}

impl<T: LogRow> SqliteLogRepo<T> {
    pub fn new(conn: SharedConnection) -> Self {
        let mut columns: Vec<&str> =
            vec!["id", "json", "reference_id", "type", "fingerprint", "version", "timestamp"];
        columns.extend(T::EXTRA_COLUMNS.iter().copied());
        let placeholders: Vec<String> = (1..=columns.len()).map(|i| format!("?{i}")).collect();
        // Table and column names are compile-time constants of the `LogRow` impls.
        let insert_sql = format!(
            "INSERT OR REPLACE INTO {} ({}) VALUES ({})",
            T::TABLE,
            columns.join(", "),
            placeholders.join(", ")
        );
        Self {
            conn,
            insert_sql,
            _marker: std::marker::PhantomData,
        }
    }

    fn upsert(&self, conn: &Connection, entry: &T) -> Result<()> {
        let mut values: Vec<SqlValue> = vec![
            SqlValue::Text(entry.id().to_string()),
            SqlValue::Text(serde_json::to_string(entry)?),
            SqlValue::Text(entry.reference_id().to_string()),
            SqlValue::Text(entry.log_type().to_string()),
            match entry.fingerprint() {
                Some(f) => SqlValue::Text(f.to_string()),
                None => SqlValue::Null,
            },
            SqlValue::Integer(entry.version() as i64),
            SqlValue::Text(entry.timestamp().to_string()),
        ];
        values.extend(entry.extra_values());
        conn.execute(&self.insert_sql, params_from_iter(values))?;
        Ok(())
    }
}

fn parse_row<T: DeserializeOwned>(id: &str, json: &str) -> Result<T> {
    serde_json::from_str(json)
        .map_err(|e| SignatureClientError::Storage(format!("Malformed log row \"{id}\": {e}")))
}

impl<T: LogRow> LogRepo<T> for SqliteLogRepo<T> {
    fn save(&self, entry: &T) -> Result<()> {
        let g = lock(&self.conn)?;
        self.upsert(&g, entry)
    }

    fn bulk_save(&self, entries: &[T]) -> Result<()> {
        if entries.is_empty() {
            return Ok(());
        }
        let mut g = lock(&self.conn)?;
        let tx = g.transaction()?;
        for e in entries {
            self.upsert(&tx, e)?;
        }
        tx.commit()?;
        Ok(())
    }

    fn get_by_id(&self, id: &str) -> Result<Option<T>> {
        let g = lock(&self.conn)?;
        let sql = format!("SELECT json FROM {} WHERE id = ?1", T::TABLE);
        let row: Option<String> = g
            .query_row(&sql, params![id], |r| r.get::<_, String>(0))
            .optional()?;
        match row {
            Some(json) => Ok(Some(parse_row(id, &json)?)),
            None => Ok(None),
        }
    }

    fn list(&self) -> Result<Vec<T>> {
        let g = lock(&self.conn)?;
        let sql = format!("SELECT id, json FROM {} ORDER BY rowid", T::TABLE);
        let mut stmt = g.prepare(&sql)?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (id, json) = row?;
            out.push(parse_row(&id, &json)?);
        }
        Ok(out)
    }

    fn list_by_fingerprint(&self, fingerprint: &str) -> Result<Vec<T>> {
        let g = lock(&self.conn)?;
        let sql = format!(
            "SELECT id, json FROM {} WHERE fingerprint = ?1 ORDER BY rowid",
            T::TABLE
        );
        let mut stmt = g.prepare(&sql)?;
        let rows = stmt.query_map(params![fingerprint], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (id, json) = row?;
            out.push(parse_row(&id, &json)?);
        }
        Ok(out)
    }

    fn remove(&self, id: &str) -> Result<bool> {
        let g = lock(&self.conn)?;
        let sql = format!("DELETE FROM {} WHERE id = ?1", T::TABLE);
        Ok(g.execute(&sql, params![id])? > 0)
    }

    fn bulk_remove(&self, ids: &[String]) -> Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let mut g = lock(&self.conn)?;
        let tx = g.transaction()?;
        let sql = format!("DELETE FROM {} WHERE id = ?1", T::TABLE);
        for id in ids {
            tx.execute(&sql, params![id])?;
        }
        tx.commit()?;
        Ok(())
    }

    fn clear(&self) -> Result<()> {
        let g = lock(&self.conn)?;
        g.execute(&format!("DELETE FROM {}", T::TABLE), [])?;
        Ok(())
    }

    fn count(&self) -> Result<usize> {
        let g = lock(&self.conn)?;
        let n: i64 = g.query_row(&format!("SELECT COUNT(*) FROM {}", T::TABLE), [], |r| r.get(0))?;
        Ok(n as usize)
    }

    fn exists(&self, id: &str) -> Result<bool> {
        let g = lock(&self.conn)?;
        let sql = format!("SELECT 1 FROM {} WHERE id = ?1", T::TABLE);
        let found: Option<i64> = g.query_row(&sql, params![id], |r| r.get(0)).optional()?;
        Ok(found.is_some())
    }
}
