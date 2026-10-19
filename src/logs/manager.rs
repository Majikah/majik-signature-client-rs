//! Log manager with a read-through cache. Port of `BaseLogManager` (+ the two concrete managers).

use indexmap::IndexMap;

use super::repo::LogRepo;
use super::types::LogRecord;
use crate::error::{Result, SignatureClientError};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkippedLog {
    pub id: String,
    pub reason: String,
}

pub struct LogManager<T: LogRecord> {
    cache: IndexMap<String, T>,
    repo: Box<dyn LogRepo<T>>,
    entity_name: &'static str,
}

impl<T: LogRecord> LogManager<T> {
    pub fn new(repo: Box<dyn LogRepo<T>>, entity_name: &'static str) -> Self {
        Self {
            cache: IndexMap::new(),
            repo,
            entity_name,
        }
    }

    /// Reload every stored entry. Malformed entries are skipped and reported.
    pub fn hydrate(&mut self) -> Result<Vec<SkippedLog>> {
        self.cache.clear();
        let mut skipped = Vec::new();
        for entry in self.repo.list()? {
            self.cache_valid(entry, &mut skipped);
        }
        Ok(skipped)
    }

    /// Reload only one account's entries (the cache then holds just those).
    pub fn hydrate_for_fingerprint(&mut self, fingerprint: &str) -> Result<Vec<SkippedLog>> {
        self.cache.clear();
        let mut skipped = Vec::new();
        for entry in self.repo.list_by_fingerprint(fingerprint)? {
            self.cache_valid(entry, &mut skipped);
        }
        Ok(skipped)
    }

    fn cache_valid(&mut self, entry: T, skipped: &mut Vec<SkippedLog>) {
        match entry.validate() {
            Ok(()) => {
                self.cache.insert(entry.id().to_string(), entry);
            }
            Err(e) => skipped.push(SkippedLog {
                id: entry.id().to_string(),
                reason: e.to_string(),
            }),
        }
    }

    /// Persist, then cache.
    pub fn save(&mut self, entry: T) -> Result<()> {
        entry.validate()?;
        self.repo.save(&entry)?;
        self.cache.insert(entry.id().to_string(), entry);
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&T> {
        self.cache.get(id)
    }

    /// Cache first, then storage.
    pub fn load(&mut self, id: &str) -> Result<Option<&T>> {
        if !self.cache.contains_key(id) {
            match self.repo.get_by_id(id)? {
                Some(entry) => {
                    entry.validate()?;
                    self.cache.insert(entry.id().to_string(), entry);
                }
                None => return Ok(None),
            }
        }
        Ok(self.cache.get(id))
    }

    pub fn get_or_err(&mut self, id: &str) -> Result<&T> {
        let name = self.entity_name;
        self.load(id)?
            .ok_or_else(|| SignatureClientError::Log(format!("{name} not found: {id}")))
    }

    /// Cached entries in insertion order.
    pub fn list(&self) -> Vec<&T> {
        self.cache.values().collect()
    }

    pub fn list_by_fingerprint(&self, fingerprint: &str) -> Vec<&T> {
        self.cache
            .values()
            .filter(|e| e.fingerprint() == Some(fingerprint))
            .collect()
    }

    pub fn delete(&mut self, id: &str) -> Result<()> {
        self.repo.remove(id)?;
        self.cache.shift_remove(id);
        Ok(())
    }

    pub fn bulk_remove(&mut self, ids: &[String]) -> Result<()> {
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

    pub fn count(&self) -> Result<usize> {
        self.repo.count()
    }

    pub fn clear(&mut self) -> Result<()> {
        self.repo.clear()?;
        self.cache.clear();
        Ok(())
    }

    /// Every stored entry (not just the cache), e.g. for a backup.
    pub fn to_json(&self) -> Result<Vec<T>> {
        self.repo.list()
    }

    pub fn bulk_restore_from_json(&mut self, data: &[T]) -> Result<Vec<SkippedLog>> {
        self.repo.bulk_save(data)?;
        self.hydrate()
    }

    /// The oldest entries of `fingerprint` beyond `max`, by timestamp (oldest first).
    pub(crate) fn excess_ids(&self, fingerprint: &str, max: usize) -> Vec<String> {
        let mut logs = self.list_by_fingerprint(fingerprint);
        if logs.len() <= max {
            return Vec::new();
        }
        // Compare instants, not strings: ISO strings with and without fractional seconds do not
        // sort lexicographically.
        logs.sort_by_key(|l| {
            l.timestamp()
                .parse::<jiff::Timestamp>()
                .unwrap_or(jiff::Timestamp::MIN)
        });
        let excess = logs.len() - max;
        logs.iter()
            .take(excess)
            .map(|l| l.id().to_string())
            .collect()
    }
}
