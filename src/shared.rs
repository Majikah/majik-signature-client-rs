//! State shared between the signature client and the key client's hooks.
//!
//! The key client owns its hooks (`KeyClient<SigHooks>`), and those hooks must reach the contacts
//! and logs, which the signature client also uses. So both hold an `Arc<SigShared>`.
//!
//! **Lock order:** never call into the key client (which may run hooks that lock `contacts`)
//! while holding a guard from this struct. Take a guard, do the work, drop it, then continue.

use std::sync::{Mutex, MutexGuard};

use crate::contacts::ContactManager;
use crate::error::{Result, SignatureClientError};
use crate::logs::{
    CreateHistoryLog, CreateUserActivityLog, HistoryLog, LogManager, UserActivityLog,
};
use crate::prefs::UserAppPreferences;
use crate::stamps::StampManager;

/// Per-account cap on activity entries (TS `MAX_ACTIVITY_LOGS`).
pub const MAX_ACTIVITY_LOGS: usize = 5000;

pub struct SigShared {
    pub contacts: Mutex<ContactManager>,
    pub history: Mutex<LogManager<HistoryLog>>,
    pub activity: Mutex<LogManager<UserActivityLog>>,
    pub stamps: Mutex<StampManager>,
}

pub(crate) fn lock<T>(m: &Mutex<T>) -> Result<MutexGuard<'_, T>> {
    m.lock().map_err(|_| SignatureClientError::Poisoned)
}

impl SigShared {
    pub fn lock_contacts(&self) -> Result<MutexGuard<'_, ContactManager>> {
        lock(&self.contacts)
    }

    /// Create + persist an activity entry for `fingerprint`, then prune that account's oldest
    /// entries beyond [`MAX_ACTIVITY_LOGS`].
    pub fn record_activity(
        &self,
        fingerprint: Option<&str>,
        mut input: CreateUserActivityLog,
    ) -> Result<UserActivityLog> {
        input.fingerprint = fingerprint.map(str::to_string);
        let entry = UserActivityLog::create(input)?;
        let mut mgr = lock(&self.activity)?;
        mgr.save(entry.clone())?;
        if let Some(fp) = fingerprint {
            let excess = mgr.excess_ids(fp, MAX_ACTIVITY_LOGS);
            if !excess.is_empty() {
                mgr.bulk_remove(&excess)?;
            }
        }
        Ok(entry)
    }

    /// `Ok(None)` when history is disabled in the preferences. Prunes beyond `maxCount`
    /// (default 100; `0` = unlimited).
    pub fn record_history(
        &self,
        fingerprint: Option<&str>,
        mut input: CreateHistoryLog,
        prefs: &UserAppPreferences,
    ) -> Result<Option<HistoryLog>> {
        if !prefs.is_history_enabled() {
            return Ok(None);
        }
        input.fingerprint = fingerprint.map(str::to_string);
        let entry = HistoryLog::create(input)?;
        let mut mgr = lock(&self.history)?;
        mgr.save(entry.clone())?;
        let max = prefs.history_max_count() as usize;
        if let (Some(fp), true) = (fingerprint, max > 0) {
            let excess = mgr.excess_ids(fp, max);
            if !excess.is_empty() {
                mgr.bulk_remove(&excess)?;
            }
        }
        Ok(Some(entry))
    }
}
