//! `SignatureClient`: the Rust port of `MajikSignatureClient` (foundation slice).
//!
//! Rust has no inheritance, so the TS `extends MajikKeyClient` becomes composition: the client
//! OWNS a `KeyClient<SigHooks>` (reachable through [`keys`](SignatureClient::keys) /
//! [`keys_mut`](SignatureClient::keys_mut)) and the contacts, logs and preferences around it.
//!
//! This slice covers: construction and hydration, own-account <-> contact sync, user app
//! preferences, history/activity logs, and the contact + group API with its events and audit
//! entries. Signing, stamps, backups and the signing session arrive in later slices.
//!
//! Behaviour changes versus the TS client (all deliberate):
//!  * `clear_directory` re-adds the own accounts' contacts afterwards, so the invariant "every own
//!    account has a contact" survives it (TS left the directory empty).
//!  * Preferences keep the TS tri-state semantics (absent / false / true) exactly, but are read
//!    with `&mut self` because the state store is a read-through cache.
//!  * Failures while recording a log never fail the operation (as in TS) but are surfaced as an
//!    `error` event instead of a `console.warn`.

use std::sync::{Arc, Mutex};

use crate::contacts::majik_contact::{
    MajikApiResponse, MajikContact, MajikContactGroup, MajikContactMeta,
    PartialMajikContactGroupMeta, SerializedMajikContactGroup, SYSTEM_GROUP_ID_FAVORITES,
};
use crate::contacts::{codec, ContactManager};
use majik_key_client::{
    ClientEvent, ClientStateRepo, HydrateReport as KeyHydrateReport, KeyClient, KeystoreRepo,
};
use serde::Serialize;
use serde_json::json;

use crate::bus::{Bus, Listener, ListenerId};
use crate::error::{Result, SignatureClientError};
use crate::events::{SigEvent, SigOnlyEvent};
use crate::hooks::SigHooks;
use crate::logs::{
    init_log_schema, AuditAction, CreateHistoryLog, CreateUserActivityLog, HistoryLog, LogManager,
    MemoryLogRepo, SkippedLog, SqliteLogRepo, UserActivityLog,
};
use crate::logs::repo::SharedConnection;
use crate::prefs::{self, UserAppPreferences};
use crate::shared::{lock, SigShared};
use crate::stamps::{
    init_stamp_schema, SkippedStamp, SqliteStampRepo, StampManager,
};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HydrateReport {
    pub contacts: crate::contacts::HydrateReport,
    pub history_skipped: Vec<SkippedLog>,
    pub activity_skipped: Vec<SkippedLog>,
    pub stamps_skipped: Vec<SkippedStamp>,
    pub keys: KeyHydrateReport,
}

fn response(success: bool, message: impl Into<String>) -> MajikApiResponse {
    MajikApiResponse {
        success,
        message: message.into(),
        code: None,
    }
}

macro_rules! pref_getter {
    ($(#[$doc:meta])* $name:ident => $method:ident) => {
        $(#[$doc])*
        pub fn $name(&mut self) -> Result<bool> {
            Ok(self.get_user_app_preferences()?.$method())
        }
    };
}

pub struct SignatureClient {
    pub(crate) keys: KeyClient<SigHooks>,
    pub(crate) shared: Arc<SigShared>,
    pub(crate) events: Arc<Bus<SigEvent>>,
    pub(crate) signing_session_depth: u32,
    /// The account an explicit `begin_signing_session` unlocked (re-locked by the matching end).
    pub(crate) session_account_id: Option<String>,
}

impl SignatureClient {
    // ── Construction ─────────────────────────────────────────────────────────

    pub fn new(
        keystore: Box<dyn KeystoreRepo>,
        client_state: Box<dyn ClientStateRepo>,
        contacts: ContactManager,
        history: LogManager<HistoryLog>,
        activity: LogManager<UserActivityLog>,
        stamps: StampManager,
    ) -> Self {
        let shared = Arc::new(SigShared {
            contacts: Mutex::new(contacts),
            history: Mutex::new(history),
            activity: Mutex::new(activity),
            stamps: Mutex::new(stamps),
        });
        let keys = KeyClient::new(SigHooks::new(Arc::clone(&shared)), keystore, client_state);
        Self::assemble(keys, shared)
    }

    /// Volatile client for tests.
    pub fn in_memory() -> Self {
        let shared = Arc::new(SigShared {
            contacts: Mutex::new(ContactManager::in_memory()),
            history: Mutex::new(LogManager::new(Box::new(MemoryLogRepo::new()), "history log")),
            activity: Mutex::new(LogManager::new(
                Box::new(MemoryLogRepo::new()),
                "user activity log",
            )),
            stamps: Mutex::new(StampManager::in_memory()),
        });
        let keys = KeyClient::in_memory(SigHooks::new(Arc::clone(&shared)));
        Self::assemble(keys, shared)
    }

    /// SQLite-backed client over the app's shared connection: creates the key, state, contact,
    /// group and log tables if missing. Call [`hydrate`](Self::hydrate) afterwards.
    pub fn with_sqlite(conn: SharedConnection) -> Result<Self> {
        let contacts = ContactManager::with_sqlite(Arc::clone(&conn))?;
        init_log_schema(&conn)?;
        let history = LogManager::new(
            Box::new(SqliteLogRepo::<HistoryLog>::new(Arc::clone(&conn))),
            "history log",
        );
        let activity = LogManager::new(
            Box::new(SqliteLogRepo::<UserActivityLog>::new(Arc::clone(&conn))),
            "user activity log",
        );
        init_stamp_schema(&conn)?;
        let stamps = StampManager::new(Box::new(SqliteStampRepo::new(Arc::clone(&conn))));
        let shared = Arc::new(SigShared {
            contacts: Mutex::new(contacts),
            history: Mutex::new(history),
            activity: Mutex::new(activity),
            stamps: Mutex::new(stamps),
        });
        let keys = KeyClient::with_sqlite(SigHooks::new(Arc::clone(&shared)), conn)?;
        Ok(Self::assemble(keys, shared))
    }

    fn assemble(mut keys: KeyClient<SigHooks>, shared: Arc<SigShared>) -> Self {
        let events: Arc<Bus<SigEvent>> = Arc::new(Bus::new());
        let forward = Arc::clone(&events);
        keys.subscribe(Arc::new(move |e: &ClientEvent| {
            forward.emit(&SigEvent::Key(e.clone()));
        }));
        Self {
            keys,
            shared,
            events,
            signing_session_depth: 0,
            session_account_id: None,
        }
    }

    // ── Accessors ────────────────────────────────────────────────────────────

    pub fn keys(&self) -> &KeyClient<SigHooks> {
        &self.keys
    }

    /// The composed key client. Account operations (create/import/unlock/...) live here, and its
    /// events reach this client's subscribers.
    pub fn keys_mut(&mut self) -> &mut KeyClient<SigHooks> {
        &mut self.keys
    }

    pub fn shared(&self) -> &Arc<SigShared> {
        &self.shared
    }

    pub fn subscribe(&self, listener: Listener<SigEvent>) -> ListenerId {
        self.events.subscribe(listener)
    }

    pub fn unsubscribe(&self, id: ListenerId) -> bool {
        self.events.unsubscribe(id)
    }

    pub(crate) fn emit(&self, event: SigOnlyEvent) {
        self.events.emit(&SigEvent::Sig(event));
    }

    pub(crate) fn emit_error(&self, context: &str, err: &SignatureClientError) {
        self.events.emit(&SigEvent::Key(ClientEvent::Error {
            message: err.to_string(),
            context: context.to_string(),
            id: None,
        }));
    }

    // ── Hydration ────────────────────────────────────────────────────────────

    /// Same order as TS: contacts, then logs, then the key client. The key client's hooks run
    /// during its own hydration and need an already-loaded contact directory.
    pub fn hydrate(&mut self) -> Result<HydrateReport> {
        let contacts = self.shared.lock_contacts()?.hydrate()?;
        let history_skipped = lock(&self.shared.history)?.hydrate()?;
        let activity_skipped = lock(&self.shared.activity)?.hydrate()?;
        let stamps_skipped = lock(&self.shared.stamps)?.hydrate()?;
        let keys = self.keys.hydrate()?;
        Ok(HydrateReport {
            contacts,
            history_skipped,
            activity_skipped,
            stamps_skipped,
            keys,
        })
    }

    pub fn is_hydrated(&self) -> bool {
        self.keys.is_hydrated()
    }

    pub fn active_fingerprint(&self) -> Option<String> {
        self.keys
            .get_active_account_key()
            .map(|k| k.fingerprint().to_string())
    }

    pub(crate) fn require_fingerprint(&self) -> Result<String> {
        self.active_fingerprint()
            .ok_or(SignatureClientError::NoActiveAccount)
    }

    // ── Preferences ──────────────────────────────────────────────────────────

    pub fn get_user_app_preferences(&mut self) -> Result<UserAppPreferences> {
        prefs::load(self.keys.state_mut())
    }

    pub fn set_user_app_preferences(&mut self, preferences: &UserAppPreferences) -> Result<()> {
        prefs::save(self.keys.state_mut(), preferences)
    }

    pub fn reset_user_app_preferences(&mut self) -> Result<()> {
        prefs::reset(self.keys.state_mut())
    }

    pub fn remove_user_app_preferences(&mut self) -> Result<()> {
        prefs::remove(self.keys.state_mut())
    }

    pref_getter!(is_analytics_enabled => is_analytics_enabled);
    pref_getter!(is_auto_seal_enabled => is_auto_seal_enabled);
    pref_getter!(is_default_to_tsa_enabled => is_default_to_tsa_enabled);
    pref_getter!(is_default_to_detached_enabled => is_default_to_detached_enabled);
    pref_getter!(is_auto_lock_on_minimize_enabled => is_auto_lock_on_minimize_enabled);
    pref_getter!(
        /// Defaults to `true`.
        is_onetime_unlock_enabled => is_onetime_unlock_enabled
    );
    pref_getter!(is_auto_save_after_sign_enabled => is_auto_save_after_sign_enabled);
    pref_getter!(is_auto_save_after_seal_enabled => is_auto_save_after_seal_enabled);
    pref_getter!(is_auto_save_after_notarize_enabled => is_auto_save_after_notarize_enabled);

    pub fn auto_lock_interval(&mut self) -> Result<Option<f64>> {
        Ok(self.get_user_app_preferences()?.auto_lock_interval())
    }

    // ── Logs ─────────────────────────────────────────────────────────────────

    /// Record a history entry for `fingerprint` (honouring the history preferences) and emit
    /// `history-log`. Never fails the caller: problems surface as an `error` event.
    pub fn record_history(
        &mut self,
        fingerprint: Option<&str>,
        input: CreateHistoryLog,
    ) -> Option<HistoryLog> {
        let prefs = self.get_user_app_preferences().unwrap_or_default();
        match self.shared.record_history(fingerprint, input, &prefs) {
            Ok(Some(entry)) => {
                self.emit(SigOnlyEvent::HistoryLog(entry.clone()));
                Some(entry)
            }
            Ok(None) => None,
            Err(e) => {
                self.emit_error("recordHistory", &e);
                None
            }
        }
    }

    /// Record an audit entry and emit `activity-log`. Never fails the caller.
    pub fn record_activity(
        &mut self,
        fingerprint: Option<&str>,
        input: CreateUserActivityLog,
    ) -> Option<UserActivityLog> {
        match self.shared.record_activity(fingerprint, input) {
            Ok(entry) => {
                self.emit(SigOnlyEvent::ActivityLog(entry.clone()));
                Some(entry)
            }
            Err(e) => {
                self.emit_error("recordActivity", &e);
                None
            }
        }
    }

    pub fn list_history_for_active_account(&self) -> Vec<HistoryLog> {
        let Some(fp) = self.active_fingerprint() else {
            return Vec::new();
        };
        lock(&self.shared.history)
            .map(|m| m.list_by_fingerprint(&fp).into_iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn list_activity_for_active_account(&self) -> Vec<UserActivityLog> {
        let Some(fp) = self.active_fingerprint() else {
            return Vec::new();
        };
        lock(&self.shared.activity)
            .map(|m| m.list_by_fingerprint(&fp).into_iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn clear_history_logs_for_active_account(&mut self) -> Result<()> {
        let fp = self.require_fingerprint()?;
        let mut mgr = lock(&self.shared.history)?;
        let ids: Vec<String> = mgr
            .list_by_fingerprint(&fp)
            .iter()
            .map(|l| l.id.clone())
            .collect();
        if !ids.is_empty() {
            mgr.bulk_remove(&ids)?;
        }
        Ok(())
    }

    pub fn clear_activity_logs_for_active_account(&mut self) -> Result<()> {
        let fp = self.require_fingerprint()?;
        let mut mgr = lock(&self.shared.activity)?;
        let ids: Vec<String> = mgr
            .list_by_fingerprint(&fp)
            .iter()
            .map(|l| l.id.clone())
            .collect();
        if !ids.is_empty() {
            mgr.bulk_remove(&ids)?;
        }
        Ok(())
    }

    /// Clear both logs for the active account and leave a `logs-restarted` audit entry.
    pub fn restart_logs_for_active_account(&mut self) -> Result<()> {
        let fp = self.require_fingerprint()?;
        self.clear_history_logs_for_active_account()?;
        self.clear_activity_logs_for_active_account()?;
        self.record_activity(
            Some(&fp),
            CreateUserActivityLog::new("logs-restarted", AuditAction::KeyDataReset).with_metadata(
                json!({
                    "at": crate::logs::types::now_iso(),
                    "message": "History and activity logs restarted",
                }),
            ),
        );
        Ok(())
    }

    /// Reload only the active account's logs into the caches.
    pub fn hydrate_logs_for_active_account(&mut self) -> Result<()> {
        let fp = self.require_fingerprint()?;
        lock(&self.shared.history)?.hydrate_for_fingerprint(&fp)?;
        lock(&self.shared.activity)?.hydrate_for_fingerprint(&fp)?;
        Ok(())
    }

    // ── Own accounts ─────────────────────────────────────────────────────────

    /// Update an own account's contact meta. A non-empty label also renames the stored key, and
    /// the key client's own-account entry is refreshed from the directory (TS `updateOwnAccountMeta`).
    pub fn update_own_account_meta(&mut self, id: &str, meta: &MajikContactMeta) -> Result<()> {
        if self.keys.get_own_account_by_id(id).is_none() {
            return Err(SignatureClientError::OwnAccountNotFound(id.to_string()));
        }
        {
            let mut contacts = self.shared.lock_contacts()?;
            contacts.update_contact_meta(id, meta)?;
        }
        if let Some(label) = meta.label.as_deref().map(str::trim).filter(|l| !l.is_empty()) {
            self.keys.key_manager_mut().update_label(id, label)?;
        }
        let updated = {
            let contacts = self.shared.lock_contacts()?;
            contacts.get_contact(id).cloned()
        };
        if let Some(contact) = updated {
            self.keys.refresh_own_account(contact);
        }
        Ok(())
    }

    /// Rename an account in the key store, the key client and the contact directory together.
    /// Prefer this over `keys_mut().update_account_label`, which does not touch the directory.
    pub fn update_account_label(&mut self, id: &str, label: &str) -> Result<()> {
        let meta = MajikContactMeta {
            label: Some(label.to_string()),
            ..Default::default()
        };
        self.update_own_account_meta(id, &meta)
    }

    /// Whether the keystore holds a key with this id or fingerprint.
    pub fn has_own_identity(&self, fingerprint: &str) -> Result<bool> {
        Ok(self.keys.key_manager().has(fingerprint)?)
    }

    /// Own-account label, else contact label, else the first 16 chars of the id.
    pub fn resolve_signer_label(&self, signer_id: &str) -> String {
        if let Some(label) = self
            .keys
            .get_own_account_by_id(signer_id)
            .and_then(|a| a.meta.label.as_deref())
            .filter(|l| !l.is_empty())
        {
            return label.to_string();
        }
        if let Ok(contacts) = self.shared.lock_contacts() {
            if let Some(label) = contacts
                .get_contact(signer_id)
                .and_then(|c| c.meta.label.as_deref())
                .filter(|l| !l.is_empty())
            {
                return label.to_string();
            }
        }
        format!("{}...", signer_id.chars().take(16).collect::<String>())
    }

    /// Wipe keys, state, contacts and stamps; leaves a `key_data_reset` audit entry.
    pub fn reset_data(&mut self) -> Result<()> {
        self.keys.reset_data()?;
        Ok(())
    }

    // ── Contacts ─────────────────────────────────────────────────────────────

    /// Direct access to the contact manager for queries and operations without wrappers.
    /// Do not call back into the key client from inside `f` (see the lock-order note on
    /// [`SigShared`]).
    pub fn with_contacts<R>(&self, f: impl FnOnce(&mut ContactManager) -> R) -> Result<R> {
        let mut contacts = self.shared.lock_contacts()?;
        Ok(f(&mut contacts))
    }

    pub fn add_contact(&mut self, contact: MajikContact) -> Result<()> {
        if contact.id().trim().is_empty()
            || contact.fingerprint().is_empty()
            || contact.public_key().raw.is_empty()
        {
            return Err(SignatureClientError::Invalid(
                "Invalid contact -- missing required fields".into(),
            ));
        }
        let json = contact.to_json();
        {
            let mut contacts = self.shared.lock_contacts()?;
            contacts.add_contact(contact)?;
        }
        let fp = self.active_fingerprint();
        self.record_activity(
            fp.as_deref(),
            CreateUserActivityLog::new(json.id.clone(), AuditAction::ContactAdded)
                .with_metadata(json!({ "contactFingerprint": json.fingerprint.clone() })),
        );
        self.emit(SigOnlyEvent::NewContact(json));
        Ok(())
    }

    pub fn remove_contact(&mut self, id: &str) -> Result<()> {
        let result = {
            let mut contacts = self.shared.lock_contacts()?;
            contacts.remove_contact(id)?
        };
        if !result.success {
            return Err(SignatureClientError::Invalid(result.message));
        }
        let fp = self.active_fingerprint();
        self.record_activity(
            fp.as_deref(),
            CreateUserActivityLog::new(id, AuditAction::ContactDeleted),
        );
        self.emit(SigOnlyEvent::RemovedContact(id.to_string()));
        Ok(())
    }

    /// Never errors (TS parity): failures come back as `success: false` plus an `error` event.
    pub fn import_contact_from_json(&mut self, json: &str) -> MajikApiResponse {
        let outcome = codec::contact_from_card_json(json)
            .map_err(SignatureClientError::from)
            .and_then(|c| self.insert_imported(c));
        self.finish_import(outcome)
    }

    /// Never errors (TS parity): failures come back as `success: false` plus an `error` event.
    pub fn import_contact_from_string(&mut self, base64_str: &str) -> MajikApiResponse {
        if base64_str.trim().is_empty() {
            return response(false, "Invalid contact string");
        }
        let outcome = codec::import_compressed(base64_str)
            .map_err(SignatureClientError::from)
            .and_then(|c| self.insert_imported(c));
        self.finish_import(outcome)
    }

    fn insert_imported(
        &self,
        contact: MajikContact,
    ) -> Result<crate::contacts::majik_contact::SerializedMajikContact> {
        let json = contact.to_json();
        let mut contacts = self.shared.lock_contacts()?;
        contacts.add_contact(contact)?;
        Ok(json)
    }

    fn finish_import(
        &self,
        outcome: Result<crate::contacts::majik_contact::SerializedMajikContact>,
    ) -> MajikApiResponse {
        match outcome {
            Ok(json) => {
                self.emit(SigOnlyEvent::NewContact(json));
                response(true, "Contact imported successfully")
            }
            Err(e) => {
                self.emit_error("importContact", &e);
                response(false, e.to_string())
            }
        }
    }

    pub fn update_contact_meta(&mut self, id: &str, meta: &MajikContactMeta) -> Result<()> {
        let mut contacts = self.shared.lock_contacts()?;
        contacts.update_contact_meta(id, meta)?;
        Ok(())
    }

    /// Empty the directory, then put the own accounts' contacts back (see module docs).
    pub fn clear_directory(&mut self) -> Result<()> {
        let own: Vec<MajikContact> = self
            .keys
            .list_own_accounts()
            .into_iter()
            .cloned()
            .collect();
        let mut contacts = self.shared.lock_contacts()?;
        contacts.clear()?;
        for account in own {
            contacts.add_contact(account)?;
        }
        Ok(())
    }

    // ── Contact groups ───────────────────────────────────────────────────────

    pub fn create_group(
        &mut self,
        id: &str,
        name: &str,
        meta: Option<PartialMajikContactGroupMeta>,
        initial_member_ids: Option<Vec<String>>,
    ) -> Result<SerializedMajikContactGroup> {
        let json = {
            let mut contacts = self.shared.lock_contacts()?;
            let group = contacts.create_group(id, name, meta, initial_member_ids)?;
            group.to_json()
        };
        self.emit(SigOnlyEvent::NewContactGroup(json.clone()));
        Ok(json)
    }

    pub fn add_group(&mut self, group: MajikContactGroup) -> Result<SerializedMajikContactGroup> {
        let json = {
            let mut contacts = self.shared.lock_contacts()?;
            let added = contacts.add_group(group)?;
            added.to_json()
        };
        self.emit(SigOnlyEvent::NewContactGroup(json.clone()));
        Ok(json)
    }

    pub fn remove_group(&mut self, id: &str) -> Result<MajikApiResponse> {
        let (before, result) = {
            let mut contacts = self.shared.lock_contacts()?;
            let before = contacts.get_group(id).map(|g| g.to_json());
            let result = contacts.remove_group(id)?;
            (before, result)
        };
        if let (true, Some(group)) = (result.success, before) {
            self.emit(SigOnlyEvent::RemovedContactGroup(group));
        }
        Ok(result)
    }

    pub fn update_group_meta(
        &mut self,
        id: &str,
        name: Option<&str>,
        description: Option<&str>,
        color: Option<&str>,
    ) -> Result<SerializedMajikContactGroup> {
        self.group_change(|c| Ok(c.update_group_meta(id, name, description, color)?.to_json()))
    }

    pub fn add_contact_to_group(
        &mut self,
        group_id: &str,
        contact_id: &str,
    ) -> Result<SerializedMajikContactGroup> {
        self.group_change(|c| Ok(c.add_contact_to_group(group_id, contact_id)?.to_json()))
    }

    pub fn add_contacts_to_group(
        &mut self,
        group_id: &str,
        contact_ids: &[String],
    ) -> Result<SerializedMajikContactGroup> {
        self.group_change(|c| Ok(c.add_contacts_to_group(group_id, contact_ids)?.to_json()))
    }

    pub fn remove_contact_from_group(
        &mut self,
        group_id: &str,
        contact_id: &str,
    ) -> Result<SerializedMajikContactGroup> {
        self.group_change(|c| Ok(c.remove_contact_from_group(group_id, contact_id)?.to_json()))
    }

    /// Emits `contact-group-change` for the destination group.
    pub fn move_contact_between_groups(
        &mut self,
        contact_id: &str,
        from_group_id: &str,
        to_group_id: &str,
    ) -> Result<SerializedMajikContactGroup> {
        self.group_change(|c| {
            c.move_contact_between_groups(contact_id, from_group_id, to_group_id)?;
            Ok(c.get_group_or_err(to_group_id)?.to_json())
        })
    }

    pub fn add_contact_to_favorites(&mut self, contact_id: &str) -> Result<SerializedMajikContactGroup> {
        self.group_change(|c| Ok(c.add_to_favorites(contact_id)?.to_json()))
    }

    pub fn remove_contact_from_favorites(
        &mut self,
        contact_id: &str,
    ) -> Result<SerializedMajikContactGroup> {
        self.group_change(|c| Ok(c.remove_from_favorites(contact_id)?.to_json()))
    }

    pub fn favorites_group_id(&self) -> &'static str {
        SYSTEM_GROUP_ID_FAVORITES
    }

    /// Run a group mutation under the contacts lock, then emit `contact-group-change` with the
    /// resulting group (after the lock is released).
    fn group_change(
        &mut self,
        f: impl FnOnce(&mut ContactManager) -> Result<SerializedMajikContactGroup>,
    ) -> Result<SerializedMajikContactGroup> {
        let json = {
            let mut contacts = self.shared.lock_contacts()?;
            f(&mut contacts)?
        };
        self.emit(SigOnlyEvent::ContactGroupChange(json.clone()));
        Ok(json)
    }
}
