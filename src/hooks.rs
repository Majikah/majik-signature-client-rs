//! `SigHooks`: what the signature client adds to account lifecycle (TS `_onAccountRegistered`,
//! `_onAccountRemoved`, `_onResetKeyData`). Own accounts are mirrored into the contact directory.

use std::sync::Arc;

use majik_key_client::{AccountHooks, KeyClientError};

use crate::contacts::majik_contact::MajikContact;
use crate::logs::{AuditAction, CreateUserActivityLog};
use crate::shared::SigShared;

pub struct SigHooks {
    shared: Arc<SigShared>,
}

impl SigHooks {
    pub fn new(shared: Arc<SigShared>) -> Self {
        Self { shared }
    }
}

fn hook_err(what: &str, e: impl std::fmt::Display) -> KeyClientError {
    KeyClientError::Invalid(format!("{what}: {e}"))
}

impl AccountHooks for SigHooks {
    /// Default `build_own_account` (`key.to_contact(meta)`) is what the TS client uses too.
    fn on_account_registered(&mut self, account: &MajikContact) -> majik_key_client::Result<()> {
        let mut contacts = self
            .shared
            .lock_contacts()
            .map_err(|e| hook_err("contacts", e))?;
        if !contacts.has_contact(account.id()) {
            contacts
                .add_contact(account.clone())
                .map_err(|e| hook_err("contacts", e))?;
        }
        Ok(())
    }

    fn on_account_removed(&mut self, id: &str) -> majik_key_client::Result<()> {
        let mut contacts = self
            .shared
            .lock_contacts()
            .map_err(|e| hook_err("contacts", e))?;
        contacts
            .remove_contact(id)
            .map_err(|e| hook_err("contacts", e))?;
        Ok(())
    }

    fn on_reset_key_data(&mut self) -> majik_key_client::Result<()> {
        {
            let mut contacts = self
                .shared
                .lock_contacts()
                .map_err(|e| hook_err("contacts", e))?;
            contacts.clear().map_err(|e| hook_err("contacts", e))?;
        }
        {
            let mut stamps =
                crate::shared::lock(&self.shared.stamps).map_err(|e| hook_err("stamps", e))?;
            stamps.clear().map_err(|e| hook_err("stamps", e))?;
        }
        // Best effort, like the TS `_recordActivity` (which swallows its own failures).
        let _ = self.shared.record_activity(
            None,
            CreateUserActivityLog::new("key-data-reset", AuditAction::KeyDataReset)
                .with_metadata(serde_json::json!({ "at": crate::logs::types::now_iso() })),
        );
        Ok(())
    }
}
