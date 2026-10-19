//! Stamp operations on the client: creating, listing, decrypting and managing signature stamps.
//! A stamp is encrypted to the owner's ML-KEM key, so creating or decrypting one needs the
//! account unlocked (otherwise `unlockRequired`).

use majik_file::MajikFileIdentity;
use majik_signature::core::stamp::InspectResult;
use majik_signature::MajikSignature;

use crate::client::SignatureClient;
use crate::error::{Result, SignatureClientError};
use crate::events::SigOnlyEvent;
use crate::file_identity::identity_from_key;
use crate::logs::{AuditAction, CreateUserActivityLog};
use crate::shared::lock;
use crate::stamps::{
    CreateStamp, MajikSignatureStamp, SkippedStamp, StampAssetKind, StampMeta,
};

#[derive(Debug, Clone, Default)]
pub struct StampOptions {
    pub mime_type: Option<String>,
    /// `None` = the active account.
    pub account_id: Option<String>,
}

impl SignatureClient {
    /// `MajikFileIdentity` of an unlocked own account (stamp / log-envelope crypto).
    pub fn file_identity_for(&mut self, account_id: Option<&str>) -> Result<MajikFileIdentity> {
        let id = self.resolve_account_id(account_id)?;
        self.keys.ensure_identity_unlocked(&id)?;
        let key = self.keys.key_manager().get(&id).ok_or_else(|| {
            SignatureClientError::Invalid(format!("Account not found in keystore: \"{id}\""))
        })?;
        identity_from_key(key)
    }

    fn stamp_activity(&mut self, stamp: &StampMeta, action: AuditAction) {
        let fp = Some(stamp.fingerprint.clone());
        self.record_activity(
            fp.as_deref(),
            CreateUserActivityLog::new(stamp.id.clone(), action)
                .with_metadata(serde_json::json!({ "kind": stamp.kind, "name": stamp.name })),
        );
    }

    pub fn create_stamp(
        &mut self,
        data: Vec<u8>,
        kind: StampAssetKind,
        name: &str,
        options: &StampOptions,
    ) -> Result<MajikSignatureStamp> {
        let identity = self.file_identity_for(options.account_id.as_deref())?;
        let created = {
            let mut stamps = lock(&self.shared.stamps)?;
            stamps.create(CreateStamp {
                data,
                identity: &identity,
                kind,
                name: name.to_string(),
                mime_type: options.mime_type.clone(),
                id: None,
            })
        };
        let stamp = self.report("createStamp", created.map_err(Into::into))?;
        let meta = stamp.meta();
        self.stamp_activity(&meta, AuditAction::StampCreated);
        self.emit(SigOnlyEvent::NewStamp(meta));
        Ok(stamp)
    }

    /// Cached stamps (call `hydrate_stamps_for_active_account` to load an account's stamps).
    pub fn list_stamps(&self, kind: Option<StampAssetKind>) -> Result<Vec<StampMeta>> {
        let stamps = lock(&self.shared.stamps)?;
        Ok(match kind {
            Some(k) => stamps.list_by_kind(k),
            None => stamps.list(),
        }
        .into_iter()
        .map(|s| s.meta())
        .collect())
    }

    pub fn list_stamps_for_active_account(&self) -> Result<Vec<StampMeta>> {
        let Some(fp) = self.active_fingerprint() else {
            return Ok(Vec::new());
        };
        let stamps = lock(&self.shared.stamps)?;
        Ok(stamps.list_by_fingerprint(&fp).into_iter().map(|s| s.meta()).collect())
    }

    /// Load and decrypt the active account's stamps into memory (the account must be unlocked).
    pub fn hydrate_stamps_for_active_account(&mut self) -> Result<Vec<SkippedStamp>> {
        let id = self.resolve_account_id(None)?;
        self.keys.ensure_identity_unlocked(&id)?;
        let key = self.keys.key_manager().get(&id).ok_or_else(|| {
            SignatureClientError::Invalid(format!("Account not found in keystore: \"{id}\""))
        })?;
        let fp = key.fingerprint().to_string();
        let mut stamps = lock(&self.shared.stamps)?;
        stamps.hydrate_for_fingerprint(&fp, Some(key))
    }

    /// Wipe every decrypted stamp from memory; returns how many were held.
    pub fn lock_stamps(&mut self) -> Result<usize> {
        Ok(lock(&self.shared.stamps)?.lock_all())
    }

    pub fn get_stamp(&self, id: &str) -> Result<Option<StampMeta>> {
        Ok(lock(&self.shared.stamps)?.get(id).map(|s| s.meta()))
    }

    pub fn get_stamp_decrypt_error(&self, id: &str) -> Result<Option<String>> {
        Ok(lock(&self.shared.stamps)?.decrypt_error(id).map(str::to_string))
    }

    /// Plaintext of a stamp already decrypted into memory (see `hydrate_stamps_for_active_account`).
    pub fn get_decrypted_stamp_bytes(&self, id: &str) -> Result<Option<Vec<u8>>> {
        Ok(lock(&self.shared.stamps)?
            .get(id)
            .and_then(|s| s.decrypted_bytes().map(<[u8]>::to_vec)))
    }

    /// Decrypt one stamp on demand without keeping the plaintext cached.
    pub fn decrypt_stamp_content(&mut self, id: &str, account_id: Option<&str>) -> Result<Vec<u8>> {
        let identity = self.file_identity_for(account_id)?;
        let result = lock(&self.shared.stamps)?.decrypt_content(id, &identity);
        self.report("decryptStampContent", result)
    }

    pub fn rename_stamp(&mut self, id: &str, new_name: &str) -> Result<StampMeta> {
        let renamed = lock(&self.shared.stamps)?.rename(id, new_name);
        let meta = self.report("renameStamp", renamed)?.meta();
        self.stamp_activity(&meta, AuditAction::StampUpdated);
        Ok(meta)
    }

    pub fn replace_stamp_content(
        &mut self,
        id: &str,
        data: Vec<u8>,
        mime_type: Option<String>,
        account_id: Option<&str>,
    ) -> Result<StampMeta> {
        let identity = self.file_identity_for(account_id)?;
        let replaced = lock(&self.shared.stamps)?.replace_content(id, data, &identity, mime_type);
        let meta = self.report("replaceStampContent", replaced)?.meta();
        self.stamp_activity(&meta, AuditAction::StampUpdated);
        Ok(meta)
    }

    pub fn remove_stamp(&mut self, id: &str) -> Result<()> {
        let meta = lock(&self.shared.stamps)?.get(id).map(|s| s.meta());
        let deleted = lock(&self.shared.stamps)?.delete(id);
        self.report("removeStamp", deleted)?;
        if let Some(meta) = meta {
            self.stamp_activity(&meta, AuditAction::StampDeleted);
        }
        self.emit(SigOnlyEvent::RemovedStamp(id.to_string()));
        Ok(())
    }

    /// Read the stamp metadata embedded in an image (no keys needed).
    pub fn inspect_stamp(&self, image: &[u8]) -> InspectResult {
        MajikSignature::inspect_stamp(image)
    }

    pub fn is_stamped(&self, image: &[u8]) -> bool {
        MajikSignature::is_stamped(image)
    }
}
