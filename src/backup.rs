//! Backups: a 6-byte magic header + `MajikCompressedJson` (zstd) payload, byte-compatible with the
//! TS `backupContacts` / `backupStamps` / `backupAppData` formats.

use majik_cjson::MajikCompressedJson;
use majik_key_client::ClientEvent;
use serde::{Deserialize, Serialize};

use crate::client::SignatureClient;
use crate::contacts::majik_contact::{MajikContact, MajikContactGroup};
use crate::contacts::{ContactManager, ContactManagerJson, MemoryContactRepo, MemoryGroupRepo};
use crate::error::{Result, SignatureClientError};
use crate::events::SigEvent;
use crate::logs::{AuditAction, CreateUserActivityLog};
use crate::prefs::UserAppPreferences;
use crate::shared::lock;
use crate::stamps::{MajikSignatureStamp, StampJson};

pub const MAGIC_SIZE: usize = 6;
/// `"STMP"` + version 1.
pub const MAGIC_STAMPS: [u8; MAGIC_SIZE] = [0x53, 0x54, 0x4d, 0x50, 0x00, 0x01];
/// `"MJKC"` + version 1.
pub const MAGIC_CONTACTS: [u8; MAGIC_SIZE] = [0x4d, 0x4a, 0x4b, 0x43, 0x00, 0x01];
/// `"MJKA"` + version 1.
pub const MAGIC_APP_DATA: [u8; MAGIC_SIZE] = [0x4d, 0x4a, 0x4b, 0x41, 0x00, 0x01];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum BackupType {
    Stamps,
    Contacts,
    AppData,
    Unknown,
}

/// TS `AppBackUpData`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppBackUpData {
    pub contacts: ContactManagerJson,
    #[serde(default)]
    pub stamps: Vec<StampJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferences: Option<UserAppPreferences>,
}

#[derive(Debug, Clone)]
pub struct ContactManagerSnapshot {
    pub manager_json: ContactManagerJson,
    pub contacts: Vec<MajikContact>,
    pub groups: Vec<MajikContactGroup>,
}

#[derive(Debug, Clone)]
pub struct AppDataSnapshot {
    pub contacts: Vec<MajikContact>,
    pub groups: Vec<MajikContactGroup>,
    pub stamps: Vec<StampJson>,
    pub preferences: Option<UserAppPreferences>,
    pub contacts_manager_json: ContactManagerJson,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RestoredContacts {
    pub contacts: usize,
    pub groups: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RestoredAppData {
    pub contacts: usize,
    pub groups: usize,
    pub stamps: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RestoredSelective {
    pub contacts: usize,
    pub groups: usize,
    pub stamps: usize,
    pub preferences: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct RestoreContactsOptions {
    pub overwrite_contacts: bool,
    pub include_groups: bool,
}

impl Default for RestoreContactsOptions {
    fn default() -> Self {
        Self {
            overwrite_contacts: true,
            include_groups: true,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct SelectiveRestoreOptions {
    pub stamps: bool,
    pub contacts: bool,
    pub groups: bool,
    pub preferences: bool,
    pub overwrite_contacts: bool,
}

impl Default for SelectiveRestoreOptions {
    fn default() -> Self {
        Self {
            stamps: true,
            contacts: true,
            groups: true,
            preferences: true,
            overwrite_contacts: true,
        }
    }
}

fn pack<T: Serialize + serde::de::DeserializeOwned>(magic: &[u8; MAGIC_SIZE], payload: T) -> Result<Vec<u8>> {
    let body = MajikCompressedJson::<T>::from_payload(payload)?.to_binary();
    let mut out = Vec::with_capacity(MAGIC_SIZE + body.len());
    out.extend_from_slice(magic);
    out.extend_from_slice(&body);
    Ok(out)
}

fn unpack<T: Serialize + serde::de::DeserializeOwned>(
    bytes: &[u8],
    magic: &[u8; MAGIC_SIZE],
    label: &str,
) -> Result<T> {
    if bytes.len() < MAGIC_SIZE {
        return Err(SignatureClientError::Invalid(format!(
            "{label} backup: buffer too small to contain a valid header."
        )));
    }
    for i in 0..MAGIC_SIZE {
        if bytes[i] != magic[i] {
            return Err(SignatureClientError::Invalid(format!(
                "{label} backup: invalid magic bytes -- this file is not a valid {label} backup \
                 (got 0x{:02x} at byte {i}, expected 0x{:02x}).",
                bytes[i], magic[i]
            )));
        }
    }
    Ok(MajikCompressedJson::<T>::decompress(bytes[MAGIC_SIZE..].to_vec())?)
}

fn temp_manager(json: &ContactManagerJson) -> Result<ContactManager> {
    Ok(ContactManager::from_json(
        json,
        Box::new(MemoryContactRepo::new()),
        Box::new(MemoryGroupRepo::new()),
    )?)
}

fn contacts_and_groups(json: &ContactManagerJson) -> Result<(Vec<MajikContact>, Vec<MajikContactGroup>)> {
    let temp = temp_manager(json)?;
    let contacts = temp.list_contacts(false, false).into_iter().cloned().collect();
    let groups = temp.list_groups(true, false).into_iter().cloned().collect();
    Ok((contacts, groups))
}

impl SignatureClient {
    /// Which kind of backup `bytes` is, from its magic header.
    pub fn probe_backup_type(bytes: &[u8]) -> BackupType {
        let header = &bytes[..bytes.len().min(MAGIC_SIZE)];
        if header == MAGIC_STAMPS {
            BackupType::Stamps
        } else if header == MAGIC_CONTACTS {
            BackupType::Contacts
        } else if header == MAGIC_APP_DATA {
            BackupType::AppData
        } else {
            BackupType::Unknown
        }
    }

    // ── Create ───────────────────────────────────────────────────────────────

    pub fn backup_contacts(&self) -> Result<Vec<u8>> {
        let json = lock(&self.shared.contacts)?.to_json();
        pack(&MAGIC_CONTACTS, json)
    }

    pub fn backup_stamps(&self) -> Result<Vec<u8>> {
        let stamps = lock(&self.shared.stamps)?.to_json()?;
        pack(&MAGIC_STAMPS, stamps)
    }

    pub fn backup_app_data(&mut self) -> Result<Vec<u8>> {
        let contacts = lock(&self.shared.contacts)?.to_json();
        let stamps = lock(&self.shared.stamps)?.to_json()?;
        let preferences = self.get_user_app_preferences().ok();
        pack(
            &MAGIC_APP_DATA,
            AppBackUpData {
                contacts,
                stamps,
                preferences,
            },
        )
    }

    // ── Read ─────────────────────────────────────────────────────────────────

    pub fn read_stamps_backup(&self, bytes: &[u8]) -> Result<Vec<StampJson>> {
        unpack(bytes, &MAGIC_STAMPS, "stamps")
    }

    pub fn read_contacts_backup(&self, bytes: &[u8]) -> Result<ContactManagerSnapshot> {
        let manager_json: ContactManagerJson = unpack(bytes, &MAGIC_CONTACTS, "contacts")?;
        let (contacts, groups) = contacts_and_groups(&manager_json)?;
        Ok(ContactManagerSnapshot {
            manager_json,
            contacts,
            groups,
        })
    }

    pub fn read_app_data_backup(&self, bytes: &[u8]) -> Result<AppDataSnapshot> {
        let data: AppBackUpData = unpack(bytes, &MAGIC_APP_DATA, "app data")?;
        let (contacts, groups) = contacts_and_groups(&data.contacts)?;
        Ok(AppDataSnapshot {
            contacts,
            groups,
            stamps: data.stamps,
            preferences: data.preferences,
            contacts_manager_json: data.contacts,
        })
    }

    // ── Restore ──────────────────────────────────────────────────────────────

    /// Add backed-up contacts. For an id that already exists, `overwrite` updates its label, notes
    /// and blocked flag from the backup; otherwise it is skipped. (The TS version called
    /// `addContact`, which throws for an existing id.)
    fn restore_contact_list(&mut self, contacts: Vec<MajikContact>, overwrite: bool) -> Result<usize> {
        let mut count = 0;
        for contact in contacts {
            let exists = lock(&self.shared.contacts)?.has_contact(contact.id());
            if exists {
                if !overwrite {
                    continue;
                }
                let meta = contact.meta.clone();
                lock(&self.shared.contacts)?.update_contact_meta(contact.id(), &meta)?;
            } else {
                self.add_contact(contact)?;
            }
            count += 1;
        }
        Ok(count)
    }

    fn restore_group_list(&mut self, groups: Vec<MajikContactGroup>) -> Result<usize> {
        let mut count = 0;
        for group in groups {
            if group.is_system() {
                continue;
            }
            let has_group = lock(&self.shared.contacts)?.has_group(group.id());
            if !has_group {
                self.add_group(group)?;
            } else {
                let gid = group.id().to_string();
                for member in group.list_member_ids() {
                    let mut contacts = lock(&self.shared.contacts)?;
                    if contacts.has_contact(&member) {
                        contacts.add_contact_to_group_if_absent(&gid, &member)?;
                    }
                }
            }
            count += 1;
        }
        Ok(count)
    }

    fn restore_stamp_rows(&mut self, rows: Vec<StampJson>) -> Result<usize> {
        let count = rows.len();
        let mut stamps = lock(&self.shared.stamps)?;
        for json in rows {
            stamps.save(MajikSignatureStamp::from_json(json)?)?;
        }
        Ok(count)
    }

    pub fn restore_stamps(&mut self, bytes: &[u8]) -> Result<usize> {
        let rows = self.read_stamps_backup(bytes)?;
        self.restore_stamp_rows(rows)
    }

    pub fn restore_contacts(
        &mut self,
        bytes: &[u8],
        options: RestoreContactsOptions,
    ) -> Result<RestoredContacts> {
        let snapshot = self.read_contacts_backup(bytes)?;
        let contacts = self.restore_contact_list(snapshot.contacts, options.overwrite_contacts)?;
        let groups = if options.include_groups {
            self.restore_group_list(snapshot.groups)?
        } else {
            0
        };
        Ok(RestoredContacts { contacts, groups })
    }

    pub fn restore_app_data(&mut self, bytes: &[u8]) -> Result<RestoredAppData> {
        let snapshot = self.read_app_data_backup(bytes)?;
        let contacts = self.restore_contact_list(snapshot.contacts, true)?;
        let groups = self.restore_group_list(snapshot.groups)?;
        let stamps = self.restore_stamp_rows(snapshot.stamps)?;
        if let Some(prefs) = &snapshot.preferences {
            self.set_user_app_preferences(prefs)?;
        }
        let fp = self.active_fingerprint();
        self.record_activity(
            fp.as_deref(),
            CreateUserActivityLog::new("app-data-restore", AuditAction::RestoreAppData)
                .with_metadata(serde_json::json!({
                    "contactsRestored": contacts,
                    "groupsRestored": groups,
                    "stampsRestored": stamps,
                })),
        );
        Ok(RestoredAppData {
            contacts,
            groups,
            stamps,
        })
    }

    /// Restore only the parts of an `AppDataSnapshot` you choose, then emit `restore-backup`.
    pub fn restore_app_data_selective(
        &mut self,
        snapshot: AppDataSnapshot,
        options: SelectiveRestoreOptions,
    ) -> Result<RestoredSelective> {
        let contacts = if options.contacts {
            self.restore_contact_list(snapshot.contacts, options.overwrite_contacts)?
        } else {
            0
        };
        let groups = if options.groups {
            self.restore_group_list(snapshot.groups)?
        } else {
            0
        };
        let stamps = if options.stamps {
            self.restore_stamp_rows(snapshot.stamps)?
        } else {
            0
        };
        let mut preferences = false;
        if options.preferences {
            if let Some(prefs) = &snapshot.preferences {
                self.set_user_app_preferences(prefs)?;
                preferences = true;
            }
        }
        self.events.emit(&SigEvent::Key(ClientEvent::RestoreBackup));
        Ok(RestoredSelective {
            contacts,
            groups,
            stamps,
            preferences,
        })
    }
}
