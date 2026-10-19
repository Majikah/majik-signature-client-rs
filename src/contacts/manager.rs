//! `ContactManager`: directory + groups + persistence. Port of `MajikContactManager`.
//!
//! Like the TS manager, every mutating call updates memory first and then persists. Everything
//! is synchronous (SQLite blocks); wrap calls in `spawn_blocking` from async Tauri commands.

use majik_contact::{
    MajikApiResponse, MajikContact, MajikContactGroup, MajikContactMeta,
    PartialMajikContactGroupMeta, SerializedMajikContact, SerializedMajikContactGroup,
    SYSTEM_GROUP_ID_BLOCKED,
};
use serde::{Deserialize, Serialize};

use super::codec;
use super::directory::{api_response, ContactDirectory, SkippedContact};
use super::error::{ContactManagerError, Result};
use super::groups::GroupManager;
use super::memory::{MemoryContactRepo, MemoryGroupRepo};
use super::sqlite::{init_schema, SharedConnection, SqliteContactRepo, SqliteGroupRepo};
use super::storage::{ContactRepo, GroupRepo};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HydrateReport {
    pub contacts_loaded: usize,
    pub contacts_skipped: Vec<SkippedContact>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContactDirectoryData {
    pub contacts: Vec<SerializedMajikContact>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GroupManagerData {
    pub groups: Vec<SerializedMajikContactGroup>,
}

/// TS `MajikContactManagerJSON`: `{ contacts: { contacts: [...] }, groups: { groups: [...] } }`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContactManagerJson {
    pub contacts: ContactDirectoryData,
    pub groups: GroupManagerData,
}

fn merr(msg: impl Into<String>) -> ContactManagerError {
    ContactManagerError::Manager(msg.into())
}

pub struct ContactManager {
    directory: ContactDirectory,
    groups: GroupManager,
    contact_repo: Box<dyn ContactRepo>,
    group_repo: Box<dyn GroupRepo>,
}

impl ContactManager {
    pub fn new(contact_repo: Box<dyn ContactRepo>, group_repo: Box<dyn GroupRepo>) -> Self {
        Self {
            directory: ContactDirectory::new(),
            groups: GroupManager::new(),
            contact_repo,
            group_repo,
        }
    }

    /// Volatile manager for tests.
    pub fn in_memory() -> Self {
        Self::new(
            Box::new(MemoryContactRepo::new()),
            Box::new(MemoryGroupRepo::new()),
        )
    }

    /// SQLite-backed manager over the app's shared connection. Creates the tables if needed.
    /// Call [`hydrate`](Self::hydrate) afterwards.
    pub fn with_sqlite(conn: SharedConnection) -> Result<Self> {
        init_schema(&conn)?;
        Ok(Self::new(
            Box::new(SqliteContactRepo::new(std::sync::Arc::clone(&conn))),
            Box::new(SqliteGroupRepo::new(conn)),
        ))
    }

    pub fn directory(&self) -> &ContactDirectory {
        &self.directory
    }

    pub fn groups(&self) -> &GroupManager {
        &self.groups
    }

    // ── Hydration / persistence ──────────────────────────────────────────────

    pub fn hydrate(&mut self) -> Result<HydrateReport> {
        let contacts = self.contact_repo.list()?;
        let contacts_skipped = self.directory.replace_from_json(contacts);
        let groups = self.group_repo.list()?;
        self.groups.restore(groups)?;
        self.groups.prune_orphaned_members(&self.directory)?;
        Ok(HydrateReport {
            contacts_loaded: self.directory.len(),
            contacts_skipped,
        })
    }

    fn persist_contact(&self, id: &str) -> Result<()> {
        let contact = self
            .directory
            .get_contact(id)
            .ok_or_else(|| merr(format!("Contact not found: {id}")))?;
        self.contact_repo.save(&contact.to_json())
    }

    fn persist_group(&self, id: &str) -> Result<()> {
        let group = self.groups.get_group_or_err(id)?;
        self.group_repo.save(&group.to_json())
    }

    fn persist_all_groups(&self) -> Result<()> {
        self.group_repo.bulk_save(&self.groups.to_json())
    }

    // ── Contacts ─────────────────────────────────────────────────────────────

    pub fn add_contact(&mut self, contact: MajikContact) -> Result<()> {
        let id = contact.id().to_string();
        self.directory.add_contact(contact)?;
        self.persist_contact(&id)
    }

    /// Atomic in memory (see `ContactDirectory::add_contacts`), then one bulk write.
    pub fn add_contacts(&mut self, contacts: Vec<MajikContact>) -> Result<()> {
        let jsons: Vec<SerializedMajikContact> = contacts.iter().map(|c| c.to_json()).collect();
        self.directory.add_contacts(contacts)?;
        self.contact_repo.bulk_save(&jsons)
    }

    pub fn remove_contact(&mut self, id: &str) -> Result<MajikApiResponse> {
        let result = self.directory.remove_contact(id)?;
        if result.success {
            self.groups.handle_contact_removed(id)?;
            self.contact_repo.remove(id)?;
            self.persist_all_groups()?;
        }
        Ok(result)
    }

    pub fn update_contact_meta(
        &mut self,
        id: &str,
        meta: &MajikContactMeta,
    ) -> Result<&MajikContact> {
        self.directory.update_contact_meta(id, meta)?;
        self.persist_contact(id)?;
        self.require(id)
    }

    pub fn block_contact(&mut self, id: &str) -> Result<&MajikContact> {
        self.directory.block_contact(id)?;
        self.groups
            .add_contact_to_group_if_absent(&mut self.directory, SYSTEM_GROUP_ID_BLOCKED, id)?;
        self.persist_contact(id)?;
        self.persist_group(SYSTEM_GROUP_ID_BLOCKED)?;
        self.require(id)
    }

    pub fn unblock_contact(&mut self, id: &str) -> Result<&MajikContact> {
        self.directory.unblock_contact(id)?;
        self.groups.remove_contact_from_group_if_present(
            &mut self.directory,
            SYSTEM_GROUP_ID_BLOCKED,
            id,
        )?;
        self.persist_contact(id)?;
        self.persist_group(SYSTEM_GROUP_ID_BLOCKED)?;
        self.require(id)
    }

    pub fn set_majikah_status(&mut self, id: &str, status: bool) -> Result<&MajikContact> {
        self.directory.set_majikah_status(id, status)?;
        self.persist_contact(id)?;
        self.require(id)
    }

    /// Remove every contact and group from memory and storage. The two system groups are
    /// recreated (empty) in memory; the TS version left the manager without them.
    pub fn clear(&mut self) -> Result<()> {
        self.directory.clear();
        self.groups = GroupManager::new();
        self.contact_repo.clear()?;
        self.group_repo.clear()?;
        Ok(())
    }

    fn require(&self, id: &str) -> Result<&MajikContact> {
        self.directory
            .get_contact(id)
            .ok_or_else(|| merr(format!("Contact not found: {id}")))
    }

    // ── Contact queries ──────────────────────────────────────────────────────

    pub fn get_contact(&self, id: &str) -> Option<&MajikContact> {
        self.directory.get_contact(id)
    }

    pub fn get_contact_by_fingerprint(&self, fingerprint: &str) -> Option<&MajikContact> {
        self.directory.get_contact_by_fingerprint(fingerprint)
    }

    pub fn get_contact_by_address(&self, address: &str) -> Option<&MajikContact> {
        self.directory.get_contact_by_address(address)
    }

    /// De-duplicated, in input order. `strict` errors on the first missing id.
    pub fn get_contacts_by_ids(&self, ids: &[String], strict: bool) -> Result<Vec<&MajikContact>> {
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for id in ids {
            if !seen.insert(id.as_str()) {
                continue;
            }
            match self.directory.get_contact(id) {
                Some(c) => out.push(c),
                None if strict => return Err(merr(format!("Contact not found: {id}"))),
                None => {}
            }
        }
        Ok(out)
    }

    /// De-duplicated, in input order. `strict` errors on the first unknown public key.
    pub fn get_contacts_by_public_keys(
        &self,
        public_keys: &[String],
        strict: bool,
    ) -> Result<Vec<&MajikContact>> {
        let mut seen = std::collections::HashSet::new();
        let mut out = Vec::new();
        for key in public_keys {
            if !seen.insert(key.as_str()) {
                continue;
            }
            match self.directory.get_contact_by_address(key) {
                Some(c) => out.push(c),
                None if strict => {
                    return Err(merr(format!("Contact not found for publicKey: {key}")))
                }
                None => {}
            }
        }
        Ok(out)
    }

    pub fn has_contact(&self, id: &str) -> bool {
        self.directory.has_contact(id)
    }

    pub fn has_fingerprint(&self, fingerprint: &str) -> bool {
        self.directory.has_fingerprint(fingerprint)
    }

    pub fn has_contact_by_address(&self, address: &str) -> bool {
        self.directory.has_contact_by_address(address)
    }

    pub fn list_contacts(&self, sorted_by_label: bool, majikah_only: bool) -> Vec<&MajikContact> {
        self.directory.list_contacts(sorted_by_label, majikah_only)
    }

    pub fn is_majikah_registered(&self, id: &str) -> Result<bool> {
        self.directory.is_majikah_registered(id)
    }

    pub fn is_majikah_identity_checked(&self, id: &str) -> Result<bool> {
        self.directory.is_majikah_identity_checked(id)
    }

    // ── Groups ───────────────────────────────────────────────────────────────

    pub fn create_group(
        &mut self,
        id: &str,
        name: &str,
        meta: Option<PartialMajikContactGroupMeta>,
        initial_member_ids: Option<Vec<String>>,
    ) -> Result<&MajikContactGroup> {
        self.groups
            .create_group(&self.directory, id, name, meta, initial_member_ids)?;
        self.persist_group(id)?;
        self.groups.get_group_or_err(id)
    }

    pub fn add_group(&mut self, group: MajikContactGroup) -> Result<&MajikContactGroup> {
        let id = group.id().to_string();
        self.groups.add_group(&self.directory, group)?;
        self.persist_group(&id)?;
        self.groups.get_group_or_err(&id)
    }

    pub fn remove_group(&mut self, id: &str) -> Result<MajikApiResponse> {
        match self.groups.remove_group(id)? {
            Some(_) => {
                self.group_repo.remove(id)?;
                Ok(api_response(true, "Group removed successfully"))
            }
            None => Ok(api_response(false, format!("Group \"{id}\" not found"))),
        }
    }

    pub fn get_group(&self, id: &str) -> Option<&MajikContactGroup> {
        self.groups.get_group(id)
    }

    pub fn get_group_or_err(&self, id: &str) -> Result<&MajikContactGroup> {
        self.groups.get_group_or_err(id)
    }

    pub fn has_group(&self, id: &str) -> bool {
        self.groups.has_group(id)
    }

    pub fn list_groups(&self, include_system: bool, sorted_by_name: bool) -> Vec<&MajikContactGroup> {
        self.groups.list_groups(include_system, sorted_by_name)
    }

    pub fn list_user_groups(&self, sorted_by_name: bool) -> Vec<&MajikContactGroup> {
        self.groups.list_groups(false, sorted_by_name)
    }

    pub fn list_system_groups(&self) -> Vec<&MajikContactGroup> {
        self.groups
            .list_groups(true, false)
            .into_iter()
            .filter(|g| g.is_system())
            .collect()
    }

    pub fn update_group_meta(
        &mut self,
        id: &str,
        name: Option<&str>,
        description: Option<&str>,
        color: Option<&str>,
    ) -> Result<&MajikContactGroup> {
        self.groups.update_group_meta(id, name, description, color)?;
        self.persist_group(id)?;
        self.groups.get_group_or_err(id)
    }

    pub fn add_contact_to_group(
        &mut self,
        group_id: &str,
        contact_id: &str,
    ) -> Result<&MajikContactGroup> {
        self.groups
            .add_contact_to_group(&mut self.directory, group_id, contact_id)?;
        self.persist_membership_change(group_id, contact_id)
    }

    pub fn add_contact_to_group_if_absent(
        &mut self,
        group_id: &str,
        contact_id: &str,
    ) -> Result<&MajikContactGroup> {
        self.groups
            .add_contact_to_group_if_absent(&mut self.directory, group_id, contact_id)?;
        self.persist_membership_change(group_id, contact_id)
    }

    pub fn add_contacts_to_group(
        &mut self,
        group_id: &str,
        contact_ids: &[String],
    ) -> Result<&MajikContactGroup> {
        self.groups
            .add_contacts_to_group(&mut self.directory, group_id, contact_ids)?;
        if group_id == SYSTEM_GROUP_ID_BLOCKED {
            for id in contact_ids {
                self.persist_contact(id)?;
            }
        }
        self.persist_group(group_id)?;
        self.groups.get_group_or_err(group_id)
    }

    pub fn remove_contact_from_group(
        &mut self,
        group_id: &str,
        contact_id: &str,
    ) -> Result<&MajikContactGroup> {
        self.groups
            .remove_contact_from_group(&mut self.directory, group_id, contact_id)?;
        self.persist_membership_change(group_id, contact_id)
    }

    pub fn remove_contact_from_group_if_present(
        &mut self,
        group_id: &str,
        contact_id: &str,
    ) -> Result<&MajikContactGroup> {
        self.groups.remove_contact_from_group_if_present(
            &mut self.directory,
            group_id,
            contact_id,
        )?;
        self.persist_membership_change(group_id, contact_id)
    }

    /// Group membership in the Blocked group also flips the contact's `blocked` flag, so that
    /// contact must be persisted too (the TS manager only wrote the group in these paths).
    fn persist_membership_change(
        &self,
        group_id: &str,
        contact_id: &str,
    ) -> Result<&MajikContactGroup> {
        if group_id == SYSTEM_GROUP_ID_BLOCKED {
            self.persist_contact(contact_id)?;
        }
        self.persist_group(group_id)?;
        self.groups.get_group_or_err(group_id)
    }

    pub fn move_contact_between_groups(
        &mut self,
        contact_id: &str,
        from_group_id: &str,
        to_group_id: &str,
    ) -> Result<()> {
        self.groups
            .move_contact(&mut self.directory, contact_id, from_group_id, to_group_id)?;
        self.persist_group(from_group_id)?;
        self.persist_group(to_group_id)?;
        if from_group_id == SYSTEM_GROUP_ID_BLOCKED || to_group_id == SYSTEM_GROUP_ID_BLOCKED {
            self.persist_contact(contact_id)?;
        }
        Ok(())
    }

    pub fn get_contacts_in_group(&self, group_id: &str) -> Result<Vec<&MajikContact>> {
        self.groups.get_contacts_in_group(&self.directory, group_id)
    }

    pub fn get_contacts_in_group_sorted(&self, group_id: &str) -> Result<Vec<&MajikContact>> {
        self.groups
            .get_contacts_in_group_sorted(&self.directory, group_id)
    }

    pub fn is_contact_in_group(&self, group_id: &str, contact_id: &str) -> Result<bool> {
        self.groups.is_contact_in_group(group_id, contact_id)
    }

    pub fn get_groups_for_contact(&self, contact_id: &str) -> Result<Vec<&MajikContactGroup>> {
        self.groups.get_groups_for_contact(contact_id)
    }

    pub fn get_group_ids_for_contact(&self, contact_id: &str) -> Result<Vec<String>> {
        self.groups.get_group_ids_for_contact(contact_id)
    }

    // ── Favorites / blocked ──────────────────────────────────────────────────

    pub fn add_to_favorites(&mut self, contact_id: &str) -> Result<&MajikContactGroup> {
        self.groups.add_to_favorites(&mut self.directory, contact_id)?;
        let id = majik_contact::SYSTEM_GROUP_ID_FAVORITES;
        self.persist_group(id)?;
        self.groups.get_group_or_err(id)
    }

    pub fn remove_from_favorites(&mut self, contact_id: &str) -> Result<&MajikContactGroup> {
        self.groups
            .remove_from_favorites(&mut self.directory, contact_id)?;
        let id = majik_contact::SYSTEM_GROUP_ID_FAVORITES;
        self.persist_group(id)?;
        self.groups.get_group_or_err(id)
    }

    pub fn is_favorite(&self, contact_id: &str) -> Result<bool> {
        self.groups.is_favorite(contact_id)
    }

    pub fn is_contact_blocked(&self, contact_id: &str) -> Result<bool> {
        self.groups.is_blocked(contact_id)
    }

    pub fn get_favorites_group(&self) -> Result<&MajikContactGroup> {
        self.groups.get_favorites_group()
    }

    pub fn get_blocked_group(&self) -> Result<&MajikContactGroup> {
        self.groups.get_blocked_group()
    }

    pub fn get_favorite_contacts(&self) -> Result<Vec<&MajikContact>> {
        self.groups
            .get_contacts_in_group(&self.directory, majik_contact::SYSTEM_GROUP_ID_FAVORITES)
    }

    pub fn get_blocked_contacts(&self) -> Result<Vec<&MajikContact>> {
        self.groups
            .get_contacts_in_group(&self.directory, SYSTEM_GROUP_ID_BLOCKED)
    }

    // ── Import / export ──────────────────────────────────────────────────────

    /// Pretty-printed contact card JSON; `None` if the contact does not exist.
    pub fn export_contact_as_json(&self, contact_id: &str) -> Result<Option<String>> {
        match self.get_contact(contact_id) {
            Some(c) => Ok(Some(codec::card_to_json(c, true)?)),
            None => Ok(None),
        }
    }

    /// gzip + base64 share string; `None` if the contact does not exist.
    pub fn export_contact_as_string(&self, contact_id: &str) -> Result<Option<String>> {
        match self.get_contact(contact_id) {
            Some(c) => Ok(Some(codec::export_compressed(c)?)),
            None => Ok(None),
        }
    }

    pub fn export_contact_compressed(&self, contact: &MajikContact) -> Result<String> {
        codec::export_compressed(contact)
    }

    /// Never errors (TS parity): failures come back as `success: false`.
    pub fn import_contact_from_json(&mut self, json: &str) -> MajikApiResponse {
        let outcome = codec::contact_from_card_json(json).and_then(|c| self.add_contact(c));
        Self::import_response(outcome)
    }

    /// Never errors (TS parity): failures come back as `success: false`.
    pub fn import_contact_from_string(&mut self, base64_str: &str) -> MajikApiResponse {
        let outcome = codec::import_compressed(base64_str).and_then(|c| self.add_contact(c));
        Self::import_response(outcome)
    }

    pub fn import_contact_compressed(&self, base64_str: &str) -> Result<MajikContact> {
        codec::import_compressed(base64_str)
    }

    fn import_response(outcome: Result<()>) -> MajikApiResponse {
        match outcome {
            Ok(()) => api_response(true, "Contact imported successfully"),
            Err(e) => api_response(false, e.to_string()),
        }
    }

    // ── Whole-manager serialization ──────────────────────────────────────────

    pub fn to_json(&self) -> ContactManagerJson {
        ContactManagerJson {
            contacts: ContactDirectoryData {
                contacts: self.directory.to_json(),
            },
            groups: GroupManagerData {
                groups: self.groups.to_json(),
            },
        }
    }

    pub fn bulk_restore_from_json(&mut self, data: &ContactManagerJson) -> Result<()> {
        self.contact_repo.bulk_save(&data.contacts.contacts)?;
        self.group_repo.bulk_save(&data.groups.groups)?;
        self.hydrate()?;
        Ok(())
    }

    pub fn from_json(
        data: &ContactManagerJson,
        contact_repo: Box<dyn ContactRepo>,
        group_repo: Box<dyn GroupRepo>,
    ) -> Result<Self> {
        let mut manager = Self::new(contact_repo, group_repo);
        manager.bulk_restore_from_json(data)?;
        Ok(manager)
    }
}
