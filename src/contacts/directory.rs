//! In-memory contact directory. Port of `MajikContactDirectory`: contacts by id (insertion
//! ordered, like the TS `Map`) plus a fingerprint index.
//!
//! Differences from TS, all deliberate:
//!  * Lookups (`get_contact`, `get_contact_by_fingerprint`, `get_contact_by_address`) return
//!    `Option` for an empty argument instead of throwing.
//!  * `add_contacts` is atomic: validated up front, so a bad entry leaves the directory untouched
//!    (TS added the earlier entries before throwing).
//!  * Restoring from JSON keeps `majikah_registered` (the TS `fromJSON`/`hydrate` rebuilt contacts
//!    without it, silently resetting the cached registration state).
//!  * Label sorting is case-insensitive ordinal, not ICU `localeCompare`.

use std::collections::{HashMap, HashSet};

use indexmap::IndexMap;
use majik_contact::{MajikApiResponse, MajikContact, MajikContactMeta, SerializedMajikContact};
use serde::Serialize;

use super::error::{ContactManagerError, Result};

pub(crate) fn api_response(success: bool, message: impl Into<String>) -> MajikApiResponse {
    MajikApiResponse {
        success,
        message: message.into(),
        code: None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SkippedContact {
    pub id: String,
    pub reason: String,
}

fn dir_err(msg: impl Into<String>) -> ContactManagerError {
    ContactManagerError::Directory(msg.into())
}

fn assert_id(id: &str) -> Result<()> {
    if id.is_empty() {
        return Err(dir_err("Contact ID must be a non-empty string"));
    }
    Ok(())
}

fn validate(contact: &MajikContact) -> Result<()> {
    if contact.id().is_empty()
        || contact.public_key().raw.is_empty()
        || contact.fingerprint().is_empty()
        || contact.ml_key().is_empty()
    {
        return Err(dir_err("Invalid contact"));
    }
    Ok(())
}

#[derive(Default)]
pub struct ContactDirectory {
    contacts: IndexMap<String, MajikContact>,
    /// fingerprint -> contact id
    fingerprints: HashMap<String, String>,
}

impl ContactDirectory {
    pub fn new() -> Self {
        Self::default()
    }

    // ── Mutation ─────────────────────────────────────────────────────────────

    pub fn add_contact(&mut self, contact: MajikContact) -> Result<()> {
        validate(&contact)?;
        if self.contacts.contains_key(contact.id()) {
            return Err(dir_err(format!(
                "Contact with id \"{}\" already exists",
                contact.id()
            )));
        }
        self.insert(contact);
        Ok(())
    }

    /// Atomic: nothing is added unless every contact is valid and unique.
    pub fn add_contacts(&mut self, contacts: Vec<MajikContact>) -> Result<()> {
        let mut seen: HashSet<&str> = HashSet::new();
        for c in &contacts {
            validate(c)?;
            if self.contacts.contains_key(c.id()) || !seen.insert(c.id()) {
                return Err(dir_err(format!(
                    "Contact with id \"{}\" already exists",
                    c.id()
                )));
            }
        }
        for c in contacts {
            self.insert(c);
        }
        Ok(())
    }

    fn insert(&mut self, contact: MajikContact) {
        self.fingerprints
            .insert(contact.fingerprint().to_string(), contact.id().to_string());
        self.contacts.insert(contact.id().to_string(), contact);
    }

    pub fn remove_contact(&mut self, id: &str) -> Result<MajikApiResponse> {
        assert_id(id)?;
        match self.contacts.shift_remove(id) {
            Some(contact) => {
                if self.fingerprints.get(contact.fingerprint()).map(String::as_str) == Some(id) {
                    self.fingerprints.remove(contact.fingerprint());
                }
                Ok(api_response(true, "Contact removed successfully"))
            }
            None => Ok(api_response(false, "Contact not found")),
        }
    }

    /// Applies only what TS applied: a non-empty `label`, a non-empty `notes`, and `blocked`.
    pub fn update_contact_meta(
        &mut self,
        id: &str,
        meta: &MajikContactMeta,
    ) -> Result<&MajikContact> {
        let contact = self
            .contacts
            .get_mut(id)
            .ok_or_else(|| dir_err("Contact not found"))?;
        if let Some(label) = meta.label.as_deref().filter(|l| !l.is_empty()) {
            contact.update_label(label);
        }
        if let Some(notes) = meta.notes.as_deref().filter(|n| !n.is_empty()) {
            contact.update_notes(notes);
        }
        if let Some(blocked) = meta.blocked {
            contact.set_blocked(blocked);
        }
        Ok(contact)
    }

    pub fn block_contact(&mut self, id: &str) -> Result<&MajikContact> {
        let contact = self
            .contacts
            .get_mut(id)
            .ok_or_else(|| dir_err(format!("Contact with id \"{id}\" not found for block")))?;
        contact.block();
        Ok(contact)
    }

    pub fn unblock_contact(&mut self, id: &str) -> Result<&MajikContact> {
        let contact = self
            .contacts
            .get_mut(id)
            .ok_or_else(|| dir_err(format!("Contact with id \"{id}\" not found for unblock")))?;
        contact.unblock();
        Ok(contact)
    }

    pub fn set_majikah_status(&mut self, id: &str, status: bool) -> Result<&MajikContact> {
        let contact = self
            .contacts
            .get_mut(id)
            .ok_or_else(|| dir_err("Contact not found"))?;
        contact.set_majikah_status(status);
        Ok(contact)
    }

    pub fn clear(&mut self) {
        self.contacts.clear();
        self.fingerprints.clear();
    }

    // ── Queries ──────────────────────────────────────────────────────────────

    pub fn get_contact(&self, id: &str) -> Option<&MajikContact> {
        self.contacts.get(id)
    }

    pub fn get_contact_mut(&mut self, id: &str) -> Option<&mut MajikContact> {
        self.contacts.get_mut(id)
    }

    pub fn get_contact_by_fingerprint(&self, fingerprint: &str) -> Option<&MajikContact> {
        let id = self.fingerprints.get(fingerprint)?;
        self.contacts.get(id)
    }

    /// Matches the base64 X25519 public key (`MajikKeyAddress`).
    pub fn get_contact_by_address(&self, address: &str) -> Option<&MajikContact> {
        if address.is_empty() {
            return None;
        }
        self.contacts.values().find(|c| c.address() == address)
    }

    pub fn has_contact(&self, id: &str) -> bool {
        self.contacts.contains_key(id)
    }

    pub fn has_fingerprint(&self, fingerprint: &str) -> bool {
        self.fingerprints.contains_key(fingerprint)
    }

    pub fn has_contact_by_address(&self, address: &str) -> bool {
        self.get_contact_by_address(address).is_some()
    }

    pub fn len(&self) -> usize {
        self.contacts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.contacts.is_empty()
    }

    pub fn list_contacts(&self, sorted_by_label: bool, majikah_only: bool) -> Vec<&MajikContact> {
        let mut out: Vec<&MajikContact> = self
            .contacts
            .values()
            .filter(|c| !majikah_only || c.is_majikah_registered())
            .collect();
        if sorted_by_label {
            out.sort_by_key(|c| c.meta.label.as_deref().unwrap_or("").to_lowercase());
        }
        out
    }

    pub fn is_majikah_identity_checked(&self, id: &str) -> Result<bool> {
        self.contacts
            .get(id)
            .map(|c| c.is_majikah_identity_checked())
            .ok_or_else(|| dir_err("Contact not found"))
    }

    pub fn is_majikah_registered(&self, id: &str) -> Result<bool> {
        self.contacts
            .get(id)
            .map(|c| c.is_majikah_registered())
            .ok_or_else(|| dir_err("Contact not found"))
    }

    // ── Serialization ────────────────────────────────────────────────────────

    pub fn to_json(&self) -> Vec<SerializedMajikContact> {
        self.contacts.values().map(|c| c.to_json()).collect()
    }

    /// Replace the directory contents. Malformed entries are skipped and reported (TS only
    /// `console.warn`ed); a later duplicate id wins, like the TS `Map.set`.
    pub fn replace_from_json(&mut self, items: Vec<SerializedMajikContact>) -> Vec<SkippedContact> {
        self.clear();
        let mut skipped = Vec::new();
        for item in items {
            let id = item.id.clone();
            // `MajikContact::from_json` accepts e.g. an empty public key, so apply the same
            // validation as `add_contact` before trusting a stored row.
            let parsed = MajikContact::from_json(item)
                .map_err(ContactManagerError::from)
                .and_then(|c| validate(&c).map(|()| c));
            match parsed {
                Ok(contact) => self.insert(contact),
                Err(e) => skipped.push(SkippedContact {
                    id,
                    reason: e.to_string(),
                }),
            }
        }
        skipped
    }
}
