//! Group manager. Port of `MajikContactGroupManager`.
//!
//! In TS the manager holds a shared reference to the directory. Rust ownership makes that a
//! `&ContactDirectory` / `&mut ContactDirectory` argument instead: the owning `ContactManager`
//! passes its directory in, so there is exactly one owner and no interior mutability.

use std::collections::{HashMap, HashSet};

use indexmap::{IndexMap, IndexSet};
use majik_contact::{
    is_system_group_id, MajikContact, MajikContactGroup, PartialMajikContactGroupMeta,
    SerializedMajikContactGroup, SYSTEM_GROUP_ID_BLOCKED, SYSTEM_GROUP_ID_FAVORITES,
};

use super::directory::ContactDirectory;
use super::error::{ContactManagerError, Result};

fn gerr(msg: impl Into<String>) -> ContactManagerError {
    ContactManagerError::Groups(msg.into())
}

fn assert_group_id(id: &str) -> Result<()> {
    if id.trim().is_empty() {
        return Err(gerr("Group ID must be a non-empty string"));
    }
    Ok(())
}

fn assert_contact_id(id: &str) -> Result<()> {
    if id.trim().is_empty() {
        return Err(gerr("Contact ID must be a non-empty string"));
    }
    Ok(())
}

fn assert_not_system(id: &str, caller: &str) -> Result<()> {
    if is_system_group_id(id) {
        return Err(gerr(format!(
            "{caller}: cannot perform this operation on system group \"{id}\""
        )));
    }
    Ok(())
}

fn require_contact<'a>(
    dir: &'a ContactDirectory,
    contact_id: &str,
    caller: &str,
) -> Result<&'a MajikContact> {
    dir.get_contact(contact_id).ok_or_else(|| {
        gerr(format!(
            "{caller}: contact \"{contact_id}\" does not exist in the directory"
        ))
    })
}

fn assert_contacts_exist(dir: &ContactDirectory, ids: &[String], caller: &str) -> Result<()> {
    let missing: Vec<&str> = ids
        .iter()
        .filter(|id| !dir.has_contact(id))
        .map(String::as_str)
        .collect();
    if !missing.is_empty() {
        return Err(gerr(format!(
            "{caller}: the following contacts do not exist in the directory: {}",
            missing.join(", ")
        )));
    }
    Ok(())
}

pub struct GroupManager {
    groups: IndexMap<String, MajikContactGroup>,
    /// contact id -> ids of the groups it belongs to
    index: HashMap<String, IndexSet<String>>,
}

impl Default for GroupManager {
    fn default() -> Self {
        Self::new()
    }
}

impl GroupManager {
    /// Starts with the two system groups (Favorites, Blocked).
    pub fn new() -> Self {
        let mut m = Self {
            groups: IndexMap::new(),
            index: HashMap::new(),
        };
        m.bootstrap_system_groups();
        m
    }

    fn bootstrap_system_groups(&mut self) {
        if !self.groups.contains_key(SYSTEM_GROUP_ID_FAVORITES) {
            let g = MajikContactGroup::create_favorites();
            self.groups.insert(g.id().to_string(), g);
        }
        if !self.groups.contains_key(SYSTEM_GROUP_ID_BLOCKED) {
            let g = MajikContactGroup::create_blocked();
            self.groups.insert(g.id().to_string(), g);
        }
    }

    // ── Index ────────────────────────────────────────────────────────────────

    fn index_add(&mut self, contact_id: &str, group_id: &str) {
        self.index
            .entry(contact_id.to_string())
            .or_default()
            .insert(group_id.to_string());
    }

    fn index_remove(&mut self, contact_id: &str, group_id: &str) {
        if let Some(set) = self.index.get_mut(contact_id) {
            set.shift_remove(group_id);
            if set.is_empty() {
                self.index.remove(contact_id);
            }
        }
    }

    fn group_mut(&mut self, id: &str) -> Result<&mut MajikContactGroup> {
        self.groups
            .get_mut(id)
            .ok_or_else(|| gerr(format!("Group \"{id}\" not found")))
    }

    fn get_ref(&self, id: &str) -> Result<&MajikContactGroup> {
        self.groups
            .get(id)
            .ok_or_else(|| gerr(format!("Group \"{id}\" not found")))
    }

    /// Adding to the Blocked group blocks the contact (TS parity).
    fn block_if_blocked_group(dir: &mut ContactDirectory, group_id: &str, contact_id: &str) {
        if group_id == SYSTEM_GROUP_ID_BLOCKED {
            if let Some(c) = dir.get_contact_mut(contact_id) {
                if !c.is_blocked() {
                    c.block();
                }
            }
        }
    }

    /// After leaving Blocked, unblock the contact unless it is somehow still a member.
    fn sync_unblock(&self, dir: &mut ContactDirectory, contact_id: &str) {
        let still_blocked = self
            .groups
            .get(SYSTEM_GROUP_ID_BLOCKED)
            .map(|g| g.has_member(contact_id).unwrap_or(false))
            .unwrap_or(false);
        if !still_blocked {
            if let Some(c) = dir.get_contact_mut(contact_id) {
                if c.is_blocked() {
                    c.unblock();
                }
            }
        }
    }

    // ── Group lifecycle ──────────────────────────────────────────────────────

    pub fn create_group(
        &mut self,
        dir: &ContactDirectory,
        id: &str,
        name: &str,
        meta: Option<PartialMajikContactGroupMeta>,
        initial_member_ids: Option<Vec<String>>,
    ) -> Result<&MajikContactGroup> {
        assert_group_id(id)?;
        assert_not_system(id, "createGroup")?;
        if self.groups.contains_key(id) {
            return Err(gerr(format!("Group with id \"{id}\" already exists")));
        }
        let members = initial_member_ids.filter(|m| !m.is_empty());
        if let Some(ids) = &members {
            assert_contacts_exist(dir, ids, "createGroup")?;
        }
        let group = MajikContactGroup::create(id, name, meta, members)?;
        for cid in group.list_member_ids() {
            self.index_add(&cid, id);
        }
        self.groups.insert(id.to_string(), group);
        self.get_ref(id)
    }

    pub fn add_group(
        &mut self,
        dir: &ContactDirectory,
        group: MajikContactGroup,
    ) -> Result<&MajikContactGroup> {
        let id = group.id().to_string();
        assert_not_system(&id, "addGroup")?;
        if self.groups.contains_key(&id) {
            return Err(gerr(format!("Group with id \"{id}\" already exists")));
        }
        let members = group.list_member_ids();
        if !members.is_empty() {
            assert_contacts_exist(dir, &members, "addGroup")?;
        }
        for cid in &members {
            self.index_add(cid, &id);
        }
        self.groups.insert(id.clone(), group);
        self.get_ref(&id)
    }

    /// `Ok(None)` when the group does not exist. System groups cannot be removed.
    pub fn remove_group(&mut self, id: &str) -> Result<Option<MajikContactGroup>> {
        assert_group_id(id)?;
        assert_not_system(id, "removeGroup")?;
        let Some(group) = self.groups.shift_remove(id) else {
            return Ok(None);
        };
        for cid in group.list_member_ids() {
            self.index_remove(&cid, id);
        }
        Ok(Some(group))
    }

    /// Drops every group, system groups included (the TS `clear()`); the owning manager is
    /// expected to re-bootstrap via [`restore`](Self::restore) or by constructing a new manager.
    pub fn clear(&mut self) {
        self.groups.clear();
        self.index.clear();
    }

    pub fn get_group(&self, id: &str) -> Option<&MajikContactGroup> {
        self.groups.get(id)
    }

    pub fn get_group_or_err(&self, id: &str) -> Result<&MajikContactGroup> {
        self.get_ref(id)
    }

    pub fn has_group(&self, id: &str) -> bool {
        self.groups.contains_key(id)
    }

    pub fn list_groups(&self, include_system: bool, sorted_by_name: bool) -> Vec<&MajikContactGroup> {
        let mut out: Vec<&MajikContactGroup> = self
            .groups
            .values()
            .filter(|g| include_system || !g.is_system())
            .collect();
        if sorted_by_name {
            out.sort_by_key(|g| g.meta.name.to_lowercase());
        }
        out
    }

    /// `color`: when `None` or empty, the existing color is kept (TS `setColor(color || current)`).
    pub fn update_group_meta(
        &mut self,
        id: &str,
        name: Option<&str>,
        description: Option<&str>,
        color: Option<&str>,
    ) -> Result<&MajikContactGroup> {
        let group = self.group_mut(id)?;
        if let Some(n) = name {
            group.update_name(n)?;
        }
        if let Some(d) = description {
            group.update_description(d);
        }
        let color = color
            .filter(|c| !c.is_empty())
            .map(str::to_string)
            .or_else(|| group.meta.color.clone());
        group.set_color(color.as_deref());
        self.get_ref(id)
    }

    // ── Membership ───────────────────────────────────────────────────────────

    pub fn add_contact_to_group(
        &mut self,
        dir: &mut ContactDirectory,
        group_id: &str,
        contact_id: &str,
    ) -> Result<&MajikContactGroup> {
        assert_group_id(group_id)?;
        assert_contact_id(contact_id)?;
        self.get_ref(group_id)?;
        require_contact(dir, contact_id, "addContactToGroup")?;
        self.group_mut(group_id)?.add_member(contact_id)?;
        self.index_add(contact_id, group_id);
        Self::block_if_blocked_group(dir, group_id, contact_id);
        self.get_ref(group_id)
    }

    pub fn add_contact_to_group_if_absent(
        &mut self,
        dir: &mut ContactDirectory,
        group_id: &str,
        contact_id: &str,
    ) -> Result<&MajikContactGroup> {
        assert_group_id(group_id)?;
        assert_contact_id(contact_id)?;
        let present = self.get_ref(group_id)?.has_member(contact_id)?;
        require_contact(dir, contact_id, "addContactToGroupIfAbsent")?;
        if !present {
            self.group_mut(group_id)?.add_member(contact_id)?;
            self.index_add(contact_id, group_id);
            Self::block_if_blocked_group(dir, group_id, contact_id);
        }
        self.get_ref(group_id)
    }

    /// All-or-nothing: every id must be valid, unique, existing and not already a member.
    pub fn add_contacts_to_group(
        &mut self,
        dir: &mut ContactDirectory,
        group_id: &str,
        contact_ids: &[String],
    ) -> Result<&MajikContactGroup> {
        assert_group_id(group_id)?;
        if contact_ids.is_empty() {
            return Err(gerr("addContactsToGroup: contactIds array must not be empty"));
        }
        for (i, id) in contact_ids.iter().enumerate() {
            if id.trim().is_empty() {
                return Err(gerr(format!(
                    "addContactsToGroup: invalid contact ID at index {i}"
                )));
            }
        }
        let unique: HashSet<&String> = contact_ids.iter().collect();
        if unique.len() != contact_ids.len() {
            return Err(gerr("addContactsToGroup: contactIds must not contain duplicates"));
        }
        let group = self.get_ref(group_id)?;
        for id in contact_ids {
            require_contact(dir, id, "addContactsToGroup")?;
        }
        let already: Vec<&str> = contact_ids
            .iter()
            .filter(|id| group.has_member(id).unwrap_or(false))
            .map(String::as_str)
            .collect();
        if !already.is_empty() {
            return Err(gerr(format!(
                "addContactsToGroup: the following contacts are already members of \"{}\": {}",
                group.meta.name,
                already.join(", ")
            )));
        }
        for id in contact_ids {
            self.group_mut(group_id)?.add_member(id)?;
            self.index_add(id, group_id);
            Self::block_if_blocked_group(dir, group_id, id);
        }
        self.get_ref(group_id)
    }

    /// Errors if the contact is not a member.
    pub fn remove_contact_from_group(
        &mut self,
        dir: &mut ContactDirectory,
        group_id: &str,
        contact_id: &str,
    ) -> Result<&MajikContactGroup> {
        assert_group_id(group_id)?;
        assert_contact_id(contact_id)?;
        self.group_mut(group_id)?.remove_member(contact_id)?;
        self.index_remove(contact_id, group_id);
        if group_id == SYSTEM_GROUP_ID_BLOCKED {
            self.sync_unblock(dir, contact_id);
        }
        self.get_ref(group_id)
    }

    pub fn remove_contact_from_group_if_present(
        &mut self,
        dir: &mut ContactDirectory,
        group_id: &str,
        contact_id: &str,
    ) -> Result<&MajikContactGroup> {
        assert_group_id(group_id)?;
        assert_contact_id(contact_id)?;
        let present = self.get_ref(group_id)?.has_member(contact_id)?;
        if present {
            self.group_mut(group_id)?.remove_member(contact_id)?;
            self.index_remove(contact_id, group_id);
            if group_id == SYSTEM_GROUP_ID_BLOCKED {
                self.sync_unblock(dir, contact_id);
            }
        }
        self.get_ref(group_id)
    }

    pub fn move_contact(
        &mut self,
        dir: &mut ContactDirectory,
        contact_id: &str,
        from_group_id: &str,
        to_group_id: &str,
    ) -> Result<()> {
        assert_contact_id(contact_id)?;
        assert_group_id(from_group_id)?;
        assert_group_id(to_group_id)?;
        if from_group_id == to_group_id {
            return Err(gerr("moveContact: source and destination groups must be different"));
        }
        require_contact(dir, contact_id, "moveContact")?;
        let from = self.get_ref(from_group_id)?;
        self.get_ref(to_group_id)?;
        if !from.has_member(contact_id)? {
            return Err(gerr(format!(
                "moveContact: contact \"{contact_id}\" is not a member of group \"{from_group_id}\""
            )));
        }
        self.remove_contact_from_group(dir, from_group_id, contact_id)?;
        self.add_contact_to_group_if_absent(dir, to_group_id, contact_id)?;
        Ok(())
    }

    // ── Queries ──────────────────────────────────────────────────────────────

    pub fn get_group_ids_for_contact(&self, contact_id: &str) -> Result<Vec<String>> {
        assert_contact_id(contact_id)?;
        Ok(self
            .index
            .get(contact_id)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default())
    }

    pub fn get_groups_for_contact(&self, contact_id: &str) -> Result<Vec<&MajikContactGroup>> {
        assert_contact_id(contact_id)?;
        Ok(self
            .index
            .get(contact_id)
            .map(|ids| ids.iter().filter_map(|id| self.groups.get(id)).collect())
            .unwrap_or_default())
    }

    pub fn get_contacts_in_group<'a>(
        &self,
        dir: &'a ContactDirectory,
        group_id: &str,
    ) -> Result<Vec<&'a MajikContact>> {
        let group = self.get_ref(group_id)?;
        Ok(group
            .list_member_ids()
            .iter()
            .filter_map(|id| dir.get_contact(id))
            .collect())
    }

    /// Sorted by label, falling back to id (case-insensitive).
    pub fn get_contacts_in_group_sorted<'a>(
        &self,
        dir: &'a ContactDirectory,
        group_id: &str,
    ) -> Result<Vec<&'a MajikContact>> {
        let mut contacts = self.get_contacts_in_group(dir, group_id)?;
        contacts.sort_by_key(|c| {
            match c.meta.label.as_deref() {
                Some(l) if !l.is_empty() => l.to_lowercase(),
                _ => c.id().to_lowercase(),
            }
        });
        Ok(contacts)
    }

    pub fn is_contact_in_group(&self, group_id: &str, contact_id: &str) -> Result<bool> {
        assert_group_id(group_id)?;
        assert_contact_id(contact_id)?;
        match self.groups.get(group_id) {
            Some(g) => Ok(g.has_member(contact_id)?),
            None => Ok(false),
        }
    }

    pub fn is_favorite(&self, contact_id: &str) -> Result<bool> {
        self.is_contact_in_group(SYSTEM_GROUP_ID_FAVORITES, contact_id)
    }

    pub fn is_blocked(&self, contact_id: &str) -> Result<bool> {
        self.is_contact_in_group(SYSTEM_GROUP_ID_BLOCKED, contact_id)
    }

    pub fn get_favorites_group(&self) -> Result<&MajikContactGroup> {
        self.get_ref(SYSTEM_GROUP_ID_FAVORITES)
    }

    pub fn get_blocked_group(&self) -> Result<&MajikContactGroup> {
        self.get_ref(SYSTEM_GROUP_ID_BLOCKED)
    }

    // ── System-group shortcuts ───────────────────────────────────────────────

    pub fn add_to_favorites(
        &mut self,
        dir: &mut ContactDirectory,
        contact_id: &str,
    ) -> Result<&MajikContactGroup> {
        self.add_contact_to_group_if_absent(dir, SYSTEM_GROUP_ID_FAVORITES, contact_id)
    }

    pub fn remove_from_favorites(
        &mut self,
        dir: &mut ContactDirectory,
        contact_id: &str,
    ) -> Result<&MajikContactGroup> {
        self.remove_contact_from_group_if_present(dir, SYSTEM_GROUP_ID_FAVORITES, contact_id)
    }

    /// Group-level block (adds to Blocked, which also marks the contact blocked).
    pub fn block_contact(
        &mut self,
        dir: &mut ContactDirectory,
        contact_id: &str,
    ) -> Result<&MajikContactGroup> {
        self.add_contact_to_group_if_absent(dir, SYSTEM_GROUP_ID_BLOCKED, contact_id)
    }

    pub fn unblock_contact(
        &mut self,
        dir: &mut ContactDirectory,
        contact_id: &str,
    ) -> Result<&MajikContactGroup> {
        self.remove_contact_from_group_if_present(dir, SYSTEM_GROUP_ID_BLOCKED, contact_id)
    }

    // ── Maintenance ──────────────────────────────────────────────────────────

    /// Remove a deleted contact from every group it was in.
    pub fn handle_contact_removed(&mut self, contact_id: &str) -> Result<()> {
        assert_contact_id(contact_id)?;
        if let Some(group_ids) = self.index.remove(contact_id) {
            for gid in group_ids {
                if let Some(group) = self.groups.get_mut(&gid) {
                    group.remove_member_if_present(contact_id)?;
                }
            }
        }
        Ok(())
    }

    /// Drop group members that no longer exist in the directory (run after hydration).
    pub fn prune_orphaned_members(&mut self, dir: &ContactDirectory) -> Result<()> {
        let group_ids: Vec<String> = self.groups.keys().cloned().collect();
        for gid in group_ids {
            let orphans: Vec<String> = self
                .get_ref(&gid)?
                .list_member_ids()
                .into_iter()
                .filter(|id| !dir.has_contact(id))
                .collect();
            for orphan in orphans {
                if let Some(group) = self.groups.get_mut(&gid) {
                    group.remove_member_if_present(&orphan)?;
                }
                self.handle_contact_removed(&orphan)?;
            }
        }
        Ok(())
    }

    // ── Serialization ────────────────────────────────────────────────────────

    pub fn to_json(&self) -> Vec<SerializedMajikContactGroup> {
        self.groups.values().map(|g| g.to_json()).collect()
    }

    /// Replace all custom groups with `data`; system groups are kept and their membership is
    /// replaced by the serialized one. Errors on an invalid entry or a duplicate group id.
    pub fn restore(&mut self, data: Vec<SerializedMajikContactGroup>) -> Result<()> {
        self.groups.retain(|id, _| is_system_group_id(id));
        self.index.clear();
        self.bootstrap_system_groups();

        for serialized in data {
            if serialized.id.is_empty() {
                return Err(gerr("fromJSON: encountered an invalid serialized group entry"));
            }
            let id = serialized.id.clone();
            let group = MajikContactGroup::from_json(serialized).map_err(|e| {
                gerr(format!("fromJSON: failed to restore group \"{id}\": {e}"))
            })?;
            let members = group.list_member_ids();

            if is_system_group_id(group.id()) {
                {
                    let existing = self.group_mut(&id)?;
                    existing.clear_members();
                    for cid in &members {
                        existing.add_member_if_absent(cid)?;
                    }
                }
                for cid in &members {
                    self.index_add(cid, &id);
                }
            } else {
                if self.groups.contains_key(&id) {
                    return Err(gerr(format!("fromJSON: duplicate group id \"{id}\"")));
                }
                self.groups.insert(id.clone(), group);
                for cid in &members {
                    self.index_add(cid, &id);
                }
            }
        }
        Ok(())
    }
}
