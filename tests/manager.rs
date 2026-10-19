//! Behavioural tests for the contact manager (in-memory and SQLite repositories).

use std::io::Write;
use std::sync::{Arc, Mutex};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use majik_signature_client::contacts::majik_contact::{
    MajikContact, MajikContactData, MajikContactGroup, MajikContactMeta, X25519RawKey,
    SYSTEM_GROUP_ID_BLOCKED, SYSTEM_GROUP_ID_FAVORITES,
};
use majik_signature_client::contacts::{
    init_schema, ContactManager, ContactManagerError, MemoryContactRepo, MemoryGroupRepo,
    SharedConnection,
};
use rusqlite::Connection;

fn contact(id: &str, label: &str) -> MajikContact {
    let mut raw = vec![0u8; 32];
    for (i, b) in id.bytes().enumerate() {
        raw[i % 32] ^= b.wrapping_add(i as u8).wrapping_add(1);
    }
    MajikContact::new(MajikContactData {
        id: id.to_string(),
        public_key: X25519RawKey::new(raw),
        fingerprint: format!("fp-{id}"),
        ml_key: "ml-key".to_string(),
        meta: Some(MajikContactMeta {
            label: Some(label.to_string()),
            ..Default::default()
        }),
        majikah_registered: None,
        ed_public_key_base64: Some("ed".to_string()),
        ml_dsa_public_key_base64: Some("mldsa".to_string()),
    })
    .unwrap()
}

fn manager_with(ids: &[&str]) -> ContactManager {
    let mut m = ContactManager::in_memory();
    for id in ids {
        m.add_contact(contact(id, &id.to_uppercase())).unwrap();
    }
    m
}

fn shared_conn() -> SharedConnection {
    Arc::new(Mutex::new(Connection::open_in_memory().unwrap()))
}

#[test]
fn add_query_and_remove_contacts() {
    let mut m = manager_with(&["a", "b"]);
    assert!(m.has_contact("a") && m.has_fingerprint("fp-b"));
    assert_eq!(m.get_contact_by_fingerprint("fp-a").unwrap().id(), "a");
    let addr = m.get_contact("b").unwrap().address();
    assert_eq!(m.get_contact_by_address(&addr).unwrap().id(), "b");
    assert!(m.has_contact_by_address(&addr));

    let err = m.add_contact(contact("a", "dup")).unwrap_err();
    assert!(matches!(err, ContactManagerError::Directory(_)));

    assert!(m.remove_contact("a").unwrap().success);
    assert!(!m.remove_contact("a").unwrap().success);
    assert!(!m.has_fingerprint("fp-a"));
    assert_eq!(m.list_contacts(false, false).len(), 1);
}

#[test]
fn add_contacts_is_atomic() {
    let mut m = manager_with(&["a"]);
    let err = m
        .add_contacts(vec![contact("b", "B"), contact("a", "dup")])
        .unwrap_err();
    assert!(matches!(err, ContactManagerError::Directory(_)));
    assert!(!m.has_contact("b"), "no partial add");

    m.add_contacts(vec![contact("b", "B"), contact("c", "C")]).unwrap();
    assert_eq!(m.list_contacts(false, false).len(), 3);
}

#[test]
fn list_sorted_by_label_and_majikah_filter() {
    let mut m = ContactManager::in_memory();
    m.add_contact(contact("1", "charlie")).unwrap();
    m.add_contact(contact("2", "Alice")).unwrap();
    m.add_contact(contact("3", "bob")).unwrap();
    let labels: Vec<String> = m
        .list_contacts(true, false)
        .iter()
        .map(|c| c.meta.label.clone().unwrap())
        .collect();
    assert_eq!(labels, vec!["Alice", "bob", "charlie"]);

    m.set_majikah_status("2", true).unwrap();
    let only: Vec<&str> = m.list_contacts(false, true).iter().map(|c| c.id()).collect();
    assert_eq!(only, vec!["2"]);
    assert!(m.is_majikah_registered("2").unwrap());
}

#[test]
fn update_meta_ignores_empty_label_and_notes() {
    let mut m = manager_with(&["a"]);
    m.update_contact_meta(
        "a",
        &MajikContactMeta {
            label: Some(String::new()),
            notes: Some("note".into()),
            ..Default::default()
        },
    )
    .unwrap();
    let c = m.get_contact("a").unwrap();
    assert_eq!(c.meta.label.as_deref(), Some("A"), "empty label ignored");
    assert_eq!(c.meta.notes.as_deref(), Some("note"));
    assert!(m.update_contact_meta("zzz", &MajikContactMeta::default()).is_err());
}

#[test]
fn blocking_syncs_contact_and_blocked_group() {
    let mut m = manager_with(&["a", "b"]);
    m.block_contact("a").unwrap();
    assert!(m.get_contact("a").unwrap().is_blocked());
    assert!(m.is_contact_blocked("a").unwrap());
    assert_eq!(m.get_blocked_contacts().unwrap().len(), 1);

    m.unblock_contact("a").unwrap();
    assert!(!m.get_contact("a").unwrap().is_blocked());
    assert!(!m.is_contact_blocked("a").unwrap());

    // Adding to the Blocked group directly blocks the contact; removing unblocks it.
    m.add_contact_to_group(SYSTEM_GROUP_ID_BLOCKED, "b").unwrap();
    assert!(m.get_contact("b").unwrap().is_blocked());
    m.remove_contact_from_group(SYSTEM_GROUP_ID_BLOCKED, "b").unwrap();
    assert!(!m.get_contact("b").unwrap().is_blocked());
}

#[test]
fn group_lifecycle_and_system_group_protection() {
    let mut m = manager_with(&["a", "b", "c"]);
    let g = m
        .create_group("g1", "Work", None, Some(vec!["a".into(), "b".into()]))
        .unwrap();
    assert_eq!(g.member_count(), 2);
    assert!(m.create_group("g1", "Dup", None, None).is_err());
    assert!(m.create_group("g2", "Bad", None, Some(vec!["nope".into()])).is_err());
    assert!(m.create_group(SYSTEM_GROUP_ID_FAVORITES, "x", None, None).is_err());
    assert!(m.remove_group(SYSTEM_GROUP_ID_BLOCKED).is_err());

    m.add_contact_to_group("g1", "c").unwrap();
    assert!(m.add_contact_to_group("g1", "c").is_err(), "already a member");
    assert!(m.add_contact_to_group_if_absent("g1", "c").is_ok());
    assert_eq!(m.get_group_ids_for_contact("c").unwrap(), vec!["g1".to_string()]);

    m.create_group("g2", "Home", None, None).unwrap();
    m.move_contact_between_groups("c", "g1", "g2").unwrap();
    assert!(!m.is_contact_in_group("g1", "c").unwrap());
    assert!(m.is_contact_in_group("g2", "c").unwrap());
    assert!(m.move_contact_between_groups("c", "g2", "g2").is_err());

    let names: Vec<String> = m
        .list_user_groups(true)
        .iter()
        .map(|g| g.meta.name.clone())
        .collect();
    assert_eq!(names, vec!["Home", "Work"]);
    assert_eq!(m.list_system_groups().len(), 2);

    m.update_group_meta("g1", Some("Office"), Some("desc"), Some("#fff")).unwrap();
    m.update_group_meta("g1", None, None, None).unwrap();
    assert_eq!(m.get_group("g1").unwrap().meta.color.as_deref(), Some("#fff"), "color kept");

    assert!(m.remove_group("g1").unwrap().success);
    assert!(!m.remove_group("g1").unwrap().success);
    assert!(m.get_group_ids_for_contact("a").unwrap().is_empty());
}

#[test]
fn add_contacts_to_group_is_all_or_nothing() {
    let mut m = manager_with(&["a", "b"]);
    m.create_group("g", "G", None, Some(vec!["a".into()])).unwrap();
    assert!(m.add_contacts_to_group("g", &["b".into(), "a".into()]).is_err());
    assert!(!m.is_contact_in_group("g", "b").unwrap(), "b not added");
    assert!(m.add_contacts_to_group("g", &["b".into(), "b".into()]).is_err());
    assert!(m.add_contacts_to_group("g", &[]).is_err());
    m.add_contacts_to_group("g", &["b".into()]).unwrap();
    assert_eq!(m.get_contacts_in_group_sorted("g").unwrap().len(), 2);
}

#[test]
fn favorites() {
    let mut m = manager_with(&["a"]);
    m.add_to_favorites("a").unwrap();
    m.add_to_favorites("a").unwrap(); // idempotent
    assert!(m.is_favorite("a").unwrap());
    assert_eq!(m.get_favorite_contacts().unwrap().len(), 1);
    m.remove_from_favorites("a").unwrap();
    assert!(!m.is_favorite("a").unwrap());
}

#[test]
fn removing_a_contact_removes_it_from_groups_and_storage() {
    let conn = shared_conn();
    let mut m = ContactManager::with_sqlite(Arc::clone(&conn)).unwrap();
    m.add_contact(contact("a", "A")).unwrap();
    m.create_group("g", "G", None, Some(vec!["a".into()])).unwrap();
    m.add_to_favorites("a").unwrap();

    assert!(m.remove_contact("a").unwrap().success);
    assert!(!m.is_favorite("a").unwrap());
    assert_eq!(m.get_group("g").unwrap().member_count(), 0);

    let mut m2 = ContactManager::with_sqlite(conn).unwrap();
    let report = m2.hydrate().unwrap();
    assert_eq!(report.contacts_loaded, 0);
    assert_eq!(m2.get_group("g").unwrap().member_count(), 0);
    assert_eq!(m2.get_favorites_group().unwrap().member_count(), 0);
}

#[test]
fn sqlite_roundtrip_preserves_everything_including_majikah_status() {
    let conn = shared_conn();
    {
        let mut m = ContactManager::with_sqlite(Arc::clone(&conn)).unwrap();
        m.add_contact(contact("a", "Alice")).unwrap();
        m.add_contact(contact("b", "Bob")).unwrap();
        m.set_majikah_status("a", true).unwrap();
        m.block_contact("b").unwrap();
        m.create_group("g", "Friends", None, Some(vec!["a".into()])).unwrap();
        m.add_to_favorites("a").unwrap();
    }
    let mut m2 = ContactManager::with_sqlite(conn).unwrap();
    let report = m2.hydrate().unwrap();
    assert_eq!(report.contacts_loaded, 2);
    assert!(report.contacts_skipped.is_empty());

    assert!(m2.is_majikah_registered("a").unwrap(), "registration state survives restart");
    assert!(m2.get_contact("b").unwrap().is_blocked());
    assert!(m2.is_contact_blocked("b").unwrap());
    assert!(m2.is_favorite("a").unwrap());
    assert_eq!(m2.get_group("g").unwrap().meta.name, "Friends");
    assert_eq!(m2.get_group_ids_for_contact("a").unwrap().len(), 2); // g + favorites
    assert_eq!(m2.get_contact("a").unwrap().meta.label.as_deref(), Some("Alice"));
}

#[test]
fn reads_rows_written_in_the_ts_adapter_shape_and_prunes_orphans() {
    let conn = shared_conn();
    init_schema(&conn).unwrap();
    {
        let g = conn.lock().unwrap();
        // Exactly the columns the TS SQLiteContactAdapter writes; JSON as JSON.stringify(toJSON()).
        let contact_json = r#"{"id":"c1","fingerprint":"fp1","meta":{"label":"Alice","notes":"","blocked":false,"createdAt":"2026-01-01T00:00:00.000Z","updatedAt":"2026-01-01T00:00:00.000Z"},"publicKeyBase64":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","mlKey":"mlkey","edPublicKeyBase64":"","mlDsaPublicKeyBase64":""}"#;
        g.execute(
            "INSERT OR REPLACE INTO majik_contacts (id, json, fingerprint, label, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6)",
            rusqlite::params!["c1", contact_json, "fp1", "Alice", "2026-01-01T00:00:00.000Z", "2026-01-01T00:00:00.000Z"],
        ).unwrap();
        // A custom group that still references a contact that no longer exists.
        let group_json = r#"{"id":"g1","meta":{"name":"Team","description":"","photoBase64":null,"createdAt":"2026-01-01T00:00:00.000Z","updatedAt":"2026-01-01T00:00:00.000Z"},"memberIds":["c1","ghost"],"isSystem":false}"#;
        g.execute(
            "INSERT OR REPLACE INTO majik_contact_groups (id, json, name, created_at, updated_at, is_system) VALUES (?1,?2,?3,?4,?5,?6)",
            rusqlite::params!["g1", group_json, "Team", "2026-01-01T00:00:00.000Z", "2026-01-01T00:00:00.000Z", 0],
        ).unwrap();
    }

    let mut m = ContactManager::with_sqlite(conn).unwrap();
    let report = m.hydrate().unwrap();
    assert_eq!(report.contacts_loaded, 1);
    assert_eq!(m.get_contact("c1").unwrap().meta.label.as_deref(), Some("Alice"));
    assert_eq!(m.get_contact_by_fingerprint("fp1").unwrap().id(), "c1");

    let g = m.get_group("g1").unwrap();
    assert_eq!(g.list_member_ids(), vec!["c1".to_string()], "ghost member pruned");
    // System groups are bootstrapped even though the TS database never stored them.
    assert!(m.get_favorites_group().is_ok() && m.get_blocked_group().is_ok());
}

#[test]
fn malformed_contact_rows_are_reported_not_fatal() {
    let conn = shared_conn();
    let mut m = ContactManager::with_sqlite(Arc::clone(&conn)).unwrap();
    m.add_contact(contact("good", "Good")).unwrap();
    {
        // Valid JSON for the row, but an empty public key makes the contact itself invalid.
        let bad = r#"{"id":"bad","fingerprint":"fpb","meta":{},"publicKeyBase64":"","mlKey":"x"}"#;
        conn.lock().unwrap().execute(
            "INSERT INTO majik_contacts (id, json) VALUES (?1, ?2)",
            rusqlite::params!["bad", bad],
        ).unwrap();
    }
    let mut m2 = ContactManager::with_sqlite(conn).unwrap();
    let report = m2.hydrate().unwrap();
    assert_eq!(report.contacts_loaded, 1);
    assert_eq!(report.contacts_skipped.len(), 1);
    assert_eq!(report.contacts_skipped[0].id, "bad");
}

#[test]
fn export_import_json_and_compressed_roundtrip() {
    let src = manager_with(&["a"]);
    let json = src.export_contact_as_json("a").unwrap().unwrap();
    assert!(src.export_contact_as_json("nope").unwrap().is_none());
    let shared = src.export_contact_as_string("a").unwrap().unwrap();

    let mut dst = ContactManager::in_memory();
    let r = dst.import_contact_from_json(&json);
    assert!(r.success, "{}", r.message);
    let imported = dst.get_contact("a").unwrap();
    assert_eq!(imported.fingerprint(), "fp-a");
    assert_eq!(imported.ml_key(), "ml-key");
    assert_eq!(imported.meta.label.as_deref(), Some("A"));

    let mut dst2 = ContactManager::in_memory();
    let r2 = dst2.import_contact_from_string(&shared);
    assert!(r2.success, "{}", r2.message);
    assert_eq!(dst2.get_contact("a").unwrap().address(), src.get_contact("a").unwrap().address());

    // Importing the same contact twice reports failure rather than erroring.
    assert!(!dst2.import_contact_from_string(&shared).success);
}

#[test]
fn import_rejects_garbage_and_decompression_bombs() {
    let mut m = ContactManager::in_memory();
    assert!(!m.import_contact_from_json("not json").success);
    assert!(!m.import_contact_from_json(r#"{"id":"x"}"#).success);
    assert!(!m.import_contact_from_string("!!!not base64!!!").success);

    // 4 MiB of zeros gzips to a few KB but must be refused on the way out.
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    enc.write_all(&vec![0u8; 4 * 1024 * 1024]).unwrap();
    let bomb = STANDARD.encode(enc.finish().unwrap());
    let r = m.import_contact_from_string(&bomb);
    assert!(!r.success);
    assert!(r.message.contains("size limit"), "{}", r.message);
    assert_eq!(m.list_contacts(false, false).len(), 0);
}

#[test]
fn whole_manager_json_roundtrip_and_clear() {
    let mut m = manager_with(&["a", "b"]);
    m.create_group("g", "G", None, Some(vec!["a".into()])).unwrap();
    m.block_contact("b").unwrap();
    let json = m.to_json();

    // The wire shape matches the TS ContactManagerJSON.
    let v = serde_json::to_value(&json).unwrap();
    assert!(v["contacts"]["contacts"].is_array());
    assert!(v["groups"]["groups"].is_array());

    let restored = ContactManager::from_json(
        &json,
        Box::new(MemoryContactRepo::new()),
        Box::new(MemoryGroupRepo::new()),
    )
    .unwrap();
    assert_eq!(restored.list_contacts(false, false).len(), 2);
    assert!(restored.is_contact_blocked("b").unwrap());
    assert!(restored.is_contact_in_group("g", "a").unwrap());

    m.clear().unwrap();
    assert!(m.list_contacts(false, false).is_empty());
    assert!(m.get_favorites_group().is_ok(), "system groups survive clear");
    assert!(m.list_user_groups(false).is_empty());
}

#[test]
fn contacts_by_ids_and_public_keys() {
    let m = manager_with(&["a", "b"]);
    let ids = vec!["a".to_string(), "a".to_string(), "zz".to_string(), "b".to_string()];
    let got: Vec<&str> = m.get_contacts_by_ids(&ids, false).unwrap().iter().map(|c| c.id()).collect();
    assert_eq!(got, vec!["a", "b"]);
    assert!(m.get_contacts_by_ids(&ids, true).is_err());

    let keys = vec![m.get_contact("b").unwrap().address(), "unknown".to_string()];
    assert_eq!(m.get_contacts_by_public_keys(&keys, false).unwrap().len(), 1);
    assert!(m.get_contacts_by_public_keys(&keys, true).is_err());
}

#[test]
fn group_instances_can_be_added_and_errors_serialise() {
    let mut m = manager_with(&["a"]);
    let g = MajikContactGroup::create("custom", "Custom", None, Some(vec!["a".into()])).unwrap();
    m.add_group(g).unwrap();
    assert!(m.is_contact_in_group("custom", "a").unwrap());

    let e = m.get_group_or_err("missing").unwrap_err();
    assert_eq!(
        serde_json::to_string(&e).unwrap(),
        r#"{"kind":"groups","message":"Group \"missing\" not found"}"#
    );
}
