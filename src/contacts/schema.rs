//! SQL schema, equivalent to the TS `MAJIKAH_SQL_SCHEMA_MAJIK_CONTACTS` and
//! `MAJIKAH_SQL_SCHEMA_MAJIK_CONTACT_GROUPS` (table names resolved). `IF NOT EXISTS`, so running
//! them over a database created by the TS adapters is a no-op.

pub const TABLE_MAJIK_CONTACTS: &str = "majik_contacts";
pub const TABLE_MAJIK_CONTACT_GROUPS: &str = "majik_contact_groups";

pub const SCHEMA_MAJIK_CONTACTS: &str = "
CREATE TABLE IF NOT EXISTS majik_contacts (
  id TEXT PRIMARY KEY,
  json TEXT NOT NULL,
  fingerprint TEXT,
  label TEXT,
  created_at TEXT,
  updated_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_majik_contacts_created_at
ON majik_contacts(created_at);
";

pub const SCHEMA_MAJIK_CONTACT_GROUPS: &str = "
CREATE TABLE IF NOT EXISTS majik_contact_groups (
  id TEXT PRIMARY KEY,
  json TEXT NOT NULL,
  name TEXT,
  created_at TEXT,
  updated_at TEXT,
  is_system INTEGER DEFAULT 0 CHECK(is_system IN (0,1))
);

CREATE INDEX IF NOT EXISTS idx_majik_contact_groups_created_at
ON majik_contact_groups(created_at);
";
