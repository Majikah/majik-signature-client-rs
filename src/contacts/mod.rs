//! # majik-contact-manager
//!
//! Contact directory, groups and persistence for Majikah clients: the Rust port of the TS
//! `MajikContactDirectory`, `MajikContactGroupManager`, `MajikContactManager` and the SQLite
//! contact / group adapters, built on [`majik-contact`](https://crates.io/crates/majik-contact).

pub mod codec;
pub mod directory;
pub mod error;
pub mod groups;
pub mod manager;
pub mod memory;
pub mod schema;
pub mod sqlite;
pub mod storage;

pub use directory::{ContactDirectory, SkippedContact};
pub use error::{ContactManagerError, Result};
pub use groups::GroupManager;
pub use manager::{
    ContactDirectoryData, ContactManager, ContactManagerJson, GroupManagerData, HydrateReport,
};
pub use memory::{MemoryContactRepo, MemoryGroupRepo};
pub use sqlite::{init_schema, SharedConnection, SqliteContactRepo, SqliteGroupRepo};
pub use storage::{ContactRepo, GroupRepo};

/// Re-exported so callers use the exact `majik-contact` version this crate was built against.
pub use majik_contact;
