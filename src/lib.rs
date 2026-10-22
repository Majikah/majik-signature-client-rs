//! # majik-signature-client
//!
//! Rust port of the TS `MajikSignatureClient`, built by composing
//! [`majik-key-client`](majik_key_client) with contacts, logs, preferences and (in later slices)
//! stamps and signing on top of `majik-signature`.

pub mod backup;
pub mod bus;
pub mod client;
pub mod contacts;
pub mod error;
pub mod events;
pub mod file_identity;
pub mod files;
pub mod hooks;
pub mod ipc;
pub mod logs;
pub mod mjks;
pub mod prefs;
pub mod shared;
pub mod signing;
pub mod stamps;
pub mod stamps_api;
pub mod tsa;

pub use backup::{AppDataSnapshot, BackupType, ContactManagerSnapshot};
pub use bus::{Bus, Listener, ListenerId};
pub use client::{HydrateReport, SignatureClient};
pub use error::{Result, SignatureClientError};
pub use events::{SigEvent, SigOnlyEvent};
pub use files::{SignDetachedFileOptions, SignFileOptions};
pub use hooks::SigHooks;
pub use logs::repo::SharedConnection;
pub use mjks::MjksMapInput;
pub use prefs::UserAppPreferences;
pub use shared::{SigShared, MAX_ACTIVITY_LOGS};
pub use signing::{OpContext, SigInput, SignResult, SignerRef, VerifyResult, VerifyTarget};
pub use stamps::{MajikSignatureStamp, StampAssetKind, StampJson, StampMeta};

pub use contacts as majik_contact_manager;
pub use majik_file;
pub use majik_key_client;
pub use majik_signature;
